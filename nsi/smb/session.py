'''SMB enumeration

Background:

SIDs and RIDs

http://pig.made-it.com/uidgid.html#28718

- SecurityIDentifier (SID)
- RelativeIDentifier (RID)

S-[Revision]-[IdentifierAuthority]-[SubAuthority0]
 -[SubAuthority1]-...-[SubAuthority<SubAuthorityCount>](-RID)

'''
from pathlib import Path
import os
import re
import random
from datetime import datetime
import typing as T
import time
import tempfile
from typing import Sequence, Set
import pprint
import dataclasses
from dataclasses import dataclass

from pymaybe import Nothing

from nsi.toolz.filesystem import ensure_paths

from ..toolz import (
    pipe, curry, map, filter, merge, compose, partial,
    maybe, splitlines, compose_left, strip,
)
from .. import toolz as _
from .. import shell
from .. import logging


log = logging.new_log(__name__)

KNOWN_USERS = ['Administrator', 'Guest', 'krbtgt', 'root', 'bin']
TIMEOUT_KEY = 'NSI_SMB_MIN_TIMEOUT'

str_command = compose_left(
    map(strip),
    filter(None),
    ' '.join,
)

@dataclass
class SmbClientArgs:
    domain: str
    username: str
    password: str
    target: str
    share: str
    getoutput: T.Callable[[str], str] = shell.getoutput
    timeout: int = 5
    polite: T.Optional[float] = None
    proxychains: bool = False
    dry_run: bool = False

    def __repr__(self):
        return (
            f'<SmbClientArgs: {self.command("")}>'
        )

    def validate(self):
        invalid = pipe(
            ['domain', 'username', 'password', 'target', 'share'],
            filter(lambda a: _.is_none(getattr(self, a))),
            tuple,
        )
        if invalid:
            raise AttributeError(
                f'The following attributes are not set: {", ".join(invalid)}'
            )

    def prep_command(self, command: str):
        if "'" in command:
            command = command.replace(
                "'", ''' '"'"' '''.strip()
            )
        return command

    def command(self, command: str):
        self.validate()
        timeout = max(self.timeout, os.environ.get(TIMEOUT_KEY, 0))
        domain = f'{self.domain}\\' if self.domain else ''
        command_parts = [
            ("proxychains -q" if self.proxychains else ""),
            (f"smbclient //{self.target}/'{self.share}'"
             f" -U '{domain}{self.username}'%'{self.password}'"),
            f"-t {timeout}" if timeout else '',
            f"-c '{self.prep_command(command)}'" if command else '',
        ]
        return pipe(
            command_parts,
            str_command,
        )

    def list_command(self):
        self.validate()
        timeout = max(self.timeout, os.environ.get(TIMEOUT_KEY, 0))
        domain = f'{self.domain}\\' if self.domain else ''
        command_parts = [
            'proxychains -q' if self.proxychains else '',
            (f'smbclient -g -L {self.target}'
             f" -U '{domain}{self.username}'%'{self.password}'"),
            f'-t {timeout}' if timeout else '',
        ]
        return pipe(
            command_parts,
            str_command,
        )

@curry
def new_args(domain: str, username: str, password: str, target: str, share: str,
             *, getoutput=SmbClientArgs.getoutput, 
             timeout: int = SmbClientArgs.timeout, 
             proxychains: bool = SmbClientArgs.proxychains, 
             polite: float = None,
             dry_run: bool = SmbClientArgs.dry_run):
    args = SmbClientArgs(
        domain, username, password, target, share, 
        getoutput=getoutput, timeout=timeout, proxychains=proxychains,
        dry_run=dry_run, polite=polite,
    )
    log.debug(f'Completed args: {args}')
    return args

SmbOutput = T.NewType('SmbOutput', str)

@curry
def smbclient(args: SmbClientArgs, command, **repl_args) -> SmbOutput:
    args = dataclasses.replace(args, **repl_args)
    command = args.command(command)
    log.debug(f'smbclient command: {command}')
    if args.dry_run:
        log.warning('Dry run')
        return ''
    if args.polite:
        time.sleep(args.polite)
    return args.getoutput(command)

@curry
def smbclient_list(args: SmbClientArgs, **repl_args) -> SmbOutput:
    args = dataclasses.replace(args, **repl_args)
    command = args.list_command()
    log.debug(f'smbclient_list command: {command}')
    if args.dry_run:
        log.warning('Dry run')
        return ''
    return args.getoutput(command)


smb_file_type_map = {
    'A': 'file',
    'AH': 'file',
    'AHS': 'file',
    'N': 'file',
    'D': 'dir',
    'DA': 'dir',
    'DH': 'dir',
    'DHS': 'dir',
}

smb_recursive_dir_re = re.compile(
    r'^(?P<path>\\.*)$'
)

smb_file_re = re.compile(
    r'^\s+(?P<name>.*?)\s+'
    fr'(?P<type>{"|".join(smb_file_type_map.keys())})r?\s+'
    r'(?P<size>\d+)\s+(?P<ts>.*)$'
)

class FileDict(T.TypedDict):
    name: str
    path: Path
    type: str
    size: int
    line: str
    dt: T.Optional[datetime]

def new_file_dict(data: dict) -> FileDict:
    name, ts, size, type, line = pipe(
        ['name', 'ts', 'size', 'type', 'line'],
        map(data.get),
    )
    return FileDict(merge(
        data,
        {'path': Path(name)},
        {'dt': _.maybe_dt(ts, default=ts)},
        {'size': _.maybe_int(size, default=size)},
        {'type': smb_file_type_map[type]},
        {'line': line}
    ))

def is_file_dict(data: dict):
    return 'path' in data and 'type' in data and 'size' in data

smb_error_type_map = {
    'STATUS_LOGON_FAILURE': {'logon', 'bad_auth'},
    'STATUS_SHARING_VIOLATION': {'sharing'},
    'STATUS_ACCESS_DENIED': {'no_access'},
    'STATUS_INVALID_PARAMETER': {'bad_path'},
    'STATUS_NO_SUCH_FILE': {'bad_path', 'no_file', 'no_dir'},
    'STATUS_OBJECT_NAME_NOT_FOUND': {'bad_path', 'no_file', 'no_dir'},
    'STATUS_OBJECT_NAME_COLLISION': {'bad_path', 'already_exists',
                                     'dir_exists'},
    'STATUS_OBJECT_NAME_INVALID': {'bad_path', 'invalid_name'},
    'STATUS_OBJECT_PATH_NOT_FOUND': {'bad_path', 'not_found'},
    'STATUS_NOT_A_DIRECTORY': {'bad_path', 'not_dir'},
    'STATUS_BAD_NETWORK_NAME': {'bad_share', 'not_a_share'},
    'STATUS_INVALID_INFO_CLASS': {'ipc_share',},
}

smb_error_re = re.compile(
    fr'NT_(?P<raw_error>.*?)(?:\W+|$)'
    # r'NT_(?P<raw_error>.*?)\s+'
)
smb_file_error_re = re.compile(
    r'Error opening local file '
)

class ErrorDict(T.TypedDict):
    raw_error: str
    line: str
    error: T.Set[str]

def new_error_dict(data: dict) -> ErrorDict:
    raw_error = data.get('raw_error')

    error = smb_error_type_map.get(raw_error, set())

    return ErrorDict(merge(
        data,
        {'error': error} if error else {},
    ))

def is_error_dict(data: dict):
    return 'error' in data

def smb_output_line_dict(line: str) -> FileDict | ErrorDict:
    file_match = smb_file_re.search(line)
    if file_match:
        return new_file_dict(merge(
            file_match.groupdict(),
            {'line': line},
        ))


    data = {}
    error_match = smb_error_re.search(line)
    if error_match:
        data = error_match.groupdict()
    return new_error_dict(merge(data, {'line': line}))

smb_errors = compose_left(
    filter(is_error_dict),
    tuple,
)
smb_files = compose_left(
    filter(is_file_dict),
    filter(lambda d: d['name'] not in {'.', '..'}),
    tuple,
)

@curry
def has_smb_errors(errors: Set[str], results):
    return any(errors.issubset(e['error']) for e in smb_errors(results))

has_no_dir = has_smb_errors({'no_dir'})
has_no_file = has_smb_errors({'no_file'})

def has_smb_files(results):
    return pipe(
        results,
        map(is_file_dict),
        any,
    )

def smb_path(*parts):
    return '/'.join(parts)

@curry
def walk(ls_func: T.Callable[[T.Tuple[str]], T.Iterable[FileDict]],
         start: Path, *, skip: T.Sequence[str]) -> T.Iterable[FileDict]:
    start = Path(start)
    skip = pipe(
        skip,
        map(Path),
        set,
    )

    def walker(path, root=Path('/')):
        for fd in ls_func(f'{path}/'):
            fd_path = root / fd['path']
            if fd_path in skip:
                continue
            match fd:
                case {'type': 'file'}:
                    yield merge(
                        fd, {'path': fd_path},
                    )
                case {'type': 'dir', 'name': '..' | '.'}:
                    pass
                case {'type': 'dir'}:
                    yield from walker(fd_path, root=fd_path)
    
    return walker(start)

def smb_results(output: SmbOutput):
    return pipe(
        output,
        splitlines,
        map(smb_output_line_dict),
        filter(None),
        tuple,
    )

@curry
def smbclient_ls(args: SmbClientArgs, path: Path, **repl_args):
    command = f'ls "{path}"'
    return pipe(
        smbclient(args, command, **repl_args),
        smb_results,
    )

@curry
@ensure_paths
def smbclient_get(args: SmbClientArgs, remote_path: Path, 
                  local_dir: Path = Path('.'), **repl_args):
    local_path = local_dir / remote_path.name
    
    command = f'get "{remote_path}" "{local_path}"'
    errors = pipe(
        smbclient(args, command, **repl_args),
        smb_results,
        smb_errors,
    )
    if errors:
        return False, errors

    return True, local_path

@curry
@ensure_paths
def smbclient_put(args: SmbClientArgs, local_path: Path, 
                  remote_path: Path = None, **repl_args):
    remote_path = remote_path or Path(local_path.name)
    command = f'put "{local_path}" "{remote_path}"'

    errors = pipe(
        smbclient(args, command, **repl_args),
        smb_results,
        smb_errors,
    )
    if errors:
        return False, errors

    results = smbclient_ls(args, remote_path)
    errors = smb_errors(results)
    if errors:
        return False, errors
    
    return True, smb_files(results)

@curry
def smbclient_mkdir(args: SmbClientArgs, path: Path, **repl_args):
    command = f'mkdir "{path}"'

    errors = pipe(
        smbclient(args, command, **repl_args),
        smb_results,
        smb_errors,
    )
    if errors:
        return False, errors

    results = smbclient_ls(args, path)
    errors = smb_errors(results)
    if errors:
        return False, errors
    
    return True, results
    
@curry
def smbclient_rmdir(args: SmbClientArgs, path: Path, **repl_args):
    command = f'rmdir "{path}"'

    errors = pipe(
        smbclient(args, command, **repl_args),
        smb_results,
        smb_errors,
    )
    if errors:
        return False, errors

    results = smbclient_ls(args, path)
    
    if has_no_dir(results):
        return True, ()
    
    return False, smb_errors(results)
    
@curry
def smbclient_rm(args: SmbClientArgs, path: Path, **repl_args):
    command = f'rm "{path}"'

    errors = pipe(
        smbclient(args, command, **repl_args),
        smb_results,
        smb_errors,
    )
    if errors:
        return False, errors

    results = smbclient_ls(args, path)
    
    if has_no_file(results):
        return True, ()
    
    return False, smb_errors(results)
    
@curry
def test_share_perms(args: SmbClientArgs, *, rng=None, prefix='nsi'):
    rng = rng or random.Random(0)

    results = smbclient_ls(args, "/")
    errors = smb_errors(results)
    
    perms = set()
    
    if errors and not has_smb_files(results):
        log.error(f'Error for {args.target}: {pprint.pformat(errors)}')
        return perms, errors

    log.debug(f'{args.username}:{args.password} on {args.target} has READ')
    perms = perms | {'read'}

    # Check for file/directory writing privilieges
    
    # Directory writing
    test_dir_name = prefix + _.random_str(20, rng=rng)

    # Create the directory, then remove it to determine write
    # permissions.
    success, mkdir_errors = smbclient_mkdir(args, test_dir_name)
    errors = _.concatv(errors, mkdir_errors)
    if success:
        perms = perms | {'write-dir'}
        success, rmdir_errors = smbclient_rmdir(args, test_dir_name)
        errors = _.concatv(errors, rmdir_errors)
        if not success:
            # We can create, but we can't remove. This is unusual, but not
            # impossible.
            perms = perms | {'cannot-remove-dir'}

    # File writing
    test_file_name = prefix + _.random_str(20, rng=rng)
    test_content = _.random_str(2**10, rng=rng)
    current_dir = Path('.').resolve()
    with tempfile.NamedTemporaryFile() as rfp:
        rfp.write(test_content.encode())
        rfp.flush()
        temp_path = Path(rfp.name)
        success, put_errors = smbclient_put(args, temp_path, test_file_name)

    errors = _.concatv(errors, put_errors)
    if success:
        perms = perms | {'write-file'}

        success, rm_errors = smbclient_rm(args, test_file_name)
        errors = _.concatv(errors, rm_errors)
        if not success:
            # Can create file, but cannot remove
            perms |= {'cannot-remove-file'}

    # Could not create directory, so must not have write permissions
    return perms, pipe(errors, tuple)


smbclient_types = ['Disk', 'IPC', 'Printer']

share_re = re.compile(
    fr'^\s+(?P<name>\S*?)\s+(?P<type>{"|".join(smbclient_types)})'
    r'\s+(?P<desc>.*)'
)
share_re = re.compile(
    r'.*?\|.*?\|.*?'
)

@curry
def enum_shares(args: SmbClientArgs, **repl_args):
    columns = ['type', 'name', 'comment']
    return pipe(
        smbclient_list(args, **repl_args),
        splitlines,
        filter(share_re.search),
        map(_.split(sep='|')),
        map(lambda t: dict(zip(*[columns, t]))),
        filter(lambda d: d['type'] in smbclient_types),
        map(lambda d: merge({'ip': args.target}, d)),
        tuple,
    )

ipc_query = smbclient(command='exit', share='IPC$', timeout=1)

@curry
def enum_os(args: SmbClientArgs):
    output = ipc_query(args)
    for line in output.splitlines():
        if "Domain=" in line:
            yield args.target, line
        elif "NT_STATUS_LOGON_FAILURE" in line:
            log.error(f'{args.target}: Enum OS failed: {line}')
            return

@curry
def line_data(regexes, content):
    regexes = [re.compile(r) for r in regexes]
    return pipe(
        content.splitlines(),
        map(lambda l: _.first_true([r.search(l) for r in regexes])),
        filter(None),
        map(lambda match: match.groupdict()),
        tuple,
    )

@curry
def rpcclient(command, domain, username, password, target, *,
              getoutput=shell.getoutput, proxychains=False, dry_run=False):
    '''Run rpcclient with command for given credentials on target
    '''
    domain = f'{domain}\\' if domain else ''
    command = (
        ('proxychains ' if proxychains else '') +
        f"rpcclient -c '{command}'"
        f""" -U '{domain}{username}%{password}' {target}"""
    )
    log.debug(f'rpcclient command: {command}')
    if dry_run:
        log.warning('Dry run')
        return ''
    return getoutput(command)

@curry
def net_rpc_group_members(group, username, password, target, *, 
                          getoutput=shell.getoutput, proxychains=False,
                          dry_run=False):
    command = (
        ('proxychains ' if proxychains else '') +
        f"net rpc group members '{group}'"
        f" -U '{username}%{password}' -I {target}"
    )
    log.debug(f'net rpc command: {command}')
    if dry_run:
        log.warning('Dry run')
        return ''
    return getoutput(command)

lsaquery = rpcclient('lsaquery')

get_dom_sid = compose(
    merge,
    line_data(
        [r'Domain Name: (?P<name>.*)',
         r'Domain Sid: (?P<sid>.*)']
    ),
    lsaquery,
)

querydispinfo = rpcclient('querydispinfo')

enum_querydispinfo = compose(
    line_data([
        (r'index: (?P<index>.*?)'
         r' RID: (?P<rid>.*?)'
         r' acb: (?P<acb>.*?)'
         r' Account: (?P<account>.*?)'
         r'\tName: (?P<name>.*?)'
         r'\tDesc: (?P<desc>.*)'),
    ]),
    querydispinfo,
)

enumdomusers = rpcclient('enumdomusers')

enum_enumdomusers = compose(
    line_data([r'user:\[(?P<name>.*?)\] rid:\[(?P<rid>.*?)\]']),
    enumdomusers,
)

enumdomgroups = rpcclient('enumdomgroups')

enum_enumdomgroups = compose(
    line_data([r'group:\[(?P<name>.*?)\] rid:\[(?P<rid>.*?)\]']),
    enumdomgroups,
)

lsaenumsid = rpcclient('lsaenumsid')

@curry
def lookupsids(domain, username, password, target, sid, *,
               getoutput=shell.getoutput, proxychains=False,
               dry_run=False):
    return pipe(
        rpcclient(
            f'lookupsids {sid}', domain, username,
            password, target, getoutput=getoutput,
            proxychains=proxychains, dry_run=dry_run,
        ),
        line_data([
            r'^(?P<sid>S-\d+.*?)\s(?P<domain>.*?)\\(?P<name>[ \S]*)$'
        ]),
        filter(lambda d: d['name'] != '*unknown*'),
        tuple,
    )

@curry
def lookupnames(domain, username, password, target, name, *,
                getoutput=shell.getoutput, proxychains=False,
                dry_run=False):
    return pipe(
        rpcclient(
            f'lookupnames {name}', domain, username, password, target,
            getoutput=getoutput, proxychains=proxychains, dry_run=dry_run,
        ),
        line_data([
            r'(?P<name>[ \S]+?) (?P<sid>S-\d+-\d+.*?)'
            r' \((?P<type>[ \S]+?): (?P<type_number>\d+)\)',
        ]),
        filter(lambda d: d['sid'] != 'S-0-0'),
        tuple,
    )

@curry
def known_users(domain, username, password, target, *,
                getoutput=shell.getoutput, proxychains=False,
                dry_run=False):
    return pipe(
        KNOWN_USERS,
        ' '.join,
        lookupnames(domain, username, password, target, getoutput=getoutput,
                    proxychains=proxychains, dry_run=dry_run),
    )

@curry
def users_from_rid_range(domain_sid, domain, username, password, target,
                         rid_range, *, getoutput=shell.getoutput,
                         proxychains=False, dry_run=False):
    return pipe(
        range(*pipe(rid_range, map(int))),
        map(lambda rid: f'{domain_sid}-{rid}'),
        ' '.join,
        lookupsids(domain, username, password, target, getoutput=getoutput,
                   proxychains=proxychains, dry_run=dry_run),
    )

@curry
def users_from_rids(domain_sid, domain, username, password, target, rids, *,
                    getoutput=shell.getoutput, proxychains=False,
                    dry_run=False):
    return pipe(
        rids,
        map(lambda rid: f'{domain_sid}-{rid}'),
        ' '.join,
        lookupsids(domain, username, password, target, getoutput=getoutput,
                   proxychains=proxychains, dry_run=dry_run),
    )

@curry
def enum_lsa(domain, username, password, target, *, getoutput=shell.getoutput,
             proxychains=False, dry_run=False):
    return pipe(
        lsaenumsid(domain, username, password, target),
        line_data([r'^(?P<sid>S-\d+.*)$']),
        map(lambda d: d['sid']),
        filter(lambda sid: sid.startswith('S-1-5-21')),
        ' '.join,
        lookupsids(domain, username, password, target, getoutput=getoutput,
                   proxychains=proxychains, dry_run=dry_run),
    )

@curry
def polenum(args: SmbClientArgs):
    command = pipe(
        [
            ('proxychains ' if args.proxychains else ''),
            (f"polenum -d {args.domain or '.'}"
             f" '{args.username}':'{args.password}'@'{args.target}'"),
        ],
        str_command,
    )
    log.debug(f'polenum command: {command}')
    if args.dry_run:
        log.warning('Dry run')
        return ''
    return args.getoutput(command)

polenum_password_policy = compose(
    merge,
    line_data([
        r'\[\+\] Minimum password length: (?P<minimum_password_length>.*)',
        r'\[\+\] Password history length: (?P<password_history_length>.*)',
        r'\[\+\] Maximum password age: (?P<maximum_password_age>.*)',
        r'\[\+\] Password Complexity Flags: (?P<password_complexity>.*)',
        r'\[\+\] Domain Refuse Password Change:'
        r' (?P<doman_refuse_password_change>.*)',
        r'\[\+\] Domain Password Store Cleartext:'
        r' (?P<domain_password_store_cleartext>.*)',
        r'\[\+\] Domain Password Lockout Admins:'
        r' (?P<domain_password_lockout_admins>.*)',
        r'\[\+\] Domain Password No Clear Change:'
        r' (?P<domain_password_no_clear_change>.*)',
        r'\[\+\] Domain Password No Anon Change:'
        r' (?P<domain_password_no_anon_change>.*)',
        r'\[\+\] Domain Password Complex: (?P<domain_password_complex>.*)',
        r'\[\+\] Minimum password age: (?P<minimum_password_age>.*)',
        r'\[\+\] Reset Account Lockout Counter:'
        r' (?P<reset_account_lockout_counter>.*)',
        r'\[\+\] Locked Account Duration: (?P<locked_account_duration>.*)',
        r'\[\+\] Account Lockout Threshold:'
        r' (?P<account_lockout_threshold>.*)',
        r'\[\+\] Forced Log off Time: (?P<forced_log_off_time>.*)',
    ]),
    polenum,
)

rpc_password_policy = compose(
    merge,
    line_data(
        [r'min_password_length: (?P<minimum_password_length>.*)',
         r'password_properties: (?P<password_complexity_flags>.*)']
    ),
    rpcclient('getdompwinfo'),
)


class null:
    pass
null_args = new_args('', '', '')
null.enum_shares = compose_left(
    null_args,
    enum_shares,
)
null.polenum_password_policy = compose_left(
    null_args,
    polenum_password_policy,
)

