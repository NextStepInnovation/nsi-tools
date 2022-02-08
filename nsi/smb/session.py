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
from typing import Sequence, Set

from pymaybe import Nothing

from ..toolz import (
    pipe, curry, map, filter, merge, compose, partial,
)
from .. import toolz as _
from .. import shell
from .. import logging


log = logging.new_log(__name__)

KNOWN_USERS = ['Administrator', 'Guest', 'krbtgt', 'root', 'bin']
TIMEOUT_KEY = 'NSI_SMB_MIN_TIMEOUT'

@curry
def smbclient(domain, username, password, target, share, command,
              *, timeout=5, getoutput=shell.getoutput, proxychains=False,
              dry_run=False):
    timeout = max(timeout, os.environ.get(TIMEOUT_KEY, 0))
    domain = rf'{domain}//' if domain else ''
    command = (
        ("proxychains " if proxychains else "") +
        f"smbclient //{target}/'{share}'"
        f" -U '{domain}{username}'%'{password}'"
    ) + (f" -t {timeout}" if timeout else '') + (
        f" -c '{command}'"
    )
    log.debug(f'smbclient command: {command}')
    if dry_run:
        log.warning('Dry run')
        return ''
    return getoutput(command)


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

smb_file_re = re.compile(
    r'^\s+(?P<name>.*?)\s+'
    fr'(?P<type>{"|".join(smb_file_type_map.keys())})\s+'
    r'(?P<size>\d+)\s+(?P<ts>.*)$'
)

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
}
smb_error_re = re.compile(
    fr'NT_(?P<raw_error>.*?)(?:\W+|$)'
    # r'NT_(?P<raw_error>.*?)\s+'
)

@curry
def smb_output_line_dict(path: str, command: str, line):
    file_match = smb_file_re.search(line)
    if file_match:
        d = file_match.groupdict()
        return merge(
            d,
            {'path': path, 'command': command},
            {'dt': _.maybe_dt(d['ts'])},
            {'size': int(d['size'])},
            {'type': smb_file_type_map[d['type']]},
        )
    error_match = smb_error_re.search(line)
    if error_match:
        d = error_match.groupdict()
        return merge(
            d,
            {'path': path, 'command': command},
            {'error': smb_error_type_map.get(
                d['raw_error'], set(),
            )},
            {'error_line': line},
        )
    return Nothing()

def smb_errors(results: Sequence[dict]):
    return pipe(
        results,
        filter(lambda d: 'error' in d),
        tuple,
    )

@curry
def has_smb_errors(errors: Set[str], results):
    return any(errors.issubset(e['error']) for e in smb_errors(results))

@curry
def has_smb_files(results):
    return any('error' not in r for r in results)

def smb_path(*parts):
    if len(parts) > 1 and parts[-1] == '/':
        return '/'.join(parts) + '/'
    return '/'.join(parts)

def smbclient_ls(domain, username, password, target, share, *path_parts,
                 getoutput=shell.getoutput, timeout=10, proxychains=False,
                 dry_run=False):
    path = smb_path(*path_parts or "")
    if ' ' in path:
        path = f'"{path}"'
    command = f'ls {path}'

    return pipe(
        smbclient(
            domain, username, password, target, share, command,
            getoutput=getoutput, timeout=timeout, 
            proxychains=proxychains, dry_run=dry_run,
        ).splitlines(),
        map(smb_output_line_dict(path, command)),
        filter(None),
        tuple,
    )

smbclient_ls_t = partial(compose(tuple, smbclient_ls))

def smbclient_mkdir(domain, username, password, target, share,
                    first_path_part, *rest_of_path,
                    getoutput=shell.getoutput, timeout=3, 
                    proxychains=False, dry_run=False):
    parts = (first_path_part,) + rest_of_path
    path = smb_path(*parts)
    command = f'mkdir "{path}"'

    errors = _.maybe_pipe(
        smbclient(
            domain, username, password, target, share, command,
            getoutput=getoutput, timeout=timeout,
            proxychains=proxychains, dry_run=dry_run,
        ).splitlines(),
        map(smb_output_line_dict(path, command)),
        filter(None),
        smb_errors,
    )
    if errors and not dry_run:
        return False, errors

    results = smbclient_ls_t(
        domain, username, password, target, share, *parts,
        getoutput=getoutput, 
        proxychains=proxychains, dry_run=dry_run
    )
    errors = smb_errors(results)
    if errors:
        return False, errors
    
    return True, results
    
def smbclient_rmdir(domain, username, password, target, share,
                    first_path_part, *rest_of_path,
                    getoutput=shell.getoutput, timeout=3, 
                    proxychains=False, dry_run=False):
    parts = (first_path_part,) + rest_of_path
    path = smb_path(*parts)
    command = f'rmdir "{path}"'

    errors = _.maybe_pipe(
        smbclient(
            domain, username, password, target, share, command,
            getoutput=getoutput, timeout=timeout, 
            proxychains=proxychains, dry_run=dry_run,
        ).splitlines(),
        map(smb_output_line_dict(path, command)),
        filter(None),
        smb_errors,
    )
    if errors and not dry_run:
        return False, errors

    results = smbclient_ls_t(
        domain, username, password, target, share, *parts,
        getoutput=getoutput, proxychains=proxychains, 
        dry_run=dry_run
    )
    
    if has_smb_errors({'no_dir'}, results):
        return True, ()
    
    return False, smb_errors(results)
    

@curry
def test_share_perms(domain, username, password, target, share, *,
                     getoutput=shell.getoutput, timeout=3,
                     rng=None, prefix='nsi', proxychains=False,
                     dry_run=False):
    rng = rng or random.Random(0)

    results = smbclient_ls(
        domain, username, password, target, share, '',
        getoutput=getoutput, timeout=timeout, proxychains=proxychains,
        dry_run=dry_run,
    )
    errors = smb_errors(results)
    
    perms = set()
    
    if errors and not has_smb_files(results) and not dry_run:
        log.error(f'Error for {target}: {errors}')
        return perms, errors

    log.debug(f'{username}:{password} on {target} has READ')
    perms = perms | {'read'}
    
    test_dir_name = prefix + _.random_str(10, rng=rng)

    # First, check to see if the directory is already there.
    results = smbclient_ls(
        domain, username, password, target, share, test_dir_name,
        getoutput=getoutput, proxychains=proxychains, dry_run=dry_run,
    )
    if has_smb_files(results):
        # The directory is already there. Ouch... Hopefully, it's just
        # a remnant of a previously-killed smbclient session
        success, results = smbclient_rmdir(
            domain, username, password, target, share, test_dir_name,
            getoutput=getoutput, proxychains=proxychains, dry_run=dry_run,
        )
        if success and not dry_run:
            # Good, we can remove it, so we have write access.
            return perms | {'write'}, ()

        if not dry_run:
            # Ok, there's something weird going on. Possibly a FS
            # permissions thing where you can create directories but not
            # remove them. Or, this user had write in the past, but now no
            # longer does.
            #
            # Don't report having write permissions. Log that this
            # directory is there and manual inspection is necessary.
            log.error(
                f'Test directory --> {test_dir_name} <-- exists already'
                ' and should be removed by hand (if possible). MANUAL'
                ' INSPECTION is necessary to determine WRITE permissions. '
            )
            return perms, (
                {'error': {'test_dir_still_exists', 'kuzu_error',
                           'bad_permissions', 'no_rmdir'}},
            )

    # Create the directory, then remove it to determine write
    # permissions.
    success, results = smbclient_mkdir(
        domain, username, password, target, share, test_dir_name,
        getoutput=getoutput, proxychains=proxychains, dry_run=dry_run
    )
    if success:
        success, results = smbclient_rmdir(
            domain, username, password, target, share, test_dir_name,
            getoutput=getoutput, proxychains=proxychains, dry_run=dry_run,
        )
        if success:
            # We can create the directory, so we have write
            # permissions
            return perms | {'write'}, ()

        # We can create, but we can't remove. This is unusual, but not
        # impossible.
        errors = results
        return perms, errors

    # Could not create directory, so must not have write permissions
    errors = results
    return perms, errors


smb_dir = smbclient(command='dir', timeout=3)

@curry
def smbclient_list(domain, username, password, target, *,
                   timeout=5, getoutput=shell.getoutput,
                   proxychains=False, dry_run=False):
    timeout = max(timeout, os.environ.get(TIMEOUT_KEY, 0))
    domain = rf'{domain}//' if domain else ''
    command = (
        ('proxychains ' if proxychains else '') +
        f'smbclient -L {target}'
        f" -U '{domain}{username}'%'{password}'"
    ) + f' -t {timeout}' if timeout else ''
    log.debug(f'smbclient_list command: {command}')
    if dry_run:
        log.warning('Dry run')
        return ''
    return getoutput(command)


smbclient_types = ['Disk', 'IPC', 'Printer']

share_re = re.compile(
    fr'^\s+(?P<name>\S*?)\s+(?P<type>{"|".join(smbclient_types)})'
    r'\s+(?P<desc>.*)'
)

@curry
def enum_shares(domain, username, password, target, *,
                getoutput=shell.getoutput, proxychains=False,
                dry_run=False):
    return pipe(
        smbclient_list(
            domain, username, password, target, timeout=3,
            getoutput=getoutput, proxychains=proxychains,
            dry_run=dry_run,
        ).splitlines(),
        filter(lambda l: any(t in l for t in smbclient_types)),
        _.groupdicts(share_re),
        map(lambda d: merge({'ip': target}, d)),
        tuple,
    )

ipc_query = smbclient(command='exit', share='IPC$', timeout=1)

@curry
def enum_os(username, password, target, *, getoutput=shell.getoutput,
            proxychains=False, dry_run=False):
    output = ipc_query(
        username, password, target, getoutput=getoutput,
        proxychains=proxychains, dry_run=dry_run,
    )
    for line in output.splitlines():
        if "Domain=" in line:
            yield target, line
        elif "NT_STATUS_LOGON_FAILURE" in line:
            log.error(f'{target}: Enum OS failed: {line}')
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
    domain = rf'{domain}\\' if domain else ''
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
def polenum(domain, username, password, target, *, getoutput=shell.getoutput,
            proxychains=False, dry_run=False):
    command = (
        ('proxychains ' if proxychains else '') +
        f"polenum -d {domain or '.'} '{username}':'{password}'@'{target}'"
    )
    log.debug(f'polenum command: {command}')
    if dry_run:
        log.warning('Dry run')
        return ''
    return getoutput(command)

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

null.enum_shares = enum_shares('', '', '')
null.polenum_password_policy = partial(
    polenum_password_policy, '', '', ''
)

