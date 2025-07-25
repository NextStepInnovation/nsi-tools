import os
import sys
import socket
import tempfile
import typing as T
import re
from collections import namedtuple
from pathlib import Path
from datetime import datetime

import socks
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SharedFile
from impacket import smb
from impacket.dcerpc.v5.srvs import SHARE_INFO_1
from impacket.nmb import NetBIOSTimeout

from .. import logging
from .. import shell
from .. import parallel
from ..toolz import *
from ..data.file_extensions import get_ext, type_from_ext

log = logging.new_log(__name__)


FILE_ATTRS = {
    0x0000: ('SMB_FILE_ATTRIBUTE_NORMAL', 'Normal file.'),
    0x0001: ('SMB_FILE_ATTRIBUTE_READONLY', 'Read-only file.'),
    0x0002: ('SMB_FILE_ATTRIBUTE_HIDDEN', 'Hidden file.'),
    0x0004: ('SMB_FILE_ATTRIBUTE_SYSTEM', 'System file.'),
    0x0008: ('SMB_FILE_ATTRIBUTE_VOLUME', 'Volume Label.'),
    0x0010: ('SMB_FILE_ATTRIBUTE_DIRECTORY', 'Directory file.'),
    0x0020: ('SMB_FILE_ATTRIBUTE_ARCHIVE', 'File changed since last archive.'),
    0x0100: ('SMB_SEARCH_ATTRIBUTE_READONLY', 'Search for Read-only files.'),
    0x0200: ('SMB_SEARCH_ATTRIBUTE_HIDDEN', 'Search for Hidden files.'),
    0x0400: ('SMB_SEARCH_ATTRIBUTE_SYSTEM', 'Search for System files.'),
    0x1000: ('SMB_SEARCH_ATTRIBUTE_DIRECTORY', 'Search for Directory files.'),
    0x2000: ('SMB_SEARCH_ATTRIBUTE_ARCHIVE', 'Search for files that have changed since they were last archived.'),
    0xC8C0: ('Other', 'Reserved.'),
}

SMB_ERROR_CODES = {
    0x00000000: "STATUS_SUCCESS: The operation completed successfully.",
    0xC0000001: "STATUS_UNSUCCESSFUL: The operation failed.",
    0xC0000002: "STATUS_NOT_IMPLEMENTED: The requested operation is not implemented.",
    0xC000000D: "STATUS_INVALID_PARAMETER: An invalid parameter was passed to a service or function.",
    0xC000000F: "STATUS_NO_SUCH_FILE: The file or directory does not exist.",
    0xC0000011: "STATUS_END_OF_FILE: The end-of-file marker has been reached.",
    0xC0000012: "STATUS_TOO_MANY_OPEN_FILES: Too many files are currently open.",
    0xC0000022: "STATUS_ACCESS_DENIED: Access is denied.",
    0xC0000023: "STATUS_BUFFER_TOO_SMALL: The buffer is too small to contain the entry.",
    0xC0000024: "STATUS_OBJECT_TYPE_MISMATCH: The object type is not correct for the attempted operation.",
    0xC0000025: "STATUS_OBJECT_NAME_INVALID: The object name is invalid.",
    0xC0000026: "STATUS_OBJECT_NAME_NOT_FOUND: The object name was not found.",
    0xC0000034: "STATUS_OBJECT_PATH_NOT_FOUND: The path to the object was not found.",
    0xC0000035: "STATUS_OBJECT_PATH_INVALID: The object path is invalid.",
    0xC0000040: "STATUS_SHARING_VIOLATION: A sharing violation occurred.",
    0xC0000041: "STATUS_FILE_LOCK_CONFLICT: A file lock conflict occurred.",
    0xC0000043: "STATUS_FILE_CLOSED: The file is closed.",
    0xC0000046: "STATUS_CANNOT_DELETE: The requested operation cannot be performed on a file with a user-mapped section open.",
    0xC0000054: "STATUS_DISK_FULL: The disk is full.",
    0xC0000056: "STATUS_NO_MEDIA_IN_DEVICE: No media is present in the device.",
    0xC0000057: "STATUS_IO_DEVICE_ERROR: An I/O device error occurred.",
    0xC000006D: "STATUS_LOGON_FAILURE: The specified account does not exist or the password was incorrect.",
    0xC000007F: "STATUS_INVALID_HANDLE: An invalid handle was specified.",
    0xC00000BB: "STATUS_NOT_SUPPORTED: The request is not supported.",
    0xC00000C0: "STATUS_BAD_NETWORK_PATH: The network path was not found.",
    0xC00000CC: "STATUS_BAD_NETWORK_NAME: The network name cannot be found.",
    0xC00000D3: "STATUS_PIPE_BROKEN: The pipe is broken.",
    0xC00000E1: "STATUS_BUFFER_OVERFLOW: The data area passed to a system call is too small.",
    0xC00000E5: "STATUS_NO_MEMORY: Not enough virtual memory or paging file quota is available to complete the specified operation.",
    0xC0000102: "STATUS_TIMEOUT: The operation timed out.",
    0xC0000185: "STATUS_TRUST_FAILURE: There is a trust relationship problem between the primary domain and the trusted domain.",
    0xC000020C: "STATUS_ACCOUNT_LOCKED_OUT: The referenced account is currently locked out and may not be logged on to.",
    0xC000023C: "STATUS_NETWORK_UNREACHABLE: The network is unreachable.",
    0xC000023D: "STATUS_HOST_UNREACHABLE: The host is unreachable.",
    0xC000023F: "STATUS_CONNECTION_REFUSED: The connection was refused by the remote host.",
    0xC0000240: "STATUS_GRACEFUL_DISCONNECT: A graceful shutdown of the connection was initiated by the peer.",
    0xC0000241: "STATUS_PORT_UNREACHABLE: The remote port is not listening.",
    0xC0000242: "STATUS_CONNECTION_ABORTED: The connection was aborted by the local system or the remote host.",
    0xC0000243: "STATUS_CONNECTION_RESET: The connection was reset by the remote host.",
    0xC0000244: "STATUS_NO_SUCH_DEVICE: The specified device does not exist.",
    0xC0000245: "STATUS_INVALID_DEVICE_REQUEST: The specified device request is invalid.",
    0xC0000246: "STATUS_INVALID_NETWORK_RESPONSE: The network response was invalid.",
    0xC0000247: "STATUS_NETWORK_BUSY: The network is busy.",
    0xC0000248: "STATUS_NO_SUCH_DOMAIN: The specified domain either does not exist or could not be contacted.",
    0xC0000249: "STATUS_NOT_LOGGED_ON: The requested operation is not allowed when the user is not logged on.",
    0xC000024A: "STATUS_NO_LOGON_SERVERS: There are currently no logon servers available to service the logon request.",
    0xC000024B: "STATUS_NO_TRUST_LSA_SECRET: The LSA secret for this trust relationship is not present on this system.",
    0xC000024C: "STATUS_NO_TRUST_SAM_ACCOUNT: The SAM account for this trust relationship is not present on this system.",
    0xC000024D: "STATUS_TRUSTED_DOMAIN_FAILURE: The trusted domain has failed authentication.",
    0xC000024E: "STATUS_TRUSTED_RELATIONSHIP_FAILURE: The trust relationship between the primary domain and the trusted domain has failed.",
    0xC000024F: "STATUS_NTS_INTERNAL_ERROR: An internal error occurred in the NT subsystem.",
    0x5: "ERROR_ACCESS_DENIED: Access is denied. (Win32 error code, sometimes seen)",
    0x2: "ERROR_FILE_NOT_FOUND: The system cannot find the file specified. (Win32 error code, sometimes seen)"
}

SMB_SHARE_TYPES = {
    0x00: {
        'name': "DiskTree",
        'desc': 'A disk share (a normal file system directory).',
    },
    0x01: {
        'name': "PrintQ",
        'desc': 'A print queue share.',
    },
    0x02: {
        'name': "Device",
        'desc': "A communications device share (e.g., serial port).",
    },
    0x03: {
        'name': "IPC",
        'desc': "An interprocess communication (IPC) share (e.g., IPC$).",
    },
    # Less common, but can appear
    0x04: {
        'name': "ClusterFS",
        'desc': "A cluster shared disk.", 
    },
    # Less common, but can appear
    0x08: {
        'name': "DFS",
        'desc': "A Distributed File System (DFS) share.", 
    },
}

def get_share_type(share: SHARE_INFO_1):
    type_set = set()
    type_val = share.fields['shi1_type'].fields['Data']
    if (type_val & 0x80000000):
        type_set.add('Special')
        type_val -= 0x80000000
    if (type_val & 0x10):
        type_set.add('Temporary')
        type_val -= 0x10
    if type_val not in SMB_SHARE_TYPES:
        log.error(
            f'The type {type_val} is not in the known set of SMB share types'
        )
    else:
        type_set.add(SMB_SHARE_TYPES[type_val]['name'])
    return type_set
    
@curry
def get_share_field(field_name: str, share: SHARE_INFO_1):
    raw_name = share.fields[field_name].fields['Data'].fields['Data']
    name = raw_name.decode('utf-16-le')
    if name[-1] == '\x00':
        name = name[:-1]
    return name.strip()

get_share_name = get_share_field('shi1_netname')
get_share_remark = get_share_field('shi1_remark')

def get_share_info(share: SHARE_INFO_1):
    return {
        'type': get_share_type(share),
        'name': get_share_name(share),
        'remark': get_share_remark(share),
    }

smb_err_base_re = re.compile(r'SMB SessionError: (?P<error>.*)$')
smb_err_re = pipe([
    r'code: (?P<code>0x[\w\d]+) - ',
    r'(?P<name>STATUS_[\w_]+)',
    r'STATUS_[\w_]+(?P<desc>.*)$',
], map(re.compile), tuple)

@as_dict
def parse_session_error(err: SessionError):
    err_match = smb_err_base_re.search(str(err))
    if err_match:
        error = err_match.groupdict()['error']
        for regex in smb_err_re:
            m = regex.search(error)
            if m:
                yield m.groupdict()
    else:
        name, desc = err.getErrorString()
        code = str(err.getErrorCode())
        return {
            'code': code, 'name': name, 'desc': desc,
        }

def split_ntlm(hash: str) -> T.Tuple[str|None, str|None]:
    if hash is None:
        return None, None
    if ':' in hash:
        parts = pipe(
            hash.split(':'),
            filter(lambda v: len(v) == 32),
            tuple,
        )
        if len(parts) == 2:
            lm, nt = parts
        elif len(parts) == 1:
            lm, nt = None, parts[0]
        else:
            raise RuntimeError(
                f'Error parsing NTLM hash: {hash}'
            )
    else:
        lm = None
        nt = hash
    return lm, nt

class LoginData(T.NamedTuple):
    domain: str 
    user: str
    password: str
    hashes: str
    ip: str
    socks: bool

    def ntlm(self):
        return split_ntlm(self.hashes)
    
    def nt(self):
        return self.ntlm()[1]
    def lm(self):
        return self.ntlm()[0]


acceptable_socket_errors_re = re.compile(
    r'timed out|No route to host'
)
@curry
def get_client(host: str, *,
               user: str = None, password: str = None, hashes: str = None, 
               domain: str = None) -> SMBConnection | None:
    try:
        client = SMBConnection(
            host, host, timeout=2,
        )
        _lmhash, nthash = split_ntlm(hashes)
        success = client.login(
            user or '', password or '', domain=domain or '', nthash=nthash or '',
        )
        if success:
            return client
        else:
            client.close()
            
    except SessionError as err:
        match parse_session_error(err):
            case {'name': ('STATUS_ACCESS_DENIED'|
                           'STATUS_TRUSTED_RELATIONSHIP_FAILURE'|
                           'STATUS_NO_LOGON_SERVERS'|
                           'STATUS_NETLOGON_NOT_STARTED'|
                           'STATUS_LOGON_FAILURE')}:
                pass
            case other:
                log.error(
                    f'Error creating SMB session on host {host}: {other}'
                )
    except NetBIOSTimeout as to_err:
        log.debug(f'NetBIOS Timeout on {host}')
    except socket.error as socket_err:
        if acceptable_socket_errors_re.search(str(socket_err)):
            pass
        else:
            log.exception(
                f'socket.error getting shares from host {host}'
            )
    except Exception as err:
        if 'No answer!' in str(err):
            log.debug(f'Gave up negotiating SMB handshake on {host}')
        else:
            log.exception(f'Unknown error connecting to {host}: {type(err)} {err}')

@ensure_paths
def win_path(unix_path: Path) -> str:
    return '\\' + pipe(
        unix_path.parts[1:],
        '\\'.join,
    )
def win_dir(unix_path: Path) -> str:
    path = win_path(unix_path)
    return path + ('\\' if unix_path != '/' else '')
def win_list_dir(unix_path: Path) -> str:
    dir = win_dir(unix_path) + '*'
    return dir

class FileType(T.TypedDict):
    ext: str
    content: str

class FileData(T.TypedDict):
    share: str
    is_dir: bool
    is_file: bool
    parent: Path | None
    path: Path
    name: str
    name_short: str
    ext: str | None
    size: int
    mtime: datetime
    ctime: datetime
    atime: datetime
    files: T.Sequence['FileData']
    dirs: T.Sequence['FileData']

    # if get_extended_meta is run 
    type: FileType
    write: bool
    read: bool

new_file_data = lambda d: FileData(d)

@curry
def child_path(path: Path, child: SharedFile) -> Path:
    return path / child.get_longname()

def file_data(share: str, file: SharedFile, parent_path: Path) -> FileData:
    return new_file_data({
        'share': share,
        'is_dir': False,
        'is_file': True,
        'parent': parent_path,
        'path': child_path(parent_path, file),
        'name': file.get_longname(),
        'name_short': file.get_shortname(),
        'ext': get_ext(file.get_longname()),
        'size': file.get_filesize(),
        'mtime': datetime.fromtimestamp(file.get_mtime_epoch()),
        'ctime': datetime.fromtimestamp(file.get_ctime_epoch()),
        'atime': datetime.fromtimestamp(file.get_atime_epoch()),
    })

is_path = lambda v: isinstance(v, Path)
def dir_data(share: str, dir: SharedFile|Path, parent_path: Path,
             files: T.Sequence[Path], dirs: T.Sequence[Path]) -> FileData:
    return new_file_data({
        'share': share,
        'is_dir': True,
        'is_file': False,
        'parent': parent_path,
        'path': dir if is_path(dir) else parent_path / dir.get_longname(),
        'name': dir.parts[-1] if is_path(dir) else dir.get_longname(),
        'name_short': dir.parts[-1] if is_path(dir) else dir.get_shortname(),
        'files': files,
        'dirs': dirs,
    })

def share_key(client: SMBConnection, share: str):
    host = client.getRemoteHost()
    creds = client.getCredentials()
    return (hash(client), host,) + creds + (share,)

_tree_ids = {}
def get_tree_id(client: SMBConnection, share: str) -> int:
    key = share_key(client, share)
    host = client.getRemoteHost()
    if key in _tree_ids:
        return _tree_ids[key]

    tree_id = client.connectTree(rf'\{host}\{share}')
    _tree_ids[key] = tree_id

    return tree_id

def list_dir(client: SMBConnection, share: str, 
             path: Path = None) -> T.Iterator[FileData]:
    path = Path(path or '/')
    children: T.Sequence[SharedFile] = ...
    try:
        children = client.listPath(share, win_list_dir(path))
    except SessionError as err:
        error = parse_session_error(err)
        log.error(
            f'{path}: {error.get("name", "")}'
        )
        children = []

    child_files: T.Sequence[SharedFile] = pipe(
        children,
        filter(lambda f: not f.is_directory()),
    )
    for child in child_files:
        yield file_data(share, child, path)

    child_dirs: T.Sequence[Path] = pipe(
        children,
        filter(lambda f: f.is_directory()),
        filter(lambda f: f.get_longname() not in {'.', '..'}),
    )
    for child in child_dirs:
        yield dir_data(share, child, path, [], [])

class ArgumentError(Exception):
    pass

_readable_shares = {}
@curry
def is_share_readable(client: SMBConnection, share: str|SHARE_INFO_1):
    if isinstance(share, SHARE_INFO_1):
        share = get_share_name(share)
    key = share_key(client, share)
    if key in _readable_shares:
        return _readable_shares[key]
    
    try:
        get_tree_id(client, share)
        _readable_shares[key] = True
    except SessionError as err:
        _readable_shares[key] = False

    return _readable_shares[key]

@curry
def is_dir_writeable(client: SMBConnection, share: str, path: str|Path|FileData):
    tid = get_tree_id(client, share)
    if is_dict(path):
        path = path['path']
    file_path = win_path(Path(path) / f'nsi-dir-write-test-{random_str(16)}')
    try:
        fid = client.createFile(tid, file_path)
        client.closeFile(tid, fid)
        client.deleteFile(share, file_path)
        return True
    except SessionError as serr:
        return False

def _get_share_file(client: SMBConnection, share: str|Path|FileData, 
                    file: str|Path|FileData):
    if is_dict(share):
        file = share
        share = file['share']
    else:
        if file is None:
            raise ArgumentError(
                'If share is not an instance of FileData, then must '
                'provide file argument path/FileData'
            )
        file = get_file_data(client, share, file)
    return share, file

@curry
def is_file_writeable(client: SMBConnection, share: str|Path|FileData, 
                      file: str|Path|FileData = None):
    share, file = _get_share_file(client, share, file)
    tid = get_tree_id(client, share)
    try:
        fid = client.openFile(
            tid, win_path(file['path']), 
            desiredAccess=smb.GENERIC_WRITE,
        )
        client.closeFile(tid, fid)
    except SessionError as smb_error:
        match parse_session_error(smb_error):
            case {'name': ('STATUS_ACCESS_DENIED'|
                           'STATUS_SHARING_VIOLATION')}:
                pass
            case other:
                log.exception(f'SMB error testing file write {file}')
        return False
    except Exception as error:
        log.exception(file)
        return False
    return True

class ShareMetadata(T.TypedDict):
    host: str
    type: set
    name: str
    remark: str
    read: bool
    write: bool

def get_shares_metadata(client: SMBConnection, *, 
                        ignore_printq: bool = True) -> T.Iterable[ShareMetadata]:
    for share_obj in client.listShares():
        info = get_share_info(share_obj)

        if ignore_printq and 'PrintQ' in info['type']:
            continue

        share = info['name']
        meta = merge(info, {
            'read': is_share_readable(client, share),
            'host': client.getRemoteHost(),
        })
        meta = merge(meta, {
            'write': (
                is_dir_writeable(client, share, '/')
                if meta['read'] else False
            ),
        })
        yield meta



def get_file_data(client: SMBConnection, share: str, path: str|Path|FileData):
    if is_dict(path):
        return path
    try:
        path = Path(path)
        files = client.listPath(share, win_path(path))
    except SessionError as err:
        match err.getErrorCode():
            case 0xc000000f:
                log.error(f'No file at {path}')
            case 0xc00000cc:
                log.error(f'No share at {share} for {client.getRemoteHost()}')
            case other:
                log.error(f'Error getting path {err}')
        return None
    return file_data(share, files[0], path.parent)

@curry
def get_extended_meta(client: SMBConnection, share: str|Path|FileData, 
                      file: str|Path|FileData = None) -> FileData:
    share, file = _get_share_file(client, share, file)

    if file['is_dir']:
        return merge(file, {
            'type': FileType({
                'content': 'directory', 'ext': None, 
                'write': is_dir_writeable(client, share, file['path']),
            })
        })

    tid = get_tree_id(client, share)

    can_read_file: bool = False
    try:
        fid = client.openFile(
            tid, win_path(file['path']), desiredAccess=smb.FILE_READ_DATA,
            fileAttributes=smb.ATTR_NORMAL, creationDisposition=smb.FILE_OPEN,
        )
        can_read_file = True
    except SessionError as smb_error:
        match parse_session_error(smb_error):
            case {'name': ('STATUS_ACCESS_DENIED'|
                           'STATUS_SHARING_VIOLATION')}:
                pass
            case other:
                log.exception(f'SMB error testing file write {file}')
    except Exception as error:
        log.exception(f'Unknown exception trying to open file: {file}')

    file_type = 'unknown'
    if can_read_file:
        with tempfile.NamedTemporaryFile(suffix=file['path'].suffix) as temp:
            content = client.readFile(tid, fid, bytesToRead=2**10)

            temp.write(content)
            temp.flush()

            output: str = ...
            status, output = shell.shell(
                f'file {temp.name}', echo=False,
            )
            if status:
                log.error(f'Received status code {status} from file command')
            else:
                file_type = output.split(':', maxsplit=1)[1].strip()

    return merge(file, {
        'type': FileType({
            'content': file_type,
            'ext': type_from_ext(file['name']),
        }),
        'write': is_file_writeable(client, file),
        'read': can_read_file,
    })


@curry
def dir_tree(client: SMBConnection, share: str, path: Path=None,
             parent: FileData|None = None) -> T.Iterator[FileData]:
    path = Path(path or '/')
    children: T.Sequence[FileData] = pipe(
        list_dir(client, share, path), 
        tuple,
    )

    child_files = pipe(children, filter(complement(get('is_dir'))), tuple)
    child_dirs = pipe(children, filter(get('is_dir')), tuple)

    parent = dir_data(
        share,
        path, (parent or {}).get('path'),
        files=pipe(child_files, mget('path'), tuple),
        dirs=pipe(child_dirs, mget('path'), tuple),
    )
    
    yield parent

    yield from child_files

    for child in child_dirs:
        yield from dir_tree(
            client, share, path=child['path'], parent=parent,
        )


def output_dir(data: LoginData, output_dir_path: Path = None):
    dir_path = Path(output_dir_path or '.')
    if data.socks:
        return dir_path / (
            f'.smb-shares-{data.user}-SOCKS'
        )
    user = data.user or "NULL"
    pw_or_hash = (nt(data.password) if data.password else data.hashes) or 'NULL'
    return dir_path / (
        f'.smb-shares-{user}-{pw_or_hash}'
    )

def format_type(type: T.Set[str]):
    type = list(type)
    special = 'Special' in type
    if special:
        type.remove('Special')
    return f"{type[0]}{'*' if special else ''}"

def format_share(share: ShareMetadata):
    host, name, type, remark, read, write = pipe(
        ['host', 'name', 'type', 'remark', 'read', 'write'],
        map(share.get),
        list,
    )
    type = format_type(type)
    read = 'READ' if read else 'NO-ACCESS'
    write = 'WRITE' if write else ''
    return pipe(
        [host, name, type, remark, read, write],
        '\t'.join,
    )

def output_key(data: LoginData) -> T.Tuple[str, str, str, str, bool]:
    return (
        data.domain, data.user, data.password, data.hashes, data.socks,
    )

@curry
def enum_shares_and_output(data: LoginData, output_dirs: dict, force: bool = False):
    output_dir = output_dirs[output_key(data)]
    output_stem = f'{data.ip}'
    json_path = output_dir / f"{output_stem}.json"
    output_path = output_dir / f"{output_stem}.txt"
    if output_path.exists() and not force:
        log.info(f'{output_path} exists... skipping.')
        return 

    client_f = get_client(
        user=data.user, password=data.password, hashes=data.hashes, 
        domain=data.domain,
    )

    def touch_output():
        output_dir.mkdir(exist_ok=True, parents=True)
        output_path.write_text('')

    client = client_f(data.ip)
    if client is None:
        touch_output()
        return

    try:
        metadata = tuple(get_shares_metadata(client))
    except SessionError as error:
        log.error(
            f'Error getting shares with {data}: {parse_session_error(error)}'
        )
        touch_output()
        return
    except socket.error as socket_err:
        if acceptable_socket_errors_re.search(str(socket_err)):
            pass
        else:
            log.exception(
                f'socket.error getting shares with {data}'
            )
    finally:
        client.close()


    output_dir.mkdir(exist_ok=True, parents=True)
    output_path.write_text('')

    pipe(
        metadata,
        json_dumps,
        json_path.write_text,
    )
    
    return pipe(
        metadata,
        map(format_share),
        '\n'.join,
        output_path.write_text,
    )

ntlmrelayx_socks_re = re.compile(
    r'SMB\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<domain>\w+?)/(?P<user>.+?)\s+'
    r'(?P<admin>TRUE|FALSE)\s+445'
)
@curry
def enumerate_smb_shares(ips_or_socks: T.Sequence[str] | str | Path, 
                         domain: str = None, user: str = None, 
                         password: str = None, hashes: str = None, 
                         *,
                         is_socks: bool = False,
                         proxy_host: str = None, proxy_port: int = None,
                         max_workers: int = None, force: bool = False,
                         output_dir_path: Path = None) -> str:

    login_data: T.Sequence[LoginData] = ...

    if is_socks:
        login_data = pipe(
            ips_or_socks,
            slurplines,
            map(groupdict(ntlmrelayx_socks_re)),
            map(get(['domain', 'user', 'ip'], default='')),
            filter(all),
            vmap(lambda d, u, i: LoginData(d, u, None, None, i, True)),
            tuple,
        )
        if not login_data:
            log.error(
                f'SOCKS proxy data yielded no logins: {ips_or_socks}'
            )
    else:
        if is_str(ips_or_socks) or is_path(ips_or_socks):
            if Path(ips_or_socks).exists():
                ip_list = get_ips_from_file(ips_or_socks)
            else:
                # individual target IP or subnet/interface
                ip_list = ip_to_seq(ips_or_socks)
        else:
            ip_list = ips_or_socks or []

        login_data = pipe(
            ip_list,
            map(lambda ip: LoginData(domain, user, password, hashes, ip, False)),
            tuple,
        )
        if not login_data:
            log.error(
                f'IP data produced no logins: {ips}'
            )

    if not login_data:
        log.error(
            'Login data not correct.'
        )
        return 
    
    log.info(
        f'Enumerating SMB shares for {len(login_data)} IP addresses using\n'
        f'   domain: {domain if domain else '.'}\n'
        f'   user: {user if user else 'NULL'}\n' +
        (f'   pass: {password if password else 'NULL'}' 
         if not hashes else f'   nthash: {hashes}')
    )

    output_dirs = pipe(
        login_data,
        groupby(output_key),
        # only socks data should have multiple login information
        valmap(lambda logins: output_dir(logins[0], output_dir_path=output_dir_path)),
    )

    if is_socks:
        if not proxy_host:
            proxy_host = '127.0.0.1'
        if not proxy_port:
            proxy_port = 1080

        socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
        socket.socket = socks.socksocket
    
    pmap_kw = merge(
        {'max_workers': max_workers} if max_workers else {}
    )
    pmap = parallel.thread_map(**pmap_kw)



    pipe(
        login_data,
        pmap(enum_shares_and_output(output_dirs=output_dirs, force=force)),
        tuple,
    )

    @curry
    def as_final_path(ext: str, dir_path: Path) -> Path:
        stem = dir_path.name[1:] # remove the dot prefix
        parent_path = dir_path.resolve().parent
        return parent_path / f'{stem}.{ext}'
    as_txt = as_final_path('txt')
    as_json = as_final_path('json')

    # pipe(
    #     output_dirs.values(),
    #     set,
    #     mapcat(lambda p: p.glob('*.json'))
    # )

    return pipe(
        output_dirs,
        valmap(lambda dir_path: (
            dir_path, 
            set(dir_path.glob('*.txt')),
            set(dir_path.glob('*.json')),
        )),
        valmap(vcall(lambda dir_path, txt_paths, json_paths: (
            dir_path, 
            pipe(
                txt_paths, 
                map(slurp), 
                map(strip()), 
                filter(None),
                '\n'.join,
            ),
            pipe(
                json_paths, 
                mapcat(json_slurp), 
                tuple,
                json_dumps(indent=2),
            ),
        ))),
        values,
        vmap(lambda dir_path, txt_content, json_content: (
            as_txt(dir_path).write_text(txt_content),
            as_json(dir_path).write_text(json_content),
        )),
        tuple,
    )

