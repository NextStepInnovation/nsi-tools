import os
import sys
import typing as T
import re
from pathlib import Path

from impacket.smbconnection import SMBConnection
from impacket.smb import SessionError

from .. import logging
from ..toolz import *

log = logging.new_log(__name__)

'''
0x0000: ('MB_FILE_ATTRIBUTE_NORMAL', 'Normal file.'),
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
'''

smb_err_re = re.compile(
    r'SMB SessionError: code: (?P<code>0x[\w\d]+) - (?P<name>[\w_]+) - (?P<desc>.*)$'
)

def get_client(user: str, host: str, 
               password: str=None, nthash: str=None, 
               domain: str=None) -> T.Tuple[bool, SMBConnection | None]:
    try:
        client = SMBConnection(host, host)
        client.login(user, password,
            **merge(
                {'nthash': nthash} if nthash else {},
                {'domain': domain} if domain else {},
            )
        )
        return True, client
    except SessionError as err:
        log.exception(
            'Problem creating client'
        )
        
    return False, None

@ensure_paths
def win_path(unix_path: Path) -> str:
    return '\\' + pipe(
        unix_path.parts[1:],
        '\\'.join,
    )

