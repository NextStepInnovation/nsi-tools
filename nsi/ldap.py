from pathlib import Path
import typing as T

import ldap3

from . import logging
from .toolz import *

log = logging.new_log(__name__)

class Server(T.TypedDict):
    host: str
    port: int
    use_ssl: bool
    get_info: str

def new_server(host: str, port: int, use_ssl: bool = None, 
               get_info: str = ldap3.ALL, **server_kw) -> Server:
    ssl = True if (port == 636 and use_ssl is None) else (use_ssl or False)
    return pipe(
        merge({
            'host': host, 'port': port, 'use_ssl': ssl, 'get_info': get_info,
        }, server_kw),
        Server,
    )

_servers = {}
@curry
def get_server(server: Server|ldap3.Server) -> ldap3.Server:
    if isinstance(server, ldap3.Server):
        return server
    host, port = get(['host', 'port'], server)
    if (host, port) in _servers:
        return _servers[(host, port)]
    log.info(server)
    server = ldap3.Server(**server)
    _servers[(host, port)] = server
    return server

@curry
def get_connection(server: Server, *, raise_exceptions: bool = True):
    conn = ldap3.Connection(
        get_server(server), raise_exceptions=raise_exceptions,
    )
    conn.bind()
    return conn
