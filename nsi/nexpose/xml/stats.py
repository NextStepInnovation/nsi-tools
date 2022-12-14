'''
Statistics about Nexpose XML reports
'''
import typing as T
from pathlib import Path
import re

from sqlalchemy.orm import (
    Session, Query,
)

from .types import Ip
from .db import (
    ingest_report, Node, Finding,
)
from ...toolz import *

__all__ = [
    'get_session', 
    'all_nodes', 'all_findings',
    'with_os', 'without_os',
    'is_windows', 'is_win_server', 'is_win_client',
    'win_servers', 'win_clients',
]

_sessions = {}

@ensure_paths
def get_session(xml_path: Path) -> Session:
    if xml_path not in _sessions:
        _sessions[xml_path] = ingest_report(xml_path)
    return _sessions[xml_path]

def all_nodes(xml_path: Path) -> T.Iterable[Node]:
    yield from get_session(xml_path).query(Node)

@curry
def with_os(os_regex: str, node: Node, case_insensitive: bool = True):
    return bool(re.search(os_regex, node.os, (re.I if case_insensitive else 0)))
without_os = complement(with_os)

is_windows = with_os('windows')
is_win_server = compose_left(
    juxt(is_windows, with_os('server')),
    all,
)
is_win_client = compose_left(
    juxt(is_windows, complement(with_os('server'))),
    all,
)

NodeFilter = T.Callable[
    [T.Iterable[Node]], T.Iterable[Node]
]
win_servers: NodeFilter = compose_left(filter(is_win_server))
win_clients: NodeFilter = compose_left(filter(is_win_client))
non_win_nodes: NodeFilter = compose_left(
    filter(complement(is_windows)),
)

def get_ips(nodes: T.Iterable[Node]) -> T.Sequence[Ip]:
    return pipe(
        (n.address for n in nodes),
        sort_ips,
    )

@curry
def get_node_ips(filter_f: NodeFilter, xml_path: Path) -> T.Sequence[Ip]:
    return pipe(
        all_nodes(xml_path),
        filter_f,
        get_ips,
        tuple,
    )
win_server_ips = get_node_ips(win_servers)
win_client_ips = get_node_ips(win_clients)
non_win_ips = get_node_ips(non_win_nodes)
all_ips = get_node_ips(lambda *_: True)

def all_findings(xml_path: Path) -> T.Iterable[Finding]:
    yield from get_session(xml_path).query(Finding)

class IpStats(T.TypedDict):
    windows_clients: T.Sequence[Ip]
    windows_servers: T.Sequence[Ip]
    non_windows: T.Sequence[Ip]

class NodeStats(T.TypedDict):
    ips: IpStats


def node_stats(xml_path: Path) -> NodeStats:
    return NodeStats({
        'ips': IpStats({
            'windows_clients': win_client_ips(xml_path),
            'windows_servers': win_server_ips(xml_path),
            'non_windows': non_win_ips(xml_path),
        }),
    })
