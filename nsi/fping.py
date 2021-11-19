'''nmap functionality


'''
from pathlib import Path
import logging
import subprocess
# from subprocess import getoutput
import shlex
from typing import Union, Iterable
from ipaddress import ip_network

from . import toolz as _
from .toolz import (
    pipe, curry, concat,
)
from . import shell, parallel, logging

log = logging.new_log(__name__)

@curry
def fping(ip_or_cidr_or_path, *, args=None, getoutput=shell.getoutput):
    '''Perform an fping scan of some number of hosts

    Args:

      ip_or_cidr_or_path (str/seq/Path): Either an IP (str), a CIDR
        (192.168.1.0/24), a sequence of IPs (list/tuple), or a path to
        a file with a list of IPs (str/Path)

    Optional:

      args (str, dict): Extra fping arguments to pass. Default: None

    '''
    ip_list, cidr = None, None
    if _.is_seq(ip_or_cidr_or_path):
        ip_list = pipe(
            ip_or_cidr_or_path,
            _.strip_comments,
        )
    elif Path(ip_or_cidr_or_path).expanduser().exists():
        ip_list = _.get_ips_from_file(ip_or_cidr_or_path)
    elif _.is_network(ip_or_cidr_or_path):
        n = ip_network(ip_or_cidr_or_path)
        if _.get_slash(n) < 32:
            cidr = ip_or_cidr_or_path
        else:
            ip_list = [ip_or_cidr_or_path]

    if cidr:
        iprange = f'-g {cidr}'
    else:
        iprange = pipe(
            ip_list,
            ' '.join,
        )

    if _.is_dict(args):
        args = pipe(
            args.items(),
            _.vmap(lambda key, val: f'-{key} {val}'),
            ' '.join,
        )
    elif args is None:
        args = '-r 1 -aR'

    command = pipe(
        f'fping {args} {iprange}',
        shlex.split,            # clean up extra whitespace
        ' '.join,
    )
    log.info(f'command: {command}')

    output = getoutput(command)
    log.debug(f'output:\n{output}')

    return _.get_ips_from_str(output)

@curry
def fping_subnets_from_path(cidr_path: Union[str, Path], *,
                            pmap=parallel.thread_map(max_workers=5),
                            **fping_kw):
    '''Perform an fping scan of some number of CIDR subnets stored in path

    '''
    return pipe(
        Path(cidr_path).expanduser().read_text(),
        fping_subnets_from_content(pmap=pmap, **fping_kw),
    )

@curry
def fping_subnets_from_content(cidr_content: Union[bytes, str], *,
                               pmap=parallel.thread_map(max_workers=5),
                               **fping_kw):
    '''Perform an fping scan of some number of CIDR subnets given as
    string/bytes

    '''
    return pipe(
        cidr_content,
        _.get_networks_from_content,
        fping_subnets,
    )

@curry
def fping_subnets(cidr_iter: Iterable[str], *,
                  pmap=parallel.thread_map(max_workers=5),
                  **fping_kw):
    '''Perform an fping scan of some number of CIDR subnets given as list

    '''
    return pipe(
        cidr_iter,
        pmap(lambda n: fping(n, **fping_kw)),
        concat,
    )
