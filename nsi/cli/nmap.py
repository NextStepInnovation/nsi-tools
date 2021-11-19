'''Tools for dealing with nmap output
'''
import sys
import re
from pathlib import Path
import logging
import pprint
import ipaddress
import json

import click
import pyperclip
from toolz import pipe, curry, dissoc, merge
from toolz.curried import map, filter, mapcat, do
import toolz.curried as _

import larc
import larc.common as __
from larc import common, shell, parallel
from larc.logging import setup_logging
from larc.cli import common as cli_common

from .. import nmap
from ..common import (
    get_sam_hashes, get_mscache_hashes, get_content, xlsx_pbcopy,
)
from .common import (
    ssh_options, ssh_getoutput,
)

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

nmap_port_re = re.compile(r'^(\d+)/tcp\s+open.*$', re.M)

def get_ports_from_content(content):
    return pipe(
        nmap_port_re.findall(content),
        map(int),
    )

@click.command(
    help=('Given data output from nmap, find all the ports found'),
)
@click.argument(
    'inpath',
    required=False,
    type=click.Path(exists=True),
)
@click.option(
    '-C', '--clipboard', is_flag=True,
    help=('Get IPs from clipboard, send sorted to clipboard'),
)
@click.option(
    '--stdout', is_flag=True,
    help='Force output to stdout',
)
@click.option(
    '--no-sort', is_flag=True,
    help='Do not sort the ports',
)
@click.option(
    '--sep', help='separator for ports (default: newline)',
    default='\n',
)
def nse_ports(inpath, clipboard, stdout, no_sort, sep):
    content = get_content(inpath, clipboard)

    return pipe(
        get_ports_from_content(content),
        common.do_nothing if no_sort else sorted,
        map(str),
        sep.join,
        print if stdout or not clipboard else xlsx_pbcopy,
    )


@click.command(
    help=('Given PATHA and PATHB of nmap outputs, print'
          ' port difference (A-B)'),
)
@click.argument(
    'patha',
    type=click.Path(exists=True),
)
@click.argument(
    'pathb',
    type=click.Path(exists=True),
)
@click.option(
    '-C', '--clipboard', is_flag=True,
    help=('Send sorted ports to clipboard'),
)
def diff_ports(patha, pathb, clipboard):
    ports_a = set(get_ports_from_content(Path(patha).read_text()))
    ports_b = set(get_ports_from_content(Path(pathb).read_text()))

    return pipe(
        ports_a - ports_b,
        sorted,
        map(str),
        '\n'.join,
        print if not clipboard else xlsx_pbcopy,
    )


@click.command()
@click.option(
    '-i', '--input-path', type=click.Path(dir_okay=False, exists=True),
    help=('Path with targets to scan'),
)
@click.option(
    '-t', '--target',
    help=('Target of scan (IP, IP range, CIDR)'),
)
@click.option(
    '-p', '--ports',
    help='Ports to scan',
)
@click.option(
    '--top-ports', type=int,
    help='Scan the top N ports'
)
@click.option(
    '--no-dns', is_flag=True,
)
@click.option(
    '-A', '--aggressive', is_flag=True,
)
@click.option(
    '--skip-discovery', is_flag=True,
)
@click.option(
    '-o', '--output-dir', default='nmap', type=click.Path(file_okay=False),
    help=('Directory where output host files will be placed'),
)
@click.option(
    '-P', '--prefix',
    help='Prefix/namespace for output files'
)
@click.option(
    '--force', is_flag=True,
)
@click.option(
    '-c', '--from-clipboard', is_flag=True,
    help=('Get IPs from clipboard'),
)
@ssh_options
@click.option('--echo', is_flag=True,
              help='Echo individual command output to stderr')
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def nmap_hosts(input_path, target, ports, top_ports, no_dns, aggressive,
               skip_discovery, output_dir,
               prefix, force, from_clipboard, ssh, echo, loglevel):
    '''Nmap scanner

    Hosts are provided from either a file with hosts
    (-i/--input-path), the clipboard content containing hosts
    information (-c/--from-clipboard), or from stdin.

    '''
    setup_logging(loglevel)

    input_content = target or cli_common.path_cb_or_stdin(
        input_path, from_clipboard
    )

    ips = pipe(
        input_content,
        lambda c: c.splitlines(),
        common.strip_comments,
        filter(None),
        mapcat(common.ip_to_seq),
        tuple,
    )

    output_dir_path = Path(output_dir).expanduser()
    if not output_dir_path.exists():
        log.info(f'Creating output directory: {output_dir_path}')
        output_dir_path.mkdir(parents=True)

    # def host_dir(ip):
    #     path = Path(output_dir_path, f'{ip}')
    #     path.mkdir(exist_ok=True, parents=True)
    #     return path

    getoutput = shell.getoutput(echo=echo)
    if ssh:
        getoutput = ssh_getoutput(ssh, echo=echo)

    nmap_command = nmap.cached_nmap(
        output_dir_path, ports=ports, top_ports=top_ports, force=force,
        skip_discovery=skip_discovery, aggressive=aggressive, no_dns=no_dns,
    )

    pmap = parallel.thread_map(max_workers=5)

    pipe(
        ips,
        pmap(nmap_command),
        tuple,
    )


def get_services(path):
    log.info(f'Loading YAML path: {path}')
    data = larc.yaml.read_yaml(path)
    ports = data.get('host', {}).get('ports', {}).get('port', [])
    if __.is_dict(ports):
        ports = [ports]
    for port in ports:
        port_number  = port.get('portid')
        service = port.get('service', {})
        if port_number and service and 'product' in service:
            yield (int(port_number), service['product'])

def get_services_from_json(path):
    log.info(f'Loading JSON path: {path}')
    
    with Path(path).expanduser().open() as rfp:
        return _.pipe(
            json.load(rfp),
            nmap.get_services_from_yaml,
        )
            
@click.command()
@click.argument(
    'paths', nargs=-1,
)
@click.option(
    '--no-ports', is_flag=True,
)
@click.option('--loglevel', default='info')
def nmap_services(paths, no_ports, loglevel):
    '''For some number of YAML-encoded NMAP outputs, print out services
    found

    '''
    # get_services_from_json(paths[0])
        
    _.pipe(
        paths,
        larc.parallel.thread_map(get_services_from_json),
        _.concat,
        __.sort_by(lambda r: ipaddress.ip_address(r[0])),
        _.map('\t'.join),
        '\n'.join,
        print
    )

    # def service_str(t):
    #     if no_ports:
    #         return t[1]
    #     return f'{t[0]:>8}: {t[1]}'

    # _.pipe(
    #     services,
    #     map(service_str),
    #     set,
    #     lambda L: sorted(L) if no_ports else L,
    #     '\n'.join,
    #     print,
    # )
