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

from .. import toolz as _
from ..toolz import (
    pipe, map, filter, mapcat, xlsx_to_clipboard,
)
from .. import (
    shell, parallel, logging, nmap, yaml,
)
from .common import (
    ssh_options, ssh_getoutput, path_cb_or_stdin, get_content,
)

log = logging.new_log(__name__)

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
        _.noop if no_sort else sorted,
        map(str),
        sep.join,
        print if stdout or not clipboard else xlsx_to_clipboard,
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
        print if not clipboard else xlsx_to_clipboard,
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
    logging.setup_logging(loglevel)

    input_content = target or path_cb_or_stdin(
        input_path, from_clipboard
    )

    ips = pipe(
        input_content,
        lambda c: c.splitlines(),
        _.strip_comments,
        filter(None),
        mapcat(_.ip_to_seq),
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
        getoutput=getoutput,
    )

    pmap = parallel.thread_map(max_workers=5)

    pipe(
        ips,
        pmap(nmap_command),
        tuple,
    )


def get_services(path):
    log.info(f'Loading YAML path: {path}')
    data = yaml.read_yaml(path)
    ports = data.get('host', {}).get('ports', {}).get('port', [])
    if _.is_dict(ports):
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
            nmap.get_services_from_nmap_dict,
        )
            
@click.command()
@click.argument(
    'paths', nargs=-1,
)
@click.option(
    '--no-ports', is_flag=True,
)
@click.option(
    '-e', '--exclude-list', type=click.Path(exists=True)
)
@click.option(
    '-i', '--include-list', type=click.Path(exists=True)
)
@click.option('--loglevel', default='info')
def nmap_services(paths, no_ports, loglevel, exclude_list, include_list):
    '''
    For some number of either JSON-encoded or grep-able nmap NMAP outputs, print
    out services found

    '''
    logging.setup_logging(loglevel)

    exclude_list = pipe(
        exclude_list,
        _.get_ips_from_file,
    ) if exclude_list else []
    log.info(f'Excluding IPs: {exclude_list}') if exclude_list else None

    include_list = pipe(
        include_list,
        _.get_ips_from_file,
    ) if include_list else []
    log.info(f'Including IPs: {include_list}') if include_list else None

    @_.ensure_paths
    def get_services(path: Path):
        match path:
            case Path(suffix='.json'):
                return get_services_from_json(path)
            case Path(suffix='.gnmap'):
                return pipe(
                    nmap.parse_gnmap(path),
                    _.mapcat(lambda host: [
                        (
                            host['ip'],
                            host['name'],
                            p['port'],
                            p['guess'],
                            p['service'],
                        )
                        for p in host['ports']
                    ]),
                    tuple,
                )

        
    _.pipe(
        paths,
        parallel.thread_map(get_services),
        _.concat,
        _.sort_by(lambda r: ipaddress.ip_address(r[0])),
        _.filter(lambda r: r[0] not in exclude_list) if exclude_list else _.noop,
        _.filter(lambda r: r[0] in include_list) if include_list else _.noop,
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
