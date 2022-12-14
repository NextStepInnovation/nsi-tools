'''Tools for dealing with nmap output
'''
import sys
import re
from pathlib import Path
import logging
import pprint
import ipaddress
import json
import subprocess
import textwrap
import typing as T

import click
import pyperclip

from .. import toolz as _
from ..toolz import (
    pipe, map, map_t, filter, mapcat, xlsx_to_clipboard, groupby, valmap, 
    get, items, vcall, vmap, is_dict, noop, first, ensure_paths, sort_by,
    curry, concat,
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
        noop if no_sort else sorted,
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


@click.command(
    help='''
    Given some set of IPs/subnets run nmap on those devices
    '''

)
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
    '-n', '--no-dns', is_flag=True,
)
@click.option(
    '-A', '--aggressive', is_flag=True,
)
@click.option(
    '-Pn', '--skip-discovery', is_flag=True,
)
@click.option(
    '--output-dir', default='nmap', type=click.Path(file_okay=False),
    help=('Directory where output host files will be placed'),
)
@click.option(
    '--timeout', default=600, type=int, show_default=True,
    help='''
    Timeout for each nmap process
    '''
)
@click.option(
    '--stem-prefix',
    help='''
    Prefix to add to output filename stem (i.e. name without extension) for each
    host to scan.
    '''
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
               skip_discovery, output_dir, timeout, stem_prefix, force, 
               from_clipboard, ssh, echo, loglevel):
    '''Nmap scanner

    Hosts are provided from either a file with hosts
    (-i/--input-path), the clipboard content containing hosts
    information (-c/--from-clipboard), or from stdin.

    '''
    logging.setup_logging(loglevel)

    ip_list, ip_dict = None, None

    input_path = Path(input_path).expanduser() if input_path else input_path
    if input_path and nmap.is_gnmap(input_path):
        ip_dict = pipe(
            input_path,
            nmap.parse_gnmap,
            groupby('ip'),
            valmap(first),
            valmap(lambda D: pipe(
                D['ports'],
                map(get('port')),
                tuple,
            )),
        )
        #log.info(ip_dict)
    else:
        input_content = target or path_cb_or_stdin(
            input_path, from_clipboard
        )

        ip_list = pipe(
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

    getoutput = shell.getoutput(
        echo=echo, timeout=timeout,
    )
    if ssh:
        getoutput = ssh_getoutput(ssh, echo=echo, timeout=timeout)

    nmap_command = nmap.nmap(
        top_ports=top_ports, force=force, stem_prefix=stem_prefix,
        skip_discovery=skip_discovery, aggressive=aggressive, no_dns=no_dns,
        getoutput=getoutput,
    )
    if ports:
        nmap_command = nmap_command(ports=ports)

    pmap = parallel.thread_map(max_workers=5)

    if ip_dict:
        pipe(
            ip_dict,
            items,
            _.shuffled,
            pmap(
                vcall(lambda ip, ports: nmap_command(ip, ports=ports))
            ),
            tuple,
        )
    else:
        pipe(
            ip_list,
            pmap(lambda ip: nmap_command(ip)),
            tuple,
        )


def get_services(path):
    log.info(f'Loading YAML path: {path}')
    data = yaml.read_yaml(path)
    ports = data.get('host', {}).get('ports', {}).get('port', [])
    if is_dict(ports):
        ports = [ports]
    for port in ports:
        port_number  = port.get('portid')
        service = port.get('service', {})
        if port_number and service and 'product' in service:
            yield (int(port_number), service['product'])

def get_services_from_json(path):
    log.info(f'Loading JSON path: {path}')
    
    with Path(path).expanduser().open() as rfp:
        return pipe(
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
    '--no-names', is_flag=True,
)
@click.option(
    '--must-have-service', is_flag=True,
)
@click.option(
    '-e', '--exclude-list', type=click.Path(exists=True)
)
@click.option(
    '-i', '--include-list', type=click.Path(exists=True)
)
@click.option(
    '--max-col-width', default=50, help='''
    Maximum column width, otherwise text is wrapped. (NOT IMPLEMENTED YET)
    ''',
)
@click.option(
    '--tsv', is_flag=True, help='''
    Output in tab-separated value form
    ''',
)
@click.option('--loglevel', default='info')
def nmap_services(paths, no_ports, no_names, must_have_service, loglevel, 
                  exclude_list, include_list, max_col_width, tsv):
    '''
    For some number of either JSON-encoded or grep-able nmap NMAP outputs, print
    out services found

    '''
    logging.setup_logging(loglevel)

    exclude_list = pipe(
        exclude_list,
        _.get_ips_from_file,
    ) if exclude_list else []

    include_list = pipe(
        include_list,
        _.get_ips_from_file,
    ) if include_list else []

    @ensure_paths
    def get_services(path: Path):
        match path:
            case Path(suffix='.json'):
                return get_services_from_json(path)
            case Path(suffix='.gnmap'):
                return pipe(
                    nmap.parse_gnmap(path),
                    mapcat(lambda host: [{
                        'ip': host['ip'],
                        'iptup': _.ip_tuple(host['ip']),
                        'name': host['name'],
                        'port': p['port'],
                        'guess': p['guess'],
                        'service': p['service'],
                    } for p in host['ports']]),
                    tuple,
                )

        
    rows = pipe(
        paths,
        parallel.thread_map(get_services),
        concat,
        filter(lambda r: (r['ip'] not in exclude_list) if exclude_list else True ),
        filter(lambda r: (r['ip'] in include_list) if include_list else True ),
        filter(lambda r: (bool(r['service'])) if must_have_service else True ),
        sort_by(get(['port', 'iptup'])),
        map(get(
            ['ip'] + 
            (['name'] if not no_names else []) + 
            (['port'] if not no_ports else []) + 
            ['guess', 'service',]
        )),
        map(map_t(str)),
        tuple,
    )

    # def visual_row(col_maxes: T.Sequence[int], max_col_width: int, 
    #                row: T.Sequence[str]) -> T.Iterable[T.Sequence[str]]:
    #     if not any(m > max_col_width for m in col_maxes):
    #         return [
    #             f'{v}:<{m}' for m, v in zip(col_maxes, row)
    #         ]
    #     new_row = pipe(
    #         zip(col_maxes, row),
    #     )

    @curry
    def visual_table(max_col_width: int, rows: T.Iterable[T.Sequence[str]]) -> str:
        rows = tuple(rows)
        col_maxes = pipe(
            rows,
            map(map_t(len)),
            lambda rows: zip(*rows),
            map(max),
            tuple,
        )
        log.info(col_maxes)
        col_formats = pipe(
            col_maxes,
            map(lambda m: f'{{0:<{m}}}'),
            tuple,
        )
        log.info(col_formats)
        def visual_row(row):
            return [
                f.format(v) for f, v in zip(col_formats, row)
            ]

        return pipe(
            rows,
            map(visual_row),
            map(' '.join),
            '\n'.join,
        )


    def tsv_table(rows: T.Iterable[T.Sequence[str]]) -> str:
        return pipe(
            rows,
            map('\t'.join),
            '\n'.join,
        )

    pipe(
        rows,
        tsv_table if tsv else visual_table(max_col_width),
        print,
    )

