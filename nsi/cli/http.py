'''HTTP protocol command-line tools
'''
# import gevent.monkey; gevent.monkey.patch_all()
from pathlib import Path
import multiprocessing
import logging
import pprint
import json
import sys
import random

import click
import pyperclip
import toolz.curried as _
from toolz.curried import (
    pipe, curry, compose, map, filter, do, groupby, mapcat,
)

from .. import toolz as _
from .. import parallel, logging, http

log = logging.new_log(__name__)

@click.command()
@click.option(
    '-i', '--ippath', type=click.Path(
        exists=True, dir_okay=False, resolve_path=True,
    ),
    help=('Path with list of IP addresses to scan, one IP per line'),
)
@click.option(
    '-t', '--target',
    help=('Target of enumeration (IP, IP network'),
)
@click.option(
    '-p', '--port', type=int,
    help='Port number for HTTP server',
)
@click.option(
    '--no-ssl', is_flag=True,
    help='Disable SSL for connections',
)
@click.option(
    '--ssl', is_flag=True,
    help='Enable SSL for connections',
)
@click.option(
    '--timeout', type=int, default=http.DIRB_TIMEOUT,
    help=(
        'Timeout for individual dirb processes in seconds'
        f' (default: {http.DIRB_TIMEOUT})'
    ),
)
@click.option(
    '-U', '--ssh-user',
    help='SSH user to use when connecting to the host for this command',
)
@click.option(
    '-H', '--ssh-host',
    help='SSH host to connect to when executing this command',
)
@click.option(
    '-o', '--output-dir', type=click.Path(), default='dirb',
    help='Output directory for dirb output (default "dirb")',
)
@click.option(
    '--force', is_flag=True,
    help='Run dirb regarless of existing output files',
)
@click.option(
    '--randomize', is_flag=True,
    help='Randomize IPs'
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def dirb_ips(ippath, target, port, no_ssl, ssl, timeout, ssh_user, ssh_host,
             output_dir, force, randomize, loglevel):
    '''Use dirb to enumerate webservers at various IP addressses.

    Provide either (-i/--ippath) as file with list of IP
    addresses/networks/interfaces or (-t/--target) with single one of
    the same.

    '''
    logging.setup_logging(loglevel)
    ssl, port = http.get_ssl_port(ssl, no_ssl, port)

    if ippath:
        log.info(f'Reading IPs from path: {ippath}')
        ips = _.get_ips_from_file(ippath)
    elif target:
        log.info(f'Reading IP from target: {target}')
        ips = _.ip_to_seq(target)
    else:
        log.error('No IP information given')
        raise click.UsageError(
            'No IP information given, provide either'
            ' -i/--ippath or -t/--target'
        )

    output_dir_path = Path(output_dir).expanduser().resolve()

    def host_dir(ip):
        path = Path(output_dir_path, f'{ip}')
        return path

    def output_raw(ip):
        return Path(host_dir(ip), f'dirb-{port}.txt')

    def output_json(ip):
        return Path(host_dir(ip), f'dirb-{port}.json')

    def should_do_dirb(ip):
        if force:
            log.info(f'[dirb]  ... FORCE rerun')
            return True
        path = output_json(ip)
        if not path.exists():
            return True
        log.info(f'[dirb]  ... {path} exists, skipping {ip}')
        return False

    dirb = http.dirb(port=port, ssl=ssl, timeout=timeout)

    pmap = parallel.thread_map(max_workers=5)
    def dirb_and_output(ip):
        raw_path = output_raw(ip)
        json_path = output_json(ip)
        log.info(
            f'Dirb output: {raw_path} JSON output: {json_path}'
        )
        output, data = dirb(ip)
        raw_path.parent.mkdir(exist_ok=True, parents=True)
        raw_path.write_text(output)
        json_path.parent.mkdir(exist_ok=True, parents=True)
        pipe(
            json.dumps(data, indent=2),
            json_path.write_text,
        )
        return ip, raw_path, json_path
        
    pipe(
        ips,
        (
            (lambda ips: random.sample(ips, len(ips)))
            if randomize else lambda x: x
        ),
        filter(should_do_dirb),
        pmap(dirb_and_output),
        tuple,
        lambda t: log.info(f'{pprint.pformat(t)}')
    )
    
    # pipe(
    #     ips,
    #     filter(should_do_dirb),
    #     parallel.thread_map(lambda ip: (ip, dirb(ip)), max_workers=5),
    #     _.vmap(lambda ip, output: (
    #         ip,
    #         output_raw(ip).write_text(output[0]),
    #         output_json(ip).write_text(json.dumps(output[1], indent=2)),
    #     )),
    #     tuple,
    #     lambda t: log.info(f'{pprint.pformat(t)}')
    # )

    # format_shares = compose(
    #     '\n'.join,
    #     map(lambda d: f'//{d["ip"]}/{d["name"]}\t{d["type"]}\t{d["desc"]}'),
    # )

    # print(format_shares(shares))


@click.command()
@click.option(
    '-i', '--ippath', type=click.Path(
        exists=True, dir_okay=False, resolve_path=True,
    ),
    help=('Path with list of IP addresses to scan, one IP per line'),
)
@click.option(
    '-t', '--target',
    help=('Target of enumeration (IP, IP network'),
)
@click.option(
    '-p', '--port', type=int,
    help='Port number for HTTP server',
)
@click.option(
    '--no-ssl', is_flag=True,
    help='Disable SSL for connections',
)
@click.option(
    '--ssl', is_flag=True,
    help='Enable SSL for connections',
)
@click.option(
    '--timeout', type=int, default=http.NIKTO_TIMEOUT,
    help=(
        'Timeout for individual nikto processes in seconds'
        f' (default: {http.NIKTO_TIMEOUT})'
    ),
)
@click.option(
    '-U', '--ssh-user',
    help='SSH user to use when connecting to the host for this command',
)
@click.option(
    '-H', '--ssh-host',
    help='SSH host to connect to when executing this command',
)
@click.option(
    '-o', '--output-dir', type=click.Path(), default='nikto',
    help='Output directory for nikto output (default "nikto")',
)
@click.option(
    '--force', is_flag=True,
    help='Run nikto regarless of existing output files',
)
@click.option(
    '--randomize', is_flag=True,
    help='Randomize IPs'
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def nikto_ips(ippath, target, port, ssl, no_ssl, timeout, ssh_user, ssh_host,
              output_dir, force, randomize, loglevel):
    '''Use nikto to enumerate webservers at various IP addressses.

    Provide either (-i/--ippath) as file with list of IP
    addresses/networks/interfaces or (-t/--target) with single one of
    the same.

    '''
    logging.setup_logging(loglevel)

    ssl, port = http.get_ssl_port(ssl, no_ssl, port)
    
    if ippath:
        log.info(f'Reading IPs from path: {ippath}')
        ips = _.get_ips_from_file(ippath)
    elif target:
        log.info(f'Reading IP from target: {target}')
        ips = _.ip_to_seq(target)
    else:
        log.error('No IP information given')
        raise click.UsageError(
            'No IP information given, provide either'
            ' -i/--ippath or -t/--target'
        )

    output_dir_path = Path(output_dir).expanduser().resolve()

    def host_dir(ip):
        path = Path(output_dir_path, f'{ip}')
        return path

    def output_raw(ip):
        return Path(host_dir(ip), f'nikto-{port}.txt')

    def output_json(ip):
        return Path(host_dir(ip), f'nikto-{port}.json')

    def should_do_nikto(ip):
        if force:
            log.info(f'[nikto]  ... FORCE rerun')
            return True
        path = output_json(ip)
        if not path.exists():
            return True
        log.info(f'[nikto]  ... {path} exists, skipping {ip}')
        return False

    if port == 443 and not no_ssl:
        ssl = True
        
    nikto = http.nikto(port=port, ssl=ssl, timeout=timeout)
    pmap = parallel.thread_map(max_workers=5)
    def nikto_and_output(ip):
        raw_path = output_raw(ip)
        json_path = output_json(ip)
        log.info(
            f'Nikto output: {raw_path} JSON output: {json_path}'
        )
        output, data = nikto(ip)
        raw_path.parent.mkdir(exist_ok=True, parents=True)
        raw_path.write_text(output)
        json_path.parent.mkdir(exist_ok=True, parents=True)
        pipe(
            json.dumps(data, indent=2),
            json_path.write_text,
        )
        return ip, raw_path, json_path
        
    pipe(
        ips,
        (
            (lambda ips: random.sample(ips, len(ips)))
            if randomize
            else _.do_nothing
        ),
        do(print),
        filter(should_do_nikto),
        pmap(nikto_and_output),
        tuple,
        lambda t: log.info(f'{pprint.pformat(t)}')
    )

    # format_shares = compose(
    #     '\n'.join,
    #     map(lambda d: f'//{d["ip"]}/{d["name"]}\t{d["type"]}\t{d["desc"]}'),
    # )

    # print(format_shares(shares))
