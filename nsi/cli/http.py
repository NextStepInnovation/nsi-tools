'''HTTP protocol command-line tools
'''
# import gevent.monkey; gevent.monkey.patch_all()
from pathlib import Path
import multiprocessing
import logging
import pprint
import json
import sys
import urllib; from urllib.parse import ParseResult
import random
import typing as T

import click
import pyperclip
from ..toolz import (
    pipe, curry, compose, map, filter, do, groupby, mapcat, ensure_paths, noop,
    vcall, compose_left, ip_to_seq, vmap,
)

from .. import toolz as _
from .. import parallel, logging, http

log = logging.new_log(__name__)

shared_options = compose_left(
    click.option(
        '-i', '--input-path', type=click.Path(
            exists=True, dir_okay=False, resolve_path=True,
        ),
        help='''
        Path with list of input data (IP addresses, ports, etc) to scan, one
        unit per line
        ''',
    ),
    click.option(
        '-u', '--url', help='''
        Specific URL to target
        '''
    ),
    click.option(
        '-t', '--target',
        help=('Target of enumeration (IP, IP network'),
    ),
    click.option(
        '-p', '--port', type=int,
        help='Port number for HTTP server',
    ),
    click.option(
        '-P', '--path', help='''
        Root path to append to all lookups
        '''
    ),
    click.option(
        '--no-ssl', is_flag=True,
        help='Disable SSL for connections',
    ),
    click.option(
        '--ssl', is_flag=True,
        help='Enable SSL for connections',
    ),
    click.option(
        '-U', '--ssh-user',
        help='SSH user to use when connecting to the host for this command',
    ),
    click.option(
        '-H', '--ssh-host',
        help='SSH host to connect to when executing this command',
    ),
    click.option(
        '--force', is_flag=True,
        help='Run regardless of existing output files',
    ),
    click.option(
        '--randomize', is_flag=True,
        help='Randomize IPs'
    ),
    click.option(
        '--dry-run', is_flag=True, help='''
        Don't actually run the command
        ''',
    ),
    click.option(
        '--loglevel', default='info',
        help=('Log output level (default: info)'),
    ),
)

@ensure_paths
def ip_port_ssl(ssl: bool, port: int, path: Path):
    for i, line in enumerate(path.read_text().splitlines()):
        match line.split():
            case (ip, ):
                yield (ip, port, ssl)
            case (ip, port):
                yield (ip, port, ssl)
            case (ip, port, ssl):
                yield (ip, port, True if 'ssl' in ssl.lower() else False)
            case error:
                log.error(
                    f'Problem with line {i} in path {path}: {line}'
                )

@curry
def host_dir(output_dir_path: str|Path, ip):
    path = Path(output_dir_path, f'{ip}')
    return path

@curry
def output_raw(host_dir_f: T.Callable[[str|Path, str], Path], prefix: str, 
               ip: str, port: int):
    return Path(host_dir_f(ip), f'{prefix}-{port}.txt')

@curry
def output_json(host_dir_f: T.Callable[[str|Path, str], Path], prefix: str,
                ip: str, port: int):
    return Path(host_dir_f(ip), f'{prefix}-{port}.json')

@curry
def should_run(output_json_f: T.Callable[[str], Path], force: bool, 
               prefix: str, ip: str):
    if force:
        log.info(f'[{prefix}]  ... FORCE rerun')
        return True
    path = output_json_f(ip)
    if not path.exists():
        return True
    log.info(f'[{prefix}]  ... {path} exists, skipping {ip}')
    return False

@curry
def run_and_output(output_raw_f: T.Callable[[str], Path], 
                   output_json_f: T.Callable[[str], Path], 
                   command_f: T.Callable[[str, int, bool], T.Tuple[str, dict]],
                   prefix: str, dry_run: bool,
                   ip: str, port: int, ssl: bool) -> T.Tuple[str, Path, Path]:
    raw_path = output_raw_f(ip, port)
    json_path = output_json_f(ip, port)
    log.info(
        f'{prefix} output: {raw_path} JSON output: {json_path}'
    )
    if dry_run:
        log.warning(
            f'DRY RUN: not running for ip: {ip} port: {port} ssl: {ssl}'
        )

    output, data = command_f(ip, port, ssl, dry_run)

    if dry_run:
        log.warning(
            f'DRY RUN: not writing to {raw_path} {json_path}'
        )
    else:
        raw_path.parent.mkdir(exist_ok=True, parents=True)
        raw_path.write_text(output)
        json_path.parent.mkdir(exist_ok=True, parents=True)
        pipe(
            json.dumps(data, indent=2),
            json_path.write_text,
        )
    return ip, raw_path, json_path
    

@click.command()
@shared_options
@click.option(
    '-o', '--output-dir', type=click.Path(), default='dirb',
    show_default=True, help='Directory path for dirb output',
)
@click.option(
    '--timeout', type=int, default=http.DIRB_TIMEOUT, show_default=True,
    help=f'''
    Timeout for individual dirb processess in seconds
    ''',
)
def dirb_ips(input_path, url, target, port, path, no_ssl, ssl, ssh_user, ssh_host,
             force, randomize, dry_run, loglevel, output_dir, timeout, ):
    '''Use dirb to enumerate webservers at various IP addressses.

    Provide either (-i/--input-path) as file with list of IP
    addresses/networks/interfaces or (-t/--target) with single one of
    the same.

    Examples of input file formats:

    192.168.1.1 (one IP per line)

    192.168.1.1 8080 (one IP [ws] one port per line)

    192.168.1.1 8080 ssl (one IP [ws] one port [ws] one string with "ssl" per line)

    '''
    logging.setup_logging(loglevel)
    ssl, port = http.get_ssl_port(ssl, no_ssl, port)

    if input_path:
        log.info(f'Reading IPs from path: {input_path}')

        ip_data = tuple(ip_port_ssl(ssl, port, input_path))
    elif target:
        log.info(f'Reading IP from target: {target}')
        ip_data = [
            (ip, port, ssl) for ip in ip_to_seq(target)
        ]
    else:
        log.error('No IP information given')
        raise click.UsageError(
            'No IP information given, provide either'
            ' -i/--input-path or -t/--target'
        )

    output_dir_path = Path(output_dir).expanduser().resolve()

    host_dir_f = host_dir(output_dir_path)
    output_raw_f = output_raw(host_dir_f, 'dirb')
    output_json_f = output_json(host_dir_f, 'dirb')

    should_run_f = should_run(output_json_f, force)

    command_f = lambda ip, port, ssl, dry_run: http.dirb(
        ip, port=port, ssl=ssl, timeout=timeout, dry_run=dry_run, path=path,
    )

    run_f = vcall(run_and_output(
        output_raw_f, output_json_f, command_f, 'dirb', dry_run,
    ))

    pmap = parallel.thread_map(max_workers=5)

    return pipe(
        ip_data,
        (
            (lambda ips: random.sample(ips, len(ips)))
            if randomize else lambda x: x
        ),
        filter(should_run_f),
        pmap(run_f),
        tuple,
        compose_left(pprint.pformat, log.info)
    )
    

@click.command()
@shared_options
@click.option(
    '-o', '--output-dir', type=click.Path(), default='nikto',
    show_default=True, help='Directory path for nikto output',
)
@click.option(
    '--timeout', type=int, default=http.NIKTO_TIMEOUT, show_default=True,
    help=f'''
    Timeout for individual nikto processess in seconds
    ''',
)
def nikto_ips(input_path, url, target, port, path, ssl, no_ssl, ssh_user, ssh_host,
              force, randomize, dry_run, loglevel, output_dir, timeout, ):
    '''Use nikto to enumerate webservers at various IP addresses/URLs.

    Provide either (-i/--input-path) as file with list of IP
    addresses/networks/interfaces, (-t/--target) with single one of
    the same, or (-u/--url) with an explicit URL to target.

    '''
    logging.setup_logging(loglevel)

    ssl, port = http.get_ssl_port(ssl, no_ssl, port)

    if input_path:
        log.info(f'Reading IPs from path: {input_path}')

        ip_data = tuple(ip_port_ssl(ssl, port, input_path))
    elif target:
        log.info(f'Reading IP from target: {target}')
        ip_data = [
            (ip, port, ssl) for ip in ip_to_seq(target)
        ]
    elif url:
        log.info(f'Targeting a specific URL: {url}')
        purl = urllib.parse.urlparse(url)
        # if 
        # port = 
        ip_data = [
            (url, port, ssl)
        ]
    else:
        log.error('No IP information given')
        raise click.UsageError(
            'No IP information given, provide either'
            ' -i/--input-path or -t/--target'
        )
    
    output_dir_path = Path(output_dir).expanduser().resolve()

    host_dir_f = host_dir(output_dir_path)
    output_raw_f = output_raw(host_dir_f, 'nikto')
    output_json_f = output_json(host_dir_f, 'nikto')

    should_run_f = should_run(output_json_f, force)

    command_f = lambda ip, port, ssl, dry_run:  http.nikto(
        ip, port=port, ssl=ssl, timeout=timeout, dry_run=dry_run, path=path,
    )

    run_f = vcall(run_and_output(
        output_raw_f, output_json_f, command_f, 'nikto', dry_run,
    ))

    pmap = parallel.thread_map(max_workers=5)

    return pipe(
        ip_data,
        (
            (lambda ips: random.sample(ips, len(ips)))
            if randomize else lambda x: x
        ),
        filter(should_run_f),
        pmap(run_f),
        tuple,
        compose_left(pprint.pformat, lambda s: log.info(f'outcome tuple: {s}'))
    )

    # ssl, port = http.get_ssl_port(ssl, no_ssl, port)
    
    # if input_path:
    #     log.info(f'Reading IPs from path: {input_path}')
    #     ips = _.get_ips_from_file(input_path)
    # elif target:
    #     log.info(f'Reading IP from target: {target}')
    #     ips = _.ip_to_seq(target)
    # else:
    #     log.error('No IP information given')
    #     raise click.UsageError(
    #         'No IP information given, provide either'
    #         ' -i/--input_path or -t/--target'
    #     )

    # output_dir_path = Path(output_dir).expanduser().resolve()

    # def host_dir(ip):
    #     path = Path(output_dir_path, f'{ip}')
    #     return path

    # def output_raw(ip):
    #     return Path(host_dir(ip), f'nikto-{port}.txt')

    # def output_json(ip):
    #     return Path(host_dir(ip), f'nikto-{port}.json')

    # def should_do_nikto(ip):
    #     if force:
    #         log.info(f'[nikto]  ... FORCE rerun')
    #         return True
    #     path = output_json(ip)
    #     if not path.exists():
    #         return True
    #     log.info(f'[nikto]  ... {path} exists, skipping {ip}')
    #     return False

    # if port == 443 and not no_ssl:
    #     ssl = True
        
    # nikto = http.nikto(port=port, ssl=ssl, timeout=timeout)
    # pmap = parallel.thread_map(max_workers=5)
    # def nikto_and_output(ip):
    #     raw_path = output_raw(ip)
    #     json_path = output_json(ip)
    #     log.info(
    #         f'Nikto output: {raw_path} JSON output: {json_path}'
    #     )
    #     output, data = nikto(ip)
    #     raw_path.parent.mkdir(exist_ok=True, parents=True)
    #     raw_path.write_text(output)
    #     json_path.parent.mkdir(exist_ok=True, parents=True)
    #     pipe(
    #         json.dumps(data, indent=2),
    #         json_path.write_text,
    #     )
    #     return ip, raw_path, json_path
        
    # pipe(
    #     ips,
    #     (
    #         (lambda ips: random.sample(ips, len(ips)))
    #         if randomize
    #         else noop
    #     ),
    #     do(print),
    #     filter(should_do_nikto),
    #     pmap(nikto_and_output),
    #     tuple,
    #     lambda t: log.info(f'{pprint.pformat(t)}')
    # )

