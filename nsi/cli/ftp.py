from pathlib import Path
import logging
import pprint

import click

from ..toolz import *
from .. import ftp, logging, shell, parallel, yaml
from . import common

log = new_log(__name__)

@click.group()
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def main(loglevel):
    logging.setup_logging(loglevel)

@main.command()
@common.input_options
@click.option(
    '-o', '--output-dir', type=click.Path(
        resolve_path=True,
    ),
    help=('Output file path'),
)
@common.cred_options
@common.ssh_options
@click.option(
    '--max-workers', type=int, default=5,
    help=(
        'Number of parallel worker threads (default=5)'
    ),
)
@click.option(
    '--echo', is_flag=True,
    help=(
        'Echo the content of the individual commands for debugging purposes'
    ),
)
def anon(ippath, target, output_dir, username, password, 
         domain, ssh, max_workers, echo):

    #echo = echo or loglevel == 'debug'

    if ippath:
        log.info(f'Reading IPs from path: {ippath}')
        ips = get_ips_from_file(ippath)
    elif target:
        log.info(f'Reading IP from target: {target}')
        ips = ip_to_seq(target)
    else:
        log.error('No IP information given')
        raise click.UsageError(
            'No IP information given, provide either'
            ' -i/--ippath or -t/--target'
        )


    getoutput = shell.getoutput(echo=echo)
    if ssh:
        getoutput = common.ssh_getoutput(ssh, echo=echo)

    pmap = parallel.thread_map(max_workers=max_workers)
    pipe(
        ips,
        pmap(lambda ip: (ip, ftp.anon_contents(ip))),
        dict,
        yaml.dump,
        print,
    )

if __name__ == '__main__':
    main()
