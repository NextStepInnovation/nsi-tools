'''fping CLI tools

'''
# import gevent.monkey; gevent.monkey.patch_all()
import logging

import click
from toolz.curried import (
    pipe, map, filter, mapcat, merge,
)
from larc import common
from larc import parallel
from larc import shell
from larc.logging import setup_logging
from larc.cli import common as cli_common

from .. import fping
from .common import ssh_getoutput, ssh_options

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

@click.command()
@click.option(
    '-i', '--cidr-path', type=click.Path(
        exists=True, dir_okay=False, resolve_path=True,
    ),
    help=('Path with list of CIDR networks to scan, one CIDR per line'),
)
@click.option(
    '-t', '--target',
    help=('Target of fping scan (single CIDR)'),
)
@ssh_options
@click.option(
    '--echo', is_flag=True,
    help=(
        'Echo the content of the individual commands for debugging purposes'
    ),
)
@click.option(
    '-c', '--from-clipboard', is_flag=True,
)
@click.option(
    '-C', '--to-clipboard', is_flag=True,
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def fping_subnets(cidr_path, target, ssh, echo,
                  from_clipboard, to_clipboard, loglevel):
    setup_logging(loglevel)

    if target:
        subnets = [target]
    else:
        subnets = pipe(
            cli_common.path_cb_or_stdin(cidr_path, from_clipboard),
            common.get_networks_from_content,
        )

    getoutput = shell.getoutput(echo=echo)
    if ssh:
        getoutput = ssh_getoutput(ssh, echo=echo)

    # pmap = parallel.gevent_map(max_workers=5)
    pmap = parallel.thread_map(max_workers=5)
    # pmap = parallel.process_map(max_workers=5)

    print_f = common.clipboard_copy if to_clipboard else print
    pipe(
        subnets,
        fping.fping_subnets(pmap=pmap, getoutput=getoutput),
        common.sort_ips,
        '\n'.join,
        print_f,
    )
