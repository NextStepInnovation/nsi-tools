'''Tools for dealing with CrackMapExec output
'''
import re
from pathlib import Path
import logging
import json
import typing as T
import pprint

import click
import strip_ansi

from .. import toolz as _
from ..toolz import *
from .. import (
    shell, cme, parallel, logging, yaml,
)
from .common import (
    ssh_options, ssh_getoutput, path_cb_or_stdin, get_content,
)

log = logging.new_log(__name__)




@click.group(
    help='''
    CrackMapExec command
    '''
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def cme_command(loglevel):
    logging.setup_logging(loglevel)





@cme_command.command(
    help='''
    CrackMapExec SMB command

    Hosts are provided from either a file with hosts (-i/--input-path), the
    clipboard content containing hosts information (-c/--from-clipboard), or
    from stdin.

    Forward extra crackmapexec arguments (i.e. ones not already handled by this
    wrapper script) this way:

    $ nsi-cme smb -i targets.txt '--force-ps32 --no-output'

    They will be passed verbatim to the crackmapexec process
    ''', context_settings = dict(
        ignore_unknown_options=True,
    )
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
    '--timeout', default=600, type=int, show_default=True,
    help='''
    Timeout for each CrackMapExec SMB process
    '''
)
@click.option(
    '-u', '--user',
    help='''
    username or file containing usernames
    '''
)
@click.option(
    '-p', '--password', help='''
    password of file containing passwords
    '''
)
@click.option(
    '-d', '--domain', help='''
    domain to authenticate to
    '''
)
@click.option(
    '-S', '--ip-block-size', default=100, help='''
    How many IPs to run at a time
    '''
)
@click.option(
    '-c', '--from-clipboard', is_flag=True,
    help=('Get IPs from clipboard'),
)
@click.option(
    '--force', is_flag=True, help='''
    Force CrackMapExec to run even if already done
    ''',
)
@click.option(
    '--no-ansi', is_flag=True, help='''
    Strip ANSI codes from output
    '''
)
@ssh_options
@click.option('--echo', is_flag=True,
              help='Echo individual command output to stderr')
@click.option(
    '--max-workers', type=int, default=5, help='''
    Maximum threads to use when running CrackMapExec
    '''
)
@click.argument(
    'raw_options', nargs=-1, type=click.UNPROCESSED,
)
def smb(input_path, target, timeout, user, password, domain, ip_block_size,
        from_clipboard, force, no_ansi, ssh, echo, max_workers, raw_options):
    input_path = Path(input_path).expanduser() if input_path else input_path
    input_content = target or path_cb_or_stdin(
        input_path, from_clipboard
    )

    def mdict(k, v):
        return {k: v} if v else {}
    
    options = merge(
        mdict('u', user),
        mdict('p', password), 
        mdict('d', domain), 
        # mdict('smb-timeout', timeout),
    )
    raw_options_str = ' '.join(raw_options)

    ip_list = pipe(
        input_content,
        splitlines,
        _.strip_comments,
        filter(None),
        mapcat(_.ip_to_seq(expand_network=False)),
        sort_ips,
    )

    hashf = hash_object(hash_func=md5)

    inputs_hash = hashf(
        hashf(ip_list) + hashf(options) + raw_options_str
    )
    target_dir_path = Path(f'.cme-target-{inputs_hash}')
    target_dir_path.mkdir(exist_ok=True)
    
    getstatusoutput = shell.getstatusoutput(
        echo=echo, timeout=timeout,
    )
    if ssh:
        raise NotImplementedError(
            'SSH not implemented for CME'
        )
        # getstatusoutput = ssh_getoutput(ssh, echo=echo, timeout=timeout)

    def target_path(i: int):
        return target_dir_path / f'target{i:05}'

    def output_path(i: int):
        path = target_path(i)
        return path.parent / f'{path.stem}.output.txt'
    
    def done_path(i: int):
        path = target_path(i)
        return path.parent / f'{path.stem}.done'

    @curry
    def write_block(i, ips):
        path = target_path(i)
        log.debug(
            f'Writing {len(ips)} IPs to block target: {path}'
        )
        pipe(
            ips,
            '\n'.join,
            lambda s: s + '\n',
            path.write_text,
        )
        return i, path

    ip_blocks = pipe(
        ip_list,
        partition_all(ip_block_size),
        enumerate,
        vmap(write_block),
        tuple,
    )

    log.info(
        f'Running CrackMapExec on {len(ip_blocks)} blocks of IPs of'
        f' size {ip_block_size}'
    )

    cme_command_f = cme.smb_crackmapexec(
        raw_options=raw_options_str, getstatusoutput=getstatusoutput,
        **options,
    )

    def run_cme(i: int, target_path: Path):
        done = done_path(i)
        outpath = output_path(i)
        if done.exists():
            if force:
                log.info(f'... FORCE rerun on {target_path}')
            else:
                log.debug(
                    f'... skipping CME run for {target_path}'
                )
                return outpath.read_text().splitlines()
        success, output = cme_command_f(target_path)
        outpath.write_text(output + '\n')
        if success:
            done.write_text('')
            log.info(f'... done with {target_path}')
        else:
            log.error(
                f'... failed on {target_path}'
            )
        return output.splitlines()

    pipe(
        ip_blocks,
        # take(2),
        parallel.thread_map(vcall(run_cme), max_workers=max_workers),
        concat,
        map(strip()),
        map(strip_ansi.strip_ansi if no_ansi else noop),
        filter(None),
        sorted,
        '\n'.join,
        print,
    )


