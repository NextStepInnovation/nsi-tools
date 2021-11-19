'''SMB protocol command-line tools
'''
# import gevent.monkey; gevent.monkey.patch_all()
from pathlib import Path
import logging
import pprint

import click
import toolz.curried as _
from larc import common as __
from larc import parallel
from larc import shell
from larc.logging import setup_logging

from .. import smb
from . import common

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

@click.command()
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
@click.option(
    '--force', is_flag=True,
    help='Force run'
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def enumerate_smb_shares(ippath, output_dir, target, username, password, 
                         domain, ssh, max_workers, echo, force, loglevel):
    setup_logging(loglevel)
    echo = echo or loglevel == 'debug'

    if ippath:
        log.info(f'Reading IPs from path: {ippath}')
        ips = __.get_ips_from_file(ippath)
    elif target:
        log.info(f'Reading IP from target: {target}')
        ips = __.ip_to_seq(target)
    else:
        log.error('No IP information given')
        raise click.UsageError(
            'No IP information given, provide either'
            ' -i/--ippath or -t/--target'
        )


    getoutput = shell.getoutput(echo=echo)
    if ssh:
        getoutput = common.ssh_getoutput(ssh, echo=echo)

    enum_shares = smb.session.enum_shares(
        domain, username, password, getoutput=getoutput,
    )
    test_share_perms = smb.session.test_share_perms(
        domain, username, password, getoutput=getoutput,
    )

    output_dir = (
        Path(output_dir) if output_dir 
        else Path(f'.{username}-smb-shares')
    )
    output_dir.mkdir(exist_ok=True, parents=True)

    # pmap = parallel.thread_map(max_workers=20)
    pmap = parallel.thread_map(max_workers=max_workers)
    
    def format_perms(d):
        return _.pipe(
            d['perms'],
            sorted,
            _.map(lambda s: s.upper()),
            ', '.join,
        ) if d['perms'] else 'NO ACCESS'
    
    def format_share(d):
        return (
            f'//{d["ip"]}/{d["name"]}\t'
            f'{d["type"]}\t{d["desc"]}\t'
            f'{format_perms(d)}'
        )

    @_.curry
    def enum_shares_and_output(output_dir, ip):
        output_path = output_dir / f"{ip}.txt"
        if output_path.exists() and not force:
            log.info(f'{output_path} exists... skipping.')
            return 
        try:
            es_output = enum_shares(ip)
        except Exception as error:
            log.exception(
                f'Problem with enum_shares for {ip}'
            )
            raise

        output_path.write_text('')
        
        return _.pipe(
            es_output,
            _.map(__.cmerge({'user': username, 'pass': password})),
            _.map(lambda share: (
                share, test_share_perms(share['ip'], share['name'])
            )),
            __.vmap(lambda share, output: (
                share, __.maybe_first(output, default={})
            )),
            __.vmap(lambda share, perms: _.merge(
                share, {'perms': perms},
            )),
            _.map(lambda share: (share, format_share(share))),
            tuple,
            _.do(
                lambda all_data: _.pipe(
                    all_data,
                    _.map(_.second),
                    '\n'.join,
                    output_path.write_text,
                )
            ),
            _.map(_.first),
            tuple,
        )

    _.pipe(
        ips,
        pmap(enum_shares_and_output(output_dir)),
        tuple,
    )

    _.pipe(
        output_dir.glob('*.txt'),
        _.map(lambda p: p.read_text().strip()),
        _.filter(None),
        '\n'.join,
        print,
    )
    # _.pipe(
    #     ips,
    #     pmap(enum_shares),
    #     _.mapcat(lambda dicts: _.pipe(
    #         dicts,
    #         _.map(__.cmerge({'user': username, 'pass': password})),
    #         tuple,
    #     )),
    #     _.filter(None),
    #     pmap(lambda share: (
    #         share, test_share_perms(share['ip'], share['name'])
    #     )),
    #     __.vmap(lambda share, output: (
    #         share, __.maybe_first(output, default={})
    #     )),
    #     __.vmap(lambda share, perms: _.merge(
    #         share, {'perms': perms},
    #     )),
    #     _.map(format_share),
    #     '\n'.join,
    #     print,
    # )


@click.command()
@click.argument('host')
@click.argument('share')
@click.argument('path', required=False)
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
@click.option(
    '--timeout', type=int,
    help=('Timeout for SMB operation'),
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def smb_ls(host, path, share, username, password, domain, ssh, max_workers,
           echo, timeout, loglevel):
    '''Get 

    '''
    setup_logging(loglevel)

    echo = echo or loglevel == 'debug'

    # if ippath:
    #     log.info(f'Reading IPs from path: {ippath}')
    #     ips = __.get_ips_from_file(ippath)
    # elif target:
    #     log.info(f'Reading IP from target: {target}')
    #     ips = __.ip_to_seq(target)
    # else:
    #     log.error('No IP information given')
    #     raise click.UsageError(
    #         'No IP information given, provide either'
    #         ' -i/--ippath or -t/--target'
    #     )

    getoutput = shell.getoutput(echo=echo)
    if ssh:
        getoutput = common.ssh_getoutput(ssh, echo=echo)

    if path:
        parts = _.pipe(
            path.split('/'),
            _.map(lambda p: p if p else '/'),
        )
    else:
        parts = []

    def format_file(d):
        print(d)
        ts = d['dt'].strftime('%Y-%m-%dT%H%M%S') if 'dt' in d else ''
        return (
            f"{ts}\t{d['name']}\t{d['type']}\t{d['size']}"
        )
    
    _.pipe(
        smb.session.smbclient_ls(
            domain, username, password, host, share, *parts,
            getoutput=getoutput, 
        ),
        _.map(format_file),
        '\n'.join,
        print,
    )
