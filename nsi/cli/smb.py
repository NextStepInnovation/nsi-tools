'''SMB protocol command-line tools
'''
from pathlib import Path
import logging
import pprint
from weakref import proxy

import click

from .. import toolz as _
from .. import (
    parallel, shell, logging, smb,
)
from . import common

log = logging.new_log(__name__)

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
    '--proxychains', is_flag=True,
    help='Run with proxychains',
)
@click.option(
    '--dry-run', is_flag=True,
    help="Don't run command",
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def enumerate_smb_shares(ippath, output_dir, target, username, password, 
                         domain, ssh, max_workers, echo, force, 
                         dry_run, proxychains, loglevel):
    logging.setup_logging(loglevel)
    echo = echo or loglevel == 'debug'

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

    if proxychains:
        log.info('Using proxychains...')

    getoutput = shell.getoutput(echo=echo, dry_run=dry_run)
    if ssh:
        getoutput = common.ssh_getoutput(ssh, echo=echo, dry_run=dry_run)

    partial_args = smb.session.new_args(
        domain, username, password, 
        getoutput=getoutput,
        proxychains=proxychains,
        dry_run=dry_run,
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
        ) if d['perms'] else 'NO-ACCESS'
    
    def format_share(d):
        return (
            f'//{d.get("ip")}/{d["name"]}\t'
            f'{d["type"]}\t{d["comment"]}\t'
            f'{format_perms(d)}'
        )

    @_.curry
    def enum_shares_and_output(output_dir, ip):
        output_path = output_dir / f"{ip}.txt"
        if output_path.exists() and not force:
            log.info(f'{output_path} exists... skipping.')
            return 
        try:
            es_output = smb.session.enum_shares(partial_args(ip, ''))
        except Exception as error:
            log.exception(
                f'Problem with enum_shares for {ip}'
            )
            raise

        output_path.write_text('')
        
        return _.pipe(
            es_output,
            _.map(_.cmerge({'user': username, 'pass': password})),
            _.map(lambda share: (
                share, smb.session.test_share_perms(partial_args(
                    share['ip'], share['name'],
                ))
            )),
            _.vmap(lambda share, output: (
                share, _.maybe_first(output, default={})
            )),
            _.vmap(lambda share, perms: _.merge(
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
@click.argument('path')
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
@click.option(
    '--proxychains', is_flag=True,
    help='Run with proxychains',
)
@click.option(
    '--dry-run', is_flag=True,
    help="Don't run command",
)
def smb_ls(host, path, share, username, password, domain, ssh, max_workers,
           echo, timeout, loglevel, proxychains, dry_run):
    '''Get 

    '''
    logging.setup_logging('debug' if dry_run else loglevel)

    echo = echo or loglevel == 'debug'

    getoutput = shell.getoutput(echo=echo)
    if ssh:
        getoutput = common.ssh_getoutput(ssh, echo=echo)

    parts = list(Path(path).parts)
    if path.endswith('/'):
        parts[-1] += '/'

    def format_file(d):
        {
            'raw_error': 'STATUS_ACCESS_DENIED', 'error': {'no_access'}, 
            'error_line': 'session setup failed: NT_STATUS_ACCESS_DENIED',
        }
        match d:
            case {'name': name, 'type': type, 'size': size, 'dt': dt}:
                ts = dt.strftime('%Y-%m-%dT%H%M%S')
                return (
                    f"{ts}\t{name}\t{type}\t{size}"
                )
            case {'error': error, 'path': path} if 'no_access' in error:
                return (
                    f'ERROR: no access to {path}'
                )
            case {'raw_error': raw_error, 'error': errors, 'error_line': line}:
                return (
                    f'ERROR: {raw_error} --> {line}'
                )
            case other:
                log.error(
                    f'Unhandled file: {other}'
                )
        return ''
    
    _.pipe(
        smb.session.smbclient_ls(
            domain, username, password, host, share, *parts,
            getoutput=getoutput, proxychains=proxychains, dry_run=dry_run,
        ),
        _.map(format_file),
        _.filter(None),
        '\n'.join,
        print,
    )
