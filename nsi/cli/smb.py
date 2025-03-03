'''SMB protocol command-line tools
'''
from pathlib import Path
import logging
import pprint
import re
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
@common.impacket_cred_options
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
    '--socks-proxy-data', type=click.Path(
        exists=True, dir_okay=False,
    ), help='''
    SOCKS5 proxy information from impacket-ntlmrelayx's "socks" command to be
    parsed for domain/username/share information
    '''
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
                         domain, hashes, ssh, max_workers, echo, force, 
                         dry_run, proxychains, socks_proxy_data, loglevel):
    logging.setup_logging(loglevel)
    echo = echo or loglevel == 'debug'

    ip_data = []
    if ippath or target:
        if target:
            log.info(f'Reading IP from target: {target}')
            ips = _.ip_to_seq(target)
        else:
            log.info(f'Reading IPs from path: {ippath}')
            ips = _.get_ips_from_file(ippath)
        ip_data = _.pipe(
            ips,
            _.map(lambda ip: (domain, username, password, hashes, ip)),
            tuple,
        )
    elif socks_proxy_data:
        socks_re = re.compile(
            r'SMB\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<domain>\w+?)/(?P<user>.+?)\s+'
            r'(?P<admin>TRUE|FALSE)\s+445'
        )
        ip_data = _.pipe(
            socks_proxy_data,
            _.slurplines,
            _.map(_.groupdict(socks_re)),
            _.map(_.get(['domain', 'user', 'ip'], default='')),
            _.filter(all),
            _.map(lambda t: (t[0], t[1], '', '', t[2])),
            tuple,
        )
        log.info(
            f'Found {len(ip_data)} IPs to search in SOCKS proxy data'
        )
        log.debug(ip_data)
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

    output_dirs = {
        i[1]: Path(f'.smb-shares-{i[1] or "NULL"}-{_.nt(password)}') 
        for i in ip_data
    } if not output_dir else Path(output_dir)
    for output_dir in set(output_dirs.values()):
        output_dir.mkdir(exist_ok=True, parents=True)

    # output_dir = (
    #     Path(output_dir) if output_dir 
    #     else Path(f'.{username or "NULL"}-{_.nt(password)}-smb-shares')
    # )
    # output_dir.mkdir(exist_ok=True, parents=True)

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
    def enum_shares_and_output(domain, username, password, hashes, ip):
        partial_args = smb.session.new_args(
            domain, username, password, hashes, ip,
            getoutput=getoutput,
            proxychains=proxychains,
            dry_run=dry_run,
        )

        output_dir = output_dirs[username]
        output_path = output_dir / f"{ip}.txt"
        if output_path.exists() and not force:
            log.info(f'{output_path} exists... skipping.')
            return 
        try:
            es_output = smb.session.enum_shares(partial_args(''))
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
                share, smb.session.test_share_perms(partial_args(share['name']))
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
        ip_data,
        pmap(_.vcall(enum_shares_and_output)),
        tuple,
    )

    _.pipe(
        output_dirs.values(),
        set,
        _.mapcat(lambda p: p.glob('*.txt')),
        # output_dir.glob('*.txt'),
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
