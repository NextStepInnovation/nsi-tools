'''DNS tools

'''
import json as _json
from pathlib import Path
from datetime import datetime, timedelta
import math
import time

import click
import toolz.curried as _
import larc
import larc.common as __

from .. import dns
from .. import bloodhound
from .common import ssh_getoutput, ssh_options

log = larc.logging.new_log(__name__)

@click.command()
@click.option(
    '-i', '--inpath', type=click.Path(exists=True),
)
@click.option(
    '--bh', is_flag=True,
)
@click.option(
    '-o', '--outpath', type=click.Path(),
)
@ssh_options
@click.option(
    '--echo', is_flag=True,
    help=(
        'Echo the content of the individual commands for debugging purposes'
    ),
)
@click.option(
    '-S', '--dns-server',
)
@click.option(
    '-c', '--from-clipboard', is_flag=True,
)
@click.option(
    '-C', '--to-clipboard', is_flag=True,
)
@click.option(
    '--csv', is_flag=True, help='Output to CSV',
)
@click.option(
    '--json', is_flag=True, help='Output to JSON',
)
@click.option(
    '--yaml', is_flag=True, help='Output to YAML',
)
@click.option(
    '--max-threads', default=5, help='Max threads',
)
@click.option(
    '--keep-duplicates', is_flag=True, help='Keep duplicate DNS entries',
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def dns_resolve(inpath, bh, outpath, ssh, echo, dns_server, from_clipboard,
                to_clipboard, csv, json, yaml, max_threads,
                keep_duplicates, loglevel):
    larc.logging.setup_logging(loglevel)

    if bh:
        hosts = bloodhound.parser.get_computer_names(inpath)
    else:
        hosts = _.pipe(
            larc.cli.common.path_cb_or_stdin(inpath, from_clipboard).splitlines(),
        )
        
    getoutput = larc.shell.getoutput(echo=echo)
    if ssh:
        getoutput = ssh_getoutput(ssh, echo=echo)

    def print_format(hosts):
        max_len = _.pipe(
            hosts,
            _.map(lambda h: h['name']),
            __.maybe_max(key=len),
            len,
        )
        return _.pipe(
            hosts,
            _.map(lambda h: (f"{h['name'].rjust(max_len)}:"
                             f" {h['ip']}")),
            '\n'.join,
        )

    def csv_format(hosts):
        return __.csv_rows_to_content(
            hosts, columns=['name', 'ip'],
        )

    def json_format(hosts):
        return _json.dumps(hosts)

    def yaml_format(hosts):
        return larc.yaml.dump({'hosts': hosts})

    formatter = print_format
    if csv:
        formatter = csv_format

    if json:
        formatter = json_format

    if yaml:
        formatter = yaml_format

    outputter = print
    if outpath:
        def outputter(data):
            with Path(outpath).open('a') as afp:
                afp.write(data + '\n')

    def _dedup(hosts):
        seen = set()
        for h in hosts:
            key = (h['name'], h['ip'])
            if key not in seen:
                yield h
                seen.add(key)
    dedup = _.compose_left(_dedup, tuple)
        
    pipeline = _.compose_left(
        dns.resolve_hosts(getoutput=getoutput, dns_server=dns_server,
                          max_workers=max_threads),
        __.sort_by(lambda h: (h['name'], __.ip_tuple(h['ip']))),
        __.do_nothing if keep_duplicates else dedup,
        formatter,
        outputter,
    )

    start = datetime.now()
    N = len(hosts)
    chunk_size = 100
    n_chunks = math.ceil(N / chunk_size)
    total_delta = timedelta(seconds=0)
    for i, chunk in enumerate(_.partition_all(chunk_size, hosts)):
        current = datetime.now()
        pipeline(chunk)
        delta = datetime.now() - current
        total_delta += delta
        avg_delta = total_delta / (i + 1)
        log.info(
            f'Average delta: {avg_delta}\t'
            f'Time left: {avg_delta * (n_chunks - (i + 1))}'
        )
