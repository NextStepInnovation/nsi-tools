from pathlib import Path

import click

from .. import toolz as _
from .. import whois, logging, yaml, parallel
from . import common

log = logging.new_log(__name__)

@_.curry
def output_whois(outdir, host):
    outpath = outdir / f'{host}.yml'
    return _.pipe(
        {host: whois.whois(host)},
        yaml.dump,
        outpath.write_text,
    )

@click.command()
@common.inpath
@common.outdir
@common.from_clipboard
@click.option(
    '--max-workers', default=5, type=int,
    help='Maximum thread-level concurrency (default: 5)'
)
@common.loglevel
def whois_ips(inpath, outdir, from_clipboard, max_workers, loglevel):
    logging.setup_logging(loglevel)
    content = common.get_content(inpath, from_clipboard)

    outpath = Path(outdir)
    outpath.mkdir(exist_ok=True, parents=True)

    ips = _.pipe(
        content.splitlines(),
        _.map(_.strip_comments),
        _.filter(lambda l: l.strip()),
        _.filter(_.compose_left(_.strip_comments, _.strip, _.is_ip)),
        _.sortips,
    )

    log.info(f'Looking up {len(ips)} IPs')
    output = _.pipe(
        ips,
        parallel.thread_map(output_whois(outpath), max_workers=max_workers),
        tuple,
    )
    log.info(output[0])


