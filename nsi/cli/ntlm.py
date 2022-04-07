from pathlib import Path
import itertools
import pprint
import re
from re import search

import click
import pyperclip

from .. import logging
from ..toolz import *
from .. import ntlm, logging, parallel
from . import common

log = new_log(__name__)

@click.command()
@click.option(
    '-h', '--hashes',
    help=('Path of file to parse for hashes. If empty, pull from stdin.'),
    type=click.Path(exists=True), required=True,
)
@click.option(
    '-p', '--potfile',
    help=('Path of file to parse for hashes. If empty, pull from stdin.'),
    type=click.Path(exists=True), required=True,
)
@click.option(
    '-a', '--admins', type=click.Path(exists=True),
    help=('Path of file with domain/local administrator names'),
)
@click.option(
    '-T', '--table', is_flag=True,
    help=('Output in Markdown table form'),
)
@click.option(
    '-C', '--to-clipboard', is_flag=True,
    help=('Send output to clipboard'),
)
@click.option(
    '--loglevel', default='info',
)
def resolve(hashes, potfile, admins, table, to_clipboard, loglevel):
    logging.setup_logging(loglevel)

    ntlm_re = re.compile(r'^[0-9a-f]{32}:.*')
    u2h = pipe(
        hashes,
        slurp,
        ntlm.get_sam_hashes,
        groupby('full_user'),
        valmap(first),
        valmap(get('hashes')),
    )
    h2pt = pipe(
        Path(potfile).read_text().splitlines(),
        map(lambda l: l.strip()),
        filter(ntlm_re.search),
        map(lambda l: l.split(':')),
        dict
    )

    admins = pipe(
        admins,
        slurplines,
        map(strip),
        map(lower),
        set,
    ) if admins else set()
    if admins:
        log.info(
            f'Found {len(admins)} admin account names'
        )

    def is_admin(u: str):
        name = u.split('/')[-1]
        return name in admins

    def tr_f(u, h):
        return f'| `{u or " "}` | `{h2pt[h] or " "}` |' + (
            (f' **Yes** |' if is_admin(u) else '  |') 
            if admins else ''
        )

    row_formatter = tr_f if table else lambda u, h: f'{u}\t{h2pt[h]}'

    return pipe(
        u2h.items(),
        sorted,
        vmap(lambda u, h: (u, h.split(':')[-1])),
        vfilter(lambda u, h: h in h2pt),
        vmap(row_formatter),
        '\n'.join,
        pyperclip.copy if to_clipboard else print,
    )

@click.command()
@click.argument(
    'search-paths', nargs=-1,
    type=click.Path(exists=True),
)
@click.option(
    '-c', '--from-clipboard', is_flag=True,
    help=('Get NTLM hashes from clipboard'),
)
@click.option(
    '-C', '--to-clipboard', is_flag=True,
    help=('Send NTLM hashes to clipboard'),
)
@click.option(
    '-o', '--output-path', type=click.Path(),
    help=('File to send NTLM hashes to')
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def extract(search_paths, from_clipboard, to_clipboard, output_path, loglevel):
    logging.setup_logging(loglevel)

    hashes = []
    
    if search_paths:
        search_paths = pipe(
            search_paths,
            map(lambda p: Path(p).expanduser()),
        )
        log.info(
            f'Searching the following paths for NTLM hashes:'
        )
        hashes = pipe(
            search_paths,
            mapdo(lambda p: log.info(f' - {p} ({p.stat().st_size} B)')),
            mapcat(ntlm.parse_ntlm_from_path),
        )

    if from_clipboard:
        clipboard = pyperclip.paste()
        log.info(
            f'Searching clipboard content for NTLM hashes ({len(clipboard)} B)'
        )
        hashes = pipe(
            clipboard,
            ntlm.parse_ntlm_from_content,
            cconcat(hashes),
        )

    hashes = tuple(hashes)
    log.info(
        f'Found {len(hashes)} hashes'
    )

    hashes_str = pipe(hashes, '\n'.join)

    output_path = pipe(
        Path(output_path).expanduser().resolve(),
        do(lambda p: p.parent.mkdir(exist_ok=True, parents=True)),
    ) if output_path else None

    outputter = pyperclip.copy if to_clipboard else (
        output_path.write_text if output_path else print
    )

    pipe(
        hashes_str,
        outputter,
    )
