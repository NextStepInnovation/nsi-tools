from pathlib import Path
import itertools
import pprint
from re import search

import click
import pyperclip

from .. import logging
from ..toolz import *
from .. import ntlm, logging, parallel
from . import common

log = new_log(__name__)

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
