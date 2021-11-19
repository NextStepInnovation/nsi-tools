'''Tools for dealing with enum4linux output
'''
import sys
import re
from pathlib import Path

import click
import pyperclip
from toolz import pipe, curry, dissoc, merge
from toolz.curried import map, filter, mapcat, do

from ..common import (
    get_sam_hashes, get_mscache_hashes, vmap,
)

ip_re = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
spool_ip_re = re.compile(
    fr'^.*?\[\+\].*?({ip_re}):(\d+)\s+(.*)', re.M,
)

@click.command(
    help=('Given a spool file (or file content from stdin) from'
          ' MSF, parse out all IPs associated with success'),
)
@click.option(
    '-i', '--inpath',
    help=('Path of file to parse for IPs. If empty, pull from stdin.'),
    type=click.Path(exists=True),
)
@click.option(
    '-C', '--clipboard-read',
    help=('Pull content from clipboard'),
    is_flag=True,
)
def dump_spool_ips(inpath, clipboard_read):
    if inpath:
        content = Path(inpath).read_text()
    elif clipboard_read:
        content = pyperclip.paste()
    else:
        content = sys.stdin.read()

    return pipe(
        spool_ip_re.findall(content),
        vmap(lambda ip, port, desc: f'{ip}\t# {port}: {desc}'),
        '\n'.join,
        print,
    )
