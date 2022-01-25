'''Tools for dealing with hashes
'''
import re
import sys
from pathlib import Path

import click

from ..toolz import *
from .. import ntlm


@click.command()
@click.option(
    '-i', '--inpath',
    help=('Path of file to parse for hashes. If empty, pull from stdin.'),
    type=click.Path(exists=True),
)
@click.option(
    '-S', '--sam', is_flag=True,
    help='Extract SAM hashes? (assume true if no flags set)'
)
@click.option(
    '-M', '--mscache', is_flag=True,
    help='Extract MS Cache hashes ($DC02$...)?',
)
def dump_hashes(inpath, sam, mscache):
    if inpath:
        content = Path(inpath).read_text()
    else:
        content = sys.stdin.read()

    def hash_content(hashes):
        return pipe(
            hashes,
            vmap(lambda u, h: f'{u}:{h}'),
            '\n'.join,
        )
            
    if sam or mscache:
        pipe(
            ((ntlm.get_sam_hashes(content) if sam else ()) +
             (ntlm.get_mscache_hashes(content) if mscache else ())),
            hash_content,
            print,
        )
    else:
        pipe(
            ntlm.get_sam_hashes(content),
            hash_content,
            print,
        )

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
    '-T', '--table', is_flag=True,
    help=('Output in Markdown table form'),
)
def ntlm_resolve(hashes, potfile, table):
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

    def tr_f(u, h):
        return f'| `{u}` | `{h2pt[h]}` |'

    row_formatter = tr_f if table else lambda u, h: f'{u}\t{h2pt[h]}'

    return pipe(
        u2h.items(),
        sorted,
        vmap(lambda u, h: (u, h.split(':')[-1])),
        vfilter(lambda u, h: h in h2pt),
        vmap(row_formatter),
        '\n'.join,
        print,
    )
