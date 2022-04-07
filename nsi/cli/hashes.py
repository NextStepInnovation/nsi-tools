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

