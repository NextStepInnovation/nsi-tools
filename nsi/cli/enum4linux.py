'''Tools for dealing with enum4linux output
'''
import click

from .common import get_input_content
from ..toolz import pipe, vmap
from ..enum4linux import user_re

@click.command()
@click.option(
    '-i', '--inpath',
    help=('Path of enum4linux file to parse for users. If empty,'
          ' pull from stdin.'),
    type=click.Path(exists=True),
)
@click.option(
    '-c', '--from-clipboard', is_flag=True,
    help=('Get enum4linux output from clipboard'),
)
def dump_users(inpath, from_clipboard):
    '''Given output from enum4linux (either from input path (-i), from the
    clipboard (-c), or from stdin (neither -i or -c), dump all users
    found to stdout

    '''
    content = get_input_content(inpath, from_clipboard)

    return pipe(
        user_re.findall(content),
        vmap(lambda user, rid: f'{user}\t{rid}'),
        '\n'.join,
        print,
    )
