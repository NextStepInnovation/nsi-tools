'''Bloodhound tools

'''
from pathlib import Path

import click

from ..toolz import *
from .. import logging

from .. import bloodhound
from .common import ssh_getoutput, ssh_options

log = logging.new_log(__name__)

bh_list = compose_left(
    click.command(),
    click.option(
        '-i', '--inpath', type=click.Path(exists=True),
    ),
    click.option(
        '-o', '--outpath', type=click.Path(),
    ),
    ssh_options,
    click.option(
        '--echo', is_flag=True,
        help=(
            'Echo the content of the individual commands for'
            ' debugging purposes'
        ),
    ),
    click.option(
        '-c', '--from-clipboard', is_flag=True,
    ),
    click.option(
        '-C', '--to-clipboard', is_flag=True,
    ),
    click.option(
        '--csv', is_flag=True, help='Output to CSV',
    ),
    click.option(
        '-u', '--user', 
        help='Get this information for this user name'
    ),
    click.option(
        '--keep-duplicates', is_flag=True, 
        help='Keep duplicate DNS entries',
    ),
    click.option(
        '--loglevel', default='info',
        help=('Log output level (default: info)'),
    ),
)

@bh_list
def bloodhound_list_computers(inpath, outpath, ssh, echo, from_clipboard,
                              to_clipboard, csv, user, keep_duplicates, 
                              loglevel):
    logging.setup_logging(loglevel)
    bloodhound.parser.list_objects(
        inpath, outpath, ssh, echo, from_clipboard,
        to_clipboard, csv, user, keep_duplicates,
        get('computers'),
    )

@bh_list
def bloodhound_list_users(inpath, outpath, ssh, echo, from_clipboard,
                          to_clipboard, csv, user, keep_duplicates, loglevel):
    logging.setup_logging(loglevel)
    bloodhound.parser.list_objects(
        inpath, outpath, ssh, echo, from_clipboard,
        to_clipboard, csv, user, keep_duplicates,
        get('users')
    )

@bh_list
def bloodhound_list_groups(inpath, outpath, ssh, echo, from_clipboard,
                           to_clipboard, csv, user, keep_duplicates, loglevel):
    logging.setup_logging(loglevel)
    bloodhound.parser.list_objects(
        inpath, outpath, ssh, echo, from_clipboard,
        to_clipboard, csv, user, keep_duplicates,
        get('groups'),
    )

@click.command()
@click.argument('group-regex')
@click.option(
    '-i', '--inpath', type=click.Path(exists=True),
    default='./bloodhound',
)
@click.option('-T', '--table', is_flag=True, help='Output to markdown table')
@click.option(
    '-R', '--recurse', is_flag=True, help=(
        'Recurse through groups to build a unique list of users or computers'
    ),
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def group_members(group_regex, inpath, table, recurse, loglevel):
    logging.setup_logging(loglevel)

    inpath = Path(inpath).expanduser()
    log.info(
        f'Searching for group members in {inpath}'
    )

    lut = bloodhound.parser.group_search(
        inpath, group_regex, recurse=recurse,
    )

    log.info(
        f'Found {len(lut)} matching group regex "{group_regex}"'
    )

    get_name = bloodhound.parser.get_name
    formatter = curry(
        (lambda g, n: f'| {g} | {get_name(n)} | {n["type"]} |' )
        if table else 
        (lambda g, n: f'{g}\t{get_name(n)}\t{n["type"]}')
    )

    pipe(
        lut.items(),
        filter(second),
        vmap(lambda g, nodes: pipe(
            nodes,
            sort_by(lambda n: (n['type'], get_name(n))),
            map(formatter(g)),
            '\n'.join,
        )),
        cconcat(['| Group Name | Member | Object Type |']) if table else noop,
        '\n'.join,
        print,
    )