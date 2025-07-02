'''Bloodhound tools

'''
from pathlib import Path
import math

import pyperclip
import click

from ..toolz import *
from .. import logging

from ..bloodhound.parser import (
    parse_directory, get_name, get_id, get_email, is_admin,
    get_description, get_displayname, is_enabled,
    group_members as _group_members, user_search, 
    user_groups as _user_groups,
)

log = logging.new_log(__name__)

def bh_list_command(obj_type: str):
    return compose_left(
        click.command(
            help=(
                f'List out BloodHound {obj_type[:-1].capitalize()} objects'
            ),
        ),
        click.option(
            '-i', '--inpath', type=click.Path(exists=True),
            help=(
                'Path of directory containing SharpHound JSON output'
            ),
        ),
        click.option(
            '-o', '--outpath', type=click.Path(),
            help=(
                'Path to output resulting data'
            ),
        ),
        click.option(
            '-a', '--admin', is_flag=True,
            help = '''
            List only objects with admincount: True
            '''
        ),
        click.option(
            '-e', '--enabled', is_flag=True,
            help = '''
            List only enabled objects
            '''
        ),
        click.option(
            '-C', '--to-clipboard', is_flag=True,
            help='Copy output to clipboard',
        ),
        click.option(
            '--csv', is_flag=True, help=(
                'Output in CSV format (default is tab-delimited)'
            ),
        ),
        click.option(
            '--loglevel', default='info',
            help=('Log output level (default: info)'),
        ),
    )(list_objects(get(obj_type)))

@curry
def list_objects(obj_func, inpath, outpath, admin, enabled, to_clipboard, csv, 
                 loglevel):
    logging.setup_logging(loglevel)
    data = parse_directory(inpath)

    def csv_format(hosts):
        return csv_rows_to_content(
            hosts, columns=[
                'name', 'displayname', 'description', 'email', 'id', 'enabled',
            ],
        )

    def print_formatter(hosts):
        return pipe(
            hosts,
            map(map_t(replace('\r', ''))),
            map(map_t(replace('\n', ' '))),
            map('\t'.join),
            # vmap(lambda name, id: f'{name}\t{id}'),
            '\n'.join,
        )
    
    formatter = print_formatter
    if csv:
        formatter = csv_format

    outputter = print
    if outpath:
        outputter = Path(outpath).expanduser().write_text
    elif to_clipboard:
        outputter = pyperclip.copy

    pipe(
        obj_func(data),
        filter(is_admin if admin else (lambda *a: True)),
        filter(is_enabled if enabled else (lambda *a: True)),
        map(lambda c: (
            get_name(c), 
            get_displayname(c),
            get_description(c),
            get_email(c), 
            get_id(c), 
        ) + ((is_enabled(c),) if not enabled else ()) ),
        set,
        sorted,
        map(map_t(str)),
        formatter,
        outputter,
    )

list_computers = bh_list_command('computers')
list_users = bh_list_command('users')
list_groups = bh_list_command('groups')

@click.command(
    help=(
        'Get members of all groups with names matching GROUP-REGEX'
    )
)
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
    '-e', '--enabled', is_flag=True,
    help = '''
    List only enabled objects
    '''
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def group_members(group_regex, inpath, table, recurse, enabled, loglevel):
    logging.setup_logging(loglevel)

    inpath = Path(inpath).expanduser()
    log.info(
        f'Searching for group members in {inpath}'
    )

    max_level = 1
    if recurse:
        max_level = math.inf

    lut = _group_members(inpath, group_regex, max_level=max_level)

    log.info(
        f'Found {len(lut)} matching group regex "{group_regex}"'
    )

    formatter = curry(
        (lambda g, n: f'| `{g}` | `{get_name(n)}` | {n["type"]} |' )
        if table else 
        (lambda g, n: f'{g}\t{get_name(n)}\t{n["type"]}')
    )

    pipe(
        lut.items(),
        filter(second),
        vmap(lambda g, nodes: pipe(
            nodes,
            filter(is_enabled if enabled else (lambda *a: True)),
            sort_by(lambda n: (n['type'], get_name(n))),
            map(formatter(g)),
            '\n'.join,
        )),
        cconcat(['| Group Name | Member | Object Type |']) if table else noop,
        '\n'.join,
        print,
    )

@click.command(
    help=(
        'Get all groups for users with names matching USER-REGEX'
    )
)
@click.argument('user-regex')
@click.option(
    '-i', '--inpath', type=click.Path(exists=True),
    default='./bloodhound',
)
@click.option('-T', '--table', is_flag=True, help='Output to markdown table')
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def user_groups(user_regex, inpath, table, loglevel):
    logging.setup_logging(loglevel)

    inpath = Path(inpath).expanduser()
    log.info(
        f'Searching for users in {inpath}'
    )

    users = sorted(user_search(inpath, user_regex))
    groups = _user_groups(inpath)

    log.info(
        f'Found {len(users)} users matching regex "{user_regex}"'
    )

    formatter = curry(
        (lambda u, g: f'| `{u}` | `{g}` |' )
        if table else 
        (lambda u, g: f'{u}\t{g}')
    )

    pipe(
        users,
        map(lambda u: (u, groups.get(u))),
        filter(second),
        vmap(lambda uname, gnames: pipe(
            gnames,
            sorted,
            map(formatter(uname)),
            '\n'.join,
        )),
        cconcat(['| User Name | Group Name |']) if table else noop,
        '\n'.join,
        print,
    )
