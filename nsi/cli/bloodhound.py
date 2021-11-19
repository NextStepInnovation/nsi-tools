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
