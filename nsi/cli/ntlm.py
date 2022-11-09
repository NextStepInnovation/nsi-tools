from pathlib import Path
import itertools
import pprint
import re
from re import search

import click
import pyperclip

from .. import logging
from ..toolz import *
from .. import toolz as _
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
    help='''
    Path of file with administrator names. This could be accounts with full
    domain administrator access or just low level. Can be used with
    --domain-admins to differentiate between the two.
    ''',
)
@click.option(
    '-d', '--domain-admins', type=click.Path(exists=True),
    help=('Path of file with domain administrator names'),
)
@click.option(
    '-H', '--include-hashes', is_flag=True,
    help='''
    Include the NT hash in the output
    '''
)
@click.option(
    '-T', '--table', is_flag=True,
    help=('Output in Markdown table form'),
)
@click.option(
    '-c', '--to-clipboard', is_flag=True,
    help=('Send output to clipboard'),
)
@click.option(
    '--loglevel', default='info',
)
def resolve(hashes, potfile, admins, domain_admins, include_hashes, table, 
            to_clipboard, loglevel):
    logging.setup_logging(loglevel)

    ntlm_re = re.compile(r'^[0-9a-f]{32}:.*')
    u2h = pipe(
        hashes,
        slurp,
        ntlm.get_sam_hashes,
        groupby('full_user'),
        valmap(first),
        valmap(get('ntlm')),
    )
    h2pt = pipe(
        Path(potfile).read_text().splitlines(),
        map(lambda l: l.strip()),
        filter(ntlm_re.search),
        map(lambda l: l.split(':')),
        dict
    )

    def get_users(path: Path):
        return pipe(
            path,
            slurplines,
            map(strip()),
            map(lower),
            set,
        ) if path else set()

    admins = get_users(admins)
    if admins:
        log.info(
            f'Found {len(admins)} admin account names'
        )
    domain_admins = get_users(domain_admins)

    @curry
    def is_in_admin_list(admin_list, u: str):
        name = u.split('/')[-1].lower()
        return name in admin_list

    is_admin = is_in_admin_list(admins)
    is_domain_admin = is_in_admin_list(domain_admins)

    def tr_f(u, h):
        return (
            '| ' + 
            pipe(
                (
                    f'`{u}`' if u else '',
                    f'`{h}`' if include_hashes else None,
                    f'`{h2pt[h]}`' if h2pt[h] else '',
                    (f'**Yes**' if is_admin(u) else '') if admins else None,
                    (f'**Yes**' if is_domain_admin(u) else '') if domain_admins else None,
                ),
                filter(lambda v: v is not None),
                ' | '.join,
            ) +
            ' |'
        )

    def norm_f(u, h):
        return pipe(
            (
                f'{u}',
                (f'{h}') if include_hashes else None,
                f'{h2pt[h]}',
                ('\thas_admin' if is_admin(u) else '\t') if admins else None,
                ('\tdomain_admin' if is_domain_admin(u) else '\t') if domain_admins else None,
            ),
            filter(lambda v: v is not None),
            '\t'.join,
        )

    row_formatter = tr_f if table else norm_f

    def admins_at_top(rows):
        return pipe(
            rows,
            sort_by(vcall(lambda u, h: (
                (
                    0 if is_domain_admin(u) else 1, 
                    0 if is_admin(u) else 1, 
                ),
                u.lower(), h,
            ))),
        )

    row_sorter = admins_at_top if (admins or domain_admins) else noop

    return pipe(
        u2h.items(),
        sort_by(vcall(lambda u, h: (u.lower(), h))),
        vmap(lambda u, h: (u, h.split(':')[-1])),
        vfilter(lambda u, h: h in h2pt),
        row_sorter,
        vmap(row_formatter),
        '\n'.join,
        pyperclip.copy if to_clipboard else print,
    )

@click.command(
    help='''
    Extract NTHashes (NTLM) from file(s). By default, will just output bare
    NTHashes. If you're passing in files that contain SAM hashdumps (e.g.
    secretsdump output), and you want all the SAM information (i.e. user, sid,
    ntlm), then use the --sam flag. If parsing NTDS.DIT secrets data from DC,
    then use --ntds flag (implies --sam).
    '''
)
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
    '--sam', is_flag=True,
    help='''
    Parse out all SAM data (user, sid, hash).
    '''
)
@click.option(
    '--ntds', is_flag=True,
    help='''
    If parsing NTDS.DIT secrets (i.e. secretsdump from DC), add full_name,
    domain columns to output.
    '''
)
@click.option(
    '--csv', is_flag=True,
    help='''
    Output as CSV
    '''
)
@click.option(
    '--lower', is_flag=True,
    help='''
    Lowercase the output (e.g. if checking for uniqueness of usernames)
    '''
)
@click.option(
    '--ip', is_flag=True, help='''
    If the file path has IP information in it, add this to each line of hash
    data
    '''
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def extract(search_paths, from_clipboard, to_clipboard, output_path, sam, csv,
            ntds, lower, ip, loglevel):
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
            mapdo(lambda p: log.debug(f' - {p} ({p.stat().st_size} B)')),
            mapcat(
                ntlm.parse_sam_from_path if sam else ntlm.parse_ntlm_from_path
            ),
            map(valmap(lambda v: v or '')),
            map(valmap(_.lower if lower else noop)),
        )

    if from_clipboard:
        clipboard = pyperclip.paste()
        log.info(
            f'Searching clipboard content for NTLM hashes ({len(clipboard)} B)'
        )
        hashes = pipe(
            clipboard,
            ntlm.parse_sam_from_content if sam else ntlm.parse_ntlm_from_content,
            cconcat(hashes),
        )

    hashes = tuple(hashes)
    log.info(
        f'Found {len(hashes)} hashes'
    )

    columns = (
        ['full_user', 'domain'] 
        if ntds else []
    ) + ['user', 'sid', 'ntlm'] + (
        ['ip'] if ip else []
    ) 

    formatter = (
        csv_rows_to_content(columns=columns) 
        if csv else compose_left(
            map(get(columns, default='')),
            map('\t'.join),
            '\n'.join,
        )
    ) if (sam or ntds) else compose_left(
        map(get('ntlm')),
        '\n'.join,
    )
    # hashes_str = pipe(hashes, '\n'.join)

    output_path = pipe(
        Path(output_path).expanduser().resolve(),
        do(lambda p: p.parent.mkdir(exist_ok=True, parents=True)),
    ) if output_path else None

    outputter = pyperclip.copy if to_clipboard else (
        output_path.write_text if output_path else print
    )

    pipe(
        hashes,
        formatter,
        outputter,
    )
