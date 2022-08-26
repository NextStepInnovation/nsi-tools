'''Tools for dealing with IP data

'''
from ipaddress import ip_interface

import click

from .. import toolz as _
from .common import (
    get_input_content, loglevel,
)
from ..logging import setup_logging
from ..yaml import dump as dump_yaml

cb_copy_ensure_nl = _.compose(
    _.clipboard_copy,
    lambda c: c if c.endswith('\n') else c + '\n'
)

@click.command()
@click.argument(
    'patha',
    type=click.Path(exists=True),
)
@click.argument(
    'pathb',
    type=click.Path(exists=True),
)
@loglevel
def diff_ips(patha, pathb, loglevel):
    '''Given PATHA and PATHB of IPs, print difference (A-B)

    '''
    setup_logging(loglevel)
    ips_a = set(_.get_ips_from_file(patha))
    ips_b = set(_.get_ips_from_file(pathb))

    _.pipe(
        ips_a - ips_b,
        _.sortips,
        '\n'.join,
        print,
    )

@click.command(
    help=('Given PATHA and PATHB of IPs, print intersection (A & B)'),
)
@click.argument(
    'patha',
    type=click.Path(exists=True),
)
@click.argument(
    'pathb',
    type=click.Path(exists=True),
)
@loglevel
def int_ips(patha, pathb, loglevel):
    '''
    '''
    setup_logging(loglevel)
    ips_a = set(_.get_ips_from_file(patha))
    ips_b = set(_.get_ips_from_file(pathb))

    _.pipe(
        ips_a & ips_b,
        _.sortips,
        '\n'.join,
        print,
    )

@click.command()
@click.argument(
    'inpath',
    required=False,
    type=click.Path(exists=True),
)
@click.option(
    '-K', '--keepcomments', is_flag=True,
    help=('Keep the in-line comments'),
)
@click.option(
    '-C', '--clipboard', is_flag=True,
    help=('Get IPs from clipboard, send sorted to clipboard'),
)
@loglevel
def sort_ips(inpath, keepcomments, clipboard, loglevel):
    '''Given a list of IPs (one per line) from a file path (INPATH), the
    clipboard (-C), or stdin if nothing provided, print in sorted
    order (to stdout unless -C is provided).

    '''
    setup_logging(loglevel)
    content = get_input_content(inpath, clipboard)

    return _.pipe(
        content.splitlines(),
        _.map(_.noop if keepcomments else _.strip_comments),
        _.filter(lambda l: l.strip()),
        _.filter(_.compose(_.is_ip, _.strip(), _.strip_comments)),
        _.sortips,
        '\n'.join,
        print if not clipboard else cb_copy_ensure_nl,
    )

@click.command()
@click.argument(
    'inpath',
    required=False,
    type=click.Path(exists=True),
)
@click.option(
    '-K', '--keep-non-ip', is_flag=True,
    help=('Keep lines without an IP'),
)
@click.option(
    '-C', '--clipboard', is_flag=True,
    help=('Get IPs from clipboard, send sorted to clipboard'),
)
@loglevel
def sort_by_ips(inpath, keep_non_ip, clipboard, loglevel):
    '''
    Given a list of lines containing an IP (one per line) from a file path
    (INPATH), the clipboard (-C), or stdin if nothing provided, print in sorted
    order based on the first IP found (to stdout unless -C is provided).

    Lines with IPs go first, sorted by the first IP contained in them, all other
    lines go after if --keep-non-ip is provided.

    '''
    setup_logging(loglevel)
    content = get_input_content(inpath, clipboard)
    get_ip_from_str = _.compose_left(_.get_ips_from_str, _.maybe_first)
    def sort_by_ips(lines):
        ip_lines = _.pipe(
            lines,
            _.map(lambda l: (get_ip_from_str(l), l)),
            tuple,
        )
        yield from _.pipe(
            ip_lines, 
            _.filter(_.first), 
            _.sort_by(_.compose_left(_.first, _.ip_tuple)), 
            _.map(_.second),
        )
        if keep_non_ip:
            yield from _.pipe(
                ip_lines, 
                _.filter(_.complement(_.first)), 
                _.map(_.second),
            )

    return _.pipe(
        content.splitlines(),
        sort_by_ips,
        '\n'.join,
        print if not clipboard else cb_copy_ensure_nl,
    )

@click.command()
@click.argument(
    'inpath',
    required=False,
    type=click.Path(exists=True),
)
@click.option(
    '-s', '--slash', type=int, default=24,
    help='Find the networks in the list of IPs of the given size (16, 24)'
)
@click.option(
    '-c', '--from-clipboard', is_flag=True,
    help=('Get IPs from clipboard'),
)
@click.option(
    '-C', '--to-clipboard', is_flag=True,
    help=('Send sorted to clipboard'),
)
@click.option(
    '--yaml', is_flag=True,
    help='Output should be in yaml form'
)
@loglevel
def get_subnets(inpath, slash, from_clipboard, to_clipboard, yaml, loglevel):
    ''''Given a list of IP addresses from a file path (INPATH), the
    clipboard (-C), or stdin (if nothing provided), print in sorted
    order (to stdout unless -C is provided) all the IP networks of a
    certain size (-s {16, 24})

    '''
    setup_logging(loglevel)
    content = get_input_content(inpath, from_clipboard)

    def get_network(ip):
        return ip_interface(ip + f'/{slash}').network
            
    return _.pipe(
        _.get_ips_from_str(content),
        _.map(get_network),
        set,
        sorted,
        _.map(str),
        _.compose(dump_yaml, list) if yaml else '\n'.join,
        print if not to_clipboard else cb_copy_ensure_nl,
    )


@click.command()
@click.argument(
    'inpath',
    required=False,
    type=click.Path(exists=True),
)
@click.option(
    '-c', '--from-clipboard', is_flag=True,
    help=('Get IPs from clipboard'),
)
@click.option(
    '-C', '--to-clipboard', is_flag=True,
    help=('Send sorted to clipboard'),
)
@click.option(
    '--prefix', default='',
    help='Prefix for each IP in output'
)
@click.option(
    '--stdout', is_flag=True,
    help='Force output to stdout',
)
@click.option(
    '--no-sort', is_flag=True,
    help='Keep IPs unsorted',
)
@click.option(
    '-u', '--unique', is_flag=True,
    help='Print only unique IPs',
)
@loglevel
def get_ips(inpath, from_clipboard, to_clipboard, prefix, stdout, loglevel, 
            no_sort, unique):
    '''Given a text block containing IPs from a file path (INPATH), the
    clipboard (-c), or stdin if nothing provided, print in sorted
    order (to stdout unless -C is provided) all the IPs

    '''
    setup_logging(loglevel)
    content = get_input_content(inpath, from_clipboard)
            
    return _.pipe(
        _.get_ips_from_str(content),
        set if unique else _.noop,
        _.noop if no_sort else _.sortips,
        _.map(lambda ip: f'{prefix}{ip}'),
        '\n'.join,
        print if stdout or not to_clipboard else cb_copy_ensure_nl,
    )


@click.command()
@click.argument(
    'inpath',
    required=False,
    type=click.Path(exists=True),
)
@click.option(
    '-c', '--from-clipboard', is_flag=True,
    help=('Get IPs from clipboard'),
)
@click.option(
    '-C', '--to-clipboard', is_flag=True,
    help=('Send sorted to clipboard'),
)
@click.option(
    '--stdout', is_flag=True,
    help='Force output to stdout',
)
@click.option(
    '--no-sort', is_flag=True,
    help='Keep IPs unsorted',
)
@click.option(
    '-u', '--unique', is_flag=True,
    help='Print only unique IPs',
)
@loglevel
def zpad_ips(inpath, from_clipboard, to_clipboard, stdout, no_sort, unique, loglevel):
    '''Given a text block containing IPs from a file path (INPATH), the
    clipboard (-c), or stdin if nothing provided, print in sorted
    order (to stdout unless -C is provided) all the IPs with octets
    padded with zeros.

    '''
    setup_logging(loglevel)
    content = get_input_content(inpath, from_clipboard)
            
    return _.pipe(
        _.get_ips_from_str(content),
        set if unique else _.noop,
        _.noop if no_sort else _.sortips,
        _.map(_.zpad),
        '\n'.join,
        print if stdout or not to_clipboard else cb_copy_ensure_nl,
    )

@click.command()
@click.argument(
    'inpath',
    required=False,
    type=click.Path(exists=True),
)
@click.option(
    '-c', '--from-clipboard', is_flag=True,
    help=('Get IPs from clipboard'),
)
@click.option(
    '-C', '--to-clipboard', is_flag=True,
    help=('Send sorted to clipboard'),
)
@click.option(
    '--stdout', is_flag=True,
    help='Force output to stdout',
)
@click.option(
    '--no-sort', is_flag=True,
    help='Keep IPs unsorted',
)
@click.option(
    '-u', '--unique', is_flag=True,
    help='Print only unique IPs',
)
@loglevel
def unzpad_ips(inpath, from_clipboard, to_clipboard, stdout, no_sort, unique, loglevel):
    '''Given a text block containing IPs from a file path (INPATH), the
    clipboard (-c), or stdin if nothing provided, print in sorted
    order (to stdout unless -C is provided) all the zero-padded IPs
    formatted as normal IPs.

    '''
    setup_logging(loglevel)
    content = get_input_content(inpath, from_clipboard)
            
    return _.pipe(
        _.get_ips_from_str(content),
        set if unique else _.noop,
        _.noop if no_sort else _.sortips,
        _.map(_.unzpad),
        '\n'.join,
        print if stdout or not to_clipboard else cb_copy_ensure_nl,
    )
