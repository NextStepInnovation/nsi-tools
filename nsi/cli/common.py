import sys
from pathlib import Path
import logging
import typing as T

import click
import pyperclip

from nsi.toolz.filesystem import ensure_paths

from .. import logging
#from .. import toolz as _
from ..toolz import curry, clipboard_paste, compose, ensure_paths
from .. import ssh

log = logging.new_log(__name__)

def get_input_content(inpath: T.Optional[T.Union[Path, str]], clipboard: bool=False):
    '''Get input data from either input Path, clipboard, or stdin
    '''
    if inpath:
        content = Path(inpath).expanduser().read_text()
    elif clipboard:
        content = clipboard_paste()
    else:
        content = sys.stdin.read()
    log.debug(repr(content))
    return content

def path_cb_or_stdin(inpath: T.Union[str, Path], clipboard: bool):
    if inpath:
        log.info(f'Getting input from path: {inpath}')
        return Path(inpath).read_text()
    elif clipboard:
        log.info('Getting input from clipboard...')
        return clipboard_paste()
    log.info('Getting input from stdin...')
    return sys.stdin.read()

def cb_or_stdin(clipboard):
    if clipboard:
        log.info('Getting input from clipboard...')
        return clipboard_paste()
    log.info('Getting input from stdin...')
    return sys.stdin.read()


def ssh_getoutput(host: str, **ssh_kw):
    if '@' in host:
        ssh_kw['username'], host = host.split('@', 1)

    if ':' in host:
        host, port = host.split(':', 1)
        ssh_kw['port'] = int(port)

    log.info(f'[ssh_getoutput] SSH args: host={host} kwargs={ssh_kw}')
    return ssh.getoutput(host, **ssh_kw)

ssh_options = compose(
    click.option(
        '--ssh',
        help=(
            'Run commands via SSH on this user@host:port (pubkey auth only)'
        )
    ),
)

input_options = compose(
    click.option(
        '-i', '--ippath', type=click.Path(
            exists=True, dir_okay=False, resolve_path=True,
        ),
        help=('Path with list of IP addresses to scan, one IP per line'),
    ),
    click.option(
        '-t', '--target',
        help=('Target of enumeration (IP, IP network)'),
    ),
)

impacket_input_options = compose(
    input_options,
    click.option(
        '-s', '--sam-path',
        help=(
            'Path of either a file with some number of SAM dumps'
            ' with NTLM hashes or a directory to walk to find the same.'
            ' If the -i/--ippath or -t/--target arguments are given, then'
            ' all NTLM user/hash combinations will be used with all IPs'
            ' provided.  If not, then the IP'
            ' address **must be** in the name of the SAM file or the parent'
            ' directory name of the file.'
        ),
        type=click.Path(exists=True, ),
    ),
)

def get_content(inpath, clipboard=False):
    if inpath:
        content = Path(inpath).read_text()
    elif clipboard:
        content = pyperclip.paste()
    else:
        content = sys.stdin.read()
    return content

inpath = compose(
    click.option(
        '-i', '--inpath', type=click.Path(
            exists=True, dir_okay=False, resolve_path=True,
        ),
        help=('Path with list of items to scan, one item per line'),
    )
)

outdir = compose(
    click.option(
        '-o', '--outdir', type=click.Path(
            file_okay=False, dir_okay=True, resolve_path=True,
        ),
        help=('Output directory path'),
    )
)

from_clipboard = compose(
    click.option(
        '-c', '--from-clipboard', is_flag=True,
        help=('Get IPs from clipboard'),
    ),
)

to_clipboard = compose(
    click.option(
        '-C', '--to-clipboard', is_flag=True,
        help=('Send output to clipboard'),
    ),
)

input_with_clipboard = compose(inpath, from_clipboard, to_clipboard)

loglevel = compose(
    click.option(
        '--loglevel', default='info', 
        type=click.Choice(
            ['debug', 'info', 'warning', 'error', 'critical']
        ),
        help='Logging level'
    )
)

cred_options = compose(
    click.option(
        '-u', '--username', default='',
        help=('User name with which to authenticate (default: NULL)'),
    ),
    click.option(
        '-p', '--password', default='',
        help=('Password with which to authenticate (default: NULL)'),
    ),
    click.option(
        '-d', '--domain', default='',
        help=('Domain to use when authenticating (default: ".")'),
    ),
)

impacket_cred_options = compose(
    cred_options,
    click.option(
        '-h', '--hashes',
        help=('NTLM hash with which to authenticate.'),
    ),
)

@curry
def _exit_with_msg(logger, msg):
    ctx = click.get_current_context()
    click.echo(ctx.get_help())
    logger.error(msg)
    raise click.Abort()

# VS Code labels everthing after this as dead code since it (understandably)
# doesn't understand toolz curry objects

exit_with_msg = _exit_with_msg(log)

