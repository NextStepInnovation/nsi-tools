from pathlib import Path
import typing as T

from . import logging
from . import shell
from .toolz import *

log = logging.new_log(__name__)

@curry
@ensure_paths
def grep_file(regexes: T.Sequence[Regex], path: Path, *, 
              getoutput=None, echo: bool=True, 
              **grep_options):
    
    log.info(
        f'Performing grep action for path: {path}'
    )
    getoutput = getoutput or shell.getoutput(
        echo=echo,
    )

    options_string = shell.options_string(grep_options)

    log.debug(f'  grep options: {options_string}')

    regex_string = pipe(
        regexes,
        map(lambda r: f"-e '{r}'"),
        ' '.join,
    )
    log.debug(f'  regexes: {regex_string}')

    command = f'''
    grep {regex_string} {options_string} {path}
    '''.strip()

    log.info(f'  command: {command}')

    return getoutput(command)

egrep_file = grep_file(extended_regexp = True)
pgrep_file = grep_file(perl_regexp = True)



@curry
@ensure_paths
def recursive_grep(path_filter_f: T.Callable[[Path], bool], root: Path):
    pass

