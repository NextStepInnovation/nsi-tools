import os
from pathlib import Path
import inspect
import functools
from typing import *

from pymaybe import Nothing
import chardet

from .common import (
    pipe, call, concatv, vmapcat, curry,
    new_log,
)
from .time import ctime, dt_ctime

log = new_log(__name__)

# ----------------------------------------------------------------------
#
# File operations
#
# ----------------------------------------------------------------------

def walk(path):
    '''Return os.walk(path) as sequence of Path objects

    >>> with tempfile.TemporaryDirectory() as temp:
    ...     root = Path(temp)
    ...     Path(root, 'a', 'b').mkdir(parents=True)
    ...     _ = Path(root, 'a', 'a.txt').write_text('')
    ...     _ = Path(root, 'a', 'b', 'b.txt').write_text('')
    ...     paths = tuple(walk(root))
    >>> paths == (Path(root, 'a', 'a.txt').resolve(), Path(root, 'a', 'b', 'b.txt').resolve())  # noqa
    True

    '''
    return pipe(
        os.walk(Path(path).expanduser().resolve()),
        vmapcat(lambda root, dirs, files: [Path(root, f) for f in files]),
    )

@curry
def walkmap(func, root):
    '''Map function over all paths in os.walk(root)

    '''
    return pipe(
        walk(root),
        map(func),
    )

def check_parents_for_file(name, start_dir=Path('.'), *, default=Nothing()):
    start_path = Path(start_dir).expanduser()
    directories = concatv([start_path], start_path.parents)
    for base in directories:
        path = Path(base, name)
        if path.exists():
            return path
    return default

def to_paths(*paths):
    return pipe(paths, map(Path), tuple)

@curry
def newer(path: Union[str, Path], test: Union[str, Path]):
    '''Is the path newer than the test path?

    '''
    return ctime(path) > ctime(test)

@curry
def older(path: Union[str, Path], test: Union[str, Path]):
    '''Is the path older than the test path?

    '''
    return ctime(path) < ctime(test)

def is_path(t):
    return t in {
        Union[str, Path], Path
    }

POS_PARAM_KINDS = {
    inspect.Parameter.POSITIONAL_ONLY,
    inspect.Parameter.POSITIONAL_OR_KEYWORD,
    inspect.Parameter.VAR_POSITIONAL,
}
def ensure_paths(func, *, expanduser: bool=True):
    '''Ensure that all path-like arguments of this function are converted into
    Path objects. Furthermore, paths by default have expanduser() called.

    Args:
        expanduser (bool): Path object should have user symbol `~` expanded

    Examples

    >>> from pathlib import Path
    >>> from typing import *
    >>> @ensure_paths
    ... def f(a: Union[str, Path]):
    ...     print(a.stem)
    ...     print(a.suffix)
    ...
    >>> f('path.txt')
    path
    .txt
    >>> f(Path('path.txt'))
    path
    .txt

    '''
    path_params = {
        name: (i, param)
        for i, (name, param)
        in enumerate(inspect.signature(func).parameters.items())
        if is_path(param.annotation)
    }

    pos_params = {
        i: (name, param)
        for name, (i, param) in path_params.items()
        if param.kind in POS_PARAM_KINDS
    }

    @functools.wraps(func)
    def path_arg_converter(*a, **kw):
        pos = [i for i in pos_params if i < len(a)]

        a = list(a)
        for i in pos:
            a[i] = Path(a[i])
            if expanduser:
                a[i] = a[i].expanduser()
        for k, v in kw.items():
            if k in path_params:
                kw[k] = Path(v)
                if expanduser:
                    kw[k] = kw[k].expanduser()
        return func(*a, **kw)
    return path_arg_converter

@ensure_paths
def read_text(path: Union[str, Path]):
    encoding = 'utf-8'
    with path.open('rb') as rfp:
        test_bytes = rfp.read(100)
        result = chardet.detect(test_bytes)
        log.debug(f'read_text: chardet result {result}')
        if result['confidence'] > 0.8:
            encoding = result['encoding']
    return path.read_text(encoding)
        

def slurp(path: Union[str, Path]):
    '''Read contents of file as str

    Examples:

    >>> with tempfile.TemporaryDirectory() as temp:
    ...     root = Path(temp)
    ...     path = root / 'test.txt'
    ...     _ = path.write_text('file content')
    ...     content = pipe(path, slurp)
    >>> content
    'file content'

    '''
    return pipe(
        path,
        read_text,
    )

def slurp_lines(path: Union[str, Path]):
    '''Slurp file contents and split lines
    '''    
    return pipe(
        path,
        slurp,
        call('splitlines')
    )

@curry
@ensure_paths
def peek(nbytes: int, path: Path):
    with path.open('r', encoding='latin-1') as rfp:
        return rfp.read(nbytes)

@ensure_paths
def backup_path(path: Path):
    path = Path(path)
    dt = dt_ctime(path)
    return Path(
        path.parent,
        ''.join((
            'backup',
            '-',
            path.stem,
            '-',
            dt.strftime('%Y-%m-%d_%H%M%S'),
            path.suffix
        ))
    )
    

