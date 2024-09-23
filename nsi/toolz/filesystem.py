import os
from pathlib import Path
import inspect
import itertools
import tempfile # noqa
import typing as T
from datetime import datetime
import functools
import pprint

from pymaybe import Nothing
import chardet
import charset_normalizer
from toolz.functoolz import compose_left, compose

from .common import (
    pipe, call, concatv, vmapcat, curry, map, filter, vfilter,
    new_log, splitlines, merge, memoize, deref, is_seq, vmap, vcall,
)

log = new_log(__name__)

__all__ = [
    # filesystem
    'POS_PARAM_KINDS', 'backup_path', 'check_parents_for_file', 
    'ensure_paths', 'ensure_paths_curry', 'glob',
    'is_path', 'newer', 'older', 'binpeek', 'read_text', 'read_bytes',
    'slurp', 'slurpb', 'slurpblines', 'slurplines', 'slurpbchunks',
    'to_paths', 'walk', 'walkmap', 'convert_utf8', 'writeline', 
    'stat', 'mstat', 'ctime', 'mtime', 'atime', 'file_size',
    'mkdir', 'mkdirp',
]

# ----------------------------------------------------------------------
#
# File operations
#
# ----------------------------------------------------------------------

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

def is_path_type(t):
    return t in {
        T.Union[str, Path], Path
    }

def is_path(obj):
    if isinstance(obj, (Path, str)):
        return True
    return False

POS_PARAM_KINDS = {
    inspect.Parameter.POSITIONAL_ONLY,
    inspect.Parameter.POSITIONAL_OR_KEYWORD,
    inspect.Parameter.VAR_POSITIONAL,
}
@curry
def ensure_paths(func, *, expanduser: bool=True, resolve: bool=False):
    '''Ensure that all path-like arguments of this function are converted into
    Path objects. Furthermore, paths by default have expanduser() called.

    Args:
        expanduser (bool): Path object should have user symbol `~` expanded

    Examples

    >>> from pathlib import Path
    >>> from typing import *
    >>> @ensure_paths
    ... def f(a: T.Union[str, Path]):
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
        if is_path_type(param.annotation)
    }

    pos_params = {
        i: (name, param)
        for name, (i, param) in path_params.items()
        if param.kind in POS_PARAM_KINDS
    }

    @functools.wraps(func)
    def path_arg_converter(*args, **kwargs):
        pos = [i for i in pos_params if i < len(args)]

        args = list(args)
        for i in pos:
            # log.debug(f'ensure_paths: arg {i} {args[i]}')
            if args[i]:
                args[i] = Path(args[i])
                if expanduser:
                    args[i] = args[i].expanduser()
        for k, v in kwargs.items():
            if k in path_params:
                if kwargs[k]:
                    kwargs[k] = Path(v)
                    if expanduser:
                        kwargs[k] = kwargs[k].expanduser()
                    if resolve:
                        kwargs[k] = kwargs[k].resolve()
        return func(*args, **kwargs)
    return path_arg_converter

ensure_paths_curry = compose(
    curry,
    ensure_paths,
)

@ensure_paths_curry
def glob(glob_expr: str, path: Path):
    return path.glob(glob_expr)

@ensure_paths
def walk(path: Path, resolve: bool = True, skip_dirs: T.Optional[T.Sequence[str]] = None):
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
    skip_dirs = set(skip_dirs or [])
    for root, dirs, files in os.walk(path):
        assert str(Path(root)) not in skip_dirs
        for i, d in tuple(enumerate(dirs)):
            str_d = str(Path(root, d))
            if str_d in skip_dirs:
                log.info(f'Removing {str_d}')
                dirs.remove(d)
        yield from [Path(root, f) for f in files]

@curry
def walkmap(func, root):
    '''Map function over all paths in os.walk(root)

    >>> with tempfile.TemporaryDirectory() as temp:
    ...     root = Path(temp)
    ...     Path(root, 'a', 'b').mkdir(parents=True)
    ...     _ = Path(root, 'a', 'a.txt').write_text('hello')
    ...     _ = Path(root, 'a', 'b', 'b.txt').write_text('world')
    ...     _ = pipe(root, walkmap(lambda p: print(p.read_text())), tuple)
    hello
    world
    '''
    return pipe(
        walk(root),
        map(func),
    )


@ensure_paths
def read_text(path: T.Union[str, Path]):
    '''Read contents of file as str

    Examples:

    >>> with tempfile.TemporaryDirectory() as temp:
    ...     root = Path(temp)
    ...     path = root / 'test.txt'
    ...     _ = path.write_text('file content')
    ...     content = pipe(path, read_text)
    >>> content
    'file content'

    '''
    encoding = 'utf-8'
    with path.open('rb') as rfp:
        test_bytes = rfp.read(1024)
        # result = chardet.detect(test_bytes)
        result = charset_normalizer.detect(test_bytes)
        log.debug(f'read_text: chardet result {result}')
        if result['confidence'] > 0.8:
            encoding = result['encoding']
    if encoding == 'ascii':
        encoding = 'utf-8'
    try:
        return path.read_text(encoding)
    except UnicodeDecodeError as unicode_err:
        try:
            log.debug(
                f'  ... ran into Unicode errors. Trying cp1252 encoding for {path}'
            )
            encoding = 'cp1252'
            return path.read_text(encoding)
        except:
            log.exception(
                f'Tried to decode {repr(test_bytes[:20])} from'
                f' {path} using {encoding} encoding.  Giving up and ignoring'
                ' errors. THERE WILL BE DATA LOSS.'
            )
            return path.read_text('utf-8', errors='ignore')
    
slurp = read_text

@curry
@ensure_paths
def slurplines(path: Path, n: int = None, **open_kw):
    def merge_kws(**kw):
        return merge(open_kw, kw)
    
    try:
        with path.open(**open_kw) as rfp:
            for i, line in enumerate(rfp):
                if n is not None and i == n:
                    break
                yield line.rstrip('\n')
    except UnicodeDecodeError as unicode_err:
        try:
            encoding = 'cp1252'
            log.debug(
                f'  ... ran into Unicode errors. Trying cp1252 encoding for {path}'
            )
            yield from slurplines(path, n=n, **merge_kws(encoding=encoding))
        except:
            log.exception(
                f'Tried to decode {path} using {encoding} encoding.'
                '  Giving up and ignoring errors. THERE WILL BE DATA LOSS.'
            )
            yield from slurplines(path, n=n, **merge_kws(errors='ignore'))


@curry
@ensure_paths
def writeline(path: Path, line: str, **open_kw):
    if path not in _writeline_path_fp:
        _writeline_path_fp[path] = path.open(
            'a', **open_kw
        )
    _writeline_path_fp[path].write(f'{line}\n')
_writeline_path_fp = {}

@ensure_paths
def read_bytes(path: T.Union[str, Path]):
    '''Read contents of file as bytes

    Examples:

    >>> with tempfile.TemporaryDirectory() as temp:
    ...     root = Path(temp)
    ...     path = root / 'test.txt'
    ...     _ = path.write_text('file content')
    ...     content = pipe(path, read_bytes)
    >>> content
    b'file content'

    '''
    return path.read_bytes()
slurpb = read_bytes

@ensure_paths
def slurpblines(path: Path, n: int = None):
    with path.open('rb') as rfp:
        for i, line in enumerate(rfp):
            if n is not None and i == n:
                break
            yield line.rstrip(b'\n')

@ensure_paths
def slurpbchunks(size: int, path: Path, n: int = None):
    with path.open('rb') as rfp:
        while chunk := rfp.read(size):
            yield chunk

@curry
@ensure_paths
def binpeek(nbytes: int, path: Path):
    with path.open('rb') as rfp:
        return rfp.read(nbytes)

@ensure_paths
def stat(path: Path):
    return path.stat()

@memoize
@ensure_paths
def mstat(path: Path):
    '''
    Memoized stat 
    '''
    return path.stat()

ctime = compose_left(
    stat, deref('st_ctime'), datetime.fromtimestamp,
)
mtime = compose_left(
    stat, deref('st_mtime'), datetime.fromtimestamp,
)
atime = compose_left(
    stat, deref('st_atime'), datetime.fromtimestamp,
)
file_size = compose_left(
    stat, deref('st_size'),
)

Pathlike = T.Union[str, Path]
OneOrMorePaths = T.Union[Pathlike, T.Sequence[Pathlike]]

def time_compare(compare_f: T.Callable[[Pathlike, Pathlike], bool], 
                 path: OneOrMorePaths, test: OneOrMorePaths):
    '''Is the path newer than the test path?

    '''
    paths = [path] if not is_seq(path) else path
    tests = [test] if not is_seq(test) else test
        
    return pipe(
        (paths, tests),
        vcall(itertools.product),
        vmap(compare_f),
        all,
    )
        
@curry
def newer(path: OneOrMorePaths, test: OneOrMorePaths):
    '''Is the path older than the test path?

    '''
    return time_compare(
        lambda path, test: ctime(path) > ctime(test),
        path, test,
    )

@curry
def older(path: OneOrMorePaths, test: OneOrMorePaths):
    '''Is the path older than the test path?

    '''
    return time_compare(
        lambda path, test: ctime(path) < ctime(test),
        path, test,
    )

@ensure_paths
def backup_path(path: Path):
    path = Path(path)
    dt = ctime(path)
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
    
@ensure_paths
def convert_utf8(path: Path):
    return pipe(
        path,
        read_text,
        path.write_text,
    )

@curry
@ensure_paths
def mkdir(path: Path, **kwargs):
    path.mkdir(**kwargs)

mkdirp = mkdir(exist_ok=True, parents=True)
