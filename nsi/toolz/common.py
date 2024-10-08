from argparse import ArgumentError
from calendar import c
from pathlib import Path
import random
import traceback
import logging
import functools
import pprint
import builtins
import collections
import textwrap
import inspect
import types
import statistics
import importlib
from click import Argument
import multipledispatch
import io
from typing import *

from pymaybe import maybe as _maybe, Nothing
import chardet

maybe = _maybe

try:
    from cytoolz.curried import *
except ImportError:
    from toolz.curried import (
        accumulate, apply, assoc, assoc_in, comp,
        complement, compose, compose_left, concat, concatv,
        cons, count, countby, curry, diff,
        dissoc, do, drop, excepts, filter,
        first, flip, frequencies, get, get_in,
        groupby, identity, interleave, interpose, isdistinct,
        isiterable, itemfilter, itemmap, iterate, join,
        juxt, keyfilter, keymap, last, map,
        mapcat, memoize, merge, merge_sorted, merge_with,
        nth, operator, partial, partition, partition_all,
        partitionby, peek, peekn, pipe, pluck,
        reduce, reduceby, remove, second,
        sliding_window, sorted, tail, take, take_nth,
        thread_first, thread_last, topk, unique, update_in,
        valfilter, valmap,

    )

from ..logging import new_log

__all__ = [
    'new_log',

    # toolz.curried
    'accumulate', 'apply', 'assoc', 'assoc_in', 'comp',
    'complement', 'compose', 'compose_left', 'concat', 'concatv',
    'cons', 'count', 'countby', 'curry', 'diff',
    'dissoc', 'do', 'drop', 'excepts', 'filter',
    'first', 'flip', 'frequencies', 'get', 'get_in',
    'groupby', 'identity', 'interleave', 'interpose', 'isdistinct',
    'isiterable', 'itemfilter', 'itemmap', 'iterate', 'join',
    'juxt', 'keyfilter', 'keymap', 'last', 'map',
    'mapcat', 'memoize', 'merge', 'merge_sorted', 'merge_with',
    'nth', 'operator', 'partial', 'partition', 'partition_all',
    'partitionby', 'peek', 'peekn', 'pipe', 'pluck',
    'reduce', 'reduceby', 'remove', 'second',
    'sliding_window', 'sorted', 'tail', 'take', 'take_nth',
    'thread_first', 'thread_last', 'topk', 'unique', 'update_in',
    'valfilter', 'valmap',


    # common
    'as_tuple', 'as_dict', 'call', 'callif', 'cat_to_set', 'concat_t', 'cconcat', 
    'cconcatv', 'concatv_t', 'contains', 'cprint', 'deref', 'dispatch', 
    'do_error', 'do_info', 'do_log', 'do_slice', 'error_raise', 'endswith',
    'filter_t', 'find', 'first_true',
    'flatdict', 'float_or_zero', 'get_t', 'help_text',
    'index', 'is_dict', 'is_float', 'is_indexable', 'is_int', 'is_numeric',
    'is_none', 'is_not_dict', 'is_not_seq', 'is_not_string', 'is_seq',
    'is_some', 'is_not_none', 'is_str', 'items', 'values', 'keys', 
    'log_lines', 'log_obj', 
    'lower', 'map_t', 'map_to_set', 'mapdo', 'mapif', 
    'maybe', 'fmaybe', 'maybe_call',
    'max', 'maybe_first', 'maybe_float', 'maybe_int', 'maybe_last',
    'maybe_max', 'maybe_min', 'maybe_pipe', 'maybe_second', 'min',
    'mini_tb', 'setglobal', 'setlocal', 'noop', 'replace', 'sc_juxt',
    'select', 'seti', 'seti_t', 'short_circuit', 'shuffled',
    'sort_by', 'sorted', 'split', 'splitlines', 'starmap', 'startswith',
    'strip', 'to_io', 'to_bytes', 'to_str', 'upper', 'val',
    'vcall', 'vcallif', 'vdo', 'vfilter', 'vfind',
    'vgroupby', 'vindex', 'vitemmap', 'vkeymap', 'vmap', 'mapget', 'mget',
    'vmapcat', 'vmapdo', 'vmapif', 'vseti', 'vseti_t',
    'vvalmap', 'wrap_text', 'maybe_mean', 'maybe_median', 'maybe_mode',
    'most_common',
]

dispatch = multipledispatch.dispatch

# ----------------------------------------------------------------------
#
# Logging operations
#
# ----------------------------------------------------------------------

log = new_log(__name__)

@curry
def log_lines(log_function, lines):
    return pipe(
        lines,
        mapcat(splitlines),
        filter(None),
        mapdo(log_function),
    )

def log_obj(log_function: Callable[[str], None], obj: Any):
    pipe(
        obj,
        pprint.pformat,
        splitlines,
        log_lines(log_function),
    )

@curry
def error_raise(func, *, pprinter=pprint.pformat):
    @functools.wraps(func)
    def raiser(*a, **kw):
        try:
            return func(*a, **kw)
        except:
            kw_str = {
                k: pprinter(v) for k, v in kw.items()
            }
            log.error(
                f'args: \n\n{pprint.pformat([pprinter(o) for o in a])}\n\n'
                f'kwargs: \n\n{pprint.pformat(kw_str)}\n\n'
            )
            raise
    return raiser

def mini_tb(levels=3):
    '''Traceback message suitable for logging

    '''
    frame = inspect.currentframe().f_back
    parents = [frame.f_back]
    for i in range(levels - 1):
        if parents[-1].f_back:
            parents.append(parents[-1].f_back)
        else:
            break
    return '\n' + pipe(
        parents,
        map(inspect.getframeinfo),
        vmap(lambda filen, lnum, fname, lns, i: (
            f'{Path(filen).name}', lnum, fname, lns[i],
        )),
        vmap(lambda path, lnum, fname, line: (
            f'- {fname} | {path}:{lnum} | {line.rstrip()}'
        )),
        '\n'.join,
    )


# ----------------------------------------------------------------------
#
# Curried object access/calling
#
# ----------------------------------------------------------------------

@curry
def ceval(source, globals=None, locals=None):
    '''Curried eval
    '''
    return eval(source, globals, locals)

def _find_shell_frame(frame: types.FrameType | None) -> types.FrameType:
    if frame is None:
        raise RecursionError('Could not find shell frame')
    if frame.f_lineno == 1:
        return frame
    return _find_shell_frame(frame.f_back)

@curry
def setglobal(name: str, value: Any, globals_dict: dict = None):
    if globals_dict is None:
        globals_dict = _find_shell_frame(inspect.currentframe()).f_globals
    globals_dict[name] = value
    return value

@curry
def setlocal(name: str, value: Any, locals_dict: dict = None):
    if locals_dict is None:
        locals_dict = _find_shell_frame(inspect.currentframe()).f_locals
    locals_dict[name] = value
    return value

def noop(value):
    '''Yes, we have no banana pudding.

    Examples:

    >>> noop(1)
    1
    >>> noop("Banana Pudding")
    'Banana Pudding'
    '''
    return value

def val(value):
    '''Value returner for delayed call with defined value. E.g. for
    compose_left definitions

    Examples:

    >>> f = compose_left(val('this value'), lambda v: len(v))
    >>> f()
    10
    '''
    def returner():
        return value
    return returner


@curry
def deref(attr, obj):
    '''Curried getattr for accessing attributes of an object.

    Examples:

    >>> class X:
    ...     def __init__(self, x):
    ...         self.x = x
    ...
    >>> pipe([X(1), X(5)], map(deref('x')), tuple)
    (1, 5)
    '''
    return getattr(obj, attr)

def call(method_name, *a, **kw):
    '''"Curried" method caller

    Examples:

    >>> class X:
    ...     def __init__(self, x):
    ...         self.x = x
    ...     def square(self):
    ...         return self.x ** 2
    ...     def mult(self, v):
    ...         return self.x * v
    ...
    >>> pipe([X(1), X(5)], map(call('square')), tuple)
    (1, 25)
    >>> pipe([X(1), X(5)], map(call('mult', 3)), tuple)
    (3, 15)
    '''
    def caller(obj):
        return getattr(obj, method_name)(*a, **kw)
    return caller

@curry
def contains(value, obj):
    '''Curried in operator

    Examples:

    >>> pipe('a string with asdf', contains('asdf'))
    True
    '''
    return value in obj


# ----------------------------------------------------------------------
#
# Basic type operations
#
# ----------------------------------------------------------------------

def is_str(v):
    '''Is this a string object
    '''
    return isinstance(v, str)
is_not_string = complement(is_str)

@curry
def decode_bytes(data: bytes):
    encoding = 'utf-8'
    result = chardet.detect(data[:1024])
    log.debug(f'decode_bytes: chardet result {result}')
    if result['confidence'] > 0.8:
        encoding = result['encoding']
    try:
        return data.decode(encoding)
    except UnicodeDecodeError as unicode_err:
        log.exception(
            f'Tried to decode {repr(data[:50])} using {encoding} '
            'encoding.  Giving up.'
        )
        return ''

def to_str(content: Any):
    '''Convert this object into a string, decoding from bytes if necessary
    '''
    match type(content):
        case builtins.bytes:
            return pipe(
                content,
                decode_bytes,
            )
    return str(content)

@curry
def to_bytes(content, encoding='utf-8', errors='ignore'):
    '''Convert this object as bytes, encoding if necessary
    '''
    match type(content):
        case builtins.bytes:
            return content
        case builtins.str:
            return content.encode(encoding, errors)
    return str(content).encode(encoding, errors)

def is_dict(d):
    return isinstance(d, collections.abc.Mapping)
is_not_dict = complement(is_dict)

def is_indexable(s):
    return hasattr(s, '__getitem__')

def is_seq(s):
    return (
        isinstance(s, collections.abc.Iterable)
        and                     # noqa
        (not is_dict(s))
        and                     # noqa
        (not isinstance(s, (str, bytes)))
    )
is_not_seq = complement(is_seq)

def fmaybe(func):
    '''Turn a function into a Maybe monad(ish)
    '''
    @functools.wraps(func)
    def maybe_monad(*a, **kw):
        try:
            return maybe(func(*a, **kw))
        except Exception as error:
            logging.exception(
                f'Exception in {func}:\n\n{str(error)[:1000]}'
            )
        return Nothing()
    return maybe_monad
maybe_call = fmaybe

@curry
def maybe_int(value, default=Nothing()):
    '''Convert to int or return Nothing (or default)

    '''
    if is_int(value):
        return int(value)
    return default

def is_int(value):
    if type(value) is float:
        return False
    try:
        int(value)
    except ValueError:
        return False
    except TypeError:
        return False
    return True

@curry
def maybe_float(value, default=Nothing()):
    '''Convert to float or return Nothing (or default)

    '''
    if is_float(value):
        return float(value)
    return default

float_or_zero = maybe_float(default=0)

def is_float(value):
    try:
        float(value)
    except ValueError:
        return False
    except TypeError:
        return False
    return True

def is_numeric(value):
    if is_float(value) or is_int(value):
        return True
    return False

def is_none(v):
    return maybe(v).is_none()
def is_some(v):
    return maybe(v).is_some()
is_not_none = is_some

def flatdict(obj: Union[dict, Any], keys=()):
    '''Flatten a Python dictionary such that nested values are returned
    with the key sequence required to access them.

    Examples:

    >>> pipe({'a': {'b': [1, 2, 3]}, 'c': 2}, flatdict, list)
    [('a', 'b', [1, 2, 3]), ('c', 2)]
    '''
    if is_dict(obj):
        for k, v in obj.items():
            yield from flatdict(v, keys + (k, ))
    else:
        yield keys + (obj,)

@curry
def as_tuple(func, filter_none: bool = False):
    '''
    Function decorator that causes a generator function to return a tuple of its
    generated values.

    Examples: 

    >>> @as_tuple
    ... def f():
    ...     yield 1
    ...     yield 2
    ...
    >>> f() == (1, 2)
    True
    >>> @as_tuple(filter_none=True)
    ... def f():
    ...     yield 1
    ...     yield []
    ...     yield 2
    ...     yield None
    ...
    >>> f() == (1, 2)
    True
    '''
    @functools.wraps(func)
    def wrapper(*a, **kw):
        return pipe(
            func(*a, **kw),
            filter(None) if filter_none else noop,
            tuple,
        )
    return wrapper

def as_dict(func):
    '''
    Function decorator that causes a generator function to return a merged
    dictionary of generated dictionaries

    Examples: 

    >>> @as_dict
    ... def f():
    ...     yield {'a': 1}
    ...     yield {'b': 2}
    ...
    >>> f() == {'a': 1, 'b': 2}
    True
    '''
    @functools.wraps(func)
    def wrapper(*a, **kw):
        return pipe(
            func(*a, **kw),
            filter(None),
            merge,
        )
    return wrapper

# ---------------------------
# String in-line functions
# ---------------------------

streamable = str | bytes | io.IOBase

def to_io(value: streamable):
    match value:
        case io_obj if isinstance(io_obj, io.IOBase):
            return io_obj
        case value_b if isinstance(value_b, bytes):
            return io.BytesIO(value_b)
        case value_s if isinstance(value_s, str):
            return io.StringIO(value_s)
        case _:
            raise IOError(
                f'Cannot deal with type {type(value)}'
            )

def help_text(s):
    return textwrap.shorten(s, 1e300)

@curry
def wrap_text(width, text, **wrap_kw):
    return pipe(
        textwrap.wrap(text, width, **wrap_kw),
        '\n'.join,
    )


def strip(chars: Optional[str] = None, value: str = None):
    '''In-line string strip function

    Examples:

    >>> strip(None, '  a  ') == 'a'
    True
    >>> pipe('  a  ', strip()) == 'a'
    True
    >>> pipe('---a----', strip('-')) == 'a'
    True
    >>> pipe('---a----', strip(chars='-')) == 'a'
    True
    '''
    if value is not None:
        return value.strip(chars)

    def strip_inner(*args):
        nonlocal value, chars
        match args, chars:
            case (), None:
                raise ArgumentError(
                    'Calling strip with neither chars nor value'
                )
            case (value,), None:
                pass
            case (value,), chars:
                pass
            case too_many, chars:
                raise ArgumentError(
                    f'Too many arguments: {len(too_many)} with chars {chars}'
                )
        return value.strip(chars)
    return strip_inner

def split(sep: Optional[str] = None, value: Optional[str] = None,  maxsplit=-1):
    '''In-line string split function

    Examples:

    >>> split(None, 'a b') == ['a', 'b']
    True
    >>> pipe('a b', split()) == ['a', 'b']
    True
    >>> pipe('a,b', split(','))
    ['a', 'b']
    '''
    if value is not None:
        return value.split(sep, maxsplit)

    def splitter(*args):
        nonlocal sep, value, maxsplit
        match args, sep:
            case (), None:
                raise ArgumentError(
                    'Calling split with neither sep or value'
                )
            case (value,), None:
                pass
            case (value,), sep:
                pass
            case too_many, sep:
                raise ArgumentError(
                    f'Too many arguments: {len(too_many)} with sep {sep}'
                )

        return value.split(sep, maxsplit)
    return splitter

@curry
def splitlines(value: streamable, keepends=False):
    '''
    In-line string splitlines function. Stream-safe.
    '''
    for line in to_io(value):
        if keepends:
            yield line
        else:
            if line.endswith('\n'):
                yield line[:-1]
            else:
                yield line

def lower(value: str):
    'In-line string lower function'
    return value.lower()

def upper(value: str):
    'In-line string upper function'
    return value.upper()

@curry
def startswith(prefix: Union[str, bytes], string: Union[str, bytes]):
    return string.startswith(prefix)

@curry
def endswith(prefix: Union[str, bytes], string: Union[str, bytes]):
    return string.startswith(prefix)

def do_slice(start: int, stop: int = None, step: int = None):
    def slicer(value: str):
        return value[start:stop:step]
    return slicer

@curry
def replace(old: str, new: str, value: str, count: int = -1):
    'In-line string replace'
    return value.replace(old, new, count)

# ---------------------------
# Dictionary in-line functions

def items(d: dict):
    'Items accessor for dictionaries'
    return d.items()

def values(d: dict):
    'Values accessor for dictionaries'
    return d.values()

def keys(d: dict):
    'Keys accessor for dictionaries'
    return d.keys()

# ----------------------------------------------------------------------
#
# Supplemental versions of toolz functions, especially variadic versions.
#
# ----------------------------------------------------------------------

@curry
def vcall(func, value):
    '''Variadic call

    Example:

    >>> pipe([1, 2], vcall(lambda a, b: a + b))
    3
    '''
    return func(*value)

@curry
def vmap(func, seq):
    '''Variadic map

    Example:

    >>> pipe([(2, 1), (2, 2), (2, 3)], vmap(lambda a, b: a ** b), tuple)
    (2, 4, 8)
    '''
    return pipe(
        seq,
        map(vcall(func)),
    )

starmap = vmap

@curry
def mapget(key, seq, *, default=None):
    '''map(get) combo

    Example:

    >>> pipe([{'a': 1}, {'a': 2}], mget('a'), sum) == 3
    True
    '''
    return pipe(
        seq,
        map(get(key, default=default)),
    )
mget = mapget

@curry
def vfilter(func, seq):
    '''Variadic filter

    Example:

    >>> pipe([(1, 2), (4, 3), (5, 6)], vfilter(lambda a, b: a < b), tuple)
    ((1, 2), (5, 6))
    '''
    return pipe(
        seq,
        filter(vcall(func)),
    )

@curry
def vmapcat(func, seq):
    '''Variadic mapcat

    Example:

    >>> pipe([(1, 2), (4, 3), (5, 6)], vmapcat(lambda a, b: [a] * b), tuple)
    (1, 1, 4, 4, 4, 5, 5, 5, 5, 5, 5)
    '''
    return pipe(
        seq,
        mapcat(vcall(func)),
    )

@curry
def vgroupby(key_func, seq):
    '''Variadic groupby

    Examples:

    >>> pipe([(1, 2, 3), (4, 5, 6)], vgroupby(lambda a, b, c: a + b))
    {3: [(1, 2, 3)], 9: [(4, 5, 6)]}
    '''
    return pipe(
        seq,
        groupby(vcall(key_func)),
    )

@curry
def vvalmap(func, d, **kw):
    '''Variadic valmap for dictionaries
    '''
    return pipe(
        d, valmap(vcall(func), **kw)
    )

@curry
def vitemmap(func, d, **kw):
    '''Variadic itemmap for dictionaries
    '''
    return pipe(
        d, itemmap(vcall(func), **kw)
    )

@curry
def vkeymap(func, d, **kw):
    '''Variadic keymap for dictionaries
    '''
    return pipe(
        d, keymap(vcall(func), **kw)
    )

concat_t = compose_left(concat, tuple)
concatv_t = compose_left(concatv, tuple)

def cconcat(start_iterable: Iterable):
    '''Curried concat
    '''
    def curried_concat(end_iterable: Iterable):
        return concat([start_iterable, end_iterable])
    return curried_concat

def cconcatv(start_iterable: Iterable):
    '''Curried concatv
    '''
    def curried_concatv(end_iterable: Iterable):
        return concatv(start_iterable, end_iterable)
    return curried_concatv

@curry
def select(keys, iterable):
    '''Select a set of keys out of each indexable in iterable. Assumes
    that these keys exist in each indexable (i.e. will throw
    IndexError or KeyError if they don't)

    Example:

    >>> pipe([{'a': 1, 'b': 2}, {'a': 3, 'b': 4}], select(['a', 'b']), tuple)
    ((1, 2), (3, 4))

    '''
    for indexable in iterable:
        yield tuple(indexable[k] for k in keys)

@curry
def find(find_func, iterable, *, default=Nothing()):
    '''Finds first value in iterable that when passed to find_func returns
    truthy

    Example:

    >>> pipe([0, 0, 1, -1, -2], find(lambda v: v < 0))
    -1
    '''
    for value in iterable:
        if find_func(value):
            return value
    return default

@curry
def vfind(find_func, iterable, *, default=Nothing()):
    '''Variadic find: finds first value in iterable that when passed to
    find_func returns truthy

    Example:

    >>> pipe([(0, 0), (0, 1)], vfind(lambda a, b: a < b))
    (0, 1)

    '''
    return find(vcall(find_func), iterable)

@curry
def index(find_func, iterable, *, default=Nothing()):
    '''Finds index of the first value in iterable that when passed to
    find_func returns truthy

    Example:

    >>> pipe([0, 0, 1, -1, -2], index(lambda v: v < 0))
    3

    '''
    for i, value in enumerate(iterable):
        if find_func(value):
            return i
    return default

@curry
def vindex(find_func, iterable, *, default=Nothing()):
    '''Variadic index: finds index of first value in iterable that when
    passed to find_func returns truthy

    Example:

    >>> pipe([(0, 0), (0, 1)], vindex(lambda a, b: a < b))
    1

    '''
    return index(vcall(find_func), iterable)

@curry
def seti(index, func, iterable):
    '''Return copy of iterable with value at index modified by func

    Examples:

    >>> pipe([10, 5, 2], seti(2, lambda v: v**2), list)
    [10, 5, 4]
    '''
    for i, v in enumerate(iterable):
        if i == index:
            yield func(v)
        else:
            yield v
seti_t = compose(tuple, seti)

@curry
def vseti(index, func, iterable):
    '''Variadict seti: return iterable of seq with value at index modified
    by func

    Examples:

    >>> pipe(
    ...   [(10, 1), (5, 2), (2, 3)],
    ...   vseti(2, lambda v, e: v**e),
    ...   list
    ... )
    [(10, 1), (5, 2), 8]
    '''
    return seti(index, vcall(func), iterable)
vseti_t = compose(tuple, vseti)

@curry
def callif(if_func, func, value, *, default=Nothing()):
    '''Return func(value) only if if_func(value) returns truthy, otherwise
    default=Nothing()

    Examples:

    >>> str(callif(lambda a: a > 0, lambda a: a * a)(-1))
    'None'
    >>> callif(lambda a: a > 0, lambda a: a * a)(2)
    4
    '''
    if if_func(value):
        return func(value)
    return default

@curry
def vcallif(if_func, func, value, *, default=Nothing()):
    '''Variadic callif: return func(value) only if if_func(value) returns
    truthy, otherwise default=Nothing(). Both if_func and func are called
    variadically.

    Examples:

    >>> pipe((-1, 1), vcallif(lambda a, b: a > 0, lambda a, b: b * b))
    None
    >>> pipe((2, 5), vcallif(lambda a, b: a > 0, lambda a, b: b * b))
    25

    '''
    return callif(vcall(if_func), vcall(func), value, default=default)

@curry
def vdo(func, value):
    '''Variadic do

    '''
    return do(vcall(func), value)

@curry
def do_log(logger, msg: Union[str, Callable], value: Any, **kw):
    if callable(msg):
        msg = msg(value)
    logger(msg, **kw)
    return value
do_info = compose_left(
    lambda logger: do_log(logger.info)
)
do_error = compose_left(
    lambda logger: do_log(logger.error)
)

@curry
def map_t(func, values):
    return pipe(
        values,
        map(func),
        tuple,
    )

@curry
def filter_t(func, values):
    return pipe(
        values,
        filter(func),
        tuple,
    )

@curry
def mapdo(do_func, iterable):
    '''Map a do function over values in iterable. It will generate all
    values in iterable immediately, run do_func over those values, and
    return the values as a tuple (i.e. there are **side effects**).

    Examples:

    >>> l = [0, 1, 2]
    >>> pipe(l, mapdo(print))
    0
    1
    2
    (0, 1, 2)
    >>> l is pipe(l, mapdo(noop))
    False

    '''
    values = tuple(iterable)
    for v in values:
        do_func(v)
    return values

@curry
def vmapdo(do_func, iterable):
    return mapdo(vcall(do_func), iterable)

@curry
def mapif(func, seq):
    # return [func(*v) for v in seq]
    if func:
        return (func(v) for v in seq)
    return seq

@curry
def vmapif(func, seq):
    # return [func(*v) for v in seq]
    if func:
        return (func(*v) for v in seq)
    return seq

def shuffled(seq):
    tup = tuple(seq)
    return random.sample(tup, len(tup))

@curry
def first_true(iterable, *, default=Nothing()):
    '''Return the first truthy thing in iterable. If none are true, return
    default=Nothing().

    '''
    for v in iterable:
        if v:
            return v
    return default

get_t = compose_left(get, tuple)

def maybe_pipe(value, *functions, default=Nothing()):
    '''Sort-of Maybe monad. Pipe value through series of functions unless
    and until one of them returns a "null" (i.e. None or Null) value
    or throws an Exception, where it will return Null or a non-null
    default value)

    '''
    if is_none(value):
        return default
    for f in functions:
        try:
            value = f(value)
        except Exception:
            log.error(f'Error in maybe_pipe: \n{traceback.format_exc()}')
            return default
        if is_none(value):
            return default
    return value

@curry
def maybe_max(iterable, *, default=Nothing(), **kw):
    '''Return max of iterable or (if empty) return Nothing()

    '''
    try:
        return max(iterable, **kw)
    except ValueError:
        return default

@curry
def maybe_min(iterable, *, default=Nothing(), **kw):
    '''Return min of iterable or (if empty) return Nothing()

    '''
    try:
        return min(iterable, **kw)
    except ValueError:
        return default

@curry
def maybe_mean(iterable, *, default=Nothing(), **kw):
    '''Return mean of iterable or (if empty) return Nothing()

    '''
    try:
        return statistics.mean(iterable, **kw)
    except statistics.StatisticsError:
        return default

@curry
def maybe_median(iterable, *, default=Nothing(), **kw):
    '''Return median of iterable or (if empty) return Nothing()

    '''
    try:
        return statistics.median(iterable, **kw)
    except statistics.StatisticsError:
        return default

@curry
def maybe_mode(iterable, *, default=Nothing(), **kw):
    '''Return mode of iterable or (if empty) return Nothing()

    '''
    try:
        return statistics.mode(iterable, **kw)
    except statistics.StatisticsError:
        return default

@curry
def short_circuit(function, value, *, default=Nothing()):
    '''If function(value) is falsy, return Nothing. Useful for
    inserting into maybe_pipe to short-circuit.

    Different from maybe in that maybe is specifically for "null"
    values, not falsy things.

    '''
    if not function(value):
        return default
    return value

def sc_juxt(*funcs, default=Nothing()):
    '''Short-circuiting juxt

    '''
    def caller(*a, **kw):
        sc = False
        for f in funcs:
            if sc:
                yield default
            output = f(*a, **kw)
            if not output:
                sc = True
                yield default
            else:
                yield output
    caller.__doc__ = help_text(f'''
    Juxtaposition of {pipe(funcs, map(deref('__name__')), ', '.join)}.
    Will short-circuit on the first falsy return value and return Nothing
    thereafter.
    ''')
    return caller

@curry
def maybe_first(iterable, *, default=Nothing()):
    '''Return first element of iterable. If empty return default=Nothing().

    '''
    try:
        return first(iterable)
    except StopIteration:
        pass
    return default

@curry
def maybe_second(iterable, *, default=Nothing()):
    '''Return second element of iterable. If empty return default=Nothing().

    '''
    try:
        return second(iterable)
    except StopIteration:
        pass
    return default

@curry
def maybe_last(iterable, *, default=Nothing()):
    '''Return last element of iterable If empty return default=Nothing().

    '''
    try:
        return last(iterable)
    except StopIteration:
        pass
    return default

# ----------------------------------------------------------------------
#
# Builtin function/object supplements
#
# ----------------------------------------------------------------------

@curry
def cprint(value_func=noop, **print_kw):
    def do_print(value, **kw):
        return print(value_func(value), **merge(print_kw, kw))
    return do_print

@curry
def max(iterable, **kw):
    '''Curried max

    Examples:

    >>> pipe([5, 2, 1, 10, -1], max())
    10
    >>> pipe([5, 2, 1, 10, -1], max(key=lambda v: 1 / v))
    1
    '''
    return builtins.max(iterable, **kw)

@curry
def min(iterable, **kw):
    '''Curried min

    Examples:

    >>> pipe([5, 2, 1, 10, 4], min())
    1
    >>> pipe([5, 2, 1, 10, 4], min(key=lambda v: 1 / v))
    10
    '''
    return builtins.min(iterable, **kw)

@curry
@functools.wraps(builtins.sorted)
def sorted(iterable, **kw):
    '''Curried sorted

    Examples:

    >>> pipe([5, 2, 6], sorted)
    [2, 5, 6]
    '''
    return builtins.sorted(iterable, **kw)

@curry
def sort_by(func, iterable, **kw):
    '''Sort iterable by key=func

    Examples:

    >>> pipe([{'a': 1}, {'a': 8}, {'a': 2}], sort_by(get('a')))
    [{'a': 1}, {'a': 2}, {'a': 8}]
    '''
    if is_str(func) or is_int(func):
        func = get(func)

    return builtins.sorted(iterable, key=func, **kw)

def cat_to_set(iterable):
    '''Concatenate all iterables in iterable to single set

    Examples:

    >>> the_set = pipe([(1, 2), (3, 2), (2, 8)], cat_to_set)
    >>> the_set == {1, 2, 3, 8}
    True
    '''
    result = set()
    for iterable_value in iterable:
        result.update(iterable_value)
    return result

@curry
def map_to_set(func: Callable[[Any], Hashable], iterable):
    '''Map func over iterable, reduce result to set.

    Return value of func needs to be hashable.

    Examples:

    >>> the_set = pipe([(1, 2), (3, 2), (2, 8)], map_to_set(lambda v: v[0]))
    >>> the_set == {1, 2, 3}
    True
    '''
    result = set()
    for value in iterable:
        result.add(func(value))
    return result

def most_common(obj: Union[Counter, Iterable[Hashable]]):
    match obj:
        case counter if isinstance(counter, Counter):
            return counter.most_common()
        case iterable:
            return pipe(
                iterable,
                Counter,
                lambda c: c.most_common(),
            )
