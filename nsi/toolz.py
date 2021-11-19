import os
import re
import logging
import builtins
import random
import traceback
import inspect
import functools
import collections
import base64
import json
import importlib
import textwrap
import contextlib
import io
import csv
import functools
import math
import urllib
from ipaddress import ip_network, ip_interface, ip_address
from pathlib import Path
import string
from datetime import datetime as _datetime
import socket
from typing import *
import hashlib
import tempfile                 # noqa: for doctest

from pyrsistent import pmap, pvector, PVector
import pymaybe
from pymaybe import maybe, Maybe, Nothing, Something
import dateutil.parser
import ifcfg
import requests
import jmespath
import bs4

try:
    from cytoolz.curried import *
except ImportError:
    from toolz.curried import *

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

# ----------------------------------------------------------------------
#
# Curried object access/calling
#
# ----------------------------------------------------------------------

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

    '''
    return value in obj

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
def do_log(logger, msg, value, **kw):
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

@curry
def groupdicts(regex, iterable, keep_match=False, **kw):
    '''Given a regex (str or re.Pattern), and iterable of strings, 
    produce single dictionary of all groupdicts of matches
    '''
    regex = regex if isinstance(regex, re.Pattern) else re.compile(regex, **kw)
    return pipe(
        iterable,
        map(regex.search),
        filter(None),
        map(lambda m: merge(
            m.groupdict(), {'__match__': m} if keep_match else {}
        )),
    )

@curry
def groupdicts_from_regexes(regexes: Sequence[re.Pattern],
                            iterable: Iterable[str], **kw):
    '''Given a sequence of regexes and an iterable of strings,
    produce a list of merged groupdicts for those regexes
    '''
    return pipe(
        iterable,
        juxt(*[compose(list, groupdicts(r, **kw)) for r in regexes]),
        concat,
    )

@curry
def grep(raw_regex, iterable, **kw):
    regex = re.compile(raw_regex, **kw)
    return filter(lambda s: regex.search(s), iterable)

@curry
def grep_t(raw_regex, iterable, **kw):
    return pipe(
        grep(raw_regex, iterable, **kw),
        tuple,
    )

@curry
def grepv(raw_regex, iterable, **kw):
    regex = re.compile(raw_regex, **kw)
    return filter(lambda s: not regex.search(s), iterable)

@curry
def grepv_t(raw_regex, iterable, **kw):
    return pipe(
        grepv(raw_regex, iterable, **kw),
        tuple,
    )

@curry
def grepitems(raw_regex, iterable, **kw):
    regex = re.compile(raw_regex, **kw)
    return pipe(
        iterable,
        filter(lambda items: any(regex.search(s) for s in items)),
        tuple,
    )

@curry
def grepvitems(raw_regex, iterable, **kw):
    regex = re.compile(raw_regex, **kw)
    return pipe(
        iterable,
        filter(lambda items: not any(regex.search(s) for s in items)),
        tuple,
    )

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
# Logging operations
#
# ----------------------------------------------------------------------

@curry
def log_lines(log_function, lines):
    return pipe(
        lines,
        mapcat(lambda line: line.splitlines()),
        filter(None),
        map(log_function),
    )

# ----------------------------------------------------------------------
#
# File operations
#
# ----------------------------------------------------------------------

def is_path_type(t):
    return t in {
        Union[str, Path], Path
    }

POS_PARAM_KINDS = {
    inspect.Parameter.POSITIONAL_ONLY,
    inspect.Parameter.POSITIONAL_OR_KEYWORD,
    inspect.Parameter.VAR_POSITIONAL,
}
def ensure_paths(func):
    '''Ensure that all path-like arguments of this function are converted into
    Path objects

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
        if is_path_type(param.annotation)
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
            a[i] = Path(a[i]).expanduser()
        for k, v in kw.items():
            if k in path_params:
                kw[k] = Path(v).expanduser()
        return func(*a, **kw)
    return path_arg_converter

@ensure_paths
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
    return path.read_text()

def slurp_lines(path: Union[str, Path]):
    '''Slurp file contents and split lines
    '''    
    return pipe(
        path,
        slurp,
        call('splitlines')
    )


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

def to_str(content, encoding='utf-8', errors='ignore'):
    '''Convert this object into a string, decoding from bytes if necessary
    '''
    match type(content):
        case builtins.bytes:
            return content.decode(encoding, errors)
    return str(content)

def to_bytes(content, encoding='utf-8', errors='ignore'):
    '''Convert this object as bytes, encoding if necessary
    '''
    match type(content):
        case builtins.str:
            return content.encode(encoding, errors)
        case builtins.bytes:
            return content
    return str(content).encode(encoding, errors)

def is_dict(d):
    return isinstance(d, collections.abc.Mapping)
is_not_dict = complement(is_dict)

def is_indexable(s):
    return hasattr(s, '__getitem__')

def is_seq(s):
    return (
        isinstance(s, collections.abc.Iterable) 
        and 
        (not is_dict(s))
        and 
        (not isinstance(s, (str, bytes)))
    )
is_not_seq = complement(is_seq)

@curry
def maybe_int(value, default=Nothing()):
    '''Convert to int or return Nothing (or default)

    '''
    if is_int(value):
        return int(value)
    return default

def is_int(value):
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

def is_none(v):
    return maybe(v).is_none()
def is_some(v):
    return maybe(v).is_some()

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

def as_tuple(func):
    @functools.wraps(func)
    def wrapper(*a, **kw):
        return tuple(func(*a, **kw))
    return wrapper

@curry
def split(sep:str, value: str, **kw):
    return value.split(sep, **kw) if sep is not None else value.split(**kw)

def lower(value: str):
    return value.lower()
    
def upper(value: str):
    return value.upper()

@curry
def replace(a: str, b: str, value: str, **kw):
    return value.replace(a, b, **kw)

def items(d: dict):
    return d.items()
    
# ----------------------------------------------------------------------
#
# Hashing and encoding functions
#
# ----------------------------------------------------------------------

def b64decode(content: Union[bytes, str]):
    return base64.b64decode(
        to_bytes(content) + b'=' * (len(content) % 4)
    )
b64decode_str = compose_left(b64decode, to_str)

def b64encode(content: Union[bytes, str]):
    return pipe(
        content,
        to_bytes,
        base64.b64encode,
    )
b64encode_str = compose_left(b64encode, to_str)

@curry
def hash(path: Union[str, Path], hash_func=hashlib.sha256):
    hash_obj = hash_func()
    with Path(path).expanduser().open('rb') as rfp:
        for chunk in iter(lambda: rfp.read(4096), b''):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

# ----------------------------------------------------------------------
#
# Random content creation functions
#
# ----------------------------------------------------------------------

def random_str(n=8, *, rng=None, exclude: Sequence = None):
    rng = rng or random
    r_str = ''.join(rng.choice(string.ascii_letters) for _ in range(n))
    if exclude and r_str in exclude:
        return random_str(n, rng=rng, exclude=exclude)
    return r_str

def random_sentence(w=10, *, rng=None):
    rng = rng or random
    return pipe(
        [random_str(rng.randrange(4, 10), rng=rng) for i in range(w)],
        lambda s: [s[0].capitalize()] + s[1:],
        ' '.join,
        lambda s: s + '.'
    )

def random_user(n=8, *, rng=None):
    rng = rng or random
    return ''.join(rng.choice(string.ascii_lowercase) for _ in range(n))

def random_pw(n=16, *, rng=None, pop=string.printable[:64]):
    rng = rng or random
    return ''.join(rng.choice(pop) for _ in range(n))

@curry
def random_sample(N, seq, *, rng=None):
    rng = rng or random
    return rng.sample(tuple(seq), N)


# ----------------------------------------------------------------------
#
# pyrsistent object functions
#
# ----------------------------------------------------------------------

def to_pyrsistent(obj):
    '''Convert object to immutable pyrsistent objects

    Examples:

    >>> to_pyrsistent({'a': 1})
    pmap({'a': 1})
    
    >>> to_pyrsistent({'a': [1, 2, 3]})['a']
    pvector([1, 2, 3])
    
    >>> to_pyrsistent({'a': [1, 2, 3]})['a'][0] = 2
    Traceback (most recent call last):
      ...
    TypeError: 'pvectorc.PVector' object does not support item assignment
    '''
    # return pyrsistent.freeze(obj)
    if is_dict(obj):
        return pipe(
            obj.items(),
            vmap(lambda k, v: (k, to_pyrsistent(v))),
            pmap,
        )
    if is_seq(obj):
        return pipe(obj, map(to_pyrsistent), pvector)
    return obj

def no_pyrsistent(obj):
    '''Convert all pyrsistent objects to Python types

    pmap -> dict
    pvector -> tuple

    Examples:

    >>> pipe(pmap({'a': pvector([1, 2, 3])}), no_pyrsistent)
    {'a': (1, 2, 3)}
    '''
    # return pyrsistent.thaw(obj)
    match obj:
        case dobj if is_dict(obj):
            return pipe(
                dobj.items(),
                vmap(lambda k, v: (
                    no_pyrsistent(k), 
                    no_pyrsistent(v)
                )),
                dict,
            )
        case seq if is_seq(seq):
            return pipe(seq, map(no_pyrsistent), tuple)
        case pymaybe.Nothing():
            return None

    t_map = [
        (is_str, str),
        (is_int, int),
        (is_float, float),
        ((lambda v: maybe_float(v) == v), float),
        ((lambda v: maybe_int(v) == v), int),
    ]

    for test_f, transform_f in t_map:
        if test_f(obj):
            return transform_f(obj)
    return obj

def freeze(func):
    '''Ensure output of func is immutable

    Uses to_pyrsistent on the output of func

    Examples:
    
    >>> @freeze
    ... def f():
    ...     return [1, 2, 3]
    >>> f()
    pvector([1, 2, 3])
    '''
    @functools.wraps(func)
    def return_frozen(*a, **kw):
        return pipe(func(*a, **kw), to_pyrsistent)
    return return_frozen

frozen_curry = compose_left(freeze, curry)


# ----------------------------------------------------------------------
#
# Error handling functions
#
# ----------------------------------------------------------------------

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

# ----------------------------------------------------------------------
#
# Time-oriented functions
#
# ----------------------------------------------------------------------

def ctime(path: Union[str, Path]):
    return Path(path).stat().st_ctime

def maybe_dt(ts, *, default=Nothing()):
    '''Parse ts to datetime object (using dateutil.parser.parse) or return
    Null

    '''
    if isinstance(ts, _datetime):
        return ts

    if ts is None:
        return default

    try:
        return dateutil.parser.parse(ts)
    except ValueError:
        return default

def parse_dt(ts: str, local=False):
    dt = dateutil.parser.parse(ts)
    if local:
        return dt.astimezone(dateutil.tz.tzlocal())
    return dt

def ctime_as_dt(path: Union[str, Path]):
    return pipe(
        path,
        ctime,
        _datetime.fromtimestamp,
    )
dt_ctime = ctime_as_dt

@curry
def to_dt(value, default=_datetime.fromtimestamp(0)):
    '''Attempt to parse the given value as a datetime object, otherwise
    return default=epoch

    Will try:
    - dateutil.parser.parse
    - 20190131T130506123456 (i.e. with microseconds)

    '''
    try_except = [
        (lambda v: dateutil.parser.parse(v), (ValueError, TypeError)),
        (lambda v: datetime.strptime(v, "%Y%m%dT%H%M%S%f"),
         (ValueError, TypeError)),
    ]
    for func, excepts in try_except:
        try:
            output = func(value)
            return output
        except excepts:
            continue
    return default

# ----------------------------------------------------------------------
#
# Filesystem functions
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
    >>> paths == (Path(root, 'a', 'a.txt').resolve(), Path(root, 'a', 'b', 'b.txt').resolve())
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


# ----------------------------------------------------------------------
#
# Dictionary functions
#
# ----------------------------------------------------------------------

@curry
def dict_hash(hash_func, d):
    '''Hash a dictionary with hash function (e.g. SHA1)

    Examples:

    >>> pipe({"a": 1}, dict_hash(hashlib.sha1))
    'e4ad4daad53a2eec0313386ada88211e50d693bd'
    '''
    return pipe(
        no_pyrsistent(d),
        lambda d: json.dumps(d, sort_keys=True),
        to_bytes,
        lambda b: hash_func(b).hexdigest(),
    )


def cmerge(*dicts):
    '''Curried dictionary merge

    Examples:

    >>> merged = pipe({'a': 1}, cmerge({'b': 2}, {'c': 3}))
    >>> merged == {'a': 1, 'b': 2, 'c': 3}
    True

    '''
    def do_merge(*more_dicts):
        '''More dots. More dots. No more dots.
        '''
        return merge(*(dicts + more_dicts))
    return do_merge

@curry
def create_key(key: Hashable, value_function, d):
    '''Create key in a given dictionary if it doesn't already exist

    Args:
      key (Hashable): key to be added (if it doesn't already exist)
    
      value_function (Callable[[dict], Any]): function that takes the
        dictionary and returns a value for the new key

      d (dict): dictionary to transform (with no side effects)

    Returns: (dict) new state of dictionary

    Examples:

    >>> new = pipe({'b': 2}, create_key('a', lambda d: d['b'] + 10))
    >>> new == {'a': 12, 'b': 2}
    True
    >>> new = pipe({'a': 1, 'b': 2}, create_key('a', lambda d: d['b'] + 10))
    >>> new == {'a': 1, 'b': 2}
    True

    '''
    if key not in d:
        return assoc(d, key, value_function(d))
    return d

@curry
def update_key(key: Hashable, value_function, d):
    '''Update key's value for a given dictionary. Will add key if it
    doesn't exist. Basically just a curried version of assoc.

    Args:
      key (Hashable): key to be updated
    
      value_function (Callable[[dict], Any]): function that takes the
        dictionary and returns a value for the key

      d (dict): dictionary to transform (with no side effects)

    Returns: (dict) new state of dictionary

    Examples:

    >>> new = pipe({'b': 2}, update_key('a', lambda d: d['b'] + 10))
    >>> new == {'a': 12, 'b': 2}
    True
    >>> new = pipe({'a': 1, 'b': 2}, update_key('a', lambda d: d['b'] + 10))
    >>> new == {'a': 12, 'b': 2}
    True

    '''
    return assoc(d, key, value_function(d))

@curry
def update_key_v(key: Hashable, value_function, d, default=None):
    '''Update key's value for a given dictionary. Will add key if it
    doesn't exist.

    Args:
      key (Hashable): key to be updated
    
      value_function (Callable[[Any], Any]): function that takes the
        current value of key (or default) and returns a value for the
        key

      default (Any=None): default value to be provided to the
        value_function if the key doesn't already exist in the
        dictionary

      d (dict): dictionary to transform (with no side effects)

    Returns: (dict) new state of dictionary

    Examples:

    >>> new = pipe({'b': 2}, update_key_v('a', lambda v: v + 5, default=0))
    >>> new == {'a': 5, 'b': 2}
    True
    >>> new = pipe({'a': 4}, update_key_v('a', lambda v: v + 5, default=0))
    >>> new == {'a': 9}
    True

    '''
    return assoc(d, key, value_function(d.get(key, default)))

@curry
def only_if_key(key, func, d):
    '''Return func(d) if key in d, otherwise return d

    '''
    return func(d) if key in d else d

@curry
def update_if_key_exists(key: Hashable, value_function, d):
    '''Update key only if it already exists

    Args:
      key (Hashable): key to be updated (if the key already exists)
    
      value_function (Callable[[dict], Any]): function that takes the
        dictionary and returns a value for the key

      d (dict): dictionary to transform (with no side effects)

    Returns: (dict) new state of dictionary

    Examples:

    >>> pipe({}, update_if_key_exists('a', lambda d: d['a'] + 5))
    {}
    >>> pipe({'a': 4}, update_if_key_exists('a', lambda d: d['a'] + 5))
    {'a': 9}

    '''
    if key in d:
        return assoc(d, key, value_function(d))
    return d

@curry
def set_key(key: Hashable, value, d):
    '''Curried assoc

    Args:
      key (Hashable): key to be updated
    
      value (Any): value for the key

      d (dict): dictionary to transform (with no side effects)

    Returns: (dict) new state of dictionary

    Examples:

    >>> new = pipe({'b': 2}, set_key('a', 5))
    >>> new == {'a': 5, 'b': 2}
    True

    '''
    return assoc(d, key, value)

@curry
def drop_key(key: Hashable, d):
    ''' Curried dissoc

    Args:
      key (Hashable): key to be removed
    
      d (dict): dictionary to transform (with no side effects)

    Returns: (dict) new state of dictionary

    Examples:

    >>> pipe({'b': 2}, drop_key('b'))
    {}
    >>> pipe({'a': 2}, drop_key('b'))
    {'a': 2}
    
    '''
    return dissoc(d, key)
remove_key = drop_key

@curry
def drop_keys(keys: Iterable[Hashable], d):
    '''Curried dissoc (multiple keys)

    Args:
      keys (Iterable[Hashable]): keys to be removed
    
      d (dict): dictionary to transform (with no side effects)

    Returns: (dict) new state of dictionary

    Examples:

    >>> pipe({'a': 1, 'b': 2}, drop_keys(['a', 'b']))
    {}
    >>> pipe({'a': 2, 'b': 2}, drop_keys(['b', 'c']))
    {'a': 2}

    '''
    return dissoc(d, *keys)
remove_keys = drop_keys

@curry
def merge_keys(from_: Iterable[Hashable], to: Hashable, value_function, d):
    '''Merge multiple keys into a single key

    Args:
      from_ (Iterable[Hashable]): keys to be merged

      to (Hashable): key into which the from_ will be merged

      value_function (Callable[[dict], Any]): function that takes the
        dictionary and returns a value for the key given by "to"
        parameter

      d (dict): dictionary to transform (with no side effects)

    Returns: (dict) new state of dictionary

    Examples:

    >>> pipe(
    ...   {'a': 1, 'b': 2},
    ...   merge_keys(['a', 'b'], 'c', lambda d: d['a'] + d['b']),
    ... )
    {'c': 3}

    '''
    value = value_function(d)
    return pipe(d, drop_keys(from_), set_key(to, value))

@curry
def replace_key(k1, k2, value_function, d):
    '''Drop key k1 and replace with k2 if k1 exists

    Args:
      k1 (Hashable): key to drop

      k2 (Hashable): key to replace k1

      value_function (Callable[[dict], Any]): function that takes the
        dictionary and returns a value for the k2 key

      d (dict): dictionary to transform (with no side effects)

    Returns: (dict) new state of dictionary

    Examples:

    >>> pipe(
    ...   {'a': 1},
    ...   replace_key('a', 'c', lambda d: d['a'] + 2),
    ... )
    {'c': 3}

    '''
    if k1 in d:
        return merge_keys([k1], k2, value_function or get(k1), d)
    return d
switch_keys = replace_key
# @curry
# def switch_keys(k1, k2, value_function, d):
#     return pipe(
#         assoc(d, k2, value_function(d)),
#         drop_key(k1)
#     )

@curry
def valmaprec(func, d, **kw):
    '''Recursively map values of a dictionary (traverses Mapping and
    Sequence objects) using a function

    '''
    if is_dict(d):
        return pipe(
            d.items(),
            vmap(lambda k, v: (k, valmaprec(func, v, **kw))),
            type(d),
        )
    elif is_seq(d):
        return pipe(
            d, map(valmaprec(func, **kw)), type(d),
        )
    else:
        return func(d)

@curry
def match_d(match: dict, d: dict, *, default=Nothing()):
    '''Given a match dictionary {key: regex}, return merged groupdicts
    only if all regexes are in the values (i.e. via regex.search) for
    all keys. Otherwise return default=Nothing().

    Args:

      match (Dict[Hashable, str]): Mapping of keys (in `d`) to regexes
        (as strings), where the regexes have named groups
        (e.g. r'(?P<group_name>regex)') somewhere in them

      d (dict): dictionary whose values (for keys given in `match`)
        must match (via search) the given regexes for these keys

      default (Any = Null): default value returned if either the
        dictionary d does not contain all the keys in `match` or not
        all of the regexes match

    Examples:

    >>> matched = pipe(
    ...   {'a': 'hello', 'b': 'world'},
    ...   match_d({'a': r'h(?P<v0>.*)', 'b': r'(?P<v1>.*)d'}),
    ... )
    >>> matched == {'v0': 'ello', 'v1': 'worl'}
    True
    >>> matched = pipe(         # missing a key
    ...   {'a': 'hello'},
    ...   match_d({'a': r'h(?P<v0>.*)', 'b': r'w(?P<v1>.*)'}),
    ... )
    >>> matched == Nothing()
    True
    >>> matched = pipe(         # regexes don't match
    ...   {'a': 'hello', 'b': 'world'},
    ...   match_d({'a': r'ckjv(?P<v0>.*)', 'b': r'dkslfjl(?P<v1>.*)'}),
    ... )
    >>> matched == Nothing()
    True

    '''
    if set(d).issuperset(set(match)):
        if all(re.search(match[k], d[k]) for k in match):
            return merge(*(
                re.search(match[k], d[k]).groupdict()
                for k in match
            ))
    return default

@curry
def bakedict(key_f, value_f, iterable):
    new = {}
    for v in iterable:
        key = key_f(v)
        values = new.setdefault(key, [])
        values.append(value_f(v))
    return new

@curry
def vbakedict(key_f, value_f, iterable):
    return bakedict(vcall(key_f), vcall(value_f), iterable)


# ----------------------------------------------------------------------
#
# Import functions
#
# ----------------------------------------------------------------------

def function_from_path(func_path: str):
    '''Return the function object for a given module path

    '''
    return pipe(
        func_path,
        lambda path: path.rsplit('.', 1),
        vcall(lambda mod_path, func_name: (
            importlib.import_module(mod_path), func_name
        )),
        vcall(lambda mod, name: (
            (name, getattr(mod, name))
            if hasattr(mod, name) else
            (name, None)
        )),
    )


def strip(content):
    return content.strip()

def strip_comments_from_line(line, *, char='#'):
    return line[:line.index(char)] if char in line else line

def strip_comments_from_lines(lines, *, char='#'):
    return pipe(
        lines,
        map(lambda l: strip_comments(l, char=char)),
        tuple,
    )

def strip_comments(line_data: Union[str, Iterable], *, char='#'):
    if is_seq(line_data):
        return strip_comments_from_lines(line_data, char=char)
    elif is_str(line_data):
        return strip_comments_from_line(line_data, char=char)
    raise TypeError(
        'Must provide either string (one line) or Iterable'
        ' type (multiple lines)'
    )

def remove_comments(lines):
    return pipe(
        lines,
        filter(lambda l: not l.startswith('#')),
    )

def help_text(s):
    return textwrap.shorten(s, 1e300)

@curry
def wrap_text(width, text):
    return pipe(
        textwrap.wrap(text, width),
        '\n'.join,
    )

def clipboard_copy(content):
    import pyperclip
    pyperclip.copy(content)

def clipboard_paste():
    import pyperclip
    return pyperclip.paste()

def xlsx_to_clipboard(content):
    return pipe(
        content,
        to_str,
        lambda c: c if c.endswith('\n') else c + '\n',
        clipboard_copy,
    )

def escape_row(row):
    return pipe(
        row,
        map(lambda v: v.replace('"', '""')),
        '\t'.join,
    )

def output_rows_to_clipboard(rows):
    return pipe(
        rows,
        map(escape_row),
        '\n'.join,
        clipboard_copy,
    )

def difflines(A, B):
    linesA = pipe(
        A.splitlines(),
        strip_comments,
        filter(None),
        set,
    )
    linesB = pipe(
        B.splitlines(),
        strip_comments,
        filter(None),
        set,
    )
    return pipe(linesA - linesB, sorted)

def intlines(A, B):
    linesA = pipe(
        A.splitlines(),
        strip_comments,
        filter(None),
        set,
    )
    linesB = pipe(
        B.splitlines(),
        strip_comments,
        filter(None),
        set,
    )
    return pipe(linesA & linesB, sorted)

@curry
def peek(nbytes, path):
    with Path(path).open('r', encoding='latin-1') as rfp:
        return rfp.read(nbytes)

def backup_path(path):
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
    
def arg_intersection(func, kw):
    params = inspect.signature(func).parameters
    if any(p.kind == p.VAR_KEYWORD for p in params.values()):
        return kw
    else:
        return {k: kw[k] for k in set(params) & set(kw)}

def positional_args(func):
    return pipe(
        inspect.signature(func).parameters.values(),
        filter(
            lambda p: p.kind not in {p.VAR_KEYWORD,
                                     p.KEYWORD_ONLY,
                                     p.VAR_POSITIONAL}
        ),
        filter(lambda p: p.default == p.empty),
        map(lambda p: p.name),
        tuple,
    )
# This might need to change in Python 3.8 with actual pos-only args
positional_only_args = positional_args

def is_arg_superset(kwargs, func):
    '''Does the kwargs dictionary contain the func's required params?

    '''
    return pipe(
        func,
        positional_only_args,
        set(kwargs).issuperset,
    )

@curry
def regex_transform(regexes, text):
    '''Given a sequence of [(regex, replacement_text), ...] pairs,
    transform text by making all replacements

    '''
    if not is_str(text):
        return text

    regexes = pipe(
        regexes,
        vmap(lambda regex, replace: (re.compile(regex), replace)),
        tuple,
    )
    for regex, replace in regexes:
        text = regex.sub(replace, text)
    return text

# ----------------------------------------------------------------------
#
# Graph functions
#
# ----------------------------------------------------------------------

@curry
def from_edgelist(edgelist, factory=None):
    '''Curried nx.from_edgelist

    '''
    import networkx as nx
    return nx.from_edgelist(edgelist, create_using=factory)

@curry
def bfs_tree(G, source, reverse=False, depth_limit=None):
    '''Curried nx.tranversal.bfs_tree

    '''
    import networkx as nx
    return nx.traversal.bfs_tree(
        G, source, reverse=reverse,
        depth_limit=depth_limit
    )


# ----------------------------------------------------------------------
#
# IP address/networking functions
#
# ----------------------------------------------------------------------

ip_re = re.compile(
    r'(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?![\d\.]+)'
)
ip_only_re = re.compile(f'^{ip_re.pattern}$')

# def windows_ipconfig():
#     ipconfig = subprocess.getoutput('ipconfig /all')
#     config_re = re.compile(r'^Windows IP Configuration\s+Host Name . . . . . . . . . . . . : (?<host>.*)(?:\s+[\w ]*[. ]*: .*\n)*?\n', re.M)
#     #     r'^',
#     # ]
#     int_re = [
#         r"^(?P<device>\w.+):",
#         r"^   Physical Address. . . . . . . . . : (?P<ether>[ABCDEFabcdef\d-]+)",
#         r"^   IPv4 Address. . . . . . . . . . . : (?P<inet4>[^\s\(]+)",
#         r"^   IPv6 Address. . . . . . . . . . . : (?P<inet6>[ABCDEFabcdef\d\:\%]+)",
#         r"^\s+Default Gateway . . . . . . . . . : (?P<default_gateway>[^\s\(]+)",
#     ]
    

def current_ip(ip_version):
    '''Returns the IP address (for a given version) of the interface where
    the default gateway is found

    '''
    ip_key = {
        'v4': 'inet',
        'v6': 'inet6',
    }
    default = ifcfg.get_parser().default_interface
    ip = default.get(ip_key[ip_version])
    netmask = default.get('netmask')
    if ip and netmask:
        return ip_interface(
            f'{ip}/{get_slash_from_mask(netmask)}'
        )
    # if default[
    # return maybe_pipe(
    #     ifcfg.interfaces().items(),
    #     # vmap(lambda iface, d: 
    #     # netifaces.gateways(),
    #     get('default'),
    #     get(ip_version),
    #     second,
    #     # netifaces.ifaddresses,
    #     get(ip_version),
    #     maybe_first,
    #     lambda d: ip_interface(
    #         f'{d["addr"]}/{get_slash_from_mask(d["netmask"])}'
    #     )
    # )

current_ipv4 = partial(current_ip, 'v4')
current_ipv6 = partial(current_ip, 'v6')

def is_ipv4(ip: Union[str, int]):
    try:
        return ip_address(ip).version == 4
    except ValueError:
        return False

def is_ip(ip: Union[str, int]):
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False

def is_interface(iface):
    try:
        ip_interface(iface)
        return True
    except ValueError:
        return False

def is_network(inet):
    try:
        ip_network(inet)
        return True
    except ValueError:
        return False

def get_slash(inet: Union[str, ip_network]):
    return 32 - int(math.log2(ip_network(inet).num_addresses))

def get_slash_from_mask(mask: str):
    addr = ip_interface(mask).ip
    max_slash = 32 if addr.version == 4 else 128
    max_int = 2**32 if addr.version == 4 else 2**128
    return max_slash - int(math.log2(max_int - int(addr)))

def is_comma_sep_ip(cs_ip):
    return ',' in cs_ip and all(is_ip(v) for v in cs_ip.split(','))

def is_ip_range(ip_range):
    if '-' in ip_range:
        parts = ip_range.split('-')
        if len(parts) == 2:
            base, last = parts
            if is_ipv4(base) and last.isdigit() and (0 <= int(last) <= 255):
                return True
    return False

def ip_to_seq(ip):
    if is_ip(ip):
        return [ip]
    elif is_network(ip):
        return pipe(ip_network(ip).hosts(), map(str), tuple)
    elif is_interface(ip):
        return pipe(ip_interface(ip).network.hosts(), map(str), tuple)
    elif is_comma_sep_ip(ip):
        return ip.split(',')
    elif is_ip_range(ip):
        base, last = ip.split('-')
        base = ip_address(base)
        last = int(last)
        first = int(str(base).split('.')[-1])
        return [str(ip_address(int(base) + i))
                for i in range(last - first + 1)]
    else:
        log.error(f'Unknown/unparsable ip value: {ip}')
        return []

def ip_tuple(ip):
    return pipe(str(ip).split('.'), map(int), tuple)

def sortips(ips):
    return sort_by(compose(ip_address, strip, strip_comments), ips)
sort_ips = sortips

def get_ips_from_file(path):
    return get_ips_from_content(Path(path).read_text())

def get_ips_from_content(content):
    return get_ips_from_lines(content.splitlines())
get_ips_from_str = get_ips_from_content

def get_ips_from_lines(lines):
    return pipe(
        lines,
        map(to_str),
        strip_comments,
        filter(strip),
        mapcat(ip_re.findall),
        # filter(is_ip),
        # mapcat(ip_to_seq),
        tuple,
    )

def get_networks_from_file(path):
    return get_networks_from_content(Path(path).expanduser().read_text())

def get_networks_from_content(content):
    return get_networks_from_lines(content.splitlines())

def get_networks_from_lines(lines):
    return pipe(
        lines,
        map(to_str),
        strip_comments,
        filter(strip),
        filter(is_network),
        tuple,
    )

@curry
def in_ip_range(ip0, ip1, ip):
    start = int(ip_address(ip0))
    stop = int(ip_address(ip1))
    return int(ip_address(ip)) in range(start, stop + 1)

def zpad(ip):
    '''Zero-pad an IP address

    Examples:
    
    >>> zpad('1.2.3.4')
    '001.002.003.004'

    '''
    return '.'.join(s.zfill(3) for s in str(ip).strip().split('.'))

def unzpad(ip):
    '''Remove zero-padding from an IP address

    Examples:
    
    >>> unzpad('001.002.003.004')
    '1.2.3.4'

    '''
    return pipe(ip.split('.'), map(int), map(str), '.'.join)

def free_port():
    # https://stackoverflow.com/a/45690594/11483229
    with contextlib.closing(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]

# ----------------------------------------------------------------------
#
# HTTP functions
#
# ----------------------------------------------------------------------

def url(*parts):
    base, *path = pipe(parts, map(str))
    return urllib.parse.urljoin(
        base, '/'.join(path),
        # base, Path(*path).as_posix(),
    )

def session_with_cookies(cookies: Tuple[dict]=pmap({})):
    session = requests.Session()
    for cookie_dict in cookies:
        session.cookies.set_cookie(
            requests.cookies.create_cookie(**cookie_dict)
        )
    return session

def valid_response(response: requests.Response):
    return response.status_code in range(200, 300)

def valid_content(response: requests.Response):
    return response.content if valid_response(response) else maybe(None)


# ----------------------------------------------------------------------
#
# CSV functions
#
# ----------------------------------------------------------------------

csv.field_size_limit(2147483647)

@curry
def csv_rows_from_path(path: Union[str, Path], *, header=True,
                       columns=None, **kw):
    '''Load CSV rows from file path

    '''
    return csv_rows_from_fp(
        Path(path).expanduser().open(), header=header,
        columns=columns, **kw
    )
csv_rows = csv_rows_from_path

@curry
def csv_rows_from_content(content: Union[str, bytes], *,
                          header=True, columns=None, **kw):
    r'''Load CSV rows from content (e.g. str or bytes)

    Args:
      content (str): string content

    Examples:
    
    >>> pipe(csv_rows_from_content('c1,c2,c3\n1,2,3'), list)
    [{'c1': '1', 'c2': '2', 'c3': '3'}]

    If header is False, then rows will be returned as lists.
    
    >>> pipe(csv_rows_from_content('1,2,3\n4,5,6', header=False), list)
    [['1', '2', '3'], ['4', '5', '6']]

    >>> pipe(csv_rows_from_content(
    ...   '1,2,3', header=False, columns=['c1', 'c2', 'c3']
    ... ), list)
    [{'c1': '1', 'c2': '2', 'c3': '3'}]

    If header is False and header row exists, the header row will be
    interpreted as a regular row.
    
    >>> pipe(csv_rows_from_content('c1,c2,c3\n1,2,3', header=False), list)
    [['c1', 'c2', 'c3'], ['1', '2', '3']]

    '''
    return csv_rows_from_fp(
        io.StringIO(content), header=header, columns=columns, **kw
    )

@curry
def csv_rows_from_fp(rfp, *, header=True, columns=None, **reader_kw):
    '''Load CSV rows from file-like object

    '''
    if header:
        column_row = next(csv.reader(rfp))
        columns = columns or column_row
        reader = csv.DictReader(rfp, columns, **reader_kw)
    elif is_seq(columns):
        reader = csv.DictReader(rfp, columns, **reader_kw)
    else:
        reader = csv.reader(rfp, **reader_kw)
    for row in pipe(reader, filter(None)):
        yield row
    
@curry
def csv_rows_to_fp(wfp, rows: Iterable[Union[dict, Sequence[str]]], *,
                   header: bool = True,
                   columns: Union[dict, Iterable[str]] = None,
                   **writer_kw):
    r'''Save CSV rows to file-like object

    Args:

      wfp (file-like): File-like object into which to write the CSV
        content

      rows (Iterable[Union[dict, Iterable]]): Row data to write to
        CSV.

        Iterable[dict], columns is None: If given as iterable of
        dictionaries and columns is None, columns will come from keys
        of row dictionaries. This means that __the row data will need
        to be exhausted__ to build column list. The final column
        sequence will be sorted.

        Iterable[dict], columns is dict: If given as iterable of
        dictionaries and columns is a dictionary, then it is assumed
        to be a mapping from row keys to the final columns. If final
        column ordering is important, then use a
        collections.OrderedDict to encode the columns.

        Iterable[dict], columns is Iterable[str]: If given as iterable
        of dictionaries and columns is an iterable, then it will be
        used as the final list of columns. It is __assumed that the
        iterable of columns contains all necessary columns__. Only the
        given columns will be provided in the final CSV data.

        Iterable[Sequence[str]], columns is None: If given as iterable
        of sequences and columns is None, then there will be no header
        in the final CSV.

        Iterable[Sequence[str]], columns is Iterable[str]: If given as
        iterable of sequences and columns is an iterable, then there
        will be a header in the final CSV if header is True.

      header (bool): Should there be a header in the final CSV?

      columns (Union[dict, Iterable[str]]): Columns to be used in
        final CSV

      **writer_kw: Keyword arguments to be passed to csv.writer (or
        csv.DictWriter)

    Examples:

    >>> import io
    >>> from pathlib import Path
    >>> wfp = io.StringIO()
    >>> pipe(
    ...     [{'a': 1, 'b': 2}, {'a': 3, 'b': 4}],
    ...     csv_rows_to_fp(wfp),
    ... )
    >>> wfp.getvalue() == 'a,b\r\n1,2\r\n3,4\r\n'
    True
    >>> wfp = io.StringIO()
    >>> pipe(
    ...     [{'a': 1, 'b': 2}, {'a': 3, 'b': 4}],
    ...     csv_rows_to_fp(wfp, columns={'b': 'B', 'a': 'A'}),
    ... )
    >>> assert wfp.getvalue() in {'A,B\r\n1,2\r\n3,4\r\n', 'B,A\r\n2,1\r\n4,3\r\n'}
    >>> wfp = io.StringIO()
    >>> pipe(
    ...     [(1, 2), (3, 4)],
    ...     csv_rows_to_fp(wfp, columns=['a', 'b']),
    ... )
    >>> assert wfp.getvalue() == 'a,b\r\n1,2\r\n3,4\r\n'
    >>> wfp = io.StringIO()
    >>> pipe(
    ...     [(1, 2), (3, 4)],
    ...     csv_rows_to_fp(wfp),
    ... )
    >>> assert wfp.getvalue() == '1,2\r\n3,4\r\n'

    >>> wfp = io.StringIO()
    >>> pipe([], csv_rows_to_fp(wfp))
    >>> assert wfp.getvalue() == ''
    '''
    
    row_iter = iter(rows)

    try:
        first_row = next(row_iter)
    except StopIteration:
        log.error('No rows in row iterator... stopping, no write made.')
        return

    # If rows are passed as iterable of sequences, each row must be an
    # in-memory sequence like a list, tuple, or pvector (i.e. not an
    # iter or generator), otherwise, this will have the
    # __side-effect__ of exhausting the first row.
    rows_are_dicts = is_dict(first_row)
    columns_is_dict = is_dict(columns)

    rows = concatv([first_row], row_iter)
    if rows_are_dicts:
        if columns_is_dict:
            items = tuple(columns.items())
            rows = pipe(
                rows,
                map(lambda r: OrderedDict([
                    (to_c, r[from_c]) for from_c, to_c in items
                ])),
            )
            columns = list(columns.values())
        elif columns is None:
            rows = tuple(rows)
            columns = pipe(
                rows,
                map(call('keys')),
                cat_to_set,
                sorted,
            )
        else:                   # assuming columns is Iterable
            columns = tuple(columns)
            rows = pipe(
                rows,
                map(lambda r: {
                    c: r[c] for c in columns
                }),
            )
        writer = csv.DictWriter(wfp, columns, **writer_kw)
        if header:
            writer.writeheader()
    else:                       # assuming rows are Iterable
        if columns is not None:  # assuming columns is Iterable
            columns = tuple(columns)
            rows = pipe(
                rows,
                map(lambda r: {
                    c: r[i] for i, c in enumerate(columns)
                }),
            )
            writer = csv.DictWriter(wfp, columns)
            if header:
                writer.writeheader()
        else:
            writer = csv.writer(wfp, **writer_kw)
            
    writer.writerows(rows)

@curry
def csv_rows_to_path(path: Union[str, Path],
                     rows: Iterable[Union[dict, Sequence[str]]], *,
                     header: bool = True,
                     columns: Union[dict, Iterable[str]] = None,
                     **writer_kw):
    '''Save CSV rows to file system path

    '''
    with Path(path).expanduser().open('w') as wfp:
        return csv_rows_to_fp(
            wfp, rows, header=header, columns=columns, **writer_kw
        )

@curry
def csv_rows_to_content(rows: Iterable[Union[dict, Sequence[str]]], *,
                        header: bool = True,
                        columns: Union[dict, Iterable[str]] = None,
                        **writer_kw):
    '''Save CSV rows to a string

    '''
    buf = io.StringIO()
    csv_rows_to_fp(
        buf, rows, header=header, columns=columns, **writer_kw
    )
    return buf.getvalue()

# ----------------------------------------------------------------------
#
# JSON handling functions
#
# ----------------------------------------------------------------------

@curry
def maybe_json(response: requests.Response, *, default=Nothing()):
    try:
        return response.json()
    except ValueError:
        return default

@curry
@functools.wraps(json.dumps)
def json_dumps(*a, **kw):
    return json.dumps(*a, **kw)

@curry
@functools.wraps(json.loads)
def json_loads(*a, **kw):
    return json.loads(*a, **kw)

@curry
def jmes(search, d, *, default=Nothing()):
    '''Curried jmespath.search

    Examples:

    >>> pipe({'a': {'b': [10, 9, 8]}}, jmes('a.b[2]'))
    8
    '''
    if is_none(d):
        log.error(
            f'null dict passed to jmes (search: {search})'
        )
        return default
    return jmespath.search(search, d)


# ----------------------------------------------------------------------
#
# HTML handling functions
#
# ----------------------------------------------------------------------

def soup(content: str):
    return bs4.BeautifulSoup(content, 'lxml')


# ----------------------------------------------------------------------
#
# NTLM/SAM database functions
#
# ----------------------------------------------------------------------

SAM_RE = re.compile(
    r'^(.*?):\d+:(\w+:\w+):::$', re.M,
)
def get_sam_hashes(content):
    return pipe(
        content,
        to_str,
        SAM_RE.findall,
    )

MSCACHE_RE = re.compile(
    r'^(.+?)/(.+?):(\$.*?\$.*?#.*?#.*?)$', re.M,
)
def get_mscache_hashes(content):
    return pipe(
        content,
        to_str,
        MSCACHE_RE.findall,
    )
