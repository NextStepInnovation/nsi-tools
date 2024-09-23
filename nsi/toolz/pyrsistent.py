import functools
from pathlib import Path

import pymaybe
from pyrsistent import pmap, pvector

from .common import (
    pipe, vmap, compose_left, curry, map, filter,
    is_dict, is_seq, is_float, is_str, is_int,
    maybe_float, maybe_int,
)

__all__ = [
    # pyrsistent
    'freeze', 'frozen_curry', 'no_pyrsistent', 'to_pyrsistent', 'to_builtins',
]

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
    TypeError: ...
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
        case path if isinstance(path, Path):
            return str(path)
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
to_builtins = no_pyrsistent

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


