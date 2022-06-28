import json
import hashlib
from typing import (
    Hashable, Iterable, Any, Iterable
)

from .common import (
    pipe, merge, curry, assoc, assoc_in, dissoc, vmap, get,
    to_bytes, is_seq, is_dict, map, filter,
)
from .json import json_dumpb
from .pyrsistent import no_pyrsistent

__all__ = [
    # dictionary
    'cassoc', 'cassoc_in', 'cdissoc', 'cmerge', 'create_key', 
    'dict_hash', 'dict_md5', 'dict_sha1', 'dict_sha256',
    'drop_key', 'drop_keys',
    'merge_keys', 'only_if_key', 'remove_key', 'remove_keys', 'replace_key',
    'set_key', 'switch_keys', 'update_if_key_exists', 'update_key', 'update_key_v',
    'valmaprec',
]

# ----------------------------------------------------------------------
#
# Dictionary functions
#
# ----------------------------------------------------------------------

@curry
def dict_hash(hash_func, d):
    '''Hash a dictionary with hash function (e.g. SHA1)

    Examples:

    >>> import hashlib
    >>> pipe({"a": 1}, dict_hash(hashlib.sha1))
    'e4ad4daad53a2eec0313386ada88211e50d693bd'
    '''
    return pipe(
        no_pyrsistent(d),
        json_dumpb(sort_keys=True),
        lambda b: hash_func(b).hexdigest(),
    )
dict_md5 = dict_hash(hashlib.md5)
dict_sha1 = dict_hash(hashlib.sha1)
dict_sha256 = dict_hash(hashlib.sha256)


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
def cassoc(key: Hashable, value: Any, d: dict, factory=dict):
    '''Curried assoc

    Args:
      key (Hashable): key to be updated
    
      value (Any): value for the key

      d (dict): dictionary to transform (with no side effects)

    Returns: (dict) new state of dictionary

    Examples:

    >>> new = pipe({'b': 2}, cassoc('a', 5))
    >>> new == {'a': 5, 'b': 2}
    True

    '''
    return assoc(d, key, value, factory)
set_key = cassoc

@curry
def cassoc_in(keys: Iterable[Hashable], value: Any, d: dict, factory=dict):
    '''Curried assoc_in

    Args:
      keys (Iterable[Hashable]): key chain to be updated
    
      value (Any): value for the key chain

      d (dict): dictionary to transform (with no side effects)

    Returns: (dict) new state of dictionary

    Examples:

    >>> purchase = {'name': 'Alice',
    ...             'order': {'items': ['Apple', 'Orange'],
    ...                       'costs': [0.50, 1.25]},
    ...             'credit card': '5555-1234-1234-1234'}
    >>> new = pipe(purchase, cassoc_in(['order', 'costs'], [0.25, 1.00]))
    >>> new == {'credit card': '5555-1234-1234-1234',
    ...         'name': 'Alice',
    ...         'order': {'costs': [0.25, 1.00], 
    ...                   'items': ['Apple', 'Orange']}}
    True
     
    '''
    return assoc_in(d, keys, value, factory)

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
    if callable(value_function):
        value = value_function(d)
    else:
        value = value_function
        
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

    Examples:

    >>> pipe({}, only_if_key('a', lambda d: d['a']**2))
    {}
    >>> pipe({'a': 2}, only_if_key('a', lambda d: d['a']**2))
    4

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
def cdissoc(key: Hashable, d):
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
drop_key = cdissoc
remove_key = cdissoc

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

    Examples:

    >>> pipe({'a': {'b': 2, 'c': [2, 3, 4, 5]}}, valmaprec(lambda i: i**2))
    {'a': {'b': 4, 'c': [4, 9, 16, 25]}}

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

