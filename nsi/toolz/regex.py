from collections import abc
from typing import Union, Sequence, Iterable, Callable, Any

import re as _re
import regex as re
import pymaybe
from toolz.functoolz import complement

from .common import *

log = new_log(__name__)

__all__ = [
    # regex
    'Regex', 'bakedict', 
    'grep', 'grep_t', 'grepitems', 'grepv', 'grepv_t', 
    'igrep', 'grept', 'igrept', 'igrepv', 'igrepvt', 
    'grepvitems', 'groupdict', 'groupdicts',
    'groupdicts_from_regexes', 'match_d', 're_search', 'regex_transform', 
    'to_regex', 'vbakedict',
]

# ----------------------------------------------------------------------
#
# Regular expression functions
#
# ----------------------------------------------------------------------

Regex = Union[str, _re.Pattern, re.Pattern]

def is_regex(obj: Regex):
    return isinstance(obj, (_re.Pattern, re.Pattern))

def to_regex(obj: Regex, flags=0):
    match obj:
        case regex if is_regex(regex):
            return regex
    return re.compile(obj, flags)

@curry
def re_search(regex: Regex, value: str, flags=0) -> pymaybe.Maybe:
    '''
    Given a regex (str or re.Pattern), and a string, return the PyMaybe-wrapped
    match object from a re.search

    Examples:

    >>> pipe(
    ...     'hello world',
    ...     re_search(
    ...         r'h(?P<a>.*?) w(?P<b>.*)'
    ...     ),
    ...     lambda m: (type(m), m.groupdict()),
    ... ) == (pymaybe.Something, {'a': 'ello', 'b': 'orld'})
    True
    >>> pipe(
    ...     'HELLO WORLD',
    ...     re_search(
    ...         r'h(?P<a>.*?) w(?P<b>.*)'
    ...     ),
    ...     lambda m: (type(m), m.groupdict()),
    ... ) == (pymaybe.Nothing, pymaybe.Nothing())
    True
    >>> pipe(
    ...     'HELLO WORLD',
    ...     re_search(
    ...         r'h(?P<a>.*?) w(?P<b>.*)', flags=re.I
    ...     ),
    ...     lambda m: (type(m), m.groupdict()),
    ... ) == (pymaybe.Something, {'a': 'ELLO', 'b': 'ORLD'})
    True
    '''

    regex = to_regex(regex, flags)
    return pymaybe.maybe(regex.search(value))
    # regex = to_regex(regex, flags)
    # def searcher(string):
    #     return pymaybe.maybe(regex.search(string))
    # return searcher

@curry
def groupdict(regex: Regex, value: str, flags=0, keep_match=False) -> dict:
    '''Given a regex (str or re.Pattern) with named expressions and a string,
    return the groupdict of the match object or empty dict

    Args: 

      regex(Union[str, regex]): regular expression with named expressions

      value(str): string to search

      flags(int): regex flags to use

      keep_match(bool): whether or not to keep the match object in the returned
        dictionary under the key "__match__"

    Examples:

    >>> pipe(
    ...     'hello world',
    ...     groupdict(
    ...         r'h(?P<a>.*?) w(?P<b>.*)',
    ...     ),
    ... ) == {'a': 'ello', 'b': 'orld'}
    True
    >>> out = pipe(
    ...     'hello world',
    ...     groupdict(
    ...         r'h(?P<a>.*?) w(?P<b>.*)', keep_match=True,
    ...     ),
    ... )
    >>> out['__match__'].groups() == ('ello', 'orld')
    True
    '''
    return pipe(
        value,
        re_search(regex, flags=flags),
        lambda m: merge(
            m.groupdict().or_else({}),
            {'__match__': m} if (keep_match and m.or_else(False)) else {},
        ),
    )
    # def groupdicter(string: str):
    #     return pipe(
    #         string,
    #         re_search(regex, flags),
    #         lambda m: merge(
    #             m.groupdict().or_else({}),
    #             {'__match__': m} if (keep_match and m) else {},
    #         ),
    #     )
    # return groupdicter

@curry
def groupdicts(regex: Regex, iterable, keep_match=False, flags=0):
    '''
    Given a regex (str or re.Pattern), and iterable of strings, produce a tuple
    of all groupdicts of matches

    Examples:

    >>> pipe(
    ...     ['hello world', 'jfghfjhgjf', 'hQWER wZXCV'],
    ...     groupdicts(
    ...         r'h(?P<a>.*?) w(?P<b>.*)',
    ...     ),
    ...     tuple,
    ... ) == ({'a': 'ello', 'b': 'orld'}, {'a': 'QWER', 'b': 'ZXCV'})
    True
    '''
    regex = to_regex(regex, flags=flags)
    return pipe(
        iterable,
        map(groupdict(regex, keep_match=keep_match)),
        filter(None),
    )

@curry
def groupdicts_from_regexes(regexes: Sequence[re.Pattern],
                            iterable: Iterable[str], *, 
                            keep_match=False, flags=0):
    '''
    Given a sequence of regexes and an iterable of strings, produce a list of
    merged groupdicts for those regexes
    '''
    regexer = compose_left(
        juxt(*[
            groupdict(r, keep_match=keep_match, flags=flags)
            for r in regexes
        ]),
        merge,
    )
    return pipe(
        iterable,
        map(regexer),
        filter(None),
    )

# ---------------------------
#
# Searching
#
# ---------------------------

_get = get
@curry
def grep(raw_regex: Regex, iterable: Iterable[Union[str, Sequence, dict]],
         exclude: bool = False, get: Union[Callable, Any] = None, 
         to_tuple: bool = False, *, flags=0):
    '''Given a regular expression (either str or compiled regex), filter
    iterable of strings (or indexable) by that regex

    Args:

    - raw_regex (Union[str, re.Pattern])
    - iterable (Iterable[str])
    - exclude (bool): return strings that do not match regex
    - get (Union[Callable, key/index]): get function/key/index argument to
      select from dict/sequence prior to regex test
    - to_tuple (bool): return a tuple rather than an iterator

    Examples:

    >>> pipe(['abc', 'aec', 'qwer'], grep(r'^a.c$'), tuple) 
    ('abc', 'aec')

    >>> pipe(['abc', 'aec', 'qwer'], grep(r'^a.c$', exclude=True), tuple) 
    ('qwer',)

    >>> pipe(['abc', 'aec', 'qwer'], grep(r'^a.c$', to_tuple=True)) 
    ('abc', 'aec')

    >>> pipe(
    ...   [{'a': 'abc', 'b': 1}, {'a': 'aec'}, {'a': 'qwer'}], 
    ...   grep(r'^a.c$', get='a'), 
    ...   tuple
    ... )
    ({'a': 'abc', 'b': 1}, {'a': 'aec'})

    '''
    # regex = to_regex(raw_regex, **re_kw)
    # if isinstance(raw_regex, _re.Pattern):
    #     regex = raw_regex
    # else:
    #     regex = re.compile(raw_regex, **re_kw)
    if not callable(get):
        get = _get(get) if get else noop
    search = compose_left(
        get,
        to_regex(raw_regex, flags).search,
        # re_search(raw_regex, **re_kw),
        # regex.search,
        complement(bool) if exclude else bool,
    )
    return pipe(
        iterable,
        filter(search),
        tuple if to_tuple else noop,
    )
igrep = grep(flags=re.I)
igrept = igrep(to_tuple=True)

grep_t = grep(to_tuple=True)
grept = grep_t

grepv = grep(exclude=True)
igrepv = grepv(flags=re.I)
grepv_t = grep(exclude=True, to_tuple=True)
grepvt = grepv_t
igrepvt = grepvt(flags=re.I)

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

@curry
def match_d(match: dict, d: dict, *, default=pymaybe.Nothing()):
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
    >>> matched == pymaybe.Nothing()
    True
    >>> matched = pipe(         # regexes don't match
    ...   {'a': 'hello', 'b': 'world'},
    ...   match_d({'a': r'ckjv(?P<v0>.*)', 'b': r'dkslfjl(?P<v1>.*)'}),
    ... )
    >>> matched == pymaybe.Nothing()
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


