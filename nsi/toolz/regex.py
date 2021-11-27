import re
from typing import Union, Sequence, Iterable

from pymaybe import maybe, Nothing

from .common import (
    pipe, merge, curry, juxt, compose, concat, vcall, vmap,
    is_str,
)

# ----------------------------------------------------------------------
#
# Regular expression functions
#
# ----------------------------------------------------------------------

Regex = Union[str, re.Pattern]

def to_regex(obj: Regex, flags=0):
    match obj:
        case regex if isinstance(regex, re.Pattern):
            return regex
    return re.compile(obj, flags)
        
def re_search(regex: Regex, flags=0):
    '''Given a regex (str or re.Pattern), and a string, return the match object 
    from a re.search
    '''
    regex = to_regex(regex, flags)
    def searcher(string):
        return maybe(regex.search(string))
    return searcher

def groupdict(regex: Regex, flags=0, keep_match=False):
    '''Given a regex (str or re.Pattern) with named expressions and a string,
    return the groupdict of the match object or empty dict
    '''
    def groupdicter(string):
        return pipe(
            string,
            re_search(regex, flags),
            lambda m: merge(
                m.groupdict().or_else({}),
                {'__match__': m} if (keep_match and m) else {},
            ),
        )
    return groupdicter

@curry
def groupdicts(regex: Regex, iterable, keep_match=False, flags=0):
    '''Given a regex (str or re.Pattern), and iterable of strings,
    produce single dictionary of all groupdicts of matches
    '''
    regex = to_regex(regex, flags)
    return pipe(
        iterable,
        map(groupdict(regex, flags=flags, keep_match=keep_match)),
        filter(None),
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


