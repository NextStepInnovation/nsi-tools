import json
import functools

import requests
import jmespath
from pymaybe import Nothing

from .common import curry, is_none, new_log, pipe, to_bytes

__all__ = [
    'jmes', 'json_dumps', 'json_dumpb', 'json_loads', 'maybe_json',
]

log = new_log(__name__)

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
def json_dumps(obj, **kw):
    if 'default' not in kw:
        kw['default'] = str
    return json.dumps(obj, **kw)

@curry
@functools.wraps(json.dumps)
def json_dumpb(obj, **kw):
    return pipe(
        json_dumps(obj, **kw),
        to_bytes,
    )

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


