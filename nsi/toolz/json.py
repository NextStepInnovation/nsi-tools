import json
import functools

import requests
import jmespath
from pymaybe import Nothing

from .common import curry, is_none, new_log, map, filter, pipe

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

