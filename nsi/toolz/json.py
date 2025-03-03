from pathlib import Path
import gzip
import bz2
import json
import functools

import requests
import jmespath
from pymaybe import Nothing

from .common import curry, is_none, new_log, pipe, to_bytes, to_str
from .filesystem import ensure_paths, ensure_paths_curry, slurp, slurpb

__all__ = [
    'maybe_json',
    'json_dumps', 'json_dumpb', 'json_dump', 'json_dump_gz', 'json_dump_bz',
    'json_loads', 'json_slurp',
    'jmes', 
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

@ensure_paths
def json_slurp(path: Path):
    decomp = {
        '.gz': gzip.decompress,
        '.bz2': bz2.decompress,
        '.bz': bz2.decompress,
    }
    if path.suffix in decomp:
        data = pipe(
            path,
            slurpb,
            decomp[path.suffix],
            to_str,
        )
    else:
        data = slurp(path)
    return json_loads(data)

@ensure_paths_curry
def json_dump(path: Path, obj, gz: bool=False, bz: bool=False, **kw):
    data = pipe(
        json_dumpb(obj, **kw),
        gzip.compress if gz else bz2.compress,
    ) if gz or bz else json_dumps(obj, **kw)
    writer = path.write_bytes if gz or bz else path.write_text
    return writer(data)
json_dump_gz = json_dump(gz=True)
json_dump_bz = json_dump(bz=True)



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


