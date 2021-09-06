import logging
from pathlib import Path
from functools import wraps
import typing as T
from collections.abc import Mapping, Iterable

import ruamel.yaml
from ruamel.yaml.comments import CommentedMap
from pymaybe import Nothing

from . import toolz as _

log = logging.getLogger('yaml')
log.addHandler(logging.NullHandler())

@wraps(ruamel.yaml.dump)
def dump(*a, **kw) -> str:
    kw['Dumper'] = ruamel.yaml.RoundTripDumper
    kw['default_flow_style'] = False
    kw['width'] = 2**31
    return ruamel.yaml.dump(*a, **kw)

@wraps(ruamel.yaml.load)
def load(*a, **kw) -> T.Any:
    kw['Loader'] = ruamel.yaml.RoundTripLoader
    return ruamel.yaml.load(*a, **kw)

@_.ensure_paths
@_.curry
def read_yaml(path: T.Union[str, Path]):
    '''Read YAML data from path and return object
    '''
    with path.expanduser().open() as rfp:
        return load(rfp)

def maybe_read_yaml(path: T.Union[str, Path]):
    try:
        return read_yaml(path)
    except Exception:
        log.exception(f'Error reading YAML path: {path}')
        return Nothing()

@_.ensure_paths
@_.curry
def write_yaml(path: T.Union[str, Path], obj: T.Any):
    match obj:
        case mapping if isinstance(mapping, Mapping):
            final_object = _.pipe(
                mapping,
                _.no_pyrsistent,
                CommentedMap,
            )
        case iterable if isinstance(iterable, Iterable):
            final_object = _.pipe(
                iterable,
                _.no_pyrsistent,
            )
        case final_object: pass

    with path.open('w') as wfp:
        dump(data, wfp)
    return True

