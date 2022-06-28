'''Dynamic import functions
'''
from pathlib import Path
import typing as T
import importlib

from .common import (
    pipe, vcall, map, filter, do,
)
from .filesystem import ensure_paths, walk
from .. import logging

log = logging.new_log(__name__)

__all__ = [
    # dynamic_import
    'function_from_path', 'load_module_directory',
]

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

@ensure_paths
def load_module_directory(path: Path):
    current = Path('.').resolve()
    modules = pipe(
        path,
        walk,
        filter(lambda p: p.suffix == '.py'),
        map(lambda p: p.relative_to(current)),
        map(lambda p: p.parent / p.stem),
        map(str),
        map(lambda s: s.replace('/', '.')),
        sorted,
        map(importlib.import_module),
        map(importlib.reload),
        tuple,
    )
    log.info(
        f'Imported {len(modules)} modules from {path}'
    )
    return tuple(modules)
