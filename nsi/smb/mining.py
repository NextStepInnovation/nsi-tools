import typing as T
import functools
import itertools
from pathlib import Path

from ..toolz import (
    pipe, map, filter, ensure_paths, to_regex, merge,
)
from .. import toolz as _
from ..toolz.dynamic_import import load_module_directory
from .. import logging
from . import session

log = logging.new_log(__name__)

def prep_predicate(p: session.FileDict):
    def get_path(p: session.FileDict):
        match p:
            case {'path': paths} if _.is_seq(paths):
                return {
                    'path': pipe(
                        paths,
                        map(to_regex),
                        tuple,
                    )
                }
            case {'path': path} if _.is_path(path):
                return {
                    'path': [to_regex(str(path))],
                }
        return {}

    return pipe(
        _.juxt(
            get_path,
        )(p),
        _.vcall(_.cmerge(p)),
    )

_filter_functions = []
def file_filter(meta_predicate: session.FileDict, *meta_predicates):
    predicates = pipe(
        _.concatv([meta_predicate], meta_predicates),

    )
    path_regexes = pipe(
        path_regexes,
        map(to_regex),
    ) if path_regexes else []
    meta = meta or {}

    if not(path_regexes and meta):
        path_regexes = [to_regex('.*')]

    def filter_deco(func):
        @functools.wraps(func)
        @ensure_paths
        def filterer(path: Path):
            log.debug(
                f'Calling filter func: {func}'
            )
            yield from func(path)
        for regex, meta in itertools.product(path_regexes, [meta]):
            _filter_functions.append((regex, meta, filterer))

    return filter_deco

def filter_files():
    pass