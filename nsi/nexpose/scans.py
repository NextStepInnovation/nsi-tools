import typing as T
import enum
import functools

from .. import logging
from ..toolz import *
from ..rest import Api, get_json
from .api import (
    get_iterator, get_iterator500, NexposeApiError, 
)
from .types import (
    Scan, ScanId, ScanMap, 
    ScanEngine, ScanEngineId, ScanEngineMap,
    SearchCriteria, SwaggerSearchCriteriaFilter,
    SiteId,
)
from .search import (
    Ops, get_field, FilterMatch,
)

log = logging.new_log(__name__)

get_scans = get_iterator(['scans'])

@functools.cache
def scan_map(api: Api) -> ScanEngineMap:
    log.info('Loading Nexpose scan map...')
    scans = tuple(get_scans(api)())
    log.info(f'  .. {len(scans)} scans loaded.')
    return pipe(
        merge(
            {r['scanName']: r for r in scans},
            {r['id']: r for r in scans},
        ), 
        do(lambda d: log.debug(tuple(d.keys()))),
    )

get_scan_engines = get_iterator(['scan_engines'])

@functools.cache
def scan_engine_map(api: Api) -> ScanEngineMap:
    log.info('Loading Nexpose scan engine map...')
    engines = tuple(get_scan_engines(api)())
    log.info(f'  .. {len(engines)} scan engines loaded.')
    return pipe(
        merge(
            {r['name']: r for r in engines},
            {r['id']: r for r in engines},
        ), 
        do(lambda d: log.debug(tuple(d.keys()))),
    )
