import typing as T
import functools
import pprint

from requests import Response

from .. import logging
from ..toolz import *
from .. import yaml
from ..rest import Api, get_json
from .api import (
    get_iterator, get_iterator500, 
    NexposeApiError, method_body, handle_error_response, api_object_getter,
)
from .types import (
    AssetList, 
    Site, SiteMap, SiteId, SiteNexposeId, 
    ScanEngine, ScanEngineId,
    ScanEngineMap,
)

log = logging.new_log(__name__)

get_engines = get_iterator(['scan_engines'])

@functools.cache
def engine_map(api: Api) -> ScanEngineMap:
    log.info('Loading Nexpose scan engine map...')
    engines = tuple(get_engines(api)())
    log.info(f'  .. {len(engines)} engines loaded.')
    return pipe(
        merge(
            {r['name']: r for r in engines},
            {r['id']: r for r in engines},
        ), 
    )

get_engine = api_object_getter(engine_map)
