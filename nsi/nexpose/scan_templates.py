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
    ScanTemplate, ScanTemplateMap,
)

log = logging.new_log(__name__)

get_templates = get_iterator(['scan_templates'])

@functools.cache
def template_map(api: Api) -> ScanTemplateMap:
    log.info('Loading Nexpose scan template map...')
    engines = tuple(get_templates(api)())
    log.info(f'  .. {len(engines)} templates loaded.')
    return {r['id']: r for r in engines}

get_template = api_object_getter(template_map)
