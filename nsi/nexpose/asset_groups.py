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
    AssetGroup, AssetGroupId, AssetGroupMap,
)

log = logging.new_log(__name__)

get_asset_groups = get_iterator(['asset_groups'])

@functools.cache
def asset_group_map(api: Api) -> AssetGroupMap:
    log.info('Loading Nexpose asset group map...')
    groups = tuple(get_asset_groups(api)())
    log.info(f'  .. {len(groups)} templates loaded.')
    return merge(
        {r['name']: r for r in groups}, 
        {r['id']: r for r in groups}
    )

get_asset_group = api_object_getter(asset_group_map)
