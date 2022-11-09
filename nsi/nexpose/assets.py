import typing as T
import enum

from requests import Response

from .. import logging
from ..toolz import *
from ..rest import Api, get_json
from .api import (
    get_iterator, get_iterator500, NexposeApiError, handle_error_response,
)
from .types import (
    Asset, AssetId, AssetMap, SearchCriteria, SwaggerSearchCriteriaFilter,
    SiteId,
)
from .search import (
    Ops, get_field, FilterMatch,
)

log = logging.new_log(__name__)

#get_assets = get_iterator500(['assets'])

# def asset_map(api: Api) -> AssetMap:
#     assets = get_assets(api)()
#     return merge({
#         r['name']: r for r in assets
#     }, {
#         r['id']: r for r in assets
#     })

def site_search_filter(api: Api, site_id: SiteId):
    pass

def search_criteria() -> SearchCriteria:
    pass

def get_asset(api: Api, asset_id: AssetId) -> Asset:
    match api('assets', asset_id).get():
        case Response(status_code=200) as success:
            return get_json(success)
        case error:
            return handle_error_response('Error getting Asset', error)

