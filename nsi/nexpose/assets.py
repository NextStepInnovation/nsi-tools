from .. import logging
from ..toolz import *
from ..rest import Api, get_json
from .api import (
    get_iterator, NexposeApiError, 
)

log = logging.new_log(__name__)

get_assets = get_iterator(['assets'])
def asset_map(api: Api):
    return {
        r['name']: r for r in get_assets(api)()
    }

