import typing as T
import functools
import pprint

from requests import Response

from .. import logging
from ..toolz import *
from .. import yaml
from ..rest import Api, get_json
from .api import (
    get_iterator, NexposeApiError, method_body, handle_error,
)
from .types import (
    AssetList, Site, SiteMap, SiteId, SiteNexposeId,
)

log = logging.new_log(__name__)

get_sites = get_iterator(['sites'])

@functools.cache
def site_map(api: Api) -> SiteMap:
    sites = tuple(get_sites(api)())
    return pipe(merge(
        {r['name']: r for r in sites},
        {r['id']: r for r in sites},
    ), do(lambda d: log.debug(tuple(d.keys()))))

def get_site(api: Api, site_id: SiteId) -> Site:
    return site_map(api)[site_id]

@curry
def get_attr(api: Api, site_id: SiteId, attr: str, default=None):
    return pipe(
        get_site(api, site_id),
        get(attr, default=default),
    )

get_raw_description:T.Callable[[Api, SiteId], str] = get_attr(
    attr='description', default='',
)
get_id:T.Callable[[Api, SiteId], SiteNexposeId] = get_attr(attr='id')

meta_delimiter = '-- NSI METADATA: DO NOT REMOVE --'
description_bp = '''{desc}

{delimiter}
{metadata}
'''

MetaResult = T.Tuple[str, dict]
def parse_meta(description: str, delimiter: str=meta_delimiter) -> MetaResult:
    desc, _, meta = description.partition(delimiter)
    if not meta:
        return desc, {}
    return desc, pipe(
        meta,
        yaml.load,
    )

get_description = compose_left(
    get_raw_description,
    parse_meta,
    first,
    lambda s: s.rstrip(),
)

@curry
def merge_meta(raw_description: str, new_meta: dict, 
               delimiter: str = meta_delimiter, replace: bool = False):
    desc, old_meta = parse_meta(raw_description)
    if replace:
        meta = new_meta
    else:
        meta = merge(old_meta, new_meta)
    return description_bp.format(
        desc=desc, metadata=yaml.dump(meta), delimiter=delimiter,
    )
replace_meta = merge_meta(replace=True)

set_body = method_body('Site', 'PUT', {
    'name': 'name',
    'description': 'description',
    'scanEngine': 'engineId',
    'scanTemplate': 'scanTemplateId',
    'importance': 'importance',
})

@curry
def set_site(api: Api, site_id: SiteId, site_body: dict):
    site = get_site(api, site_id)
    response = api('sites', get_id(api, site_id)).put(
        json=set_body(site, site_body),
    )
    match response:
        case Response(status_code=200):
            site_map.cache_clear()
            return True, get_site(api, site_id)
        case error:
            return handle_error('Error setting Site data', error)

def get_metadata(api: Api, site_id: SiteId):
    return pipe(
        get_raw_description(api, site_id),
        parse_meta,
        second,
    )

def set_metadata(api: Api, site_id: SiteId, new_meta: dict, replace: bool = False):
    new_description = merge_meta(
        get_raw_description(api, site_id), new_meta, replace=replace,
    )
    log.debug(
        f'new_description: {repr(new_description)}'
    )
    return set_site(api, site_id, {'description': new_description})

def new_site_body(name: str, included: AssetList, excluded: AssetList, 
                  description: str, metadata: dict):
    return merge(
        {
            'name': name,
            'description': merge_meta(description, metadata),
        },
        {
            'scan': merge(
                {
                    'assets': pipe(
                        [('includedTargets', list(included)),
                         ('excludedTargets', list(excluded))],
                        filter(compose_left(second, bool)),
                        dict,
                        valmap(lambda assets: {'addresses': assets}),
                    ),
                },
            ),
        } if included or excluded else {},
    )

def new_site(api: Api, name: str, included: AssetList = (), excluded: AssetList = (),
             description: str = '', metadata: dict = None):
    metadata = metadata or {}
    response = api('sites').post(json=new_site_body(
        name, included, excluded, description, metadata
    ))
    match response:
        case Response(status_code=201):
            site_map.cache_clear()
            return True, get_site(api, get_json(response)['id'])
        case error_response:
            return handle_error('Error in Site creation', error_response)

def mark_for_deletion(api: Api, site_id: SiteId):
    site = get_site(api, site_id)
    _, meta = parse_meta(site['description'])
    if meta.get('prevent_delete'):
        log_pprint(
            log.error, 
            f'Site {site["name"]} has been marked to not be deleted.', 
            dict(meta)
        )
        return False, {
            'message': f'Cannot be marked for deletion {dict(meta)}'
        }
    log.info(f'Marking {site["name"]} to be deleted')
    return set_metadata(api, site_id, {'allow_delete': True})

def mark_prevent_deletion(api: Api, site_id: SiteId):
    site = get_site(api, site_id)
    log.info(f'Setting {site["name"]} to not be deleted')
    return set_metadata(api, site_id, {'prevent_delete': True})

def log_pprint(logger_f, prefix: str, obj: T.Any):
    logger_f(prefix)
    for line in pprint.pformat(obj).splitlines():
        logger_f(line)

def delete_site(api: Api, site_id: int):
    site = get_site(api, site_id)
    _, meta = parse_meta(site['description'])

    if not meta.get('allow_delete') or meta.get('prevent_delete'):
        log_pprint(
            log.error, 'Deletion not allowed for this site.', dict(meta)
        )

        return False, {
            'message': f'Deletion not allowed for this site: {meta}'
        }

    # response = api('sites', site['id']).delete()
    # match response:
    #     case Response(status_code=200):
    #         return True, {}
    #     case error_response:
    #         return handle_error('Error in Site deletion', error_response)

# def site_assets(api: Api, site_id: SiteId):
#     site = get_

