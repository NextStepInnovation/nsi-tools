import typing as T
import enum
import functools
from ipaddress import ip_address, ip_interface

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
    SiteId, IpList,
)
from .search import (
    Ops, get_field, FilterMatch,
)

from .sites import site_map, new_site
from .scan_engines import engine_map

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

max_assets = 1024

class ScanStatus(T.TypedDict):
    pass

def scan_ips(api: Api, ip_list: IpList, 
             engine_id: ScanEngineId) -> T.Iterator[ScanStatus]:
    log.info(
        f'Staring scan of {len(ip_list)} IP elements'
        f' using scan engine {engine_id}'
    )
    engine_id = engine_map(api)[engine_id]['id']

    ip_list = pipe(
        ip_list,
        strip_comments_from_lines,
        map(strip()),
        filter(None),
    )

    interfaces = pipe(
        ip_list, 
        filter(is_interface), 
        map(ip_interface), 
        tuple
    )

    ips = pipe(
        ip_list, 
        filter(is_ip),
        map(ip_address), 
        tuple,
    )

    if interfaces:
        n_interface_ips = pipe(
            interfaces,
            map(lambda i: i.network.num_addresses),
            sum,
        )
        log.info(
            f'  ... found {len(interfaces)} interfaces in IP list with'
            f' {n_interface_ips} potential ips in it'
        )

    site_name = pipe(
        ip_list,
        sort_ips,
        json_dumps,
        md5,
        lambda h: f'temp_site_{md5}_engine_{engine_id}'
    )

    site = new_site(api, )
