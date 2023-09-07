import typing as T
import enum
import functools
from ipaddress import ip_address, ip_interface

from .. import logging
from ..toolz import *
from ..rest import Api, get_json
from .api import (
    get_iterator, get_iterator500, NexposeApiError, api_object_getter,
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

get_scan = api_object_getter(scan_map)

max_assets = 1024

class ScanStatus(T.TypedDict):
    pass

def scan_ips(api: Api, site_name: str, ip_list: IpList,
             engine_id: ScanEngineId) -> T.Iterator[ScanStatus]:
    from .sites import site_map, new_site, new_site_scan
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
        set,
        tuple,
    )

    potential_ips = len(ips)

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
        potential_ips += len(n_interface_ips)

    existing_assets = pipe(
        site_map(api),
        values,
        groupby(get('id')),
        valmap(first),
        map(get('assets')),
        sum,
    )

    log.info(
        f'There are {existing_assets} total assets currently defined for this site.'
    )

    potential_total_assets = existing_assets + potential_ips

    if potential_total_assets >= max_assets:
        log.warning(
            'You have requested a scan that potentially will put the total'
            f' number of assets at {potential_total_assets}, which is above'
            f' to maximum number of assets ({max_assets}).'
        )

    site_name = pipe(
        ip_list,
        sort_ips,
        json_dumps,
        md5,
        lambda h: f'temp_site_{site_name}_{md5}_engine_{engine_id}'
    )

    site = new_site(api, site_name)

    new_site_scan(

    )