import typing as T
import enum
import time
import functools
import pprint
import math
from ipaddress import ip_address, ip_interface

from requests import Response

from .. import logging
from ..toolz import *
from ..rest import Api, get_json
from .api import (
    get_iterator, get_iterator500, NexposeApiError, api_object_getter,
    handle_error_response,
)
from .types import (
    Scan, ScanId, ScanMap, 
    ScanEngine, ScanEngineId, ScanEngineMap,
    SearchCriteria, SwaggerSearchCriteriaFilter,
    SiteId, IpList, ScanTemplateId,
)
from .search import (
    Ops, get_field, FilterMatch,
)

from .scan_engines import engine_map

log = logging.new_log(__name__)

get_scans = get_iterator(['scans'])

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

#get_scan = api_object_getter(scan_map)
def get_scan(api: Api, scan_id: int) -> Scan:
    match api('scans', scan_id).get():
        case Response(status_code=200) as success:
            return success.json()
        case error:
            return handle_error_response('Error getting scan', error)

scan_states = {
    "aborted",
    "unknown",
    "running",
    "finished",
    "stopped",
    "error",
    "paused",
    "dispatched",
    "integrating"
}

scan_status_states = {
    "errored-out",
    'queued',
    'started',
    'started-running',
    'done',
}

class ScanStatus(T.TypedDict):
    tags: T.Sequence[str]
    site_name: str
    state: str
    queue_placement: int
    begin_time: str
    end_time: str
    scan_data: Scan

def new_scan_status(include_ips, exclude_ips, tags, engine_id, 
                    credentials, scan_template):
    parts = concatv_t(
        
    )


def wait_for_scan(api: Api, scan_id: int, wait_time: int = 10, run_index: int = 0):
    log.info(f'Checking to see if scan ({scan_id}) is ready...')

    def inc_sleep(sleep):
        return math.ceil(sleep*1.5)
    
    match api('scans', scan_id).get():
        case Response(status_code = 200) as success:
            match get_json(success):
                case {'status': 'failed'|'error'|'abort'} as failed:
                    log.error(f'  ... scan failed outright')
                    log_obj(log.error, failed)
                    return False, failed
                case {'status': 'unknown'} as unknown:
                    log.error('  ... scan failed for unknown reason')
                    log_obj(log.error, unknown)
                    return False, unknown
                case {'status': 'stopped' | 'paused'} as stopped:
                    log.error('  ... scan has been manually stopped/paused')
                    log_obj(log.warning, stopped)
                    return False, stopped
                case {'status': 'finished'} as done:
                    log.info('Scan finished.')
                    return True, done
                case {'status': 'dispatched'|'running'} as running:
                    n_assets = running.get('assets', 0)
                    log.info(
                        f'  ... not done. {n_assets} completed.'
                        f' Waiting {wait_time} seconds'
                    )
                    time.sleep(wait_time)
                    return wait_for_scan(
                        api, scan_id, inc_sleep(wait_time), run_index + 1,
                    )
                case {'status': 'integrating'}:
                    wait_time = 5
                    log.info(f'  ... is integrating. Waiting {wait_time} seconds')
                    time.sleep(wait_time)
                    return wait_for_scan(
                        api, scan_id, inc_sleep(wait_time), run_index + 1,
                    )
                case unhandled:
                    log.error('  ... given unhandled status for report generation')
                    log_obj(log.error, unhandled)
                    return False, unhandled
        case error:
            return handle_error_response('Error setting Site data', error)

