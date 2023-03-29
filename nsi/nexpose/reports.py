import functools
import time
import typing as T

from requests import Response

from .. import logging
from ..toolz import *
from ..rest import Api, get_json

from .types import (
    AssetList, AssetId, 
    ScanId, ScanList, 
    SiteId, SiteList,
    Report, ReportNexposeId, ReportId, ReportMap, ReportList,
)
from .api import get_iterator, NexposeApiError, handle_error_response
from .sites import get_site, site_map

log = logging.new_log(__name__)

get_reports = get_iterator(['reports'])

@functools.cache
def report_map(api: Api) -> ReportMap:
    reports = tuple(get_reports(api)())
    return merge(
        {r['name']: r for r in reports},
        {r['id']: r for r in reports},
    )

def get_report(api: Api, report_id: ReportId):
    return report_map(api).get(report_id)

def get_report_histories(api, report_id: ReportId):
    log.info(f'Getting Report history for {report_id}')
    report = get_report(api, report_id)
    if not report:
        log.error(f'  ... Report {report_id} does not exist')
        return []
    return get_iterator(['reports', report['id'], 'history'])(api)()

def wait_for_report(api: Api, report_id: ReportNexposeId, instance_id: int,
                    wait_time: int = 1, run_index: int = 0, 
                    max_runs: int = 7):
    log.info(f'Checking to see if report ({report_id}) is ready...')

    match api('reports', report_id, 'history', instance_id).get():
        case Response(status_code = 200) as success:
            match get_json(success):
                case {'status': 'failed'} as failed:
                    log.error('  ... content generation failed outright')
                    log_obj(log.error, failed)
                case {'status': 'unknown'} as unknown:
                    log.error('  ... content generation failed for unknown reason')
                    log_obj(log.error, unknown)
                case {'status': 'complete'}:
                    return True
                case {'status': 'running'} as running:
                    if run_index > max_runs:
                        log.error(
                            f'Tried {max_runs} times and giving up. This is'
                            ' either a very large report (so try again later),'
                            ' or something is very wrong.'
                        )
                        log_obj(log.error, running)
                    log.info(f'  ... not done. Waiting {wait_time} seconds')
                    time.sleep(wait_time)
                    return wait_for_report(
                        api, report_id, instance_id, wait_time * 2, 
                        run_index + 1,
                    )
                case unhandled:
                    log.error('  ... given unhandled status for report generation')
                    log_obj(log.error, unhandled)
    return False


'''
Policy SQL Query Report

https://discuss.rapid7.com/t/sql-query-to-export-policy-scan-results-with-remediation-rationale-and-proof/1173

SELECT
  dp.policy_id, dp.title as policy_title, dpr.rule_id, dpr.title as policy_rule_title,
  dp.benchmark_name, da.ip_address, da.host_name, dpr.description, dp.category,
  fapr.date_tested, htmlToText(fapr.proof) as proof, fapr.compliance,
  dpr.severity, htmlToText(dpr.rationale) as rationale, htmlToText(dpr.remediation) as remediation
FROM fact_asset_policy_rule fapr
  JOIN dim_policy dp on dp.policy_id = fapr.policy_id
  JOIN dim_policy_rule dpr on dpr.policy_id = fapr.policy_id and fapr.rule_id = dpr.rule_id
  JOIN dim_asset da on da.asset_id = fapr.asset_id
WHERE fapr.compliance = false order by dp.title, dpr.title 
'''

def new_report_body(api: Api, name: str, site_ids: SiteList,
                    asset_ids: AssetList, scan_ids: ScanList):
    return {
        'name': name,
        'format': 'xml-export-v2',
        'scope': merge(
            {'sites': [
                s['id'] for s in [site_map(api).get(i) for i in site_ids]
            ]} if site_ids else {},
        ),
        'filters': {
            'severity': 'all',
            'statuses': [
                'vulnerable-version',
                'vulnerable',
                'potentially-vulnerable',
            ],
        },
    }

def new_report(api: Api, name: str, site_ids: SiteList, 
               asset_ids: AssetList = None, 
               scan_ids: ScanList = None) -> T.Tuple[bool, Report]:
    match api('reports').post(json=new_report_body(
            api, name, site_ids, asset_ids=asset_ids, scan_ids=scan_ids,
        )):
        case Response(status_code = 200 | 201) as success:
            report_map.cache_clear()
            return True, get_report(api, get_json(success)['id'])
        case error_response:
            return handle_error_response('Error in Report creation', error_response)

def generate_report(api: Api, report_id: ReportNexposeId) -> T.Tuple[bool, int]:
    match api('reports', report_id, 'generate').post():
        case Response(status_code = 200 | 201) as success:
            return True, get_json(success)['id']
        case error_response:
            return handle_error_response(
                'Error in Report content generation', error_response
            )

def output_report(api: Api, report_id: ReportNexposeId, instance_id: int):
    match api('reports', report_id, 'history', instance_id, 'output').get():
        case Response(status_code = 200 | 201) as success:
            return True, success.content
        case error_response:
            return handle_error_response(
                'Error in downloading Report content', error_response
            )

def delete_report(api: Api, report_id: ReportId) -> T.Tuple[bool, T.Optional[dict]]:
    log.info(f'Deleting Report {report_id}')
    report = get_report(api, report_id)
    if not report:
        log.error(f'  ... no Report {report_id} exists.')
        return True
    match api('reports', report_id).delete():
        case Response(status_code = 200) as success:
            report_map.cache_clear()
            return True, None
        case error_response:
            return handle_error_response(
                'Error in deleting Report', error_response
            )

def delete_report_history(api: Api, report_id: ReportNexposeId, 
                          instance_id: int) -> T.Tuple[bool, T.Optional[dict]]:
    log.info(f'Deleting report history ({report_id}, {instance_id})')
    match api('reports', report_id, 'history', instance_id).delete():
        case Response(status_code = 200) as success:
            return True, None
        case error_response:
            return handle_error_response(
                'Error in deleting Report content history', error_response
            )

def delete_all_report_histories(api: Api, report_id: ReportId) -> T.Tuple[bool, T.Optional[dict]]:
    log.info(f'Deleting all Report content history for {report_id}')
    report = get_report(api, report_id)
    if not report:
        log.error(f'  ... no Report {report_id} exists.')
        return True
    instance_ids = pipe(get_report_histories(api, report_id), map(get('id')), tuple)
    if not instance_ids:
        log.error(f'  ... no content generated for Report {report_id}')
    for instance_id in instance_ids:
        success, output = delete_report_history(api, report['id'], instance_id)
        if not success:
            log.error(f'  ... could not delete ({report_id}, {instance_id})')
            log_obj(log.error, output)
    return True
    
def destroy_report(api: Api, report_id: ReportId):
    '''
    Idempotent report destruction. Will delete all generated Report content and
    the Report object itself.
    '''
    log.info(f'Destroying Report {report_id}')
    report = get_report(api, report_id)
    if not report:
        log.error(f'  ... no Report {report_id} exists.')
        return True

    delete_all_report_histories(api, report_id)
    return delete_report(api, report['id'])

def download_report(api: Api, name: str, site_ids: SiteList = None,
                    asset_ids: AssetList = None, scan_ids: ScanList = None,
                    force_regen: bool = False) -> T.Tuple[bool, T.Optional[T.Union[bytes, dict]]]:
    log.info(f'Downloading report {name}')
    report = get_report(api, name)
    if not report:
        log.info('Report does not exist, so creating')
        success, report = new_report(
            api, name, 
            site_ids=site_ids, asset_ids=asset_ids, scan_ids=scan_ids,
        )
        if not success:
            log.error('  ... could not create report')
            return False, None
    elif force_regen:
        log.info(f'FORCE_REGEN: Report {name} exists, so destroying')
        success = destroy_report(api, name)
        if not success:
            log.error('FORCE_REGEN: Could not delete existing report')
            return False, None
        return download_report(api, name, site_ids, asset_ids, scan_ids)

    log.info('Generating report content')
    report_id = report['id']
    success, instance_id = generate_report(api, report_id)
    if not success:
        log.error('  ... could not generate report content')
        return False, None

    if not wait_for_report(api, report_id, instance_id):
        return False, None

    return output_report(api, report_id, instance_id)
            

# def new_report(api: Api, body: dict):
#     response = api('reports').post(json=body)
#     report_id = get_json(response).get('id')
#     if report_id:
#         return report_id
#     raise NexposeApiError(
#         'Could not create report template:\n'
#         '\n'
#         f'{response.content.decode()}'
#     )

# def generate_report(api: Api, report_id: int):
#     response = api('reports', report_id, 'generate').post()
#     instance_id = get_json(response).get('id')
#     if instance_id:
#         return instance_id
#     raise NexposeApiError(
#         'Could not create report content:\n'
#         '\n'
#         f'{response.content.decode()}'
#     )

# def lookup_report(api: Api, name: str):
#     report_id = report_map(api).get(name, {}).get('id')
#     instance_id = maybe_pipe(
#         api('reports', report_id, 'history').get(),
#         get_json,
#         get('resources', default={}),
#         filter(lambda r: r.get('status') in {'complete', 'running'}),
#         first,
#         lambda instance: instance['id']
#     ) or None
#     return report_id, instance_id

# def get_report_content(api: Api, report_id: int, instance_id: int):
#     response = api(
#         'reports', report_id, 'history', instance_id, 'output'
#     ).get()
#     return response.status_code == 200, response.content

# def delete_report_content(api: Api, report_id: int, instance_id: int):
#     response = api(
#         'reports', report_id, 'history', instance_id
#     ).delete()
#     return response.status_code == 200, response

# def delete_report(api: Api, report_id: int):
#     response = api('reports', report_id).delete()
#     return response.status_code == 200, response

# def destroy_report(api: Api, report_id: int, instance_id: int):
#     success, response = delete_report_content(api, report_id, instance_id)
#     if not success:
#         log.error('Could not delete report content:\n'
#                   f'{response.content.decode()}')
#         return False

#     success, response = delete_report(api, report_id)
#     if not success:
#         log.error('Could not delete report:\n'
#                   f'\n{response.content.decode()}')
#         return False

#     return True

