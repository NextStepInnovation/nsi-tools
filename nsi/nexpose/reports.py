import time

from .. import logging
from ..toolz import *
from ..rest import Api, get_json
from .api import (
    get_iterator, NexposeApiError, 
)

log = logging.new_log(__name__)

get_reports = get_iterator(['reports'])
def report_map(api: Api):
    return {
        r['name']: r for r in get_reports(api)()
    }

get_templates = get_iterator(['report_templates'])
@memoize
def template_map(api: Api):
    return {
        t['name']: t for t in get_templates(api)()
    }

@curry
def template_id(api: Api, name: str):
    return template_map(api)[name]['id']

def wait_for_report(api: Api, report_id: int, instance_id: int,
                    wait_time: int = 1, run_index: int = 0, 
                    max_runs: int = 7):
    log.info(f'Checking for report: {report_id}')

    response = api('reports', report_id, 'history', instance_id).get()
    json = get_json(response)
    status = json.get('status')
    if status:
        if status == 'failed':
            log.error('Report failed')
            return False
        elif status == 'aborted':
            log.error('Report aborted')
            return False
        elif status == 'unknown':
            log.error('Report terminated for unknown reason')
            return False
        elif status == 'complete':
            return True
        elif status == 'running':
            if run_index > max_runs:
                log.error(
                    f'Tried {max_runs} times... giving up. This is either'
                    f' a huge report (try again later), or something\'s wrong.'
                )
                return False
            log.info(f'  not done... waiting {wait_time} seconds')
            time.sleep(wait_time)
            return wait_for_report(
                api, report_id, instance_id, wait_time * 2, run_index + 1
            )
        else:
            log.error(f'Unhandled status returned: {status}')
            return False
    else:
        raise NexposeApiError(
            f'Got an unhandled response (code: {response.status_code})\n'
            '\n'
            f'{response.content.decode()}'
        )

def new_report(api: Api, body: dict):
    response = api('reports').post(json=body)
    report_id = get_json(response).get('id')
    if report_id:
        return report_id
    raise NexposeApiError(
        'Could not create report template:\n'
        '\n'
        f'{response.content.decode()}'
    )

def generate_report(api: Api, report_id: int):
    response = api('reports', report_id, 'generate').post()
    instance_id = get_json(response).get('id')
    if instance_id:
        return instance_id
    raise NexposeApiError(
        'Could not create report content:\n'
        '\n'
        f'{response.content.decode()}'
    )

def lookup_report(api: Api, name: str):
    report_id = report_map(api).get(name, {}).get('id')
    instance_id = maybe_pipe(
        api('reports', report_id, 'history').get(),
        get_json,
        get('resources', default={}),
        filter(lambda r: r.get('status') in {'complete', 'running'}),
        first,
        lambda instance: instance['id']
    ) or None
    return report_id, instance_id

def get_report_content(api: Api, report_id: int, instance_id: int):
    response = api(
        'reports', report_id, 'history', instance_id, 'output'
    ).get()
    return response.status_code == 200, response.content

def delete_report_content(api: Api, report_id: int, instance_id: int):
    response = api(
        'reports', report_id, 'history', instance_id
    ).delete()
    return response.status_code == 200, response

def delete_report(api: Api, report_id: int):
    response = api('reports', report_id).delete()
    return response.status_code == 200, response

def destroy_report(api: Api, report_id: int, instance_id: int):
    success, response = delete_report_content(api, report_id, instance_id)
    if not success:
        log.error('Could not delete report content:\n'
                  f'{response.content.decode()}')
        return False

    success, response = delete_report(api, report_id)
    if not success:
        log.error('Could not delete report:\n'
                  f'\n{response.content.decode()}')
        return False

    return True

def report_body(api: Api, site_name: str, options: dict):
    def all_asset_ids():
        return all_site_asset_ids(api, site_name)

    def in_all(ids):
        return pipe((set(ids) & all_asset_ids()), sorted)

    return pipe(
        options,
        only_if_key('template', update_key(
            'template',
            lambda body: template_id(body['template'])
        )),

        only_if_key('scope', update_key(
            'scope',
            lambda body: pipe(
                body['scope'],
                only_if_key('assets', update_key(
                    'assets',
                    lambda scope: pipe(
                        asset_ids(api, scope['assets']),
                        in_all,
                    )
                )),
                only_if_key('sites', update_key(
                    'sites',
                    lambda scope: sites_ids(api, scope['sites'])
                )),
                only_if_key('groups', switch_keys(
                    'groups', 'assetGroups', lambda d: d['groups']
                )),
            )
        )),

        only_if_key('filters', update_key(
            'filters',
            lambda body: merge(
                {'severity': 'all',
                 'statuses': ['vulnerable-version',
                              'vulnerable',
                              'potentially-vulnerable']},
                body['filters']
            )
        )),
    )

