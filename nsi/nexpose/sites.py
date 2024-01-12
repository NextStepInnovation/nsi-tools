import typing as T
import math
import functools
import pprint
import time
from ipaddress import ip_address, ip_interface

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
    AssetList, Site, SiteMap, SiteId, SiteNexposeId, ErrorJson,
    ScanEngineId, Outcome, ScanTemplateId, IpList,
)

from . import scans
# from .scans import scan_map, get_scan
from .scan_engines import engine_map, get_engine
from .asset_groups import asset_group_map, get_asset_group
from .scan_templates import get_template

log = logging.new_log(__name__)

get_sites = get_iterator(['sites'])

max_assets = 1024

@functools.cache
def site_map(api: Api) -> SiteMap:
    log.info('Loading Nexpose site map...')
    sites = tuple(get_sites(api)())
    log.info(f'  .. {len(sites)} sites loaded.')
    return pipe(
        merge(
            {r['name']: r for r in sites},
            {r['id']: r for r in sites},
        ), 
    )

get_site = api_object_getter(site_map)

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
            return handle_error_response('Error setting Site data', error)

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
                  description: str, engine_id: int, metadata: dict):
    return merge(
        {
            'name': name,
            'description': merge_meta(description, metadata),
        },
        {'engineId': engine_id} if engine_id else {},
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
        } if (included or excluded) else {},
    )

def new_site(api: Api, name: str, included: AssetList = (), 
             excluded: AssetList = (), description: str = '', 
             engine_id: ScanEngineId = None,
             metadata: dict = None) -> T.Tuple[bool, Site | ErrorJson]:
    metadata = metadata or {}
    engine_id = engine_map(api)[engine_id]['id'] if engine_id is not None else None
    log.debug(f'engine id: {engine_id}')
    response = api('sites').post(json=new_site_body(
        name, included, excluded, description, engine_id, metadata
    ))
    match response:
        case Response(status_code=201):
            site_map.cache_clear()
            return True, get_site(api, get_json(response)['id'])
        case error_response:
            return handle_error_response('Error in Site creation', error_response)

def mark_for_deletion(api: Api, site_id: SiteId):
    site = get_site(api, site_id)
    _desc, meta = parse_meta(site['description'])
    if meta.get('prevent_delete'):
        log_pprint(
            log.error, 
            f'Site {site["name"]} has been marked to not be deleted.', 
            dict(meta)
        )
        return False, {
            'reason': {'invalid-command', 'prevented'},
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
    _desc, meta = parse_meta(site['description'])

    def can_delete():
        if meta.get('prevent_delete'):
            return False
        if 'allow_delete' in meta:
            if not meta['allow_delete']:
                return False
        return True

    if not can_delete():
        log_pprint(
            log.error, 'Deletion not allowed for this site.', dict(meta)
        )

        return False, {
            'reason': {'invalid-command', 'prevented'},
            'message': f'Deletion not allowed for this site: {meta}'
        }

    response = api('sites', site['id']).delete()
    match response:
        case Response(status_code=200):
            return True, site
        case error_response:
            return handle_error_response('Error in Site deletion', error_response)

@curry
def get_site_data(api: Api, site_id: SiteId, data_path: T.Sequence[str]):
    '''
    Returns an iterator for the data associated with the data_path. E.g. assets,
    alerts, etc.
    '''
    return get_iterator500(
        ['sites', get_site(api, site_id)['id'], *data_path], api
    )()

site_scans = get_site_data(data_path=['scans'])
site_assets = get_site_data(data_path=['assets'])
site_alerts = get_site_data(data_path=['alerts'])
site_smtp_alerts = get_site_data(data_path=['alerts', 'smtp'])
site_snmp_alerts = get_site_data(data_path=['alerts', 'snmp'])
site_syslog_alerts = get_site_data(data_path=['alerts', 'syslog'])
site_included_asset_groups = get_site_data(data_path=['included_asset_groups'])
site_excluded_asset_groups = get_site_data(data_path=['excluded_asset_groups'])

@as_dict
def site_targets(api: Api, site_id: SiteId):
    site = get_site(api, site_id)

    match api('sites', site['id'], 'included_targets').get():
        case Response(status_code=200) as success:
            yield {
                'included': (success.json() or {}).get('addresses', [])
            }
    match api('sites', site['id'], 'excluded_targets').get():
        case Response(status_code=200) as success:
            yield {
                'excluded': (success.json() or {}).get('addresses', [])
            }

site_credentials = get_site_data(data_path=['site_credentials'])

credential_services = {
    "as400", "cifs", "cifshash", "cvs", "db2", "ftp", "http", "ms-sql", 
    "mysql", "notes", "oracle", "oracle-service-name", "pop", "postgresql", 
    "remote-exec", "snmp", "snmpv3", "ssh", "ssh-key", "sybase", 
    "telnet", "kerberos",
}
CredentialService = T.NewType('CredentialService', str)

class ScanCredentials(T.TypedDict):
    authenticationType: str
    communityName: str
    database: str
    domain: str
    enumerateSids: bool
    notesIDPassword: str
    ntlmHash: str
    oracleListenerPassword: str
    password: str
    pemKey: str
    permissionElevation: str
    permissionElevationPassword: str
    permissionElevationUserName: str
    privacyPassword: str
    privacyType: str
    privateKeyPassword: str
    realm: str
    service: str
    sid: str
    useWindowsAuthentication: bool
    username: str

cred_properties = {
    'as400': ('domain', 'username', 'password'),
    'cifs': ('domain', 'username', 'password'),
    'cifshash': ('domain', 'username', 'ntlmHash'),
    'cvs': ('domain', 'username', 'password'),
    'db2': ('database', 'username', 'password'),
    'ftp': ('username', 'password'),
    'http': ('realm', 'username', 'password'),
    'kerberos': ('username', 'password'),
    'ms-sql': ('database',
                'useWindowsAuthentication',
                'domain',
                'username',
                'password'),
    'mysql': ('database', 'username', 'password'),
    'notes': ('notesIDPassword',),
    'oracle': ('sid',
                'username',
                'password',
                'enumerateSids',
                'oracleListenerPassword'),
    'oracle-service-name': ('serviceName', 'username', 'password'),
    'pop': ('username', 'password'),
    'postgresql': ('database', 'username', 'password'),
    'remote-exec': ('username', 'password'),
    'snmp': ('communityName',),
    'snmpv3': ('authenticationType',
                'username',
                'password',
                'privacyType',
                'privacyPassword'),
    'ssh': ('username',
            'password',
            'permissionElevation',
            'permissionElevationUsername',
            'password'),
    'ssh-key': ('username',
                'privateKeyPassword',
                'pemKey',
                'permissionElevation',
                'permissionElevationUsername',
                'password'),
    'sybase': ('database',
                'useWindowsAuthentication',
                'domain',
                'username',
                'password'),
    'telnet': ('username', 'password')
}

def validate_creds(service: CredentialService, creds: ScanCredentials) -> bool:
    if service not in credential_services:
        log.error(
            f'The service {service} is not a valid credential service.'
        )
        return False
    wrong_props = set(creds.keys()) - set(cred_properties[service])
    if wrong_props:
        log.error(
            f'You have spurious properties for these credentials: '
            f'{", ".join(wrong_props)}'
        )
        log.error(
            f'The valid properties for {service} credentials are:'
            f' {", ".join(cred_properties[service])}'
        )
        return False
    return True


ScanCredentialMap = T.Dict[CredentialService, T.Sequence[ScanCredentials]]
ScanCredentialPair = T.Tuple[CredentialService, ScanCredentials]

@curry
def add_site_credentials(api: Api, site_id: SiteId, name: str, 
                         service: CredentialService, creds: ScanCredentials, *,
                         description: str = None,
                         enabled: bool = True, host_restriction: str = None,
                         port_restriction: int = None):
    if not validate_creds(service, creds):
        log.error(
            f'There was a problem with the {service} service credential'
            f' data: {creds}'
        )
        return False, None
    post_data = pipe(
        merge(
            {
                'name': name,
                'description': description,
                'hostRestriction': host_restriction,
                'portRestriction': port_restriction,
                'enabled': enabled,
            }, 
            {'account': merge({'service': service}, creds)},
        ),
        valfilter(lambda v: v is not None),
    )

    site = get_site(api, site_id)

    response = api('sites', site['id'], 'site_credentials').post(
        json=post_data,
    )

    match response:
        case Response(status_code=201):
                return True, response.json()
        case error_response:
            return handle_error_response(
                'Error in Scan Credentials creation', error_response
            )

@curry
def post_site_data(api: Api, site_id: SiteId, data_path: T.Sequence[str]):
    '''
    Returns an iterator for the data associated with the data_path. E.g. assets,
    alerts, etc.
    '''
    return get_iterator500(
        ['sites', get_site(api, site_id)['id'], *data_path], api
    )()

def new_site_scan(api: Api, site_id: SiteId, 
                  engine_id: ScanEngineId = None,
                  asset_group_ids: T.Sequence[int] = None,
                  hosts: AssetList = (),
                  name: str = None,
                  template_id: ScanTemplateId = None) -> Outcome:
    log.info(
        f'Creating new site scan for site: {site_id}'
    )
    site = get_site(api, site_id)

    engine_id = get_engine(api, engine_id)['id'] if engine_id else None
    log.debug(f'engine id: {engine_id}')

    ag_ids = [
        get_asset_group(api, i)['id'] for i in (asset_group_ids or [])
    ]
    log.debug(f'asset group ids: {ag_ids}')

    template_id = get_template(api, template_id)['id'] if template_id is not None else None

    if not hosts:
        log.info(
            'Setting hosts to all defined targets'
        )
        hosts = site_targets(api, site['id']).get('included', [])
        log.info(
            f'   hosts: {hosts}'
        )

    scan_body = merge(
        {'assetGroupIds': ag_ids} if ag_ids else {},
        {'engineId': engine_id} if engine_id is not None else {},
        {'hosts': hosts} if hosts else {},
        {'name': name} if name else {},
        {'templeId': template_id} if template_id is not None else {},
    )

    log.info(f'Scan body: {scan_body}')

    response = api('sites', site['id'], 'scans').post(json=scan_body)

    match response:
        case Response(status_code=201):
            return True, scans.get_scan(api, get_json(response)['id'])
        case error_response:
            return handle_error_response('Error in Scan creation', error_response)



def scan_ips(api: Api, include_ips: IpList, exclude_ips: IpList,
             credentials: T.Dict[CredentialService, T.Iterator[ScanCredentials]], 
             engine_id: ScanEngineId, tags: T.Sequence[str], 
             scan_template: ScanTemplateId = 'full-audit-without-web-spider', 
             credentials_service: CredentialService = 'cifs') -> scans.ScanStatus:
    log.info(
        f'Staring scan of {len(include_ips)} IP elements' +
        f' with {len(exclude_ips)} excluded IPs' if exclude_ips else '' +
        f' using scan engine {engine_id}'
    )

    engine_id = engine_map(api)[engine_id]['id']

    include_list = pipe(
        include_ips or [],
        strip_comments_from_lines,
        map(strip()),
        filter(None),
        tuple,
    )

    exclude_list = pipe(
        exclude_ips or [],
        strip_comments_from_lines,
        map(strip()),
        filter(None),
        tuple,
    )

    interfaces = pipe(
        include_list, 
        filter(is_interface), 
        map(ip_interface), 
        tuple
    )

    ips = pipe(
        include_list, 
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
        potential_ips += n_interface_ips

    existing_assets = pipe(
        site_map(api),
        values,
        groupby(get('id')),
        valmap(first),
        values,
        map(get('assets')),
        sum,
    )

    log.info(
        f'There are {existing_assets} total assets currently'
        ' defined for this instance of Nexpose.'
    )

    potential_total_assets = existing_assets + potential_ips

    if potential_total_assets >= max_assets:
        log.warning(
            'You have requested a scan that potentially will put the total'
            f' number of assets at {potential_total_assets}, which is above'
            f' to maximum number of assets ({max_assets}).'
        )

    tags = pipe(
        tags,
        map(lower),
        mapcat(split()),
        map(strip()),
        set,
        sorted,
    )

    site_name = pipe(
        include_list,
        sort_ips,
        json_dumps,
        md5,
        lambda h: f'temp_site_{"-".join(tags)}_{h}_engine_{engine_id}'
    )

    log.info(f'Creating temporary site:')
    log.info(f'   name: {site_name}')
    log.info(f'   include_list: {include_list}')
    log.info(f'   exclude_list: {exclude_list}')
    log.info(f'   engine_id: {engine_id}')

    match new_site(
        api, site_name, include_list, exclude_list, '', engine_id,
        ):
        case True, site:
            pass
        case False, error_json:
            log.error(
                f'There was an error in creating site: {site_name}'
            )
            log.error(pprint.pformat(error_json))
            return False, error_json

    # Add credentials to site
    for service, creds in credentials.items():
        for cred in creds:
            match add_site_credentials(
                api, site['id'], f'{site_name}-creds', service, cred
                ):
                case True, cred:
                    pass
                case False, error_json:
                    log.error(
                        f'There was an error in adding site credentials: {cred}'
                    )
                    log.error(pprint.pformat(error_json))
                    delete_site(api, site_name)
                    return False, error_json

    match new_site_scan(api, site_name):
        case True, scan:
            pass
        case False, error_json:
            log.error(
                f'There was an error in creating scan for: {site_name}'
            )
            log.error(pprint.pformat(error_json))
            delete_site(api, site_name)
            return False, error_json

    log.info(
        f'Scan {scan["id"]} started. Waiting for it to end.'
    )
    # def inc_sleep(sleep):
    #     new = math.ceil(sleep*1.5)
    #     if new >= 30:
    #         return 30
    #     return new

    success, scan = scans.wait_for_scan(api, scan['id'], )
    # sleep = 10
    # try:
    #     while True:
    #         time.sleep(sleep)
    #         scan = scans.get_scan(api, scan['id'])
    #         for line in pipe(scan, pprint.pformat, splitlines):
    #             log.info(line)
    #         if scan['status'] != 'running':
    #             break
    #         sleep = inc_sleep(sleep)
    #         log.info(
    #             f'  ... still running. Waiting another {sleep} seconds'
    #         )
    # except Exception as exc:
    #     # delete_site(api, site_name)
    #     raise

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

    if not success:
        log.error(
            f'Scan was incomplete, terminating with status {scan["status"]}'
        )
        delete_site(api, site_name)
        return False, scan


    log.info(
        f'Scan {scan["id"]} completed. {scan["assets"]} assets found.'
    )
    return True, site


    