import typing as T
import pprint

import urllib3
import requests
import requests.auth
from requests import Response, Request

import nsi
from ..toolz import *
from ..rest import Api, HttpMethod, get_json

log = nsi.logging.new_log(__name__)

class NexposeApiError(IOError):
    pass

Url = T.NewType('Url', str)
Status = T.NewType('Status', str)

class Link(T.TypedDict):
    href: Url
    rel: str

LinkSequence = T.Sequence[Link]
class LinksDict(T.TypedDict):
    self: Url
    first: Url
    next: Url
    last: Url

def links_dict(link_seq: LinkSequence) -> LinksDict:
    return pipe(
        link_seq,
        groupby('rel'),
        valmap(first),
        valmap(get('href')),
    )

class PageInfo(T.TypedDict):
    number: int
    size: int
    totalPages: int
    totalResources: int

class Error(T.TypedDict):
    links: T.Sequence[Link]
    message: str
    status: str

def log_error(error: Error):
    links = links_dict(error['links'])
    status = error['status']
    message = error['message']
    def do_log(msg):
        log.error(
            '{msg}\n'
            '\n'
            f'Links: {pprint.pprint(links)}\n'
            '\n'
            f'Message: {message}'
        )

    match status:
        case "401":
            # Unauthorized
            do_log(
                'STATUS: 401 (Not Authorized). Check your credentials.'
            )
        case "404":
            # Not found
            do_log(
                'STATUS: 404 (Not found). You sure this exists?'
            )
        case "500":
            # Server Error
            do_log(
                'STATUS: 500 (Server Error). Serious issue here, check'
                ' Nexpose server logs.'
            )
        case "503":
            # Unavailable
            do_log(
                'STATUS: 503 (Service Unavailable). Check server logs.'
            )

def handle_error_response(error_prefix: str, response: Response):
    error_json = get_json(response)
    log.error(
        f'{error_prefix}:'
    )
    log.error(f'  code: {response.status_code}')
    log.error(f'  raw: {response.content[:200]}')
    log.error(f'  message: {error_json.get("message")}')
    if 'messages' in error_json:
        for m in error_json['messages']:
            log.error(f'  - {m}')
    return False, error_json

@curry
def pprint_obj(printer, obj):
    return pipe(
        obj,
        no_pyrsistent,
        pprint.pformat,
        splitlines,
        map(printer),
        tuple,
    )

@curry
def merge_params(kwargs: dict, new_params: dict):
    params = merge(
        kwargs.get('params', {}),
        new_params,
    )
    return assoc(kwargs, 'params', params)

RequestMethod = T.Callable[[T.ParamSpecArgs, T.ParamSpecKwargs], Response]

@curry
def iter_resources(method: RequestMethod, size: int, **kwargs):
    '''
    Automatically iterate over paginated resources
    '''

    method_kw = merge_params(kwargs, {'size': size})

    match method(**method_kw):
        case Response(status_code=200 | 201) as success:
            match get_json(success):
                case {'resources': resources, 
                      'links': link_seq} as r_json:

                    for resource in resources:
                        yield resource

                    if 'next' in links_dict(link_seq):
                        page_no = r_json['page']['number']
                        yield from iter_resources(method, size, **merge_params(
                            kwargs, {'page': page_no + 1},
                        ))

                case {'id': _item_id} as json_with_id:
                    yield json_with_id

        case error:
            return handle_error_response('Error getting resource', error)

@curry
def iter_resources_by(page_size: int, method: RequestMethod):
    return partial(iter_resources, method, page_size)
iter_by_50s = iter_resources_by(50)
iter_by_500s = iter_resources_by(500)

ResourceGetter = T.Callable[
    [HttpMethod], T.Dict
]


class ProxyDict(T.TypedDict):
    https: Url
    http: Url

@curry
def new_api(hostname: str, port: int, username: str, password: str, *,
            proxies: ProxyDict = None, verify: bool | str = False):
    session = requests.Session()
    session.auth = requests.auth.HTTPBasicAuth(username, password)
    if proxies:
        session.proxies = proxies
    session.verify = verify
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return Api(
        f'https://{hostname}:{port}/api/3', session
    )

@curry
def resource_iterator(path: T.Sequence[T.Union[str, int]], api: Api, method: str, 
                      resource_iterator: ResourceGetter, **request_kwargs):
    return resource_iterator(
        partial(getattr(api(*path), method), **request_kwargs)
    )

get_iterator = resource_iterator(method='get', resource_iterator=iter_by_50s)
get_iterator500 = resource_iterator(method='get', resource_iterator=iter_by_500s)
post_iterator = resource_iterator(method='post', resource_iterator=iter_by_50s)
post_iterator500 = resource_iterator(method='post', resource_iterator=iter_by_500s)

@curry
def method_body(obj_type: str, method: str, key_map: dict, site: dict, 
                new_body: dict):
    valid_keys = set(key_map.values())

    body = {}
    for site_key, method_key in key_map.items():
        if site_key in site:
            body[method_key] = site[site_key]
        if site_key != method_key and site_key in new_body:
            new_body = pipe(
                new_body,
                lambda d: assoc(d, method_key, d[site_key]),
                lambda d: dissoc(d, site_key),
            )
    final = merge(body, new_body)
    spurious = set(final) - set(valid_keys)
    if spurious:
        log.error(
            f'The following keys for {obj_type} {method}'
            f' are spurious: {", ".join(sorted(spurious))}'
        )
    log.debug(f'final {obj_type} {method} body:')
    for line in pipe(pprint.pformat(final), splitlines):
        log.debug(line)
    return final

