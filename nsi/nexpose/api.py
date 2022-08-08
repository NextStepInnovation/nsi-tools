import typing as T
import pprint

import urllib3
import requests
import requests.auth

import nsi
from nsi.toolz import *
from nsi.rest import Api, HttpMethod, get_json

log = nsi.logging.new_log(__name__)

class NexposeApiError(IOError):
    pass

def kw_tuple_to_dict(kw_seq: T.Sequence[T.Tuple[str, T.Any]]):
    '''
    Convert (key, value) tuple into dictionary while progressively merging
    values that are dictionaries. Purpose: allow for call-stack modification of
    kw arguments.
    
    '''
    args = {}
    for (kw, value) in kw_seq:
        if type(value) is dict:
            args[kw] = merge(args.get(kw, {}), value)
        else:
            args[kw] = value
    return args

def resources_iter(method, *kw_tuple, **kw):
    kwargs = kw_tuple_to_dict(kw_tuple)

    params = kwargs.get('params', {})
    size = params.get('size', 'unknown')

    log.info(
        f'    page: 0 of-size: {size} for method: {method}'
    )
    response = method(**kwargs)
    json = fmaybe(response.json)().or_else({})

    if json.get('page'):
        for value in json.get('resources', []):
            yield value

        for page_i in range(1, json['page']['totalPages']):
            log.info(
                f'    page: {page_i} of-size: {json["page"].get("size")}'
                f' for method: {method}'
            )
            response = method(
                **assoc(kwargs, 'params', merge(params, {'page': page_i}))
            )
            json = fmaybe(response.json)().or_else({})
            for value in json.get('resources', []):
                yield value
    else:
        for value in json.get('resources', []):
            yield value

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

@curry
def merge_params(params, kwargs):
    return assoc(kwargs, 'params', merge(
        kwargs['params'], params
    ))

@curry
def iter_resources(method: requests.Response, size=500, **kwargs):
    '''
    Automatically iterate over resources using progressive page sizing
    '''
    kwargs = pipe(
        kwargs,
        merge_params({
            'size': size,
        }),
    )

    match pipe(method(**kwargs), get_json):
        case {
            'resources': resources, 
            'page': {
                'number': page_no,
                'size': page_size,
                'totalResources': n_resources,
                'totalPages': n_pages
            }, 
            'links': link_seq
            } as paged_json:
            for resource in resources:
                yield resource
            links = links_dict(link_seq)
            if 'next' in links:
                yield from iter_resources(method, pipe(
                    kwargs,
                    merge_params({'page': page_no + 1})
                ))
        case {
            'links': link_seq,
            'message': message,
            'status': status
            } as error:
            # Something went wrong
            log_error(error)
        case {
            'id': item_id,
            } as item_json:
            yield item_json
iter_500 = iter_resources(params={'size': 500})

@curry
def get_resources(n: int, method):
    return partial(resources_iter, method, ('params', {'size': n}))
get_by_50s = get_resources(50)
get_by_500s = get_resources(500)

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
def get_iterator(path: T.Sequence[T.Any], api: Api, 
                 resource_getter: ResourceGetter = get_by_50s):
    return resource_getter(api(*path).get)
