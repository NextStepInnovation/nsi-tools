import urllib
import urllib.parse
import typing as T
import functools

import requests
from pyrsistent import pmap, PMap

import nsi
from nsi.toolz import *

log = nsi.logging.new_log(__name__)

class TokenAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, request):
        request.headers['Authorization'] = 'Bearer {}'.format(self.token)
        return request

# E.g. https://example.com/api/v1
BaseURI = T.NewType('BaseURI', str)

class Api:
    base: urllib.parse.ParseResult
    session: requests.Session
    method_kw: PMap

    def __init__(self, base: BaseURI, session: requests.Session, *,
                 ns_keywords: T.Sequence[str] = None, **method_kw):
        self.base = urllib.parse.urlparse(base)
        self.session = session
        self.ns_keywords = ns_keywords or ()
        self.method_kw = pmap(method_kw)

    def url(self, *parts, **query):
        return pipe(
            (
                self.base.scheme,
                self.base.netloc,
                pipe(
                    concatv([self.base.path], parts),
                    map(str),
                    '/'.join,
                ),
                self.base.params,
                pipe(
                    self.base.query,
                    parse_qs,
                    lambda qd: merge(qd, query),
                    urlencode(doseq=True),
                ),
                self.base.fragment,
            ),
            urlunparse,
        )

    def __call__(self, *parts, **kw):
        return Endpoint(
            self, parts, 
            ns_keywords=self.ns_keywords, 
            **merge(self.method_kw, kw),
        )

def namespace_data(data: dict, sep='[]'):
    '''Take the data in a dictionary and convert it into a namespaced form.

    Examples:

    >>> ns_dict = namespace_data({'aspect': {'val0': 3, 'val1': 'something'}})
    >>> ns_dict == {
    ...     'aspect[val0]': 3,
    ...     'aspect[val1]': 'something',
    ... }
    True
    >>> ns_dict = namespace_data(
    ...    {'aspect': {'val0': 3, 'val1': 'something'}}, sep='{}'
    ... )
    >>> ns_dict == {
    ...     'aspect{val0}': 3,
    ...     'aspect{val1}': 'something',
    ... }
    True
    '''
    def ns_dict(ns: str, d: dict):
        return pipe(
            d.items(),
            vmap(lambda k, v: (f'{ns}{sep[0]}{k}{sep[1]}', v)),
            dict,
        )

    if is_dict(data):
        return pipe(
            data.items(),
            vmap(lambda k, v: ns_dict(k, v) if is_dict(v) else {k: v}),
            vcall(merge),
        )
    return data
                    
class Endpoint:
    def __init__(self, api, parts, *, 
                 ns_keywords: T.Sequence[str] = None, **kwargs):
        self.api = api
        self.parts = tuple(parts)
        self.ns_keywords = ns_keywords or ()

        self.kwargs = pipe(
            merge(
                {'url': self.url},
                kwargs,
            ),
            pmap,
        )

        for name in ['get', 'post', 'put', 'delete', 'head',
                     'options', 'patch']:
            setattr(
                self, name, self.method(name, **self.kwargs)
            )
            # setattr(
            #     self, f'maybe_{name}', self.maybe_method(name, **self.kwargs)
            # )

    def __call__(self, *parts, **kw):
        return Endpoint(
            self.api, tuple(concatv(self.parts, parts)), 
            ns_keywords=self.ns_keywords, **kw
        )

    @property
    def url(self):
        return pipe(
            self.parts,
            map(str),
            vcall(self.api.url),
        )

    def method(self, name, **orig_kw) -> requests.Response:
        session_method = getattr(self.api.session, name)
        @functools.wraps(session_method)
        def caller(*args, **kw):
            kw = merge(orig_kw, kw)
            for key in self.ns_keywords:
                if key in kw:
                    kw[key] = pipe(
                        kw.pop(key),
                        namespace_data,
                    )
            # Preserve JSON data passed in to Api object
            if 'json' in self.api.method_kw:
                kw['json'] = merge(
                    self.api.method_kw.get('json', {}),
                    kw.get('json', {}),
                )
            log.debug(
                f'{name.upper()}: args: {args} kw: {kw}'
            )
            return error_raise(session_method)(*args, **kw)
        return caller

    # def maybe_method(self, name: str, **orig_kw) -> T.Tuple[
    #         bool, requests.Response, T.Sequence[Exception]
    #         ]:
    #     session_method = getattr(self.api.session, name)
    #     @functools.wraps(session_method)
    #     def caller(*args, **kw):
    #         try:
    #             success, response, errors = (
    #                 True, self.method(name, **orig_kw)(*args, **kw), None,
    #             )
    #         except Exception as error:
    #             log.exception(f'Error in maybe_{name}')
    #             success, response, errors (
    #                 False, None, [error]
    #             )
    #         return success, response, errors
    #     return caller

def get_json(response: requests.Response) -> dict:
    '''Retrieve JSON from response or empty dictionary if no JSON exists
    '''
    return fmaybe(response.json)().or_else({})

Tv = T.TypeVar('Tv')
P = T.ParamSpec('P')

HttpMethod = T.Callable[
    [
        # *args
        # **kwargs
    ], requests.Response
]
