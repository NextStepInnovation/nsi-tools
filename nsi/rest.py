import urllib
import urllib.parse
import typing as T
import functools
import textwrap
import keyword
from collections import namedtuple

import requests
import networkx as nx
from pyrsistent import pmap, PMap

from . import logging
from .templates import render
from .toolz import *

log = logging.new_log(__name__)

class TokenAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, request):
        request.headers['Authorization'] = 'Bearer {}'.format(self.token)
        return request

# E.g. https://example.com/api/v1
BaseURL = T.NewType('BaseURL', str)

P = T.ParamSpec # both *args, and **kwargs
Method = T.Callable[[P], requests.Response]

Api_T = T.TypeVar('Api_T', bound='Api')
Endpoint_T = T.TypeVar('Endpoint_T', bound='Endpoint')
ParseResult = namedtuple(
    'ParseResult', ['scheme', 'netloc', 'path', 'params', 'query', 'fragment']
)

# These are keyword arguments passed to the Request that need to be "namespaced"
# first. That is, they need to be passed to the `namespace_data` function to be
# "flattened" into a namespace before being passed the Request as a JSON/body
# parameter. See the `namespace_data` function for more details
NSKeywords = T.Sequence[str]

class Api:
    base: ParseResult
    session: requests.Session
    method_kwargs: PMap
    ns_keywords: NSKeywords

    def __init__(self, base: BaseURL, session: requests.Session, *,
                 ns_keywords: NSKeywords = None, **method_kwargs):
        self.base = urllib.parse.urlparse(base)
        self.session = session
        self.ns_keywords = pipe(ns_keywords or (), tuple)
        self.method_kwargs = pmap(method_kwargs)

    def url(self, *parts, **query) -> str:
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
                    lambda qdict: merge(qdict, query),
                    urlencode(doseq=True),
                ),
                self.base.fragment,
            ),
            urlunparse,
        )

    def __call__(self, *parts, **kwargs) -> Endpoint_T:
        return Endpoint(
            self, parts, 
            ns_keywords=self.ns_keywords, 
            **merge(self.method_kwargs, kwargs),
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
    get: Method
    post: Method
    put: Method
    delete: Method
    head: Method
    options: Method
    patch: Method

    def __init__(self, api: Api_T, url_parts: T.Sequence[str | int], *, 
                 ns_keywords: T.Sequence[str] = None, **kwargs):
        self.api = api
        self.url_parts = tuple(url_parts)
        self.ns_keywords = ns_keywords or ()

        self.orig_kwargs = kwargs

        for name in ['get', 'post', 'put', 'delete', 'head',
                     'options', 'patch']:
            setattr(
                self, name, self.method(name)
            )
            # setattr(
            #     self, f'maybe_{name}', self.maybe_method(name, **self.kwargs)
            # )

    def __call__(self, *url_parts, **kwargs) -> Endpoint_T:
        url_parts = pipe(
            concatv(self.url_parts, url_parts),
            tuple,
        )
        return Endpoint(
            self.api, url_parts, 
            ns_keywords=self.ns_keywords, 
            **merge(self.orig_kwargs, kwargs),
        )

    @property
    def url(self):
        return pipe(
            self.url_parts,
            map(str),
            vcall(self.api.url),
        )

    def get_kwargs(self, **kwargs) -> dict:
        kwargs: dict = pipe(
            merge(
                {'url': self.url},
                self.orig_kwargs,
                kwargs,
            ),
        )

        for key in self.ns_keywords:
            if key in kwargs:
                kwargs[key] = namespace_data(kwargs[key])

        match self.api.method_kwargs:
            case {'json': json_data}:
                kwargs['json'] = merge(
                    json_data, kwargs.get('json', {})
                )

        return kwargs

    def method(self, name: str) -> Method:
        session_method = getattr(self.api.session, name)
        @functools.wraps(session_method)
        def caller(*args, **kwargs):
            kwargs: dict = self.get_kwargs(**kwargs)
            log.debug(
                f'{name.upper()} --> args: {args} kw: {kwargs}'
            )
            return error_raise(session_method)(*args, **kwargs)
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

#----------------------------------------------------------------------------
# Swagger functionality
#----------------------------------------------------------------------------

# name_to_type = {
#     'ip': 'Ip',
#     'protocol': 'Protocol',
#     'url': 'Url',
#     'href': 'Url',
#     'port': 'Port',
#     'mac': 'Mac',
# }
type_map = {
    'integer': 'int',
    'string': 'str',
    'object': 'str',
    'number': 'float',
    'boolean': 'bool'
}

def get_ref(ref_str: str):
    return ref_str.split('/')[-1]

def def_edges(japi: dict, def_name: str):
    for name, prop in japi['definitions'][def_name]['properties'].items():
        match prop:
            case {'$ref': ref_str}:
                ref = get_ref(ref_str)
                yield (def_name, ref)
                yield from def_edges(japi, ref)
            case {'type': 'array', 'items': {'$ref': ref_str}}:
                ref = get_ref(ref_str)
                yield (def_name, ref)
                yield from def_edges(japi, ref)

def_graph = compose_left(def_edges, from_edgelist(factory=nx.DiGraph))

class DefProperty(T.TypedDict):
    name: str
    type: str

def def_properties(japi: dict, def_name: str) -> T.Iterable[DefProperty]:
    for name, prop in japi['definitions'][def_name]['properties'].items():
        out_prop = {'name': name}
        match prop:
            # case _special if name in name_to_type:
            #     yield merge(out_prop, {'type': name_to_type[name]})
            case {'type': ptype} if ptype in type_map:
                yield merge(out_prop, {'type': type_map[ptype]})
            case {'$ref': ref_str}:
                ref = get_ref(ref_str)
                yield merge(out_prop, {'type': ref})
            case {'type': 'array', 'items': array_items}:
                match array_items:
                    case {'$ref': ref_str}:
                        ref = get_ref(ref_str)
                        yield merge(out_prop, {'type': f'T.Sequence[{ref}]'})
                    case {'type': atype} if atype in type_map:
                        atype = type_map[atype]
                        yield merge(out_prop, {'type': f'T.Sequence[{atype}]'})

def_td_class_bp = '''
class {{ name }}(T.TypedDict):
    {%- for prop in properties %}
    {{ prop.name }}: {{ prop.type }}
    {%- endfor %}
'''

def_td_expr_bp = '''
{{ name }} = T.TypedDict('{{ name }}', {
    {%- for prop in properties %}
    '{{ prop.name }}': {{ prop.type }},
    {%- endfor %}
})
'''

def valid_var(prop: DefProperty):
    name = prop['name']
    return name.isidentifier() and not keyword.iskeyword(name)

def def_codes(japi: dict, *root_defs: T.Tuple[str]):
    total_graph = nx.DiGraph()
    for root_def in root_defs:
        digraph = def_graph(japi, root_def)
        total_graph = nx.compose(total_graph, digraph)
    
    names = pipe(
        total_graph,
        nx.transitive_closure,
        lambda g: g.out_degree,
        dict,
        items,
        sort_by(second),
        map(first)
    )
    for def_name in names:
        properties = tuple(def_properties(japi, def_name))
        if pipe(properties, map(valid_var), all):
            bp = def_td_class_bp
        else:
            bp = def_td_expr_bp
        yield render(bp, name=def_name, properties=properties)
