import io
from pathlib import Path
import functools
import typing as T

import markdownify
import lxml.etree

from .toolz import *
from . import logging

log = logging.new_log(__name__)

ns2url = {
    'xml': 'http://www.w3.org/XML/1998/namespace',
    'xhtml': 'http://www.w3.org/1999/xhtml',
    'xccdf': 'http://checklists.nist.gov/xccdf/1.2',
    'ns2': 'http://cpe.mitre.org/language/2.0',
    'notes': 'http://benchmarks.cisecurity.org/notes',
    'ae': 'http://benchmarks.cisecurity.org/ae/0.5',
    'ciscf': 'https://benchmarks.cisecurity.org/ciscf/1.0',
    'cc7': 'http://cisecurity.org/20-cc/v7.0',
    'cc6': 'http://cisecurity.org/20-cc/v6.1',
    'cc8': 'http://cisecurity.org/20-cc/v8.0',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    'controls': 'http://cisecurity.org/controls',
    'ds': 'http://www.w3.org/2000/09/xmldsig#'
}
url2ns = pipe(
    ns2url,
    items,
    map(reversed),
    map(tuple),
    dict,
)

def tag_ns(tag: str | lxml.etree._Element):
    if not is_str(tag):
        tag = tag.tag
    if '}' in tag:
        return url2ns[tag.split('}')[0][1:]]
    elif ':' in tag:
        return tag.split(':', 1)[0]
    return None, tag

def unpack_ns(tag: str):
    if ':' in tag and '{' not in tag:
        ns, tag = tag.split(':', 1)
        return f"{{{ns2url[ns]}}}" + tag
    return tag

def pack_ns(tag: str):
    if '{' in tag:
        url, tag = tag.split('}')
        url = url[1:]
        return f"{url2ns[url]}:{tag}"
    return tag

@curry
def build_nsmap(node, agg = None):
    agg = agg or {}
    if type(node) is lxml.etree._ElementTree:
        return build_nsmap(node.getroot(), agg)
    return merge(
        agg, node.nsmap, pipe(
            node.getchildren(),
            map(build_nsmap(agg=agg)),
            filter(None),
            merge,
        ),
    )




@curry
def xpath(node: lxml.etree._ElementTree | lxml.etree._Element, path: str, **xpath_kw):
    xpath_kw['namespaces'] = ns2url
    return node.xpath(path, **xpath_kw)

def nfind(node: lxml.etree._ElementTree | lxml.etree._Element):
    return functools.wraps(node.find)(partial(
        node.find, namespaces=ns2url
    ))

_builders = None
def xml_builder(*tags):
    def decorator(callback_func):
        global _builders
        _builders = _builders or {}
        callback = callback_func()
        @functools.wraps(callback_func)
        def wrapper(action: str, elem: lxml.etree._Element, nstag: str):
            return callback(action, elem, nstag)
        for tag in tags:
            _builders.setdefault(tag, []).append(wrapper)
        return wrapper
    return decorator

def get_xhtml_markdown(node: lxml.etree._Element):
    has_xhtml = pipe(
        node.getchildren(), tuple, bool,
    )
    if not has_xhtml:
        return node.text.strip()
    return pipe(
        node.getchildren(),
        filter(lambda c: tag_ns(c) == 'xhtml'),
        map(lxml.etree.tostring),
        map(to_str),
        '\n'.join,
        replace('xhtml:', ''),
        markdownify.markdownify,
    )

@curry
def dict_from_children(child_f, node, tags, ns='xccdf'):
    ns = f'{ns}:' if ns else ''
    return pipe(
        tags,
        map(lambda t: (t, nfind(node)(f'{ns}{t}'))),
        vfilter(lambda t, n: n is not None),
        vmap(lambda t, n: (t, child_f(n))),
        dict,
    )
from_text = dict_from_children(
    lambda n: n.text
)
from_xhtml = dict_from_children(
    lambda n: get_xhtml_markdown(n)
)

def get_id(obj: str | dict | lxml.etree._Element):
    if is_str(obj):
        return md5(obj)
    if is_dict(obj):
        return get_id(obj['id'])
    return get_id(obj.attrib['id'])

@xml_builder('xccdf:Group')
def group_builder():
    group_stack = []
    def builder(action: str, nstag: str, elem: lxml.etree._Element):
        match (action, nstag, elem):
            case ('start', 'xccdf:Group', group):
                group_stack.append(dict(elem.attrib).copy())
            case ('end', 'xccdf:Group', group):
                group_dict = merge(
                    group_stack.pop(),
                    {'id': get_id(group)},
                    from_text(group, ['title']),
                    from_xhtml(group, ['description']),
                    {'parents': pipe(
                        group_stack,
                        map(get_id),
                        tuple,
                    )},
                )
                
                return group_dict
    return builder

@xml_builder('xccdf:Group', 'xccdf:Rule')
def rule_builder():
    group_stack = []
    def builder(action, nstag, elem):
        match (action, nstag, elem):
            case ('start', 'xccdf:Group', group):
                group_stack.append(get_id(group))

            case ('end', 'xccdf:Rule', rule):
                if group_stack:
                    rule_dict = merge(
                        rule.attrib,
                        {'id': get_id(rule)},
                        {'groups': tuple(group_stack)},
                        from_text(rule, ['title']),
                        from_xhtml(rule, [
                            'description', 'rationale', 'fixtext'
                        ]),
                    )

                    return rule_dict
                
            case ('end', 'xccdf:Group', _group):
                group_stack.pop()
    return builder

_the_bad = None
@xml_builder('xccdf:TestResult')
def result_builder():
    def builder(action, nstag, elem):
        result_stack = []
        match (action, nstag, elem):
            case ('end', 'xccdf:TestResult', test_result):
                if nfind(test_result)('xccdf:target') is None:
                    global _the_bad
                    _the_bad = test_result
                    log.error(test_result)

                result_dict = merge(
                    test_result.attrib,
                    {'id': get_id(test_result)},
                    from_text(test_result, [
                        'title', 'remark', 'organization', 'target', 
                        'target-address', 'score',
                    ]),
                    pipe(
                        xpath(test_result)('.//xccdf:fact'),
                        map(lambda n: (n.attrib['name'].split(':')[-1], n.text)),
                        dict,
                    ),
                    {'results': pipe(
                        xpath(test_result)('./xccdf:rule-result'),
                        map(lambda n: (n.attrib['idref'], nfind(n)('xccdf:result'))),
                        vfilter(lambda i, r: r is not None),
                        vmap(lambda i, r: (get_id(i), r.text)),
                        dict
                    )},
                )
                result_dict = merge(result_dict, {
                    'passed': pipe(
                        result_dict['results'],
                        valfilter(lambda v: v == 'pass'),
                        count,
                    ),
                    'failed': pipe(
                        result_dict['results'],
                        valfilter(lambda v: v == 'fail'),
                        count,
                    )
                })

                return result_dict
    return builder

@ensure_paths
def parse_xml(path: Path):
    context = lxml.etree.iterparse(
        path.open('rb'), events=('start', 'end'), tag=pipe(
            _builders,
            keys,
            map(unpack_ns),
            set,
            tuple,
        )
    )
    for action, elem in context:
        nstag = pack_ns(elem.tag)
        for builder in _builders.get(nstag, []):
            output = builder(action, nstag, elem)
            if output:
                yield (builder.__name__, output)



