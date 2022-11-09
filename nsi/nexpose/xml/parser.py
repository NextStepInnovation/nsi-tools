'''
Nexpose XML Report parser

'''
from pathlib import Path
import functools
from datetime import datetime
import typing as T

import lxml
from pyrsistent import pmap
import bs4

from ...toolz import *
from ..types import (
    Float, Int, Html, Timestamp, Url, Ip, 
    TagName, TagId, 
    VulnerabilityNexposeId,
)
from .types import (
    Fingerprint, Software, Test, Configuration, Service, Endpoint, Reference,
    Node, Exploit, Malware, FindingId, Finding, FindingMap, Scan, XmlReport,
)

log = new_log(__name__)

Element = lxml.etree._Element
ElementTree = lxml.etree._ElementTree

def dtparse(ts):
    return datetime.strptime(ts, '%Y%m%dT%H%M%S%f')

def replace_tag(tag):
    def replace(node):
        node.tag = tag
        node.attrib.clear()
        return node
    return replace

def replace_link(node):
    node.tag = 'a'
    url = node.attrib.pop('LinkURL', '')
    title = node.attrib.pop('LinkTitle', '')
    node.attrib.clear()
    node.attrib['href'] = url
    if not node.text:
        node.text = title
    return node

def replace_paragraph(node):
    if 'preformat' in node.attrib:
        node.tag = 'pre'
        node.attrib.clear()
        # text = node.text
        # node.text = ''
        # pre = etree.SubElement(node, 'pre')
        # pre.text = text
        return node
    return replace_tag('p')(node)
        
    
replacements = {
    'Paragraph': replace_paragraph,
    'OrderedList': replace_tag('ol'),
    'UnorderedList': replace_tag('ul'),
    'ListItem': replace_tag('li'),
    'ContainerBlockElement': replace_tag('div'),
    'URLLink': replace_link,
    'Table': replace_tag('table'),
    'TableRow': replace_tag('tr'),
    'TableCell': replace_tag('td'),
    'TableHeader': replace_tag('th'),
}

def replace_html(obj: T.Any):
    match obj:
        case node if isinstance(node, Element):
            decendants = list(node.iterdescendants())
            for child in decendants:
                if child.tag not in replacements:
                    log.error('Unprocessed tag in Nexpose "HTML": %s', child.tag)
                else:
                    replacements[child.tag](child)

            return (
                ''.join(lxml.etree.tounicode(n) for n in node.getchildren())
            )
        case nodes if is_seq(nodes):
            return pipe(
                nodes,
                map(replace_html),
                '\n'.join
            )

def all_tests(node: Element):
    for test in node.xpath('tests/test'):
        yield pipe(test.attrib, partial(set_key, 'html', replace_html(test)))

def all_endpoints(node: Element):
    for endpoint in node.xpath('endpoints/endpoint'):
        services = []
        for s in endpoint.xpath('services/service'):
            services.append({
                'fingerprints': [
                    dict(n.attrib) for n in s.xpath('fingerprints/fingerprint')
                ],
                'configuration': [
                    pipe(n.attrib, partial(set_key, 'content', n.text))
                    for n in s.xpath('configuration/config')
                ],
                'tests': pipe(all_tests(s), list),
            })

        yield pipe(endpoint.attrib, partial(set_key, 'services', services))


def all_scans(tree: ElementTree):
    xpath = "/NexposeReport/scans/scan"
    for node in tree.xpath(xpath):
        yield dict(node.attrib)

def all_nodes(tree: ElementTree):
    xpath = "/NexposeReport/nodes/node"
    for node in tree.xpath(xpath):
        yield pipe(
            merge(
                node.attrib, {
                    'names': [n.text for n in node.xpath('names/name')],
                    'fingerprints': [
                        dict(n.attrib) for n in node.xpath('fingerprints/os')
                    ],
                    'software': [
                        dict(n.attrib) for n in node.xpath('software/fingerprint')
                    ],
                    'tests': pipe(
                        node,
                        all_tests, 
                        tuple,
                    ),
                    'endpoints': pipe(
                        node,
                        all_endpoints,
                        tuple,
                    )
                }
            ),
            lambda d: set_key('sites', d.get('site-name', '').split(','), d)
        )


def severity_score_to_desc(score: T.Union[str, int]):
    score = pipe(score, maybe_int(default=0))
    if score >= 8:
        return 'High'
    elif score >= 4:
        return 'Medium'
    return 'Low'

def reference_content_to_md(ref: Reference):
    source, content = ref.get('source'), ref.get('content', '')
    content = {
        'URL': f'[{content}]({content})',
        'CVE': f'[{content}](http://nvd.nist.gov/vuln/detail/{content})',
        'BID': f'[{content}](http://www.securityfocus.com/bid/{content})',
        'DEBIAN': (
            f'[{content}](https://security-tracker.debian.org'
            f'/tracker/{content})'
        ),
        'NVD': (
            f'[{content}](http://nvd.nist.gov/vuln/detail/{content})'
        ),
        'FREEBSD': (
            f'[{content}](http://www.freebsd.org/security/#adv)'
        ),
        'GENTOO': (
            f'[{content}](http://www.gentoo.org/security/en/'
            f'glsa/{content.lower()}.xml)'
        ),
        'REDHAT': (
            f'[{content}](http://rhn.redhat.com/errata/'
            f'{content.lower().replace(":","-")}.html)'
        ),
        'SECTRACK': (
            f'[{content}](http://securitytracker.com/id?{content})'
        ),
        'SUSE': (
            f'[{content}](http://www.novell.com/linux/'
            f'security/advisories.html)'
        ),
        'UBUNTU': (
            f'[{content}](https://usn.ubuntu.com/{content}/)'
        ),
        'DISA_SEVERITY': (
            f'[{content}](http://iase.disa.mil/stigs/iavm-cve.html)'
        ),
        'DISA_VMSKEY': (
            f'[{content}](http://iase.disa.mil/stigs/iavm-cve.html)'
        ),
        'IAVM': (
            f'[{content}](http://iase.disa.mil/stigs/iavm-cve.html)'
        ),
        'MSKB': (
            f'[{content}](https://support.microsoft.com/'
            f'en-us/kb/{content})'
        ),
        'CERT': (
            f'[{content}](http://www.us-cert.gov/cas/techalerts/'
            f'{content}.html)'
        ),
        'CERT-VN': (
            f'[{content}](http://www.kb.cert.org/vuls/id/{content})'
        ),
        'MS': (
            f'[{content}](http://technet.microsoft.com/security/'
            f'bulletin/{content})'
        ),
    }.get(source, content)

    return merge(ref, {
        'content': content
    })

def all_findings(tree: ElementTree):
    xpath = '/NexposeReport/VulnerabilityDefinitions/vulnerability'

    for finding in tree.xpath(xpath):
        yield pipe(
            merge(
                finding.attrib, {
                    'malware': [n.text for n in finding.xpath('malware/name')],
                    'exploits': [
                        dict(n.attrib) for n in finding.xpath('exploits/exploit')
                    ],
                    'description': replace_html(finding.xpath('description')),
                    'references': [
                        pipe(
                            n.attrib, 
                            partial(set_key, 'content', n.text),
                            reference_content_to_md,
                        )
                        for n in finding.xpath('references/reference')
                    ],
                    'tags': [
                        n.text for n in finding.xpath('tags/tag')
                    ],
                    'solution': replace_html(finding.xpath('solution')),
                    'severity-desc': severity_score_to_desc(
                        finding.attrib['severity']
                    ),
                }
            ),
        )


def with_any_tags(vdb, tags, iterable):
    return pipe(
        iterable,
        filter(lambda n: not set(tags).isdisjoint(vdb[n['id']]['tags']))
    )

def without_tags(vdb, tags, iterable):
    return pipe(
        iterable,
        filter(lambda n: set(tags).isdisjoint(vdb[n['id']]['tags']))
    )

def make_keywords(obj: T.Any):
    def to_keyword(key: str):
        return (
            key
            .replace('-', ' ')
            .replace(' ', '_')
        )

    match obj:
        case dct if is_dict(dct):
            return {
                to_keyword(k): make_keywords(v) 
                for k, v in dct.items()
            }
        case seq if is_seq(seq):
            return pipe(
                seq,
                map(make_keywords),
                tuple,
            )
    return obj

@ensure_paths
def parse(xml_path: T.Union[str, Path]) -> XmlReport:
    json_path = xml_path.parent / (xml_path.stem + '.json')
    if json_path.exists() and newer(json_path, xml_path):
        log.info(f'Found JSON cache of {xml_path.name} at {json_path.name}')
        if not newer(xml_path, json_path):
            return pipe(
                json_path,
                slurp,
                json_loads,
            )
        log.info(f'  .. XML is newer than JSON. Reloading XML.')
        
    log.info(f'Loading Nexpose XML report at {xml_path}')
    tree = lxml.etree.parse(str(xml_path))
    return pipe(
        {
            'nodes': all_nodes(tree),
            'findings': all_findings(tree),
            'scans': all_scans(tree),
        },
        valmap(tuple),
        cmerge({
            'hash': pipe(xml_path, slurp, md5),
            'path': str(xml_path),
        }),
        do(lambda d: (
            log.info(f'  .. found {len(d["nodes"])} nodes'),
            log.info(f'  .. found {len(d["findings"])} findings'),
            log.info(f'  .. found {len(d["scans"])} scans'),
        )),
        valmap(make_keywords),
        lambda report: merge(
            report, 
        ),
        do(
            lambda d: pipe(
                d,
                json_dumps(indent=2),
                json_path.write_text,
                do(lambda s: log.info(
                    f'  .. wrote JSON cache file {json_path} with'
                    f' size {s / 2**20:.02f}MiB'
                ))
            )
        ),
        XmlReport,
    )

_finding_maps = {}
def finding_map(report: XmlReport):
    if report['hash'] not in _finding_maps:
        _finding_maps[report['hash']] = {
            f['id']: f for f in report['findings']
        }
    return _finding_maps[report['hash']]

_node_maps = {}
def node_map(report: XmlReport):
    if report['hash'] not in _node_maps:
        _node_maps[report['hash']] = {
            n['address']: n for n in report['nodes']
        }
    return _node_maps[report['hash']]

@curry
def all_node_findings(report: XmlReport, node: Node):
    for test in node['tests']:
        yield merge(
            finding_map(report)[test['id']],
            {'test': test},
            {
                'node': {'address': node['address']},
            },
        )
    for endpoint in node['endpoints']:
        for service in endpoint['services']:
            for test in service['tests']:
                yield merge(
                    finding_map(report)[test['id']],
                    {'test': test},
                    {
                        'endpoint': pipe(
                            endpoint,
                            cdissoc('services'),
                        ),
                    },
                    {
                        'service': pipe(
                            service,
                            cdissoc('tests'),
                        )
                    },
                    {
                        'node': pipe(
                            node, 
                            cdissoc('tests'),
                            cdissoc('endpoints'),
                        )
                    },
                )

def finding_node_map(report: XmlReport):
    return pipe(
        report['nodes'],
        map(all_node_findings(report)),
        mapcat(compose_left(
            map(lambda f: (f['id'], f['node']['address']))
        )),
        groupby(first),
        valmap(map_t(second)),
    )

def node_finding_map(report: XmlReport):
    return pipe(
        report['nodes'],
        map(all_node_findings(report)),
        mapcat(compose_left(
            map(lambda f: (f['id'], f['node']['address']))
        )),
        groupby(second),
        valmap(map_t(first)),
    )


@curry
def filter_report(node_filter: T.Sequence[Ip], 
                  finding_filter: T.Sequence[TagId], 
                  report: XmlReport):
    return report

def ip_filter(ips: T.Sequence[Ip]):
    ip_set = set(ips)
    return lambda node: node['address'] in ip_set

def tag_filter(tags: T.Sequence[TagName]):
    tag_set = pipe(tags, map(lower), set)
    return lambda finding: not pipe(
        finding['tags'], lower, set
    ).isdisjoint(tag_set)

