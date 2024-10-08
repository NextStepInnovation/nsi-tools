import typing as T
from pathlib import Path

from ...toolz import (
    pipe, sort_by, filter, get, last, map,
)

from ..types import (
    Float, Int, Html, Timestamp, Url, Ip, 
    TagName, TagId, TagList, IpList, RegexList,
    VulnerabilityNexposeId,
)

class Fingerprint(T.TypedDict):
    certainty: Float
    device_class: str
    family: str
    product: str
    vendor: str
    version: str
    arch: str

def fingerprint_os(fp: Fingerprint, with_certainty: bool = True) -> str:
    vendor, product, version, device_class, certainty = pipe(
        ['vendor', 'product', 'version', 'device_class', 'certainty'],
        map(fp.get)
    )
    parts = (
        vendor if vendor and vendor != 'Microsoft' else '',
        product,
        version,
        f"({device_class})" if device_class else '',
        (f"[{(int(float(certainty)*100))}% certain]" 
         if (certainty and float(certainty) < 1.0 and with_certainty) 
         else ''),
    )

    return pipe(
        parts,
        filter(None),
        lambda parts: parts if parts else ('Unknown OS',),
        ' '.join,
    )

class Software(T.TypedDict):
    certainty: Float
    family: str
    product: str
    software_class: str
    vendor: str
    version: str

class Test(T.TypedDict):
    html: Html
    id: str
    key: str
    pci_compliance_status: str
    scan_id: Int
    status: str
    vulnerable_since: Timestamp

class NodeTest(Test):
    pass

class ServiceTest(Test):
    pass

class Configuration(T.TypedDict):
    content: str
    name: str

class Service(T.TypedDict):
    fingerprints: T.Sequence[Fingerprint]
    configuration: T.Sequence[Configuration]
    tests: T.Sequence[Test]

class Endpoint(T.TypedDict):
    protocol: str
    port: Int
    status: str
    services: T.Sequence[Service]

class Reference(T.TypedDict):
    source: str
    content: str

class Node(T.TypedDict):
    address: str
    device_id: Int
    endpoints: T.Sequence[Endpoint]
    fingerprints: T.Sequence[Fingerprint]
    names: T.Sequence[str]
    risk_score: Float
    scan_template: str
    site_importance: str
    site_name: str
    sites: T.Sequence[str]
    software: T.Sequence[Software]
    status: str
    tests: T.Sequence[Test]

def node_os(node: Node, with_certainty: bool = True) -> str:
    if not node['fingerprints']:
        return 'Unknown OS'
    best_guess = pipe(
        node['fingerprints'],
        sort_by(get('certainty')),
        last,
    )
    return fingerprint_os(best_guess)

class Exploit(T.TypedDict):
    id: Int
    link: Url
    skillLevel: str
    title: str
    type: str

Malware = T.NewType('Malware', str)

FindingId = VulnerabilityNexposeId

class Finding(T.TypedDict):
    added: Timestamp
    cvssScore: str
    cvssVector: str
    description: Html
    exploits: T.Sequence[Exploit]
    id: FindingId
    malware: T.Sequence[Malware]
    modified: Timestamp
    pciSeverity: str
    published: Timestamp
    references: T.Sequence[Reference]
    riskScore: Float
    severity: Int
    severity_desc: str
    solution: Html
    tags: T.Sequence[TagName]
    title: str

FindingMap = T.Dict[FindingId, Finding]

class Scan(T.TypedDict):
    id: Int
    name: str
    startTime: Timestamp
    endTime: Timestamp
    status: str

# -----------------------------------------------------------------------------
# XML Report
# -----------------------------------------------------------------------------

class XmlReport(T.TypedDict):
    hash: str
    path: Path
    nodes: T.Sequence[Node]
    findings: T.Sequence[Finding]
    scans: T.Sequence[Scan]

