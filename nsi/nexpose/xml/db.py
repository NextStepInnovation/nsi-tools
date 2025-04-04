from ast import For
import pprint
from pathlib import Path
import re
import typing as T

from sqlalchemy import (
    ForeignKey, create_engine, Table, Column, String, Integer, Float, true,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    declarative_base, relationship, Session,
)

from ... import logging
from ...toolz import (
    pipe, vmap, merge, ensure_paths, get, filter, map, vfilter,
    take, mapcat, do, newer, first, maybe_first, groupby, deref, valmap,
    igrep, is_str, is_seq, curry, complement, strip, get_ips_from_lines,
)

from . import parser
from . import types
from .types import (
    TagName, TagList, Ip, IpList, RegexList,
)

__all__ = [
    'get_engine', 'get_session', 
    'Fingerprint', 'ServiceFingerprint', 'NodeFingerprint', 
    'Software', 
    'Test', 'ServiceTest', 'NodeTest', 
    'Configuration', 'Service', 'Endpoint', 'NodeName', 'Site', 'Node', 'Exploit',
    'Malware', 'Tag', 'Finding', 'Scan', 'NexposeReport',
]

log = logging.new_log(__name__)

def address_seq(addresses: IpList):
    return pipe(
        addresses,
        get_ips_from_lines,
    )

@ensure_paths
def get_db_path(xml_path: Path) -> Path:
    return xml_path.parent / f'{xml_path.stem}.db'

@ensure_paths
def get_engine(xml_path: Path, echo=False, future=True, **engine_kw) -> Engine:
    path = get_db_path(xml_path)
    return create_engine(
        f'sqlite+pysqlite:///{path}', 
        echo=echo, 
        future=future,
        **engine_kw
    )

@ensure_paths
def get_session(xml_path: Path, session_kw=None, engine_kw=None) -> Session:
    engine = get_engine(xml_path, **(engine_kw or {}))
    return Session(engine, **(session_kw or {}))


Base = declarative_base()

'''
class Fingerprint(T.TypedDict):
    certainty: report.FloatStr
    device_class: str
    family: str
    vendor: str
    version: str
'''

class NexposeData:
    typed_dict = None
    repr_keys = ()
    ingest_keys = ()
    output_default = None

    def __repr__(self):
        attrs_str = pipe(
            self.repr_keys,
            map(lambda k: k(self) if callable(k) else (k, getattr(self, k))),
            vfilter(lambda k, v: bool(v)),
            vmap(lambda k, v: f'{k}={v}'),
            ', '.join,
        )
        return f'{self.typed_dict.__name__}({attrs_str})'

    @classmethod
    def from_dict(cls, data: dict):
        self = cls()

        data = merge(data, self.prepare(data))

        for key in self.ingest_keys:
            setattr(self, key, data.get(key, ''))

        self.ingest(data)
        return self

    def to_dict(self):
        data = merge(self.output_default or {})
        output_keys = tuple(data) or self.ingest_keys

        for key in output_keys:
            data[key] = getattr(self, key)

        return merge(data, self.output_dict(data))

    def output_dict(self, data: dict):
        return data

    def prepare(self, data: dict) -> dict:
        return {}

    def ingest(self, data: dict):
        pass


'''
class Fingerprint(T.TypedDict):
    certainty: Float
    device_class: str
    family: str
    product: str
    vendor: str
    version: str
    arch: str
'''
class Fingerprint(Base, NexposeData):
    typed_dict = types.Fingerprint
    repr_keys = (
        'certainty', 'device_class', 'family', 'product', 'vendor', 'version',
        'arch'
    )
    ingest_keys = repr_keys

    __tablename__ = 'fingerprint'
    table_id = Column(Integer, primary_key=True)
    fingerprint_type = Column(String(10))
    
    certainty = Column(Float)
    device_class = Column(String)
    family = Column(String)
    product = Column(String)
    vendor = Column(String)
    version = Column(String)
    arch = Column(String)

    __mapper_args__ = {
        "polymorphic_on": fingerprint_type,
    }

    def prepare(self, data: types.Fingerprint):
        return {
            'certainty': float(data['certainty']),
        }

class NodeFingerprint(Fingerprint):
    node = relationship('Node', back_populates='fingerprints')
    node_id = Column(Integer, ForeignKey('node.table_id'))

    __mapper_args__ = {
        'polymorphic_identity': 'node'
    }

class ServiceFingerprint(Fingerprint):
    service_id = Column(Integer, ForeignKey('service.table_id'))
    service = relationship('Service', back_populates='fingerprints')

    __mapper_args__ = {
        'polymorphic_identity': 'service'
    }



'''
class Software(T.TypedDict):
    certainty: Float
    family: str
    product: str
    software_class: str
    vendor: str
    version: str
'''
class Software(Base, NexposeData):
    typed_dict = types.Software
    repr_keys = (
        (lambda s: ('node', s.node.address)), 
        'certainty', 'family', 'product', 
        'software_class', 
        'vendor', 'version', 
    )
    ingest_keys = (
        'certainty', 'family', 'product', 
        'software_class', 
        'vendor', 'version', 
    )

    __tablename__ = 'software'
    table_id = Column(Integer, primary_key=True)
    certainty = Column(Float)
    family = Column(String)
    product = Column(String)
    software_class = Column(String)
    vendor = Column(String)
    version = Column(String)

    node_id = Column(Integer, ForeignKey('node.table_id'))
    node = relationship('Node', back_populates='software')

    def prepare(self, data: types.Software):
        return pipe(
            merge(
                data,
                {'certainty': float(data['certainty'])},
            ),
        )


'''
class Test(T.TypedDict):
    html: Html
    id: str
    key: str
    pci_compliance_status: str
    scan_id: Int
    status: str
    vulnerable_since: Timestamp
'''
class Test(Base, NexposeData):
    typed_dict = types.Test
    repr_keys = (
        'id', (lambda s: ('finding', s.finding.title)), 'status'
    )
    ingest_keys = (
        'html', 'id', 'key', 'pci_compliance_status', 'scan_id',
        'status', 'vulnerable_since',
    )

    __tablename__ = 'test'
    table_id = Column(Integer, primary_key=True)
    test_type = Column(String(10))

    html = Column(String)
    id = Column(String, ForeignKey('finding.id'))
    key = Column(String)
    pci_compliance_status = Column(String)
    status = Column(String)
    vulnerable_since = Column(String)

    finding = relationship('Finding', back_populates='tests')
    scan_id = Column(Integer, ForeignKey('scan.id'))
    scan = relationship('Scan', back_populates='tests')

    __mapper_args__ = {
        "polymorphic_on": test_type,
    }

    @classmethod
    def node_filter(cls, addresses: IpList):
        return NotImplemented

    @classmethod
    def node_finding_filter(cls, addresses: IpList, 
                            include_tags: TagList, exclude_tags: TagList, 
                            include_regex: RegexList = None,
                            exclude_regex: RegexList = None):
        node_filter = cls.node_filter(addresses)
        finding_filter = cls.finding_filter(
            include_tags, exclude_tags, include_regex, exclude_regex,
        )
        if finding_filter is not None:
            return node_filter & finding_filter
        return node_filter

    @classmethod
    def finding_filter(cls, include_tags: TagList, exclude_tags: TagList,
                       include_regex: RegexList, exclude_regex: RegexList):
        finding_filter = Finding.finding_filter(
            include_tags, exclude_tags,  include_regex, exclude_regex,
        )
        if finding_filter is not None:
            return cls.finding.has(finding_filter)
        



class ServiceTest(Test):
    typed_dict = types.ServiceTest
    service_id = Column(Integer, ForeignKey('service.table_id'))
    service = relationship('Service', back_populates='tests')

    __mapper_args__ = {
        "polymorphic_identity": 'service',
    }

    @classmethod
    def node_filter(cls, addresses: IpList):
        return pipe(
            addresses,
            address_seq,
            Node.address.in_,
            Endpoint.node.has,
            Service.endpoint.has,
            cls.service.has,
        )

    @property
    def node(self):
        return self.service.endpoint.node

class NodeTest(Test):
    typed_dict = types.NodeTest
    node_id = Column(Integer, ForeignKey('node.table_id'))
    node = relationship('Node', back_populates='tests')

    __mapper_args__ = {
        "polymorphic_identity": 'node',
    }

    @classmethod
    def node_filter(cls, addresses: IpList):
        return pipe(
            addresses,
            address_seq,
            Node.address.in_,
            cls.node.has
        )


'''
class Configuration(T.TypedDict):
    content: str
    name: str
'''
class Configuration(Base, NexposeData):
    typed_dict = types.Configuration
    repr_keys = (
        'name', 'content'
    )
    ingest_keys = (
        'content', 'name',
    )

    __tablename__ = 'configuration'
    table_id = Column(Integer, primary_key=True)
    content = Column(String)
    name = Column(String)

    service_id = Column(Integer, ForeignKey('service.table_id'))
    service = relationship('Service', back_populates='configuration_parts')


'''
class Service(T.TypedDict):
    fingerprints: T.Sequence[Fingerprint]
    configuration: T.Sequence[Configuration]
    tests: T.Sequence[Test]
'''
class Service(Base, NexposeData):
    typed_dict = types.Service
    repr_keys = (
        (lambda s: ('fingerprint', str(s.fingerprint))),
        (lambda s: ('configuration', str(s.configuration))),
    )

    __tablename__ = 'service'
    table_id = Column(Integer, primary_key=True)
    
    fingerprints = relationship('ServiceFingerprint', back_populates='service')
    configuration_parts = relationship('Configuration', back_populates='service')
    tests = relationship('ServiceTest', back_populates='service')

    endpoint_id = Column(Integer, ForeignKey('endpoint.table_id'))
    endpoint = relationship('Endpoint', back_populates='services')

    @property
    def fingerprint(self):
        if self.fingerprints:
            return self.fingerprints[0]

    @property
    def configuration(self):
        return pipe(
            self.configuration_parts,
            map(lambda c: (c.name, c.content)),
            dict,
        )

    def ingest(self, data: types.Service):
        pipe(
            data['fingerprints'],
            map(ServiceFingerprint.from_dict),
            self.fingerprints.extend,
        )
        pipe(
            data['configuration'],
            map(Configuration.from_dict),
            self.configuration_parts.extend,
        )
        pipe(
            data['tests'],
            map(ServiceTest.from_dict),
            self.tests.extend,
        )

    def output_dict(self, data: dict):
        return {
            'fingerprints': [
                fp.to_dict() for fp in self.fingerprints
            ],
            'configuration': [
                c.to_dict() for c in self.configuration_parts
            ],
            'tests': [
                t.to_dict() for t in self.tests
            ],
        }



'''
class Endpoint(T.TypedDict):
    protocol: str
    port: report.IntStr
    status: str
    services: T.Sequence[Service]
'''

class Endpoint(Base, NexposeData):
    typed_dict = types.Endpoint
    repr_keys = (
        'port', 'protocol', 'status', (lambda s: ('node', s.node.address)),
    )
    ingest_keys = (
        'port', 'protocol', 'status',
    )

    __tablename__ = 'endpoint'
    table_id = Column(Integer, primary_key=True)

    protocol = Column(String)
    port = Column(Integer)
    status = Column(String)

    services = relationship('Service', back_populates='endpoint')

    node_id = Column(Integer, ForeignKey('node.table_id'))
    node = relationship('Node', back_populates='endpoints')

    def prepare(self, data: types.Endpoint):
        return {
            'port': int(data['port']),
        }

    def ingest(self, data: types.Endpoint):
        pipe(
            data['services'],
            map(Service.from_dict),
            self.services.extend,
        )

    def output_dict(self, data: dict):
        return {
            'services': [
                s.to_dict() for s in self.services
            ]
        }

'''
class Reference(T.TypedDict):
    source: str
    content: str
'''

class Reference(Base, NexposeData):
    typed_dict = types.Reference
    repr_keys = (
        'source', 'content'
    )
    ingest_keys = repr_keys

    __tablename__ = 'reference'
    table_id = Column(Integer, primary_key=True)

    source = Column(String)
    content = Column(String)

    finding_id = Column(Integer, ForeignKey('finding.id'))
    finding = relationship('Finding', back_populates='references')


class Site(Base):
    __tablename__ = 'site'
    repr_keys = ('name', )

    name = Column(String, primary_key=True)

    nodes = relationship(
        'Node',
        secondary=Table(
            'site_node', Base.metadata,
            Column(
                'site_name', String, ForeignKey('site.name'), 
                primary_key=True,
            ),
            Column(
                'node_id', Integer, ForeignKey('node.table_id'), 
                primary_key=True,
            ),
        ),
        backref='sites',
    )

    _sites = {}
    @classmethod
    def from_name(cls, name):
        if name in cls._sites:
            return cls._sites[name]
        cls._sites[name] = cls(name=name)
        return cls._sites[name]


class NodeName(Base):
    __tablename__ = 'node_name'
    table_id = Column(Integer, primary_key=True)

    name = Column(String)

    node_id = Column(Integer, ForeignKey('node.table_id'))
    node = relationship('Node', back_populates='names')

    def __repr__(self):
        return f'NodeName: {self.name}'

    @classmethod
    def from_name(cls, name):
        return cls(name=name)

'''
class Node(T.TypedDict):
    address: str
    device_id: report.IntStr
    endpoints: T.Sequence[Endpoint]
    fingerprints: T.Sequence[Fingerprint]
    names: T.Sequence[NodeName]
    risk_score: report.FloatStr
    scan_template: str
    site_importance: str
    site_name: str
    sites: T.Sequence[Site]
    software: T.Sequence[Software]
    status: str
    tests: T.Sequence[Test]
'''

PortArg = str | int | T.Sequence[int|str]
def port_set(ports: PortArg):
    return pipe(
        ports if is_seq(ports) else [ports],
        map(int),
        set,
    )

class Node(Base, NexposeData):
    typed_dict = types.Node
    repr_keys = (
        'address', 'risk_score', 'site_name', 'device_id', 'os',
    )
    ingest_keys = (
        'address', 'device_id', 'risk_score', 'scan_template', 'site_importance',
        'site_name', 'status',
    )

    __tablename__ = 'node'
    table_id = Column(Integer, primary_key=True)

    address = Column(String, index=True)
    device_id = Column(Integer)
    risk_score = Column(Float)
    scan_template = Column(String)
    site_importance = Column(String)
    site_name = Column(String, ForeignKey('site.name'))
    status = Column(String)
    
    endpoints = relationship('Endpoint', back_populates='node')
    fingerprints = relationship('NodeFingerprint', back_populates='node')

    names = relationship('NodeName', back_populates='node')
    software = relationship('Software', back_populates='node')
    tests = relationship('NodeTest', back_populates='node')

    report_id = Column(Integer, ForeignKey('nexpose_report.table_id'))
    report = relationship('NexposeReport', back_populates='nodes')

    def tests_from_data(data: types.Node):
        pass

    @property
    def all_tests(self):
        yield from self.tests
        for endpoint in self.endpoints:
            for service in endpoint.services:
                yield from service.tests

    @classmethod
    @curry
    def has_name(cls, name: str | T.Tuple[str], node: 'Node', *, no: bool = False):
        names = [name] if is_str(name) else name
        return pipe(
            names,
            mapcat(lambda n: pipe(node.names, map(str), igrep(n))),
            tuple,
            complement(bool) if no else bool,
        )

    @property
    def name(self):
        return self.names[0].name if self.names else ''
    
    @classmethod
    @curry
    def has_os(cls, with_os: str | T.Sequence[str], node: 'Node', *, 
               without_os: str = None):
        with_regexes = [with_os] if is_str(with_os) else with_os
    
        without_os = without_os or []
        without_regexes = [without_os] if is_str(without_os) else without_os
    
        node_os = cls.get_os(node)
        with_matches = pipe(
            with_regexes,
            filter(lambda regex: re.search(regex, node_os, re.I)),
            tuple,
        )
        without_matches = pipe(
            without_regexes,
            filter(lambda regex: re.search(regex, node_os, re.I)),
            tuple,
        )
        if with_matches and not without_matches:
            return True
        return False

    @classmethod
    @curry
    def get_os(cls, node: 'Node', with_certainty: bool = True) -> str:
        if node.fingerprint is None:
            return 'Unknown OS'
        fp = node.fingerprint
        parts = (
            fp.vendor if fp.vendor != 'Microsoft' else '',
            fp.product,
            fp.version,
            f"({fp.device_class})" if fp.device_class else '',
            (f"[{int(float(fp.certainty)*100)}% certain]" 
            if (fp.certainty and float(fp.certainty) < 1.0 and with_certainty) 
            else ''),
        )

        return pipe(
            parts,
            filter(None),
            lambda parts: parts if parts else ('Unknown OS',),
            ' '.join,
        )

    @property
    def os(self):
        return Node.get_os(self)

    @property
    def os_bare(self):
        return Node.get_os(self, with_certainty=False)

    @classmethod
    @curry
    def has_ports(cls, port: PortArg, node: 'Node', *, 
                  no: bool = False):
        ports = port_set(port)
        return pipe(
            node.ports & ports,
            complement(bool) if no else bool,
        )
    
    @classmethod
    def with_ports(cls, with_port: PortArg, without_port: PortArg = None):
        def query(session: Session):
            in_ports = port_set(with_port)
            port_filter = Endpoint.port.in_(in_ports)
            if without_port:
                port_filter = port_filter & ~Node.endpoints.any(
                    Endpoint.port.in_(port_set(without_port))
                )
            return session.query(cls).join(cls.endpoints).filter(port_filter)
        return query

    @property
    def ports(self) -> T.Set[int]:
        return set(e.port for e in self.endpoints)

    @property
    def fingerprint(self) -> NodeFingerprint:
        if self.fingerprints:
            return self.fingerprints[0]

    def prepare(self, data: types.Node):
        return {
            'device_id': int(data['device_id']),
            'risk_score': float(data['risk_score']),
        }

    _ingested = 0
    def ingest(self, data: types.Node):
        if self._ingested % 10 == 0 and self._ingested:
            log.debug(f'Node: {self._ingested} {self.address}')
        self.__class__._ingested += 1

        pipe(
            data['sites'],
            map(Site.from_name),
            self.sites.extend,
        )
        self.site = Site.from_name(data['site_name'])

        pipe(
            data['endpoints'],
            map(Endpoint.from_dict),
            self.endpoints.extend,
        )
        pipe(
            data['fingerprints'],
            map(NodeFingerprint.from_dict),
            self.fingerprints.extend,
        )
        pipe(
            data['names'],
            map(NodeName.from_name),
            self.names.extend,
        )
        pipe(
            data['software'],
            map(Software.from_dict),
            self.software.extend,
        )
        pipe(
            data['tests'],
            map(NodeTest.from_dict),
            self.tests.extend,
        )

    def output_dict(self, data: dict):
        return {
            'sites': [
                s.name for s in self.sites
            ],
            'endpoints': [
                ep.to_dict() for ep in self.endpoints
            ],
            'fingerprints': [
                f.to_dict() for f in self.fingerprints
            ],
            'names': [s.name for s in self.names],
            'software': [s.to_dict() for s in self.software],
            'tests': [t.to_dict() for t in self.tests],
        }

'''
class Exploit(T.TypedDict):
    id: report.IntStr
    link: report.UrlStr
    skillLevel: str
    title: str
    type: str
'''

class Exploit(Base, NexposeData):
    typed_dict = types.Exploit
    repr_keys = (
        'id', 'title', 
    )
    ingest_keys = (
        'id', 'link', 'skillLevel', 'title', 'type',
    )

    __tablename__ = 'exploit'
    id = Column(Integer, primary_key=True)

    link = Column(String)
    skillLevel = Column(String)
    title = Column(String)
    type = Column(String)

    findings = relationship(
        'Finding',
        secondary=Table(
            'exploit_finding', Base.metadata,
            Column(
                'exploit_id', String, ForeignKey('exploit.id'), 
                primary_key=True,
            ),
            Column(
                'finding_id', String, ForeignKey('finding.id'), 
                primary_key=True,
            ),
        ),
        backref='exploits',
    )

    def prepare(self, data: types.Exploit):
        return {
            'id': int(data['id']),
        }

    _exploits = {}
    @classmethod
    def from_dict(cls, data: types.Exploit):
        if data['id'] in cls._exploits:
            return cls._exploits[data['id']]
        cls._exploits[data['id']] = super().from_dict(data)
        return cls._exploits[data['id']]
    

class Malware(Base):
    __tablename__ = 'malware'
    name = Column(String, primary_key=True)

    findings = relationship(
        'Finding',
        secondary=Table(
            'malware_finding', Base.metadata,
            Column(
                'malware_name', String, ForeignKey('malware.name'), 
                primary_key=True,
            ),
            Column(
                'finding_id', String, ForeignKey('finding.id'), 
                primary_key=True,
            ),
        ),
        backref='malware',
    )

    def __repr__(self):
        return f'Malware(name="{self.name}")'

    _names = {}
    @classmethod
    def from_name(cls, name):
        if name in cls._names:
            return cls._names[name]
        cls._names[name] = cls(name=name)
        return cls._names[name]

class Tag(Base):
    __tablename__ = 'tag'
    name = Column(String, primary_key=True)

    findings = relationship(
        'Finding',
        secondary=Table(
            'tag_finding', Base.metadata,
            Column(
                'tag_name', String, ForeignKey('tag.name'), 
                primary_key=True,
            ),
            Column(
                'finding_id', String, ForeignKey('finding.id'), 
                primary_key=True,
            ),
        ),
        backref='tags',
    )

    def __repr__(self):
        return f'Tag(name="{self.name}")'

    _names = {}
    @classmethod
    def from_name(cls, name):
        if name in cls._names:
            return cls._names[name]
        cls._names[name] = cls(name=name)
        return cls._names[name]

    # @classmethod
    # def search_query(cls, search: str):
    #     return cls.name

'''
class Finding(T.TypedDict):
    added: report.DatetimeStr
    cvssScore: str
    cvssVector: str
    description: report.HtmlStr
    exploits: T.Sequence[Exploit]
    id: str
    malware: T.Sequence[str]
    modified: report.DatetimeStr
    pciSeverity: str
    published: report.DatetimeStr
    references: T.Sequence[Reference]
    riskScore: report.FloatStr
    severity: report.IntStr
    severity_desc: str
    solution: report.HtmlStr
    tags: T.Sequence[str]
    title: str
'''

class Finding(Base, NexposeData):
    typed_dict = types.Finding
    repr_keys = (
        'id', 'title', 'severity_desc',
    )
    ingest_keys = (
        'id', 'added', 'cvssScore', 'cvssVector', 'description', 'modified',
        'pciSeverity', 'published', 'riskScore', 'severity', 'severity_desc',
        'solution', 'title',
    )

    __tablename__ = 'finding'
    id = Column(String, primary_key=True)

    added = Column(String)
    cvssScore = Column(String)
    cvssVector = Column(String)
    description = Column(String)
    modified = Column(String)
    pciSeverity = Column(String)
    published = Column(String)
    riskScore = Column(Float)
    severity = Column(Integer)
    severity_desc = Column(String)
    solution = Column(String)
    title = Column(String)
    
    nodes = relationship(
        'Node',
        secondary=Table(
            'node_finding', Base.metadata,
            Column(
                'node_id', String, ForeignKey('node.table_id'), 
                primary_key=True,
            ),
            Column(
                'finding_id', String, ForeignKey('finding.id'), 
                primary_key=True,
            ),
        ),
        backref='findings',
    )


    # exploits = relationship('Exploit', back_populates='findings')
    # malware = relationship('Malware', back_populates='findings')
    # tags = relationship('Tag', back_populates='findings')
    # exploits = relationship('Exploit')
    # malware = relationship('Malware')
    # tags = relationship('Tag')
    tests = relationship('Test', back_populates='finding')
    references = relationship('Reference', back_populates='finding')

    report_id = Column(Integer, ForeignKey('nexpose_report.table_id'))
    report = relationship('NexposeReport', back_populates='findings')

    def prepare(self, data: types.Finding):
        return {
            'riskScore': float(data['riskScore']),
            'severity': int(data['severity']),
        }

    _ingested = 0
    def ingest(self, data: types.Finding):
        if self._ingested % 100 == 0 and self._ingested:
            log.debug(f'Finding: {self._ingested} {self.id}')
        self.__class__._ingested += 1

        pipe(
            data['exploits'],
            map(Exploit.from_dict),
            self.exploits.extend,
        )
        pipe(
            data['references'],
            map(Reference.from_dict),
            self.references.extend,
        )
        pipe(
            data['tags'],
            map(Tag.from_name),
            self.tags.extend,
        )
        pipe(
            data['malware'],
            map(Malware.from_name),
            self.malware.extend,
        )

    def output_dict(self, data: dict):
        return {
            'exploits': [e.to_dict() for e in self.exploits],
            'references': [r.to_dict() for r in self.references],
            'tags': [t.name for t in self.tags],
            'malware': [m.name for m in self.malware],
        }

    @classmethod
    def node_filter(cls, addresses: T.Sequence[str]):
        return pipe(
            addresses,
            address_seq,
            Node.address.in_,
            cls.nodes.any,
        )

    @classmethod
    def finding_filter(cls, include_tags: TagList, exclude_tags: TagList,
                       include_regex: RegexList = None, 
                       exclude_regex: RegexList = None):
        regex_filter = cls.regex_filter(include_regex, exclude_regex)
        match (include_tags, exclude_tags):
            case (None, None):
                return regex_filter
            case (None, exclude):
                tag_filter = ~Finding.tags.any(Tag.name.in_(exclude_tags))
                if regex_filter is not None:
                    return tag_filter & regex_filter
                return tag_filter
            case (include, None):
                return regex_filter
            case (include, exclude):
                filter = (
                    Finding.tags.any(Tag.name.in_(include_tags)) | 
                    ~Finding.tags.any(Tag.name.in_(exclude_tags))
                )
                if regex_filter is not None:
                    return filter & regex_filter
                return filter
            
    @classmethod
    def regex_filter(cls, include_regex: RegexList, exclude_regex: RegexList):
        def join_regexes(regexes: RegexList):
            return pipe(
                regexes,
                map(re.escape),
                '|'.join,
                lambda s: f'({s})'
            )
        
        match (include_regex, exclude_regex):
            case (None | [], None | []):
                return None
            case (None | [], exclude):
                exclude = join_regexes(exclude)
                return ~(Finding.title.regexp_match(exclude) |
                         Finding.description.regexp_match(exclude))
            case (include, None | []):
                return None
            case (include, exclude):
                include, exclude = pipe(
                    (include, exclude),
                    map(join_regexes)
                )
                filter = (
                    (Finding.title.regexp_match(include) |
                     Finding.description.regexp_match(include)) |
                    ~(Finding.title.regexp_match(exclude) |
                      Finding.description.regexp_match(exclude))
                )
                return filter



'''
class Scan(T.TypedDict):
    id: report.IntStr
    name: str
    startTime: report.DatetimeStr
    endTime: report.DatetimeStr
    status: str
'''

class Scan(Base, NexposeData):
    typed_dict = types.Scan
    repr_keys = (
        'id', 'name', 'startTime', 'endTime'
    )
    ingest_keys = (
        'id', 'name', 'startTime', 'endTime', 'status'
    )

    __tablename__ = 'scan'
    id = Column(Integer, primary_key=True)

    name = Column(String)
    startTime = Column(String)
    endTime = Column(String)
    status = Column(String)

    tests = relationship('Test', back_populates='scan')

    report_id = Column(Integer, ForeignKey('nexpose_report.table_id'))
    report = relationship('NexposeReport', back_populates='scans')

    def prepare(self, data: types.Scan):
        return {
            'id': int(data['id']),
        }


'''
class NexposeReport(T.TypedDict):
    hash: str
    path: Path
    nodes: NodeList
    findings: FindingList
    scans: T.Sequence[Scan]
'''

class NexposeReport(Base, NexposeData):
    typed_dict = types.XmlReport
    repr_keys = (
        'path', 'hash',
        (lambda s: ('nodes', f'{len(s.nodes)}')),
        (lambda s: ('findings', f'{len(s.findings)}')),
        (lambda s: ('scans', f'{len(s.scans)}')),
    )
    ingest_keys = ('path', 'hash')

    __tablename__ = 'nexpose_report'
    table_id = Column(Integer, primary_key=True)

    path = Column(String)
    hash = Column(String)

    nodes = relationship('Node', back_populates='report')
    findings = relationship('Finding', back_populates='report')
    scans = relationship('Scan', back_populates='report')
    

    def ingest(self, data: types.XmlReport):
        log.info(
            'Starting ingestion:'
        )
        log.info(
            f'  ... {len(data["findings"])} findings'
        )
        pipe(
            data['findings'],
            map(Finding.from_dict),
            self.findings.extend,
        )

        log.info(
            f'  ... {len(data["nodes"])} nodes'
        )
        pipe(
            data['nodes'],
            map(Node.from_dict),
            self.nodes.extend,
        )

        log.info(
            f'  ... building finding lookup-table'
        )
        finding_lut = pipe(
            self.findings,
            groupby(deref('id')),
            valmap(first),
        )

        log.info(
            f'  ... building node-finding association table'
        )
        for dnode, snode in zip(data['nodes'], self.nodes):
            findings = []
            for test in dnode.get('tests', []):
                findings.append(test['id'])
            for endpoint in dnode.get('endpoints', []):
                for service in endpoint.get('services', []):
                    for test in service.get('tests', []):
                        findings.append(test['id'])
            pipe(
                findings,
                set,
                map(lambda i: finding_lut[i]),
                snode.findings.extend,
            )

        log.info(
            f'  ... {len(data["scans"])} scans'
        )
        pipe(
            data['scans'],
            map(Scan.from_dict),
            self.scans.extend,
        )

    def output_dict(self, data: dict):
        return {
            'findings': '',
        }

@ensure_paths
def init_db(xml_path: Path):
    Base.metadata.create_all(get_engine(xml_path))

@ensure_paths
def ingest_report(xml_path: Path) -> Session:
    db_path = get_db_path(xml_path)

    if db_path.exists():
        if newer(db_path, xml_path):
            log.info(
                f'SQLite3 database already exists and is newer than XML: {db_path.resolve()}'
            )
            return get_session(xml_path)
        else:
            log.info(
                f'SQLite3 database ({db_path.resolve()}) exists but is older'
                ' than XML. Deleting and re-ingesting.'
            )
            db_path.unlink()

    init_db(xml_path)
    report = pipe(
        parser.parse(xml_path),
        NexposeReport.from_dict,
    )

    with get_session(xml_path) as session:
        with session.begin():
            session.add(report)

    return get_session(xml_path)

