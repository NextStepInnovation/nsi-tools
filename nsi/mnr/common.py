import typing as T
import struct
import socket
from pathlib import Path
from datetime import datetime
from collections import namedtuple
from dataclasses import dataclass, asdict, fields

import ifcfg
import dateutil.tz
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import (
    DNS, DNSQR, DNSRR, DNSRRSRV, DNSRRNSEC
)
from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest, NBNSQueryResponse
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
import dpkt

from .. import logging
from ..toolz import (
    pipe, vmap, map, filter, memoize, curry, to_bytes, is_str, merge,
    ensure_paths, dissoc, valfilter, to_str, split, do, is_seq, is_dict,
    to_dt, concatv,
)
from ..types import Ip, IpList

log = logging.new_log(__name__)

class Interface(T.TypedDict):
    inet: str
    inet4: T.Sequence[str]
    ether: str
    inet6: T.Sequence[str]
    netmask: str
    netmasks: T.Sequence[str]
    broadcast: str
    broadcasts: T.Sequence[str]
    device: str
    flags: str
    mtu: str

    ipv4: str
    ipv4_bytes: bytes
    ipv6: str
    index: int
    index_bytes: bytes

@memoize
def get_interface(device: str) -> Interface:
    iface = ifcfg.interfaces()[device]
    index = socket.if_nametoindex(iface['device'])
    ipv6 = iface.get('inet6', ['::'])[0]
    return merge(iface, {
        'ipv4': iface['inet'], 
        'ipv4_bytes': socket.inet_aton(iface['inet']),
        'ipv6': ipv6,
        'ipv6_bytes': socket.inet_pton(socket.AF_INET6, ipv6),
        'index': index,
        'index_bytes': struct.pack('@I', index),
    })

@memoize
def default_interface() -> Interface:
    iface = ifcfg.default_interface()
    return get_interface(iface['device'])

class DnsConfig(T.TypedDict):
    interface: Interface
    ignore_localhost: bool
    ignore_ips: IpList
    ignore_names: T.Sequence[str]
    only_ips: IpList
    only_names: T.Sequence[str]

def new_configuration(**kw):
    return pipe(merge({
        'interface': default_interface(),
        'analyze_only': False,
        'ignore_localhost': True,
        'ignore_ips': [],
        'ignore_names': [],
        'only_ips': [],
        'only_names': [],
    }, kw), norm_configuration)

def norm_configuration(config: DnsConfig):
    return merge(config, {
        'ignore_names': [n.lower() for n in config['ignore_names']],
        'ignore_ips': [i.lower() for i in config['ignore_ips']],
        'only_names': [n.lower() for n in config['only_names']],
        'only_ips': [i.lower() for i in config['only_ips']],
    })

def lstrings(data: bytes, encoding: str = 'utf-8') -> T.Iterable[str]:
    while data:
        size, data = data[0], data[1:]
        datum = data[:size]
        yield decode_bytes(datum, encoding=encoding)
        data = data[size:]

def field_names(cls):
    for field in fields(cls):
        yield field.name

@dataclass
class MnrData:
    @classmethod
    def from_json(cls, record: dict):
        return pipe(
            field_names(cls),
            map(lambda f: (f, record.get(f))),
            dict,
            lambda d: cls(**d),
        )

    def to_json(self):
        return asdict(self)

@dataclass
class EtherFields(MnrData):
    src: str
    dst: str
    type: int

    @classmethod
    def from_frame(cls, frame: Ether):
        return cls(**frame.fields)

@dataclass
class IPv4Fields(MnrData):
    version: int
    ihl: int
    tos: int
    len: int
    id: int
    flags: str
    frag: int
    ttl: int
    proto: int
    chksum: int
    src: str
    dst: str

    @classmethod
    def from_frame(cls, frame: Ether):
        fields = dissoc(frame[IP].fields, 'options')
        return cls(**merge(fields, {
            'flags': fields['flags'].flagrepr(),
        }))
        
@dataclass
class IPv6Fields(MnrData):
    version: int
    tc: int
    fl: int
    plen: int
    nh: int
    hlim: int
    src: str
    dst: str

    @classmethod
    def from_frame(cls, frame: Ether):
        return cls(**frame[IPv6].fields)
    
rrtype_pairs = [
    (1, 'A'), (2, 'NS'), (3, 'MD'), (4, 'MF'), (5, 'CNAME'), (6, 'SOA'), (7, 'MB'),
    (8, 'MG'), (9, 'MR'), (10, 'NULL'), (11, 'WKS'), (12, 'PTR'), (13, 'HINFO'),
    (14, 'MINFO'), (15, 'MX'), (16, 'TXT'), (17, 'RP'), (18, 'AFSDB'), (19, 'X25'),
    (20, 'ISDN'), (21, 'RT'), (22, 'NSAP'), (23, 'NSAP-PTR'), (24, 'SIG'), (25, 'KEY'),
    (26, 'PX'), (27, 'GPOS'), (28, 'AAAA'), (29, 'LOC'), (30, 'NXT'), (31, 'EID'),
    (32, 'NIMLOC'), (33, 'SRV'), (34, 'ATMA'), (35, 'NAPTR'), (36, 'KX'), (37, 'CERT'),
    (38, 'A6'), (39, 'DNAME'), (40, 'SINK'), (41, 'OPT'), (42, 'APL'), (43, 'DS'),
    (44, 'SSHFP'), (45, 'IPSECKEY'), (46, 'RRSIG'), (47, 'NSEC'), (48, 'DNSKEY'),
    (49, 'DHCID'), (50, 'NSEC3'), (51, 'NSEC3PARAM'), (52, 'TLSA'), (55, 'HIP'),
    (56, 'NINFO'), (57, 'RKEY'), (58, 'TALINK'), (59, 'CDS'), (60, 'CDNSKEY'),
    (61, 'OPENPGPKEY'), (99, 'SPF'), (100, 'UINFO'), (101, 'UID'), (102, 'GID'),
    (103, 'UNSPEC'), (104, 'NID'), (105, 'L32'), (106, 'L64'), (107, 'LP'),
    (108, 'EUI48'), (109, 'EUI64'), (249, 'TKEY'), (250, 'TSIG'), (251, 'IXFR'),
    (252, 'AXFR'), (253, 'MAILB'), (254, 'MAILA'), (255, '*'), (256, 'URI'),
    (257, 'CAA'), (32768, 'TA'), (32769, 'DLV')
]
rrtype_to_str = dict(rrtype_pairs)

MDNS_RECORDS = (DNSQR,  DNSRR, DNSRRSRV, DNSRRNSEC)
NBNS_RECORDS = (NBNSQueryRequest, NBNSQueryResponse)
LLMNR_RECORDS = (LLMNRQuery, LLMNRResponse)

def decode_bytes(v: bytes, encoding: str = 'utf-8'):
    try:
        return v.decode(encoding)
    except UnicodeDecodeError:
        try:
            return v.decode('utf-16le')
        except UnicodeDecodeError:
            try:
                return v.decode('latin-1')
            except:
                log.error(f'{repr(v)}')
                raise
        except:
            log.error(f'{repr(v)}')
            raise
    except:
        log.error(f'{repr(v)}')
        raise

def decode_netbios_name(name: str|bytes) -> T.Tuple[str, str]:
    """Return the NetBIOS first-level decoded nbname."""
    try:
        name = to_bytes(name)
        decoded = bytes(
            [((name[i] - 0x41) << 4) |
            ((name[i+1] - 0x41) & 0xf) for i in range(0, 32, 2)]
        )
        service = nbns_suffixes[decoded[-1]]

        return f'{service} ({hex(decoded[-1])})', decoded[:-1]
    except:
        log.error(f'Problem parsing NBNS name: {name}')
        return '', ''

@dataclass
class MnrRecord(MnrData):
    name: str
    rrname: str
    target: str
    nextname: str
    qname: str
    rdata: T.Sequence[bytes] | bytes | str
    rdata_dict: T.Dict[str, str] | None
    type: int
    type_str: str
    cacheflush: int
    rclass: int
    ttl: int
    rdlen: int
    rdlen: int
    priority: int
    weight: int
    port: int
    typebitmaps: bytes
    qtype: int
    unicastresponse: int
    qclass: int
    nbns_service: str

    @classmethod
    def record_fields(cls, record: (DNSQR | DNSRR | DNSRRSRV | DNSRRNSEC | 
                                    NBNSQueryRequest | NBNSQueryResponse | 
                                    LLMNRQuery | LLMNRResponse | 
                                    dpkt.netbios.NS.Q | dpkt.netbios.NS.RR)):
        if isinstance(record, (dpkt.netbios.NS.Q, dpkt.netbios.NS.RR)):
            service, name = decode_netbios_name(record.name)
            fields = pipe(
                field_names(cls),
                filter(lambda n: hasattr(record, n)),
                map(lambda n: (n, getattr(record, n))),
                dict,
                lambda f: merge(f, {
                    'name': name,
                    'nbns_service': service,
                })
            )
        else:
            fields = record.fields
            if isinstance(record, (NBNSQueryRequest, )):
                fields = merge(fields, {
                    'qname': fields['QUESTION_NAME'],
                    'qclass': fields['QUESTION_CLASS'],
                    'qtype': 1,
                })
            for k, v in fields.items():
                if isinstance(v, bytes):
                    try:
                        fields[k] = decode_bytes(v)
                    except:
                        log.error(f'{k} {repr(v)}')
                        raise
            if 'rdata' in fields:
                if is_seq(fields['rdata']):
                    rdata_strings = pipe(
                        fields['rdata'],
                        map(lambda b: decode_bytes(b) if isinstance(b, bytes) else b),
                        list,
                    )
                    fields['rdata'] = rdata_strings
                    rdata_dict_str = pipe(
                        rdata_strings, 
                        filter(lambda s: '=' in s), 
                        tuple,
                    )
                    if rdata_dict_str:
                        fields = merge(fields, {
                            'rdata_dict': pipe(
                                rdata_dict_str,
                                map(split('=', maxsplit=1)),
                                dict,
                            ),
                        })
                else:
                    rd = fields['rdata']
                    fields['rdata'] = decode_bytes(rd) if isinstance(rd, bytes) else rd
        return fields

    @classmethod
    def from_record(cls: 'MnrRecord', 
                    record: (DNSQR | DNSRR | DNSRRSRV | DNSRRNSEC | 
                             NBNSQueryRequest | NBNSQueryResponse | 
                             LLMNRQuery | LLMNRResponse | 
                             dpkt.netbios.NS)):
        fields = cls.record_fields(record)
        type_key = lambda d: (d.get('type') or d.get('qtype'))
        def get_name(d):
            name = (d.get('rrname') or d.get('qname'))
            if name is not None:
                if isinstance(name, bytes):
                    return decode_bytes(name)
            return name
        return cls(**pipe(
            field_names(cls),
            map(lambda f: (f, fields.get(f))),
            dict,
            lambda d: merge(d, {
                'name': get_name(d),
                'type_str': rrtype_to_str[type_key(d)] if type_key(d) is not None else None,
            } if get_name(d) is not None else {}),
        ))

def get_mnr_type(frame: Ether):
    match frame[UDP].dport:
        case 137:
            if NBNSHeader in frame:
                return 'nbns'
        case 5355:
            if LLMNRQuery in frame or LLMNRResponse in frame:
                return 'llmnr'
        case 5353:
            if DNS in frame:
                return 'mdns'
    log.error(
        'Spurious non-MNR frame'
    )

nbns_suffixes = {
    0x00: "Workstation Service / Redirector (Workstation Name)",
    0x01: "Messenger Service (Workstation Name) - Usually for Send/Receive messages",
    0x03: "Messenger Service (Username)",
    0x06: "RAS Server Service",
    0x1B: "Domain Master Browser / PDC",
    0x1C: "Domain Controllers (Domain Name)",
    0x1D: "Master Browser (Domain Name)",
    0x1E: "Browser Service Election / Normal Group",
    0x20: "File Server Service (Workstation Name)",
    0x21: "RAS Client Service",
    0x22: "Microsoft Exchange Directory Service",
    0x23: "Microsoft Exchange Store Service",
    0x24: "Microsoft Exchange MTA Service",
    0x2B: "Microsoft Exchange IMC Service",
    0x2F: "Microsoft Exchange Message Submission",
    0x30: "Modem Sharing Service",
    0x31: "Modem Sharing Client",
    0x32: "Microsoft Exchange Referral",
    0x33: "Microsoft Exchange NNTP Service",
    0x43: "SMS Clients (Site Server)",
    0x4C: "DEC Pathworks TCPIP Services for Windows NT",
    0x52: "DEC Pathworks TCPIP Services for Windows NT",
    0x6A: "Microsoft Exchange",
    0xBE: "Network Monitor Agent",
    0xBF: "Network Monitor Application",
    0xA0: "NetWare Link (for MS Windows)",
    0xB8: "Remote Access Service (RAS) - Client",
    0xB9: "Remote Access Service (RAS) - Server",
    0xBA: "Remote Access Service (RAS) - Admin",
    0xBB: "Remote Access Service (RAS) - Remote",
    0xBD: "DNS Host (for MS Windows)",
    0xC0: "Internet Information Services (IIS) - Web Server",
    0xD4: "SQL Server (Database Engine)",
    0xE0: "SQL Server (Database Engine)",
    0xF0: "Remote Access Service (RAS) - Multi",
    0xFD: "Network Client (MS-DOS) for MS Windows",
    0xFE: "MS Mail Connector",
    0xFF: "MS-DOS Network Client"
}


@dataclass
class MnrFields(MnrData):
    type: str
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    t: int
    z: int
    ad: int
    cd: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    questions: T.Sequence[MnrRecord]
    answers: T.Sequence[MnrRecord]
    nameserver: T.Sequence[MnrRecord]
    additional: T.Sequence[MnrRecord]

    @classmethod
    def from_json(cls: 'MnrFields', json_fields: dict):
        return cls(**pipe(
            field_names(cls), 
            map(lambda f: (f, json_fields.get(f))),
            dict,
            lambda F: merge(F, pipe(
                ['questions', 'answers', 'nameserver', 'additional'],
                map(lambda k: (k, [
                    MnrRecord.from_json(r) for r in F.get(k, [])
                ])),
                dict,
            )),
        ))

    @classmethod
    def from_frame(cls, frame: Ether):
        if NBNSHeader in frame:
            nbns: NBNSHeader = frame[NBNSHeader]
            fields = nbns.fields
            #log.error(frame[NBNSQueryRequest])
            if NBNSQueryRequest in nbns:
                fields = merge(fields, {
                    'qd': [nbns[NBNSQueryRequest]],
                })
            if NBNSQueryResponse in nbns:
                fields = merge(fields, {
                    'an': [nbns[NBNSQueryResponse]],
                })
            if Raw in nbns:
                ns = dpkt.netbios.NS(nbns.original)
                fields = pipe(
                    concatv([
                        'qd', 'ar', 'an', 'ns',
                    ], field_names(cls)),
                    filter(lambda n: hasattr(ns, n)),
                    map(lambda n: (n, getattr(ns, n))),
                    dict,
                )
        else:
            if DNS in frame:
                fields = frame[DNS].fields
            if LLMNRQuery in frame:
                fields = frame[LLMNRQuery].fields
            if LLMNRResponse in frame:
                fields = frame[LLMNRResponse].fields

        if fields is None:
            log.error(
                'Cannot create object'
            )
            return
        try:
            return cls(**pipe(
                field_names(cls),
                map(lambda f: (f, fields.get(f))),
                dict,
                lambda d: merge(d, {
                    'type': get_mnr_type(frame),
                    'questions': [MnrRecord.from_record(r) for r in fields.get('qd', [])],
                    'answers': [MnrRecord.from_record(r) for r in fields.get('an', [])],
                    'nameserver': [MnrRecord.from_record(r) for r in fields.get('ns', [])],
                    'additional': [MnrRecord.from_record(r) for r in fields.get('ar', [])],
                }),
            ))
        except:
            log.error(frame)
            raise

def get_ip_fields(frame: Ether):
    if IP in frame:
        return IPv4Fields.from_frame(frame)
    if IPv6 in frame:
        return IPv6Fields.from_frame(frame)
    log.error(
        f'This frame is neither IPv4 nor IPv6'
   )

@dataclass
class Message(MnrData):
    ts: str
    dt: datetime
    ether: EtherFields
    ip: IPv4Fields | IPv6Fields
    mnr: MnrFields

    def to_json(self):
        return {
            'ts': self.ts,
            'ether': self.ether.to_json(),
            'ip': self.ip.to_json(),
            'mnr': self.mnr.to_json(),
        }

    @classmethod
    def from_json(cls, message: dict):
        ether = message.get('ether', {})
        ip = message.get('ip', {})
        mnr = message.get('mnr', {})
        ts = message.get('ts')
        return cls(**pipe(
            field_names(cls),
            map(lambda f: (f, message.get(f))),
            dict,
            lambda F: merge(F, {
                'ts': ts,
                'dt': to_dt(ts),
                'ether': EtherFields.from_json(ether),
                'ip': (
                    IPv4Fields.from_json(ip) if ip.get('version', 4) == 4
                    else IPv6Fields.from_json(ip)
                ),
                'mnr': MnrFields.from_json(mnr),
            }),
        ))

    @classmethod
    def from_frame(cls, frame: Ether) -> 'Message':
        dt = datetime.fromtimestamp(
            int(frame.time), dateutil.tz.tzutc(),
        )
        ts = str(dt)
        return cls(**pipe(
            {
                'ts': ts,
                'dt': dt,
                'ether': EtherFields.from_frame(frame),
                'ip': get_ip_fields(frame),
                'mnr': MnrFields.from_frame(frame),
            },
        ))

