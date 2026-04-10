import typing as T
import struct
import socket
from pathlib import Path
from collections import namedtuple

import ifcfg
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import (
    DNS, DNSQR, DNSRR, DNSRRSRV, DNSRRNSEC
)
from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest, NBNSQueryResponse
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse

from .. import logging
from ..toolz import (
    pipe, vmap, map, filter, memoize, curry, to_bytes, is_str, merge,
    ensure_paths, dissoc, valfilter, to_str, split, do, is_seq, is_dict,
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
        yield datum.decode(encoding=encoding)
        data = data[size:]

class DictWithNulls(T.TypedDict):
    @classmethod
    def from_dict(cls, record: dict):
        type_key = lambda d: d.get('type') or d.get('qtype')
        
        return pipe(
            cls.__annotations__.keys(),
            map(lambda f: (f, record.get(f))),
            dict,
            cls,
        )
    
def prepare_data(data: DictWithNulls | T.Any):
    if is_seq(data):
        return pipe([
            prepare_data(v) for v in data
        ], filter(lambda v: v is not None), tuple)
    elif is_dict(data):
        return pipe({
            k: prepare_data(v) for k, v in data.items()
        }, valfilter(lambda v: v is not None))
    return data


class EtherFields(DictWithNulls):
    src: str
    dst: str
    type: int

    def from_frame(frame: Ether):
        return dict(frame.fields)

class IPv4Fields(DictWithNulls):
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
        return cls(merge(fields, {
            'flags': fields['flags'].flagrepr(),
        }))
        
class IPv6Fields(DictWithNulls):
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
        return dict(frame[IPv6].fields)
        fields = dissoc(frame[IPv6].fields, 'options')
        return cls(merge(fields, {
            'flags': fields['flags'].flagrepr(),
        }))
    
def get_ip_fields(frame: Ether):
    if IP in frame:
        return IPv4Fields.from_frame(frame)
    if IPv6 in frame:
        return IPv6Fields.from_frame(frame)
    log.error(
        f'This frame is neither IPv4 nor IPv6'
    )

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

class MulticastRecord(DictWithNulls):
    name: str
    rrname: str
    target: str
    nextname: str
    qname: str
    rdata: T.Sequence[bytes]
    rdata_dict: T.Dict[str, str]
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

    @classmethod
    def record_fields(cls, record: (DNSQR | DNSRR | DNSRRSRV | DNSRRNSEC | 
                                    NBNSQueryRequest | NBNSQueryResponse | 
                                    LLMNRQuery | LLMNRResponse)):
        fields = record.fields
        if isinstance(record, (NBNSQueryRequest, )):
            fields = merge(fields, {
                'qname': fields['QUESTION_NAME'],
                'qclass': fields['QUESTION_CLASS'],
                'qtype': 1,
            })
        if 'rdata' in fields:
            rdata_str = pipe(
                fields['rdata'],
                map(str),
                tuple,
            )
            rdata_dict_str = pipe(rdata_str, filter(lambda s: '=' in s), tuple)
            if rdata_dict_str:
                fields = merge(fields, {
                    'rdata_dict': pipe(
                        rdata_dict_str,
                        map(split('=', maxsplit=1)),
                        # tuple, do(log.error),
                        dict,
                    ),
                })
        return fields

    @classmethod
    def from_record(cls, record: (DNSQR | DNSRR | DNSRRSRV | DNSRRNSEC | 
                                  NBNSQueryRequest | NBNSQueryResponse | 
                                  LLMNRQuery | LLMNRResponse)):
        fields = cls.record_fields(record)
        type_key = lambda d: (d.get('type') or d.get('qtype'))
        name_key = lambda d: (d.get('rrname') or d.get('qname'))
        return pipe(
            cls.__annotations__.keys(),
            map(lambda f: (f, fields.get(f))),
            dict,
            lambda d: merge(d, {
                'name': name_key(d),
                'type_str': rrtype_to_str[type_key(d)] if type_key(d) is not None else None,
            } if name_key(d) is not None else {}),
            cls,
        )

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
#def nbns_rec_to_dns(request)
    
class DNSFields(T.TypedDict):
    mnr_type: str
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
    questions: T.Sequence[MulticastRecord]
    answers: T.Sequence[MulticastRecord]
    nameserver: T.Sequence[MulticastRecord]
    additional: T.Sequence[MulticastRecord]

    @classmethod
    def dns_fields(cls, frame: Ether):
        if DNS in frame:
            return frame[DNS].fields
        if LLMNRQuery in frame:
            return frame[LLMNRQuery].fields
        if LLMNRResponse in frame:
            return frame[LLMNRResponse].fields
        if NBNSHeader in frame:
            nbns = frame[NBNSHeader]
            fields = nbns.fields
            #log.error(frame[NBNSQueryRequest])
            return merge(fields, {
                'qd': [frame[NBNSQueryRequest]],
            })
        log.error(
            f'Not an MNR packet.'

        )

    @classmethod
    def from_frame(cls, frame: Ether):
        fields = cls.dns_fields(frame)
        if fields is None:
            log.error(
                'Cannot create object'
            )
            return
        return pipe(
            cls.__annotations__.keys(),
            map(lambda f: (f, fields.get(f))),
            dict,
            lambda d: merge(d, {
                'mnr_type': get_mnr_type(frame),
                'questions': [MulticastRecord.from_record(r) for r in fields.get('qd', [])],
                'answers': [MulticastRecord.from_record(r) for r in fields.get('an', [])],
                'nameserver': [MulticastRecord.from_record(r) for r in fields.get('ns', [])],
                'additional': [MulticastRecord.from_record(r) for r in fields.get('ar', [])],
            }),
            cls,
        )

class Message(T.TypedDict):
    ether: EtherFields
    ip: IPv4Fields | IPv6Fields
    dns: DNSFields

    @classmethod
    def from_frame(cls, frame: Ether):
        return pipe(
            {
                'ether': EtherFields.from_frame(frame),
                'ip': get_ip_fields(frame),
                'dns': DNSFields.from_frame(frame),
            },
            cls,
        )


def get_records(message: Message):
    pass

