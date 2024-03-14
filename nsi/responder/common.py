import typing as T
import struct
import socket
from collections import namedtuple

import ifcfg
import dns.message
import dns.rrset

from .. import logging
from ..toolz import *
from ..types import Ip, IpList

log = logging.new_log(__name__)

IPV4 = 'ipv4'
IPV6 = 'ipv6'
A = 'A'
AAAA = 'AAAA'

to_latin = to_bytes(encoding='latin-1')
from_latin = lambda b: b if is_str(b) else b.decode('latin-1')

@memoize
def has_ipv6():
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(('::1', 0))
        return True
    except:
        return False

class Interface(T.TypedDict):
    device: str
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
    return {
        'device': iface['device'], 
        'ipv4': iface['inet'], 
        'ipv4_bytes': socket.inet_aton(iface['inet']),
        'ipv6': ipv6,
        'ipv6_bytes': socket.inet_pton(socket.AF_INET6, ipv6),
        'index': index,
        'index_bytes': struct.pack('@I', index),
    }

@memoize
def default_interface() -> Interface:
    iface = ifcfg.default_interface()
    return get_interface(iface['device'])

ClientAddress = namedtuple('ClientAddress', (
    'host', 'port', 'flowinfo', 'scope_id'
))

def client_ip(client_address: ClientAddress):
    host = ClientAddress(*client_address).host
    if '::ffff:' in host:
        return host.replace('::ffff:', '')
    return host

class Configuration(T.TypedDict):
    interface: Interface
    analyze_only: bool
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

def norm_configuration(config: Configuration):
    return merge(config, {
        'ignore_names': [n.lower() for n in config['ignore_names']],
        'ignore_ips': [i.lower() for i in config['ignore_ips']],
        'only_names': [n.lower() for n in config['only_names']],
        'only_ips': [i.lower() for i in config['only_ips']],
    })

query_pairs = [
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
query_num_to_name = dict(query_pairs)
query_name_to_num = {y: x for x, y in query_pairs}

def llmnr_query_type(data: bytes) -> str:
    message = dns.message.from_wire(data)
    if not message.question:
        return
    return query_num_to_name.get(message.question[0].rdtype)

def respond_to_ip(config: Configuration, ip: Ip):
    ip = ip.lower()

    if config['ignore_localhost'] and (ip.startswith('127.') or ip.startswith('::')):
        log.debug(f'Received localhost request ({ip}).')
        return False

    if ip in config['ignore_ips']:
        log.warning(
            f'{ip} in ignore list.'
        )
        return False

    if config['only_ips'] and ip not in config['only_ips']:
        log.warning(
            f'{ip} not in IP list to respond to.'
        )
        return False

    return True

def respond_to_name(config: Configuration, name: str):
    name = name.lower()

    if name in config['ignore_names']:
        log.warning(
            f'Name ({name}) in list of names to ignore.'
        )
        return False

    if config['only_names'] and name not in config['only_names']:
        log.warning(
            f'Name ({name}) not in list of names to respond do.'
        )
        return False

    return True

def respond_to_host(config: Configuration, ip: Ip, name: str):
    return respond_to_ip(config, ip) and respond_to_name(config, name)

is_netbios_byte = lambda v: v in range(ord('a'), ord('q'))
def is_netbios_name(name: bytes):
    name = to_latin(name)
    return len(name) == 32 and pipe(
        name[1:-1].lower(), 
        map(is_netbios_byte),
        all,
    )

def encode_netbios_name(name: str|bytes) -> bytes:
    """Return the NetBIOS first-level encoded name."""
    name = to_latin(name)
    l = []
    for c in struct.pack('16s', name):
        l.append((c >> 4) + 0x41)
        l.append((c & 0xf) + 0x41)
    return bytes(l)

def decode_netbios_name(name: bytes) -> str:
    """Return the NetBIOS first-level decoded nbname."""
    name = to_latin(name)
    return bytes(
        [((name[i] - 0x41) << 4) |
         ((name[i+1] - 0x41) & 0xf) for i in range(0, 32, 2)]
    ).decode('latin-1').replace('\x00', '').replace('\x1b', '').strip()

