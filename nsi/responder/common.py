import typing as T
import struct
import socket
from collections import namedtuple

import dns.rdatatype
import ifcfg
import dns.message

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
    try:
        if not socket.has_ipv6:
            return False
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(('::1', 0))
        return True
    except:
        return False

MNR = {
    'mdns': {
        'ipv4': '224.0.0.251', # Standard mDNS multicast address for IPv4
        'ipv6': 'ff02::fb',    # Standard mDNS multicast address for IPv6
        'port': 5353,          # Standard mDNS port
        'query_ttl': 255,
        'response_ttl': 30,
    },
    'llmnr': {
        'ipv4': '224.0.0.252', # Standard mDNS multicast address for IPv4
        'ipv6': 'ff02::1:3',   # Standard mDNS multicast address for IPv6
        'port': 5355,          # Standard mDNS port
        'query_ttl': 1,
        'response_ttl': 30,
    },
    'nbns': {
        'ipv4': None, # NBT-NS is broadcast
        'ipv6': None, # NBT-NS is broadcast
        'port': 137,  # standard NBT-NS port
        'query_ttl': 1,
        'response_ttl': 165,
    },
}

RDATATYPE = {
    'ipv4': dns.rdatatype.A,
    'ipv6': dns.rdatatype.AAAA,
}

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

ClientAddress = namedtuple('ClientAddress', (
    'host', 'port', 'flowinfo', 'scope_id'
))

def client_ip(client_address: ClientAddress):
    host = ClientAddress(*client_address).host
    if '::ffff:' in host:
        return host.replace('::ffff:', '')
    return host

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

def respond_to_ip(config: DnsConfig, ip: Ip):
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

def respond_to_name(config: DnsConfig, name: str):
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

def respond_to_host(config: DnsConfig, ip: Ip, name: str):
    return respond_to_ip(config, ip) and respond_to_name(config, name)

