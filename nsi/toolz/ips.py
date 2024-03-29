import re
import math
import socket
import contextlib
from pathlib import Path
from typing import Union
import typing as T
from ipaddress import (
    ip_address, ip_interface, ip_network, IPv4Address, IPv6Address,
    IPv4Network, IPv6Network,
)
IpNetwork = IPv4Network | IPv6Network

import ifcfg

from .common import (
    pipe, partial, compose, curry, mapcat,
    new_log, sort_by, strip, to_str, map, filter,
)
from .text_processing import strip_comments

__all__ = [
    # ips
    'current_ip', 'current_ipv4', 'current_ipv6', 'free_port', 'get_ips_from_content',
    'get_ips_from_file', 'get_ips_from_lines', 'get_ips_from_str', 
    'get_networks_from_content', 'get_networks_from_file',
    'get_networks_from_lines', 'get_slash', 'get_slash_from_mask', 'in_ip_range', 
    'ip_only_re', 'ip_re', 'ip_relaxed_re', 'ip_to_seq', 'ip_tuple', 
    'is_comma_sep_ip', 'is_interface', 'to_ipv4', 'to_ip_obj', 'to_network',
    'is_ip', 'is_ip_range', 'is_ipv4', 'is_network', 'get_ip_filter',
    'sort_ips', 'sortips', 'unzpad', 'zpad',
]

log = new_log(__name__)

# ----------------------------------------------------------------------
#
# IP address/networking functions
#
# ----------------------------------------------------------------------

ip_re = re.compile(
    r'(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?![\d\.]+)'
)
ip_relaxed_re = re.compile(
    r'(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
)
ip_only_re = re.compile(f'^{ip_re.pattern}$')

# def windows_ipconfig():
#     ipconfig = subprocess.getoutput('ipconfig /all')
#     config_re = re.compile(r'^Windows IP Configuration\s+Host Name . . . . . . . . . . . . : (?<host>.*)(?:\s+[\w ]*[. ]*: .*\n)*?\n', re.M)
#     #     r'^',
#     # ]
#     int_re = [
#         r"^(?P<device>\w.+):",
#         r"^   Physical Address. . . . . . . . . : (?P<ether>[ABCDEFabcdef\d-]+)",
#         r"^   IPv4 Address. . . . . . . . . . . : (?P<inet4>[^\s\(]+)",
#         r"^   IPv6 Address. . . . . . . . . . . : (?P<inet6>[ABCDEFabcdef\d\:\%]+)",
#         r"^\s+Default Gateway . . . . . . . . . : (?P<default_gateway>[^\s\(]+)",
#     ]

def to_ipv4(ip: str):
    try:
        match ip_address(ip):
            case IPv4Address() as ipv4:
                return str(ipv4)
            case IPv6Address() as ipv6:
                ipv4 = ipv6.ipv4_mapped
                if ipv4:
                    return str(ipv4)
            case unhandled:
                log.error(
                    f'Could not determine IP for {repr(ip)}'
                )
    except ValueError:
        pass
    match = ip_re.search(ip)
    if match:
        return match.group()
    return ip

IpObject = IPv4Address|IPv6Address|IPv4Network|IPv6Network
def to_ip_obj(ip: str) -> None|IpObject:
    if is_ip(ip):
        return ip_address(ip)
    elif is_interface(ip):
        return ip_interface(ip)
    elif is_network(ip):
        return ip_network(ip)
    log.error(
        f'Could not translate {repr(ip)} into an IP object'
    )

def to_network(ip_data: str) -> T.Optional[IpNetwork]:
    ip_obj = to_ip_obj(ip_data)
    if ip_obj:
        return ip_network(ip_obj)
    log.error(
        f'Cannot translate {repr(ip_data)} to an IP network'
    )

def get_ip_filter(ips: T.Sequence[str]) -> T.Callable[[str], bool]:
    '''
    Given a list of strings that could be IP addresses, IP interface
    designations, or IP subnets, return a filter function that will determine if
    a given IP string belongs to that set of things.
    '''
    networks: T.Sequence[IpNetwork] = pipe(
        ips,
        map(to_network),
        tuple,
    ) # type: ignore
    def ip_filter(ip: str, networks=networks):
        ip_net = to_network(ip)
        if ip_net:
            for network in networks:
                if network.supernet_of(ip_net): # type: ignore
                    return True
        return False
    return ip_filter

def default_interface() -> dict:
    return ifcfg.get_parser().default_interface # type: ignore

def current_ip(ip_version):
    '''Returns the IP address (for a given version) of the interface where
    the default gateway is found

    '''
    ip_key = {
        'v4': 'inet',
        'v6': 'inet6',
    }

    default = default_interface()
    ip = default.get(ip_key[ip_version])
    netmask = default.get('netmask')
    if ip and netmask:
        return ip_interface(
            f'{ip}/{get_slash_from_mask(netmask)}'
        )
    # if default[
    # return maybe_pipe(
    #     ifcfg.interfaces().items(),
    #     # vmap(lambda iface, d: 
    #     # netifaces.gateways(),
    #     get('default'),
    #     get(ip_version),
    #     second,
    #     # netifaces.ifaddresses,
    #     get(ip_version),
    #     maybe_first,
    #     lambda d: ip_interface(
    #         f'{d["addr"]}/{get_slash_from_mask(d["netmask"])}'
    #     )
    # )

current_ipv4 = partial(current_ip, 'v4')
current_ipv6 = partial(current_ip, 'v6')

def is_ipv4(ip: Union[str, int]):
    try:
        return ip_address(ip).version == 4
    except ValueError:
        return False

def is_ip(ip: Union[str, int]):
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False

def is_interface(iface):
    try:
        ip_interface(iface)
        return True
    except ValueError:
        return False

def is_network(inet):
    try:
        ip_network(inet)
        return True
    except ValueError:
        return False

def get_slash(inet: str | IpNetwork):
    return 32 - int(math.log2(ip_network(inet).num_addresses))

def get_slash_from_mask(mask: str):
    addr = ip_interface(mask).ip
    max_slash = 32 if addr.version == 4 else 128
    max_int = 2**32 if addr.version == 4 else 2**128
    return max_slash - int(math.log2(max_int - int(addr)))

def is_comma_sep_ip(cs_ip):
    return ',' in cs_ip and all(is_ip(v) for v in cs_ip.split(','))

def is_ip_range(ip_range):
    if '-' in ip_range:
        parts = ip_range.split('-')
        if len(parts) == 2:
            base, last = parts
            if is_ipv4(base) and last.isdigit() and (0 <= int(last) <= 255):
                return True
    return False

@curry
def ip_to_seq(ip, expand_network: bool=True) -> T.Sequence[str]:
    '''Convert IP expression to a sequence of IPs

    Args:
    
    - expand_network (bool): expand network/interface expressions to individual
      IPs
    '''
    if is_ip(ip):
        return [ip]
    elif is_network(ip):
        if not expand_network:
            return [str(ip)]
        return pipe(ip_network(ip).hosts(), map(str), tuple) # type: ignore
    elif is_interface(ip):
        if not expand_network:
            return [str(ip_interface(ip).network)]
        return pipe(
            ip_interface(ip).network.hosts(), 
            map(str), 
            tuple,
        ) # type: ignore
    elif is_comma_sep_ip(ip):
        return ip.split(',')
    elif is_ip_range(ip):
        base, last = ip.split('-')
        base = ip_address(base)
        last = int(last)
        first = int(str(base).split('.')[-1])
        return [str(ip_address(int(base) + i))
                for i in range(last - first + 1)]
    else:
        log.error(f'Unknown/unparsable ip value: {repr(ip)}')
        return []

def ip_tuple(ip):
    return pipe(str(ip).split('.'), map(int), tuple)

def normalize_ip_element(ip: str):
    match strip()(strip_comments(ip)):
        case interface if is_interface(ip):
            return ip_interface(interface).network.network_address
        case address if is_ip(ip):
            return ip_address(ip)
        case unknown:
            raise TypeError(f'Cannot normalize IP element: {unknown}')
        

def sortips(ips):
    return sort_by(normalize_ip_element, ips)

sort_ips = sortips

def get_ips_from_file(path):
    return get_ips_from_content(Path(path).read_text())

def get_ips_from_content(content):
    return get_ips_from_lines(content.splitlines())
get_ips_from_str = get_ips_from_content

def get_ips_from_lines(lines):
    return pipe(
        lines,
        map(to_str),
        strip_comments,
        filter(strip()),
        mapcat(ip_re.findall),
        # filter(is_ip),
        # mapcat(ip_to_seq),
        tuple,
    )

def get_networks_from_file(path):
    return get_networks_from_content(Path(path).expanduser().read_text())

def get_networks_from_content(content):
    return get_networks_from_lines(content.splitlines())

def get_networks_from_lines(lines):
    return pipe(
        lines,
        map(to_str),
        strip_comments,
        filter(strip()),
        filter(is_network),
        tuple,
    )

@curry
def in_ip_range(ip0, ip1, ip):
    start = int(ip_address(ip0))
    stop = int(ip_address(ip1))
    return int(ip_address(ip)) in range(start, stop + 1)

def zpad(ip):
    '''Zero-pad an IP address

    Examples:
    
    >>> zpad('1.2.3.4')
    '001.002.003.004'

    '''
    return '.'.join(s.zfill(3) for s in str(ip).strip().split('.'))

def unzpad(ip):
    '''Remove zero-padding from an IP address

    Examples:
    
    >>> unzpad('001.002.003.004')
    '1.2.3.4'

    '''
    return pipe(ip.split('.'), map(int), map(str), '.'.join)

def free_port():
    # https://stackoverflow.com/a/45690594/11483229
    with contextlib.closing(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]

