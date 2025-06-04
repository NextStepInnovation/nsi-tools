import socket
import struct

from .. import logging
from . import common
from .common import (
    DnsConfig, has_ipv6, MNR,
)

log = logging.new_log(__name__)

SOCK = {
    'proto': {
        'ipv4': socket.IPPROTO_IP,
        'ipv6': socket.IPPROTO_IPV6,
    },
    'family': {
        'ipv4': socket.AF_INET,
        'ipv6': socket.AF_INET6,
    },
    'ttl': {
        'ipv4': socket.IP_MULTICAST_TTL,
        'ipv6': socket.IPV6_MULTICAST_HOPS,
    },
    'bind': {
        'ipv4': socket.IP_ADD_MEMBERSHIP,
        'ipv6': socket.IPV6_JOIN_GROUP,
    },
}

def get_mnr_socket(config: DnsConfig, ip_version: str = None) -> socket.socket:
    if ip_version is None:
        ip_version = 'ipv6' if has_ipv6() else 'ipv4'

    sock = socket.socket(
        SOCK['family'][ip_version], socket.SOCK_DGRAM, socket.IPPROTO_UDP
    )

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Allow multiple sockets to bind to the same port
    if hasattr(socket, 'SO_REUSEPORT'):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    return sock

def get_mnr_bind_socket(config: DnsConfig, mnr_type: str) -> socket.socket:
    iface = config['interface']

    sock = get_mnr_socket(config)

    settings = MNR[mnr_type]

    ipv4, ipv6, port = settings['ipv4'], settings['ipv6'], settings['port']
    log.info(
        f'Setting up {mnr_type} socket on ipv4: {ipv4} ipv6: {ipv6} port: {port}'
        f' family {repr(sock.family)}'
    )
    if ipv4 or ipv6:
        if ipv4:
            sock.setsockopt(
                SOCK['proto']['ipv4'], SOCK['ttl']['ipv4'], 255
            )
            ipv4_mreq = struct.pack(
                '4sl', socket.inet_aton(ipv4), socket.INADDR_ANY
            )
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, ipv4_mreq,
            )

        if ipv6 and has_ipv6():
            sock.setsockopt(
                SOCK['proto']['ipv6'], SOCK['ttl']['ipv6'], 255
            )
            ipv6_mreq = struct.pack(
                '16sI', socket.inet_pton(socket.AF_INET6, ipv6), iface['index']
            )
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, ipv6_mreq
            )

        sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 
            bytes(iface['device']+'\0', 'utf-8')
        )

        if has_ipv6():
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False
            )

    sock.bind(('', port))
    return sock