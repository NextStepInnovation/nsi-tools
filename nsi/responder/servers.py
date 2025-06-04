import ssl
import typing as T
from socketserver import (
    ThreadingTCPServer, ThreadingUDPServer, BaseRequestHandler,
)
from threading import Thread, Event
import struct
import socket
from copy import deepcopy
from ipaddress import ip_address

import ifcfg
import dns.message
import dns.exception

from .. import logging
from ..toolz import (
    dict_md5, pipe, splitlines, map, pipe, vmap, map, curry,
)
from .common import (
    DnsConfig, new_configuration
)
from . import packets, sockets, netbios

log = logging.new_log(__name__)

'''

ThreadingUDP
--> mDNS/LLMNR/NBTNS handlers
    --> send to thread-safe queue

Publish server
--> pulls from queue
--> publishes to channels

Clients
--> sub to channels
--> do something with queries

'''


import asyncio

class DnsPacketHandler:
    def __init__(self, *a, **kw):
        "log.info('DnsPacketHandler')"
    def connection_made(self, transport):
        self.transport = transport
        log.info(transport._sock)
    def datagram_received(self, data, addr):
        ip, port, *rest = addr
        log.info(f'IP: {ip} PORT: {port}')
        try:
            try:
                message = dns.message.from_wire(data)
            except dns.exception.FormError as form_exc:
                log.error(
                    f'Bad DNS message: {data}'
                )
                return
            
            if addr == '192.168.68.60':
                pipe(message.to_text(), splitlines, map(log.info), tuple)

        except:
            log.exception(
                f'Error handling: {data}'
            )
    def connection_lost(self, exc):
        """
        Called when the connection is lost or closed.
        'exc' is an exception object or None if the connection was closed cleanly.
        """
        server_addr = self.transport.get_extra_info('sockname')
        log.info(f"UDP Server on {server_addr}: Connection lost: {exc}")

class NbnsPacketHandler(DnsPacketHandler):
    def datagram_received(self, data, addr):
        ip, port, *rest = addr
        log.info(f'IP: {ip}')
        try:
            try:
                message = netbios.parse_nbns(data)
            except Exception as form_exc:
                log.error(
                    f'Bad DNS message: {data}'
                )
                return
            
            pipe(message.to_text(), splitlines, map(log.info), tuple)

        except:
            log.exception(
                f'Error handling: {data}'
            )


async def multicast_server(mnr_type: str, handler, config: DnsConfig):
    iface = config['interface']

    log.info(
        f'Binding {mnr_type} server to {iface["ipv4"]}'
    )

    sock = sockets.get_mnr_bind_socket(config, mnr_type )
    loop = asyncio.get_event_loop()
    t, p = await loop.create_datagram_endpoint(
        handler, sock=sock,
    )
    return t, p

async def serve_async(config: DnsConfig):
    tasks = pipe(
        [
            (multicast_server, ['mdns', DnsPacketHandler]),
            (multicast_server, ['llmnr', DnsPacketHandler]),
            (multicast_server, ['nbns', NbnsPacketHandler]),
        ],
        vmap(lambda f, args: f(*(args + [config]))),
        tuple,
    )
    results = await asyncio.gather(*tasks)

    loop = asyncio.get_running_loop()

    try:
        while True:
            await asyncio.sleep(30)
    finally:
        for transport, _proto in results:
            log.info(
                f'Closing transport {transport.get_extra_info("sockname")}'
            )
            transport.close()
