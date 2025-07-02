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
    dict_md5, pipe, splitlines, map, pipe, vmap, curry, filter,
)
from .common import (
    DnsConfig, new_configuration, client_ip,
)
from .netbios import NbnsMessage
from .mdns import MdnsMessage
from .llmnr import LlmnrMessage
from . import packets, sockets

log = logging.new_log(__name__)

'''

Asyncio UDP
--> mDNS/LLMNR/NBTNS handlers
    --> send to asyncio-safe queue

Publish server
--> pulls from queue
--> publishes to channels

Clients
--> sub to channels
--> do something with queries/objects

'''


import asyncio

class DnsPacketHandler:
    queue: asyncio.Queue
    def connection_made(self, transport):
        self.transport = transport
        log.info(transport._sock)
    def process_message(self, message: dns.message.Message):
        '''
        Because we have no control over packet handler instantiation, need
        polymorphism
        '''
        raise NotImplementedError
    def datagram_received(self, data, addr):
        ip, port, *rest = addr
        log.info(f'IP: {ip} PORT: {port}')
        try:
            try:
                message = self.process_message(ip, port, dns.message.from_wire(data))
                self.queue.put(message)
            except dns.exception.FormError as form_exc:
                log.exception(
                    f'Bad DNS message: {data}'
                )
                return

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

class MdnsPacketHandler(DnsPacketHandler):
    def process_message(self, ip, port, message):
        return MdnsMessage(ip, port, message)
class LlmnrPacketHandler(DnsPacketHandler):
    def process_message(self, ip, port, message):
        return LlmnrMessage(ip, port, message)
class NbnsPacketHandler(DnsPacketHandler):
    def process_message(self, ip, port, message):
        return NbnsMessage(ip, port, message)
    
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

async def serve_mnr_listeners(queue: asyncio.Queue, config: DnsConfig):
    DnsPacketHandler.queue = queue
    tasks = pipe(
        [
            (multicast_server, ['mdns', MdnsPacketHandler]),
            (multicast_server, ['llmnr', LlmnrPacketHandler]),
            (multicast_server, ['nbns', NbnsPacketHandler]),
        ],
        vmap(lambda f, args: f(*(args + [config]))),
        tuple,
    )
    results = await asyncio.gather(*tasks)

    # loop = asyncio.get_running_loop()

    try:
        while True:
            await asyncio.sleep(30)
    finally:
        for transport, _proto in results:
            log.info(
                f'Closing transport {transport.get_extra_info("sockname")}'
            )
            transport.close()

import zmq
from zmq.asyncio import Context

context = Context.instance()

async def serve_mnr_pub(queue: asyncio.Queue, config: DnsConfig):
    pub = context.socket(zmq.PUB)
    pub.connect('tcp://127.0.0.1:65021')

    try:
        while True:
            message = queue.get()

    except:
        1