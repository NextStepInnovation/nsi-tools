import ssl
import queue
import typing as T
from socketserver import (
    ThreadingTCPServer, ThreadingUDPServer, BaseRequestHandler,
)
from threading import Thread, Event
import struct
import socket
from copy import deepcopy
from ipaddress import ip_address
import asyncio

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



# import zmq
# from zmq.asyncio import Context

# context = Context.instance()

class DnsPacketHandler:
    # socket: zmq.Socket = None
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
        log.info(f'IP: {ip} PORT: {port}, *rest: {rest}')
        try:
            try:
                message = self.process_message(ip, port, dns.message.from_wire(data))
            except dns.exception.FormError as form_exc:
                log.exception(
                    f'Bad DNS message: {data}'
                )
            loop = asyncio.get_event_loop()
            loop.create_task(
                self.publish_message(message)
            )
        except:
            log.exception(
                f'Error handling: {data}'
            )
    
    async def publish_message(self, message):

        try:
            mdict = message.to_dict()
            await self.socket.send_string('mnr', flags=zmq.SNDMORE)
            await self.socket.send_json(mdict)
            await self.socket.send_string(mdict['type'], flags=zmq.SNDMORE)
            await self.socket.send_json(mdict)
        except:
            log.exception(
                f'Problem publishing {message}'
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

async def serve_mnr_listeners(config: DnsConfig):
    socket = context.socket(zmq.PUB)
    socket.bind('tcp://127.0.0.1:65021')

    DnsPacketHandler.socket = socket

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
            socket.close()


def test_listener():
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.connect('tcp://127.0.0.1:65021')
    socket.setsockopt_string(zmq.SUBSCRIBE, 'mnr')
    try:
        while True:
            log.info('listen')
            _chan, msg = socket.recv_string(), socket.recv_json()
            log.info(msg)
    except KeyboardInterrupt:
        pass
    return 