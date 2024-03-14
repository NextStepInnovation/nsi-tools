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
from . import netbios

log = logging.new_log(__name__)

class DNSQuestion(T.TypedDict):
    name: str
    name_bytes: bytes
    type: str | None
    type_int: int

class DNSAnswer(T.TypedDict):
    name: str
    name_bytes: bytes
    type: str | None
    type_int: int

class DNSMessage:
    tid: int
    data: bytes
    question: T.Sequence[DNSQuestion] = ()
    answer: T.Sequence[DNSAnswer] = ()
    def __init__(self, req_data: bytes):
        self.data = req_data
        self.parse_data()
    def parse_data(self):
        self._message = dns.message.from_wire(self.data)
        self.tid = self._message.id
        self.question = [{
            'name': q.name.to_text()[:-1],
            'name_bytes': q.name.to_wire(),
            'type_int': int(q.rdtype),
            'type': q.rdtype.to_text(q.rdtype),
        } for q in self._message.question]
        self.answer = [{
            'name': q.name.to_text()[:-1],
            'name_bytes': q.name.to_wire(),
            'type_int': int(q.rdtype),
            'type': q.rdtype.to_text(q.rdtype),
        } for q in self._message.answer]
        
    def to_text(self):
        return self._message.to_text()


