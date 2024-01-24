import typing as T
import struct
import socket
from dataclasses import (
    dataclass, fields, astuple,
)
from collections import OrderedDict

import ifcfg

from .. import logging
from ..toolz import *
from .common import (
    Configuration, client_ip, to_latin,
)

log = logging.new_log(__name__)

class Fielded(type):
    def __new__(cls, name, bases, dct):
        instance = super().__new__(cls, name, bases, dct)
        instance._fields = pipe(
            dct,
            items,
            vfilter(lambda k, v: not (k.startswith('_') or callable(v))),
            map(first),
            tuple,
        )
        for k in instance._fields:
            setattr(instance, k, to_latin(dct[k]))
        return instance

class Packet(metaclass=Fielded):
    _fields = ()
    def __init__(self, config: Configuration, req_data: bytes):
        self.config = config
        self.req_data = req_data
    
    def __repr__(self):
        return pipe(
            self._fields,
            map(lambda k: f'{k}={repr(getattr(self, k))}'),
            map(to_str),
            ', '.join,
            lambda s: f'{self.__class__.__name__}({s})'
        )
    
    def compute(self):
        pass
        
    def to_bytes(self):
        self.compute()
        return pipe(
            self._fields,
            map(lambda k: getattr(self, k)),
            map(lambda v: v(self, self.config, self.req_data) if callable(v) else v),
            map(to_latin),
            b''.join,
        )

class LLMNRv4Answer(Packet):
    tid = '\x00\x00'
    flags = '\x80\x00'
    question = "\x00\x01"
    answer_count = "\x00\x01"
    authority_count = "\x00\x00"
    additional_count = "\x00\x00"
    question_name_len = "\x09"
    question_name = ''
    question_name_null = "\x00"
    type = "\x00\x01"
    class_ = "\x00\x01"
    answer_name_len = "\x09"
    answer_name = ""
    answer_name_null = "\x00"
    type1 = "\x00\x01"
    class1 = "\x00\x01"
    ttl = "\x00\x00\x00\x1e"
    ip_len = "\x00\x04"
    ip = "\x00\x00\x00\x00"

    def compute(self):
        self.tid = self.req_data[:2]
        name = llmnr_name(self.req_data)
        self.question_name = name
        self.answer_name = name
        self.ip = self.config['interface']["ipv4_bytes"]
        self.ip_len = struct.pack('>h', len(self.ip))
        self.answer_name_len = struct.pack('>B', len(self.answer_name))
        self.question_name_len = struct.pack('>B', len(self.question_name))

def llmrn_query(req_data: bytes):
    pass

class LLMNRv6Answer(Packet):
    tid = '\x00\x00'
    flags = "\x80\x00"
    question_count = "\x00\x01"
    answer_count = "\x00\x01"
    authority_count = "\x00\x00"
    additional_count = "\x00\x00"
    question_name_len = "\x09"
    question_name = ""
    question_name_null = "\x00"
    type = "\x00\x1c"
    class_ = "\x00\x01"
    answer_name_len = "\x09"
    answer_name = ""
    answer_name_null = "\x00"
    type1 = "\x00\x1c"
    class1 = "\x00\x01"
    ttl = "\x00\x00\x00\x1e" # 30 seconds
    ip_len = "\x00\x08"
    ip = "\x00\x00\x00\x00\x00\x00\x00\x00"

    def compute(self):
        self.tid = self.req_data[:2]
        name = llmnr_name(self.req_data)
        self.question_name = name
        self.answer_name = name
        self.ip = self.config['interface']["ipv6_bytes"]
        self.ip_len = struct.pack('>h', len(self.ip))
        self.answer_name_len = struct.pack('>B', len(self.answer_name))
        self.question_name_len = struct.pack('>B', len(self.question_name))

class MDNSv4Answer(Packet):
    tid = "\x00\x00"
    flags = "\x84\x00"
    question_count = "\x00\x00"
    answer_count = "\x00\x01"
    authority_count = "\x00\x00"
    additional_count = "\x00\x00"
    answer_name = ""
    answer_name_null = "\x00"
    type = "\x00\x01"
    class_ = "\x00\x01"
    ttl = "\x00\x00\x00\x78"
    ip_len = "\x00\x04"
    ip = "\x00\x00\x00\x00"

    def compute(self):
        self.answer_name = mdns_answer_name(self.req_data)
        self.ip = self.config['interface']['ipv4_bytes']
        self.ip_len = struct.pack('>h', len(self.ip))

    
class MDNSv6Answer(Packet):
    tid = "\x00\x00"
    flags = "\x84\x00"
    question_count = "\x00\x00"
    answer_count = "\x00\x01"
    authority_count = "\x00\x00"
    additional_count = "\x00\x00"
    answer_name = ""
    answer_name_null = "\x00"
    type = "\x00\x1c"
    class_ = "\x00\x01"
    ttl = "\x00\x00\x00\x78" # 2 minutes
    ip_len = "\x00\x08"
    ip = "\x00\x00\x00\x00\x00\x00\x00\x00"

    def compute(self):
        self.answer_name = mdns_answer_name(self.req_data)
        self.ip = self.config['interface']['ipv6_bytes']
        self.ip_len = struct.pack('>h', len(self.ip))


