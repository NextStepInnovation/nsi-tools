import typing as T
import struct
import pprint

import dns.message
import dns.exception

from .. import logging
from ..toolz import *
from .common import (
    query_num_to_name, is_netbios_name, decode_netbios_name, from_latin,
)
from . import dns

log = logging.new_log(__name__)

def get_name(accum):
    if is_netbios_name(accum):
        return decode_netbios_name(accum)
    return accum

def parse_name(data: bytes, index: int, accum: str = '', accum_bytes: bytes = b''):
    if index >= len(data):
        return index, get_name(accum), accum_bytes

    length = data[index]
    ref = struct.unpack('>H', data[index: index + 2])[0]

    if length == 0:
        return index + 1, get_name(accum[:-1]), accum_bytes + b'\x00'
    elif ref & 3<<14 == 3<<14:
        ref_index = ref ^ 3<<14
        _index, a, ab = parse_name(data, ref_index, accum, accum_bytes)
        return index + 2, a, ab
    else:
        part = data[index + 1: index + 1 + length]
        p_str, p_bytes = (
            from_latin(part) + '.',
            bytes([length]) + part
        )
        accum += p_str
        accum_bytes += p_bytes
        return parse_name(data, index + 1 + length, accum, accum_bytes)

def parse_rr(data: bytes, rd_type: int):
    match rd_type:
        case 1: # A
            a, b, c, d = data[:4]
            ip = f'{a}.{b}.{c}.{d}'
            return {
                'ip': ip,
            }
        case 2 | 5 | 16: # NS | CDATA | TXT
            _rd_index, name, name_bytes = parse_name(data, 0)
            return {
                'name': name,
                'name_bytes': name_bytes,
            }

@curry
def parse_records(n_records: int, record_index: int, data: bytes, index: int, 
                  is_question: bool = False):
    if record_index == n_records:
        return

    rd_index, name, name_bytes = parse_name(data, index)

    rd_type, rd_class = struct.unpack(
        '>HH', data[rd_index: rd_index + 4]
    )

    rr_index = rd_index + 4
    record = {
        'name': name,
        'name_bytes': name_bytes,
        'type_int': rd_type,
        'type': query_num_to_name.get(rd_type),
        '_class_int': rd_class,
    }
    if is_question:
        index = rr_index
    else:
        ttl, rdata_length = struct.unpack(
            '>IH', data[rr_index: rr_index + 6]
        )
        rr_index = rr_index + 6

        rdata = parse_rr(data[rr_index: rr_index + rdata_length], rd_type)
        
        index = rr_index + rdata_length
        record = merge(record, {
            'ttl': ttl, 'rdata': rdata,
        })

    yield merge(record, {'_index': index})
    yield from parse_records(
        n_records, record_index + 1, data, index, is_question=is_question
    )

parse_questions = parse_records(is_question = True)

class NBNSMessage(dns.DNSMessage):
    def parse_data(self):
        (self.tid, flags, n_question, 
         n_answer, n_authority, n_additional) = struct.unpack(
             '>HHHHHH', self.data[:12],
        )
        log.debug(
            f'n_question: {n_question} n_answer: {n_answer}'
            f' n_authority: {n_authority} n_additional: {n_additional}'
        )

        self.question = tuple(parse_questions(
            n_question, 0, self.data, 12,
        ))

        last_index = self.question[-1]['_index'] if n_question else 12

        self.answer = tuple(parse_records(
            n_answer, 0, self.data, last_index
        ))

        last_index = self.answer[-1]['_index'] if n_answer else last_index

        self.authority = tuple(parse_records(
            n_authority, 0, self.data, last_index
        ))

        last_index = self.authority[-1]['_index'] if n_authority else last_index

        self.additional = tuple(parse_records(
            n_additional, 0, self.data, last_index
        ))

    def to_text(self):
        return pipe(
            [
                f'tid: {self.tid}',
                'Questions:',
            ] + [
                f'name: {q["name"]}  type: {q["type"]}'
                for q in self.question
            ] + ['Answers:'] + [
                f'name: {a["name"]}  type: {a["type"]}'
                for a in self.answer
            ] + ['Authority:'] + [
                f'name: {a["name"]}  type: {a["type"]}'
                for a in self.authority
            ] + ['Additional:'] + [
                f'name: {a["name"]}  type: {a["type"]}'
                for a in self.additional
            ],
            '\n'.join
        )


