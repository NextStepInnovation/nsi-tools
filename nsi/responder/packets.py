import typing as T
import struct
import socket
import random

import dns
import dns.message
import dns.rdatatype
import dns.rrset
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType


from .. import logging
from ..toolz import (
    pipe, map, filter, items, vfilter, first, to_str, curry
)
from .common import (
    DnsConfig, client_ip, to_latin, has_ipv6, MNR, RDATATYPE,
)

log = logging.new_log(__name__)

def build_response(query: dns.message.QueryMessage, answer: str, *answers: str, ttl: int = 255):
    '''
    For any DNS query, create a response that provides answers commensurate with
    the questions in the query
    '''
    response = dns.message.make_response(query)
    response.question.clear()
    answers = (answer,) + answers
    if len(query.question) != len(answers):
        answers = (answers[0],) * len(query.question)
    for question, answer in zip(query.question, answers):
        response.answer.append(
            dns.rrset.from_text(
                question.name, ttl, question.rdclass, question.rdtype, answer
            )
        )
    return response

@curry
def send_mnr_query(ip_version: str, mnr_type: str, sock: socket.socket, name: str) -> bool:
    """
    Sends a multicast DNS (mDNS/LLMNR) query.

    Args:
        sock (socket.socket): socket to use to send the query
        name (str): hostname to look up

    Returns:
        bool: Packet successfully sent
    """
    if mnr_type not in MNR or ip_version not in MNR[mnr_type]:
        log.error(
            f"Invalid MNR type ({mnr_type}) and/or IP version ({ip_version}) specified."
        )
        return

    mnr_group, mnr_port = MNR[mnr_type][ip_version], MNR[mnr_type]['port']

    log.debug(
        f"Attempting to send {mnr_type} {ip_version} query for:"
        f" {name} to {mnr_group}:{mnr_port}"
    )

    query = dns.message.make_query(
        name, RDATATYPE[ip_version]
    )

    success: bool = False
    try:
        sock.sendto(
            query.to_wire(), 
            (mnr_group, mnr_port,) + ((0, 0) if ip_version == 'ipv6' else ())
        )
        success = True
    except Exception as e:
        log.exception(
            f"Error sending {mnr_type} query for {ip_version}: {e}"
        )

    return success

@curry
def send_nbns_query(config: DnsConfig, sock: socket.socket, name: str) -> bool:
    """
    Sends a NetBIOS Name Service (NBNS) query.

    Args:
        sock (socket.socket): socket to use to send the query
        name (str): hostname to look up

    Returns:
        bool: Packet successfully sent

    """

    if not sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    group = config['interface']['broadcast']
    port = 137

    log.debug(
        f"Attempting to send nbns query for: {name} to {group}:{port}"
    )

    query = dns.message.make_query(
        name, RDATATYPE[ip_version]
    )

    success: bool = False
    try:
        sock.sendto(
            query.to_wire(), 
            (mnr_group, mnr_port,) + ((0, 0) if ip_version == 'ipv6' else ())
        )
        success = True
    except Exception as e:
        log.exception(
            f"Error sending {mnr_type} query for {ip_version}: {e}"
        )

    return success

