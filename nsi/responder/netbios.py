import typing as T
import struct
import pprint

import dns.message
import dns.exception
from dns.rrset import RRset

from .. import logging
from ..toolz import (
    pipe, map,
)
from .common import (
    to_latin, DnsMessage,
)

log = logging.new_log(__name__)

opcodes = {
    0: 'query',
    5: 'registration',
    6: 'release',
    7: 'WACK',
    8: 'refresh',
}

suffixes = {
    0x00: "Workstation Service / Redirector (Workstation Name)",
    0x01: "Messenger Service (Workstation Name) - Usually for Send/Receive messages",
    0x03: "Messenger Service (Username)",
    0x06: "RAS Server Service",
    0x1B: "Domain Master Browser / PDC",
    0x1C: "Domain Controllers (Domain Name)",
    0x1D: "Master Browser (Domain Name)",
    0x1E: "Browser Service Election / Normal Group",
    0x20: "File Server Service (Workstation Name)",
    0x21: "RAS Client Service",
    0x22: "Microsoft Exchange Directory Service",
    0x23: "Microsoft Exchange Store Service",
    0x24: "Microsoft Exchange MTA Service",
    0x2B: "Microsoft Exchange IMC Service",
    0x2F: "Microsoft Exchange Message Submission",
    0x30: "Modem Sharing Service",
    0x31: "Modem Sharing Client",
    0x32: "Microsoft Exchange Referral",
    0x33: "Microsoft Exchange NNTP Service",
    0x43: "SMS Clients (Site Server)",
    0x4C: "DEC Pathworks TCPIP Services for Windows NT",
    0x52: "DEC Pathworks TCPIP Services for Windows NT",
    0x6A: "Microsoft Exchange",
    0xBE: "Network Monitor Agent",
    0xBF: "Network Monitor Application",
    0xA0: "NetWare Link (for MS Windows)",
    0xB8: "Remote Access Service (RAS) - Client",
    0xB9: "Remote Access Service (RAS) - Server",
    0xBA: "Remote Access Service (RAS) - Admin",
    0xBB: "Remote Access Service (RAS) - Remote",
    0xBD: "DNS Host (for MS Windows)",
    0xC0: "Internet Information Services (IIS) - Web Server",
    0xD4: "SQL Server (Database Engine)",
    0xE0: "SQL Server (Database Engine)",
    0xF0: "Remote Access Service (RAS) - Multi",
    0xFD: "Network Client (MS-DOS) for MS Windows",
    0xFE: "MS Mail Connector",
    0xFF: "MS-DOS Network Client"
}

question_types = {
    0x20: 'nb', # NetBIOS general Name Service Resource Record
    0x21: 'nbstat', # NetBIOS NODE STATUS Resource Record
}

rr_types = {
    0x01: 'a', # IP address Resource Record 
    0x02: 'ns', # Name Server Resource Record 
    0x0A: 'null', # NULL Resource Record
    0x20: 'nb', # NetBIOS general Name Service Resource Record
    0x21: 'nbstat', # NetBIOS NODE STATUS Resource Record
}

is_netbios_byte = lambda v: v in range(ord('A'), ord('Q'))
def is_netbios_name(name: bytes):
    name = to_latin(name)
    return len(name) == 32 and pipe(
        map(is_netbios_byte),
        all,
    )

def encode_netbios_name(service: int, name: str|bytes) -> bytes:
    """Return the NetBIOS first-level encoded name."""
    name = to_latin(name.upper()) + b' '*(15 - len(name)) + bytes([service])
    l = []
    for c in struct.pack('16s', name):
        l.append((c >> 4) + 0x41)
        l.append((c & 0xf) + 0x41)
    return bytes(l)

def decode_netbios_name(name: bytes) -> str:
    """Return the NetBIOS first-level decoded nbname."""
    name = to_latin(name)
    decoded = bytes(
        [((name[i] - 0x41) << 4) |
         ((name[i+1] - 0x41) & 0xf) for i in range(0, 32, 2)]
    )
    service = suffixes[decoded[-1]]

    return f'{service} ({hex(decoded[-1])})', decoded[:-1]

class NbnsMessage(DnsMessage):
    type = 'nbns'
    def query_to_dict(self, rrset: RRset):
        service, name = decode_netbios_name(rrset.name.to_wire())
        return {
            'source': self.source,
            'type': rrset.rdtype,
            'type_name': rr_types[rrset.rdtype],
            'class': int(rrset.rdclass),
            'class_name': rrset.rdclass.name.lower(),
            'name': name,
            'name_wire': rrset.name.to_wire(),
            'service': service,
        }