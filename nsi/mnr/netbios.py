import typing as T
import struct

from ..toolz import new_log

log = new_log(__name__)

import struct
import socket

def decode_netbios_name(data, offset):
    """
    Decodes the unique NetBIOS name encoding (half-ASCII).
    """
    length = data[offset]
    if length == 0:
        return "", offset + 1
    
    log.error(f'length: {length}')
    
    # NetBIOS names are typically 32 bytes (representing 16 characters)
    encoded_name = data[offset + 1 : offset + 1 + length]
    decoded_name = ""
    
    for i in range(0, len(encoded_name), 2):
        # Each char is split into two nibbles, shifted by 0x41 ('A')
        char_code = ((encoded_name[i] - 0x41) << 4) | (encoded_name[i+1] - 0x41)
        decoded_name += chr(char_code)
        
    return decoded_name.strip(), offset + 1 + length

def parse_nbns_resource_record(data, offset):
    """
    Parses a single Resource Record (Answer, Authority, or Additional).
    """
    name, next_offset = decode_netbios_name(data, offset)
    # Type (2 bytes), Class (2 bytes), TTL (4 bytes), Data Length (2 bytes)
    rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[next_offset:next_offset+10])
    
    rdata = data[next_offset+10 : next_offset+10+rdlength]
    
    record = {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "rdlength": rdlength,
        "rdata": rdata.hex()
    }
    
    return record, next_offset + 10 + rdlength

def parse_ethernet_frame(raw_data):
    """
    The entry point: Parses Eth -> IP -> UDP -> NBNS
    """
    # 1. Parse Ethernet Header (14 bytes)
    eth_header = struct.unpack('!6s6sH', raw_data[:14])
    log.info(eth_header)
    eth_proto = socket.ntohs(eth_header[0])
    
    if eth_proto != 0x0800:  # IPv4 only for this example
        return "Not an IPv4 packet"

    # 2. Parse IP Header (Assume 20 bytes, no options)
    ip_header = raw_data[14:34]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    protocol = iph
    
    if protocol != 17:  # UDP
        return "Not a UDP packet"

    # 3. Parse UDP Header (8 bytes)
    udp_header = raw_data[34:42]
    udph = struct.unpack('!HHHH', udp_header)
    dest_port = udph
    
    if dest_port != 137: # NBNS Port
        return "Not an NBNS packet"

    # 4. Parse NBNS Header
def parse_nbns_content(raw_data):
    nbns_data = raw_data[42:]
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', nbns_data[:12])
    
    offset = 12
    nbns_packet = {
        "transaction_id": hex(transaction_id),
        "questions": [],
        "answers": [],
        "authorities": [],
        "additionals": []
    }

    log.error(f'qc: {qdcount} ac: {ancount} nc: {nscount} arc: {arcount}')
    # Parse Questions
    for i, _ in enumerate(range(qdcount)):
        log.error(f'qd: {i} of {qdcount}')
        qname, offset = decode_netbios_name(nbns_data, offset)
        log.error(f'qname: {qname} offset: {offset}')
        qtype, qclass = struct.unpack('!HH', nbns_data[offset:offset+4])
        nbns_packet["questions"].append({"name": qname, "type": qtype, "class": qclass})
        offset += 4

    log.error(f'offset: {offset}')
    # Parse Resource Records (Answers, Authorities, Additionals)
    for section, count in [("answers", ancount), ("authorities", nscount), ("additionals", arcount)]:
        for _ in range(count):
            record, offset = parse_nbns_resource_record(nbns_data, offset)
            nbns_packet[section].append(record)

    return nbns_packet







def parse_nbns_name(data, offset):
    """
    Parses a NetBIOS name, supporting both half-ASCII encoding 
    and DNS-style compression pointers.
    """
    labels = []
    jumped = False
    first_offset = offset
    curr_ptr = offset

    while True:
        length = data[curr_ptr]
        
        # Check for Pointer (0xc0)
        if (length & 0xc0) == 0xc0:
            # Pointer is 2 bytes: [11xxxxxx][xxxxxxxx]
            pointer_bytes = data[curr_ptr : curr_ptr + 2]
            pointer_val = struct.unpack('!H', pointer_bytes)[0] & 0x3fff
            
            if not jumped:
                first_offset = curr_ptr + 2
                jumped = True
            
            curr_ptr = pointer_val
            continue  # Follow the pointer

        # End of name
        if length == 0:
            curr_ptr += 1
            break
            
        # Standard NetBIOS Label (Half-ASCII)
        # NetBIOS names are typically one 32-byte label, but we handle segments
        encoded = data[curr_ptr + 1 : curr_ptr + 1 + length]
        decoded = ""
        for i in range(0, len(encoded), 2):
            char_code = ((encoded[i] - 0x41) << 4) | (encoded[i+1] - 0x41)
            decoded += chr(char_code)
        
        labels.append(decoded.strip())
        curr_ptr += 1 + length

    # If we never jumped, the next offset is where we stopped.
    # If we did jump, the next offset is 2 bytes after the first pointer encountered.
    return ".".join(labels), (first_offset if jumped else curr_ptr)

def parse_nbns_packet(data):
    """
    Parses the full NBNS payload including Questions and Resource Records.
    """
    # Header: ID(2), Flags(2), QD(2), AN(2), NS(2), AR(2)
    transaction_id, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
    
    log.error((transaction_id, flags, qd, an, ns, ar))

    ptr = 12
    packet = {
        "id": hex(transaction_id),
        "flags": hex(flags),
        "questions": [],
        "answers": [],
        "authorities": [],
        "additionals": []
    }

    # Helper to parse Resource Records (Answers/Auth/Add)
    def parse_rr(current_ptr):
        name, next_ptr = parse_nbns_name(data, current_ptr)
        rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[next_ptr : next_ptr + 10])
        rdata = data[next_ptr + 10 : next_ptr + 10 + rdlen]
        return {
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "data": rdata
        }, next_ptr + 10 + rdlen

    # 1. Questions
    for _ in range(qd):
        qname, ptr = parse_nbns_name(data, ptr)
        qtype, qclass = struct.unpack('!HH', data[ptr : ptr + 4])
        packet["questions"].append({"name": qname, "type": qtype, "class": qclass})
        ptr += 4

    # 2. Answers, Authorities, Additionals
    for section, count in [("answers", an), ("authorities", ns), ("additionals", ar)]:
        for _ in range(count):
            record, ptr = parse_rr(ptr)
            packet[section].append(record)

    return packet