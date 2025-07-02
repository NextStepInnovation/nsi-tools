import struct

from dns.rrset import RRset
from dns.rdatatype import (
    NSEC, A, AAAA, 
)
from dns.rdataclass import RdataClass


from ..toolz import pipe, merge, filter, map, curry
from .common import (
    DnsConfig, DnsMessage, encode_name, encode_ip,
)



class MdnsMessage(DnsMessage):
    type = 'mdns'
    def query_to_dict(self, rrset: RRset):
        rdclass = rrset.rdclass
        QU = bool(rdclass & (1 << 15))
        if not QU:
            rdclass -= 1 << 15
        return {
            'qu': QU,
            'qm': not QU,
            'type': rrset.rdtype,
            'type_name': rrset.rdtype.name.lower(),
            'class': int(rdclass),
            'class_name': RdataClass(rdclass).name.lower(),
            'name': rrset.name.to_text(),
        }
        
    
    def rrset_to_dict(self, rrset: RRset):
        rdclass = rrset.rdclass
        flush = bool(rdclass & (1 << 15))
        if flush:
            rdclass -= 1 << 15
    
        base = {
            'flush': flush,
            'type': rrset.rdtype,
            'type_name': rrset.rdtype.name.lower(),
            'class': int(rdclass),
            'class_name': RdataClass(rdclass).name.lower(),
            'name': rrset.name.to_text(),
        }
        extra = {}
        match rrset.rdtype:
            case 1 | 28: # A | AAAA
                pass
            case 13: # PTR
                pass            
            case 16: # TXT
                pass
            case 33: # SRV
                pass
            case 47: # NSEC
                pass

        return merge(base, extra)
    

@curry
def base_header(questions: int, answers: int, ns: int, additional: int):
    # Start with a minimal mDNS response header (ID=0, Flags=0x8400, ANCOUNT=6)
    # This is not a query, but a response with answers.
    return struct.pack(
        "!HHHHHH", 
        0,          # ID
        0x8400,     # Flags (Reponse 0x8000 | Authoritative 0x0400)
        questions,  # QCOUNT
        answers,    # ANCOUNT
        ns,         # NSCOUNT
        additional  # ADCOUNT
    )
answer_header = lambda: base_header(0, 1, 0, 0)

def a_record(name: str, ip: str):
    # --- 1. A Record ---
    # Name: mydevice.local
    
    return (
        answer_header() +
        encode_name(name) +
        struct.pack(
            "!HHIH", 
            1,       # Type: A (1)
            0x8001,  # Class: IN (1) | Cache bit (0x8000 for mDNS)
            120,     # TTL: 120 (seconds)
            4        # RDLENGTH: 4 (bytes of IP address octets)
        ) +
        encode_ip(ip)
    ) 

def ptr_record(ptr: str, name: str):
    # --- 2. PTR Record ---
    # Name: _http._tcp.local -> mydevice.local

    ptr = encode_name(ptr)
    name = encode_name(name)
    return (
        answer_header() +
        ptr + 
        struct.pack(
            "!HHIH", 
            12,       # Type: PTR (12)
            0x8001,   # Class: IN (1) | Cache bit -> 0x8001
            120,      # TTL: 120
            len(name) # RDLENGTH: (will be compressed name length 0xC000 | offset)
        ) + 
        name
    )

    
def srv_record():
    # Store the offset for '_http._tcp.local' for compression
    # This offset is calculated relative to the start of the UDP payload (byte 0)
    # It's the position where '_http._tcp.local' label starts in the packet.
    http_tcp_local_offset = len(test_mdns_packet_with_compression) - (len(b"\x05_http\x04_tcp\x05local\x00") + 8) # 8 bytes for PTR data field

    # --- 3. SRV Record ---
    # Name: My Web Service._http._tcp.local (compressed)
    # Type: SRV (33)
    # Class: IN (1) | Caching bit -> 0x8001
    # TTL: 120
    # RDLENGTH: (calculated later: 6 bytes for priority/weight/port + compressed name length)
    # RDATA: Priority 0, Weight 0, Port 80, Target mydevice.local (compressed)
    # Name (My Web Service._http._tcp.local): 13My\x20Web\x20Service (compressed from _http._tcp.local)
    test_mdns_packet_with_compression.extend(b"\x0DMy Web Service") # Label "My Web Service"
    # Pointer to _http._tcp.local
    test_mdns_packet_with_compression.extend(struct.pack("!H", 0xC000 | http_tcp_local_offset))
    # Calculate RDLENGTH for SRV: 6 bytes fixed fields + 2 bytes for compressed name
    srv_rdlength = 6 + 2
    test_mdns_packet_with_compression.extend(struct.pack("!HHIH", 33, 0x8001, 120, srv_rdlength))
    test_mdns_packet_with_compression.extend(struct.pack("!HHH", 0, 0, 80)) # Priority, Weight, Port
    test_mdns_packet_with_compression.extend(struct.pack("!H", 0xC000 | mydevice_local_offset)) # Compressed pointer to mydevice.local

    # --- 4. TXT Record ---
    # Name: My Web Service._http._tcp.local (compressed from SRV name)
    # Type: TXT (16)
    # Class: IN (1) | Caching bit -> 0x8001
    # TTL: 120
    # RDLENGTH: (calculated later based on text strings)
    # RDATA: "path=/index.html" (16 bytes), "version=1.0" (11 bytes)
    # The name for the TXT record is the same as the SRV instance name.
    # We need to find the offset of "My Web Service._http._tcp.local"
    # The SRV name started with b"\x0DMy Web Service" followed by the pointer to _http._tcp.local.
    # The offset of the SRV name is the current length of the bytearray minus the size of the SRV name itself (13 bytes + 2 bytes for pointer)
    # PLUS the 8 bytes for the RR data (type, class, ttl, rdlength) that precedes the RDATA section
    srv_name_start_offset = len(test_mdns_packet_with_compression) - (len(b"\x0DMy Web Service") + 2 + 8)
    test_mdns_packet_with_compression.extend(struct.pack("!H", 0xC000 | srv_name_start_offset))
    txt_data = b"\x10path=/index.html\x0Bversion=1.0"
    txt_rdlength = len(txt_data)
    test_mdns_packet_with_compression.extend(struct.pack("!HHIH", 16, 0x8001, 120, txt_rdlength))
    test_mdns_packet_with_compression.extend(txt_data)

    # --- 5. HINFO Record ---
    # Name: mydevice.local (compressed)
    # Type: HINFO (13)
    # Class: IN (1) | Caching bit -> 0x8001
    # TTL: 120
    # RDLENGTH: (calculated based on cpu/os strings)
    # RDATA: "ARM", "Linux"
    test_mdns_packet_with_compression.extend(struct.pack("!H", 0xC000 | mydevice_local_offset)) # Compressed pointer
    hinfo_cpu = b"\x03ARM" # Length 3
    hinfo_os = b"\x05Linux" # Length 5
    hinfo_rdlength = len(hinfo_cpu) + len(hinfo_os)
    test_mdns_packet_with_compression.extend(struct.pack("!HHIH", 13, 0x8001, 120, hinfo_rdlength))
    test_mdns_packet_with_compression.extend(hinfo_cpu)
    test_mdns_packet_with_compression.extend(hinfo_os)

    # --- 6. NSEC Record ---
    # Name: mydevice.local (compressed)
    # Type: NSEC (47)
    # Class: IN (1) | Caching bit -> 0x8001
    # TTL: 120
    # RDLENGTH: (calculated based on next domain + type bit map)
    # RDATA: Next Domain Name: _http._tcp.local (compressed), Type Bit Map: A(1), HINFO(13), TXT(16), SRV(33)
    test_mdns_packet_with_compression.extend(struct.pack("!H", 0xC000 | mydevice_local_offset)) # Compressed pointer
    # Next Domain Name: _http._tcp.local (compressed)
    nsec_next_domain_bytes = struct.pack("!H", 0xC000 | http_tcp_local_offset)

    # Type Bit Map for A(1), HINFO(13), TXT(16), SRV(33)
    # Window Block 0 (types 0-255):
    #   A (1): bit 1 set
    #   HINFO (13): bit 13 set
    #   TXT (16): bit 16 set
    # Need bytes that represent these bits.
    # Max bit is 33, so we need up to (33 // 8) + 1 = 5 bytes for block 0.
    # Block Length: 5 bytes
    # Bits:
    # Type 1: 0000 0001 (bit 0 is MSB of first byte) -> byte 0: 0100 0000 (0x40)
    # Type 13: 0000 1101 -> byte 1: 0000 0000; byte 2: 0001 0000 (0x10)
    # Type 16: 0001 0000 -> byte 2: 0000 1000 (0x08)
    # Type 33: 0010 0001 -> byte 4: 0000 0010 (0x02)
    # Combining:
    # byte 0 (for types 0-7): 0100 0000 (bit 1) -> 0x40
    # byte 1 (for types 8-15): 0000 0000 -> 0x00
    # byte 2 (for types 16-23): 0001 1000 (bit 13 (0x10) | bit 16 (0x08)) -> 0x18
    # byte 3 (for types 24-31): 0000 0000 -> 0x00
    # byte 4 (for types 32-39): 0000 0010 (bit 33) -> 0x02
    # So, the bitmap bytes are: b'\x40\x00\x18\x00\x02'

    nsec_type_bitmap_bytes = b'\x00' # Window Block Number 0
    nsec_type_bitmap_bytes += struct.pack("!B", 5) # Block Length 5
    nsec_type_bitmap_bytes += b'\x40\x00\x18\x00\x02' # The actual bitmask

    nsec_rdlength = len(nsec_next_domain_bytes) + len(nsec_type_bitmap_bytes)
    test_mdns_packet_with_compression.extend(struct.pack("!HHIH", 47, 0x8001, 120, nsec_rdlength))
    test_mdns_packet_with_compression.extend(nsec_next_domain_bytes)
    test_mdns_packet_with_compression.extend(nsec_type_bitmap_bytes)
