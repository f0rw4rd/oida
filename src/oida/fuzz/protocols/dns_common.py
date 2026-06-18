"""Common DNS constants and utilities shared across DNS fuzzers."""

from typing import Tuple


# DNS Query Types (QTYPE)
DNS_QTYPE_A = 0x0001  # IPv4 address
DNS_QTYPE_NS = 0x0002  # Nameserver
DNS_QTYPE_CNAME = 0x0005  # Canonical name
DNS_QTYPE_SOA = 0x0006  # Start of authority
DNS_QTYPE_PTR = 0x000C  # Pointer record
DNS_QTYPE_MX = 0x000F  # Mail exchange
DNS_QTYPE_TXT = 0x0010  # Text record
DNS_QTYPE_AAAA = 0x001C  # IPv6 address
DNS_QTYPE_SRV = 0x0021  # Service record
DNS_QTYPE_DNSKEY = 0x0030  # DNSSEC key
DNS_QTYPE_RRSIG = 0x002E  # DNSSEC signature
DNS_QTYPE_CAA = 0x0101  # Certificate Authority Authorization
DNS_QTYPE_AXFR = 0x00FC  # Zone transfer
DNS_QTYPE_IXFR = 0x00FB  # Incremental zone transfer
DNS_QTYPE_ANY = 0x00FF  # Any record type

# DNS Query Classes (QCLASS)
DNS_QCLASS_IN = 0x0001  # Internet
DNS_QCLASS_CH = 0x0003  # Chaos
DNS_QCLASS_HS = 0x0004  # Hesiod
DNS_QCLASS_ANY = 0x00FF  # Any class

# DNS Response Codes (RCODE)
DNS_RCODE_NOERROR = 0  # No error
DNS_RCODE_FORMERR = 1  # Format error
DNS_RCODE_SERVFAIL = 2  # Server failure
DNS_RCODE_NXDOMAIN = 3  # Name does not exist
DNS_RCODE_NOTIMP = 4  # Not implemented
DNS_RCODE_REFUSED = 5  # Query refused

# DNS Header Flags
DNS_FLAG_QR = 0x8000  # Query/Response flag
DNS_FLAG_OPCODE_QUERY = 0x0000
DNS_FLAG_OPCODE_IQUERY = 0x0800
DNS_FLAG_OPCODE_STATUS = 0x1000
DNS_FLAG_OPCODE_NOTIFY = 0x2000
DNS_FLAG_OPCODE_UPDATE = 0x2800
DNS_FLAG_AA = 0x0400  # Authoritative answer
DNS_FLAG_TC = 0x0200  # Truncation
DNS_FLAG_RD = 0x0100  # Recursion desired
DNS_FLAG_RA = 0x0080  # Recursion available
DNS_FLAG_Z = 0x0040  # Reserved
DNS_FLAG_AD = 0x0020  # Authenticated data (DNSSEC)
DNS_FLAG_CD = 0x0010  # Checking disabled (DNSSEC)

# Standard DNS ports
DNS_PORT_UDP = 53
DNS_PORT_TCP = 53


def encode_domain_name(domain: str) -> bytes:
    """Encode a domain name to DNS wire format.

    Args:
        domain: Domain name in dotted notation (e.g., "example.com")

    Returns:
        DNS wire format bytes with length-prefixed labels
    """
    result = b""
    for label in domain.split("."):
        if label:
            result += bytes([len(label)]) + label.encode("ascii")
    result += b"\x00"  # Null terminator
    return result


def decode_domain_name(data: bytes, offset: int = 0) -> Tuple[str, int]:
    """Decode a domain name from DNS wire format.

    Args:
        data: DNS packet data
        offset: Starting offset in the data

    Returns:
        Tuple of (domain_name, bytes_consumed)

    Raises:
        ValueError: If compression pointer loop is detected
    """
    labels = []
    current_offset = offset
    bytes_consumed = 0
    jumped = False
    visited_offsets = set()

    while True:
        if current_offset >= len(data):
            break

        # Detect compression pointer loops
        if current_offset in visited_offsets:
            raise ValueError(f"Compression pointer loop detected at offset {current_offset}")
        visited_offsets.add(current_offset)

        length = data[current_offset]

        # Check for pointer (compression)
        if length >= 0xC0:
            # Bounds check for pointer read
            if current_offset + 1 >= len(data):
                raise ValueError(f"Truncated compression pointer at offset {current_offset}")
            if not jumped:
                bytes_consumed = current_offset - offset + 2
            pointer = ((length & 0x3F) << 8) | data[current_offset + 1]
            current_offset = pointer
            jumped = True
            continue

        if length == 0:
            if not jumped:
                bytes_consumed = current_offset - offset + 1
            break

        current_offset += 1
        label = data[current_offset : current_offset + length].decode("ascii", errors="replace")
        labels.append(label)
        current_offset += length

    return ".".join(labels), bytes_consumed


__all__ = [
    # Query types
    "DNS_QTYPE_A",
    "DNS_QTYPE_NS",
    "DNS_QTYPE_CNAME",
    "DNS_QTYPE_SOA",
    "DNS_QTYPE_PTR",
    "DNS_QTYPE_MX",
    "DNS_QTYPE_TXT",
    "DNS_QTYPE_AAAA",
    "DNS_QTYPE_SRV",
    "DNS_QTYPE_DNSKEY",
    "DNS_QTYPE_RRSIG",
    "DNS_QTYPE_CAA",
    "DNS_QTYPE_AXFR",
    "DNS_QTYPE_IXFR",
    "DNS_QTYPE_ANY",
    # Query classes
    "DNS_QCLASS_IN",
    "DNS_QCLASS_CH",
    "DNS_QCLASS_HS",
    "DNS_QCLASS_ANY",
    # Response codes
    "DNS_RCODE_NOERROR",
    "DNS_RCODE_FORMERR",
    "DNS_RCODE_SERVFAIL",
    "DNS_RCODE_NXDOMAIN",
    "DNS_RCODE_NOTIMP",
    "DNS_RCODE_REFUSED",
    # Header flags
    "DNS_FLAG_QR",
    "DNS_FLAG_OPCODE_QUERY",
    "DNS_FLAG_OPCODE_IQUERY",
    "DNS_FLAG_OPCODE_STATUS",
    "DNS_FLAG_OPCODE_NOTIFY",
    "DNS_FLAG_OPCODE_UPDATE",
    "DNS_FLAG_AA",
    "DNS_FLAG_TC",
    "DNS_FLAG_RD",
    "DNS_FLAG_RA",
    "DNS_FLAG_Z",
    "DNS_FLAG_AD",
    "DNS_FLAG_CD",
    # Ports
    "DNS_PORT_UDP",
    "DNS_PORT_TCP",
    # Functions
    "encode_domain_name",
    "decode_domain_name",
]
