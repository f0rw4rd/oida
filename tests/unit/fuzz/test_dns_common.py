"""
Tests for DNS common utilities.

Tests cover:
- DNS constants (query types, classes, response codes, flags)
- encode_domain_name: normal domains, subdomains, edge cases
- decode_domain_name: normal decoding, compression pointers, error handling
"""

import pytest


# =============================================================================
# Test DNS Constants
# =============================================================================


class TestDNSConstants:
    """Tests for DNS constant values."""

    def test_query_types(self):
        """Standard DNS query types have correct values."""
        from src.oida.fuzz.protocols.dns_common import (
            DNS_QTYPE_A,
            DNS_QTYPE_AAAA,
            DNS_QTYPE_NS,
            DNS_QTYPE_CNAME,
            DNS_QTYPE_MX,
            DNS_QTYPE_TXT,
            DNS_QTYPE_SOA,
            DNS_QTYPE_SRV,
            DNS_QTYPE_PTR,
            DNS_QTYPE_ANY,
            DNS_QTYPE_AXFR,
        )

        assert DNS_QTYPE_A == 0x0001
        assert DNS_QTYPE_AAAA == 0x001C
        assert DNS_QTYPE_NS == 0x0002
        assert DNS_QTYPE_CNAME == 0x0005
        assert DNS_QTYPE_MX == 0x000F
        assert DNS_QTYPE_TXT == 0x0010
        assert DNS_QTYPE_SOA == 0x0006
        assert DNS_QTYPE_SRV == 0x0021
        assert DNS_QTYPE_PTR == 0x000C
        assert DNS_QTYPE_ANY == 0x00FF
        assert DNS_QTYPE_AXFR == 0x00FC

    def test_query_classes(self):
        """DNS query classes have correct values."""
        from src.oida.fuzz.protocols.dns_common import (
            DNS_QCLASS_IN,
            DNS_QCLASS_CH,
            DNS_QCLASS_HS,
            DNS_QCLASS_ANY,
        )

        assert DNS_QCLASS_IN == 0x0001
        assert DNS_QCLASS_CH == 0x0003
        assert DNS_QCLASS_HS == 0x0004
        assert DNS_QCLASS_ANY == 0x00FF

    def test_response_codes(self):
        """DNS response codes have correct values."""
        from src.oida.fuzz.protocols.dns_common import (
            DNS_RCODE_NOERROR,
            DNS_RCODE_FORMERR,
            DNS_RCODE_SERVFAIL,
            DNS_RCODE_NXDOMAIN,
            DNS_RCODE_NOTIMP,
            DNS_RCODE_REFUSED,
        )

        assert DNS_RCODE_NOERROR == 0
        assert DNS_RCODE_FORMERR == 1
        assert DNS_RCODE_SERVFAIL == 2
        assert DNS_RCODE_NXDOMAIN == 3
        assert DNS_RCODE_NOTIMP == 4
        assert DNS_RCODE_REFUSED == 5

    def test_header_flags(self):
        """DNS header flags have correct values."""
        from src.oida.fuzz.protocols.dns_common import (
            DNS_FLAG_QR,
            DNS_FLAG_RD,
            DNS_FLAG_RA,
            DNS_FLAG_AA,
            DNS_FLAG_TC,
            DNS_FLAG_AD,
            DNS_FLAG_CD,
        )

        assert DNS_FLAG_QR == 0x8000
        assert DNS_FLAG_RD == 0x0100
        assert DNS_FLAG_RA == 0x0080
        assert DNS_FLAG_AA == 0x0400
        assert DNS_FLAG_TC == 0x0200
        assert DNS_FLAG_AD == 0x0020
        assert DNS_FLAG_CD == 0x0010

    def test_port_constants(self):
        """DNS port constants are correct."""
        from src.oida.fuzz.protocols.dns_common import DNS_PORT_UDP, DNS_PORT_TCP

        assert DNS_PORT_UDP == 53
        assert DNS_PORT_TCP == 53


# =============================================================================
# Test encode_domain_name
# =============================================================================


class TestEncodeDomainName:
    """Tests for encode_domain_name function."""

    def test_simple_domain(self):
        """Encode simple domain."""
        from src.oida.fuzz.protocols.dns_common import encode_domain_name

        result = encode_domain_name("example.com")
        assert result == b"\x07example\x03com\x00"

    def test_subdomain(self):
        """Encode subdomain."""
        from src.oida.fuzz.protocols.dns_common import encode_domain_name

        result = encode_domain_name("www.example.com")
        assert result == b"\x03www\x07example\x03com\x00"

    def test_single_label(self):
        """Encode single-label domain (just TLD)."""
        from src.oida.fuzz.protocols.dns_common import encode_domain_name

        result = encode_domain_name("localhost")
        assert result == b"\x09localhost\x00"

    def test_deep_subdomain(self):
        """Encode deeply nested subdomain."""
        from src.oida.fuzz.protocols.dns_common import encode_domain_name

        result = encode_domain_name("a.b.c.d.example.com")
        # Each label should be length-prefixed
        assert result.startswith(b"\x01a\x01b\x01c\x01d")
        assert result.endswith(b"\x00")

    def test_ends_with_null(self):
        """All encoded domains end with null byte."""
        from src.oida.fuzz.protocols.dns_common import encode_domain_name

        for domain in ["example.com", "test", "a.b.c"]:
            result = encode_domain_name(domain)
            assert result[-1:] == b"\x00"


# =============================================================================
# Test decode_domain_name
# =============================================================================


class TestDecodeDomainName:
    """Tests for decode_domain_name function."""

    def test_simple_decode(self):
        """Decode simple domain name."""
        from src.oida.fuzz.protocols.dns_common import decode_domain_name

        data = b"\x07example\x03com\x00"
        name, consumed = decode_domain_name(data)
        assert name == "example.com"
        assert consumed == len(data)

    def test_decode_with_offset(self):
        """Decode domain name at specific offset."""
        from src.oida.fuzz.protocols.dns_common import decode_domain_name

        # Some padding + the domain
        data = b"\x00\x00\x07example\x03com\x00"
        name, consumed = decode_domain_name(data, offset=2)
        assert name == "example.com"

    def test_decode_subdomain(self):
        """Decode subdomain."""
        from src.oida.fuzz.protocols.dns_common import decode_domain_name

        data = b"\x03www\x07example\x03com\x00"
        name, consumed = decode_domain_name(data)
        assert name == "www.example.com"

    def test_decode_compression_pointer(self):
        """Decode domain with compression pointer."""
        from src.oida.fuzz.protocols.dns_common import decode_domain_name

        # example.com at offset 0, then pointer at offset 13
        data = b"\x07example\x03com\x00\x03www\xc0\x00"
        name, consumed = decode_domain_name(data, offset=13)
        assert name == "www.example.com"

    def test_decode_compression_loop_detection(self):
        """Detect compression pointer loop."""
        from src.oida.fuzz.protocols.dns_common import decode_domain_name

        # Self-referencing pointer at offset 0
        data = b"\xc0\x00"
        with pytest.raises(ValueError, match="loop"):
            decode_domain_name(data)

    def test_decode_empty_data(self):
        """Decode with empty data returns empty string."""
        from src.oida.fuzz.protocols.dns_common import decode_domain_name

        name, consumed = decode_domain_name(b"")
        assert name == ""

    def test_decode_truncated_pointer(self):
        """Truncated compression pointer raises ValueError."""
        from src.oida.fuzz.protocols.dns_common import decode_domain_name

        # Pointer marker (0xC0) but no second byte
        data = b"\xc0"
        with pytest.raises(ValueError, match="Truncated"):
            decode_domain_name(data)

    def test_round_trip(self):
        """Encode then decode produces original domain."""
        from src.oida.fuzz.protocols.dns_common import encode_domain_name, decode_domain_name

        for domain in ["example.com", "www.example.com", "a.b.c.test.org"]:
            encoded = encode_domain_name(domain)
            decoded, _ = decode_domain_name(encoded)
            assert decoded == domain
