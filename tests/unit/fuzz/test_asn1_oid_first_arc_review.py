#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression test: `ASN1Builder.build_object_identifier` must not raise when
the combined first two OID arcs (40*arc1 + arc2) exceed 255.

Bug: the first two components were packed into a single raw byte
(`first_byte = 40 * components[0] + components[1]`) without checking that
the combined value fits in one octet. X.690 8.19.4 requires this combined
value to be base-128 encoded like any other arc when it overflows a single
byte. `bytes([first_byte])` raised `ValueError: bytes must be in range(0,
256)` for e.g. arc1=2, arc2=999 (combined 1079) -- a value an attacker can
reach via user-suppliable fuzzer options such as the SNMP fuzzer's
`-O oid_prefix=2.999.1`, aborting the whole campaign.

Reference vector: OID 2.999.1 -> combined = 40*2+999 = 1079 = 0x88 0x37
(base-128, continuation bit set on the first octet), then arc 1 = 0x01 ->
body bytes 88 37 01 -> TLV 06 03 88 37 01.
"""

from oida.fuzz.core.codecs.asn1 import ASN1Builder


class TestObjectIdentifierFirstArcOverflow:
    def test_large_combined_first_arcs_do_not_raise(self):
        builder = ASN1Builder()
        result = builder.build_object_identifier([2, 999, 1])
        assert result == bytes.fromhex("0603883701")

    def test_large_combined_first_arcs_string_form(self):
        builder = ASN1Builder()
        result = builder.build_object_identifier("2.999.1")
        assert result == bytes.fromhex("0603883701")

    def test_small_oid_unchanged(self):
        """Existing small-OID behavior must not regress."""
        builder = ASN1Builder()
        result = builder.build_object_identifier([1, 2, 3])
        # tag(0x06) len(0x02) 40*1+2=42(0x2a) 3
        assert result == bytes([0x06, 0x02, 0x2A, 0x03])
