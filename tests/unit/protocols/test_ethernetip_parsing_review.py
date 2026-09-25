"""Crash-resistance review of the EtherNet/IP response parsers.

This suite drives the ACTUAL parse functions that consume bytes from an
untrusted EtherNet/IP peer with malformed, truncated, and hostile inputs.

Focus areas (highest response-parsing density in the codebase):
- ListIdentity / List Services / List Identity CPF parsing
- CIP reply parsing (SendRRData)
- Identity Object Get_Attributes_All parsing
- item-count / item-length fields that are read from the response and then
  used to loop or slice
- EPATH parsing (index-advance / infinite-loop risk)

Outcome of the review: every raw-bytes parse path in
``src/oida/protocols/ethernetip/`` is already hardened (preceding ``len()``
guards, a ``try/except``, or is provably slice-safe). No reproducing crash
was found, so no production code was changed. These tests pin that graceful
degradation so a future edit that drops a guard fails loudly here.
"""

from __future__ import annotations

import struct
import time

import pytest

from oida.protocols.ethernetip import cip_definitions
from oida.protocols.ethernetip.parsers import parse_list_identity
from oida.protocols.ethernetip.mixins.enip_commands import EnipCommandsMixin
from oida.protocols.ethernetip.mixins.cip_objects import CipObjectsMixin


class _DummyLogger:
    """No-op logger with the full ics_logger surface used by the mixins."""

    def __getattr__(self, _name):  # display/success/fail/warning/debug/...
        return lambda *a, **k: None


class _Harness:
    """Minimal object we can bind unbound mixin methods to."""

    def __init__(self):
        self.logger = _DummyLogger()


# --------------------------------------------------------------------------
# Helpers to build well-formed frames
# --------------------------------------------------------------------------


def _enip_header(command: int, payload: bytes) -> bytes:
    return struct.pack("<HHIIQI", command, len(payload), 0, 0, 0, 0) + payload


def _well_formed_list_identity() -> bytes:
    """A minimal valid ListIdentity response (command 0x63)."""
    name = b"PLC-1"
    identity = (
        struct.pack("<H", 1)  # protocol version
        + b"\x00" * 16  # sockaddr
        + struct.pack("<H", 0x0001)  # vendor id
        + struct.pack("<H", 0x000C)  # device type
        + struct.pack("<H", 0x0042)  # product code
        + struct.pack("<BB", 20, 5)  # revision
        + struct.pack("<H", 0x0003)  # status
        + struct.pack("<I", 0xDEADBEEF)  # serial
        + struct.pack("<B", len(name))
        + name
        + struct.pack("<B", 3)  # state
    )
    cpf = struct.pack("<H", 1) + struct.pack("<HH", 0x000C, len(identity)) + identity
    return _enip_header(0x63, cpf)


# --------------------------------------------------------------------------
# parse_list_identity  (parsers.py) - no try/except wrapper, must be self-safe
# --------------------------------------------------------------------------


class TestParseListIdentity:
    def test_well_formed_parses(self):
        info = parse_list_identity(_well_formed_list_identity())
        assert info is not None
        assert info["vendor_id"] == 0x0001
        assert info["serial_number"] == 0xDEADBEEF
        assert info["product_name"] == "PLC-1"
        assert info["revision"] == (20, 5)
        assert info["state"] == 3

    @pytest.mark.parametrize("n", list(range(0, 40)))
    def test_truncated_at_every_prefix_never_raises(self, n):
        """Feed every truncation of a valid frame - must return dict or None."""
        frame = _well_formed_list_identity()
        out = parse_list_identity(frame[:n])
        assert out is None or isinstance(out, dict)

    def test_oversized_length_field_is_bounded(self):
        # length field claims far more than the packet carries.
        payload = struct.pack("<H", 1) + struct.pack("<HH", 0x000C, 0xFFFF)
        frame = struct.pack("<HHIIQI", 0x63, 0xFFFF, 0, 0, 0, 0) + payload
        assert parse_list_identity(frame) is None  # bounded, no over-read/crash

    def test_huge_item_length_no_overread(self):
        # item_length claims 0xFFFF but only a few identity bytes present.
        identity = b"\x01\x00" + b"\x00" * 16 + b"\x00" * 15
        cpf = struct.pack("<H", 1) + struct.pack("<HH", 0x000C, 0xFFFF) + identity
        frame = _enip_header(0x63, cpf)
        # 6 + 0xFFFF > len(cpf) -> returns None (no slice past buffer)
        assert parse_list_identity(frame) is None

    def test_name_length_beyond_buffer_yields_empty_name(self):
        # name_length byte says 200 but no name bytes follow.
        identity = (
            struct.pack("<H", 1)
            + b"\x00" * 16
            + struct.pack("<H", 1)
            + struct.pack("<H", 1)
            + struct.pack("<H", 1)
            + struct.pack("<BB", 1, 0)
            + struct.pack("<H", 0)
            + struct.pack("<I", 0)
            + struct.pack("<B", 200)  # lying name length
        )
        cpf = struct.pack("<H", 1) + struct.pack("<HH", 0x000C, len(identity)) + identity
        info = parse_list_identity(_enip_header(0x63, cpf))
        assert info is not None
        assert info["product_name"] == ""  # not over-read


# --------------------------------------------------------------------------
# _parse_enip_header / _parse_cip_response  (enip_commands.py)
# --------------------------------------------------------------------------


class TestEnipHeaderAndCipResponse:
    def setup_method(self):
        self.h = _Harness()

    def test_header_short_returns_none(self):
        assert EnipCommandsMixin._parse_enip_header(self.h, b"\x00" * 10) is None

    def test_header_oversized_length_gives_empty_data(self):
        hdr = struct.pack("<HHIIQI", 0x6F, 0xFFFF, 1, 0, 0, 0)
        parsed = EnipCommandsMixin._parse_enip_header(self.h, hdr)
        assert parsed is not None
        assert parsed["data"] == b""  # bounded, no over-read

    def test_cip_response_wellformed(self):
        # CPF: iface(4) timeout(2) item_count(2), null item, data item 0xB2
        b2 = struct.pack("<HH", 0x00B2, 4) + struct.pack("<BBBB", 0xCC, 0, 0x08, 0)
        null = struct.pack("<HH", 0x0000, 0)
        cpf = struct.pack("<IHH", 0, 0, 2) + null + b2
        frame = _enip_header(0x6F, cpf)
        res = EnipCommandsMixin._parse_cip_response(self.h, frame)
        assert res["reply_service"] == 0xCC
        assert res["general_status"] == 0x08

    @pytest.mark.parametrize("n", list(range(0, 48)))
    def test_cip_response_truncations_never_raise(self, n):
        b2 = struct.pack("<HH", 0x00B2, 4) + struct.pack("<BBBB", 0xCC, 0, 0x08, 0)
        cpf = struct.pack("<IHH", 0, 0, 1) + b2
        frame = _enip_header(0x6F, cpf)[:n]
        res = EnipCommandsMixin._parse_cip_response(self.h, frame)
        assert isinstance(res, dict)  # default sentinel on failure

    def test_cip_response_huge_item_count_terminates(self):
        # item_count = 0xFFFF but no items -> loop must break, not hang.
        cpf = struct.pack("<IHH", 0, 0, 0xFFFF)
        frame = _enip_header(0x6F, cpf)
        start = time.monotonic()
        res = EnipCommandsMixin._parse_cip_response(self.h, frame)
        assert time.monotonic() - start < 1.0
        assert res["general_status"] == 0xFF  # never found a valid item

    def test_cip_response_b2_item_len_overrun_is_caught(self):
        # 0xB2 item claims len 4 but truncated to 1 byte after header.
        cpf = struct.pack("<IHH", 0, 0, 1) + struct.pack("<HH", 0x00B2, 4) + b"\x01"
        frame = _enip_header(0x6F, cpf)
        res = EnipCommandsMixin._parse_cip_response(self.h, frame)
        assert isinstance(res, dict)  # struct.error swallowed


# --------------------------------------------------------------------------
# _parse_identity_response  (cip_objects.py)
# --------------------------------------------------------------------------


class TestParseIdentityResponse:
    def setup_method(self):
        self.h = _Harness()

    def test_wellformed(self):
        data = (
            struct.pack("<H", 0x0001)
            + struct.pack("<H", 0x000C)
            + struct.pack("<H", 0x0042)
            + struct.pack("<BB", 1, 2)
            + struct.pack("<H", 0)  # status (bytes 8-9)
            + struct.pack("<I", 0x11223344)
            + struct.pack("<B", 3)
            + b"ABC"
        )
        info = CipObjectsMixin._parse_identity_response(self.h, data)
        assert info["vendor_id"] == 0x0001
        assert info["serial_number"] == 0x11223344
        assert info["product_name"] == "ABC"

    @pytest.mark.parametrize("n", list(range(0, 25)))
    def test_truncations_never_raise(self, n):
        data = b"\x01\x00\x0c\x00\x42\x00\x01\x02\x00\x00\x44\x33\x22\x11\x03ABC"
        out = CipObjectsMixin._parse_identity_response(self.h, data[:n])
        assert isinstance(out, dict)

    def test_lying_name_length_no_overread(self):
        data = (
            b"\x01\x00\x0c\x00\x42\x00\x01\x02\x00\x00\x44\x33\x22\x11"
            + struct.pack("<B", 250)  # name_len lie, no bytes follow
        )
        info = CipObjectsMixin._parse_identity_response(self.h, data)
        assert "product_name" not in info  # guard skipped the over-read


# --------------------------------------------------------------------------
# cip_definitions: parse_attribute wrapper + parse_epath infinite-loop guard
# --------------------------------------------------------------------------


class TestCipDefinitions:
    @pytest.mark.parametrize(
        "data",
        [b"", b"\x00", b"\x20", b"\x21\xff", b"\xff" * 3, bytes(range(256))],
    )
    def test_parse_epath_terminates_and_never_raises(self, data):
        start = time.monotonic()
        out = cip_definitions.parse_epath(data)
        assert time.monotonic() - start < 1.0
        assert isinstance(out, str)

    def test_parse_interface_counters_truncated(self):
        # Declared 44-byte structure; feed 10 bytes -> raw fallback, no crash.
        assert "raw" in cip_definitions.parse_interface_counters(b"\x00" * 10)

    def test_parse_interface_capability_lying_count(self):
        # caps(4) + count=0xFF but no array bytes -> guard skips the loop.
        data = struct.pack("<I", 0) + struct.pack("<B", 0xFF)
        out = cip_definitions.parse_interface_capability(data)
        assert "supported_speeds" not in out

    def test_parse_attribute_swallows_parser_crash(self):
        # Drive a real attribute whose parser would struct.unpack on short data.
        # parse_attribute must catch and degrade rather than raise.
        for cid in (0xF6, 0x01, 0x04, 0xF5):
            for aid in range(1, 12):
                # Should never raise regardless of class/attr/data shape, and
                # must always honor the documented (name, cip_type, value)
                # contract rather than e.g. returning the exception itself.
                for data in (b"\x01", b""):
                    result = cip_definitions.parse_attribute(cid, 1, aid, data)
                    # Documented contract: always a 3-tuple (name, cip_type, value).
                    assert isinstance(result, tuple) and len(result) == 3
                    name, cip_type, value = result
                    assert isinstance(name, str)
                    assert isinstance(cip_type, str)
                    # A crashed parser degrades to the raw hex of the input
                    # (empty string for empty input) rather than propagating.
                    assert value is not None
