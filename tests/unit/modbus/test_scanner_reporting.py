"""
Unit tests for the pure decode/report-building logic in
oida.protocols.modbus.scanner_mixins.reporting.ScannerReportingMixin
(previously ~12% covered -- the existing suite never exercised it).

Covers:
- _decode_register_values: address annotation, multi-register grouping stride.
- _build_decode_all_rows: hex / i16 (negative-only) / bits / printable-ASCII
  columns, non-int passthrough.
- _build_decode_type_rows: single-register inline decode, multi-register
  consecutive grouping + non-consecutive skip, custom decode-width, string
  width->register math, float formatting.
"""

from unittest.mock import MagicMock

import pytest

try:
    import pymodbus  # noqa: F401

    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False

pytestmark = pytest.mark.skipif(not PYMODBUS_AVAILABLE, reason="pymodbus library not installed")

from oida.protocols.modbus.decoder import ModbusDecoder, encode_float32


def make_scanner(decode_type=None, decode_width=None, endian="big"):
    from oida.protocols.modbus.scanner import ModbusScanner

    s = ModbusScanner.__new__(ModbusScanner)
    s.logger = MagicMock()
    s.decode_type = decode_type
    s.decode_width = decode_width
    s.endian = endian
    return s


# ---------------------------------------------------------------------------
# _decode_register_values
# ---------------------------------------------------------------------------


class TestDecodeRegisterValues:
    def test_u16_addresses_annotated(self):
        s = make_scanner()
        out = s._decode_register_values({0: 10, 1: 20}, "u16")
        assert [d["value"] for d in out] == [10, 20]
        assert [d["address"] for d in out] == [0, 1]

    def test_u32_groups_two_registers(self):
        s = make_scanner()
        # u32 from [0x0001, 0x0000] big/big -> 0x00010000
        out = s._decode_register_values({0: 0x0001, 1: 0x0000}, "u32")
        assert out[0]["value"] == 0x00010000
        assert out[0]["address"] == 0  # stride of 2 -> base address

    def test_f32_decode(self):
        s = make_scanner()
        regs = encode_float32(1.5)
        out = s._decode_register_values({0: regs[0], 1: regs[1]}, "f32")
        assert abs(out[0]["value"] - 1.5) < 1e-6


# ---------------------------------------------------------------------------
# _build_decode_all_rows
# ---------------------------------------------------------------------------


class TestBuildDecodeAllRows:
    def test_positive_value_no_i16_column(self):
        s = make_scanner()
        decoder = ModbusDecoder()
        rows = s._build_decode_all_rows(decoder, [(0, {"value": 100})])
        addr, val, hex_val, i16, bits, ascii_ = rows[0]
        assert addr == 0 and val == 100 and hex_val == "0x0064"
        assert i16 == ""  # positive -> i16 column blank

    def test_negative_i16_shown(self):
        s = make_scanner()
        decoder = ModbusDecoder()
        rows = s._build_decode_all_rows(decoder, [(0, {"value": 0xFFFF})])
        i16 = rows[0][3]
        assert i16 == "-1"

    def test_printable_ascii_shown(self):
        s = make_scanner()
        decoder = ModbusDecoder()
        # 0x4142 -> "AB"
        rows = s._build_decode_all_rows(decoder, [(0, {"value": 0x4142})])
        ascii_ = rows[0][5]
        assert ascii_ == '"AB"'

    def test_non_int_value_passthrough(self):
        s = make_scanner()
        decoder = ModbusDecoder()
        rows = s._build_decode_all_rows(decoder, [(0, {"value": True})])
        assert rows[0] == [0, True, "", "", "", ""]


# ---------------------------------------------------------------------------
# _build_decode_type_rows
# ---------------------------------------------------------------------------


class TestBuildDecodeTypeRows:
    def test_single_register_inline(self):
        s = make_scanner(decode_type="i16")
        headers, rows = s._build_decode_type_rows([(0, {"value": 0xFFFF})])
        assert headers[0] == "Addr"
        # i16 decode of 0xFFFF -> -1
        assert rows[0][3] == -1

    def test_single_register_non_int_blank(self):
        s = make_scanner(decode_type="i16")
        headers, rows = s._build_decode_type_rows([(0, {"value": None})])
        assert rows[0] == [0, None, "", ""]

    def test_multi_register_consecutive_grouping(self):
        s = make_scanner(decode_type="u32")
        items = [(0, {"value": 0x0001}), (1, {"value": 0x0000})]
        headers, rows = s._build_decode_type_rows(items)
        assert headers[1] == "Registers"
        # single grouped row spanning 0-1
        assert len(rows) == 1
        assert rows[0][0] == "0-1"

    def test_multi_register_skips_non_consecutive(self):
        s = make_scanner(decode_type="u32")
        # addresses 0,1 consecutive (one group); 5 alone -> no group
        items = [(0, {"value": 1}), (1, {"value": 0}), (5, {"value": 9})]
        headers, rows = s._build_decode_type_rows(items)
        assert len(rows) == 1
        assert rows[0][0] == "0-1"

    def test_float_formatting(self):
        s = make_scanner(decode_type="f32")
        regs = encode_float32(3.25)
        items = [(0, {"value": regs[0]}), (1, {"value": regs[1]})]
        headers, rows = s._build_decode_type_rows(items)
        # decoded float rendered with fixed precision
        assert "3.25" in str(rows[0][3])

    def test_custom_decode_width_groups(self):
        s = make_scanner(decode_type="u16", decode_width=2)
        items = [(0, {"value": 0x0001}), (1, {"value": 0x0002})]
        headers, rows = s._build_decode_type_rows(items)
        # width=2 forces grouping even for a 1-register type
        assert headers[1] == "Registers"
        assert rows[0][0] == "0-1"

    def test_string_width_register_math(self):
        # width=4 chars -> ceil(4/2)=2 registers per group
        s = make_scanner(decode_type="str", decode_width=4)
        items = [(0, {"value": 0x4142}), (1, {"value": 0x4344})]
        headers, rows = s._build_decode_type_rows(items)
        assert len(rows) == 1
        assert "ABCD" in str(rows[0][3])
