"""
Unit tests for oida.protocols.modbus.mixins.fuzz.FuzzMixin
(was ~8% covered).

Covers:
- _handle_fuzz: confirm gating (fuzzing writes to device), mode routing
  (basic/data/boundary -> _fuzz_registers, function -> _fuzz_function_codes,
  full -> both, map -> _fuzz_registers_from_map), unknown-mode error,
  stats aggregation into results.
- _parse_fuzz_range: comma list + ranges, dedup/sort.
- _pack_as_registers: 32-bit value -> two 16-bit registers (byte order).
- _generate_raw_fuzz_payloads / _generate_typed_fuzz_payloads: boundary set
  inclusion for u16/i32/u32/f32, count honoured, f32 special values.
- _fuzz_registers: payload write loop, original-value restore, error/crash
  classification.
- _fuzz_function_codes: vendor FC sweep 65-127, supported detection.
- _fuzz_registers_from_map: writable filter, missing map.
"""

import struct
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

try:
    import pymodbus  # noqa: F401

    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False

pytestmark = pytest.mark.skipif(not PYMODBUS_AVAILABLE, reason="pymodbus library not installed")


class FakeLogger:
    def __init__(self):
        self.display_msgs = []
        self.success_msgs = []
        self.warning_msgs = []
        self.fail_msgs = []

    def display(self, msg=""):
        self.display_msgs.append(msg)

    def success(self, msg):
        self.success_msgs.append(msg)

    def warning(self, msg):
        self.warning_msgs.append(msg)

    def fail(self, msg):
        self.fail_msgs.append(msg)

    def debug(self, msg):
        pass


def make_modbus(args=None, unit_id=1):
    from oida.protocols.modbus.nxc_connection import modbus

    inst = modbus.__new__(modbus)
    inst.logger = FakeLogger()
    inst.conn = MagicMock()
    inst.scanner = MagicMock()
    inst.scanner.unit_id = unit_id
    inst.results = {"data": {}}
    inst.args = args if args is not None else SimpleNamespace()
    return inst


def _ok():
    r = MagicMock()
    r.isError.return_value = False
    return r


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------


class TestParseFuzzRange:
    def test_range_and_list(self):
        inst = make_modbus()
        assert inst._parse_fuzz_range("0-2,10") == [0, 1, 2, 10]

    def test_dedup_sorted(self):
        inst = make_modbus()
        assert inst._parse_fuzz_range("5,1-3,2") == [1, 2, 3, 5]


class TestPackAsRegisters:
    def test_u32_split(self):
        inst = make_modbus()
        regs = inst._pack_as_registers(">I", 0x00010002)
        assert regs == [0x0001, 0x0002]

    def test_i32_negative(self):
        inst = make_modbus()
        regs = inst._pack_as_registers(">i", -1)
        # -1 as 32-bit big-endian -> 0xFFFF 0xFFFF
        assert regs == [0xFFFF, 0xFFFF]


class TestGenerateRawPayloads:
    def test_boundaries_present(self):
        inst = make_modbus()
        vals = list(inst._generate_raw_fuzz_payloads("boundary", 8))
        for b in (0, 0xFFFF, 0x8000, 0x7FFF):
            assert b in vals

    def test_count_extends_with_randoms(self):
        inst = make_modbus()
        vals = list(inst._generate_raw_fuzz_payloads("boundary", 20))
        # 8 boundaries + 12 randoms
        assert len(vals) == 20
        assert all(0 <= v <= 0xFFFF for v in vals)


class TestGenerateTypedPayloads:
    def test_u32_boundaries_as_register_pairs(self):
        inst = make_modbus()
        vals = list(inst._generate_typed_fuzz_payloads("u32", 5))
        # each payload is a 2-register list
        assert all(isinstance(v, list) and len(v) == 2 for v in vals)
        # 0xFFFFFFFF boundary -> [0xFFFF, 0xFFFF]
        assert [0xFFFF, 0xFFFF] in vals

    def test_i32_includes_signed_boundaries(self):
        inst = make_modbus()
        vals = list(inst._generate_typed_fuzz_payloads("i32", 8))
        # -1 -> [0xFFFF, 0xFFFF]; min int32 0x80000000 -> [0x8000, 0x0000]
        assert [0xFFFF, 0xFFFF] in vals
        assert [0x8000, 0x0000] in vals

    def test_f32_special_values(self):
        inst = make_modbus()
        vals = list(inst._generate_typed_fuzz_payloads("f32", 11))
        # nan packs to a specific register pair; just verify all are reg pairs
        assert all(isinstance(v, list) and len(v) == 2 for v in vals)
        # +inf big-endian float -> 0x7F80 0x0000
        inf_regs = [
            struct.unpack(">H", struct.pack(">f", float("inf"))[0:2])[0],
            struct.unpack(">H", struct.pack(">f", float("inf"))[2:4])[0],
        ]
        assert inf_regs in vals

    def test_unknown_type_falls_back_to_u16(self):
        inst = make_modbus()
        vals = list(inst._generate_typed_fuzz_payloads("weird", 8))
        # u16 fallback yields plain ints
        assert all(isinstance(v, int) for v in vals)


# ---------------------------------------------------------------------------
# _fuzz_function_codes
# ---------------------------------------------------------------------------


class TestFuzzFunctionCodes:
    def test_sweeps_vendor_range_and_detects_supported(self):
        inst = make_modbus()

        def send(conn, fc, payload, unit):
            # FC 70 "supported", rest exceptions. success=True marks a received
            # response (normal or exception); a failed send would be success=False.
            if fc == 70:
                return {"success": True, "is_exception": False, "response_payload": b"\x01\x02"}
            return {"success": True, "is_exception": True}

        inst.scanner.send_custom_fc.side_effect = send
        stats = inst._fuzz_function_codes()
        assert stats["tests"] == 63  # 65..127 inclusive
        assert any(s["fc"] == 70 for s in stats["supported"])

    def test_none_response_counts_error(self):
        inst = make_modbus()
        inst.scanner.send_custom_fc.return_value = None
        stats = inst._fuzz_function_codes()
        assert stats["errors"] == 63


# ---------------------------------------------------------------------------
# _fuzz_registers
# ---------------------------------------------------------------------------


class TestFuzzRegisters:
    def test_writes_and_restores_original(self):
        inst = make_modbus(SimpleNamespace(scan_range="0-0", decode=None, fuzz_max_addresses=10))
        inst.conn.write_register.return_value = _ok()
        with patch(
            "oida.protocols.modbus.register_io.read_registers_batched",
            return_value={0: 1234},
        ):
            stats = inst._fuzz_registers(8, "boundary")
        assert stats["tests"] >= 8
        assert stats["writes"] >= 1
        # original value restored at the end
        inst.conn.write_register.assert_any_call(0, 1234, device_id=1)

    def test_no_addresses_fails(self):
        inst = make_modbus(SimpleNamespace(scan_range="", decode=None))
        # empty range -> _parse_fuzz_range raises on int('') -> caught? no:
        # range "" splits to [''], int('') raises ValueError -> not caught here,
        # so use a range that parses to empty via dedup is impossible; instead
        # patch _parse_fuzz_range to return []
        with patch.object(inst, "_parse_fuzz_range", return_value=[]):
            stats = inst._fuzz_registers(5, "boundary")
        assert stats == {}
        assert any("No addresses" in m for m in inst.logger.fail_msgs)

    def test_crash_classified_on_connection_error(self):
        inst = make_modbus(SimpleNamespace(scan_range="0-0", decode=None, fuzz_max_addresses=10))
        inst.conn.write_register.side_effect = ConnectionError("connection reset")
        with patch(
            "oida.protocols.modbus.register_io.read_registers_batched",
            return_value={0: None},
        ):
            stats = inst._fuzz_registers(2, "boundary")
        assert stats["crashes"] >= 1
        assert stats["errors"] >= 1


# ---------------------------------------------------------------------------
# _fuzz_registers_from_map
# ---------------------------------------------------------------------------


class TestFuzzFromMap:
    def test_missing_map(self):
        inst = make_modbus(SimpleNamespace(fuzz_all_access=False, fuzz_max_addresses=10))
        with patch("oida.protocols.modbus.decoder.load_register_map", return_value=None):
            stats = inst._fuzz_registers_from_map("nope", 10)
        assert stats == {}
        assert any("not found" in m for m in inst.logger.fail_msgs)

    def test_no_writable_registers(self):
        # Register maps store "registers" as a dict keyed by name (see
        # register_maps/generic.json), not a list.
        inst = make_modbus(SimpleNamespace(fuzz_all_access=False, fuzz_max_addresses=10))
        reg_map = {"registers": {"status": {"address": 0, "type": "u16", "access": "r"}}}
        with patch("oida.protocols.modbus.decoder.load_register_map", return_value=reg_map):
            stats = inst._fuzz_registers_from_map("m", 10)
        assert stats == {}
        assert any("No writable" in m for m in inst.logger.warning_msgs)

    def test_writable_registers_fuzzed(self):
        inst = make_modbus(SimpleNamespace(fuzz_all_access=False, fuzz_max_addresses=10))
        reg_map = {
            "registers": {
                "sp": {"address": 5, "type": "u16", "access": "rw", "name": "sp"},
            }
        }
        inst.conn.write_register.return_value = _ok()
        with patch("oida.protocols.modbus.decoder.load_register_map", return_value=reg_map):
            stats = inst._fuzz_registers_from_map("m", 10)
        assert stats["tests"] > 0
        assert stats["writes"] > 0


# ---------------------------------------------------------------------------
# _handle_fuzz dispatch
# ---------------------------------------------------------------------------


class TestHandleFuzz:
    def test_requires_confirm(self):
        inst = make_modbus(SimpleNamespace(confirm=False))
        inst._handle_fuzz()
        assert any("requires --confirm" in m for m in inst.logger.fail_msgs)

    def test_unknown_mode(self):
        inst = make_modbus(
            SimpleNamespace(confirm=True, fuzz_mode="bogus", fuzz_iterations=10, register_map=None)
        )
        inst._handle_fuzz()
        assert any("Unknown fuzz mode" in m for m in inst.logger.fail_msgs)

    def test_basic_mode_routes_to_register_fuzz(self):
        inst = make_modbus(
            SimpleNamespace(confirm=True, fuzz_mode="basic", fuzz_iterations=10, register_map=None)
        )
        with patch.object(inst, "_fuzz_registers", return_value={"tests": 5, "writes": 2}) as fr:
            inst._handle_fuzz()
        fr.assert_called_once()
        assert inst.results["data"]["fuzz"]["tests"] == 5

    def test_function_mode_routes_to_fc_fuzz(self):
        inst = make_modbus(
            SimpleNamespace(
                confirm=True, fuzz_mode="function", fuzz_iterations=10, register_map=None
            )
        )
        with patch.object(inst, "_fuzz_function_codes", return_value={"tests": 63}) as ff:
            inst._handle_fuzz()
        ff.assert_called_once()

    def test_full_mode_runs_both(self):
        inst = make_modbus(
            SimpleNamespace(confirm=True, fuzz_mode="full", fuzz_iterations=10, register_map=None)
        )
        with (
            patch.object(inst, "_fuzz_registers", return_value={"tests": 1}) as fr,
            patch.object(inst, "_fuzz_function_codes", return_value={"tests": 2}) as ff,
        ):
            inst._handle_fuzz()
        fr.assert_called_once()
        ff.assert_called_once()

    def test_map_mode_routes_to_map_fuzz(self):
        inst = make_modbus(
            SimpleNamespace(
                confirm=True, fuzz_mode="basic", fuzz_iterations=10, register_map="vfd/x"
            )
        )
        with patch.object(inst, "_fuzz_registers_from_map", return_value={"tests": 3}) as fm:
            inst._handle_fuzz()
        fm.assert_called_once()
