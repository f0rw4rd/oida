"""
Unit tests for the SunSpec model-chain discovery logic in
oida.protocols.modbus.mixins.sunspec.SunSpecMixin.

Complements test_sunspec.py (which covers the pure helpers and the security
assessment). Here we exercise the device-interaction methods against a fake
Modbus connection:
- _sunspec_find_base: marker probing across SUNSPEC_BASE_ADDRESSES, miss,
  short-read, read-error and exception handling.
- _sunspec_walk_models: header walk, end sentinel (0xFFFF), cursor advance by
  (2 + length), suspicious-length guard, read-error break, max-model safety.
- _sunspec_read_block: single + multi-chunk (>125) reads, error/exception ->
  None.
- _sunspec_read_model: routing to mapped vs raw display, read-block failure.
- _handle_sunspec: end-to-end flow (no marker, marker-but-no-models, full
  discovery + results structure + assess gating).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")

from oida.protocols.modbus.mixins.sunspec_constants import (
    SUNSPEC_BASE_ADDRESSES,
    SUNSPEC_MARKER,
)


@pytest.fixture(autouse=True)
def _stub_print_table(monkeypatch):
    import oida.utils.export_utils as eu

    monkeypatch.setattr(eu, "print_table", lambda *a, **k: None)
    yield


class FakeLogger:
    def __init__(self):
        self.display_msgs = []
        self.success_msgs = []
        self.warning_msgs = []
        self.fail_msgs = []
        self.findings = []

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

    def security_finding(self, title, category="", detail=""):
        self.findings.append({"title": title, "category": category, "detail": detail})


def _reg_resp(values):
    r = MagicMock()
    r.isError.return_value = False
    r.registers = list(values)
    return r


def _err_resp():
    r = MagicMock()
    r.isError.return_value = True
    return r


class FakeSunSpec:
    def __init__(self, args=None):
        from oida.protocols.modbus.mixins.sunspec import SunSpecMixin

        self.logger = FakeLogger()
        self.conn = MagicMock()
        self.results = {"data": {"sunspec": {}}}
        self.args = args if args is not None else SimpleNamespace(verbose=0, unit_id=None)
        for name in (
            "_handle_sunspec",
            "_sunspec_find_base",
            "_sunspec_walk_models",
            "_sunspec_read_model",
            "_sunspec_read_block",
            "_sunspec_display_raw_model",
            "_sunspec_display_mapped_model",
            "_sunspec_assess_security",
        ):
            setattr(self, name, getattr(SunSpecMixin, name).__get__(self, FakeSunSpec))


MARKER_HI = SUNSPEC_MARKER >> 16
MARKER_LO = SUNSPEC_MARKER & 0xFFFF


# ---------------------------------------------------------------------------
# _sunspec_find_base
# ---------------------------------------------------------------------------


class TestFindBase:
    def test_marker_found_at_first_address(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _reg_resp([MARKER_HI, MARKER_LO])
        addr = fs._sunspec_find_base(unit_id=1)
        assert addr == SUNSPEC_BASE_ADDRESSES[0]

    def test_marker_found_at_second_address(self):
        fs = FakeSunSpec()

        def read(addr, count, device_id):
            if addr == SUNSPEC_BASE_ADDRESSES[1]:
                return _reg_resp([MARKER_HI, MARKER_LO])
            return _reg_resp([0, 0])

        fs.conn.read_holding_registers.side_effect = read
        assert fs._sunspec_find_base(unit_id=1) == SUNSPEC_BASE_ADDRESSES[1]

    def test_no_marker_returns_none(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _reg_resp([0x1234, 0x5678])
        assert fs._sunspec_find_base(unit_id=1) is None

    def test_read_error_skips_address(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _err_resp()
        assert fs._sunspec_find_base(unit_id=1) is None

    def test_short_read_skipped(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _reg_resp([MARKER_HI])  # only 1 reg
        assert fs._sunspec_find_base(unit_id=1) is None

    def test_exception_handled(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.side_effect = OSError("reset")
        assert fs._sunspec_find_base(unit_id=1) is None


# ---------------------------------------------------------------------------
# _sunspec_walk_models
# ---------------------------------------------------------------------------


class TestWalkModels:
    def test_single_model_then_end_sentinel(self):
        fs = FakeSunSpec()
        base = 40000

        # header at base+2: model 1, length 4; next header at base+8 = end 0xFFFF
        def read(addr, count, device_id):
            if addr == base + 2:
                return _reg_resp([1, 4])
            if addr == base + 8:
                return _reg_resp([0xFFFF, 0])
            raise AssertionError(f"unexpected addr {addr}")

        fs.conn.read_holding_registers.side_effect = read
        models = fs._sunspec_walk_models(base, unit_id=1)
        assert len(models) == 1
        m = models[0]
        assert m["model_id"] == 1
        assert m["length"] == 4
        assert m["header_address"] == base + 2
        assert m["data_address"] == base + 4

    def test_two_models_cursor_advances(self):
        fs = FakeSunSpec()
        base = 0
        # model1 (id 1, len 2) at 2; model2 (id 103, len 3) at 2+2+2=6;
        # end at 6+2+3=11
        seq = {
            2: [1, 2],
            6: [103, 3],
            11: [0xFFFF, 0],
        }
        fs.conn.read_holding_registers.side_effect = lambda addr, count, device_id: _reg_resp(
            seq[addr]
        )
        models = fs._sunspec_walk_models(base, unit_id=1)
        assert [m["model_id"] for m in models] == [1, 103]
        assert models[1]["header_address"] == 6

    def test_read_error_breaks_walk(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _err_resp()
        models = fs._sunspec_walk_models(40000, unit_id=1)
        assert models == []

    def test_suspicious_length_breaks(self):
        fs = FakeSunSpec()
        # length 0 is rejected as suspicious
        fs.conn.read_holding_registers.return_value = _reg_resp([1, 0])
        models = fs._sunspec_walk_models(40000, unit_id=1)
        assert models == []

    def test_too_large_length_breaks(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _reg_resp([1, 5000])
        models = fs._sunspec_walk_models(40000, unit_id=1)
        assert models == []

    def test_exception_breaks_walk(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.side_effect = OSError("x")
        assert fs._sunspec_walk_models(40000, unit_id=1) == []

    def test_max_models_safety_limit(self):
        """A model chain that never terminates is capped at 50 and warns."""
        fs = FakeSunSpec()
        # every header reports a benign model with length 1, no end sentinel
        fs.conn.read_holding_registers.side_effect = lambda addr, count, device_id: _reg_resp(
            [1, 1]
        )
        models = fs._sunspec_walk_models(40000, unit_id=1)
        assert len(models) == 50
        assert any("model limit" in m for m in fs.logger.warning_msgs)


# ---------------------------------------------------------------------------
# _sunspec_read_block
# ---------------------------------------------------------------------------


class TestReadBlock:
    def test_single_chunk(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _reg_resp([1, 2, 3])
        out = fs._sunspec_read_block(100, 3, unit_id=1)
        assert out == [1, 2, 3]
        fs.conn.read_holding_registers.assert_called_once_with(100, count=3, device_id=1)

    def test_multi_chunk_over_125(self):
        fs = FakeSunSpec()

        def read(addr, count, device_id):
            return _reg_resp([0] * count)

        fs.conn.read_holding_registers.side_effect = read
        out = fs._sunspec_read_block(0, 200, unit_id=1)
        assert len(out) == 200
        # 200 -> 125 + 75 = 2 reads
        assert fs.conn.read_holding_registers.call_count == 2
        first = fs.conn.read_holding_registers.call_args_list[0]
        assert first.kwargs["count"] == 125

    def test_read_error_returns_none(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _err_resp()
        assert fs._sunspec_read_block(0, 10, unit_id=1) is None

    def test_exception_returns_none(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.side_effect = OSError("x")
        assert fs._sunspec_read_block(0, 10, unit_id=1) is None

    def test_max_registers_arg_respected(self):
        fs = FakeSunSpec(args=SimpleNamespace(verbose=0, unit_id=None, max_registers=10))
        fs.conn.read_holding_registers.side_effect = lambda addr, count, device_id: _reg_resp(
            [0] * count
        )
        fs._sunspec_read_block(0, 25, unit_id=1)
        # 25 / 10 -> 10 + 10 + 5 = 3 reads
        assert fs.conn.read_holding_registers.call_count == 3


# ---------------------------------------------------------------------------
# _sunspec_read_model routing
# ---------------------------------------------------------------------------


class TestReadModel:
    def test_read_block_failure_returns_metadata_only(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _err_resp()
        info = {"model_id": 1, "length": 4, "data_address": 40004, "header_address": 40002}
        out = fs._sunspec_read_model(info, sunspec_maps={}, unit_id=1, verbose=0)
        assert out["model_id"] == 1
        assert out["has_map"] is False
        assert out["registers"] == {}
        assert any("Failed to read model" in m for m in fs.logger.warning_msgs)

    def test_no_map_uses_raw_display(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _reg_resp([10, 20, 30, 40])
        info = {"model_id": 999, "length": 4, "data_address": 40004, "header_address": 40002}
        out = fs._sunspec_read_model(info, sunspec_maps={}, unit_id=1, verbose=0)
        assert out["has_map"] is False
        # raw register dump should be populated
        assert out["registers"]

    def test_with_map_uses_mapped_display(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _reg_resp([1234, 0])
        reg_map = {
            "registers": {
                "field_a": {"offset": 0, "type": "u16", "name": "field_a"},
            }
        }
        info = {"model_id": 1, "length": 2, "data_address": 40004, "header_address": 40002}
        out = fs._sunspec_read_model(info, sunspec_maps={1: reg_map}, unit_id=1, verbose=0)
        assert out["has_map"] is True


# ---------------------------------------------------------------------------
# _handle_sunspec end-to-end
# ---------------------------------------------------------------------------


class TestHandleSunspec:
    def test_no_marker_records_not_found(self):
        fs = FakeSunSpec()
        fs.conn.read_holding_registers.return_value = _reg_resp([0, 0])
        fs._handle_sunspec()
        assert fs.results["data"]["sunspec"] == {"found": False}
        assert any("No SunSpec marker" in m for m in fs.logger.fail_msgs)

    def test_marker_but_no_models(self):
        fs = FakeSunSpec()
        base = SUNSPEC_BASE_ADDRESSES[0]

        def read(addr, count, device_id):
            if addr == base:
                return _reg_resp([MARKER_HI, MARKER_LO])
            # first model header -> immediate end sentinel
            return _reg_resp([0xFFFF, 0])

        fs.conn.read_holding_registers.side_effect = read
        fs._handle_sunspec()
        result = fs.results["data"]["sunspec"]
        assert result["found"] is True
        assert result["base_address"] == base
        assert result["models"] == []

    def test_full_discovery_records_models(self):
        fs = FakeSunSpec()
        base = SUNSPEC_BASE_ADDRESSES[0]

        def read(addr, count, device_id):
            if addr == base:
                return _reg_resp([MARKER_HI, MARKER_LO])
            if addr == base + 2:
                return _reg_resp([1, 2])  # model 1, length 2
            if addr == base + 6:
                return _reg_resp([0xFFFF, 0])  # end
            # model data block read
            return _reg_resp([0] * count)

        fs.conn.read_holding_registers.side_effect = read
        fs._handle_sunspec()
        result = fs.results["data"]["sunspec"]
        assert result["found"] is True
        assert len(result["models"]) == 1
        assert result["models"][0]["model_id"] == 1

    def test_assess_gated_off_by_default(self):
        fs = FakeSunSpec(args=SimpleNamespace(verbose=0, unit_id=None, sunspec_assess=False))
        base = SUNSPEC_BASE_ADDRESSES[0]

        def read(addr, count, device_id):
            if addr == base:
                return _reg_resp([MARKER_HI, MARKER_LO])
            if addr == base + 2:
                return _reg_resp([1, 2])
            if addr == base + 6:
                return _reg_resp([0xFFFF, 0])
            return _reg_resp([0] * count)

        fs.conn.read_holding_registers.side_effect = read
        fs._handle_sunspec()
        # no security findings emitted when assess is off
        assert fs.logger.findings == []

    def test_unit_id_none_defaults_to_one(self):
        fs = FakeSunSpec(args=SimpleNamespace(verbose=0, unit_id=None))
        fs.conn.read_holding_registers.return_value = _reg_resp([0, 0])
        fs._handle_sunspec()
        # find_base probed with device_id=1
        _, kwargs = fs.conn.read_holding_registers.call_args
        assert kwargs["device_id"] == 1
