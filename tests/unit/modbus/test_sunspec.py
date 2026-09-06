"""
Unit tests for SunSpec module pure functions and assessment logic.

Tests:
- _is_not_implemented(): sentinel value detection across all data types
- _raw_regs_to_value(): register-to-typed-value conversion for all types
- _load_sunspec_maps(): JSON map loading
- _sunspec_assess_security(): security finding generation (mocked mixin)
"""

import math
import struct

import pytest

from oida.protocols.modbus.mixins.sunspec import (
    _is_not_implemented,
    _load_sunspec_maps,
    _raw_regs_to_value,
)
from oida.protocols.modbus.mixins.sunspec_constants import (
    SUNSPEC_CRITICAL_CONTROLS,
    SUNSPEC_NOT_IMPLEMENTED,
    SUNSPEC_SECURITY_MODELS,
)


# =============================================================================
# _is_not_implemented
# =============================================================================


class TestIsNotImplemented:
    """Tests for SunSpec 'not implemented' sentinel detection."""

    def test_u16_sentinel(self):
        assert _is_not_implemented(0xFFFF, "u16") is True

    def test_u16_normal(self):
        assert _is_not_implemented(100, "u16") is False

    def test_u16_zero(self):
        assert _is_not_implemented(0, "u16") is False

    def test_i16_sentinel_unsigned(self):
        assert _is_not_implemented(0x8000, "i16") is True

    def test_i16_sentinel_signed(self):
        assert _is_not_implemented(-32768, "i16") is True

    def test_i16_normal(self):
        assert _is_not_implemented(42, "i16") is False

    def test_u32_sentinel(self):
        assert _is_not_implemented(0xFFFFFFFF, "u32") is True

    def test_u32_normal(self):
        assert _is_not_implemented(1000, "u32") is False

    def test_i32_sentinel_unsigned(self):
        assert _is_not_implemented(0x80000000, "i32") is True

    def test_i32_sentinel_signed(self):
        assert _is_not_implemented(-2147483648, "i32") is True

    def test_i32_normal(self):
        assert _is_not_implemented(-1, "i32") is False

    def test_u64_sentinel(self):
        assert _is_not_implemented(0xFFFFFFFFFFFFFFFF, "u64") is True

    def test_i64_sentinel_unsigned(self):
        assert _is_not_implemented(0x8000000000000000, "i64") is True

    def test_i64_sentinel_signed(self):
        assert _is_not_implemented(-(1 << 63), "i64") is True

    def test_f32_nan(self):
        """f32 sentinel is NaN -- the W5 fix ensures decoded floats are checked."""
        assert _is_not_implemented(float("nan"), "f32") is True

    def test_f32_normal(self):
        assert _is_not_implemented(3.14, "f32") is False

    def test_f32_zero(self):
        assert _is_not_implemented(0.0, "f32") is False

    def test_f32_inf(self):
        """Infinity is NOT the not-implemented sentinel."""
        assert _is_not_implemented(float("inf"), "f32") is False

    def test_f32_negative_nan(self):
        """Negative NaN should also be detected."""
        assert _is_not_implemented(float("-nan"), "f32") is True

    def test_f32_with_integer_input(self):
        """Before W5 fix, an integer u16 was passed -- should not crash."""
        # math.isnan(0x7FC0) should raise TypeError, caught by the handler
        assert _is_not_implemented(0x7FC0, "f32") is False

    def test_sunssf_sentinel(self):
        assert _is_not_implemented(0x8000, "sunssf") is True

    def test_sunssf_normal(self):
        assert _is_not_implemented(0xFFFC, "sunssf") is False  # -4 as u16

    def test_acc16_sentinel(self):
        """acc16 not-implemented is 0x0000."""
        assert _is_not_implemented(0x0000, "acc16") is True

    def test_acc16_normal(self):
        assert _is_not_implemented(1, "acc16") is False

    def test_acc32_sentinel(self):
        assert _is_not_implemented(0x00000000, "acc32") is True

    def test_str_sentinel(self):
        assert _is_not_implemented("", "str") is True

    def test_str_normal(self):
        assert _is_not_implemented("SolarEdge", "str") is False

    def test_unknown_dtype(self):
        """Unknown dtype should return False (no sentinel defined)."""
        assert _is_not_implemented(0xFFFF, "bitfield32") is False


# =============================================================================
# _raw_regs_to_value
# =============================================================================


class TestRawRegsToValue:
    """Tests for raw register to typed value conversion."""

    # u16
    def test_u16(self):
        assert _raw_regs_to_value([1234], "u16") == 1234

    def test_u16_max(self):
        assert _raw_regs_to_value([0xFFFF], "u16") == 0xFFFF

    def test_u16_zero(self):
        assert _raw_regs_to_value([0], "u16") == 0

    # i16
    def test_i16_positive(self):
        assert _raw_regs_to_value([100], "i16") == 100

    def test_i16_negative(self):
        """0x8000 = 32768 -> -32768 in signed i16."""
        assert _raw_regs_to_value([0x8000], "i16") == -32768

    def test_i16_minus_one(self):
        """0xFFFF -> -1 in signed i16."""
        assert _raw_regs_to_value([0xFFFF], "i16") == -1

    def test_i16_boundary(self):
        """32767 stays positive."""
        assert _raw_regs_to_value([32767], "i16") == 32767

    # u32
    def test_u32(self):
        assert _raw_regs_to_value([0x0001, 0x0000], "u32") == 0x00010000

    def test_u32_max(self):
        assert _raw_regs_to_value([0xFFFF, 0xFFFF], "u32") == 0xFFFFFFFF

    def test_u32_low_word_only(self):
        assert _raw_regs_to_value([0x0000, 0x0001], "u32") == 1

    def test_u32_short_regs(self):
        assert _raw_regs_to_value([1], "u32") is None

    # i32
    def test_i32_positive(self):
        assert _raw_regs_to_value([0, 1000], "i32") == 1000

    def test_i32_negative(self):
        """0x80000000 -> -2147483648."""
        assert _raw_regs_to_value([0x8000, 0x0000], "i32") == -2147483648

    def test_i32_minus_one(self):
        assert _raw_regs_to_value([0xFFFF, 0xFFFF], "i32") == -1

    # u64
    def test_u64(self):
        val = _raw_regs_to_value([0, 0, 0, 1], "u64")
        assert val == 1

    def test_u64_large(self):
        val = _raw_regs_to_value([0x0001, 0x0000, 0x0000, 0x0000], "u64")
        assert val == (1 << 48)

    def test_u64_short_regs(self):
        assert _raw_regs_to_value([1, 2], "u64") is None

    # i64
    def test_i64_negative(self):
        val = _raw_regs_to_value([0x8000, 0, 0, 0], "i64")
        assert val == -(1 << 63)

    # f32
    def test_f32_normal(self):
        """Pack 3.14 as big-endian float, split into two u16 registers."""
        raw = struct.pack(">f", 3.14)
        r0, r1 = struct.unpack(">HH", raw)
        result = _raw_regs_to_value([r0, r1], "f32")
        assert abs(result - 3.14) < 0.001

    def test_f32_nan(self):
        """NaN f32 should decode to NaN."""
        # IEEE 754 quiet NaN: 0x7FC00000
        r0, r1 = 0x7FC0, 0x0000
        result = _raw_regs_to_value([r0, r1], "f32")
        assert math.isnan(result)

    def test_f32_zero(self):
        result = _raw_regs_to_value([0, 0], "f32")
        assert result == 0.0

    def test_f32_short_regs(self):
        assert _raw_regs_to_value([1], "f32") is None

    # string
    def test_str_decode(self):
        """Pack 'AB' into a register (0x4142)."""
        result = _raw_regs_to_value([0x4142], "str")
        assert result == "AB"

    def test_str_multi_regs(self):
        result = _raw_regs_to_value([0x4142, 0x4344], "str")
        assert result == "ABCD"

    def test_str_with_nulls(self):
        """Trailing NULs should be stripped."""
        result = _raw_regs_to_value([0x4100, 0x0000], "str")
        assert result == "A"

    def test_string_alias(self):
        result = _raw_regs_to_value([0x4142], "string")
        assert result == "AB"

    # sunssf is a signed int16 scale-factor exponent
    def test_sunssf(self):
        assert _raw_regs_to_value([0xFFFC], "sunssf") == -4

    # acc16 (treated as u16)
    def test_acc16(self):
        assert _raw_regs_to_value([500], "acc16") == 500

    # acc32 (treated as u32)
    def test_acc32(self):
        assert _raw_regs_to_value([0, 500], "acc32") == 500

    # acc64 (treated as u64)
    def test_acc64(self):
        assert _raw_regs_to_value([0, 0, 0, 500], "acc64") == 500

    # empty
    def test_empty_regs(self):
        assert _raw_regs_to_value([], "u16") is None

    # unknown type falls back to regs[0]
    def test_unknown_type(self):
        assert _raw_regs_to_value([42], "bitfield16") == 42


# =============================================================================
# _load_sunspec_maps
# =============================================================================


class TestLoadSunspecMaps:
    """Tests for JSON map loading."""

    def test_returns_dict(self):
        maps = _load_sunspec_maps()
        assert isinstance(maps, dict)

    def test_known_models_present(self):
        """At least model 1 (Common) should be in the maps."""
        maps = _load_sunspec_maps()
        assert 1 in maps, "Model 1 (Common) not found in sunspec maps"

    def test_model_has_registers(self):
        maps = _load_sunspec_maps()
        if 103 in maps:
            assert "registers" in maps[103], "Model 103 map missing 'registers' key"

    def test_model_has_sunspec_model_id(self):
        maps = _load_sunspec_maps()
        for model_id, data in maps.items():
            assert data.get("sunspec_model_id") == model_id


# =============================================================================
# Security Assessment Logic (mocked mixin)
# =============================================================================


class FakeLogger:
    """Minimal logger mock for testing _sunspec_assess_security."""

    def __init__(self):
        self.findings = []
        self.messages = []

    def security_finding(self, title, category="", detail=""):
        self.findings.append({"finding": title, "category": category, "details": detail})

    def display(self, msg):
        self.messages.append(msg)

    def success(self, msg):
        self.messages.append(msg)

    def warning(self, msg):
        self.messages.append(msg)

    def debug(self, msg):
        pass


class FakeSunSpecMixin:
    """Minimal mock of SunSpecMixin for testing _sunspec_assess_security."""

    def __init__(self, results_models):
        from oida.protocols.modbus.mixins.sunspec import SunSpecMixin

        self.logger = FakeLogger()
        self.results = {"data": {"sunspec": {}}}
        self.args = type("Args", (), {"verbose": 0})()
        # Bind the method
        self._assess = SunSpecMixin._sunspec_assess_security.__get__(self, type(self))
        self._models = results_models

    def assess(self):
        self._assess(self._models)


class TestSunspecAssessSecurity:
    """Tests for the security assessment logic."""

    def _make_model(self, model_id, registers=None):
        return {"model_id": model_id, "registers": registers or {}}

    def test_no_security_models_finding(self):
        """Should emit finding when no security models (3-9) present."""
        mixin = FakeSunSpecMixin([self._make_model(1), self._make_model(103)])
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert any("No SunSpec security models" in t for t in titles)

    def test_security_models_present_no_auth_finding(self):
        """Should NOT emit auth finding when security model present."""
        mixin = FakeSunSpecMixin([self._make_model(1), self._make_model(3)])
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert not any("No SunSpec security models" in t for t in titles)

    def test_writable_controls_detected(self):
        """Should detect writable control registers from model 123."""
        regs = {
            "conn": {"value": 1, "access": "rw", "raw": 1},
            "w_max_lim_pct": {"value": 100, "access": "rw", "raw": 100},
        }
        mixin = FakeSunSpecMixin(
            [
                self._make_model(1),
                self._make_model(123, regs),
            ]
        )
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert any("writable control register" in t for t in titles)
        assert any("Conn" in t for t in titles)

    def test_conn_specific_finding(self):
        """Should emit specific Conn finding when model 123 conn is writable."""
        regs = {"conn": {"value": 1, "access": "rw", "raw": 1}}
        mixin = FakeSunSpecMixin([self._make_model(123, regs)])
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert any("Conn" in t and "writable" in t for t in titles)

    def test_set_op_specific_finding(self):
        """Should emit specific SetOp finding when model 802 set_op is writable."""
        regs = {"set_op": {"value": 1, "access": "rw", "raw": 1}}
        mixin = FakeSunSpecMixin([self._make_model(802, regs)])
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert any("SetOp" in t for t in titles)

    def test_stor_ctl_mod_specific_finding(self):
        """Should emit StorCtl_Mod finding when model 124 stor_ctl_mod is writable."""
        regs = {"stor_ctl_mod": {"value": 2, "access": "rw", "raw": 2}}
        mixin = FakeSunSpecMixin([self._make_model(124, regs)])
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert any("StorCtl_Mod" in t for t in titles)

    def test_not_implemented_registers_skipped(self):
        """Registers marked not_implemented should not be flagged."""
        regs = {"conn": {"value": None, "access": "rw", "raw": 0xFFFF, "not_implemented": True}}
        mixin = FakeSunSpecMixin([self._make_model(123, regs)])
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert not any("Conn" in t for t in titles)

    def test_active_production_with_controls(self):
        """Should emit operational risk when inverter is producing + controls exposed."""
        inv_regs = {
            "operating_state": {"raw": 4, "value": 4},
            "ac_power": {"value": 5000.0, "raw": 5000},
        }
        ctrl_regs = {"conn": {"value": 1, "access": "rw", "raw": 1}}
        mixin = FakeSunSpecMixin(
            [
                self._make_model(103, inv_regs),
                self._make_model(123, ctrl_regs),
            ]
        )
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert any("actively producing" in t for t in titles)

    def test_no_active_production_without_controls(self):
        """Active production without writable controls should not trigger finding."""
        inv_regs = {
            "operating_state": {"raw": 4, "value": 4},
            "ac_power": {"value": 5000.0, "raw": 5000},
        }
        mixin = FakeSunSpecMixin([self._make_model(103, inv_regs)])
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert not any("actively producing" in t for t in titles)

    def test_battery_remote_control(self):
        """Should emit finding when battery is in remote mode (loc_rem_ctl=0)."""
        regs = {"loc_rem_ctl": {"raw": 0, "value": 0}}
        mixin = FakeSunSpecMixin([self._make_model(802, regs)])
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert any("REMOTE control" in t for t in titles)

    def test_battery_local_control_no_finding(self):
        """loc_rem_ctl != 0 should not trigger remote control finding."""
        regs = {"loc_rem_ctl": {"raw": 1, "value": 1}}
        mixin = FakeSunSpecMixin([self._make_model(802, regs)])
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert not any("REMOTE control" in t for t in titles)

    def test_high_capacity_finding(self):
        """Should flag >=100kW devices with writable controls."""
        np_regs = {"w_rtg": {"value": 500000, "raw": 500000}}  # 500 kW
        ctrl_regs = {"conn": {"value": 1, "access": "rw", "raw": 1}}
        mixin = FakeSunSpecMixin(
            [
                self._make_model(120, np_regs),
                self._make_model(123, ctrl_regs),
            ]
        )
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert any("High-capacity" in t for t in titles)

    def test_low_capacity_no_extra_finding(self):
        """<100kW devices should not get the high-capacity finding."""
        np_regs = {"w_rtg": {"value": 10000, "raw": 10000}}  # 10 kW
        ctrl_regs = {"conn": {"value": 1, "access": "rw", "raw": 1}}
        mixin = FakeSunSpecMixin(
            [
                self._make_model(120, np_regs),
                self._make_model(123, ctrl_regs),
            ]
        )
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        assert not any("High-capacity" in t for t in titles)

    def test_findings_count_stored_in_results(self):
        """The findings count should be stored in results data."""
        mixin = FakeSunSpecMixin([self._make_model(1)])
        mixin.assess()
        sunspec = mixin.results["data"]["sunspec"]
        assert "security_findings_count" in sunspec
        assert sunspec["security_findings_count"] >= 1  # at least no-security-models

    def test_snapshot_findings_isolation(self):
        """C1 fix: pre-existing findings should not be included in sunspec results."""
        mixin = FakeSunSpecMixin([self._make_model(1)])
        # Simulate pre-existing findings from another mixin
        mixin.logger.findings.append({"finding": "pre-existing", "category": "OTHER"})
        mixin.assess()
        sunspec = mixin.results["data"]["sunspec"]
        sunspec_finding_titles = [f["finding"] for f in sunspec["security_findings"]]
        assert "pre-existing" not in sunspec_finding_titles

    def test_duplicate_model_ids_first_wins(self):
        """C2 fix: duplicate model IDs should use the first instance."""
        regs1 = {"conn": {"value": 1, "access": "rw", "raw": 1}}
        regs2 = {"conn": {"value": 0, "access": "rw", "raw": 0, "not_implemented": True}}
        mixin = FakeSunSpecMixin(
            [
                self._make_model(123, regs1),
                self._make_model(123, regs2),  # duplicate, should be ignored
            ]
        )
        mixin.assess()
        titles = [f["finding"] for f in mixin.logger.findings]
        # First model has conn=1 (implemented) so Conn finding should exist
        assert any("Conn" in t for t in titles)

    def test_empty_models(self):
        """Should handle empty model list gracefully."""
        mixin = FakeSunSpecMixin([])
        mixin.assess()
        # Should still emit no-security-models finding
        assert len(mixin.logger.findings) >= 1

    def test_no_findings_success_message(self):
        """When all security models present and no controls, should show success."""
        mixin = FakeSunSpecMixin([self._make_model(3)])
        mixin.assess()
        assert any("No security findings" in m for m in mixin.logger.messages)


# =============================================================================
# Constants validation
# =============================================================================


class TestSunspecConstants:
    """Validate constants are consistent and complete."""

    def test_security_models_are_3_to_9(self):
        assert SUNSPEC_SECURITY_MODELS == {3, 4, 5, 6, 7, 8, 9}

    def test_critical_controls_models_have_names(self):
        """All models in SUNSPEC_CRITICAL_CONTROLS should have entries in model names."""
        from oida.protocols.modbus.mixins.sunspec_constants import SUNSPEC_MODEL_NAMES

        for model_id in SUNSPEC_CRITICAL_CONTROLS:
            assert model_id in SUNSPEC_MODEL_NAMES, (
                f"Model {model_id} in CRITICAL_CONTROLS but not in MODEL_NAMES"
            )

    def test_not_implemented_covers_all_common_types(self):
        expected_types = {"u16", "i16", "u32", "i32", "u64", "i64", "f32", "str", "sunssf"}
        for t in expected_types:
            assert t in SUNSPEC_NOT_IMPLEMENTED, f"Missing sentinel for type {t}"
