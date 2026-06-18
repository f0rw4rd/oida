"""Modbus Fuzzer Balance Validation Tests

Tests that verify both Modbus TCP and RTU fuzzers have balanced coverage
across feature categories, and that the RTU fuzzer maintains parity with
TCP on critical features.

Covers:
- Category distribution balance
- TCP/RTU feature parity on critical items
- Request ordering (baseline first, high-crash early)
"""

import pytest

from oida.fuzz.protocols.modbus.tcp import ModbusFuzzer
from oida.fuzz.protocols.modbus.rtu import ModbusRTUFuzzer

pytestmark = pytest.mark.core


# ============================================================
# Category Distribution
# ============================================================


class TestCategoryDistribution:
    """Verify request category distribution is balanced."""

    def _get_category_counts(self, fuzzer_class):
        defs = fuzzer_class.get_request_definitions()
        counts = {}
        for d in defs:
            counts[d.category] = counts.get(d.category, 0) + 1
        return counts

    def test_tcp_no_single_category_dominates(self):
        """No single category should have more than 40% of all TCP requests."""
        counts = self._get_category_counts(ModbusFuzzer)
        total = sum(counts.values())
        for cat, count in counts.items():
            pct = count / total * 100
            assert pct <= 40, (
                f"TCP category '{cat}' has {pct:.0f}% of requests ({count}/{total}). "
                "Max allowed is 40%."
            )

    def test_rtu_no_single_category_dominates(self):
        """No single category should have more than 40% of all RTU requests."""
        counts = self._get_category_counts(ModbusRTUFuzzer)
        total = sum(counts.values())
        for cat, count in counts.items():
            pct = count / total * 100
            assert pct <= 40, (
                f"RTU category '{cat}' has {pct:.0f}% of requests ({count}/{total}). "
                "Max allowed is 40%."
            )

    def test_tcp_has_at_least_5_categories(self):
        """TCP fuzzer should cover at least 5 distinct categories."""
        counts = self._get_category_counts(ModbusFuzzer)
        assert len(counts) >= 5, (
            f"TCP has only {len(counts)} categories: {sorted(counts.keys())}. Expected >= 5."
        )

    def test_rtu_has_at_least_4_categories(self):
        """RTU fuzzer should cover at least 4 distinct categories."""
        counts = self._get_category_counts(ModbusRTUFuzzer)
        assert len(counts) >= 4, (
            f"RTU has only {len(counts)} categories: {sorted(counts.keys())}. Expected >= 4."
        )


# ============================================================
# TCP/RTU Feature Parity on Critical Items
# ============================================================


class TestTCPRTUParity:
    """Verify RTU has coverage for critical features that TCP covers."""

    def _get_names(self, fuzzer_class):
        return {d.name for d in fuzzer_class.get_request_definitions()}

    def _get_categories(self, fuzzer_class):
        return {d.category for d in fuzzer_class.get_request_definitions()}

    def test_both_have_baseline(self):
        """Both fuzzers must have a baseline request."""
        tcp_names = self._get_names(ModbusFuzzer)
        rtu_names = self._get_names(ModbusRTUFuzzer)
        tcp_has = any("Baseline" in n for n in tcp_names)
        rtu_has = any("Baseline" in n for n in rtu_names)
        assert tcp_has, "TCP missing baseline request"
        assert rtu_has, "RTU missing baseline request"

    def test_both_have_read_operations(self):
        """Both fuzzers must have read operation requests."""
        tcp_cats = self._get_categories(ModbusFuzzer)
        rtu_cats = self._get_categories(ModbusRTUFuzzer)
        assert "read" in tcp_cats, "TCP missing 'read' category"
        assert "read" in rtu_cats, "RTU missing 'read' category"

    def test_both_have_write_operations(self):
        """Both fuzzers must have write operation requests."""
        tcp_cats = self._get_categories(ModbusFuzzer)
        rtu_cats = self._get_categories(ModbusRTUFuzzer)
        assert "write" in tcp_cats, "TCP missing 'write' category"
        assert "write" in rtu_cats, "RTU missing 'write' category"

    def test_both_have_boundary_testing(self):
        """Both fuzzers must have boundary testing requests."""
        tcp_cats = self._get_categories(ModbusFuzzer)
        rtu_cats = self._get_categories(ModbusRTUFuzzer)
        assert "boundary" in tcp_cats, "TCP missing 'boundary' category"
        assert "boundary" in rtu_cats, "RTU missing 'boundary' category"

    def test_both_have_broadcast(self):
        """Both fuzzers must have broadcast testing requests."""
        tcp_cats = self._get_categories(ModbusFuzzer)
        rtu_cats = self._get_categories(ModbusRTUFuzzer)
        assert "broadcast" in tcp_cats, "TCP missing 'broadcast' category"
        assert "broadcast" in rtu_cats, "RTU missing 'broadcast' category"

    def test_rtu_has_diagnostics(self):
        """RTU should have diagnostics coverage (TCP has it)."""
        rtu_names = self._get_names(ModbusRTUFuzzer)
        assert any("Diagnostics" in n or "Diagnostic" in n for n in rtu_names), (
            "RTU missing diagnostics request"
        )

    def test_rtu_has_device_id(self):
        """RTU should have device identification (TCP has it)."""
        rtu_names = self._get_names(ModbusRTUFuzzer)
        assert any("Device_ID" in n or "Device_Identification" in n for n in rtu_names), (
            "RTU missing device identification request"
        )

    def test_rtu_has_overflow_testing(self):
        """RTU should have overflow/buffer attack testing."""
        rtu_names = self._get_names(ModbusRTUFuzzer)
        assert any("Overflow" in n for n in rtu_names), "RTU missing overflow testing request"


# ============================================================
# Request Ordering
# ============================================================


class TestRequestOrdering:
    """Verify requests are ordered for maximum early coverage."""

    def test_tcp_baseline_is_first(self):
        """TCP baseline should be the first request definition."""
        defs = ModbusFuzzer.get_request_definitions()
        assert defs[0].name == "Modbus_Baseline", (
            f"First TCP request should be Modbus_Baseline, got {defs[0].name}"
        )

    def test_rtu_baseline_is_first(self):
        """RTU baseline should be the first request definition."""
        defs = ModbusRTUFuzzer.get_request_definitions()
        assert defs[0].name == "RTU_Baseline", (
            f"First RTU request should be RTU_Baseline, got {defs[0].name}"
        )

    def test_tcp_high_crash_before_standard(self):
        """TCP high-crash tests should come before standard reads."""
        defs = ModbusFuzzer.get_request_definitions()
        names = [d.name for d in defs]
        mbap_idx = names.index("Modbus_MBAP_Testing")
        read_idx = names.index("Modbus_Read_Operations")
        assert mbap_idx < read_idx, (
            f"MBAP testing (idx {mbap_idx}) should come before read operations (idx {read_idx})"
        )

    def test_rtu_overflow_before_standard(self):
        """RTU overflow tests should come before standard reads."""
        defs = ModbusRTUFuzzer.get_request_definitions()
        names = [d.name for d in defs]
        overflow_idx = names.index("RTU_Overflow_Testing")
        read_idx = names.index("RTU_Read_Operations")
        assert overflow_idx < read_idx, (
            f"Overflow testing (idx {overflow_idx}) should come before "
            f"read operations (idx {read_idx})"
        )


# ============================================================
# RTU-Specific Feature Requirements
# ============================================================


class TestRTUSpecificFeatures:
    """Verify RTU-specific features are present."""

    def test_rtu_has_overflow_testing(self):
        """RTU must test frame overflow (256-byte ADU limit)."""
        names = {d.name for d in ModbusRTUFuzzer.get_request_definitions()}
        assert "RTU_Overflow_Testing" in names

    def test_rtu_has_file_record(self):
        """RTU should have file record operation testing."""
        names = {d.name for d in ModbusRTUFuzzer.get_request_definitions()}
        assert "RTU_File_Record" in names

    def test_rtu_has_invalid_fc(self):
        """RTU should test invalid function codes."""
        names = {d.name for d in ModbusRTUFuzzer.get_request_definitions()}
        assert "RTU_Invalid_FC" in names

    def test_rtu_has_memory_map(self):
        """RTU should have memory map boundary testing."""
        names = {d.name for d in ModbusRTUFuzzer.get_request_definitions()}
        assert "RTU_Memory_Map" in names


# ============================================================
# TCP-Specific Feature Requirements
# ============================================================


class TestTCPSpecificFeatures:
    """Verify TCP-specific features are present."""

    def test_tcp_has_mbap_testing(self):
        """TCP must test MBAP header (not applicable to RTU)."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        assert "Modbus_MBAP_Testing" in names

    def test_tcp_has_combined_fuzzing(self):
        """TCP must have combined field fuzzing."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        assert "Modbus_Combined_Fuzzing" in names

    def test_tcp_has_system_functions(self):
        """TCP should test vendor/system functions."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        assert "Modbus_System_Functions" in names

    def test_tcp_has_user_defined(self):
        """TCP should test user-defined function codes."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        assert "Modbus_User_Defined" in names

    def test_tcp_has_malformed(self):
        """TCP should have malformed packet generation."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        assert "Modbus_Malformed" in names
