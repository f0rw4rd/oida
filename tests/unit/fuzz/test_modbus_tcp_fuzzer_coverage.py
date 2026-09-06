"""Modbus TCP Fuzzer Coverage Validation Tests

Tests that enforce coverage invariants for the Modbus TCP protocol fuzzer.
These codify the audit baseline and flag regressions.

Covers:
- Minimum request count (P0 tier = 8+)
- All feature categories have coverage
- Critical CVE patterns are covered by existing requests
- PDU builder function inventory
- Boundary value list completeness
"""

import pytest

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.protocols.modbus.tcp import ModbusFuzzer
from oida.fuzz.protocols.modbus.constants import (
    ADDRESS_BOUNDARIES,
    ALL_FUNCTION_CODES,
    BYTE_COUNT_BOUNDARIES,
    COIL_VALUE_BOUNDARIES,
    MEMORY_AREA_BOUNDARIES,
    QUANTITY_BOUNDARIES,
    UNIT_ID_BOUNDARIES,
    READ_FUNCTION_CODES,
    ALL_DIAGNOSTIC_CODES,
    DEVICE_ID_READ_CODES,
    DEVICE_ID_OBJECT_IDS,
    VENDOR_FUNCTION_CODES,
    EXCEPTION_CODES,
)

pytestmark = pytest.mark.core


# ============================================================
# Tier Compliance: P0 Critical ICS requires 8+ request definitions
# ============================================================


class TestModbusTCPTierCompliance:
    """Verify Modbus TCP meets P0 (Critical ICS) minimum requirements."""

    def test_inherits_from_base_fuzzer(self):
        """ModbusFuzzer must inherit from BaseFuzzer."""
        assert issubclass(ModbusFuzzer, BaseFuzzer)

    def test_minimum_request_count(self):
        """P0 tier requires at least 8 request definitions."""
        definitions = ModbusFuzzer.get_request_definitions()
        assert len(definitions) >= 8, (
            f"P0 tier requires >= 8 request definitions, got {len(definitions)}"
        )

    def test_current_request_count(self):
        """Baseline: ModbusFuzzer should have exactly 15 request definitions."""
        definitions = ModbusFuzzer.get_request_definitions()
        assert len(definitions) == 15, (
            f"Expected 15 request definitions (current baseline), got {len(definitions)}. "
            "If you added requests, update this test."
        )

    def test_all_definitions_are_request_info(self):
        """All definitions must be RequestInfo instances."""
        definitions = ModbusFuzzer.get_request_definitions()
        for d in definitions:
            assert isinstance(d, RequestInfo), f"Definition {d} is not a RequestInfo instance"

    def test_all_definitions_have_names(self):
        """All definitions must have non-empty names."""
        definitions = ModbusFuzzer.get_request_definitions()
        for d in definitions:
            assert d.name and len(d.name) > 0, f"Definition has empty name: {d}"

    def test_no_duplicate_names(self):
        """All request definition names must be unique."""
        definitions = ModbusFuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert len(names) == len(set(names)), (
            f"Duplicate request names found: {[n for n in names if names.count(n) > 1]}"
        )


# ============================================================
# Category Balance: Multi-category protocol needs all categories
# ============================================================


class TestModbusTCPCategoryBalance:
    """Verify all required feature categories have at least one request."""

    REQUIRED_CATEGORIES = {"baseline", "read", "write", "boundary", "protocol"}
    OPTIONAL_CATEGORIES = {"broadcast", "special"}

    def test_required_categories_covered(self):
        """Every required category must have at least one request."""
        definitions = ModbusFuzzer.get_request_definitions()
        categories = {d.category for d in definitions}
        missing = self.REQUIRED_CATEGORIES - categories
        assert not missing, (
            f"Missing required categories: {missing}. Present categories: {sorted(categories)}"
        )

    def test_optional_categories_present(self):
        """Optional categories should also be present (soft check)."""
        definitions = ModbusFuzzer.get_request_definitions()
        categories = {d.category for d in definitions}
        missing = self.OPTIONAL_CATEGORIES - categories
        if missing:
            pytest.skip(f"Optional categories missing (not a failure): {missing}")

    def test_baseline_is_first(self):
        """Baseline request should be first in the list for early validation."""
        definitions = ModbusFuzzer.get_request_definitions()
        assert definitions[0].category == "baseline", (
            f"First request should be 'baseline' category, got '{definitions[0].category}'"
        )

    def test_read_requests_count(self):
        """Should have multiple read-category requests."""
        definitions = ModbusFuzzer.get_request_definitions()
        reads = [d for d in definitions if d.category == "read"]
        assert len(reads) >= 3, f"Expected >= 3 read requests, got {len(reads)}"

    def test_write_requests_count(self):
        """Should have multiple write-category requests."""
        definitions = ModbusFuzzer.get_request_definitions()
        writes = [d for d in definitions if d.category == "write"]
        assert len(writes) >= 2, f"Expected >= 2 write requests, got {len(writes)}"

    def test_boundary_requests_count(self):
        """Should have multiple boundary-category requests."""
        definitions = ModbusFuzzer.get_request_definitions()
        boundaries = [d for d in definitions if d.category == "boundary"]
        assert len(boundaries) >= 2, f"Expected >= 2 boundary requests, got {len(boundaries)}"


# ============================================================
# Critical Feature Coverage: CVE patterns must be covered
# ============================================================


class TestModbusTCPCriticalFeatures:
    """Verify fuzzer-relevant CVE patterns are covered by existing requests."""

    def _get_request_names(self):
        return {d.name for d in ModbusFuzzer.get_request_definitions()}

    def test_mbap_length_overflow_covered(self):
        """CVE-2024-10918: MBAP length mismatch must have dedicated testing.

        The libmodbus stack overflow is triggered by unexpected request length.
        The fuzzer must have MBAP header testing requests.
        """
        names = self._get_request_names()
        assert "Modbus_MBAP_Testing" in names, (
            "Missing Modbus_MBAP_Testing -- CVE-2024-10918 requires MBAP length overflow testing"
        )

    def test_write_multiple_byte_count_mismatch_covered(self):
        """CVE-2022-0367: Heap overflow in modbus_reply from crafted requests.

        The fuzzer must test byte_count/quantity mismatches in write-multiple operations.
        """
        names = self._get_request_names()
        assert "Modbus_Combined_Fuzzing" in names, (
            "Missing Modbus_Combined_Fuzzing -- CVE-2022-0367 requires byte count mismatch testing"
        )

    def test_memory_overflow_covered(self):
        """CVE-2018-7843: OOB read from invalid address+size combinations.

        The fuzzer must test high address + high quantity overflow patterns.
        """
        names = self._get_request_names()
        assert "Modbus_Memory_Map" in names, (
            "Missing Modbus_Memory_Map -- CVE-2018-7843 requires memory boundary testing"
        )

    def test_boundary_testing_covered(self):
        """CVE-2015-6490: Stack BOF from crafted Modbus TCP packets.

        The fuzzer must have comprehensive boundary value testing.
        """
        names = self._get_request_names()
        assert "Modbus_Boundary_Testing" in names, (
            "Missing Modbus_Boundary_Testing -- CVE-2015-6490 requires boundary fuzzing"
        )

    def test_file_record_covered(self):
        """CVE-2018-7849: Uncaught exception from file operations.

        The fuzzer must test file record operations (FC 14/15).
        """
        names = self._get_request_names()
        assert "Modbus_File_Record" in names, (
            "Missing Modbus_File_Record -- CVE-2018-7849 requires file record testing"
        )

    def test_exception_testing_covered(self):
        """Exception response handling is a common vulnerability pattern.

        The fuzzer must test exception response frames.
        """
        names = self._get_request_names()
        assert "Modbus_Exception_Testing" in names, (
            "Missing Modbus_Exception_Testing -- exception handling bugs require error testing"
        )

    def test_malformed_packets_covered(self):
        """Generic malformed packets catch implementation-specific parsing bugs.

        The fuzzer must have malformed/random packet generation.
        """
        names = self._get_request_names()
        assert "Modbus_Malformed" in names, (
            "Missing Modbus_Malformed -- malformed packet generation is essential"
        )


# ============================================================
# Protocol Constants Completeness
# ============================================================


class TestModbusTCPConstantsCompleteness:
    """Verify boundary value lists are comprehensive."""

    def test_all_19_standard_function_codes(self):
        """ALL_FUNCTION_CODES must contain all 19 standard Modbus FCs."""
        assert len(ALL_FUNCTION_CODES) == 19, (
            f"Expected 19 standard FCs, got {len(ALL_FUNCTION_CODES)}"
        )

    def test_read_function_codes_complete(self):
        """READ_FUNCTION_CODES must contain FC 01, 02, 03, 04."""
        assert len(READ_FUNCTION_CODES) == 4
        expected = [b"\x01", b"\x02", b"\x03", b"\x04"]
        for fc in expected:
            assert fc in READ_FUNCTION_CODES, f"Missing read FC: {fc.hex()}"

    def test_address_boundaries_include_extremes(self):
        """Address boundaries must include 0, 32767, 32768, 65535."""
        assert b"\x00\x00" in ADDRESS_BOUNDARIES, "Missing address 0"
        assert b"\x7f\xff" in ADDRESS_BOUNDARIES, "Missing address 32767"
        assert b"\x80\x00" in ADDRESS_BOUNDARIES, "Missing address 32768 (sign bit)"
        assert b"\xff\xff" in ADDRESS_BOUNDARIES, "Missing address 65535"

    def test_quantity_boundaries_include_protocol_max(self):
        """Quantity boundaries must include 0, 1, 2000 (max), and 65535."""
        assert b"\x00\x00" in QUANTITY_BOUNDARIES, "Missing quantity 0"
        assert b"\x00\x01" in QUANTITY_BOUNDARIES, "Missing quantity 1"
        assert b"\x07\xd0" in QUANTITY_BOUNDARIES, "Missing quantity 2000 (protocol max)"
        assert b"\xff\xff" in QUANTITY_BOUNDARIES, "Missing quantity 65535"

    def test_quantity_boundaries_include_max_plus_one(self):
        """Quantity boundaries should include 2001 (one over protocol max)."""
        assert b"\x07\xd1" in QUANTITY_BOUNDARIES, "Missing quantity 2001 (max+1 boundary)"

    def test_byte_count_boundaries_include_extremes(self):
        """Byte count boundaries must include 0, 1, 252 (max PDU), 255."""
        assert b"\x00" in BYTE_COUNT_BOUNDARIES, "Missing byte count 0"
        assert b"\x01" in BYTE_COUNT_BOUNDARIES, "Missing byte count 1"
        assert b"\xfc" in BYTE_COUNT_BOUNDARIES, "Missing byte count 252 (max PDU)"
        assert b"\xff" in BYTE_COUNT_BOUNDARIES, "Missing byte count 255"

    def test_coil_value_boundaries_include_valid_and_invalid(self):
        """Coil value boundaries must include valid (0x0000, 0xFF00) and invalid."""
        assert b"\x00\x00" in COIL_VALUE_BOUNDARIES, "Missing coil OFF"
        assert b"\xff\x00" in COIL_VALUE_BOUNDARIES, "Missing coil ON"
        # At least one invalid value
        invalid_count = sum(1 for v in COIL_VALUE_BOUNDARIES if v not in (b"\x00\x00", b"\xff\x00"))
        assert invalid_count >= 2, "Need at least 2 invalid coil values"

    def test_unit_id_boundaries_cover_full_range(self):
        """Unit ID boundaries must include broadcast, valid, and reserved."""
        assert b"\x00" in UNIT_ID_BOUNDARIES, "Missing broadcast (0)"
        assert b"\x01" in UNIT_ID_BOUNDARIES, "Missing minimum valid (1)"
        assert b"\xf7" in UNIT_ID_BOUNDARIES, "Missing maximum valid (247)"
        assert b"\xff" in UNIT_ID_BOUNDARIES, "Missing reserved (255)"

    def test_exception_codes_count(self):
        """Must have at least 8 exception codes."""
        assert len(EXCEPTION_CODES) >= 8, (
            f"Expected >= 8 exception codes, got {len(EXCEPTION_CODES)}"
        )

    def test_diagnostic_codes_count(self):
        """Must have at least 14 diagnostic sub-function codes."""
        assert len(ALL_DIAGNOSTIC_CODES) >= 14, (
            f"Expected >= 14 diagnostic codes, got {len(ALL_DIAGNOSTIC_CODES)}"
        )

    def test_device_id_read_codes_count(self):
        """Must have 4 device ID read codes (basic, regular, extended, specific)."""
        assert len(DEVICE_ID_READ_CODES) == 4

    def test_device_id_object_ids_include_vendor_specific(self):
        """Device ID object IDs must include vendor-specific range."""
        assert b"\x80" in DEVICE_ID_OBJECT_IDS, "Missing vendor-specific start (0x80)"

    def test_vendor_function_codes_count(self):
        """Must have at least 5 vendor function codes (FC 0x44-0x48)."""
        assert len(VENDOR_FUNCTION_CODES) >= 5, (
            f"Expected >= 5 vendor FCs, got {len(VENDOR_FUNCTION_CODES)}"
        )

    def test_memory_area_boundaries_count(self):
        """Memory area boundaries should have at least 6 values."""
        assert len(MEMORY_AREA_BOUNDARIES) >= 6, (
            f"Expected >= 6 memory area boundaries, got {len(MEMORY_AREA_BOUNDARIES)}"
        )


# ============================================================
# PDU Builder Inventory
# ============================================================


class TestModbusTCPPDUBuilders:
    """Verify all PDU builder functions exist and are callable."""

    PDU_BUILDERS = [
        "create_quick_fc_pdu",
        "create_baseline_read_pdu",
        "create_read_pdu",
        "create_write_single_pdu",
        "create_write_multiple_pdu",
        "create_diagnostics_pdu",
        "create_file_record_pdu",
        "create_mask_write_pdu",
        "create_read_write_multiple_pdu",
        "create_device_id_pdu",
        "create_canopen_mei_pdu",
        "create_read_exception_status_pdu",
        "create_get_comm_event_counter_pdu",
        "create_get_comm_event_log_pdu",
        "create_report_slave_id_pdu",
        "create_read_fifo_queue_pdu",
        "create_vendor_functions_pdu",
        "create_address_boundary_pdu",
        "create_quantity_boundary_pdu",
        "create_byte_count_boundary_pdu",
        "create_coil_value_boundary_pdu",
        "create_register_value_boundary_pdu",
        "create_coils_boundary_pdu",
        "create_discrete_inputs_boundary_pdu",
        "create_input_registers_boundary_pdu",
        "create_holding_registers_boundary_pdu",
        "create_write_coils_boundary_pdu",
        "create_write_registers_boundary_pdu",
        "create_memory_overflow_pdu",
        "create_exception_responses_pdu",
        "create_trigger_illegal_address_pdu",
        "create_trigger_illegal_value_pdu",
        "create_trigger_illegal_function_pdu",
        "create_combined_invalid_fc_address_pdu",
        "create_combined_zero_quantity_pdu",
        "create_combined_byte_count_mismatch_pdu",
        "create_combined_oversized_pdu",
        "create_combined_high_addr_max_qty_pdu",
        "create_malformed_pdu",
        "create_user_defined_pdu",
        "create_error_testing_pdu",
    ]

    @pytest.mark.parametrize("builder_name", PDU_BUILDERS)
    def test_pdu_builder_exists(self, builder_name):
        """Each PDU builder function must exist in pdu module."""
        from oida.fuzz.protocols.modbus import pdu

        assert hasattr(pdu, builder_name), f"PDU builder {builder_name} not found in pdu module"

    @pytest.mark.parametrize("builder_name", PDU_BUILDERS)
    def test_pdu_builder_callable(self, builder_name):
        """Each PDU builder must be callable."""
        from oida.fuzz.protocols.modbus import pdu

        func = getattr(pdu, builder_name)
        assert callable(func), f"{builder_name} is not callable"

    def test_pdu_builder_count(self):
        """Baseline: pdu.py should have at least 32 builder functions."""
        from oida.fuzz.protocols.modbus import pdu

        builders = [
            name for name in dir(pdu) if name.startswith("create_") and callable(getattr(pdu, name))
        ]
        assert len(builders) >= 32, (
            f"Expected >= 32 PDU builders, got {len(builders)}: {sorted(builders)}"
        )


# ============================================================
# Protocol Options Validation
# ============================================================


class TestModbusTCPProtocolOptions:
    """Verify protocol options are complete and well-typed."""

    REQUIRED_OPTIONS = [
        "transport",
        "unit_id",
        "transaction_id",
        "timeout",
        "enable_write",
        "enable_broadcast",
    ]

    def test_protocol_options_defined(self):
        """PROTOCOL_OPTIONS must be defined."""
        assert hasattr(ModbusFuzzer, "PROTOCOL_OPTIONS")
        assert isinstance(ModbusFuzzer.PROTOCOL_OPTIONS, dict)

    @pytest.mark.parametrize("option_name", REQUIRED_OPTIONS)
    def test_required_option_exists(self, option_name):
        """Each required option must be present."""
        assert option_name in ModbusFuzzer.PROTOCOL_OPTIONS, (
            f"Missing required option: {option_name}"
        )

    def test_transport_choices(self):
        """Transport option must support tcp and udp."""
        opt = ModbusFuzzer.PROTOCOL_OPTIONS["transport"]
        assert "tcp" in opt.get("choices", [])
        assert "udp" in opt.get("choices", [])

    def test_unit_id_default(self):
        """Unit ID default should be 1 (standard slave address)."""
        opt = ModbusFuzzer.PROTOCOL_OPTIONS["unit_id"]
        assert opt["default"] == 1

    def test_monitor_options_present(self):
        """Monitor configuration options should be present."""
        options = ModbusFuzzer.PROTOCOL_OPTIONS
        assert "monitor_timeout" in options
        assert "monitor_retry_count" in options
        assert "monitor_failure_threshold" in options


# ============================================================
# Capability Enumeration
# ============================================================


class TestModbusTCPCapabilityEnumeration:
    """Verify capability enumeration method exists."""

    def test_enumerate_capabilities_method_exists(self):
        """ModbusFuzzer must have _enumerate_capabilities method."""
        assert hasattr(ModbusFuzzer, "_enumerate_capabilities")

    def test_supports_function_code_method_exists(self):
        """ModbusFuzzer must have _supports_function_code method."""
        assert hasattr(ModbusFuzzer, "_supports_function_code")


# ============================================================
# Monitor Integration
# ============================================================


class TestModbusTCPMonitorIntegration:
    """Verify monitor setup is configured."""

    def test_default_monitors_configured(self):
        """DEFAULT_MONITORS must be set for Modbus health checking."""
        assert hasattr(ModbusFuzzer, "DEFAULT_MONITORS")
        assert ModbusFuzzer.DEFAULT_MONITORS is not None
        # Should reference modbus monitor
        assert "modbus" in ModbusFuzzer.DEFAULT_MONITORS.lower()

    def test_setup_custom_monitors_method_exists(self):
        """setup_custom_monitors must be implemented."""
        assert hasattr(ModbusFuzzer, "setup_custom_monitors")
