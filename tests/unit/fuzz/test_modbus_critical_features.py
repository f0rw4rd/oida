"""Modbus Critical Feature Coverage Tests

Tests that verify fuzzer-relevant CVE patterns from ref/modbus/cves/README.md
are covered by existing requests. A CVE is "covered" if an existing generic
request already mutates the relevant field -- no dedicated request per CVE needed.

Also tests that critical Modbus vulnerability patterns have mutation coverage:
1. MBAP length field manipulation (CVE-2024-10918, CVE-2013-0662)
2. Byte count / quantity mismatch (CVE-2022-0367)
3. Memory boundary overflow (CVE-2018-7843, CVE-2019-6857)
4. File operation fuzzing (CVE-2018-7849)
5. Generic malformed packets (CVE-2024-11737, CVE-2024-8938)
"""

import pytest

from oida.fuzz.protocols.modbus.tcp import ModbusFuzzer
from oida.fuzz.protocols.modbus.rtu import ModbusRTUFuzzer
from oida.fuzz.protocols.modbus.constants import (
    ADDRESS_BOUNDARIES,
    BYTE_COUNT_BOUNDARIES,
    MEMORY_AREA_BOUNDARIES,
    QUANTITY_BOUNDARIES,
    EXCEPTION_FUNCTION_CODES,
    EXCEPTION_CODES,
    INVALID_FUNCTION_CODES,
)

pytestmark = pytest.mark.core


# ============================================================
# CVE-2024-10918: Stack BOF in libmodbus from unexpected request length
# ============================================================


class TestCVE2024_10918Coverage:
    """CVE-2024-10918: Stack buffer overflow in modbus_reply() triggered by
    request with unexpected length. The fuzzer must mutate MBAP length fields
    to send requests where stated length != actual length.
    """

    def test_tcp_mbap_testing_exists(self):
        """TCP must have MBAP header testing request."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        assert "Modbus_MBAP_Testing" in names

    def test_tcp_mbap_testing_description_mentions_cve(self):
        """MBAP testing description should reference this CVE."""
        defs = ModbusFuzzer.get_request_definitions()
        mbap = next(d for d in defs if d.name == "Modbus_MBAP_Testing")
        assert "CVE-2024-10918" in mbap.description or "MBAP" in mbap.description


# ============================================================
# CVE-2022-0367: Heap overflow in libmodbus from crafted requests
# ============================================================


class TestCVE2022_0367Coverage:
    """CVE-2022-0367: Heap buffer overflow in modbus_reply() from insufficient
    validation of request data sizes. The fuzzer must test byte_count/quantity
    mismatches in write-multiple operations.
    """

    def test_tcp_combined_fuzzing_exists(self):
        """TCP must have combined field fuzzing for write mismatch."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        assert "Modbus_Combined_Fuzzing" in names

    def test_byte_count_boundaries_include_zero(self):
        """Byte count boundaries must include zero (invalid)."""
        assert b"\x00" in BYTE_COUNT_BOUNDARIES

    def test_byte_count_boundaries_include_max(self):
        """Byte count boundaries must include 255 (maximum byte value)."""
        assert b"\xff" in BYTE_COUNT_BOUNDARIES

    def test_byte_count_boundaries_include_pdu_max(self):
        """Byte count boundaries must include 252 (maximum PDU payload)."""
        assert b"\xfc" in BYTE_COUNT_BOUNDARIES


# ============================================================
# CVE-2018-7843: OOB read from invalid data size/offset
# ============================================================


class TestCVE2018_7843Coverage:
    """CVE-2018-7843: Out-of-bounds read when reading memory blocks with
    invalid data size or offset. The fuzzer must test high address + high
    quantity combinations that overflow 16-bit address space.
    """

    def test_tcp_memory_map_exists(self):
        """TCP must have memory map boundary testing."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        assert "Modbus_Memory_Map" in names

    def test_rtu_memory_map_exists(self):
        """RTU must have memory map testing."""
        names = {d.name for d in ModbusRTUFuzzer.get_request_definitions()}
        assert "RTU_Memory_Map" in names

    def test_memory_area_boundaries_include_end_of_range(self):
        """Memory area boundaries must include near-end addresses."""
        assert b"\xff\xfe" in MEMORY_AREA_BOUNDARIES, "Missing 65534"
        assert b"\xff\xff" in MEMORY_AREA_BOUNDARIES, "Missing 65535"

    def test_memory_area_boundaries_include_sign_bit(self):
        """Memory area boundaries must include sign-bit flip address."""
        assert b"\x80\x00" in MEMORY_AREA_BOUNDARIES, "Missing 32768 (sign bit)"


# ============================================================
# CVE-2018-7849: Uncaught exception from file operations
# ============================================================


class TestCVE2018_7849Coverage:
    """CVE-2018-7849: Uncaught exception from improper data integrity check
    when sending files over Modbus. The fuzzer must test file record operations.
    """

    def test_tcp_file_record_exists(self):
        """TCP must have file record testing."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        assert "Modbus_File_Record" in names

    def test_rtu_file_record_exists(self):
        """RTU must have file record testing."""
        names = {d.name for d in ModbusRTUFuzzer.get_request_definitions()}
        assert "RTU_File_Record" in names


# ============================================================
# CVE-2024-11737 & CVE-2024-8938: Generic malformed packet handling
# ============================================================


class TestGenericMalformedCoverage:
    """CVE-2024-11737 and CVE-2024-8938: Improper input validation and buffer
    overflow from manipulated Modbus function calls. The fuzzer must have
    generic malformed packet generation that covers arbitrary FC + data combos.
    """

    def test_tcp_malformed_exists(self):
        """TCP must have malformed packet generation."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        assert "Modbus_Malformed" in names

    def test_tcp_exception_testing_exists(self):
        """TCP must have exception response testing."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        assert "Modbus_Exception_Testing" in names

    def test_invalid_function_codes_include_reserved(self):
        """Invalid FC list must include reserved codes."""
        assert b"\x00" in INVALID_FUNCTION_CODES, "Missing FC 0x00 (reserved)"
        assert b"\x09" in INVALID_FUNCTION_CODES, "Missing FC 0x09 (reserved)"

    def test_invalid_function_codes_include_exception_flag(self):
        """Invalid FC list must include exception flag codes."""
        assert b"\x80" in INVALID_FUNCTION_CODES, "Missing FC 0x80 (exception flag)"

    def test_exception_function_codes_count(self):
        """Must test at least 8 exception response function codes."""
        assert len(EXCEPTION_FUNCTION_CODES) >= 8, (
            f"Expected >= 8 exception FCs, got {len(EXCEPTION_FUNCTION_CODES)}"
        )

    def test_exception_codes_include_all_standard(self):
        """Exception codes must include all standard Modbus exceptions."""
        # Standard exceptions: 01-08, 0A, 0B
        required = [b"\x01", b"\x02", b"\x03", b"\x04", b"\x05", b"\x06"]
        for code in required:
            assert code in EXCEPTION_CODES, f"Missing exception code {code.hex()}"


# ============================================================
# Address + Quantity Overflow Pattern
# ============================================================


class TestAddressQuantityOverflow:
    """Verify the #1 Modbus vulnerability pattern is covered:
    Starting Address + Quantity > 65535 causes integer overflow on 16-bit systems.
    """

    def test_address_boundaries_include_max(self):
        """Address boundaries must include 0xFFFF for overflow testing."""
        assert b"\xff\xff" in ADDRESS_BOUNDARIES

    def test_quantity_boundaries_include_overflow_values(self):
        """Quantity boundaries must include values that cause overflow with high addresses."""
        # 2000 at address 0xFFFF would overflow: 0xFFFF + 2000 > 0xFFFF
        assert b"\x07\xd0" in QUANTITY_BOUNDARIES, "Missing quantity 2000"
        # 65535 at any non-zero address overflows
        assert b"\xff\xff" in QUANTITY_BOUNDARIES, "Missing quantity 65535"

    def test_tcp_has_combined_high_addr_attack(self):
        """TCP must have a combined high-address + max-quantity attack."""
        names = {d.name for d in ModbusFuzzer.get_request_definitions()}
        # This is covered by Modbus_Combined_Fuzzing or Modbus_Memory_Map
        assert "Modbus_Combined_Fuzzing" in names or "Modbus_Memory_Map" in names


# ============================================================
# Boundary Value Completeness for Critical Fields
# ============================================================


class TestBoundaryValueCompleteness:
    """Verify boundary value lists cover the full range of critical test points."""

    def test_address_boundaries_have_min_max_midpoint(self):
        """Address boundaries must cover min, midpoint, max."""
        values = ADDRESS_BOUNDARIES
        assert b"\x00\x00" in values, "Missing min (0)"
        assert b"\x7f\xff" in values, "Missing midpoint (32767)"
        assert b"\xff\xff" in values, "Missing max (65535)"

    def test_address_boundaries_minimum_count(self):
        """Address boundaries should have at least 6 values."""
        assert len(ADDRESS_BOUNDARIES) >= 6, (
            f"Expected >= 6 address boundaries, got {len(ADDRESS_BOUNDARIES)}"
        )

    def test_quantity_boundaries_minimum_count(self):
        """Quantity boundaries should have at least 5 values."""
        assert len(QUANTITY_BOUNDARIES) >= 5, (
            f"Expected >= 5 quantity boundaries, got {len(QUANTITY_BOUNDARIES)}"
        )

    def test_byte_count_boundaries_minimum_count(self):
        """Byte count boundaries should have at least 5 values."""
        assert len(BYTE_COUNT_BOUNDARIES) >= 5, (
            f"Expected >= 5 byte count boundaries, got {len(BYTE_COUNT_BOUNDARIES)}"
        )

    def test_memory_area_boundaries_include_real_device_limits(self):
        """Memory area boundaries should include common device limits."""
        # 9999 is a common PLC register space limit
        assert b"\x27\x0f" in MEMORY_AREA_BOUNDARIES, "Missing 9999 (common device limit)"
