#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for HART protocol scanner

Tests cover:
- hartip-py library integration
- HARTScanner class
- Command enumeration
- Security analysis
- Data classes
"""

import pytest
import struct
from unittest.mock import patch, MagicMock

from oida.protocols.hart.hartip import (
    HARTIPClient,
    HARTIPResponse,
    HARTCommand,
    HARTIPVersion,
    Device,
    MANUFACTURERS,
    UNITS,
    COMMAND_REGISTRY,
    get_vendor_name,
    get_unit_name,
    get_device_type_name,
    get_parser,
    pack_ascii,
    unpack_ascii,
    parse_cmd0,
    parse_cmd1,
    parse_cmd3,
    parse_cmd13,
    parse_cmd48,
    probe_server_version,
    decode_device_status,
    decode_extended_device_status,
    decode_cmd0_flags,
)
from oida.protocols.hart.scanner import (
    HARTScanner,
    HARTDeviceInfo,
    HARTVariable,
    HARTScanResult,
    metadata,
    LockState,
    PhysicalSignaling,
    analyze_protocol_security,
)


# ============================================================================
# Library Integration Tests
# ============================================================================


class TestLibraryIntegration:
    """Tests that the hartip-py library is properly integrated"""

    def test_library_imported(self):
        """Test that hartip-py library is available"""
        import hartip

        assert hasattr(hartip, "HARTIPClient")
        assert hasattr(hartip, "parse_cmd0")

    def test_manufacturers_from_library(self):
        """Test that MANUFACTURERS comes from the library"""
        # The library has 551 manufacturers, much more than the old fallback
        assert len(MANUFACTURERS) > 100

    def test_units_from_library(self):
        """Test that UNITS comes from the library"""
        # The library has 178 units, much more than the old fallback
        assert len(UNITS) > 50

    def test_vendor_lookup(self):
        """Test vendor name lookup via library"""
        assert get_vendor_name(0x26) == "Rosemount (Emerson)"
        assert get_vendor_name(0x17) == "Honeywell"
        assert get_vendor_name(0x2A) == "Siemens"
        assert get_vendor_name(0x37) == "Yokogawa"
        assert get_vendor_name(0x11) == "Endress+Hauser"

    def test_unit_lookup(self):
        """Test unit name lookup via library"""
        assert get_unit_name(6) == "psi"
        assert get_unit_name(7) == "bar"
        assert get_unit_name(32) == "degC"
        assert get_unit_name(33) == "degF"
        assert get_unit_name(39) == "mA"

    def test_ascii_pack_unpack(self):
        """Test HART 6-bit ASCII packing/unpacking via library"""
        text = "TEST"
        packed = pack_ascii(text)
        assert len(packed) == 3  # 4 chars -> 3 bytes

        unpacked = unpack_ascii(packed)
        assert unpacked == text.upper()

    def test_parse_cmd0(self):
        """Test Command 0 parsing via library"""
        # Build a standard Command 0 response payload
        payload = bytes(
            [
                0x00,  # Expansion code
                0x26,  # Manufacturer ID (Rosemount/Emerson)
                0x2A,  # Device type
                0x05,  # Preambles
                0x07,  # HART revision (7)
                0x05,  # Device revision
                0x02,  # Software revision
                0x10,  # HW rev (2) << 3 | signaling (0)
                0x00,  # Flags
                0x01,
                0x02,
                0x03,  # Unique ID
            ]
        )
        info = parse_cmd0(payload)
        assert info.manufacturer_id == 0x26
        assert info.device_type == 0x2A
        assert info.hart_revision == 7
        assert info.software_revision == 2

    def test_parse_cmd1(self):
        """Test Command 1 parsing via library"""
        temp_bytes = struct.pack(">f", 25.5)
        payload = bytes([32]) + temp_bytes  # 32 = degC
        var = parse_cmd1(payload)
        assert var is not None
        assert abs(var.value - 25.5) < 0.01
        assert var.unit_code == 32

    def test_parse_cmd3(self):
        """Test Command 3 parsing via library"""
        # Build payload: loop_current(4) + 4 variables * (unit(1) + value(4))
        payload = struct.pack(">f", 12.5)  # loop current
        payload += bytes([6]) + struct.pack(">f", 25.5)  # PV: psi
        payload += bytes([32]) + struct.pack(">f", 23.2)  # SV: degC
        payload += bytes([57]) + struct.pack(">f", 50.0)  # TV: %
        payload += bytes([39]) + struct.pack(">f", 12.5)  # QV: mA

        result = parse_cmd3(payload)
        assert abs(result["loop_current"] - 12.5) < 0.01
        assert len(result["variables"]) == 4
        assert result["variables"][0].label == "PV"
        assert abs(result["variables"][0].value - 25.5) < 0.01

    def test_parse_cmd13(self):
        """Test Command 13 parsing via library"""
        # Build packed tag + descriptor + date
        tag_packed = pack_ascii("PT-101".ljust(8))[:6]
        desc_packed = pack_ascii("PRESSURE SENSOR".ljust(16))[:12]
        date_bytes = bytes([15, 12, 124])  # day=15, month=12, year=124 (2024)

        payload = tag_packed + desc_packed + date_bytes
        result = parse_cmd13(payload)
        assert "tag" in result
        assert "descriptor" in result


# ============================================================================
# HART-IP Client Tests
# ============================================================================


class TestHARTIPClient:
    """Tests for HART-IP client (library-backed)"""

    def test_client_initialization(self):
        """Test client initialization"""
        client = HARTIPClient(host="192.168.1.100", port=5094, protocol="udp", timeout=5.0)

        assert client.host == "192.168.1.100"
        assert client.port == 5094
        assert client.protocol == "udp"
        assert client.timeout == 5.0
        assert not client.connected

    def test_client_default_ports(self):
        """Test default port selection based on protocol"""
        udp_client = HARTIPClient(host="192.168.1.100", protocol="udp")
        assert udp_client.port == 5094

        tcp_client = HARTIPClient(host="192.168.1.100", protocol="tcp")
        assert tcp_client.port == 5094  # Library uses 5094 for both

    def test_client_has_methods(self):
        """Test that the library client has expected methods"""
        client = HARTIPClient(host="localhost")
        assert hasattr(client, "connect")
        assert hasattr(client, "close")
        assert hasattr(client, "send_command")
        assert hasattr(client, "read_unique_id")
        assert hasattr(client, "read_primary_variable")
        assert hasattr(client, "read_tag_descriptor_date")
        assert hasattr(client, "read_additional_status")
        assert hasattr(client, "read_long_tag")


# ============================================================================
# HART Scanner Tests
# ============================================================================


class TestHARTScanner:
    """Tests for HART scanner"""

    def test_scanner_initialization(self):
        """Test scanner initialization"""
        args = {
            "rhost": "192.168.1.100",
            "rport": 5094,
            "timeout": 5,
            "protocol": "udp",
            "poll-addr": 0,
            "debug": False,
        }
        scanner = HARTScanner(args)

        assert scanner.host == "192.168.1.100"
        assert scanner.port == 5094
        assert scanner.poll_address == 0
        assert scanner.protocol_name == "HART"

    def test_scanner_default_values(self):
        """Test scanner default values"""
        scanner = HARTScanner({"rhost": "127.0.0.1"})

        assert scanner.host == "127.0.0.1"
        assert scanner.port == 5094
        assert scanner.timeout == 5

    def test_check_dependencies(self):
        """Test dependency check"""
        scanner = HARTScanner({"rhost": "127.0.0.1"})
        assert scanner.check_dependencies() is True

    def test_get_protocol_name(self):
        """Test protocol name getter"""
        scanner = HARTScanner({"rhost": "127.0.0.1"})
        assert scanner.get_protocol_name() == "HART"

    def test_get_default_port(self):
        """Test default port getter"""
        scanner = HARTScanner({"rhost": "127.0.0.1"})
        assert scanner.get_default_port() == 5094


# ============================================================================
# HART Data Classes Tests
# ============================================================================


class TestHARTDataClasses:
    """Tests for HART data classes"""

    def test_device_info(self):
        """Test HARTDeviceInfo dataclass"""
        info = HARTDeviceInfo(
            manufacturer_id=0x03,
            manufacturer_name="Emerson (Rosemount)",
            device_type=42,
            device_revision=3,
            software_revision=10,
            hardware_revision=2,
            unique_id=b"\x01\x02\x03",
            tag="SENSOR01",
            descriptor="Temperature",
            poll_address=0,
        )

        assert info.manufacturer_id == 0x03
        assert info.manufacturer_name == "Emerson (Rosemount)"
        assert info.tag == "SENSOR01"

    def test_variable(self):
        """Test HARTVariable dataclass"""
        var = HARTVariable(
            name="Primary Variable",
            value=25.5,
            units_code=32,
            units_name="degC",
            status=0,
        )

        assert var.name == "Primary Variable"
        assert var.value == 25.5
        assert var.units_name == "degC"

    def test_scan_result(self):
        """Test HARTScanResult dataclass"""
        result = HARTScanResult(
            host="192.168.1.100",
            port=5094,
            poll_address=0,
            connected=True,
        )

        assert result.host == "192.168.1.100"
        assert result.connected is True
        assert result.variables == []
        assert result.errors == []


# ============================================================================
# Metadata and Constants Tests
# ============================================================================


class TestMetadata:
    """Tests for module metadata"""

    def test_metadata(self):
        """Test metadata function"""
        meta = metadata()

        assert meta["name"] == "HART"
        assert meta["default_port"] == 5094
        assert "udp" in meta["transport"]
        assert "tcp" in meta["transport"]
        assert "tls" in meta["transport"]
        assert meta["version"] == "3.0.0"

    def test_manufacturers(self):
        """Test manufacturer lookup - using official FieldComm Group IDs"""
        assert get_vendor_name(0x26) == "Rosemount (Emerson)"
        assert get_vendor_name(0x17) == "Honeywell"
        assert get_vendor_name(0x2A) == "Siemens"
        assert get_vendor_name(0x37) == "Yokogawa"
        assert get_vendor_name(0x11) == "Endress+Hauser"

    def test_units(self):
        """Test units lookup"""
        assert get_unit_name(32) == "degC"
        assert get_unit_name(33) == "degF"
        assert get_unit_name(6) == "psi"
        assert get_unit_name(7) == "bar"

    def test_manufacturers_lookup(self):
        """Test manufacturer lookup via library"""
        assert 0x26 in MANUFACTURERS

    def test_units_lookup(self):
        """Test units lookup via library"""
        assert 32 in UNITS


# ============================================================================
# Integration Tests (with mocking)
# ============================================================================


class TestHARTScannerIntegration:
    """Integration tests for HART scanner with mocked connections"""

    @patch.object(HARTIPClient, "connect")
    @patch.object(HARTIPClient, "send_command")
    @patch.object(HARTIPClient, "read_unique_id")
    def test_read_device_info(self, mock_read_uid, mock_send, mock_connect):
        """Test reading device info with mocked responses"""
        # Build a proper Command 0 response payload
        cmd0_payload = bytes(
            [
                0x00,  # Expansion code
                0x26,  # Manufacturer ID (Rosemount/Emerson)
                0x2A,  # Device type
                0x05,  # Preambles
                0x07,  # Protocol revision
                0x05,  # Device revision
                0x02,  # Software revision
                0x10,  # HW rev (2) << 3 | signaling (0)
                0x00,  # Flags
                0x01,
                0x02,
                0x03,  # Unique ID
            ]
        )

        mock_response = MagicMock(spec=HARTIPResponse)
        mock_response.response_code = 0
        mock_response.device_status = 0
        mock_response.payload = cmd0_payload
        mock_response.pdu = MagicMock()
        # v0.3.0: set parsed to auto-dispatched result
        mock_response.parsed = parse_cmd0(cmd0_payload)

        mock_read_uid.return_value = mock_response
        mock_connect.return_value = None

        # Mock read_tag_descriptor_date to raise (simulate not available)
        mock_send.side_effect = Exception("not called")

        scanner = HARTScanner({"rhost": "192.168.1.100", "rport": 5094})
        scanner.client = HARTIPClient("192.168.1.100")

        info = scanner.read_device_info()

        assert info is not None
        assert info.manufacturer_id == 0x26
        assert "Rosemount" in info.manufacturer_name or "Emerson" in info.manufacturer_name

    @patch.object(HARTIPClient, "connect")
    @patch.object(HARTIPClient, "read_primary_variable")
    def test_read_primary_variable(self, mock_read_pv, mock_connect):
        """Test reading primary variable"""
        temp_bytes = struct.pack(">f", 25.5)
        payload = bytes([32]) + temp_bytes
        mock_response = MagicMock(spec=HARTIPResponse)
        mock_response.response_code = 0
        mock_response.device_status = 0
        mock_response.payload = payload
        # v0.3.0: set parsed to auto-dispatched result
        mock_response.parsed = parse_cmd1(payload)

        mock_read_pv.return_value = mock_response
        mock_connect.return_value = None

        scanner = HARTScanner({"rhost": "192.168.1.100"})
        scanner.client = HARTIPClient("192.168.1.100")

        pv = scanner.read_primary_variable()

        assert pv is not None
        assert pv.name == "Primary Variable"
        assert abs(pv.value - 25.5) < 0.01
        assert pv.units_name == "degC"

    @patch.object(HARTIPClient, "connect")
    @patch.object(HARTIPClient, "read_additional_status")
    def test_read_additional_status(self, mock_read_status, mock_connect):
        """Test reading additional status (Command 48) with resp.parsed"""
        mock_response = MagicMock(spec=HARTIPResponse)
        mock_response.response_code = 0
        mock_response.device_status = 0
        mock_response.payload = bytes([0x01] + [0x00] * 8)
        mock_response.parsed = {"extended_device_status": 0x01}

        mock_read_status.return_value = mock_response
        mock_connect.return_value = None

        scanner = HARTScanner({"rhost": "192.168.1.100"})
        scanner.client = HARTIPClient("192.168.1.100")

        result = scanner.read_additional_status()

        assert result is not None
        assert "extended_device_status" in result
        assert "extended_device_status_decoded" in result
        assert result["extended_device_status_decoded"]["maintenance_required"] is True


# ============================================================================
# Command Tests
# ============================================================================


class TestHARTCommands:
    """Tests for HART command constants"""

    def test_universal_commands(self):
        """Test universal command values"""
        assert HARTCommand.READ_UNIQUE_ID == 0
        assert HARTCommand.READ_PRIMARY_VARIABLE == 1
        assert HARTCommand.READ_CURRENT_AND_PERCENT == 2
        assert HARTCommand.READ_DYNAMIC_VARS == 3
        assert HARTCommand.WRITE_POLL_ADDRESS == 6

    def test_common_practice_commands(self):
        """Test common practice command values"""
        assert HARTCommand.RESET_CONFIG_FLAG == 38
        assert HARTCommand.PERFORM_SELF_TEST == 41
        assert HARTCommand.PERFORM_MASTER_RESET == 42
        assert HARTCommand.READ_ADDITIONAL_STATUS == 48

    def test_lock_commands(self):
        """Test lock-related command values"""
        assert HARTCommand.LOCK_DEVICE == 71
        assert HARTCommand.READ_LOCK_DEVICE_STATE == 76

    def test_wireless_commands(self):
        """Test WirelessHART command values"""
        assert HARTCommand.READ_LONG_TAG == 20
        assert HARTCommand.READ_SUB_DEVICE_IDENTITY == 84
        assert HARTCommand.READ_NETWORK_ID == 768


# ============================================================================
# Security Analysis Tests
# ============================================================================


class TestSecurityAnalysis:
    """Tests for security analysis functions"""

    def test_protocol_security_analysis_critical(self):
        """Test that HART 5 gets critical severity"""
        findings = analyze_protocol_security(revision=5, write_protected=False)
        finding_ids = [f.get("id") for f in findings]
        assert "HART-SEC-001" in finding_ids
        assert "HART-SEC-002" in finding_ids
        assert "HART-SEC-004" in finding_ids

        sec_001 = next(f for f in findings if f.get("id") == "HART-SEC-001")
        assert sec_001["severity"] == "critical"

    def test_protocol_security_analysis_high(self):
        """Test that HART 6 gets high severity"""
        findings = analyze_protocol_security(revision=6, write_protected=True)
        sec_001 = next(f for f in findings if f.get("id") == "HART-SEC-001")
        assert sec_001["severity"] == "high"

    def test_protocol_security_analysis_includes_encryption(self):
        """Test that analyze_protocol_security returns encryption findings"""
        findings = analyze_protocol_security(revision=5, write_protected=False)
        finding_ids = [f.get("id") for f in findings]
        assert "HART-SEC-004" in finding_ids


class TestDeviceLock:
    """Tests for device lock detection and bruteforce"""

    def test_lock_state_constants(self):
        """Test LockState constants are defined"""
        assert LockState.UNLOCKED == 0
        assert LockState.LOCKED == 1
        assert LockState.PERMANENTLY_LOCKED == 2
        assert LockState.UNKNOWN == -1
        assert LockState.NOT_SUPPORTED == -2

    def test_device_info_lock_state(self):
        """Test HARTDeviceInfo has lock_state field"""
        info = HARTDeviceInfo()
        assert info.lock_state == LockState.UNKNOWN

    def test_device_info_get_lock_state_name(self):
        """Test lock state name helper"""
        info = HARTDeviceInfo()
        info.lock_state = LockState.UNLOCKED
        assert info.get_lock_state_name() == "Unlocked"

        info.lock_state = LockState.LOCKED
        assert info.get_lock_state_name() == "Locked"

        info.lock_state = LockState.PERMANENTLY_LOCKED
        assert info.get_lock_state_name() == "Permanently Locked"

    def test_device_info_is_locked(self):
        """Test is_locked helper"""
        info = HARTDeviceInfo()
        info.lock_state = LockState.UNLOCKED
        assert not info.is_locked()

        info.lock_state = LockState.LOCKED
        assert info.is_locked()

        info.lock_state = LockState.PERMANENTLY_LOCKED
        assert info.is_locked()

    def test_central_credentials_has_hart(self):
        """Test that central credentials database includes HART"""
        from oida.utils.default_credentials import HART_LOCK_DEFAULTS, get_protocol_defaults

        assert len(HART_LOCK_DEFAULTS) > 20
        assert "" in HART_LOCK_DEFAULTS
        assert "EMERSON" in HART_LOCK_DEFAULTS
        assert "SIEMENS" in HART_LOCK_DEFAULTS

        codes = get_protocol_defaults("hart")
        assert codes == HART_LOCK_DEFAULTS

    def test_scanner_has_lock_methods(self):
        """Test HARTScanner has lock-related methods"""
        scanner = HARTScanner({"rhost": "127.0.0.1", "rport": 5094})

        assert hasattr(scanner, "read_lock_state")
        assert hasattr(scanner, "try_unlock")
        assert hasattr(scanner, "bruteforce_lock")
        assert hasattr(scanner, "lock_security_analysis")

    def test_hartip_client_has_lock_methods(self):
        """Test HARTIPClient has lock-related methods"""
        client = HARTIPClient("127.0.0.1", 5094)
        # The library client has send_command which handles all commands
        assert hasattr(client, "send_command")

    def test_hart_commands_include_lock(self):
        """Test that HART commands include lock commands"""
        assert HARTCommand.READ_LOCK_DEVICE_STATE == 76
        assert HARTCommand.LOCK_DEVICE == 71


class TestDeviceTypeNames:
    """Tests for device type name lookup"""

    def test_pressure_transmitter(self):
        """Test pressure transmitter type detection"""
        assert "Pressure" in get_device_type_name(42)

    def test_temperature_transmitter(self):
        """Test temperature transmitter type detection"""
        assert "Temperature" in get_device_type_name(51)

    def test_flow_meter(self):
        """Test flow meter type detection"""
        assert "Flow" in get_device_type_name(62)

    def test_level_transmitter(self):
        """Test level transmitter type detection"""
        assert "Level" in get_device_type_name(73)

    def test_unknown_type(self):
        """Test unknown device type"""
        name = get_device_type_name(200)
        assert name is not None
        assert len(name) > 0


class TestPhysicalSignaling:
    """Tests for physical signaling codes"""

    def test_signaling_names(self):
        """Test signaling code to name mapping"""
        assert PhysicalSignaling.get_name(0) == "Bell 202 FSK"
        assert PhysicalSignaling.get_name(2) == "FSK"
        assert PhysicalSignaling.get_name(4) == "WirelessHART"
        assert "Unknown" in PhysicalSignaling.get_name(99)


class TestGetVendorName:
    """Tests for library vendor name lookup"""

    def test_known_manufacturer(self):
        """Test known manufacturer"""
        name = get_vendor_name(0x26)
        assert "Rosemount" in name or "Emerson" in name

    def test_unknown_manufacturer(self):
        """Test unknown manufacturer returns something"""
        name = get_vendor_name(0xFF)
        assert name is not None
        assert len(name) > 0


# ============================================================================
# v0.3.0 Feature Tests
# ============================================================================


class TestV030Features:
    """Tests for hartip-py v0.3.0 features"""

    def test_library_version(self):
        """Test that hartip-py >= 0.3.0 is installed"""
        import hartip

        parts = hartip.__version__.split(".")
        major, minor = int(parts[0]), int(parts[1])
        assert (major, minor) >= (0, 3)

    def test_device_class_exists(self):
        """Test that high-level Device class is available"""
        assert Device is not None
        assert hasattr(Device, "open")
        assert hasattr(Device, "close")
        assert hasattr(Device, "primary_variable")

    def test_probe_server_version_exists(self):
        """Test that probe_server_version function is available"""
        assert callable(probe_server_version)

    def test_hartip_version_enum(self):
        """Test HARTIPVersion enum values"""
        assert HARTIPVersion.V1 == 1
        assert HARTIPVersion.V2 == 2

    def test_decode_device_status(self):
        """Test device status decoder"""
        result = decode_device_status(0x00)
        assert isinstance(result, dict)

    def test_decode_extended_device_status(self):
        """Test extended device status decoder"""
        result = decode_extended_device_status(0x01)
        assert isinstance(result, dict)
        assert result["maintenance_required"] is True

    def test_decode_cmd0_flags(self):
        """Test Command 0 flags decoder"""
        result = decode_cmd0_flags(0x80)
        assert isinstance(result, dict)

    def test_get_parser_dispatch(self):
        """Test get_parser() returns correct parser for command number"""
        parser_fn = get_parser(0)
        assert parser_fn is not None
        assert callable(parser_fn)

    def test_parse_cmd48(self):
        """Test Command 48 parsing"""
        payload = bytes([0x00] * 9)
        result = parse_cmd48(payload)
        assert result is not None

    def test_command_registry(self):
        """Test COMMAND_REGISTRY is populated"""
        assert len(COMMAND_REGISTRY) > 10
        assert 0 in COMMAND_REGISTRY
        assert 1 in COMMAND_REGISTRY

    def test_get_device_type_name_from_library(self):
        """Test that get_device_type_name comes from library (not local)"""
        name = get_device_type_name(42)
        assert "Pressure" in name

    def test_hartip_response_has_parsed(self):
        """Test that HARTIPResponse has parsed attribute"""
        assert hasattr(HARTIPResponse, "parsed")

    def test_client_has_read_lock_state(self):
        """Test HARTIPClient has read_lock_state method"""
        client = HARTIPClient("127.0.0.1", 5094)
        assert hasattr(client, "read_lock_state")

    def test_client_has_read_additional_status(self):
        """Test HARTIPClient has read_additional_status method"""
        client = HARTIPClient("127.0.0.1", 5094)
        assert hasattr(client, "read_additional_status")

    def test_scanner_tls_params(self):
        """Test scanner accepts TLS parameters"""
        scanner = HARTScanner(
            {
                "rhost": "127.0.0.1",
                "psk-identity": "test_id",
                "psk-key": "deadbeef",
                "cipher-suite": "TLS_PSK_WITH_AES_128_CCM",
            }
        )
        assert scanner.psk_identity == "test_id"
        assert scanner.psk_key == "deadbeef"
        assert scanner.cipher_suite == "TLS_PSK_WITH_AES_128_CCM"

    def test_scanner_server_version_default(self):
        """Test scanner server_version defaults to None"""
        scanner = HARTScanner({"rhost": "127.0.0.1"})
        assert scanner.server_version is None

    def test_scanner_has_probe_version(self):
        """Test scanner has probe_version method"""
        scanner = HARTScanner({"rhost": "127.0.0.1"})
        assert hasattr(scanner, "probe_version")

    def test_scanner_has_read_additional_status(self):
        """Test scanner has read_additional_status method"""
        scanner = HARTScanner({"rhost": "127.0.0.1"})
        assert hasattr(scanner, "read_additional_status")


# ============================================================================
# Pytest Markers
# ============================================================================

pytestmark = [
    pytest.mark.hart,
]
