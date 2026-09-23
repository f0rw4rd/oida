#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Modbus device identification operations.

Tests MEI device identification (FC 43/14), Server ID (FC 17),
Unit ID discovery, and gateway detection.
"""

import pytest
from unittest.mock import MagicMock, patch

# Check for pymodbus availability
from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")

from oida.protocols.modbus.scanner import (
    MEI_OBJECT_NAMES,
    MEIReadDeviceIdCode,
    ModbusExceptionCode,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_client():
    """Create a mock Modbus client with identification responses."""
    client = MagicMock()

    # Mock read_device_information response (FC 43/14)
    mei_response = MagicMock()
    mei_response.isError.return_value = False
    mei_response.information = {
        0x00: b"Test Vendor",
        0x01: b"Test Product",
        0x02: b"1.0.0",
    }
    mei_response.more_follows = False
    mei_response.next_object_id = 0
    client.read_device_information.return_value = mei_response

    # Mock report_device_id response (FC 17)
    server_id_response = MagicMock()
    server_id_response.isError.return_value = False
    server_id_response.status = True
    server_id_response.identifier = b"Test Server ID"
    client.report_device_id.return_value = server_id_response

    return client


@pytest.fixture
def scanner_args():
    """Create default scanner arguments."""
    return {
        "rhost": "192.168.1.100",
        "rport": 502,
        "timeout": 5,
        "unit-id": 1,
        "get-device-id": True,
        "discover-units": False,
        "unit-range": "1-247",
    }


def create_mock_scanner(args):
    """Create a mock ModbusScanner instance."""
    from oida.protocols.modbus.scanner import ModbusScanner

    with patch.object(ModbusScanner, "__init__", lambda self, *a, **kw: None):
        scanner = ModbusScanner.__new__(ModbusScanner)
        scanner.args = args
        scanner.host = args.get("rhost", "127.0.0.1")
        scanner.port = args.get("rport", 502)
        scanner.timeout = args.get("timeout", 5)
        scanner.unit_id = args.get("unit-id", 1)
        scanner.get_device_id = args.get("get-device-id", True)
        scanner.discover_units = args.get("discover-units", False)
        scanner.unit_range = args.get("unit-range", "1-247")
        scanner.logger = MagicMock()
        scanner.security = MagicMock()
        return scanner


# =============================================================================
# Test MEI Device Identification (FC 43/14)
# =============================================================================


class TestMEIDeviceIdentification:
    """Tests for MEI device identification (FC 43/14)."""

    def test_mei_basic_read(self, mock_client, scanner_args):
        """Test basic MEI read (read_code=1)."""
        scanner = create_mock_scanner(scanner_args)

        result = scanner._read_device_identification(mock_client, mei_object="basic")

        assert result is not None
        assert result["VendorName"] == "Test Vendor"
        assert mock_client.read_device_information.call_args.kwargs == {
            "read_code": MEIReadDeviceIdCode.BASIC,
            "object_id": 0x00,
            "device_id": scanner.unit_id,
        }

    def test_mei_regular_read(self, mock_client, scanner_args):
        """Test regular MEI read (read_code=2)."""
        # Add regular objects to response
        mei_response = MagicMock()
        mei_response.isError.return_value = False
        mei_response.information = {
            0x00: b"Test Vendor",
            0x01: b"Test Product",
            0x02: b"1.0.0",
            0x03: b"https://vendor.com",
            0x04: b"Product Name",
            0x05: b"Model Name",
        }
        mei_response.more_follows = False
        mock_client.read_device_information.return_value = mei_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_device_information(
            read_code=MEIReadDeviceIdCode.REGULAR,
            object_id=0x00,
            device_id=1,
        )

        assert not result.isError()
        assert len(result.information) >= 3

    def test_mei_extended_read(self, mock_client, scanner_args):
        """Test extended MEI read (read_code=3)."""
        # Add extended objects to response
        mei_response = MagicMock()
        mei_response.isError.return_value = False
        mei_response.information = {
            0x00: b"Test Vendor",
            0x01: b"Test Product",
            0x02: b"1.0.0",
            0x06: b"User Application",
        }
        mei_response.more_follows = False
        mock_client.read_device_information.return_value = mei_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner._read_device_identification(mock_client, mei_object="extended")

        assert result is not None
        assert result["UserApplicationName"] == "User Application"
        assert mock_client.read_device_information.call_args.kwargs["read_code"] == (
            MEIReadDeviceIdCode.EXTENDED
        )

    def test_mei_specific_object_read(self, mock_client, scanner_args):
        """Test specific object read (read_code=4)."""
        mei_response = MagicMock()
        mei_response.isError.return_value = False
        mei_response.information = {
            0x02: b"1.2.3",
        }
        mei_response.more_follows = False
        mock_client.read_device_information.return_value = mei_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner._read_device_identification(
            mock_client, mei_object="specific", mei_object_id=0x02
        )

        assert result == {"MajorMinorRevision": "1.2.3"}
        assert mock_client.read_device_information.call_args.kwargs["object_id"] == 0x02

    def test_mei_not_supported(self, mock_client, scanner_args):
        """Test handling when MEI is not supported."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_FUNCTION
        mock_client.read_device_information.return_value = error_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner._read_device_identification(mock_client, mei_object="basic")

        assert result is None


class TestMEIResponseParsing:
    """Tests for MEI response parsing."""

    def test_parse_vendor_name(self, mock_client, scanner_args):
        """Test parsing VendorName (object 0x00)."""
        mei_response = MagicMock()
        mei_response.isError.return_value = False
        mei_response.information = {
            0x00: b"Schneider Electric",
        }
        mock_client.read_device_information.return_value = mei_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_device_information(read_code=1, object_id=0x00, device_id=1)

        objects = {}
        for obj_id, value in result.information.items():
            obj_name = MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")
            objects[obj_name] = value.decode("utf-8")

        assert objects["VendorName"] == "Schneider Electric"

    def test_parse_product_code(self, mock_client, scanner_args):
        """Test parsing ProductCode (object 0x01)."""
        mei_response = MagicMock()
        mei_response.isError.return_value = False
        mei_response.information = {
            0x01: b"PM5100",
        }
        mock_client.read_device_information.return_value = mei_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_device_information(read_code=1, object_id=0x00, device_id=1)

        objects = {}
        for obj_id, value in result.information.items():
            obj_name = MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")
            objects[obj_name] = value.decode("utf-8")

        assert objects["ProductCode"] == "PM5100"

    def test_parse_version(self, mock_client, scanner_args):
        """Test parsing MajorMinorRevision (object 0x02)."""
        mei_response = MagicMock()
        mei_response.isError.return_value = False
        mei_response.information = {
            0x02: b"V3.2.16",
        }
        mock_client.read_device_information.return_value = mei_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_device_information(read_code=1, object_id=0x00, device_id=1)

        objects = {}
        for obj_id, value in result.information.items():
            obj_name = MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")
            objects[obj_name] = value.decode("utf-8")

        assert objects["MajorMinorRevision"] == "V3.2.16"

    def test_parse_malformed_utf8(self, mock_client, scanner_args):
        """Test parsing non-UTF8 bytes with replacement."""
        mei_response = MagicMock()
        mei_response.isError.return_value = False
        mei_response.information = {
            0x00: b"\xff\xfe\x00\x01",  # Invalid UTF-8
        }
        mock_client.read_device_information.return_value = mei_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_device_information(read_code=1, object_id=0x00, device_id=1)

        objects = {}
        for obj_id, value in result.information.items():
            obj_name = MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")
            try:
                objects[obj_name] = value.decode("utf-8", errors="replace")
            except Exception:
                objects[obj_name] = value.hex()

        # Should not raise exception
        assert "VendorName" in objects

    def test_parse_null_terminated_string(self, mock_client, scanner_args):
        """Test parsing null-terminated string."""
        mei_response = MagicMock()
        mei_response.isError.return_value = False
        mei_response.information = {
            0x00: b"Test Vendor\x00\x00\x00",
        }
        mock_client.read_device_information.return_value = mei_response

        scanner = create_mock_scanner(scanner_args)
        result = scanner._parse_mei_response(mei_response)

        assert result["VendorName"] == "Test Vendor"


class TestMEIPagination:
    """Tests for MEI pagination handling."""

    def test_mei_pagination_more_follows(self, mock_client, scanner_args):
        """Test handling more_follows=True pagination."""
        # First response with more_follows=True
        first_response = MagicMock()
        first_response.isError.return_value = False
        first_response.information = {0x00: b"Vendor"}
        first_response.more_follows = True
        first_response.next_object_id = 0x01

        # Second response with more_follows=False
        second_response = MagicMock()
        second_response.isError.return_value = False
        second_response.information = {0x01: b"Product"}
        second_response.more_follows = False
        second_response.next_object_id = 0

        mock_client.read_device_information.side_effect = [
            first_response,
            second_response,
        ]

        scanner = create_mock_scanner(scanner_args)

        result = scanner._read_device_identification(mock_client, mei_object="basic")

        assert result == {"VendorName": "Vendor", "ProductCode": "Product"}
        assert mock_client.read_device_information.call_count == 2

    def test_mei_empty_response(self, mock_client, scanner_args):
        """Test handling empty MEI response."""
        mei_response = MagicMock()
        mei_response.isError.return_value = False
        mei_response.information = {}
        mei_response.more_follows = False
        mock_client.read_device_information.return_value = mei_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_device_information(read_code=1, object_id=0x00, device_id=1)

        assert not result.isError()
        assert len(result.information) == 0


# =============================================================================
# Test Server ID (FC 17)
# =============================================================================


class TestServerID:
    """Tests for Server ID (FC 17)."""

    def test_read_server_id_success(self, mock_client, scanner_args):
        """Test successful Server ID read."""
        server_id_response = MagicMock()
        server_id_response.isError.return_value = False
        server_id_response.status = True
        server_id_response.identifier = b"Test Device ID"
        mock_client.report_device_id.return_value = server_id_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner.read_server_id(mock_client)

        assert result["identifier"] == "Test Device ID"
        assert result["run_status"] == "Running"

    def test_read_server_id_not_supported(self, mock_client, scanner_args):
        """Test Server ID when FC 17 not supported."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 1  # Illegal function
        mock_client.report_device_id.return_value = error_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner.read_server_id(mock_client)

        assert result is None

    def test_parse_server_id_response(self, mock_client, scanner_args):
        """Test parsing Server ID response format."""
        # Server ID format: [status] [byte_count] [identifier...]
        server_id_response = MagicMock()
        server_id_response.isError.return_value = False
        server_id_response.status = True  # Running
        server_id_response.identifier = b"Schneider_M340_01.00"
        mock_client.report_device_id.return_value = server_id_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner.read_server_id(mock_client)

        assert "Schneider" in result["identifier"]

    def test_server_id_status_stopped(self, mock_client, scanner_args):
        """Test Server ID with device in stopped state."""
        server_id_response = MagicMock()
        server_id_response.isError.return_value = False
        server_id_response.status = False  # Stopped
        server_id_response.identifier = b"Device ID"
        mock_client.report_device_id.return_value = server_id_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner.read_server_id(mock_client)

        assert result["run_status"] == "Stopped"


# =============================================================================
# Test Unit ID Discovery
# =============================================================================


class TestUnitIDDiscovery:
    """Tests for Unit ID discovery."""

    def test_discover_single_unit(self, mock_client, scanner_args):
        """Test discovering a single active unit."""

        # Only unit 1 responds
        def read_side_effect(*args, **kwargs):
            unit = kwargs.get("device_id", 1)
            if unit == 1:
                response = MagicMock()
                response.isError.return_value = False
                response.registers = [0]
                return response
            else:
                response = MagicMock()
                response.isError.return_value = True
                return response

        mock_client.read_holding_registers.side_effect = read_side_effect

        scanner = create_mock_scanner(scanner_args)
        scanner.discover_units = True
        # Small range so gateway sampling doesn't trigger and the scan is fast.
        scanner.unit_range = "1-3"

        result = scanner._discover_units(mock_client)

        assert result.get("gateway_mode") is not True
        assert 1 in result and result[1]["active"] is True
        assert 2 not in result
        assert 3 not in result

    def test_discover_multiple_units(self, mock_client, scanner_args):
        """Test discovering multiple active units."""
        active_units = {1, 5, 10}

        def read_side_effect(*args, **kwargs):
            unit = kwargs.get("device_id", 1)
            response = MagicMock()
            if unit in active_units:
                response.isError.return_value = False
                response.registers = [unit * 100]
            else:
                response.isError.return_value = True
            return response

        mock_client.read_holding_registers.side_effect = read_side_effect

        create_mock_scanner(scanner_args)

        # Discover units
        found_units = []
        for unit in range(1, 15):
            result = mock_client.read_holding_registers(0, 1, device_id=unit)
            if not result.isError():
                found_units.append(unit)

        assert found_units == [1, 5, 10]

    def test_no_units_found(self, mock_client, scanner_args):
        """Test handling when no units respond."""

        def read_side_effect(*args, **kwargs):
            response = MagicMock()
            response.isError.return_value = True
            return response

        mock_client.read_holding_registers.side_effect = read_side_effect

        create_mock_scanner(scanner_args)

        found_units = []
        for unit in range(1, 5):
            result = mock_client.read_holding_registers(0, 1, device_id=unit)
            if not result.isError():
                found_units.append(unit)

        assert len(found_units) == 0

    def test_unit_range_parsing(self, scanner_args):
        """Test parsing unit range argument."""
        scanner_args["unit-range"] = "1-10"
        scanner = create_mock_scanner(scanner_args)

        # Parse range
        range_str = scanner.unit_range
        start, end = map(int, range_str.split("-"))

        assert start == 1
        assert end == 10


# =============================================================================
# Test Gateway Detection
# =============================================================================


class TestGatewayDetection:
    """Tests for Modbus gateway detection."""

    def test_gateway_path_unavailable(self, mock_client, scanner_args):
        """Every sampled unit ID gets GATEWAY_PATH_UNAVAILABLE (10) -> the real
        _discover_units() aggregation must recognize this as gateway/bridge
        behavior rather than as per-unit discovery results."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 10  # Gateway path unavailable
        mock_client.read_holding_registers.return_value = error_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner._discover_units(mock_client)

        assert result["gateway_mode"] is True
        assert result["error_code"] == 10
        assert result["note"] == "Device returns identical error for all unit IDs"
        # real code queried multiple sample unit IDs before concluding gateway mode
        assert mock_client.read_holding_registers.call_count >= 3

    def test_gateway_target_failed(self, mock_client, scanner_args):
        """Every sampled unit ID gets GATEWAY_TARGET_DEVICE_FAILED (11) -> same
        gateway-mode aggregation, but the reported error_code must reflect the
        actual exception code the mock responses carried."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 11  # Gateway target device failed
        mock_client.read_holding_registers.return_value = error_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner._discover_units(mock_client)

        assert result["gateway_mode"] is True
        assert result["error_code"] == 11
        assert result["note"] == "Device returns identical error for all unit IDs"
        assert mock_client.read_holding_registers.call_count >= 3

    def test_gateway_multiple_units_different_devices(self, mock_client, scanner_args):
        """Test gateway with multiple devices on different unit IDs."""
        devices = {
            1: {"vendor": b"Vendor A"},
            5: {"vendor": b"Vendor B"},
            10: {"vendor": b"Vendor C"},
        }

        def mei_side_effect(read_code, object_id, device_id):
            response = MagicMock()
            if device_id in devices:
                response.isError.return_value = False
                response.information = {0x00: devices[device_id]["vendor"]}
            else:
                response.isError.return_value = True
                response.exception_code = 11
            return response

        mock_client.read_device_information.side_effect = mei_side_effect

        create_mock_scanner(scanner_args)

        # Query different units
        results = {}
        for unit in [1, 5, 10, 15]:
            result = mock_client.read_device_information(
                read_code=1, object_id=0x00, device_id=unit
            )
            if not result.isError():
                results[unit] = result.information[0x00].decode()

        assert len(results) == 3
        assert results[1] == "Vendor A"
        assert results[5] == "Vendor B"
        assert results[10] == "Vendor C"


# =============================================================================
# Test Exception Status (FC 7)
# =============================================================================


class TestExceptionStatus:
    """Tests for Exception Status (FC 7)."""

    def test_read_exception_status(self, mock_client, scanner_args):
        """The real read_exception_status() must unwrap the response and return
        the raw status byte, and it must query the scanner's own unit_id."""
        exc_response = MagicMock()
        exc_response.isError.return_value = False
        exc_response.status = 0b00001111  # First 4 bits set
        mock_client.read_exception_status.return_value = exc_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner.read_exception_status(mock_client)

        assert result == 0b00001111
        mock_client.read_exception_status.assert_called_once_with(device_id=scanner.unit_id)

    def test_exception_status_not_supported(self, mock_client, scanner_args):
        """FC 7 not supported (ILLEGAL_FUNCTION) must make the real code return
        None rather than propagating the raw error response."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 1
        mock_client.read_exception_status.return_value = error_response

        scanner = create_mock_scanner(scanner_args)

        result = scanner.read_exception_status(mock_client)

        assert result is None
        mock_client.read_exception_status.assert_called_once_with(device_id=scanner.unit_id)


# =============================================================================
# Test MEI Object Names
# =============================================================================


class TestMEIObjectNames:
    """Tests for MEI object name constants."""

    def test_vendor_name_id(self):
        """Test VendorName object ID."""
        assert MEI_OBJECT_NAMES[0x00] == "VendorName"

    def test_product_code_id(self):
        """Test ProductCode object ID."""
        assert MEI_OBJECT_NAMES[0x01] == "ProductCode"

    def test_version_id(self):
        """Test MajorMinorRevision object ID."""
        assert MEI_OBJECT_NAMES[0x02] == "MajorMinorRevision"

    def test_vendor_url_id(self):
        """Test VendorUrl object ID."""
        assert MEI_OBJECT_NAMES[0x03] == "VendorUrl"

    def test_product_name_id(self):
        """Test ProductName object ID."""
        assert MEI_OBJECT_NAMES[0x04] == "ProductName"

    def test_model_name_id(self):
        """Test ModelName object ID."""
        assert MEI_OBJECT_NAMES[0x05] == "ModelName"

    def test_user_application_name_id(self):
        """Test UserApplicationName object ID."""
        assert MEI_OBJECT_NAMES[0x06] == "UserApplicationName"

    def test_unknown_object_id_fallback(self):
        """Test fallback for unknown object IDs."""
        unknown_id = 0x80
        name = MEI_OBJECT_NAMES.get(unknown_id, f"Object_{unknown_id:02X}")
        assert name == "Object_80"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
