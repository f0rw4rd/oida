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
try:
    import pymodbus

    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False

pytestmark = pytest.mark.skipif(not PYMODBUS_AVAILABLE, reason="pymodbus library not installed")

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

    # Mock report_slave_id response (FC 17)
    server_id_response = MagicMock()
    server_id_response.isError.return_value = False
    server_id_response.status = True
    server_id_response.identifier = b"Test Server ID"
    client.report_slave_id.return_value = server_id_response

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
        create_mock_scanner(scanner_args)

        result = mock_client.read_device_information(
            read_code=MEIReadDeviceIdCode.BASIC,
            object_id=0x00,
            device_id=1,
        )

        assert not result.isError()
        assert 0x00 in result.information

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

        create_mock_scanner(scanner_args)

        result = mock_client.read_device_information(
            read_code=MEIReadDeviceIdCode.EXTENDED,
            object_id=0x00,
            device_id=1,
        )

        assert not result.isError()
        assert 0x06 in result.information

    def test_mei_specific_object_read(self, mock_client, scanner_args):
        """Test specific object read (read_code=4)."""
        mei_response = MagicMock()
        mei_response.isError.return_value = False
        mei_response.information = {
            0x02: b"1.2.3",
        }
        mei_response.more_follows = False
        mock_client.read_device_information.return_value = mei_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_device_information(
            read_code=MEIReadDeviceIdCode.SPECIFIC,
            object_id=0x02,
            device_id=1,
        )

        assert not result.isError()
        assert 0x02 in result.information
        assert result.information[0x02] == b"1.2.3"

    def test_mei_not_supported(self, mock_client, scanner_args):
        """Test handling when MEI is not supported."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_FUNCTION
        mock_client.read_device_information.return_value = error_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_device_information(
            read_code=MEIReadDeviceIdCode.BASIC,
            object_id=0x00,
            device_id=1,
        )

        assert result.isError()
        assert result.exception_code == 1


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

        create_mock_scanner(scanner_args)
        result = mock_client.read_device_information(read_code=1, object_id=0x00, device_id=1)

        value = result.information[0x00].decode("utf-8").strip("\x00")
        assert value == "Test Vendor"


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

        create_mock_scanner(scanner_args)

        # First call
        result1 = mock_client.read_device_information(read_code=1, object_id=0x00, device_id=1)
        assert result1.more_follows is True
        assert result1.next_object_id == 0x01

        # Second call
        result2 = mock_client.read_device_information(read_code=1, object_id=0x01, device_id=1)
        assert result2.more_follows is False

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
        mock_client.report_slave_id.return_value = server_id_response

        create_mock_scanner(scanner_args)

        result = mock_client.report_slave_id(device_id=1)

        assert not result.isError()
        assert result.status is True
        assert result.identifier == b"Test Device ID"

    def test_read_server_id_not_supported(self, mock_client, scanner_args):
        """Test Server ID when FC 17 not supported."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 1  # Illegal function
        mock_client.report_slave_id.return_value = error_response

        create_mock_scanner(scanner_args)

        result = mock_client.report_slave_id(device_id=1)

        assert result.isError()

    def test_parse_server_id_response(self, mock_client, scanner_args):
        """Test parsing Server ID response format."""
        # Server ID format: [status] [byte_count] [identifier...]
        server_id_response = MagicMock()
        server_id_response.isError.return_value = False
        server_id_response.status = True  # Running
        server_id_response.identifier = b"Schneider_M340_01.00"
        mock_client.report_slave_id.return_value = server_id_response

        create_mock_scanner(scanner_args)

        result = mock_client.report_slave_id(device_id=1)

        assert result.status is True
        identifier = result.identifier.decode("utf-8", errors="replace")
        assert "Schneider" in identifier

    def test_server_id_status_stopped(self, mock_client, scanner_args):
        """Test Server ID with device in stopped state."""
        server_id_response = MagicMock()
        server_id_response.isError.return_value = False
        server_id_response.status = False  # Stopped
        server_id_response.identifier = b"Device ID"
        mock_client.report_slave_id.return_value = server_id_response

        create_mock_scanner(scanner_args)

        result = mock_client.report_slave_id(device_id=1)

        assert result.status is False


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

        # Test unit 1
        result = mock_client.read_holding_registers(0, 1, device_id=1)
        assert not result.isError()

        # Test unit 2
        result = mock_client.read_holding_registers(0, 1, device_id=2)
        assert result.isError()

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
        """Test detecting gateway with unavailable path."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 10  # Gateway path unavailable
        mock_client.read_holding_registers.return_value = error_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_holding_registers(0, 1, device_id=100)

        assert result.isError()
        assert result.exception_code == 10

    def test_gateway_target_failed(self, mock_client, scanner_args):
        """Test detecting gateway with failed target device."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 11  # Gateway target device failed
        mock_client.read_holding_registers.return_value = error_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_holding_registers(0, 1, device_id=200)

        assert result.isError()
        assert result.exception_code == 11

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
            result = mock_client.read_device_information(read_code=1, object_id=0x00, device_id=unit)
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
        """Test reading exception status."""
        exc_response = MagicMock()
        exc_response.isError.return_value = False
        exc_response.status = 0b00001111  # First 4 bits set
        mock_client.read_exception_status.return_value = exc_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_exception_status(device_id=1)

        assert not result.isError()
        assert result.status == 0b00001111

    def test_exception_status_not_supported(self, mock_client, scanner_args):
        """Test handling when FC 7 not supported."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 1
        mock_client.read_exception_status.return_value = error_response

        create_mock_scanner(scanner_args)

        result = mock_client.read_exception_status(device_id=1)

        assert result.isError()


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
