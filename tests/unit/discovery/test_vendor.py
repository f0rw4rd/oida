"""
Tests for vendor-specific discovery scanners (Moxa, Lantronix)
"""

import pytest


class TestMoxaScannerInit:
    """Test MoxaScanner initialization and validation"""

    def test_valid_init(self):
        """Test valid initialization"""
        from oida.protocols.discovery.vendor import MoxaScanner

        scanner = MoxaScanner(interface="eth0", timeout=5.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.subnet is None
        assert scanner.discovered_devices == {}

    def test_init_with_subnet(self):
        """Test initialization with subnet"""
        from oida.protocols.discovery.vendor import MoxaScanner

        scanner = MoxaScanner(interface="eth0", subnet="192.168.1.0/24", timeout=3.0)
        assert scanner.interface == "eth0"
        assert scanner.subnet == "192.168.1.0/24"
        assert scanner.timeout == 3.0

    def test_init_invalid_interface_empty(self):
        """Test that empty interface raises ValueError"""
        from oida.protocols.discovery.vendor import MoxaScanner

        with pytest.raises(ValueError, match="cannot be empty"):
            MoxaScanner(interface="")

    def test_init_invalid_timeout_zero(self):
        """Test that zero timeout raises ValueError"""
        from oida.protocols.discovery.vendor import MoxaScanner

        with pytest.raises(ValueError, match="must be positive"):
            MoxaScanner(interface="eth0", timeout=0)

    def test_init_invalid_timeout_negative(self):
        """Test that negative timeout raises ValueError"""
        from oida.protocols.discovery.vendor import MoxaScanner

        with pytest.raises(ValueError, match="must be positive"):
            MoxaScanner(interface="eth0", timeout=-1)

    def test_init_invalid_subnet(self):
        """Test that invalid subnet raises ValueError"""
        from oida.protocols.discovery.vendor import MoxaScanner

        with pytest.raises(ValueError, match="Invalid subnet"):
            MoxaScanner(interface="eth0", subnet="invalid")

    def test_moxa_constants(self):
        """Test Moxa protocol constants"""
        from oida.protocols.discovery.vendor import MoxaScanner

        assert MoxaScanner.MOXA_PORT == 4800
        assert MoxaScanner.MOXA_OUI == bytes.fromhex("0090e8")
        assert MoxaScanner.DISCOVERY_PROBE == b"\x01\x00\x00\x08\x00\x00\x00\x00"


class TestMoxaScannerParseResponse:
    """Test MoxaScanner._parse_response method"""

    def test_valid_response(self):
        """Test parsing valid Moxa response"""
        from oida.protocols.discovery.vendor import MoxaScanner

        scanner = MoxaScanner(interface="eth0")

        # Build valid response:
        # - First byte: 0x81 (response function code)
        # - Bytes 13-18: MAC with Moxa OUI (00:90:E8)
        response = bytearray(24)
        response[0] = 0x81  # Response function code
        response[13:19] = bytes.fromhex("0090e8123456")  # Moxa OUI + MAC suffix

        device = scanner._parse_response(bytes(response), "192.168.1.100")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.100"]
        assert device.mac_address == "00:90:e8:12:34:56"
        assert device.manufacturer == "Moxa"
        assert device.device_type == "Serial Device Server"
        assert "moxa" in device.discovered_by

    def test_response_too_short(self):
        """Test that short response returns None"""
        from oida.protocols.discovery.vendor import MoxaScanner

        scanner = MoxaScanner(interface="eth0")
        device = scanner._parse_response(b"\x81" * 10, "192.168.1.100")
        assert device is None

    def test_invalid_function_code(self):
        """Test that invalid function code returns None"""
        from oida.protocols.discovery.vendor import MoxaScanner

        scanner = MoxaScanner(interface="eth0")
        response = bytearray(24)
        response[0] = 0x01  # Wrong function code (should be 0x81)
        response[13:19] = bytes.fromhex("0090e8123456")

        device = scanner._parse_response(bytes(response), "192.168.1.100")
        assert device is None

    def test_invalid_oui(self):
        """Test that non-Moxa OUI returns None"""
        from oida.protocols.discovery.vendor import MoxaScanner

        scanner = MoxaScanner(interface="eth0")
        response = bytearray(24)
        response[0] = 0x81
        response[13:19] = bytes.fromhex("001122334455")  # Not Moxa OUI

        device = scanner._parse_response(bytes(response), "192.168.1.100")
        assert device is None


class TestMoxaScannerScan:
    """Test MoxaScanner.scan method"""

    def test_scan_returns_empty_dict_on_no_responses(self):
        """Test that scan returns empty dict when no responses"""
        from oida.protocols.discovery.vendor import MoxaScanner

        # This test will fail to bind/send but should not crash
        scanner = MoxaScanner(interface="nonexistent_interface_xyz", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)

    def test_scan_with_subnet(self):
        """Test scan with subnet parameter"""
        from oida.protocols.discovery.vendor import MoxaScanner

        scanner = MoxaScanner(interface="lo", subnet="192.168.1.0/24", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)


class TestLantronixScannerInit:
    """Test LantronixScanner initialization and validation"""

    def test_valid_init(self):
        """Test valid initialization"""
        from oida.protocols.discovery.vendor import LantronixScanner

        scanner = LantronixScanner(interface="eth0", timeout=5.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.subnet is None

    def test_init_with_subnet(self):
        """Test initialization with subnet"""
        from oida.protocols.discovery.vendor import LantronixScanner

        scanner = LantronixScanner(interface="eth0", subnet="10.0.0.0/8")
        assert scanner.subnet == "10.0.0.0/8"

    def test_init_invalid_interface(self):
        """Test that empty interface raises ValueError"""
        from oida.protocols.discovery.vendor import LantronixScanner

        with pytest.raises(ValueError, match="cannot be empty"):
            LantronixScanner(interface="")

    def test_init_invalid_timeout(self):
        """Test that zero timeout raises ValueError"""
        from oida.protocols.discovery.vendor import LantronixScanner

        with pytest.raises(ValueError, match="must be positive"):
            LantronixScanner(interface="eth0", timeout=0)

    def test_lantronix_constants(self):
        """Test Lantronix protocol constants"""
        from oida.protocols.discovery.vendor import LantronixScanner

        assert LantronixScanner.LANTRONIX_PORT == 30718
        assert LantronixScanner.DISCOVERY_PROBE == b"\x00\x00\x00\xf6"


class TestLantronixScannerParseResponse:
    """Test LantronixScanner._parse_response method"""

    def test_valid_response(self):
        """Test parsing valid Lantronix response"""
        from oida.protocols.discovery.vendor import LantronixScanner

        scanner = LantronixScanner(interface="eth0")

        # Build valid response (30 bytes):
        # - Bytes 0-5: MAC address
        # - Bytes 6-9: IP address
        # - Bytes 10-13: Subnet mask
        # - Bytes 14-17: Gateway
        # - Bytes 18-29: Other data
        response = bytearray(30)
        response[0:6] = bytes.fromhex("001122334455")  # MAC
        response[6:10] = bytes([192, 168, 1, 100])  # IP
        response[10:14] = bytes([255, 255, 255, 0])  # Netmask
        response[14:18] = bytes([192, 168, 1, 1])  # Gateway

        device = scanner._parse_response(bytes(response), "192.168.1.100")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.100"]
        assert device.mac_address == "00:11:22:33:44:55"
        assert device.manufacturer == "Lantronix"
        assert device.device_type == "Serial Device Server"
        assert "lantronix" in device.discovered_by
        assert device.lantronix_data["configured_ip"] == "192.168.1.100"
        assert device.lantronix_data["subnet_mask"] == "255.255.255.0"
        assert device.lantronix_data["gateway"] == "192.168.1.1"

    def test_response_too_short(self):
        """Test that short response returns None"""
        from oida.protocols.discovery.vendor import LantronixScanner

        scanner = LantronixScanner(interface="eth0")
        device = scanner._parse_response(b"\x00" * 20, "192.168.1.100")
        assert device is None


class TestLantronixScannerScan:
    """Test LantronixScanner.scan method"""

    def test_scan_returns_empty_dict_on_no_responses(self):
        """Test that scan returns empty dict when no responses"""
        from oida.protocols.discovery.vendor import LantronixScanner

        # This test will fail to bind/send but should not crash
        scanner = LantronixScanner(interface="nonexistent_interface_xyz", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)

    def test_scan_with_subnet(self):
        """Test scan with subnet parameter"""
        from oida.protocols.discovery.vendor import LantronixScanner

        scanner = LantronixScanner(interface="lo", subnet="10.0.0.0/8", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)


class TestScanHost:
    """Test scan_host methods for both scanners"""

    def test_moxa_scan_host_unreachable(self):
        """Test Moxa scan_host returns None for unreachable host"""
        from oida.protocols.discovery.vendor import MoxaScanner

        scanner = MoxaScanner(interface="lo", timeout=0.01)
        # Use localhost which won't have a Moxa device
        result = scanner.scan_host("127.0.0.1")
        assert result is None

    def test_lantronix_scan_host_unreachable(self):
        """Test Lantronix scan_host returns None for unreachable host"""
        from oida.protocols.discovery.vendor import LantronixScanner

        scanner = LantronixScanner(interface="lo", timeout=0.01)
        # Use localhost which won't have a Lantronix device
        result = scanner.scan_host("127.0.0.1")
        assert result is None
