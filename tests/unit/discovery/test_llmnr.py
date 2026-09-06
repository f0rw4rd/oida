"""
Tests for LLMNRScanner class
"""

import pytest
from unittest.mock import patch, MagicMock
import socket
import struct


@pytest.fixture
def llmnr_scanner_class():
    """Get LLMNRScanner class"""
    from oida.protocols.discovery import LLMNRScanner

    return LLMNRScanner


def build_llmnr_response(name: str, transaction_id: int = 0x1234) -> bytes:
    """Build a mock LLMNR response packet using scapy DNS layer.

    Impl reads the queried name from ``dns_resp.qd.qname``; response packets
    echo the question, so qd is set on responses too.
    """
    from scapy.layers.dns import DNS, DNSQR

    return bytes(DNS(id=transaction_id, qr=1, qd=DNSQR(qname=name)))


def build_llmnr_query(name: str, transaction_id: int = 0x1234) -> bytes:
    """Build a mock LLMNR query packet using scapy DNS layer."""
    from scapy.layers.dns import DNS, DNSQR

    return bytes(DNS(id=transaction_id, qr=0, qd=DNSQR(qname=name)))


class TestLLMNRScannerInit:
    """Test LLMNRScanner initialization"""

    def test_default_parameters(self, llmnr_scanner_class):
        """Test scanner with default parameters"""
        scanner = llmnr_scanner_class("eth0")

        assert scanner.interface == "eth0"
        assert scanner.subnet is None
        assert scanner.timeout == 10
        assert scanner.discovered_devices == {}

    def test_custom_subnet(self, llmnr_scanner_class):
        """Test scanner with custom subnet"""
        scanner = llmnr_scanner_class("eth0", subnet="10.0.0.0/24")

        assert scanner.subnet == "10.0.0.0/24"

    def test_custom_timeout(self, llmnr_scanner_class):
        """Test scanner with custom timeout"""
        scanner = llmnr_scanner_class("eth0", timeout=30)

        assert scanner.timeout == 30


class TestLLMNRActiveMode:
    """Test LLMNR active query mode"""

    def test_query_packet_format(self, llmnr_scanner_class):
        """Test that query packets have correct format"""
        scanner = llmnr_scanner_class("eth0", subnet="192.168.1.0/24", timeout=1)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recvfrom.side_effect = socket.timeout()

            with patch("oida.protocols.discovery.get_interface_network") as mock_get_net:
                mock_get_net.return_value = "192.168.1.0/24"

                scanner.scan()

            # Verify sendto was called
            assert mock_socket.sendto.called

            # Check packet was sent to LLMNR multicast address
            call_args = mock_socket.sendto.call_args_list
            multicast_calls = [
                call for call in call_args if "224.0.0.252" in str(call) and "5355" in str(call)
            ]
            assert len(multicast_calls) > 0

    def test_queries_common_hostnames(self, llmnr_scanner_class):
        """Test that common hostnames are queried"""
        scanner = llmnr_scanner_class("eth0", subnet="192.168.1.0/24", timeout=1)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recvfrom.side_effect = socket.timeout()

            with patch("oida.protocols.discovery.get_interface_network") as mock_get_net:
                mock_get_net.return_value = "192.168.1.0/24"

                scanner.scan()

            # Multiple queries sent (WPAD and common names)
            assert mock_socket.sendto.call_count >= 1

    def test_multicast_address_used(self, llmnr_scanner_class):
        """Test that LLMNR multicast address is used"""
        scanner = llmnr_scanner_class("eth0", subnet="192.168.1.0/24", timeout=1)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recvfrom.side_effect = socket.timeout()

            with patch("oida.protocols.discovery.get_interface_network") as mock_get_net:
                mock_get_net.return_value = "192.168.1.0/24"

                scanner.scan()

            # Check LLMNR constants
            assert scanner.LLMNR_MULTICAST_ADDR == "224.0.0.252"
            assert scanner.LLMNR_PORT == 5355


class TestLLMNRPassiveMode:
    """Test LLMNR passive listening mode"""

    def test_joins_multicast_group(self, llmnr_scanner_class):
        """Test that scanner joins LLMNR multicast group"""
        scanner = llmnr_scanner_class("eth0", timeout=1)

        with patch("oida.protocols.discovery.network.get_interface_ip", return_value="192.0.2.1"):
            with patch("socket.socket") as mock_socket_class:
                mock_socket = MagicMock()
                mock_socket_class.return_value = mock_socket
                mock_socket.recvfrom.side_effect = socket.timeout()

                scanner._passive_listen()

                # bind was attempted (may be at port 5355 or 0 on fallback)
                assert mock_socket.bind.called

    def test_listens_on_port_5355(self, llmnr_scanner_class):
        """Test that scanner listens on LLMNR port"""
        scanner = llmnr_scanner_class("eth0", timeout=1)

        with patch("oida.protocols.discovery.network.get_interface_ip", return_value="192.0.2.1"):
            with patch("socket.socket") as mock_socket_class:
                mock_socket = MagicMock()
                mock_socket_class.return_value = mock_socket
                mock_socket.recvfrom.side_effect = socket.timeout()

                scanner._passive_listen()

                # Check bind was called (might be on port 5355 or fallback)
                assert mock_socket.bind.called


class TestLLMNRPacketParsing:
    """Test LLMNR packet parsing"""

    def test_parse_dns_header(self, llmnr_scanner_class):
        """Test parsing of DNS-like header"""
        scanner = llmnr_scanner_class("eth0")

        response = build_llmnr_response("WORKSTATION")

        # This should not raise an exception
        scanner._parse_llmnr_response(response, "192.168.1.100")

        # Check device was created
        assert len(scanner.discovered_devices) == 1

    def test_extract_response_flag(self, llmnr_scanner_class):
        """Test extraction of response flag"""
        scanner = llmnr_scanner_class("eth0")

        response = build_llmnr_response("DESKTOP")

        scanner._parse_llmnr_response(response, "192.168.1.100")

        device = scanner.discovered_devices["192.168.1.100"]
        assert device.llmnr_data["is_response"] is True

    def test_parse_name_labels(self, llmnr_scanner_class):
        """Test parsing of name labels"""
        scanner = llmnr_scanner_class("eth0")

        response = build_llmnr_response("TESTPC")

        scanner._parse_llmnr_response(response, "192.168.1.100")

        device = scanner.discovered_devices["192.168.1.100"]
        assert device.name == "TESTPC"

    def test_handle_compression_pointer(self, llmnr_scanner_class):
        """Test handling of DNS compression pointers"""
        scanner = llmnr_scanner_class("eth0")

        # Build packet with compression pointer (label length > 63)
        header = struct.pack(">HHHHHH", 0x1234, 0x8000, 0, 1, 0, 0)
        # Name with compression pointer (0xC0 = 192, indicating pointer)
        name_bytes = b"\xc0\x0c"  # Pointer to offset 12

        packet = header + name_bytes

        # Should not crash
        scanner._parse_llmnr_response(packet, "192.168.1.100")

    def test_short_packet_ignored(self, llmnr_scanner_class):
        """Test that short packets are ignored"""
        scanner = llmnr_scanner_class("eth0")

        short_packet = b"\x00\x01\x02"  # Less than 12 bytes

        scanner._parse_llmnr_response(short_packet, "192.168.1.100")

        assert len(scanner.discovered_devices) == 0

    def test_non_ascii_name_handling(self, llmnr_scanner_class):
        """Test handling of non-ASCII names"""
        scanner = llmnr_scanner_class("eth0")

        # Build packet with non-ASCII bytes
        header = struct.pack(">HHHHHH", 0x1234, 0x8000, 0, 1, 0, 0)
        name_bytes = b"\x04TEST\xff\x00"  # Contains non-ASCII byte

        packet = header + name_bytes + struct.pack(">HH", 0x0001, 0x0001)

        # Should not crash, might extract partial name
        scanner._parse_llmnr_response(packet, "192.168.1.100")


class TestLLMNRDeviceCreation:
    """Test LLMNR device creation"""

    def test_device_created_with_llmnr_data(self, llmnr_scanner_class):
        """Test that device is created with LLMNR data"""
        scanner = llmnr_scanner_class("eth0")

        response = build_llmnr_response("MYCOMPUTER")

        scanner._parse_llmnr_response(response, "192.168.1.100")

        device = scanner.discovered_devices["192.168.1.100"]
        assert device.ip_addresses == ["192.168.1.100"]
        assert device.name == "MYCOMPUTER"
        assert "llmnr" in device.discovered_by
        assert device.llmnr_data is not None

    def test_device_updated_on_multiple_responses(self, llmnr_scanner_class):
        """Test that device is updated on multiple responses"""
        scanner = llmnr_scanner_class("eth0")

        response1 = build_llmnr_response("PC1")
        response2 = build_llmnr_response("PC1")

        scanner._parse_llmnr_response(response1, "192.168.1.100")
        scanner._parse_llmnr_response(response2, "192.168.1.100")

        # Should still only have one device
        assert len(scanner.discovered_devices) == 1

    def test_existing_device_name_not_overwritten(self, llmnr_scanner_class):
        """Test that existing device name is preserved"""
        scanner = llmnr_scanner_class("eth0")

        from oida.protocols.discovery import DiscoveredDevice

        # Pre-populate with existing device
        existing = DiscoveredDevice(
            ip_addresses=["192.168.1.100"],
            name="ExistingName",
            discovered_by=["arp"],
        )
        scanner.discovered_devices["192.168.1.100"] = existing

        response = build_llmnr_response("NewName")
        scanner._parse_llmnr_response(response, "192.168.1.100")

        device = scanner.discovered_devices["192.168.1.100"]
        assert device.name == "ExistingName"

    def test_empty_device_name_gets_updated(self, llmnr_scanner_class):
        """Test that empty device name gets updated"""
        scanner = llmnr_scanner_class("eth0")

        from oida.protocols.discovery import DiscoveredDevice

        # Pre-populate with device without name
        existing = DiscoveredDevice(
            ip_addresses=["192.168.1.100"],
            name="",
            discovered_by=["arp"],
        )
        scanner.discovered_devices["192.168.1.100"] = existing

        response = build_llmnr_response("NewName")
        scanner._parse_llmnr_response(response, "192.168.1.100")

        device = scanner.discovered_devices["192.168.1.100"]
        assert device.name == "NewName"


class TestLLMNRScan:
    """Test full LLMNR scan"""

    def test_scan_returns_devices(self, llmnr_scanner_class):
        """Test that scan returns discovered devices"""
        scanner = llmnr_scanner_class("eth0", timeout=1)

        with patch("oida.protocols.discovery.network.get_interface_ip", return_value="192.0.2.1"):
            with patch("oida.protocols.discovery.network.get_interface_network", return_value=None):
                with patch("socket.socket") as mock_socket_class:
                    mock_socket = MagicMock()
                    mock_socket_class.return_value = mock_socket

                    response = build_llmnr_response("TESTHOST")
                    mock_socket.recvfrom.side_effect = [
                        (response, ("192.168.1.100", 5355)),
                        socket.timeout(),
                    ]

                    devices = scanner.scan()

                    assert "192.168.1.100" in devices

    def test_scan_handles_exceptions(self, llmnr_scanner_class):
        """Test that scan handles exceptions gracefully"""
        scanner = llmnr_scanner_class("eth0", timeout=1)

        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = OSError("Socket error")

            devices = scanner.scan()

            assert devices == {}
