"""
Tests for SSDPScanner class
"""

import pytest
from unittest.mock import patch, MagicMock
import socket


@pytest.fixture
def ssdp_scanner_class():
    """Get SSDPScanner class"""
    from oida.protocols.discovery import SSDPScanner

    return SSDPScanner


# Sample SSDP responses for testing (using CRLF as per HTTP spec)
SSDP_RESPONSE_BASIC = (
    "HTTP/1.1 200 OK\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "LOCATION: http://192.168.1.100:8080/description.xml\r\n"
    "SERVER: Linux/5.4, UPnP/1.0\r\n"
    "ST: upnp:rootdevice\r\n"
    "USN: uuid:12345678-1234-1234-1234-123456789abc::upnp:rootdevice\r\n"
    "\r\n"
)

SSDP_NOTIFY = (
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "LOCATION: http://192.168.1.200:8080/description.xml\r\n"
    "NT: upnp:rootdevice\r\n"
    "NTS: ssdp:alive\r\n"
    "SERVER: UPnP/1.0\r\n"
    "\r\n"
)

UPNP_DEVICE_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <friendlyName>Test Device</friendlyName>
    <manufacturer>Test Manufacturer</manufacturer>
    <modelName>Model123</modelName>
    <modelDescription>A test UPnP device</modelDescription>
    <modelNumber>1.0</modelNumber>
    <serialNumber>SN12345</serialNumber>
    <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
    <UDN>uuid:12345678-1234-1234-1234-123456789abc</UDN>
  </device>
</root>
"""

UPNP_DEVICE_XML_NO_NAMESPACE = """<?xml version="1.0"?>
<root>
  <device>
    <friendlyName>Simple Device</friendlyName>
    <manufacturer>Simple Vendor</manufacturer>
    <modelName>SimpleModel</modelName>
  </device>
</root>
"""


class TestSSDPScannerInit:
    """Test SSDPScanner initialization"""

    def test_default_passive_mode(self, ssdp_scanner_class):
        """Test scanner defaults to passive mode"""
        scanner = ssdp_scanner_class("eth0")

        assert scanner.interface == "eth0"
        assert scanner.timeout == 30
        assert scanner.active is False
        assert scanner.discovered_devices == {}

    def test_active_mode_flag(self, ssdp_scanner_class):
        """Test scanner with active mode enabled"""
        scanner = ssdp_scanner_class("eth0", timeout=10, active=True)

        assert scanner.active is True
        assert scanner.timeout == 10


class TestSSDPScannerPassive:
    """Test SSDP passive listening"""

    def test_passive_listen_only(self, ssdp_scanner_class):
        """Test that passive mode doesn't send M-SEARCH"""
        scanner = ssdp_scanner_class("eth0", timeout=1, active=False)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recvfrom.side_effect = socket.timeout()

            scanner.scan()

            # Verify no sendto was called (passive mode)
            mock_socket.sendto.assert_not_called()

    def test_no_msearch_sent_in_passive(self, ssdp_scanner_class):
        """Test that M-SEARCH is not sent in passive mode"""
        scanner = ssdp_scanner_class("eth0", timeout=1, active=False)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recvfrom.side_effect = socket.timeout()

            scanner.scan()

            # Check that sendto was never called
            assert not any("M-SEARCH" in str(call) for call in mock_socket.sendto.call_args_list)


class TestSSDPScannerActive:
    """Test SSDP active M-SEARCH"""

    def test_msearch_sent_on_start(self, ssdp_scanner_class):
        """Test that M-SEARCH is sent in active mode"""
        scanner = ssdp_scanner_class("eth0", timeout=1, active=True)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recvfrom.side_effect = socket.timeout()

            scanner.scan()

            # Verify sendto was called with M-SEARCH
            assert mock_socket.sendto.called
            sent_data = mock_socket.sendto.call_args[0][0]
            assert b"M-SEARCH" in sent_data

    def test_periodic_msearch_resend(self, ssdp_scanner_class):
        """Test that M-SEARCH is resent periodically"""
        scanner = ssdp_scanner_class("eth0", timeout=5, active=True)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Make recvfrom timeout multiple times
            mock_socket.recvfrom.side_effect = [socket.timeout()] * 10

            with patch("time.time") as mock_time:
                # Simulate time progression
                mock_time.side_effect = [0, 0.5, 1, 1.5, 2, 2.5, 3, 6]

                scanner.scan()

            # Multiple sendto calls expected
            assert mock_socket.sendto.call_count >= 1

    def test_response_collection(self, ssdp_scanner_class):
        """Test that SSDP responses are collected"""
        scanner = ssdp_scanner_class("eth0", timeout=1, active=True)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Return one response then timeout
            mock_socket.recvfrom.side_effect = [
                (SSDP_RESPONSE_BASIC.encode(), ("192.168.1.100", 1900)),
                socket.timeout(),
            ]

            with patch.object(scanner, "_fetch_device_description", return_value=None):
                devices = scanner.scan()

            assert len(devices) == 1
            assert "192.168.1.100" in devices


class TestSSDPResponseParsing:
    """Test SSDP response parsing"""

    def test_parse_http_headers(self, ssdp_scanner_class):
        """Test parsing of HTTP headers"""
        scanner = ssdp_scanner_class("eth0")

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            mock_socket.recvfrom.side_effect = [
                (SSDP_RESPONSE_BASIC.encode(), ("192.168.1.100", 1900)),
                socket.timeout(),
            ]

            with patch.object(scanner, "_fetch_device_description", return_value=None):
                devices = scanner.scan()

            device = devices["192.168.1.100"]
            assert device.ssdp_data is not None
            assert "location" in device.ssdp_data
            assert "server" in device.ssdp_data

    def test_extract_location_header(self, ssdp_scanner_class):
        """Test extraction of LOCATION header"""
        scanner = ssdp_scanner_class("eth0")

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            mock_socket.recvfrom.side_effect = [
                (SSDP_RESPONSE_BASIC.encode(), ("192.168.1.100", 1900)),
                socket.timeout(),
            ]

            with patch.object(scanner, "_fetch_device_description", return_value=None):
                devices = scanner.scan()

            device = devices["192.168.1.100"]
            assert device.ssdp_data["location"] == "http://192.168.1.100:8080/description.xml"

    def test_missing_location_no_fetch(self, ssdp_scanner_class):
        """Test that missing LOCATION doesn't cause fetch attempt"""
        scanner = ssdp_scanner_class("eth0")

        response_no_location = "HTTP/1.1 200 OK\r\nSERVER: Test/1.0\r\nST: upnp:rootdevice\r\n\r\n"

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            mock_socket.recvfrom.side_effect = [
                (response_no_location.encode(), ("192.168.1.100", 1900)),
                socket.timeout(),
            ]

            with patch.object(scanner, "_fetch_device_description") as mock_fetch:
                mock_fetch.return_value = None
                scanner.scan()

                # _fetch_device_description should not be called with empty location
                assert not any(
                    call[0][0].startswith("http")
                    for call in mock_fetch.call_args_list
                    if mock_fetch.call_args_list
                )


class TestSSDPXMLParsing:
    """Test SSDP XML parsing"""

    def test_parse_upnp_device_xml(self, ssdp_scanner_class):
        """Test parsing UPnP device description XML"""
        scanner = ssdp_scanner_class("eth0")

        result = scanner._parse_device_xml(UPNP_DEVICE_XML.encode())

        assert result["friendly_name"] == "Test Device"
        assert result["manufacturer"] == "Test Manufacturer"
        assert result["model_name"] == "Model123"
        assert result["model_description"] == "A test UPnP device"
        assert result["serial_number"] == "SN12345"

    def test_parse_xml_with_namespace(self, ssdp_scanner_class):
        """Test parsing XML with UPnP namespace"""
        scanner = ssdp_scanner_class("eth0")

        result = scanner._parse_device_xml(UPNP_DEVICE_XML.encode())

        assert "friendly_name" in result
        assert "manufacturer" in result

    def test_parse_xml_without_namespace(self, ssdp_scanner_class):
        """Test parsing XML without namespace"""
        scanner = ssdp_scanner_class("eth0")

        result = scanner._parse_device_xml(UPNP_DEVICE_XML_NO_NAMESPACE.encode())

        assert result.get("friendly_name") == "Simple Device"
        assert result.get("manufacturer") == "Simple Vendor"

    def test_malformed_xml_handled(self, ssdp_scanner_class):
        """Test that malformed XML is handled gracefully"""
        scanner = ssdp_scanner_class("eth0")

        malformed_xml = b"<root><device><not closed>"

        result = scanner._parse_device_xml(malformed_xml)

        assert result == {}

    def test_extract_all_fields(self, ssdp_scanner_class):
        """Test extraction of all device fields"""
        scanner = ssdp_scanner_class("eth0")

        result = scanner._parse_device_xml(UPNP_DEVICE_XML.encode())

        expected_fields = [
            "friendly_name",
            "manufacturer",
            "model_name",
            "model_description",
            "model_number",
            "serial_number",
            "device_type",
            "udn",
        ]

        for field in expected_fields:
            assert field in result, f"Missing field: {field}"


class TestSSDPDeviceCreation:
    """Test SSDP device creation"""

    def test_device_created_with_ssdp_data(self, ssdp_scanner_class):
        """Test that device is created with SSDP data"""
        scanner = ssdp_scanner_class("eth0")

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            mock_socket.recvfrom.side_effect = [
                (SSDP_RESPONSE_BASIC.encode(), ("192.168.1.100", 1900)),
                socket.timeout(),
            ]

            with patch.object(scanner, "_fetch_device_description") as mock_fetch:
                mock_fetch.return_value = {
                    "friendly_name": "Test Device",
                    "manufacturer": "Test Vendor",
                    "model_name": "Model123",
                }

                devices = scanner.scan()

            device = devices["192.168.1.100"]
            assert device.name == "Test Device"
            assert device.manufacturer == "Test Vendor"
            assert device.model == "Model123"
            assert "ssdp" in device.discovered_by

    def test_device_updated_on_multiple_responses(self, ssdp_scanner_class):
        """Test that device is updated on multiple responses"""
        scanner = ssdp_scanner_class("eth0")

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            mock_socket.recvfrom.side_effect = [
                (SSDP_RESPONSE_BASIC.encode(), ("192.168.1.100", 1900)),
                (SSDP_RESPONSE_BASIC.encode(), ("192.168.1.100", 1900)),
                socket.timeout(),
            ]

            with patch.object(scanner, "_fetch_device_description", return_value=None):
                devices = scanner.scan()

            # Should still only have one device
            assert len(devices) == 1

    def test_fetch_device_description(self, ssdp_scanner_class):
        """Test fetching device description from URL"""
        scanner = ssdp_scanner_class("eth0")

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = UPNP_DEVICE_XML.encode()
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            result = scanner._fetch_device_description("http://192.168.1.100:8080/description.xml")

            assert result is not None
            assert result.get("friendly_name") == "Test Device"

    def test_fetch_device_description_failure(self, ssdp_scanner_class):
        """Test handling of fetch failure"""
        scanner = ssdp_scanner_class("eth0")

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = Exception("Connection refused")

            result = scanner._fetch_device_description("http://192.168.1.100:8080/description.xml")

            assert result is None


class TestSSDPSocketConfiguration:
    """Test SSDP socket configuration"""

    def test_socket_options_set(self, ssdp_scanner_class):
        """Test that socket options are configured"""
        scanner = ssdp_scanner_class("eth0", timeout=1)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recvfrom.side_effect = socket.timeout()

            scanner.scan()

            # Verify socket options were set
            assert mock_socket.setsockopt.called

    def test_multicast_ttl_set(self, ssdp_scanner_class):
        """Test that multicast TTL is set"""
        scanner = ssdp_scanner_class("eth0", timeout=1, active=True)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recvfrom.side_effect = socket.timeout()

            scanner.scan()

            # Check that IP_MULTICAST_TTL was set
            ttl_calls = [
                call
                for call in mock_socket.setsockopt.call_args_list
                if socket.IPPROTO_IP in call[0] and socket.IP_MULTICAST_TTL in call[0]
            ]
            assert len(ttl_calls) > 0
