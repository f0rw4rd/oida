"""
Tests for DNSSDScanner class
"""

from unittest.mock import patch, MagicMock

import pytest

from tests.service_gate import require_import

zeroconf = require_import("zeroconf", reason="zeroconf not installed")


@pytest.fixture
def dnssd_scanner_class():
    """Get DNSSDScanner class"""
    from oida.protocols.discovery import DNSSDScanner

    return DNSSDScanner


class TestDNSSDScannerInit:
    """Test DNSSDScanner initialization"""

    def test_default_timeout(self, dnssd_scanner_class):
        """Test default timeout value"""
        scanner = dnssd_scanner_class("eth0")

        assert scanner.interface == "eth0"
        assert scanner.timeout == 10
        assert scanner.discovered_devices == {}

    def test_custom_timeout(self, dnssd_scanner_class):
        """Test custom timeout"""
        scanner = dnssd_scanner_class("eth0", timeout=30)

        assert scanner.timeout == 30

    def test_services_domain_constant(self, dnssd_scanner_class):
        """Test SERVICES_DOMAIN constant"""
        assert dnssd_scanner_class.SERVICES_DOMAIN == "_services._dns-sd._udp.local"

    def test_lock_initialized(self, dnssd_scanner_class):
        """Test that thread lock is initialized"""
        scanner = dnssd_scanner_class("eth0")

        assert scanner._lock is not None


class TestDNSSDScannerScan:
    """Test DNSSDScanner scan method"""

    def test_zeroconf_import_failure(self, dnssd_scanner_class):
        """Test handling when zeroconf is not installed"""
        scanner = dnssd_scanner_class("eth0", timeout=1)

        with patch.dict("sys.modules", {"zeroconf": None}):
            devices = scanner.scan()
            assert devices == {}

    def test_browse_extended_services(self, dnssd_scanner_class):
        """Test that extended service types are browsed"""
        scanner = dnssd_scanner_class("eth0", timeout=1)

        mock_zeroconf = MagicMock()
        mock_browser = MagicMock()

        # Interface enumeration is mocked by the autouse mock_netifaces fixture;
        # override the address for this interface to a known value.
        from oida.utils import iface_info

        with patch.object(
            iface_info, "ifaddresses", return_value={iface_info.AF_INET: [{"addr": "192.168.1.1"}]}
        ):
            with patch("zeroconf.Zeroconf", return_value=mock_zeroconf):
                with patch(
                    "zeroconf.ServiceBrowser", return_value=mock_browser
                ) as mock_browser_class:
                    with patch("zeroconf.ServiceListener"):
                        with patch("time.sleep"):
                            scanner.scan()

                            # Should browse many service types
                            assert mock_browser_class.call_count > 10

    def test_service_enumeration(self, dnssd_scanner_class):
        """Test service enumeration"""
        scanner = dnssd_scanner_class("eth0", timeout=1)

        mock_zeroconf = MagicMock()

        # Interface enumeration is mocked by the autouse mock_netifaces fixture;
        # override the address for this interface to a known value.
        from oida.utils import iface_info

        with patch.object(
            iface_info, "ifaddresses", return_value={iface_info.AF_INET: [{"addr": "192.168.1.1"}]}
        ):
            with patch("zeroconf.Zeroconf", return_value=mock_zeroconf):
                with patch("zeroconf.ServiceBrowser"):
                    with patch("zeroconf.ServiceListener"):
                        with patch("time.sleep"):
                            devices = scanner.scan()

                            # Result is dict of devices
                            assert isinstance(devices, dict)


class TestDNSSDServiceHandling:
    """Test DNS-SD service handling"""

    def test_creates_dnssd_data_structure(self, dnssd_scanner_class):
        """Test that dnssd_data structure is created"""
        scanner = dnssd_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info.port = 80
        mock_info.server = "device.local."

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Web._http._tcp.local.")

        device = scanner.discovered_devices["192.168.1.100"]
        assert device.dnssd_data is not None
        assert "services" in device.dnssd_data
        assert len(device.dnssd_data["services"]) == 1

    def test_appends_services_to_existing(self, dnssd_scanner_class):
        """Test that services are appended to existing device"""
        scanner = dnssd_scanner_class("eth0")

        mock_zc = MagicMock()

        # First service
        mock_info1 = MagicMock()
        mock_info1.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info1.port = 80
        mock_info1.server = "device.local."

        mock_zc.get_service_info.return_value = mock_info1
        scanner._handle_service(mock_zc, "_http._tcp.local.", "HTTP._http._tcp.local.")

        # Second service
        mock_info2 = MagicMock()
        mock_info2.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info2.port = 631
        mock_info2.server = "device.local."

        mock_zc.get_service_info.return_value = mock_info2
        scanner._handle_service(mock_zc, "_ipp._tcp.local.", "IPP._ipp._tcp.local.")

        device = scanner.discovered_devices["192.168.1.100"]
        assert len(device.dnssd_data["services"]) == 2

    def test_discovered_by_dns_sd(self, dnssd_scanner_class):
        """Test that discovered_by includes 'dns-sd'"""
        scanner = dnssd_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info.port = 80
        mock_info.server = "device.local."

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Web._http._tcp.local.")

        device = scanner.discovered_devices["192.168.1.100"]
        assert "dns-sd" in device.discovered_by

    def test_service_info_none_skipped(self, dnssd_scanner_class):
        """Test that None service info is skipped"""
        scanner = dnssd_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = None

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Web._http._tcp.local.")

        assert len(scanner.discovered_devices) == 0

    def test_no_addresses_skipped(self, dnssd_scanner_class):
        """Test that services without addresses are skipped"""
        scanner = dnssd_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = []
        mock_info.addresses = []

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Web._http._tcp.local.")

        assert len(scanner.discovered_devices) == 0

    def test_name_from_server(self, dnssd_scanner_class):
        """Test device name is taken from server"""
        scanner = dnssd_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info.port = 80
        mock_info.server = "mydevice.local."

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Service._http._tcp.local.")

        device = scanner.discovered_devices["192.168.1.100"]
        assert device.name == "mydevice.local"

    def test_name_fallback_to_service_name(self, dnssd_scanner_class):
        """Test name falls back to service name if no server"""
        scanner = dnssd_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info.port = 80
        mock_info.server = ""

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "MyService._http._tcp.local.")

        device = scanner.discovered_devices["192.168.1.100"]
        assert device.name == "MyService._http._tcp.local."

    def test_service_structure(self, dnssd_scanner_class):
        """Test service info structure in dnssd_data"""
        scanner = dnssd_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info.port = 8080
        mock_info.server = "device.local."

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Web._http._tcp.local.")

        device = scanner.discovered_devices["192.168.1.100"]
        service = device.dnssd_data["services"][0]

        assert service["type"] == "_http._tcp.local."
        assert service["name"] == "Web._http._tcp.local."
        assert service["port"] == 8080
        assert service["server"] == "device.local."

    def test_existing_device_dnssd_none(self, dnssd_scanner_class):
        """Test handling when existing device has None dnssd_data"""
        scanner = dnssd_scanner_class("eth0")

        from oida.protocols.discovery import DiscoveredDevice

        # Pre-populate with device without dnssd_data
        existing = DiscoveredDevice(
            ip_addresses=["192.168.1.100"],
            discovered_by=["arp"],
            dnssd_data=None,
        )
        scanner.discovered_devices["192.168.1.100"] = existing

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info.port = 80
        mock_info.server = "device.local."

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Web._http._tcp.local.")

        device = scanner.discovered_devices["192.168.1.100"]
        assert device.dnssd_data is not None
        assert len(device.dnssd_data["services"]) == 1

    def test_exception_handling(self, dnssd_scanner_class):
        """Test exception handling in service handler"""
        scanner = dnssd_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_zc.get_service_info.side_effect = Exception("Service lookup failed")

        # Should not raise exception
        scanner._handle_service(mock_zc, "_http._tcp.local.", "Web._http._tcp.local.")

        assert len(scanner.discovered_devices) == 0

    def test_fallback_addresses_from_bytes(self, dnssd_scanner_class):
        """Test address extraction from raw bytes"""
        scanner = dnssd_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()

        # No parsed_addresses attribute
        del mock_info.parsed_addresses
        mock_info.addresses = [b"\xc0\xa8\x01\x64"]  # 192.168.1.100
        mock_info.port = 80
        mock_info.server = "device.local."

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Web._http._tcp.local.")

        assert "192.168.1.100" in scanner.discovered_devices


class TestDNSSDServiceTypes:
    """Test DNS-SD service types"""

    def test_includes_industrial_services(self, dnssd_scanner_class):
        """Test that industrial service types are included"""
        from oida.protocols.discovery import MDNS_SERVICE_TYPES

        industrial_services = ["_modbus", "_opcua", "_plc", "_hmi", "_scada"]
        found = [s for s in MDNS_SERVICE_TYPES if any(ind in s for ind in industrial_services)]
        assert len(found) > 0

    def test_includes_common_services(self, dnssd_scanner_class):
        """Test that common service types are browsed"""
        scanner = dnssd_scanner_class("eth0", timeout=1)

        mock_zeroconf = MagicMock()
        service_types_browsed = []

        def track_browser(zc, stype, listener):
            service_types_browsed.append(stype)
            return MagicMock()

        # Interface enumeration is mocked by the autouse mock_netifaces fixture;
        # override the address for this interface to a known value.
        from oida.utils import iface_info

        with patch.object(
            iface_info, "ifaddresses", return_value={iface_info.AF_INET: [{"addr": "192.168.1.1"}]}
        ):
            with patch("zeroconf.Zeroconf", return_value=mock_zeroconf):
                with patch("zeroconf.ServiceBrowser", side_effect=track_browser):
                    with patch("zeroconf.ServiceListener"):
                        with patch("time.sleep"):
                            scanner.scan()

        # Should include common services
        assert any("_http" in s for s in service_types_browsed)
        assert any("_printer" in s or "_ipp" in s for s in service_types_browsed)
