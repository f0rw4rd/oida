"""
Tests for MDNSScanner class
"""

import pytest
from unittest.mock import patch, MagicMock
import threading

zeroconf = pytest.importorskip("zeroconf", reason="zeroconf not installed")


@pytest.fixture
def mdns_scanner_class():
    """Get MDNSScanner class"""
    from oida.protocols.discovery import MDNSScanner

    return MDNSScanner


class TestMDNSScannerInit:
    """Test MDNSScanner initialization"""

    def test_default_timeout(self, mdns_scanner_class):
        """Test default timeout value"""
        scanner = mdns_scanner_class("eth0")

        assert scanner.interface == "eth0"
        assert scanner.timeout == 30
        assert scanner.discovered_devices == {}
        assert scanner._zeroconf is None

    def test_custom_timeout(self, mdns_scanner_class):
        """Test custom timeout"""
        scanner = mdns_scanner_class("eth0", timeout=60)

        assert scanner.timeout == 60

    def test_lock_initialized(self, mdns_scanner_class):
        """Test that thread lock is initialized"""
        scanner = mdns_scanner_class("eth0")

        assert scanner._lock is not None
        assert isinstance(scanner._lock, type(threading.Lock()))


class TestMDNSScannerCheckZeroconf:
    """Test zeroconf availability check"""

    @pytest.mark.skip(
        reason="_check_zeroconf method no longer exists; zeroconf check is done inline in scan()"
    )
    def test_zeroconf_available(self, mdns_scanner_class):
        """Test when zeroconf is available - SKIPPED: _check_zeroconf removed"""
        scanner = mdns_scanner_class("eth0")

        with patch.dict("sys.modules", {"zeroconf": MagicMock()}):
            result = scanner._check_zeroconf()
            assert result is True

    @pytest.mark.skip(
        reason="_check_zeroconf method no longer exists; zeroconf check is done inline in scan()"
    )
    def test_zeroconf_not_available(self, mdns_scanner_class):
        """Test when zeroconf is not available - SKIPPED: _check_zeroconf removed"""
        scanner = mdns_scanner_class("eth0")

        with patch.dict("sys.modules", {"zeroconf": None}):
            # Force ImportError
            with patch.object(scanner, "_check_zeroconf", side_effect=lambda: False):
                result = scanner._check_zeroconf()
                assert result is False


class TestMDNSScannerScan:
    """Test MDNSScanner scan method"""

    @pytest.mark.skip(
        reason="_check_zeroconf method no longer exists; zeroconf check is done inline in scan()"
    )
    def test_zeroconf_not_available_returns_empty(self, mdns_scanner_class):
        """Test that scan returns empty when zeroconf not available - SKIPPED: _check_zeroconf removed"""
        scanner = mdns_scanner_class("eth0", timeout=1)

        with patch.object(scanner, "_check_zeroconf", return_value=False):
            devices = scanner.scan()
            assert devices == {}

    @pytest.mark.skip(
        reason="_check_zeroconf method no longer exists; zeroconf check is done inline in scan()"
    )
    def test_browse_all_service_types(self, mdns_scanner_class):
        """Test that all service types are browsed - SKIPPED: _check_zeroconf removed"""
        scanner = mdns_scanner_class("eth0", timeout=1)

        mock_zeroconf = MagicMock()
        mock_browser = MagicMock()

        with patch.object(scanner, "_check_zeroconf", return_value=True):
            with patch("zeroconf.Zeroconf", return_value=mock_zeroconf):
                with patch(
                    "zeroconf.ServiceBrowser", return_value=mock_browser
                ) as mock_browser_class:
                    with patch("zeroconf.InterfaceChoice"):
                        with patch("time.sleep"):
                            scanner.scan()

                            # Should browse multiple service types
                            assert mock_browser_class.call_count > 0

    def test_service_with_addresses(self, mdns_scanner_class):
        """Test handling service with addresses"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info.port = 80
        mock_info.server = "testdevice.local."
        mock_info.properties = {}

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Test._http._tcp.local.")

        assert len(scanner.discovered_devices) == 1
        assert "192.168.1.100" in scanner.discovered_devices

    def test_service_no_addresses_skipped(self, mdns_scanner_class):
        """Test that services without addresses are skipped"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = []
        mock_info.addresses = []

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Test._http._tcp.local.")

        assert len(scanner.discovered_devices) == 0

    def test_service_properties_parsed(self, mdns_scanner_class):
        """Test that service properties are parsed"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info.port = 80
        mock_info.server = "device.local."
        mock_info.properties = {
            b"version": b"1.0",
            b"name": b"TestDevice",
        }

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Test._http._tcp.local.")

        device = scanner.discovered_devices["192.168.1.100"]
        service = device.mdns_services[0]
        assert "version" in service["properties"]
        assert service["properties"]["version"] == "1.0"

    def test_multiple_services_same_ip(self, mdns_scanner_class):
        """Test multiple services from same IP"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()

        # First service
        mock_info1 = MagicMock()
        mock_info1.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info1.port = 80
        mock_info1.server = "device.local."
        mock_info1.properties = {}

        mock_zc.get_service_info.return_value = mock_info1
        scanner._handle_service(mock_zc, "_http._tcp.local.", "Web._http._tcp.local.")

        # Second service
        mock_info2 = MagicMock()
        mock_info2.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info2.port = 22
        mock_info2.server = "device.local."
        mock_info2.properties = {}

        mock_zc.get_service_info.return_value = mock_info2
        scanner._handle_service(mock_zc, "_ssh._tcp.local.", "SSH._ssh._tcp.local.")

        # Should have one device with two services
        assert len(scanner.discovered_devices) == 1
        device = scanner.discovered_devices["192.168.1.100"]
        assert len(device.mdns_services) == 2

    def test_thread_safety(self, mdns_scanner_class):
        """Test thread-safe access to discovered_devices"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()

        def add_service(ip_suffix):
            mock_info = MagicMock()
            mock_info.parsed_addresses.return_value = [f"192.168.1.{ip_suffix}"]
            mock_info.port = 80
            mock_info.server = f"device{ip_suffix}.local."
            mock_info.properties = {}
            mock_zc.get_service_info.return_value = mock_info
            scanner._handle_service(
                mock_zc, "_http._tcp.local.", f"Device{ip_suffix}._http._tcp.local."
            )

        # Simulate concurrent access
        threads = []
        for i in range(10):
            t = threading.Thread(target=add_service, args=(i,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # All devices should be added
        assert len(scanner.discovered_devices) == 10


class TestMDNSServiceHandling:
    """Test mDNS service handling"""

    def test_handle_service_creates_device(self, mdns_scanner_class):
        """Test that handling service creates device"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info.port = 80
        mock_info.server = "mydevice.local."
        mock_info.properties = {}

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Service._http._tcp.local.")

        assert "192.168.1.100" in scanner.discovered_devices
        device = scanner.discovered_devices["192.168.1.100"]
        assert device.name == "mydevice.local"  # Stripped trailing dot
        assert "mdns" in device.discovered_by

    def test_handle_service_updates_existing(self, mdns_scanner_class):
        """Test that handling service updates existing device"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()

        # First service
        mock_info1 = MagicMock()
        mock_info1.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info1.port = 80
        mock_info1.server = "device.local."
        mock_info1.properties = {}

        mock_zc.get_service_info.return_value = mock_info1
        scanner._handle_service(mock_zc, "_http._tcp.local.", "HTTP._http._tcp.local.")

        first_seen = scanner.discovered_devices["192.168.1.100"].first_seen

        # Second service
        mock_info2 = MagicMock()
        mock_info2.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info2.port = 443
        mock_info2.server = "device.local."
        mock_info2.properties = {}

        mock_zc.get_service_info.return_value = mock_info2
        scanner._handle_service(mock_zc, "_https._tcp.local.", "HTTPS._https._tcp.local.")

        device = scanner.discovered_devices["192.168.1.100"]
        assert len(device.mdns_services) == 2
        assert device.first_seen == first_seen  # First seen unchanged

    def test_parsed_addresses_vs_raw(self, mdns_scanner_class):
        """Test fallback from parsed_addresses to raw addresses"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()

        # Simulate no parsed_addresses method
        del mock_info.parsed_addresses
        mock_info.addresses = [b"\xc0\xa8\x01\x64"]  # 192.168.1.100
        mock_info.port = 80
        mock_info.server = "device.local."
        mock_info.properties = {}

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Service._http._tcp.local.")

        # Should have extracted address from raw bytes
        assert "192.168.1.100" in scanner.discovered_devices

    def test_handle_service_info_none(self, mdns_scanner_class):
        """Test handling when service info is None"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = None

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Service._http._tcp.local.")

        assert len(scanner.discovered_devices) == 0

    def test_handle_service_exception(self, mdns_scanner_class):
        """Test exception handling in service handler"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_zc.get_service_info.side_effect = Exception("Service lookup failed")

        # Should not raise exception
        scanner._handle_service(mock_zc, "_http._tcp.local.", "Service._http._tcp.local.")

        assert len(scanner.discovered_devices) == 0


class TestMDNSServiceInfo:
    """Test mDNS service info structure"""

    def test_service_info_structure(self, mdns_scanner_class):
        """Test service info dictionary structure"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info.port = 8080
        mock_info.server = "testserver.local."
        mock_info.properties = {}

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Test._http._tcp.local.")

        device = scanner.discovered_devices["192.168.1.100"]
        service = device.mdns_services[0]

        assert "type" in service
        assert "name" in service
        assert "port" in service
        assert "server" in service
        assert "properties" in service

        assert service["type"] == "_http._tcp.local."
        assert service["port"] == 8080
        assert service["server"] == "testserver.local."

    def test_property_bytes_to_string(self, mdns_scanner_class):
        """Test that bytes properties are converted to strings"""
        scanner = mdns_scanner_class("eth0")

        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.100"]
        mock_info.port = 80
        mock_info.server = "device.local."
        mock_info.properties = {
            b"key": b"value",
            "str_key": "str_value",
        }

        mock_zc.get_service_info.return_value = mock_info

        scanner._handle_service(mock_zc, "_http._tcp.local.", "Test._http._tcp.local.")

        device = scanner.discovered_devices["192.168.1.100"]
        props = device.mdns_services[0]["properties"]

        assert props["key"] == "value"
        assert props["str_key"] == "str_value"
