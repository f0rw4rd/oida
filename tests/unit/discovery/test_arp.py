"""
Tests for ARPScanner class
"""

import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def arp_scanner_class():
    """Get ARPScanner class"""
    from oida.protocols.discovery import ARPScanner

    return ARPScanner


class TestARPScannerInit:
    """Test ARPScanner initialization"""

    def test_default_parameters(self, arp_scanner_class):
        """Test scanner with default parameters"""
        scanner = arp_scanner_class("eth0")

        assert scanner.interface == "eth0"
        assert scanner.subnet is None
        assert scanner.timeout == 2.0
        assert scanner.discovered_devices == {}

    def test_custom_subnet(self, arp_scanner_class):
        """Test scanner with custom subnet"""
        scanner = arp_scanner_class("eth0", subnet="10.0.0.0/24")

        assert scanner.subnet == "10.0.0.0/24"

    def test_custom_timeout(self, arp_scanner_class):
        """Test scanner with custom timeout"""
        scanner = arp_scanner_class("eth0", timeout=5.0)

        assert scanner.timeout == 5.0


class TestARPScannerScan:
    """Test ARPScanner scan method"""

    def test_scan_with_mocked_scapy(self, arp_scanner_class):
        """Test scan with mocked scapy"""
        scanner = arp_scanner_class("eth0", subnet="192.168.1.0/24")

        # Create mock response
        mock_response = MagicMock()
        mock_response.psrc = "192.168.1.100"
        mock_response.hwsrc = "aa:bb:cc:dd:ee:ff"

        mock_sent = MagicMock()

        with patch("oida.protocols.discovery.arp.get_interface_network") as mock_get_net:
            mock_get_net.return_value = "192.168.1.0/24"

            with patch("oida.protocols.discovery.arp.scapy_srp") as mock_srp:
                mock_srp.return_value = ([(mock_sent, mock_response)], [])

                with patch("scapy.all.Ether"):
                    with patch("scapy.all.ARP"):
                        with patch("scapy.all.conf"):
                            with patch(
                                "oida.protocols.discovery.arp.lookup_mac_vendor"
                            ) as mock_vendor:
                                mock_vendor.return_value = "TestVendor"

                                devices = scanner.scan()

                                assert len(devices) == 1
                                assert "aa:bb:cc:dd:ee:ff" in devices
                                device = devices["aa:bb:cc:dd:ee:ff"]
                                assert device.mac_address == "aa:bb:cc:dd:ee:ff"
                                assert "192.168.1.100" in device.ip_addresses

    def test_scan_auto_detect_subnet(self, arp_scanner_class):
        """Test that subnet is auto-detected from interface"""
        scanner = arp_scanner_class("eth0")

        with patch("oida.protocols.discovery.arp.get_interface_network") as mock_get_net:
            mock_get_net.return_value = "10.0.0.0/24"

            with patch("oida.protocols.discovery.arp.scapy_srp") as mock_srp:
                mock_srp.return_value = ([], [])

                with patch("scapy.all.Ether"):
                    with patch("scapy.all.ARP"):
                        with patch("scapy.all.conf"):
                            scanner.scan()
                            mock_get_net.assert_called_once_with("eth0")

    def test_scan_no_responses(self, arp_scanner_class):
        """Test scan with no ARP responses"""
        scanner = arp_scanner_class("eth0", subnet="192.168.1.0/24")

        with patch("oida.protocols.discovery.arp.scapy_srp") as mock_srp:
            mock_srp.return_value = ([], [])

            with patch("scapy.all.Ether"):
                with patch("scapy.all.ARP"):
                    with patch("scapy.all.conf"):
                        devices = scanner.scan()
                        assert devices == {}

    def test_scan_multiple_responses(self, arp_scanner_class):
        """Test scan with multiple ARP responses"""
        scanner = arp_scanner_class("eth0", subnet="192.168.1.0/24")

        # Create multiple mock responses
        responses = []
        for i in range(3):
            mock_response = MagicMock()
            mock_response.psrc = f"192.168.1.{100 + i}"
            mock_response.hwsrc = f"aa:bb:cc:dd:ee:{i:02x}"
            mock_sent = MagicMock()
            responses.append((mock_sent, mock_response))

        with patch("oida.protocols.discovery.arp.scapy_srp") as mock_srp:
            mock_srp.return_value = (responses, [])

            with patch("scapy.all.Ether"):
                with patch("scapy.all.ARP"):
                    with patch("scapy.all.conf"):
                        with patch("oida.protocols.discovery.arp.lookup_mac_vendor") as mock_vendor:
                            mock_vendor.return_value = "Unknown"

                            devices = scanner.scan()
                            assert len(devices) == 3

    def test_scan_scapy_not_available(self, arp_scanner_class):
        """Test scan when scapy is not installed"""
        scanner = arp_scanner_class("eth0", subnet="192.168.1.0/24")

        # Temporarily mark lazy import as unavailable
        from oida.protocols.discovery import arp

        lazy_mod = arp._scapy_all
        orig_available = lazy_mod._available
        lazy_mod._available = False
        try:
            devices = scanner.scan()
            assert devices == {}
        finally:
            lazy_mod._available = orig_available

    def test_scan_invalid_interface(self, arp_scanner_class):
        """Test scan with invalid interface"""
        scanner = arp_scanner_class("nonexistent_if", subnet="192.168.1.0/24")

        with patch("oida.protocols.discovery.arp.scapy_srp") as mock_srp:
            mock_srp.side_effect = OSError("Interface not found")

            with patch("scapy.all.Ether"):
                with patch("scapy.all.ARP"):
                    with patch("scapy.all.conf"):
                        devices = scanner.scan()
                        assert devices == {}

    def test_scan_no_subnet_no_detection(self, arp_scanner_class):
        """Test scan when subnet cannot be determined"""
        scanner = arp_scanner_class("eth0")

        with patch("oida.protocols.discovery.arp.get_interface_network") as mock_get_net:
            mock_get_net.return_value = None

            devices = scanner.scan()
            assert devices == {}

    def test_vendor_lookup_integration(self, arp_scanner_class):
        """Test that vendor lookup is called for each response"""
        scanner = arp_scanner_class("eth0", subnet="192.168.1.0/24")

        mock_response = MagicMock()
        mock_response.psrc = "192.168.1.100"
        mock_response.hwsrc = "00:0e:8c:12:34:56"  # Siemens OUI
        mock_sent = MagicMock()

        with patch("oida.protocols.discovery.arp.scapy_srp") as mock_srp:
            mock_srp.return_value = ([(mock_sent, mock_response)], [])

            with patch("scapy.all.Ether"):
                with patch("scapy.all.ARP"):
                    with patch("scapy.all.conf"):
                        with patch("oida.protocols.discovery.arp.lookup_mac_vendor") as mock_vendor:
                            mock_vendor.return_value = "Siemens AG"

                            devices = scanner.scan()
                            mock_vendor.assert_called_with("00:0e:8c:12:34:56")

                            device = devices["00:0e:8c:12:34:56"]
                            assert device.manufacturer == "Siemens AG"

    def test_device_creation_from_response(self, arp_scanner_class):
        """Test that device is properly created from ARP response"""
        scanner = arp_scanner_class("eth0", subnet="192.168.1.0/24")

        mock_response = MagicMock()
        mock_response.psrc = "192.168.1.100"
        mock_response.hwsrc = "aa:bb:cc:dd:ee:ff"
        mock_sent = MagicMock()

        with patch("oida.protocols.discovery.arp.scapy_srp") as mock_srp:
            mock_srp.return_value = ([(mock_sent, mock_response)], [])

            with patch("scapy.all.Ether"):
                with patch("scapy.all.ARP"):
                    with patch("scapy.all.conf"):
                        with patch("oida.protocols.discovery.arp.lookup_mac_vendor") as mock_vendor:
                            mock_vendor.return_value = "Unknown"

                            devices = scanner.scan()
                            device = devices["aa:bb:cc:dd:ee:ff"]

                            assert device.mac_address == "aa:bb:cc:dd:ee:ff"
                            assert device.ip_addresses == ["192.168.1.100"]
                            assert "arp" in device.discovered_by
                            assert device.first_seen != ""
                            assert device.last_seen != ""
                            assert device.arp_data is not None

    def test_scan_empty_mac_skipped(self, arp_scanner_class):
        """Test that responses with empty MAC are skipped"""
        scanner = arp_scanner_class("eth0", subnet="192.168.1.0/24")

        mock_response = MagicMock()
        mock_response.psrc = "192.168.1.100"
        mock_response.hwsrc = ""  # Empty MAC
        mock_sent = MagicMock()

        with patch("oida.protocols.discovery.arp.scapy_srp") as mock_srp:
            mock_srp.return_value = ([(mock_sent, mock_response)], [])

            with patch("scapy.all.Ether"):
                with patch("scapy.all.ARP"):
                    with patch("scapy.all.conf"):
                        devices = scanner.scan()
                        assert devices == {}

    def test_scan_empty_ip_skipped(self, arp_scanner_class):
        """Test that responses with empty IP are skipped"""
        scanner = arp_scanner_class("eth0", subnet="192.168.1.0/24")

        mock_response = MagicMock()
        mock_response.psrc = ""  # Empty IP
        mock_response.hwsrc = "aa:bb:cc:dd:ee:ff"
        mock_sent = MagicMock()

        with patch("oida.protocols.discovery.arp.scapy_srp") as mock_srp:
            mock_srp.return_value = ([(mock_sent, mock_response)], [])

            with patch("scapy.all.Ether"):
                with patch("scapy.all.ARP"):
                    with patch("scapy.all.conf"):
                        devices = scanner.scan()
                        assert devices == {}

    def test_scan_vendor_unknown_clears_manufacturer(self, arp_scanner_class):
        """Test that 'Unknown' vendor results in empty manufacturer"""
        scanner = arp_scanner_class("eth0", subnet="192.168.1.0/24")

        mock_response = MagicMock()
        mock_response.psrc = "192.168.1.100"
        mock_response.hwsrc = "aa:bb:cc:dd:ee:ff"
        mock_sent = MagicMock()

        with patch("oida.protocols.discovery.arp.scapy_srp") as mock_srp:
            mock_srp.return_value = ([(mock_sent, mock_response)], [])

            with patch("scapy.all.Ether"):
                with patch("scapy.all.ARP"):
                    with patch("scapy.all.conf"):
                        with patch("oida.protocols.discovery.arp.lookup_mac_vendor") as mock_vendor:
                            mock_vendor.return_value = "Unknown"

                            devices = scanner.scan()
                            device = devices["aa:bb:cc:dd:ee:ff"]
                            assert device.manufacturer == ""
