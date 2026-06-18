"""
Unit tests for IPv4 resolve scanner.
"""

from unittest.mock import patch, MagicMock
from datetime import datetime

from oida.protocols.discovery.ipv4_resolve import (
    IPv4ResolveScanner,
    IPv4ResolvePassiveScanner,
)
from oida.protocols.discovery.core import DiscoveredDevice


class TestIPv4ResolveScanner:
    """Tests for IPv4ResolveScanner."""

    def test_init(self):
        """Test scanner initialization."""
        scanner = IPv4ResolveScanner(
            interface="eth0",
            timeout=5,
            subnet="192.168.1.0/24",
        )
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5
        assert scanner.subnet == "192.168.1.0/24"
        assert scanner.macs_to_resolve == {}

    def test_init_with_macs(self):
        """Test scanner initialization with MACs to resolve."""
        device = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["fe80::1"],
            name="IPv6 Device",
            discovered_by=["ipv6"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
        )
        scanner = IPv4ResolveScanner(
            interface="eth0",
            macs_to_resolve={"aa:bb:cc:dd:ee:ff": device},
        )
        assert len(scanner.macs_to_resolve) == 1

    def test_scan_no_macs(self):
        """Test scan with no MACs to resolve."""
        scanner = IPv4ResolveScanner(interface="eth0")
        results = scanner.scan()
        assert results == {}

    @patch("oida.protocols.discovery.ipv4_resolve.get_interface_network")
    def test_scan_no_subnet(self, mock_get_network):
        """Test scan when no subnet can be determined."""
        mock_get_network.return_value = None

        device = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["fe80::1"],
            name="IPv6 Device",
            discovered_by=["ipv6"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
        )
        scanner = IPv4ResolveScanner(
            interface="eth0",
            macs_to_resolve={"aa:bb:cc:dd:ee:ff": device},
        )
        results = scanner.scan()
        assert results == {}

    @patch("oida.protocols.discovery.ipv4_resolve.scapy_srp")
    @patch("oida.protocols.discovery.ipv4_resolve.get_interface_network")
    def test_scan_finds_ipv4(self, mock_get_network, mock_srp):
        """Test scan successfully finds IPv4 for MAC."""
        mock_get_network.return_value = "192.168.1.0/24"

        # Mock ARP response
        mock_response = MagicMock()
        mock_response.hwsrc = "aa:bb:cc:dd:ee:ff"
        mock_response.psrc = "192.168.1.100"
        mock_srp.return_value = ([(None, mock_response)], [])

        device = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["fe80::1"],
            name="IPv6 Device",
            discovered_by=["ipv6"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
        )
        scanner = IPv4ResolveScanner(
            interface="eth0",
            macs_to_resolve={"aa:bb:cc:dd:ee:ff": device},
        )
        results = scanner.scan()

        assert len(results) == 1
        assert "aa:bb:cc:dd:ee:ff" in results
        assert "192.168.1.100" in results["aa:bb:cc:dd:ee:ff"].ip_addresses
        # IPv4 should be inserted first
        assert results["aa:bb:cc:dd:ee:ff"].ip_addresses[0] == "192.168.1.100"

    @patch("oida.protocols.discovery.ipv4_resolve.scapy_srp")
    @patch("oida.protocols.discovery.ipv4_resolve.get_interface_network")
    def test_scan_no_match(self, mock_get_network, mock_srp):
        """Test scan when ARP response doesn't match any target MAC."""
        mock_get_network.return_value = "192.168.1.0/24"

        # Mock ARP response with different MAC
        mock_response = MagicMock()
        mock_response.hwsrc = "11:22:33:44:55:66"
        mock_response.psrc = "192.168.1.100"
        mock_srp.return_value = ([(None, mock_response)], [])

        device = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["fe80::1"],
            name="IPv6 Device",
            discovered_by=["ipv6"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
        )
        scanner = IPv4ResolveScanner(
            interface="eth0",
            macs_to_resolve={"aa:bb:cc:dd:ee:ff": device},
        )
        results = scanner.scan()

        assert len(results) == 0


class TestIPv4ResolvePassiveScanner:
    """Tests for IPv4ResolvePassiveScanner (ARP cache lookup)."""

    def test_init(self):
        """Test passive scanner initialization."""
        scanner = IPv4ResolvePassiveScanner(interface="eth0")
        assert scanner.interface == "eth0"
        assert scanner.macs_to_resolve == {}

    def test_scan_no_macs(self):
        """Test scan with no MACs to resolve."""
        scanner = IPv4ResolvePassiveScanner(interface="eth0")
        results = scanner.scan()
        assert results == {}

    @patch("builtins.open")
    def test_scan_from_arp_cache(self, mock_open):
        """Test scan successfully reads from ARP cache."""
        # Mock /proc/net/arp content
        arp_content = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.100    0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.200    0x1         0x2         11:22:33:44:55:66     *        eth0
"""
        mock_open.return_value.__enter__.return_value.read.return_value = arp_content
        mock_open.return_value.__enter__.return_value.__iter__ = lambda self: iter(
            arp_content.splitlines()
        )

        device = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["fe80::1"],
            name="IPv6 Device",
            discovered_by=["ipv6"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
        )
        scanner = IPv4ResolvePassiveScanner(
            interface="eth0",
            macs_to_resolve={"aa:bb:cc:dd:ee:ff": device},
        )
        results = scanner.scan()

        assert len(results) == 1
        assert "192.168.1.100" in results["aa:bb:cc:dd:ee:ff"].ip_addresses

    @patch("builtins.open")
    def test_scan_arp_cache_not_found(self, mock_open):
        """Test scan when ARP cache cannot be read."""
        mock_open.side_effect = FileNotFoundError()

        device = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["fe80::1"],
            name="IPv6 Device",
            discovered_by=["ipv6"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
        )
        scanner = IPv4ResolvePassiveScanner(
            interface="eth0",
            macs_to_resolve={"aa:bb:cc:dd:ee:ff": device},
        )
        results = scanner.scan()

        assert results == {}
