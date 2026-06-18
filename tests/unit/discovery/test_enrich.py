"""
Unit tests for enrichment scanners.
"""

from unittest.mock import patch, MagicMock
from datetime import datetime

from oida.protocols.discovery.enrich import (
    PingEnrichScanner,
    ReverseDNSEnrichScanner,
    NetBIOSEnrichScanner,
    MDNSEnrichScanner,
)
from oida.protocols.discovery.core import DiscoveredDevice


def make_device(mac: str, ips: list, name: str = "") -> DiscoveredDevice:
    """Helper to create test devices."""
    return DiscoveredDevice(
        mac_address=mac,
        ip_addresses=ips,
        name=name,
        discovered_by=["test"],
        first_seen=datetime.now().isoformat(),
        last_seen=datetime.now().isoformat(),
    )


class TestPingEnrichScanner:
    """Tests for PingEnrichScanner."""

    def test_init(self):
        """Test scanner initialization."""
        scanner = PingEnrichScanner(interface="eth0", timeout=5)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5
        assert scanner.devices == {}

    def test_init_with_devices(self):
        """Test scanner initialization with devices."""
        devices = {
            "aa:bb:cc:dd:ee:ff": make_device("aa:bb:cc:dd:ee:ff", ["192.168.1.100"]),
        }
        scanner = PingEnrichScanner(interface="eth0", devices=devices)
        assert len(scanner.devices) == 1

    def test_scan_no_devices(self):
        """Test scan with no devices."""
        scanner = PingEnrichScanner(interface="eth0")
        results = scanner.scan()
        assert results == {}

    @patch("oida.protocols.discovery.enrich.subprocess.run")
    def test_scan_ping_success(self, mock_run):
        """Test scan with successful ping."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="PING 192.168.1.100: 64 bytes time=1.23 ms\n",
        )

        devices = {
            "aa:bb:cc:dd:ee:ff": make_device("aa:bb:cc:dd:ee:ff", ["192.168.1.100"]),
        }
        scanner = PingEnrichScanner(interface="eth0", timeout=2, devices=devices)
        results = scanner.scan()

        assert len(results) == 1
        device = results["aa:bb:cc:dd:ee:ff"]
        assert hasattr(device, "ping_data")
        assert "192.168.1.100" in device.ping_data
        assert device.ping_data["192.168.1.100"]["alive"] is True

    @patch("oida.protocols.discovery.enrich.subprocess.run")
    def test_scan_ping_failure(self, mock_run):
        """Test scan with failed ping."""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        devices = {
            "aa:bb:cc:dd:ee:ff": make_device("aa:bb:cc:dd:ee:ff", ["192.168.1.100"]),
        }
        scanner = PingEnrichScanner(interface="eth0", timeout=2, devices=devices)
        results = scanner.scan()

        # No results for failed pings
        assert len(results) == 0

    @patch("oida.protocols.discovery.enrich.subprocess.run")
    def test_scan_ipv6(self, mock_run):
        """Test scan with IPv6 address uses IPv6 ping."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="PING fe80::1: time=0.5 ms\n",
        )

        devices = {
            "aa:bb:cc:dd:ee:ff": make_device("aa:bb:cc:dd:ee:ff", ["fe80::1"]),
        }
        scanner = PingEnrichScanner(interface="eth0", timeout=2, devices=devices)
        scanner.scan()

        # Check IPv6 ping was used (ping6 or ping -6 depending on platform)
        call_args = mock_run.call_args[0][0]
        assert call_args[0] in ("ping", "ping6")
        if call_args[0] == "ping":
            assert "-6" in call_args


class TestReverseDNSEnrichScanner:
    """Tests for ReverseDNSEnrichScanner."""

    def test_init(self):
        """Test scanner initialization."""
        scanner = ReverseDNSEnrichScanner(interface="eth0", timeout=2)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 2

    def test_scan_no_devices(self):
        """Test scan with no devices."""
        scanner = ReverseDNSEnrichScanner(interface="eth0")
        results = scanner.scan()
        assert results == {}

    @patch("oida.protocols.discovery.enrich.socket.gethostbyaddr")
    def test_scan_resolves_hostname(self, mock_gethostbyaddr):
        """Test scan successfully resolves hostname."""
        mock_gethostbyaddr.return_value = ("server.example.com", [], ["192.168.1.100"])

        devices = {
            "aa:bb:cc:dd:ee:ff": make_device("aa:bb:cc:dd:ee:ff", ["192.168.1.100"]),
        }
        scanner = ReverseDNSEnrichScanner(interface="eth0", timeout=2, devices=devices)
        results = scanner.scan()

        assert len(results) == 1
        device = results["aa:bb:cc:dd:ee:ff"]
        assert hasattr(device, "dns_names")
        assert "server.example.com" in device.dns_names
        assert device.name == "server"  # Short hostname

    @patch("oida.protocols.discovery.enrich.socket.gethostbyaddr")
    def test_scan_no_ptr_record(self, mock_gethostbyaddr):
        """Test scan when no PTR record exists."""
        import socket

        mock_gethostbyaddr.side_effect = socket.herror("Host not found")

        devices = {
            "aa:bb:cc:dd:ee:ff": make_device("aa:bb:cc:dd:ee:ff", ["192.168.1.100"]),
        }
        scanner = ReverseDNSEnrichScanner(interface="eth0", timeout=2, devices=devices)
        results = scanner.scan()

        assert len(results) == 0

    @patch("oida.protocols.discovery.enrich.socket.gethostbyaddr")
    def test_scan_preserves_existing_name(self, mock_gethostbyaddr):
        """Test scan doesn't overwrite existing device name."""
        mock_gethostbyaddr.return_value = ("newname.example.com", [], ["192.168.1.100"])

        devices = {
            "aa:bb:cc:dd:ee:ff": make_device(
                "aa:bb:cc:dd:ee:ff", ["192.168.1.100"], name="existing-name"
            ),
        }
        scanner = ReverseDNSEnrichScanner(interface="eth0", timeout=2, devices=devices)
        results = scanner.scan()

        assert len(results) == 1
        device = results["aa:bb:cc:dd:ee:ff"]
        # Existing name should be preserved
        assert device.name == "existing-name"
        # But dns_names should still be populated
        assert "newname.example.com" in device.dns_names


class TestNetBIOSEnrichScanner:
    """Tests for NetBIOSEnrichScanner."""

    def test_init(self):
        """Test scanner initialization."""
        scanner = NetBIOSEnrichScanner(interface="eth0", timeout=2)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 2

    def test_scan_no_devices(self):
        """Test scan with no devices."""
        scanner = NetBIOSEnrichScanner(interface="eth0")
        results = scanner.scan()
        assert results == {}

    def test_scan_skips_ipv6(self):
        """Test scan skips IPv6 addresses (NetBIOS is IPv4 only)."""
        devices = {
            "aa:bb:cc:dd:ee:ff": make_device("aa:bb:cc:dd:ee:ff", ["fe80::1"]),
        }
        scanner = NetBIOSEnrichScanner(interface="eth0", timeout=2, devices=devices)
        results = scanner.scan()

        # No IPv4 addresses to query
        assert len(results) == 0

    def test_parse_nbns_response_valid(self):
        """Test parsing valid NBNS response."""
        scanner = NetBIOSEnrichScanner(interface="eth0")

        # Minimal NBNS response with one name
        # Header (12) + query name (34) + type/class (4) + TTL (4) + length (2) = 56
        # Then: num_names (1) + name (15) + suffix (1) + flags (2)
        response = (
            b"\x00" * 56  # Header + query
            + b"\x01"  # 1 name
            + b"WORKSTATION    "  # 15 char name (padded)
            + b"\x00"  # suffix
            + b"\x00\x00"  # flags
        )

        name = scanner._parse_nbns_response(response)
        assert name == "WORKSTATION"

    def test_parse_nbns_response_too_short(self):
        """Test parsing too-short NBNS response."""
        scanner = NetBIOSEnrichScanner(interface="eth0")
        name = scanner._parse_nbns_response(b"\x00" * 10)
        assert name is None


class TestMDNSEnrichScanner:
    """Tests for MDNSEnrichScanner."""

    def test_init(self):
        """Test scanner initialization."""
        scanner = MDNSEnrichScanner(interface="eth0", timeout=2)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 2

    def test_scan_no_devices(self):
        """Test scan with no devices."""
        scanner = MDNSEnrichScanner(interface="eth0")
        results = scanner.scan()
        assert results == {}

    def test_expand_ipv6(self):
        """Test IPv6 expansion."""
        scanner = MDNSEnrichScanner(interface="eth0")

        # Test compressed IPv6
        expanded = scanner._expand_ipv6("fe80::1")
        assert expanded == "fe80:0000:0000:0000:0000:0000:0000:0001"

        # Test full IPv6
        expanded = scanner._expand_ipv6("2001:db8:85a3:0000:0000:8a2e:0370:7334")
        assert expanded == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"


class TestEnrichmentIntegration:
    """Integration tests for enrichment scanners."""

    def test_multiple_ips_per_device(self):
        """Test enrichment handles devices with multiple IPs."""
        devices = {
            "aa:bb:cc:dd:ee:ff": make_device(
                "aa:bb:cc:dd:ee:ff", ["192.168.1.100", "192.168.1.101", "fe80::1"]
            ),
        }

        # Test with ping scanner
        with patch("oida.protocols.discovery.enrich.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="time=1.0 ms\n",
            )

            scanner = PingEnrichScanner(interface="eth0", timeout=2, devices=devices)
            results = scanner.scan()

            assert len(results) == 1
            device = results["aa:bb:cc:dd:ee:ff"]
            # All 3 IPs should be pinged
            assert len(device.ping_data) == 3

    def test_discovered_by_updated(self):
        """Test that discovered_by is updated with enrichment source."""
        devices = {
            "aa:bb:cc:dd:ee:ff": make_device("aa:bb:cc:dd:ee:ff", ["192.168.1.100"]),
        }

        with patch("oida.protocols.discovery.enrich.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="time=1.0 ms\n")

            scanner = PingEnrichScanner(interface="eth0", timeout=2, devices=devices)
            results = scanner.scan()

            device = results["aa:bb:cc:dd:ee:ff"]
            assert "ping" in device.discovered_by

        with patch("oida.protocols.discovery.enrich.socket.gethostbyaddr") as mock_dns:
            mock_dns.return_value = ("host.example.com", [], ["192.168.1.100"])

            scanner = ReverseDNSEnrichScanner(interface="eth0", timeout=2, devices=devices)
            results = scanner.scan()

            device = results["aa:bb:cc:dd:ee:ff"]
            assert "rdns" in device.discovered_by
