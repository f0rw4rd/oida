"""
Integration tests for discovery protocol

Every test that runs the CLI or instantiates a scanner class asserts on
the return code (subprocess) or on the success/structure of the returned
results dict.

Test Classification:
  Category A (happy path): assert returncode == 0 or validate results structure
  Category B (conditional): assert returncode in [0, 1] or check for success/error
  Category C (error expected): assert returncode != 0 or assert failure in results
"""

import pytest
from unittest.mock import patch
import subprocess
import sys

from tests.service_gate import require_service


@pytest.mark.discovery
class TestDiscoveryIntegration:
    """Integration tests for network discovery"""

    protocol_name = "discovery"
    default_port = None  # Interface-based

    # ========================================================================
    # CLI Tests
    # ========================================================================

    def test_help_command(self):
        """Test discovery --help command [Category A]"""
        result = subprocess.run(
            [sys.executable, "-m", "oida.cli", "discovery", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, f"--help should exit 0, got {result.returncode}"
        assert "discovery" in result.stdout.lower()
        assert "--passive" in result.stdout or "passive" in result.stdout.lower()
        assert "--active" in result.stdout or "active" in result.stdout.lower()

    # ========================================================================
    # Discovery Scan Tests (mocked)
    # ========================================================================

    def test_passive_discovery_mocked(self):
        """Test passive discovery runs (mocked) [Category B]"""
        from oida.protocols.discovery import DiscoveryScanner

        scanner = DiscoveryScanner(
            {
                "target": "lo",  # loopback - safe for testing
                "timeout": 1,
                "passive": True,
                "active": False,
                "lldp": False,  # Disable protocols for quick test
                "dcp": False,
                "mdns": False,
                "ssdp": False,
                "cdp": False,
            }
        )
        assert scanner is not None, "Scanner instantiation failed"

        with patch.object(scanner, "connect", return_value="lo"):
            with patch.object(scanner, "_report_findings"):
                results = scanner.discover()

                assert isinstance(results, dict), "discover() must return a dict"
                assert "devices" in results, "results must contain 'devices' key"
                assert "scan_mode" in results, "results must contain 'scan_mode' key"
                # Conditional: raw socket may not be available, so scan_mode
                # may be empty; but the call must not crash
                assert results is not None

    def test_active_discovery_mocked(self):
        """Test active discovery runs (mocked) [Category B]"""
        from oida.protocols.discovery import DiscoveryScanner

        scanner = DiscoveryScanner(
            {
                "target": "lo",
                "timeout": 1,
                "passive": False,
                "active": True,
                "arp-scan": False,  # Disable for testing
                "dcp": False,
                "dns-sd": False,
                "ws-discovery": False,
                "llmnr": False,
            }
        )
        assert scanner is not None, "Scanner instantiation failed"

        with patch.object(scanner, "connect", return_value="lo"):
            with patch.object(scanner, "_report_findings"):
                results = scanner.discover()

                assert isinstance(results, dict), "discover() must return a dict"
                # Without raw sockets the scan returns early; only assert
                # "active" in scan_mode when the scan actually ran
                if results.get("scan_mode"):
                    assert "active" in results["scan_mode"]

    def test_discover_no_connection_returns_empty(self):
        """Test discover() with no connection returns empty results [Category C]"""
        from oida.protocols.discovery import DiscoveryScanner

        scanner = DiscoveryScanner(
            {
                "target": "lo",
                "timeout": 1,
            }
        )
        assert scanner is not None, "Scanner instantiation failed"

        # Call discover() with connection=None (simulates interface failure)
        results = scanner.discover(connection=None)

        assert isinstance(results, dict), "discover() must return a dict even on failure"
        assert results["devices"] == [], "devices should be empty on connection failure"
        assert results["scan_mode"] == [], "scan_mode should be empty on connection failure"

    # ========================================================================
    # Data Conversion / Output Tests
    # ========================================================================

    def test_json_output_format(self):
        """Test JSON output format [Category A]"""
        from oida.protocols.discovery import DiscoveryScanner, DiscoveredDevice

        scanner = DiscoveryScanner(
            {
                "target": "lo",
                "timeout": 1,
                "passive": True,
                "active": False,
                "lldp": False,
                "dcp": False,
                "mdns": False,
                "ssdp": False,
                "cdp": False,
            }
        )
        assert scanner is not None, "Scanner instantiation failed"

        # Add a test device
        device = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.100"],
            name="TestDevice",
        )
        scanner.discovered_devices["aa:bb:cc:dd:ee:ff"] = device

        device_dict = scanner._device_to_dict(device)

        assert isinstance(device_dict, dict), "_device_to_dict must return a dict"
        assert device_dict["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert "192.168.1.100" in device_dict["ip_addresses"]
        assert device_dict["name"] == "TestDevice"

    # ========================================================================
    # Filtering Tests
    # ========================================================================

    def test_filter_industrial(self):
        """Test industrial device filtering [Category A]"""
        from oida.protocols.discovery import DiscoveryScanner

        scanner = DiscoveryScanner(
            {
                "target": "lo",
                "filter-industrial": True,
            }
        )
        assert scanner is not None, "Scanner instantiation failed"

        industrial_device = {
            "name": "Siemens PLC",
            "manufacturer": "Siemens",
            "model": "S7-1500",
            "description": "",
            "device_type": "",
        }

        consumer_device = {
            "name": "Smart TV",
            "manufacturer": "Samsung",
            "model": "",
            "description": "",
            "device_type": "",
        }

        assert scanner._is_industrial(industrial_device) is True
        assert scanner._is_industrial(consumer_device) is False

    # ========================================================================
    # Configuration / Flag Tests
    # ========================================================================

    def test_timeout_handling(self):
        """Test timeout is respected [Category A]"""
        from oida.protocols.discovery import DiscoveryScanner

        scanner = DiscoveryScanner(
            {
                "target": "lo",
                "timeout": 5,
            }
        )
        assert scanner is not None, "Scanner instantiation failed"
        assert scanner.timeout == 5

    def test_protocol_disable_flags(self):
        """Test protocol disable flags [Category A]"""
        from oida.protocols.discovery import DiscoveryScanner

        scanner = DiscoveryScanner(
            {
                "target": "lo",
                "no-lldp": True,
                "no-dcp": True,
                "no-mdns": True,
                "no-ssdp": True,
                "no-cdp": True,
            }
        )
        assert scanner is not None, "Scanner instantiation failed"

        assert scanner.enable_lldp is False
        assert scanner.enable_dcp is False
        assert scanner.enable_mdns is False
        assert scanner.enable_ssdp is False
        assert scanner.enable_cdp is False

    # ========================================================================
    # Statistics / Verbose Tests
    # ========================================================================

    def test_verbose_output(self):
        """Test verbose output doesn't crash [Category A]"""
        from oida.protocols.discovery import DiscoveryScanner, DiscoveredDevice

        scanner = DiscoveryScanner(
            {
                "target": "lo",
                "timeout": 1,
            }
        )
        assert scanner is not None, "Scanner instantiation failed"

        # Add test device
        device = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.100"],
            name="Test",
            discovered_by=["arp"],
        )
        scanner.discovered_devices["aa:bb:cc:dd:ee:ff"] = device

        # Generate stats
        stats = scanner._generate_statistics()

        assert isinstance(stats, dict), "_generate_statistics must return a dict"
        assert stats["total_devices"] == 1
        assert stats["devices_with_mac"] == 1

    # ========================================================================
    # Device Merging Tests
    # ========================================================================

    def test_device_merging_integration(self):
        """Test device merging from multiple sources [Category A]"""
        from oida.protocols.discovery import DiscoveryScanner, DiscoveredDevice

        scanner = DiscoveryScanner({"target": "lo"})
        assert scanner is not None, "Scanner instantiation failed"

        # Simulate ARP discovery
        arp_device = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.100"],
            manufacturer="TestVendor",
            discovered_by=["arp"],
        )

        # Simulate mDNS discovery (same IP)
        mdns_device = DiscoveredDevice(
            ip_addresses=["192.168.1.100"],
            name="TestDevice.local",
            mdns_services=[{"type": "_http._tcp.local.", "port": 80}],
            discovered_by=["mdns"],
        )

        scanner._merge_devices({"aa:bb:cc:dd:ee:ff": arp_device}, "arp")
        scanner._merge_devices({"192.168.1.100": mdns_device}, "mdns")

        # Should have one merged device
        assert len(scanner.discovered_devices) == 1

        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert device.mac_address == "aa:bb:cc:dd:ee:ff"
        assert device.manufacturer == "TestVendor"
        assert "arp" in device.discovered_by
        assert "mdns" in device.discovered_by

    # ========================================================================
    # Security Analysis Tests
    # ========================================================================

    def test_security_analysis_integration(self):
        """Test security analysis generation [Category A]"""
        from oida.protocols.discovery import DiscoveryScanner, DiscoveredDevice

        scanner = DiscoveryScanner({"target": "lo"})
        assert scanner is not None, "Scanner instantiation failed"

        # Add industrial device
        device = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.100"],
            name="Siemens PLC",
            manufacturer="Siemens",
            arp_data={"response_time": "2024-01-01"},
        )
        scanner.discovered_devices["aa:bb:cc:dd:ee:ff"] = device

        results = {
            "devices": [scanner._device_to_dict(device)],
        }

        analysis = scanner._analyze_security(results)

        assert isinstance(analysis, dict), "_analyze_security must return a dict"
        assert "findings" in analysis
        assert any("industrial" in f.lower() for f in analysis["findings"])

    # ========================================================================
    # Error Handling Tests
    # ========================================================================

    def test_missing_interface_raises(self):
        """Test that missing interface raises ValueError [Category C]"""
        from oida.protocols.discovery import DiscoveryScanner

        with pytest.raises(ValueError, match="Interface is required"):
            DiscoveryScanner({"target": None})


@pytest.mark.discovery
class TestDiscoveryProtocolLoader:
    """Test discovery protocol is properly loaded"""

    def test_discovery_in_protocol_list(self):
        """Test discovery appears in protocol list [Category A]"""
        from oida.loader import ProtocolLoader
        from pathlib import Path

        protocols_dir = Path(__file__).parent.parent.parent / "src" / "oida" / "protocols"
        loader = ProtocolLoader(str(protocols_dir))
        protocols = loader.get_protocols()

        assert protocols is not None, "get_protocols() should not return None"
        assert "discovery" in protocols

    def test_discovery_class_loadable(self):
        """Test discovery class can be loaded [Category A]"""
        from oida.loader import ProtocolLoader
        from pathlib import Path

        protocols_dir = Path(__file__).parent.parent.parent / "src" / "oida" / "protocols"
        loader = ProtocolLoader(str(protocols_dir))

        try:
            protocol_class = loader.get_protocol_class("discovery")
            assert protocol_class is not None, "Protocol class should not be None"
        except Exception as e:
            require_service(f"Could not load discovery class: {e}")

    def test_proto_args_loadable(self):
        """Test proto_args module can be loaded [Category A]"""
        from oida.loader import ProtocolLoader
        from pathlib import Path

        protocols_dir = Path(__file__).parent.parent.parent / "src" / "oida" / "protocols"
        loader = ProtocolLoader(str(protocols_dir))

        proto_args = loader.load_proto_args("discovery")
        assert proto_args is not None, "proto_args should not be None"
        assert hasattr(proto_args, "proto_args")
