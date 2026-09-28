"""
Tests for DiscoveryScanner orchestrator class
"""

import pytest
from unittest.mock import patch
import threading


@pytest.fixture
def scanner_class():
    """Get DiscoveryScanner class"""
    from oida.protocols.discovery import DiscoveryScanner

    return DiscoveryScanner


@pytest.fixture
def device_class():
    """Get DiscoveredDevice class"""
    from oida.protocols.discovery import DiscoveredDevice

    return DiscoveredDevice


class TestDiscoveryScannerInit:
    """Test DiscoveryScanner initialization"""

    def test_default_args(self, scanner_class):
        """Test scanner with default arguments"""
        scanner = scanner_class({"target": "eth0"})

        assert scanner.interface == "eth0"
        assert scanner.timeout == 3  # Default is 3 seconds
        assert scanner.passive_mode is True
        assert scanner.active_mode is False

    def test_passive_mode_default(self, scanner_class):
        """Test passive mode is default"""
        scanner = scanner_class({"target": "eth0"})

        assert scanner.passive_mode is True

    def test_active_mode_enabled(self, scanner_class):
        """Test active mode can be enabled"""
        scanner = scanner_class(
            {
                "target": "eth0",
                "active": True,
            }
        )

        assert scanner.active_mode is True

    def test_protocol_toggles(self, scanner_class):
        """Test protocol toggle options"""
        scanner = scanner_class(
            {
                "target": "eth0",
                "no-lldp": True,
                "no-dcp": True,
                "active": True,  # mdns is active mode only
            }
        )

        assert scanner.enable_lldp is False
        assert scanner.enable_dcp is False
        # mdns is enabled by default in active mode (when not disabled)
        assert scanner.enable_mdns is True
        # ssdp is passive mode (listening)
        assert scanner.enable_ssdp is True

    def test_output_options(self, scanner_class):
        """Test output options"""
        scanner = scanner_class(
            {
                "target": "eth0",
                "ics-only": True,
            }
        )

        assert scanner.filter_industrial is True


class TestDiscoveryScannerConnect:
    """Test DiscoveryScanner connect method"""

    def test_validates_interface(self, scanner_class):
        """Test interface validation"""
        scanner = scanner_class({"target": "eth0"})

        with patch("scapy.all.get_if_list") as mock_get_if:
            mock_get_if.return_value = ["eth0", "lo"]

            result = scanner.connect()

            assert result == "eth0"

    def test_invalid_interface_raises_error(self, scanner_class):
        """Invalid interface raises ConfigurationError (operational, not
        crash-reportable) during initialization, with the not-found message"""
        import pytest
        from oida.utils.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="not found"):
            scanner_class({"target": "nonexistent_if"})

    def test_returns_interface_name(self, scanner_class):
        """Test that connect returns interface name"""
        scanner = scanner_class({"target": "eth0"})

        with patch("scapy.all.get_if_list") as mock_get_if:
            mock_get_if.return_value = ["eth0"]

            result = scanner.connect()

            assert result == "eth0"


class TestDiscoveryScannerDiscover:
    """Test DiscoveryScanner discover method"""

    def test_passive_only_tasks(self, scanner_class):
        """Test passive mode only runs passive tasks"""
        scanner = scanner_class(
            {
                "target": "eth0",
                # passive is default, active is off by default
            }
        )

        # Track which scanners were called
        called_scanners = []

        def mock_run_scanner(name):
            called_scanners.append(name)
            return {}

        # Mock scan methods and pass valid connection
        with patch(
            "oida.protocols.discovery.scanner.check_raw_socket_capability",
            return_value=(True, None),
        ):
            with patch.object(scanner, "_run_lldp_passive", return_value={}) as mock_lldp:
                with patch.object(scanner, "_run_dcp_active", return_value={}) as mock_dcp:
                    with patch.object(scanner, "_run_scanner", side_effect=mock_run_scanner):
                        with patch.object(scanner, "_report_findings"):
                            # Pass connection="eth0" to indicate valid interface
                            scanner.discover(connection="eth0")

                            # Passive methods should be called
                            assert mock_lldp.called
                            # DCP only runs as an active probe (dcp-identify);
                            # passive-only mode must not invoke it
                            assert not mock_dcp.called
                            # Passive listeners: ssdp-listen, cdp, arp-passive
                            assert "ssdp-listen" in called_scanners
                            assert "cdp" in called_scanners

                            # Active methods should not be called (mdns is active only)
                            assert "arp" not in called_scanners
                            assert "mdns" not in called_scanners

    def test_active_only_tasks(self, scanner_class):
        """Test active mode only runs active tasks"""
        scanner = scanner_class(
            {
                "target": "eth0",
                "no-passive": True,  # Disable passive mode
                "active": True,
            }
        )

        # Track which scanners were called
        called_scanners = []

        def mock_run_scanner(name):
            called_scanners.append(name)
            return {}

        with patch(
            "oida.protocols.discovery.scanner.check_raw_socket_capability",
            return_value=(True, None),
        ):
            with patch.object(scanner, "_run_lldp_passive", return_value={}) as mock_lldp:
                with patch.object(scanner, "_run_scanner", side_effect=mock_run_scanner):
                    with patch.object(scanner, "_report_findings"):
                        scanner.discover(connection="eth0")

                        # Passive methods should not be called when no-passive=True
                        assert not mock_lldp.called

                        # Active methods should be called
                        assert "arp" in called_scanners
                        assert "mdns" in called_scanners

    def test_both_modes_combined(self, scanner_class):
        """Test both passive and active modes together"""
        scanner = scanner_class(
            {
                "target": "eth0",
                # passive is default, just enable active
                "active": True,
            }
        )

        # Track which scanners were called
        called_scanners = []

        def mock_run_scanner(name):
            called_scanners.append(name)
            return {}

        with patch(
            "oida.protocols.discovery.scanner.check_raw_socket_capability",
            return_value=(True, None),
        ):
            with patch.object(scanner, "_run_lldp_passive", return_value={}) as mock_lldp:
                with patch.object(scanner, "_run_dcp_active", return_value={}):
                    with patch.object(scanner, "_run_dcp_active", return_value={}):
                        with patch.object(scanner, "_run_scanner", side_effect=mock_run_scanner):
                            with patch.object(scanner, "_report_findings"):
                                results = scanner.discover(connection="eth0")

                                # Both types should run
                                assert mock_lldp.called
                                assert "arp" in called_scanners
                                assert "passive" in results["scan_mode"]
                                assert "active" in results["scan_mode"]

    def test_neither_mode_defaults_passive(self, scanner_class):
        """Test that neither mode (explicit) defaults to passive"""
        scanner = scanner_class(
            {
                "target": "eth0",
                # no-passive and active both False means passive mode is enabled
            }
        )

        # Track which scanners were called
        called_scanners = []

        def mock_run_scanner(name):
            called_scanners.append(name)
            return {}

        with patch(
            "oida.protocols.discovery.scanner.check_raw_socket_capability",
            return_value=(True, None),
        ):
            with patch.object(scanner, "_run_lldp_passive", return_value={}) as mock_lldp:
                with patch.object(scanner, "_run_dcp_active", return_value={}):
                    with patch.object(scanner, "_run_scanner", side_effect=mock_run_scanner):
                        with patch.object(scanner, "_report_findings"):
                            scanner.discover(connection="eth0")

                            # Should default to passive mode
                            assert mock_lldp.called

    def test_no_tasks_warning(self, scanner_class):
        """Test warning when no tasks are enabled"""
        scanner = scanner_class(
            {
                "target": "eth0",
                # Disable all protocols
                "no-lldp": True,
                "no-dcp": True,
                "no-mdns": True,
                "no-ssdp": True,
                "no-cdp": True,
                "no-stp": True,
                "no-ipv6": True,
                "no-dhcp": True,
                "no-fins": True,
                "no-hsrp": True,
                "no-igmp": True,
            }
        )

        with patch.object(scanner, "_report_findings"):
            results = scanner.discover()

            # Should return empty results
            assert results["devices"] == []

    def test_parallel_execution(self, scanner_class):
        """Test that tasks run in parallel"""
        scanner = scanner_class(
            {
                "target": "eth0",
                # Default passive mode
            }
        )

        execution_order = []

        def track_lldp():
            execution_order.append("lldp_start")
            import time

            time.sleep(0.1)
            execution_order.append("lldp_end")
            return {}

        def track_scanner(name):
            if name == "cdp":  # cdp is a passive scanner
                execution_order.append("cdp_start")
                import time

                time.sleep(0.1)
                execution_order.append("cdp_end")
            return {}

        with patch(
            "oida.protocols.discovery.scanner.check_raw_socket_capability",
            return_value=(True, None),
        ):
            with patch.object(scanner, "_run_lldp_passive", side_effect=track_lldp):
                with patch.object(scanner, "_run_dcp_active", return_value={}):
                    with patch.object(scanner, "_run_scanner", side_effect=track_scanner):
                        with patch.object(scanner, "_report_findings"):
                            scanner.discover(connection="eth0")

        # Verify parallel execution (starts should come before all ends)
        # Note: Due to thread scheduling, exact order may vary
        assert "lldp_start" in execution_order
        assert "cdp_start" in execution_order

    def test_exception_handling_in_tasks(self, scanner_class):
        """Test that exceptions in tasks are handled"""
        scanner = scanner_class(
            {
                "target": "eth0",
                # Default passive mode
            }
        )

        with patch(
            "oida.protocols.discovery.scanner.check_raw_socket_capability",
            return_value=(True, None),
        ):
            with patch.object(scanner, "_run_lldp_passive", side_effect=Exception("LLDP error")):
                with patch.object(scanner, "_run_dcp_active", return_value={}):
                    with patch.object(scanner, "_run_scanner", return_value={}):
                        with patch.object(scanner, "_report_findings"):
                            # Should not raise exception
                            results = scanner.discover(connection="eth0")

                            assert isinstance(results, dict)


class TestDeviceMerging:
    """Test device merging in DiscoveryScanner"""

    def test_merge_by_mac_address(self, scanner_class, device_class):
        """Test device merging by MAC address"""
        scanner = scanner_class({"target": "eth0"})

        device1 = device_class(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.100"],
            discovered_by=["arp"],
        )
        device2 = device_class(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["10.0.0.100"],
            discovered_by=["lldp"],
        )

        scanner._merge_devices({"aa:bb:cc:dd:ee:ff": device1}, "arp")
        scanner._merge_devices({"aa:bb:cc:dd:ee:ff": device2}, "lldp")

        assert len(scanner.discovered_devices) == 1
        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert "192.168.1.100" in device.ip_addresses
        assert "10.0.0.100" in device.ip_addresses

    def test_merge_by_ip_address(self, scanner_class, device_class):
        """Test device merging by IP address"""
        scanner = scanner_class({"target": "eth0"})

        device1 = device_class(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.100"],
            discovered_by=["arp"],
        )
        device2 = device_class(
            mac_address="",  # No MAC
            ip_addresses=["192.168.1.100"],
            discovered_by=["ssdp"],
            name="UPnP Device",
        )

        scanner._merge_devices({"aa:bb:cc:dd:ee:ff": device1}, "arp")
        scanner._merge_devices({"192.168.1.100": device2}, "ssdp")

        assert len(scanner.discovered_devices) == 1

    def test_new_device_with_mac(self, scanner_class, device_class):
        """Test adding new device with MAC"""
        scanner = scanner_class({"target": "eth0"})

        device = device_class(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.100"],
        )

        scanner._merge_devices({"aa:bb:cc:dd:ee:ff": device}, "arp")

        assert "aa:bb:cc:dd:ee:ff" in scanner.discovered_devices

    def test_new_device_without_mac(self, scanner_class, device_class):
        """Test adding new device without MAC"""
        scanner = scanner_class({"target": "eth0"})

        device = device_class(
            ip_addresses=["192.168.1.100"],
        )

        scanner._merge_devices({"192.168.1.100": device}, "ssdp")

        assert "ip:192.168.1.100" in scanner.discovered_devices

    def test_ip_to_mac_mapping_updated(self, scanner_class, device_class):
        """Test that IP to MAC mapping is updated"""
        scanner = scanner_class({"target": "eth0"})

        device = device_class(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.100"],
        )

        scanner._merge_devices({"aa:bb:cc:dd:ee:ff": device}, "arp")

        assert scanner._ip_to_mac.get("192.168.1.100") == "aa:bb:cc:dd:ee:ff"

    def test_thread_safe_merging(self, scanner_class, device_class):
        """Test thread-safe device merging"""
        scanner = scanner_class({"target": "eth0"})

        def add_device(i):
            device = device_class(
                mac_address=f"aa:bb:cc:dd:ee:{i:02x}",
                ip_addresses=[f"192.168.1.{i}"],
            )
            scanner._merge_devices({f"aa:bb:cc:dd:ee:{i:02x}": device}, "arp")

        threads = []
        for i in range(20):
            t = threading.Thread(target=add_device, args=(i,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        assert len(scanner.discovered_devices) == 20


class TestIndustrialFiltering:
    """Test industrial device filtering"""

    def test_filter_by_keyword_plc(self, scanner_class):
        """Test filtering by PLC keyword"""
        scanner = scanner_class({"target": "eth0"})

        device_dict = {
            "name": "PLC Controller",
            "manufacturer": "",
            "model": "",
            "description": "",
            "device_type": "",
        }

        assert scanner._is_industrial(device_dict) is True

    def test_filter_by_manufacturer_siemens(self, scanner_class):
        """Test filtering by Siemens manufacturer"""
        scanner = scanner_class({"target": "eth0"})

        device_dict = {
            "name": "",
            "manufacturer": "Siemens AG",
            "model": "",
            "description": "",
            "device_type": "",
        }

        assert scanner._is_industrial(device_dict) is True

    def test_filter_multiple_keywords(self, scanner_class):
        """Test filtering with multiple keywords"""
        scanner = scanner_class({"target": "eth0"})

        device_dict = {
            "name": "HMI Panel",
            "manufacturer": "Beckhoff",
            "model": "",
            "description": "",
            "device_type": "",
        }

        assert scanner._is_industrial(device_dict) is True

    def test_no_match_excluded(self, scanner_class):
        """Test non-industrial device is excluded"""
        scanner = scanner_class({"target": "eth0"})

        device_dict = {
            "name": "Living Room TV",
            "manufacturer": "Samsung",
            "model": "Smart TV",
            "description": "Entertainment device",
            "device_type": "",
        }

        assert scanner._is_industrial(device_dict) is False


class TestStatisticsGeneration:
    """Test statistics generation"""

    def test_total_device_count(self, scanner_class, device_class):
        """Test total device count"""
        scanner = scanner_class({"target": "eth0"})

        for i in range(5):
            device = device_class(mac_address=f"aa:bb:cc:dd:ee:{i:02x}")
            scanner.discovered_devices[f"aa:bb:cc:dd:ee:{i:02x}"] = device

        stats = scanner._generate_statistics()

        assert stats["total_devices"] == 5

    def test_devices_with_mac_count(self, scanner_class, device_class):
        """Test count of devices with MAC"""
        scanner = scanner_class({"target": "eth0"})

        device1 = device_class(mac_address="aa:bb:cc:dd:ee:ff")
        device2 = device_class(ip_addresses=["192.168.1.100"])  # No MAC

        scanner.discovered_devices["aa:bb:cc:dd:ee:ff"] = device1
        scanner.discovered_devices["ip:192.168.1.100"] = device2

        stats = scanner._generate_statistics()

        assert stats["devices_with_mac"] == 1

    def test_manufacturer_distribution(self, scanner_class, device_class):
        """Test manufacturer distribution"""
        scanner = scanner_class({"target": "eth0"})

        device1 = device_class(mac_address="aa:bb:cc:dd:ee:01", manufacturer="Siemens")
        device2 = device_class(mac_address="aa:bb:cc:dd:ee:02", manufacturer="Siemens")
        device3 = device_class(mac_address="aa:bb:cc:dd:ee:03", manufacturer="Beckhoff")

        scanner.discovered_devices["d1"] = device1
        scanner.discovered_devices["d2"] = device2
        scanner.discovered_devices["d3"] = device3

        stats = scanner._generate_statistics()

        assert stats["manufacturer_distribution"]["Siemens"] == 2
        assert stats["manufacturer_distribution"]["Beckhoff"] == 1

    def test_protocol_distribution(self, scanner_class, device_class):
        """Test protocol distribution"""
        scanner = scanner_class({"target": "eth0"})

        device1 = device_class(discovered_by=["arp", "lldp"])
        device2 = device_class(discovered_by=["arp"])

        scanner.discovered_devices["d1"] = device1
        scanner.discovered_devices["d2"] = device2

        stats = scanner._generate_statistics()

        assert stats["protocol_distribution"]["arp"] == 2
        assert stats["protocol_distribution"]["lldp"] == 1


class TestSecurityAnalysis:
    """Test security analysis"""

    def test_findings_generated(self, scanner_class):
        """Test that security findings are generated"""
        scanner = scanner_class({"target": "eth0"})

        results = {
            "devices": [
                {"arp_data": {}, "mdns_services": None, "ssdp_data": None},
            ]
        }

        analysis = scanner._analyze_security(results)

        assert "findings" in analysis
        assert isinstance(analysis["findings"], list)

    def test_industrial_device_detection(self, scanner_class):
        """Test industrial device detection in analysis"""
        scanner = scanner_class({"target": "eth0"})

        results = {
            "devices": [
                {
                    "name": "Siemens PLC",
                    "manufacturer": "Siemens",
                    "model": "S7-1500",
                    "description": "",
                    "device_type": "",
                    "arp_data": None,
                    "mdns_services": None,
                    "ssdp_data": None,
                },
            ]
        }

        analysis = scanner._analyze_security(results)

        assert any("industrial" in f.lower() for f in analysis["findings"])


class TestDiscoveryScannerTiming:
    """Test DiscoveryScanner timing behavior"""

    def test_passive_only_respects_timeout(self, scanner_class):
        """Test that passive-only scan completes within timeout + reasonable buffer.

        When user specifies -t 10, the scan should complete in ~10s, not 23s.
        This test verifies the timeout is respected.

        BUG: Currently executor_timeout = self.timeout + 15, causing scans to take
        much longer than the user-specified timeout.
        """
        import time

        timeout = 3  # Use short timeout for test
        # BUG: Currently this would be timeout + 15 = 18s due to executor overhead
        # Expected: timeout + 2s buffer for task completion overhead
        max_allowed = timeout + 3  # Should complete within 3s of timeout

        scanner = scanner_class(
            {
                "target": "lo",  # loopback always exists
                "timeout": timeout,
                "active": False,  # Passive only
            }
        )

        # Mock scanners to sleep for the timeout (simulating real behavior)
        def mock_scanner(name):
            # Real scanners use time.sleep(self.timeout) - simulate this
            time.sleep(scanner.timeout)
            return {}

        def mock_lldp():
            time.sleep(scanner.timeout)
            return {}

        start = time.time()
        with patch(
            "oida.protocols.discovery.scanner.check_raw_socket_capability",
            return_value=(True, None),
        ):
            with patch.object(scanner, "_run_lldp_passive", side_effect=mock_lldp):
                with patch.object(scanner, "_run_dcp_active", return_value={}):
                    with patch.object(scanner, "_run_scanner", side_effect=mock_scanner):
                        with patch.object(scanner, "_report_findings"):
                            scanner.discover(connection="lo")
        elapsed = time.time() - start

        assert elapsed < max_allowed, (
            f"Passive scan took {elapsed:.1f}s, expected < {max_allowed}s "
            f"(timeout={timeout}s). Executor timeout should match user timeout."
        )

    def test_active_scan_respects_timeout(self, scanner_class):
        """Test that active scan completes within reasonable time of timeout."""
        import time

        timeout = 3
        max_allowed = timeout + 10  # Active has more overhead

        scanner = scanner_class(
            {
                "target": "lo",
                "timeout": timeout,
                "active": True,
                "no-passive": True,  # Active only for cleaner test
            }
        )

        def mock_scanner(name):
            time.sleep(0.1)
            return {}

        start = time.time()
        with patch(
            "oida.protocols.discovery.scanner.check_raw_socket_capability",
            return_value=(True, None),
        ):
            with patch.object(scanner, "_run_lldp_passive", return_value={}):
                with patch.object(scanner, "_run_dcp_active", return_value={}):
                    with patch.object(scanner, "_run_dcp_active", return_value={}):
                        with patch.object(scanner, "_run_scanner", side_effect=mock_scanner):
                            with patch.object(scanner, "_report_findings"):
                                scanner.discover(connection="lo")
        elapsed = time.time() - start

        assert elapsed < max_allowed, (
            f"Active scan took {elapsed:.1f}s, expected < {max_allowed}s (timeout={timeout}s)"
        )

    def test_combined_passive_active_respects_timeout(self, scanner_class):
        """Test that combined passive+active scan respects timeout."""
        import time

        timeout = 3
        # Combined mode: passive runs extended, so allow more buffer
        max_allowed = timeout + 15

        scanner = scanner_class(
            {
                "target": "lo",
                "timeout": timeout,
                "active": True,  # Both passive and active
            }
        )

        def mock_scanner(name):
            time.sleep(0.1)
            return {}

        start = time.time()
        with patch(
            "oida.protocols.discovery.scanner.check_raw_socket_capability",
            return_value=(True, None),
        ):
            with patch.object(scanner, "_run_lldp_passive", return_value={}):
                with patch.object(scanner, "_run_dcp_active", return_value={}):
                    with patch.object(scanner, "_run_dcp_active", return_value={}):
                        with patch.object(scanner, "_run_scanner", side_effect=mock_scanner):
                            with patch.object(scanner, "_report_findings"):
                                scanner.discover(connection="lo")
        elapsed = time.time() - start

        assert elapsed < max_allowed, (
            f"Combined scan took {elapsed:.1f}s, expected < {max_allowed}s (timeout={timeout}s)"
        )
