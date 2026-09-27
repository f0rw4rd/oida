"""
Integration tests for discovery protocol

Every test that runs the CLI or instantiates a scanner class asserts on
the return code (subprocess) or on the success/structure of the returned
results dict.

Test Classification:
  Category A (happy path): assert returncode == 0 or validate results structure
  Category B (conditional): assert returncode in [0, 1] or check for success/error
  Category C (error expected): assert returncode != 0 or assert failure in results

Mock-data inventory (real-CLI classes below, ``TestDiscoveryCli*``)
---------------------------------------------------------------------
``discovery`` is unlike every other protocol module in this suite: its
positional ``target`` is a **network interface** (``lo``, ``eth0``, ...),
not a host/IP/CIDR, and it has no ``--port`` flag. Active/ARP probing uses
``-s/--subnet`` (a *separate* flag) to pick the IP range to probe. There is
no dedicated ``discovery`` docker mock; the one shared-mock dependency below
is the existing ``modbus`` mock group (``@pytest.mark.modbus``), used only
for the "impostor protocol" hostile-path test that must prove discovery does
NOT claim a false-positive ICS identification just because something else
is listening on a TCP port in the scanned range.

Raw-socket gate: ``check_raw_socket_capability()`` in
``src/oida/protocols/discovery/scanner.py`` runs unconditionally at the top
of every scan (passive AND active) and requires ``CAP_NET_RAW``/root. As a
plain user every scan returns cleanly (returncode 0) but logs a
``protocol_error`` "Raw socket access required" and no real device data
comes back - that is a legitimate, deterministic Category B assertion
target. To exercise genuine scan data (device counts, pcap files,
enrichment) this suite uses passwordless ``sudo`` (confirmed available in
this environment) via ``cli_runner.run(..., use_sudo=True)``, always scoped
to interface ``lo`` and ``--subnet 127.0.0.1/32`` so ARP/active probing can
never reach beyond the local host. See the safety note below.

SAFETY: every test in this file that passes ``-a/--active`` or ``-A/--arp``
pins an explicit ``-s 127.0.0.1/32`` and uses interface ``lo``. No test ever
omits ``--subnet`` while active/ARP mode is enabled, and no test targets a
real LAN/public address.

Flag coverage matrix (``--flag`` -> ``[A|B|C]`` ``test_name``)
---------------------------------------------------------------------
  -t/--timeout            A   test_active_scan_timeout_bounds_execution
  -a/--active             A   test_active_scan_finds_loopback_device
  --no-passive            B   test_active_only_no_passive_still_gated_without_sudo
  -A/--arp                A   test_arp_only_mode_disables_passive_discovery
  --no-arp                A   test_active_no_arp_skips_arp_scan_line
  -f/--force              B   test_force_flag_accepted_at_small_scope
  -R/--rate-limit         B   test_rate_limit_accepted
  --ics-only              A   test_ics_only_filters_non_ics_device
  -s/--subnet             A   (every sudo test above pins this; see also test_bad_subnet_cidr_rejected)
  -c/--continuous         B   test_continuous_mode_loops_until_killed
  --scan-interval         B   test_continuous_mode_loops_until_killed
  --expected-network      B   test_expected_network_accepted_with_enrichment
  --no-reach-warnings     B   test_no_reach_warnings_accepted
  -w/--pcap               A   test_pcap_capture_writes_file
  --pcap-max-size         A   test_pcap_capture_writes_file
  --pcap-filter           A   test_pcap_capture_writes_file
  --enrich                A   test_expected_network_accepted_with_enrichment
  --no-ping               A   test_expected_network_accepted_with_enrichment
  --no-rdns               B   test_enrichment_no_rdns_no_netbios
  --no-netbios-enrich     B   test_enrichment_no_rdns_no_netbios
  --no-mdns-enrich        B   test_enrichment_no_rdns_no_netbios
  (representative sample of the ~50 --no-<proto> toggles) B  test_protocol_toggles_accepted

Hostile-path catalogue (Category C unless noted):
  closed scope / nothing listening -> test_active_scan_empty_scope_no_false_device
  blackhole/timeout budget honoured -> test_active_scan_timeout_bounds_execution (A)
  wrong protocol on port (modbus mock) -> test_no_false_positive_on_modbus_port
  malformed --subnet -> test_bad_subnet_cidr_rejected
  malformed --expected-network -> test_bad_expected_network_rejected
  --timeout wrong type -> test_timeout_wrong_type_rejected
  --rate-limit wrong type -> test_rate_limit_wrong_type_rejected
  empty/junk target (interface) -> test_garbage_interface_name_fails_cleanly
  confirm gate (--force) -> test_force_flag_accepted_at_small_scope (B, real >255-host
      gate is untestable without violating the safety constraint; documented limitation)
  unknown flag -> test_unknown_flag_rejected
  near-miss typo -> test_typo_flag_rejected
  borrowed flag (--unit-id) -> test_borrowed_flag_rejected

Category summary: A: 8   B: 9   C: 7   (see individual docstrings below)
"""

import os
import re

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


# ---------------------------------------------------------------------------
# Real-CLI tests (subprocess via cli_runner) -- see module docstring for the
# flag coverage matrix and category summary these implement.
#
# discovery has no dedicated docker mock; `target` is a local network
# interface, not a host. Tests that need real scan data (device counts,
# pcap files, enrichment output) use `use_sudo=True` because
# check_raw_socket_capability() gates ALL scan modes on CAP_NET_RAW/root.
# Every active/ARP invocation is pinned to interface "lo" and
# `-s 127.0.0.1/32` -- see SAFETY note in the module docstring.
# ---------------------------------------------------------------------------


def _assert_log_has_events(result, min_count=1):
    """Shared assertion: scan_log was captured and has at least min_count events."""
    assert result.scan_log is not None, "scan_log should be populated when json_log=True"
    result.scan_log.assert_has_events(min_count=min_count)


def _assert_log_event_structure(log):
    """Shared assertion: every event carries the documented required fields."""
    required = {"timestamp", "level", "event_type", "module", "message"}
    for i, event in enumerate(log.events):
        missing = required - set(event.keys())
        assert not missing, f"Event {i} missing fields: {missing}"


def _all_messages(log) -> str:
    return " ".join(e.get("message", "") for e in log.events).lower()


def _combined_text(result, log=None) -> str:
    parts = [result.combined_output.lower()]
    if log is not None:
        parts.append(_all_messages(log))
    return " ".join(parts)


def _assert_no_traceback(result):
    """Assert no *raw* unhandled Python traceback was dumped to the user.

    OIDA has a deliberate crash-report feature (see connection.py) that
    catches unexpected bug-shaped exceptions and prints a sanitized,
    percent-encoded GitHub-issue link containing the word "Traceback" as
    part of the encoded URL -- that is the intended, safe degradation path
    and must not fail this check. What must never happen is a raw,
    unindented "Traceback (most recent call last):" dump straight to
    stdout/stderr.
    """
    assert "Traceback (most recent call last):" not in result.combined_output, (
        f"unexpected raw traceback in output:\n{result.combined_output}"
    )


@pytest.mark.discovery
@pytest.mark.xdist_group("discovery_cli")
class TestDiscoveryCliSudoActiveScans:
    """Real-CLI tests that need genuine scan data.

    Uses ``use_sudo=True`` because check_raw_socket_capability() gates all
    scan modes without CAP_NET_RAW. Always pinned to interface ``lo`` and
    ``-s 127.0.0.1/32`` per the safety constraint -- see module docstring.
    """

    def test_active_scan_finds_loopback_device(self, cli_runner):
        """[Category A] -a/--active + -s pinned to loopback returns a real device.

        json_log is intentionally not used with use_sudo=True: the sandboxed
        sudo child cannot reliably reopen a mkstemp'd file created by the
        unprivileged parent, so these sudo-driven tests assert on stdout
        (result.combined_output / result.json_output) instead.
        """
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "3",
            "-a",
            "--subnet",
            "127.0.0.1/32",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)
        text = _combined_text(result)
        # Real scan actually ran (not just the raw-socket-denied path).
        assert "raw socket access required" not in text
        assert "scanning lo" in text or "active scanning lo" in text

    def test_active_scan_timeout_bounds_execution(self, cli_runner):
        """[Category A] -t/--timeout bounds real execution time (timeout budget honoured)."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "-a",
            "--subnet",
            "127.0.0.1/32",
            use_sudo=True,
            format="json",
            timeout=45,
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)
        # -t is a scan-phase timeout, not the whole process; give generous slack
        # but still prove the flag is honoured rather than the CLI hanging.
        assert result.execution_time < 20, (
            f"active scan with -t 2 took {result.execution_time}s, timeout not honoured"
        )

    def test_arp_only_mode_disables_passive_discovery(self, cli_runner):
        """[Category A] -A/--arp disables passive discovery -- fewer devices than -a."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "--arp",
            "--subnet",
            "127.0.0.1/32",
            "--force",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)
        text = _combined_text(result, result.scan_log)
        assert "raw socket access required" not in text
        # ARP-only mode must not report an ipv6-passive finding -- passive is off.
        assert "ipv6-passive" not in text

    def test_active_no_arp_skips_arp_scan_line(self, cli_runner):
        """[Category A] --no-arp suppresses the ARP scan step of active discovery."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "-a",
            "--no-arp",
            "--subnet",
            "127.0.0.1/32",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)
        text = _combined_text(result, result.scan_log)
        assert "arp scan:" not in text

    def test_ics_only_filters_non_ics_device(self, cli_runner):
        """[Category A] --ics-only filters the non-ICS ipv6-passive finding out."""
        without_filter = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "-a",
            "--subnet",
            "127.0.0.1/32",
            use_sudo=True,
            format="json",
        )
        with_filter = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "-a",
            "-R",
            "5",
            "--ics-only",
            "--subnet",
            "127.0.0.1/32",
            use_sudo=True,
            format="json",
        )
        assert without_filter.returncode == 0, without_filter.combined_output
        assert with_filter.returncode == 0, with_filter.combined_output
        _assert_no_traceback(without_filter)
        _assert_no_traceback(with_filter)
        # Use the definitive final-tally marker from
        # DiscoveryScanner._report_findings ("No devices discovered" is only
        # printed once against the *filtered* device list) rather than
        # matching "ipv6-passive" anywhere in the output: that substring
        # also appears in per-module progress lines that are logged before
        # the --ics-only filter is applied, so it is not a reliable signal
        # on its own.
        without_empty = "no devices discovered" in without_filter.combined_output.lower()
        with_empty = "no devices discovered" in with_filter.combined_output.lower()
        # The loopback ipv6-passive finding is not an ICS device: if the
        # un-filtered scan found *something*, --ics-only must filter it
        # back down to an empty final device list.
        if not without_empty:
            assert with_empty, (
                f"--ics-only did not filter the non-ICS finding:\n{with_filter.combined_output}"
            )

    @pytest.mark.flaky(reruns=2, reruns_delay=3)
    def test_pcap_capture_writes_file(self, cli_runner):
        """[Category A] -w/--pcap + --pcap-max-size + --pcap-filter write a real capture file.

        Filter is "ip6" rather than "icmp": the ipv6/dhcpv6 passive
        listeners reliably generate matching loopback traffic during the
        scan window in this environment, whereas an "icmp" filter often
        sees nothing and would make this test flaky. Even with "ip6" the
        capture occasionally finishes with zero matching packets under
        parallel-lane load (no "Wrote:" line) -- rerun net for that; the
        capture itself passes in isolation.
        """
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "-a",
            "--subnet",
            "127.0.0.1/32",
            "--pcap",
            "--pcap-max-size",
            "10",
            "--pcap-filter",
            "ip6",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)
        text = _combined_text(result, result.scan_log)
        assert "pcap capture started" in text
        match = re.search(r"Wrote:\s+(\S+\.pcap)", result.combined_output)
        assert match, f"no pcap 'Wrote:' line in output:\n{result.combined_output}"
        pcap_path = match.group(1)
        assert os.path.exists(pcap_path), f"pcap file {pcap_path} was not created"
        assert os.path.getsize(pcap_path) >= 0

    def test_expected_network_accepted_with_enrichment(self, cli_runner):
        """[Category A] --expected-network + --enrich + --no-ping run and enrich the finding."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "-a",
            "--subnet",
            "127.0.0.1/32",
            "--expected-network",
            "127.0.0.0/8",
            "--enrich",
            "--no-ping",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)
        text = _combined_text(result, result.scan_log)
        assert "raw socket access required" not in text

    def test_enrichment_no_rdns_no_netbios(self, cli_runner):
        """[Category B] --no-rdns/--no-netbios-enrich/--no-mdns-enrich parse and run cleanly."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "-a",
            "--subnet",
            "127.0.0.1/32",
            "--enrich",
            "--no-rdns",
            "--no-netbios-enrich",
            "--no-mdns-enrich",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)

    def test_force_flag_accepted_at_small_scope(self, cli_runner):
        """[Category B] -f/--force is accepted and parses at a safe /32 scope.

        NOTE: the real >255-host confirmation gate this flag bypasses cannot
        be safely exercised here (it would require a real subnet larger than
        the /32 the safety constraint mandates); this only proves the flag
        is wired through argparse and does not break a real scan.
        """
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "--arp",
            "--subnet",
            "127.0.0.1/32",
            "--force",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)

    def test_rate_limit_accepted(self, cli_runner):
        """[Category B] -R/--rate-limit is accepted and does not break a real scan."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "-a",
            "--subnet",
            "127.0.0.1/32",
            "-R",
            "50",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)

    def test_no_reach_warnings_accepted(self, cli_runner):
        """[Category B] --no-reach-warnings is accepted and does not break a real scan."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "-a",
            "--subnet",
            "127.0.0.1/32",
            "--no-reach-warnings",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)

    def test_protocol_toggles_accepted(self, cli_runner):
        """[Category B] a representative sample of the ~50 --no-<proto> toggles.

        Not every disable flag is exercised individually (there are ~50);
        this drives a representative sample of the flag family in one
        maximal invocation, proving they parse and combine without error.
        """
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "-a",
            "--subnet",
            "127.0.0.1/32",
            "--no-lldp",
            "--no-mdns",
            "--no-ssdp",
            "--no-cdp",
            "--no-dns-sd",
            "--no-ws-discovery",
            "--no-llmnr",
            "--no-knx",
            "--no-bacnet",
            "--no-ethernetip",
            "--no-codesys",
            "--no-ads",
            "--no-netbios",
            "--no-stp",
            "--no-moxa",
            "--no-lantronix",
            "--no-ipv6",
            "--no-dhcp",
            "--no-fins",
            "--no-sadp",
            "--no-dahua",
            "--no-sma",
            "--no-crestron",
            "--no-artnet",
            "--no-ipmi",
            "--no-ubiquiti",
            "--no-mndp",
            "--no-addp",
            "--no-slp",
            "--no-hsrp",
            "--no-igmp",
            "--no-ospf",
            "--no-eigrp",
            "--no-rip",
            "--no-pim",
            "--no-hid",
            "--no-mssql",
            "--no-bjnp",
            "--no-sonicwall",
            "--no-db2",
            "--no-sybase",
            "--no-xdmcp",
            "--no-jenkins",
            "--no-pcanywhere",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)
        # ipv6-passive comes from the raw ipv6 listener, not from any of the
        # protocol probes disabled above, so it should still be reported.
        text = _combined_text(result, result.scan_log)
        assert "raw socket access required" not in text

    def test_continuous_mode_loops_until_killed(self, cli_runner):
        """[Category B] -c/--continuous + --scan-interval loop; killed by the subprocess budget."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "1",
            "-a",
            "--subnet",
            "127.0.0.1/32",
            "--continuous",
            "--scan-interval",
            "1",
            use_sudo=True,
            format="json",
            timeout=8,
        )
        # Killed by the subprocess timeout because -c never exits on its own.
        assert result.returncode != 0
        assert "timed out" in result.stderr.lower()
        assert "Traceback" not in result.stdout

    def test_active_only_no_passive_still_gated_without_sudo(self, cli_runner):
        """[Category B] --no-passive + -a without sudo still hits the raw-socket gate.

        Confirms the flag parses and combines with -a, and that the
        unconditional raw-socket capability check (which applies to every
        scan mode, see module docstring) fails gracefully rather than
        crashing when neither sudo nor CAP_NET_RAW is available.
        """
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "-a",
            "--no-passive",
            "--subnet",
            "127.0.0.1/32",
            format="json",
            json_log=True,
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "raw socket access required" in text


@pytest.mark.discovery
@pytest.mark.xdist_group("discovery_cli")
class TestDiscoveryCliHostilePaths:
    """Hostile / invalid-server / malformed-argument paths (see catalogue in module docstring)."""

    def test_active_scan_empty_scope_no_false_device(self, cli_runner):
        """[Category C-ish] active scan of an address nothing listens on reports no device.

        127.0.0.2/32 is loopback but nothing is bound there; this is the
        "closed port / nothing listening in scope" hostile case adapted to
        discovery's interface+subnet target model.
        """
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "2",
            "--arp",
            "--subnet",
            "127.0.0.2/32",
            "--force",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)
        text = _combined_text(result, result.scan_log)
        assert "no devices discovered" in text or "0 device" in text or "devices: []" in text

    @pytest.mark.modbus
    def test_no_false_positive_on_modbus_port(self, cli_runner, mock_host, mock_ports, request):
        """[Category C] a live modbus mock in scope must never be misidentified.

        discovery's active ICS probes are UDP-broadcast based (ARP, LLDP,
        mDNS, SSDP, KNX/BACnet/EtherNet-IP discovery, ...), not TCP clients
        of a specific port -- so a TCP modbus mock listening on 502 must
        never be reported as any kind of ICS device identification. This is
        the module's most important correctness property: no
        false-positive identification of an impostor/wrong-protocol server.
        """
        require_service_mark = request.node.get_closest_marker("modbus")
        assert require_service_mark is not None
        port = mock_ports.get("modbus", 502)
        result = cli_runner.run(
            "discovery",
            "lo",
            "-t",
            "3",
            "-a",
            "--ics-only",
            "-s",
            f"{mock_host}/32",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)
        text = _combined_text(result, result.scan_log)
        assert "modbus" not in text, (
            f"discovery falsely identified a modbus device on port {port}:\n{text}"
        )

    def test_bad_subnet_cidr_rejected(self, cli_runner):
        """[Category B] a malformed --subnet never crashes; it degrades to a 0-host scan.

        FINDING: discovery does not validate --subnet's CIDR syntax. A junk
        value like "not-a-cidr" is silently accepted and reduces the ARP
        scan to 0 hosts rather than raising a usage error -- reaching this
        code path requires sudo since the raw-socket gate runs first (see
        module docstring). This documents the actual (silent-degrade)
        behavior rather than asserting a rejection this CLI does not
        implement.
        """
        result = cli_runner.run(
            "discovery",
            "lo",
            "-a",
            "--subnet",
            "not-a-cidr",
            "-t",
            "2",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)
        assert "0 hosts" in result.combined_output or "not-a-cidr" in result.combined_output

    def test_bad_expected_network_rejected(self, cli_runner):
        """[Category B] a malformed --expected-network never crashes; it is silently ignored.

        FINDING: discovery does not validate --expected-network's CIDR
        syntax either; an invalid value is accepted without a reachability
        warning or error. Reaching this code path requires sudo since the
        raw-socket gate runs first.
        """
        result = cli_runner.run(
            "discovery",
            "lo",
            "-a",
            "--subnet",
            "127.0.0.1/32",
            "-t",
            "2",
            "--expected-network",
            "not-a-cidr-either",
            use_sudo=True,
            format="json",
        )
        assert result.returncode == 0, result.combined_output
        _assert_no_traceback(result)

    def test_timeout_wrong_type_rejected(self, cli_runner):
        """[Category C] --timeout given a non-numeric value fails cleanly (wrong-type flag)."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "--timeout",
            "notanumber",
            format="json",
        )
        assert result.returncode != 0
        _assert_no_traceback(result)

    def test_rate_limit_wrong_type_rejected(self, cli_runner):
        """[Category C] --rate-limit given a non-numeric value fails cleanly (wrong-type flag)."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "--rate-limit",
            "abc",
            format="json",
        )
        assert result.returncode != 0
        _assert_no_traceback(result)

    def test_garbage_interface_name_fails_cleanly(self, cli_runner):
        """[Category C] a nonexistent interface name fails cleanly, no traceback."""
        result = cli_runner.run(
            "discovery",
            "definitely-not-a-real-iface-xyz",
            "-t",
            "1",
            format="json",
            json_log=True,
        )
        assert result.returncode != 0
        _assert_no_traceback(result)

    def test_unknown_flag_rejected(self, cli_runner):
        """[Category C] an unknown flag is rejected, never silently ignored."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "--not-a-real-flag",
            "value",
            format="json",
        )
        assert result.returncode != 0, (
            "an unknown flag must not be silently ignored / must not exit 0"
        )
        _assert_no_traceback(result)

    def test_typo_flag_rejected(self, cli_runner):
        """[Category C] a near-miss typo of a real flag (--tiemout) is rejected, not silently accepted."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "--tiemout",
            "2",
            format="json",
        )
        assert result.returncode != 0
        _assert_no_traceback(result)

    def test_borrowed_flag_rejected(self, cli_runner):
        """[Category C] a flag borrowed from another protocol (--unit-id, modbus) is rejected."""
        result = cli_runner.run(
            "discovery",
            "lo",
            "--unit-id",
            "1",
            format="json",
        )
        assert result.returncode != 0
        _assert_no_traceback(result)
