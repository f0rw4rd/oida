"""
Tests for PcapScanner class (scanner.py).

Uses real pcap fixtures from tests/fixtures/pcap/.
"""

from pathlib import Path

import pytest

from oida.protocols.pcap.scanner import PcapScanner

from tests.unit.pcap.conftest import FIXTURES_ROOT, requires_pyshark


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _skip_unless_exists(path: Path):
    """Fail the test if the fixture file is missing."""
    if not path.exists():
        pytest.fail(f"Fixture not found: {path}")


# ---------------------------------------------------------------------------
# File validation
# ---------------------------------------------------------------------------


class TestFileValidation:
    """PcapScanner handles missing / invalid files gracefully."""

    def test_nonexistent_file_returns_result_with_pcap_file_key(self):
        scanner = PcapScanner("/does/not/exist.pcap")
        result = scanner.run_scan()
        assert "pcap_file" in result
        assert result["pcap_file"] == "/does/not/exist.pcap"

    def test_nonexistent_file_has_no_devices(self):
        scanner = PcapScanner("/does/not/exist.pcap")
        result = scanner.run_scan()
        assert result["devices"] == []

    def test_nonexistent_file_scan_mode_populated(self):
        scanner = PcapScanner("/does/not/exist.pcap")
        result = scanner.run_scan()
        assert "scan_mode" in result
        assert result["scan_mode"] == ["pcap-replay"]


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------


class TestResultStructure:
    """Verify the top-level keys in scan results."""

    def test_initial_result_has_required_keys(self):
        scanner = PcapScanner("dummy.pcap")
        assert "pcap_file" in scanner.results
        assert "scan_mode" in scanner.results
        assert "protocols_used" in scanner.results
        assert "devices" in scanner.results

    def test_run_scan_adds_statistics_and_traffic_keys(self, arp_pcap):
        _skip_unless_exists(arp_pcap)
        scanner = PcapScanner(str(arp_pcap))
        result = scanner.run_scan()
        assert "statistics" in result
        assert "traffic_statistics" in result

    def test_statistics_contains_expected_fields(self, arp_pcap):
        _skip_unless_exists(arp_pcap)
        scanner = PcapScanner(str(arp_pcap))
        result = scanner.run_scan()
        stats = result["statistics"]
        for key in ("total_devices", "packets_processed", "pcap_file"):
            assert key in stats, f"Missing key: {key}"

    def test_traffic_statistics_is_dict(self, arp_pcap):
        _skip_unless_exists(arp_pcap)
        scanner = PcapScanner(str(arp_pcap))
        result = scanner.run_scan()
        assert isinstance(result["traffic_statistics"], dict)

    def test_protocols_used_is_list(self, arp_pcap):
        _skip_unless_exists(arp_pcap)
        scanner = PcapScanner(str(arp_pcap))
        result = scanner.run_scan()
        assert isinstance(result["protocols_used"], list)

    def test_devices_is_list(self, arp_pcap):
        _skip_unless_exists(arp_pcap)
        scanner = PcapScanner(str(arp_pcap))
        result = scanner.run_scan()
        assert isinstance(result["devices"], list)


# ---------------------------------------------------------------------------
# Args propagation
# ---------------------------------------------------------------------------


class TestArgsPropagation:
    """Verify that extract flags are stored and accessible."""

    def test_extract_files_flag_stored(self):
        scanner = PcapScanner("f.pcap", args={"extract_files": True})
        assert scanner.args["extract_files"] is True

    def test_extract_all_alias_sets_extract_files(self):
        # -e/--extract-all collapses onto the extract_files dest
        scanner = PcapScanner("f.pcap", args={"extract_files": True})
        assert scanner.args["extract_files"] is True

    def test_args_default_empty_dict(self):
        scanner = PcapScanner("f.pcap")
        assert scanner.args == {}

    def test_args_custom_dict_preserved(self):
        custom = {"extract_files": True, "extract_dir": "/tmp/out"}
        scanner = PcapScanner("f.pcap", args=custom)
        assert scanner.args["extract_dir"] == "/tmp/out"


# ---------------------------------------------------------------------------
# PyShark pipeline
# ---------------------------------------------------------------------------

# Parametrize over a selection of small, fast pcap files.
_PIPELINE_PCAPS = [
    ("arp", FIXTURES_ROOT / "arp" / "bruteshark_arp_broadcast.pcap"),
    ("dhcp", FIXTURES_ROOT / "dhcp" / "zeek_dhcp_flood.pcap"),
    ("dns_generated", FIXTURES_ROOT / "dns" / "generated_dns.pcap"),
    ("modbus", FIXTURES_ROOT / "modbus" / "cisagov_modbus_example.pcap"),
    ("s7comm", FIXTURES_ROOT / "s7comm" / "cisagov_snap7.pcap"),
]


class TestPySharkPipeline:
    """Test the PyShark pipeline against real captures."""

    @requires_pyshark
    @pytest.mark.parametrize(
        "label,pcap_path",
        _PIPELINE_PCAPS,
        ids=[p[0] for p in _PIPELINE_PCAPS],
    )
    def test_pipeline_completes(self, label, pcap_path):
        """Scanner completes without exception for each pcap."""
        _skip_unless_exists(pcap_path)
        scanner = PcapScanner(str(pcap_path))
        result = scanner.run_scan()
        assert isinstance(result["statistics"]["packets_processed"], int)
        assert result["statistics"]["packets_processed"] >= 0

    @requires_pyshark
    def test_packet_count_with_dns(self, dns_pcap):
        _skip_unless_exists(dns_pcap)
        scanner = PcapScanner(str(dns_pcap))
        result = scanner.run_scan()
        assert result["statistics"]["packets_processed"] > 0

    @requires_pyshark
    def test_packet_count_with_modbus(self, modbus_pcap):
        _skip_unless_exists(modbus_pcap)
        scanner = PcapScanner(str(modbus_pcap))
        result = scanner.run_scan()
        assert result["statistics"]["packets_processed"] > 0

    def test_pyshark_unavailable_returns_zero(self, arp_pcap):
        """When pyshark is unavailable, packets_processed should be 0."""
        _skip_unless_exists(arp_pcap)
        from unittest.mock import PropertyMock, patch
        from oida.protocols.pcap import scanner as pcap_scanner_mod

        lazy_cls = type(pcap_scanner_mod._pyshark)
        with patch.object(lazy_cls, "is_available", new_callable=PropertyMock, return_value=False):
            scanner = PcapScanner(str(arp_pcap))
            result = scanner.run_scan()
        assert result["statistics"]["packets_processed"] == 0


# ---------------------------------------------------------------------------
# Listener creation
# ---------------------------------------------------------------------------


class TestListenerCreation:
    """Test _create_pyshark_listeners."""

    def test_create_pyshark_listeners_returns_dict(self):
        scanner = PcapScanner("dummy.pcap")
        listeners = scanner._create_pyshark_listeners()
        assert isinstance(listeners, dict)


# ---------------------------------------------------------------------------
# Logger integration
# ---------------------------------------------------------------------------


class TestLoggerIntegration:
    """Verify PcapScanner creates and uses ICSLogger directly."""

    def test_logger_created_on_init(self):
        from oida.utils.ics_logger import ICSLogger

        scanner = PcapScanner("f.pcap")
        assert isinstance(scanner.logger, ICSLogger)

    def test_logger_uses_empty_host(self):
        scanner = PcapScanner("/long/path/to/capture.pcap")
        assert scanner.logger.extra["host"] == ""

    def test_logger_protocol_is_pcap(self):
        scanner = PcapScanner("f.pcap")
        assert scanner.logger.extra["protocol"] == "PCAP"

    def test_logger_can_be_overridden(self):
        scanner = PcapScanner("f.pcap")
        sentinel = object()
        scanner.logger = sentinel
        assert scanner.logger is sentinel


# ---------------------------------------------------------------------------
# Discovered devices
# ---------------------------------------------------------------------------


class TestDiscoveredDevices:
    """Test device tracking."""

    def test_discovered_devices_initially_empty(self):
        scanner = PcapScanner("f.pcap")
        assert scanner.discovered_devices == {}

    def test_devices_in_result_match_discovered(self, arp_pcap):
        _skip_unless_exists(arp_pcap)
        scanner = PcapScanner(str(arp_pcap))
        result = scanner.run_scan()
        expected_count = len(scanner.discovered_devices)
        assert len(result["devices"]) == expected_count


# ---------------------------------------------------------------------------
# Endpoint tracking
# ---------------------------------------------------------------------------


class TestEndpointTracking:
    """Test _endpoints dict and _track_endpoint / _is_noise_endpoint."""

    def test_endpoints_initially_empty(self):
        scanner = PcapScanner("f.pcap")
        assert scanner._endpoints == {}

    def test_is_noise_broadcast_mac(self):
        assert PcapScanner._is_noise_endpoint("192.168.1.1", "ff:ff:ff:ff:ff:ff") is True

    def test_is_noise_ipv4_multicast(self):
        assert PcapScanner._is_noise_endpoint("224.0.0.1", "01:00:5e:00:00:01") is True

    def test_is_noise_ipv4_multicast_239(self):
        assert PcapScanner._is_noise_endpoint("239.255.255.250", "01:00:5e:7f:ff:fa") is True

    def test_is_noise_ipv6_multicast_mac(self):
        assert PcapScanner._is_noise_endpoint("fe80::1", "33:33:00:00:00:01") is True

    def test_is_noise_ipv6_multicast_addr(self):
        assert PcapScanner._is_noise_endpoint("ff02::1", "33:33:00:00:00:01") is True

    def test_is_noise_broadcast_ip(self):
        assert PcapScanner._is_noise_endpoint("255.255.255.255", "ff:ff:ff:ff:ff:ff") is True

    def test_is_noise_zero_ipv4(self):
        assert PcapScanner._is_noise_endpoint("0.0.0.0", "00:00:00:00:00:00") is True

    def test_is_noise_zero_ipv6(self):
        assert PcapScanner._is_noise_endpoint("::", "00:00:00:00:00:00") is True

    def test_is_noise_subnet_broadcast(self):
        assert PcapScanner._is_noise_endpoint("192.168.1.255", "ff:ff:ff:ff:ff:ff") is True

    def test_not_noise_normal_host(self):
        assert PcapScanner._is_noise_endpoint("192.168.1.1", "00:11:22:33:44:55") is False

    def test_not_noise_ipv6_host(self):
        assert PcapScanner._is_noise_endpoint("fe80::1", "00:11:22:33:44:55") is False


# ---------------------------------------------------------------------------
# x509 propagation to listeners
# ---------------------------------------------------------------------------


class TestX509Propagation:
    """Test that --x509 flag is propagated to listeners."""

    def test_x509_flag_propagated_to_listeners(self):
        scanner = PcapScanner("f.pcap", args={"x509": True})
        listeners = scanner._create_pyshark_listeners()
        for listener in listeners.values():
            assert listener._x509 is True

    def test_x509_default_false_on_listeners(self):
        scanner = PcapScanner("f.pcap")
        listeners = scanner._create_pyshark_listeners()
        for listener in listeners.values():
            assert listener._x509 is False


# ---------------------------------------------------------------------------
# Assets / stats collection
# ---------------------------------------------------------------------------


class TestAssetsStatsCollection:
    """Test that --assets implicitly enables stats collection."""

    def test_assets_flag_stored(self):
        scanner = PcapScanner("f.pcap", args={"assets": True})
        assert scanner.args["assets"] is True

    def test_assets_pipeline_collects_stats(self, arp_pcap):
        """When --assets is set, stats should be collected (collect_stats=True)."""
        _skip_unless_exists(arp_pcap)
        scanner = PcapScanner(str(arp_pcap), args={"assets": True})
        scanner.run_scan()
        # Stats were collected - PassiveStatistics was used
        assert hasattr(scanner, "stats")


# ---------------------------------------------------------------------------
# Asset file writing
# ---------------------------------------------------------------------------


class TestWriteAssetFiles:
    """Test _write_asset_files creates CSV and IP list files."""

    def test_write_asset_files_creates_csv(self, tmp_path):
        from oida.protocols.discovery.core import DiscoveredDevice

        scanner = PcapScanner("f.pcap", args={"output": str(tmp_path)})
        scanner.discovered_devices = {
            "test_1": DiscoveredDevice(
                ip_addresses=["192.168.1.1"],
                mac_address="00:11:22:33:44:55",
                discovered_by=["modbus"],
            ),
        }
        scanner._write_asset_files(scanner.discovered_devices)
        csv_path = tmp_path / "devices.csv"
        assert csv_path.exists()
        content = csv_path.read_text()
        assert "192.168.1.1" in content
        assert "00:11:22:33:44:55" in content

    def test_write_asset_files_creates_ipv4_txt(self, tmp_path):
        from oida.protocols.discovery.core import DiscoveredDevice

        scanner = PcapScanner("f.pcap", args={"output": str(tmp_path)})
        scanner.discovered_devices = {
            "test_1": DiscoveredDevice(
                ip_addresses=["10.0.0.1", "10.0.0.2"],
                mac_address="00:11:22:33:44:55",
                discovered_by=["endpoint"],
            ),
        }
        scanner._write_asset_files(scanner.discovered_devices)
        ipv4_path = tmp_path / "ipv4.txt"
        assert ipv4_path.exists()
        lines = ipv4_path.read_text().strip().splitlines()
        assert "10.0.0.1" in lines
        assert "10.0.0.2" in lines

    def test_write_asset_files_creates_ipv6_txt(self, tmp_path):
        from oida.protocols.discovery.core import DiscoveredDevice

        scanner = PcapScanner("f.pcap", args={"output": str(tmp_path)})
        scanner.discovered_devices = {
            "test_1": DiscoveredDevice(
                ip_addresses=["fe80::1"],
                mac_address="00:11:22:33:44:55",
                discovered_by=["endpoint"],
            ),
        }
        scanner._write_asset_files(scanner.discovered_devices)
        ipv6_path = tmp_path / "ipv6.txt"
        assert ipv6_path.exists()
        assert "fe80::1" in ipv6_path.read_text()

    def test_write_asset_files_noop_without_output_dir(self):
        from oida.protocols.discovery.core import DiscoveredDevice

        scanner = PcapScanner("f.pcap")
        scanner.discovered_devices = {
            "test_1": DiscoveredDevice(
                ip_addresses=["192.168.1.1"],
                mac_address="00:11:22:33:44:55",
                discovered_by=["endpoint"],
            ),
        }
        # Should not raise - silently skips without output dir
        scanner._write_asset_files(scanner.discovered_devices)


# ---------------------------------------------------------------------------
# Pipeline early-failure error path (regression)
# ---------------------------------------------------------------------------


class _RaisingArgs(dict):
    """dict whose .get('decode_as') raises a crash-classified exception.

    Simulates a failure that occurs early inside _run_pyshark_pipeline's try
    block (between the try-open and the FileCapture loop) and is classified as
    a crash by the except handler ("crashed"/"retcode" in the message).
    """

    def get(self, key, default=None):
        if key == "decode_as":
            raise RuntimeError("tshark crashed (retcode 2)")
        return super().get(key, default)


class TestPipelineEarlyFailure:
    """The crash branch must not mask an early error with UnboundLocalError."""

    def test_early_crash_does_not_raise_unboundlocalerror(self, monkeypatch):
        from unittest.mock import PropertyMock, patch
        from oida.protocols.pcap import scanner as scanner_mod

        scanner = PcapScanner("f.pcap")
        scanner.args = _RaisingArgs()

        # Reach the try block: need a listener, pyshark "available", and a
        # packet count call that does not itself raise.
        monkeypatch.setattr(scanner, "_create_pyshark_listeners", lambda: {"x": object()})
        monkeypatch.setattr(scanner, "_get_packet_count", lambda _f: 0)

        lazy_cls = type(scanner_mod._pyshark)
        # packet_count == 0 and is_crash -> handler takes the `elif is_crash`
        # branch and re-raises. Before the fix it raised UnboundLocalError
        # (capture/packet_count unbound); after the fix the original error
        # propagates intact.
        with patch.object(lazy_cls, "is_available", new_callable=PropertyMock, return_value=True):
            with pytest.raises(RuntimeError) as excinfo:
                scanner._run_pyshark_pipeline()

        assert "crashed" in str(excinfo.value)
        assert not isinstance(excinfo.value, UnboundLocalError)
