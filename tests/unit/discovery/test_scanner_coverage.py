"""
Coverage-focused tests for DiscoveryScanner runtime methods and the
NXC-style ``discovery`` connection class.

Targets large uncovered regions of scanner.py:
- _parse_lldp_description() (vendor string parsing)
- _run_lldp_passive() / _run_dcp_active() / _convert_dcp_devices()
- _derive_eui64_addresses() / _ping_eui64_addresses()
- _correlate_ips_to_macs() / _resolve_macs_from_arp_cache()
  / _resolve_ipv4_for_mac_only() / _run_ipv4_resolve_scanner()
- _merge_devices_live() (continuous-mode merge)
- _run_enrichment_phase()
- _report_findings() / _write_output_files() / _build_device_description()
- _device_to_dict() / _format_excluded_locals() / _check_ip_scope()
- pcap capture start/stop
- the ``discovery`` NXC class

Only genuine external I/O is mocked: scapy scanner classes, subprocess
(ping), the system ARP cache, and raw-socket capability checks. The
orchestration / parsing / merge logic under test runs for real.
"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def scanner_class():
    from oida.protocols.discovery import DiscoveryScanner

    return DiscoveryScanner


@pytest.fixture
def device_class():
    from oida.protocols.discovery import DiscoveredDevice

    return DiscoveredDevice


# ---------------------------------------------------------------------------
# _parse_lldp_description
# ---------------------------------------------------------------------------
class TestParseLldpDescription:
    def test_siemens(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        desc = (
            "Siemens, SIMATIC S7, CPU-1200, 6ES7 214-1BG40-0XB0, HW: 1, FW: V.4.1.3, S C-E6S04921"
        )
        out = s._parse_lldp_description({"system_description": desc})
        assert out["manufacturer"] == "Siemens"
        assert out["model"] == "CPU-1200"
        assert out["article_number"].startswith("6ES7")
        assert "4.1.3" in out["firmware"]
        assert out["hardware"] == "1"
        assert out["serial"] == "C-E6S04921"

    def test_cisco(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        out = s._parse_lldp_description(
            {"system_description": "Cisco IOS Software, C2960 Software"}
        )
        assert out["manufacturer"] == "Cisco"
        assert out["model"] == "C2960"

    def test_beckhoff(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        out = s._parse_lldp_description(
            {"system_description": "Beckhoff Automation, CX9020, TwinCAT 3"}
        )
        assert out["manufacturer"] == "Beckhoff"
        assert out["model"] == "CX9020"

    def test_schneider(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        out = s._parse_lldp_description(
            {"system_description": "Schneider Electric, Modicon M580 controller"}
        )
        assert out["manufacturer"] == "Schneider Electric"
        assert "M580" in out["model"]

    def test_wago_article_number(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        out = s._parse_lldp_description({"system_description": "WAGO 750-8210 PFC200 controller"})
        assert out["manufacturer"] == "WAGO"
        assert out["article_number"] == "750-8210"

    def test_phoenix(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        out = s._parse_lldp_description({"system_description": "Phoenix Contact device"})
        assert out["manufacturer"] == "Phoenix Contact"

    def test_generic_firmware_extraction(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        out = s._parse_lldp_description({"system_description": "Generic Box Firmware: 2.4.6 ready"})
        assert "2.4.6" in out["firmware"]

    def test_empty_description(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        out = s._parse_lldp_description({"system_description": ""})
        assert out["manufacturer"] == ""
        assert out["firmware"] == ""


# ---------------------------------------------------------------------------
# _run_lldp_passive  (mock the LLDPScanner external I/O only)
# ---------------------------------------------------------------------------
class TestRunLldpPassive:
    def test_converts_lldp_devices(self, scanner_class):
        s = scanner_class({"target": "eth0"})

        fake_scanner = MagicMock()
        fake_scanner.connect.return_value = "eth0"
        fake_scanner.discover.return_value = {
            "devices": [
                {
                    "mac_address": "00:1b:1b:11:22:33",
                    "management_addresses": ["10.0.0.5"],
                    "system_name": "switch01",
                    "system_description": "Cisco IOS Software, C2960 Software",
                    "capabilities": ["Bridge"],
                    "port_description": "GigabitEthernet0/1",
                }
            ]
        }

        with patch("oida.protocols.discovery.lldp.LLDPScanner", return_value=fake_scanner):
            devices = s._run_lldp_passive()

        assert "00:1b:1b:11:22:33" in devices
        dev = devices["00:1b:1b:11:22:33"]
        assert dev.name == "switch01"
        assert dev.manufacturer == "Cisco"
        assert "Bridge" in dev.device_type
        assert dev.lldp_data["parsed_model"] == "C2960"

    def test_connect_failure_returns_empty(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        fake_scanner = MagicMock()
        fake_scanner.connect.return_value = None
        with patch("oida.protocols.discovery.lldp.LLDPScanner", return_value=fake_scanner):
            assert s._run_lldp_passive() == {}

    def test_permission_error_returns_empty(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        with patch(
            "oida.protocols.discovery.lldp.LLDPScanner",
            side_effect=PermissionError("need root"),
        ):
            assert s._run_lldp_passive() == {}

    def test_device_without_mac_skipped(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        fake_scanner = MagicMock()
        fake_scanner.connect.return_value = "eth0"
        fake_scanner.discover.return_value = {"devices": [{"mac_address": "", "system_name": "x"}]}
        with patch("oida.protocols.discovery.lldp.LLDPScanner", return_value=fake_scanner):
            assert s._run_lldp_passive() == {}


# ---------------------------------------------------------------------------
# _convert_dcp_devices
# ---------------------------------------------------------------------------
class TestConvertDcpDevices:
    def test_converts(self, scanner_class):
        s = scanner_class({"target": "eth0"})

        class FakeDcp:
            mac = "00:0e:8c:aa:bb:cc"
            ip = "192.168.0.10"
            name = "plc-01"
            netmask = "255.255.255.0"
            gateway = "192.168.0.1"
            vendor_id = 42
            device_id = 7
            vendor_name = "Siemens"

        devices = s._convert_dcp_devices([FakeDcp()], "dcp-identify")
        assert "00:0e:8c:aa:bb:cc" in devices
        dev = devices["00:0e:8c:aa:bb:cc"]
        assert dev.name == "plc-01"
        assert dev.manufacturer == "Siemens"
        assert dev.device_type == "PROFINET IO-Device"
        assert "192.168.0.10" in dev.ip_addresses
        assert dev.dcp_data["device_id"] == 7

    def test_skips_no_mac(self, scanner_class):
        s = scanner_class({"target": "eth0"})

        class FakeNoMac:
            mac = ""

        assert s._convert_dcp_devices([FakeNoMac()], "dcp") == {}

    def test_drops_zero_ip(self, scanner_class):
        s = scanner_class({"target": "eth0"})

        class FakeZeroIp:
            mac = "00:0e:8c:00:00:01"
            ip = "0.0.0.0"
            name = "x"

        devices = s._convert_dcp_devices([FakeZeroIp()], "dcp")
        assert devices["00:0e:8c:00:00:01"].ip_addresses == []


# ---------------------------------------------------------------------------
# _run_dcp_active (profinet not installed branch)
# ---------------------------------------------------------------------------
class TestRunDcpActive:
    def test_profinet_unavailable_returns_empty(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        with patch("oida.protocols.discovery.scanner._profinet") as mock_pf:
            mock_pf.is_available = False
            assert s._run_dcp_active() == {}


# ---------------------------------------------------------------------------
# _derive_eui64_addresses
# ---------------------------------------------------------------------------
class TestDeriveEui64:
    def test_derives_for_mac(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        dev = device_class(mac_address="00:80:f4:0c:7b:e0")
        s.discovered_devices["00:80:f4:0c:7b:e0"] = dev

        count = s._derive_eui64_addresses()
        assert count == 1
        assert dev.ipv6_data is not None
        derived = dev.ipv6_data["eui64_derived"]
        assert len(derived) == 1
        # Derived address must NOT be added to ip_addresses until verified
        assert derived[0] not in dev.ip_addresses

    def test_skips_device_without_mac(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        s.discovered_devices["ip:1.2.3.4"] = device_class(ip_addresses=["1.2.3.4"])
        assert s._derive_eui64_addresses() == 0

    def test_no_double_derive(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        dev = device_class(mac_address="00:80:f4:0c:7b:e0")
        s.discovered_devices["k"] = dev
        s._derive_eui64_addresses()
        # Second call adds nothing new
        assert s._derive_eui64_addresses() == 0


# ---------------------------------------------------------------------------
# _ping_eui64_addresses  (subprocess is the external I/O)
# ---------------------------------------------------------------------------
class TestPingEui64:
    def test_no_addresses_returns_zero(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        s.discovered_devices["k"] = device_class(mac_address="00:80:f4:0c:7b:e0")
        # No eui64_derived populated -> nothing to ping
        assert s._ping_eui64_addresses() == 0

    def test_ping_success_adds_address(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        dev = device_class(mac_address="00:80:f4:0c:7b:e0")
        dev.ipv6_data = {"eui64_derived": ["fe80::280:f4ff:fe0c:7be0"]}
        s.discovered_devices["00:80:f4:0c:7b:e0"] = dev

        completed = MagicMock()
        completed.returncode = 0
        with patch("subprocess.run", return_value=completed):
            responded = s._ping_eui64_addresses()

        assert responded == 1
        assert "fe80::280:f4ff:fe0c:7be0" in dev.ip_addresses
        assert "eui64-ping" in dev.discovered_by
        assert "fe80::280:f4ff:fe0c:7be0" in dev.ipv6_data["eui64_verified"]

    def test_ping_failure_does_not_add(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        dev = device_class(mac_address="00:80:f4:0c:7b:e0")
        dev.ipv6_data = {"eui64_derived": ["fe80::280:f4ff:fe0c:7be0"]}
        s.discovered_devices["k"] = dev

        completed = MagicMock()
        completed.returncode = 1
        with patch("subprocess.run", return_value=completed):
            assert s._ping_eui64_addresses() == 0
        assert "fe80::280:f4ff:fe0c:7be0" not in dev.ip_addresses


# ---------------------------------------------------------------------------
# _correlate_ips_to_macs
# ---------------------------------------------------------------------------
class TestCorrelateIpsToMacs:
    def test_extracts_mac_from_eui64_ipv6(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        # IP-only device with EUI-64 link-local
        dev = device_class(ip_addresses=["fe80::280:f4ff:fe0c:7be0"])
        s.discovered_devices["ip:fe80::280:f4ff:fe0c:7be0"] = dev

        count = s._correlate_ips_to_macs()
        assert count >= 1
        # Device re-keyed under derived MAC
        assert "00:80:f4:0c:7b:e0" in s.discovered_devices
        assert "ip:fe80::280:f4ff:fe0c:7be0" not in s.discovered_devices

    def test_correlate_ip_only_to_known_mac(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        mac_dev = device_class(mac_address="aa:bb:cc:dd:ee:ff", ip_addresses=["10.0.0.5"])
        ip_dev = device_class(ip_addresses=["10.0.0.5"], name="seen-by-mdns")
        s.discovered_devices["aa:bb:cc:dd:ee:ff"] = mac_dev
        s.discovered_devices["ip:10.0.0.5"] = ip_dev

        s._correlate_ips_to_macs()
        # IP-only entry merged into MAC device
        assert "ip:10.0.0.5" not in s.discovered_devices
        assert s.discovered_devices["aa:bb:cc:dd:ee:ff"].name == "seen-by-mdns"


# ---------------------------------------------------------------------------
# _resolve_macs_from_arp_cache / _resolve_ipv4_for_mac_only
# (system ARP cache is the external dependency we stub)
# ---------------------------------------------------------------------------
class TestArpCacheResolution:
    def test_resolve_mac_from_cache(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        s.discovered_devices["ip:10.0.0.9"] = device_class(ip_addresses=["10.0.0.9"])

        with patch(
            "oida.utils.platform_compat.get_arp_cache_as_ip_to_mac",
            return_value={"10.0.0.9": "11:22:33:44:55:66"},
        ):
            resolved = s._resolve_macs_from_arp_cache()

        assert resolved == 1
        assert "11:22:33:44:55:66" in s.discovered_devices
        assert "ip:10.0.0.9" not in s.discovered_devices

    def test_empty_arp_cache_returns_zero(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        with patch(
            "oida.utils.platform_compat.get_arp_cache_as_ip_to_mac",
            return_value={},
        ):
            assert s._resolve_macs_from_arp_cache() == 0

    def test_resolve_ipv4_for_mac_only(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        # Device has MAC + only IPv6, needs IPv4
        dev = device_class(mac_address="aa:bb:cc:dd:ee:ff", ip_addresses=["fe80::1"])
        s.discovered_devices["aa:bb:cc:dd:ee:ff"] = dev

        with patch(
            "oida.utils.platform_compat.get_arp_cache_as_mac_to_ips",
            return_value={"aa:bb:cc:dd:ee:ff": ["10.0.0.20"]},
        ):
            resolved = s._resolve_ipv4_for_mac_only()

        assert resolved == 1
        # IPv4 inserted first
        assert dev.ip_addresses[0] == "10.0.0.20"

    def test_resolve_ipv4_skips_devices_with_ipv4(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        dev = device_class(mac_address="aa:bb:cc:dd:ee:ff", ip_addresses=["10.0.0.5"])
        s.discovered_devices["aa:bb:cc:dd:ee:ff"] = dev
        with patch(
            "oida.utils.platform_compat.get_arp_cache_as_mac_to_ips",
            return_value={"aa:bb:cc:dd:ee:ff": ["10.0.0.99"]},
        ):
            assert s._resolve_ipv4_for_mac_only() == 0
        assert "10.0.0.99" not in dev.ip_addresses


# ---------------------------------------------------------------------------
# _run_ipv4_resolve_scanner
# ---------------------------------------------------------------------------
class TestRunIpv4ResolveScanner:
    def test_no_mac_only_devices_returns_zero(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        # Device already has IPv4 -> nothing to resolve
        s.discovered_devices["aa:bb:cc:dd:ee:ff"] = device_class(
            mac_address="aa:bb:cc:dd:ee:ff", ip_addresses=["10.0.0.1"]
        )
        assert s._run_ipv4_resolve_scanner() == 0

    def test_resolves_via_scanner(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        dev = device_class(mac_address="aa:bb:cc:dd:ee:ff", ip_addresses=["fe80::1"])
        s.discovered_devices["aa:bb:cc:dd:ee:ff"] = dev

        resolved_dev = device_class(mac_address="aa:bb:cc:dd:ee:ff", ip_addresses=["10.0.0.30"])
        fake_scanner = MagicMock()
        fake_scanner.scan.return_value = {"aa:bb:cc:dd:ee:ff": resolved_dev}

        with patch(
            "oida.protocols.discovery.scanner.IPv4ResolveScanner", return_value=fake_scanner
        ):
            resolved = s._run_ipv4_resolve_scanner()

        assert resolved == 1
        assert s._ip_to_mac["10.0.0.30"] == "aa:bb:cc:dd:ee:ff"


# ---------------------------------------------------------------------------
# _merge_devices_live (continuous mode)
# ---------------------------------------------------------------------------
class TestMergeDevicesLive:
    def test_new_then_update(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})

        dev = device_class(mac_address="aa:bb:cc:dd:ee:ff", ip_addresses=["10.0.0.1"])
        s._merge_devices_live({"aa:bb:cc:dd:ee:ff": dev}, "arp")
        assert "aa:bb:cc:dd:ee:ff" in s.discovered_devices

        # Update with new info (a name) via same MAC
        dev2 = device_class(mac_address="aa:bb:cc:dd:ee:ff", discovered_by=["mdns"], name="myhost")
        s._merge_devices_live({"aa:bb:cc:dd:ee:ff": dev2}, "mdns")
        merged = s.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert merged.name == "myhost"
        assert "mdns" in merged.discovered_by

    def test_skips_local_mac(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        s.local_mac = "aa:bb:cc:dd:ee:ff"
        dev = device_class(mac_address="AA:BB:CC:DD:EE:FF")
        s._merge_devices_live({"x": dev}, "arp")
        assert len(s.discovered_devices) == 0

    def test_ip_only_then_rekey_by_mac(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        # First seen as IP-only
        ip_dev = device_class(ip_addresses=["10.0.0.7"], name="ipdev")
        s._merge_devices_live({"10.0.0.7": ip_dev}, "ssdp")
        assert "ip:10.0.0.7" in s.discovered_devices

        # Later seen with a MAC for the same IP -> should re-key to MAC.
        # Use a MAC that differs from the eth0 mock's local MAC so it isn't
        # filtered as the local interface.
        mac_dev = device_class(mac_address="66:77:88:99:aa:bb", ip_addresses=["10.0.0.7"])
        s._merge_devices_live({"66:77:88:99:aa:bb": mac_dev}, "arp")
        assert "66:77:88:99:aa:bb" in s.discovered_devices
        assert "ip:10.0.0.7" not in s.discovered_devices


# ---------------------------------------------------------------------------
# _check_ip_scope / _format_excluded_locals
# ---------------------------------------------------------------------------
class TestScopeAndLocals:
    def test_check_ip_scope_flags_out_of_scope(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        s.interface_networks = ["10.0.0.0/24"]
        s.warn_out_of_scope = True

        dev = device_class(mac_address="aa:bb:cc:dd:ee:ff", ip_addresses=["192.168.50.1"])
        s._check_ip_scope(dev, "arp")

        assert "192.168.50.1" in dev.out_of_scope_ips
        assert len(s.out_of_scope_warnings) == 1
        assert s.out_of_scope_warnings[0].ip == "192.168.50.1"

    def test_check_ip_scope_in_scope_no_warning(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        s.interface_networks = ["10.0.0.0/24"]
        dev = device_class(ip_addresses=["10.0.0.50"])
        s._check_ip_scope(dev, "arp")
        assert dev.out_of_scope_ips == []
        assert s.out_of_scope_warnings == []

    def test_check_ip_scope_disabled(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        s.warn_out_of_scope = False
        s.interface_networks = ["10.0.0.0/24"]
        dev = device_class(ip_addresses=["192.168.50.1"])
        s._check_ip_scope(dev, "arp")
        assert s.out_of_scope_warnings == []

    def test_format_excluded_locals_includes_mac_and_network(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        out = s._format_excluded_locals()
        # eth0 mock => MAC 00:11:22:33:44:55, network 192.168.1.0/24
        assert "00:11:22:33:44:55" in out
        assert "192.168.1.100/24" in out


# ---------------------------------------------------------------------------
# _device_to_dict / _build_device_description
# ---------------------------------------------------------------------------
class TestDeviceToDict:
    def test_serializes_all_fields(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        dev = device_class(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["10.0.0.1"],
            name="dev",
            ntp_data={"stratum": 2},
        )
        d = s._device_to_dict(dev)
        assert d["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert d["ip_addresses"] == ["10.0.0.1"]
        # Verify the dataclass-driven serialization includes nested protocol payloads
        assert d["ntp_data"] == {"stratum": 2}

    def test_build_device_description_delegates(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        desc = s._build_device_description({"name": "router-1", "manufacturer": "Cisco"})
        assert "router-1" in desc
        assert "Cisco" in desc


# ---------------------------------------------------------------------------
# _run_enrichment_phase
# ---------------------------------------------------------------------------
class TestEnrichmentPhase:
    def test_no_devices_short_circuits(self, scanner_class):
        s = scanner_class({"target": "eth0", "active": True, "enrich": True})
        # No discovered devices -> returns immediately, no scanners constructed
        s._run_enrichment_phase()  # must not raise
        assert s.discovered_devices == {}

    def test_runs_enabled_scanners(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0", "active": True, "enrich": True})
        s.discovered_devices["k"] = device_class(mac_address="aa:bb:cc:dd:ee:ff")

        fake = MagicMock()
        fake.scan.return_value = {"k": s.discovered_devices["k"]}

        with (
            patch("oida.protocols.discovery.scanner.PingEnrichScanner", return_value=fake) as p,
            patch(
                "oida.protocols.discovery.scanner.ReverseDNSEnrichScanner", return_value=fake
            ) as r,
            patch("oida.protocols.discovery.scanner.NetBIOSEnrichScanner", return_value=fake) as n,
            patch("oida.protocols.discovery.scanner.MDNSEnrichScanner", return_value=fake) as m,
        ):
            s._run_enrichment_phase()

        # All four enrichment scanners enabled by default when enrich=True
        assert p.called and r.called and n.called and m.called


# ---------------------------------------------------------------------------
# _report_findings / _write_output_files
# ---------------------------------------------------------------------------
class TestReportAndWrite:
    def test_report_no_devices(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        # Should log "No devices discovered" and not raise
        s._report_findings({"devices": []})

    def test_report_with_devices(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        results = {
            "devices": [
                {
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "ip_addresses": ["10.0.0.1"],
                    "manufacturer": "Siemens",
                    "name": "plc",
                    "is_new": True,
                    "updated_fields": ["new_device"],
                },
                {
                    "mac_address": "",
                    "ip_addresses": ["0.0.0.0"],
                    "is_new": False,
                    "updated_fields": [],
                },
            ],
            "statistics": {"total_devices": 2, "devices_with_mac": 1},
        }
        with patch("oida.protocols.discovery.scanner.export_data") as mock_export:
            s._report_findings(results)
        assert mock_export.called
        # The table rows passed to export_data should contain the discovered MAC
        rows = mock_export.call_args.kwargs.get("data") or mock_export.call_args.args[0]
        flat = str(rows)
        assert "aa:bb:cc:dd:ee:ff" in flat

    def test_write_output_files_no_output_dir(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        results = {"devices": [{"ip_addresses": ["10.0.0.1"]}]}
        with patch("oida.utils.export_utils.get_config", return_value={"output_dir": None}):
            # No output dir configured -> returns without writing
            s._write_output_files(results)

    def test_write_output_files_writes_ip_lists(self, scanner_class, tmp_path):
        s = scanner_class({"target": "eth0"})
        results = {
            "devices": [
                {
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "ip_addresses": ["10.0.0.1", "fe80::1", "0.0.0.0"],
                    "manufacturer": "Acme",
                    "name": "n",
                    "discovered_by": ["arp"],
                }
            ]
        }
        with (
            patch(
                "oida.utils.export_utils.get_config",
                return_value={"output_dir": str(tmp_path)},
            ),
            patch("oida.protocols.discovery.scanner.export_data"),
        ):
            s._write_output_files(results)

        ipv4 = (tmp_path / "ipv4.txt").read_text()
        ipv6 = (tmp_path / "ipv6.txt").read_text()
        assert "10.0.0.1" in ipv4
        assert "0.0.0.0" not in ipv4  # filtered out
        assert "fe80::1" in ipv6


# ---------------------------------------------------------------------------
# pcap capture
# ---------------------------------------------------------------------------
class TestPcapCapture:
    def test_disabled_returns_false(self, scanner_class):
        s = scanner_class({"target": "eth0"})  # pcap disabled by default
        assert s._start_pcap_capture("/tmp") is False

    def test_stop_without_capture_returns_none(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        assert s._stop_pcap_capture() is None

    def test_start_when_interface_down(self, scanner_class):
        s = scanner_class({"target": "eth0", "pcap": True})
        with (
            patch("scapy.all.AsyncSniffer"),
            patch("oida.protocols.discovery.core.is_interface_up", return_value=False),
        ):
            assert s._start_pcap_capture("/tmp") is False

    def test_start_success(self, scanner_class):
        s = scanner_class({"target": "eth0", "pcap": True})
        sniffer = MagicMock()
        with (
            patch("scapy.all.AsyncSniffer", return_value=sniffer),
            patch("oida.protocols.discovery.core.is_interface_up", return_value=True),
        ):
            assert s._start_pcap_capture("/tmp") is True
        sniffer.start.assert_called_once()

    def test_stop_writes_packets(self, scanner_class, tmp_path):
        s = scanner_class({"target": "eth0", "pcap": True})
        # Simulate an active capture with buffered packets
        s._pcap_capture = MagicMock()
        s._pcap_file = str(tmp_path / "capture.pcap")
        s._pcap_packets = [b"pkt1", b"pkt2"]
        s._pcap_size = 8
        s._pcap_last_packet_time = __import__("time").time()

        with (
            patch("scapy.all.wrpcap") as mock_wrpcap,
            patch("oida.protocols.discovery.core.is_interface_up", return_value=True),
        ):
            out = s._stop_pcap_capture()

        assert out == str(tmp_path / "capture.pcap")
        mock_wrpcap.assert_called_once()
        # finally-block clears the capture handle
        assert s._pcap_capture is None

    def test_stop_no_packets_returns_none(self, scanner_class):
        s = scanner_class({"target": "eth0", "pcap": True})
        s._pcap_capture = MagicMock()
        s._pcap_file = "/tmp/x.pcap"
        s._pcap_packets = []
        s._pcap_size = 0
        s._pcap_last_packet_time = __import__("time").time()
        with (
            patch("scapy.all.wrpcap") as mock_wrpcap,
            patch("oida.protocols.discovery.core.is_interface_up", return_value=True),
        ):
            assert s._stop_pcap_capture() is None
        mock_wrpcap.assert_not_called()


# ---------------------------------------------------------------------------
# discover() error/guard paths
# ---------------------------------------------------------------------------
class TestDiscoverGuards:
    def test_no_connection_fails_fast(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        results = s.discover(connection=None)
        assert results["devices"] == []

    def test_raw_socket_permission_error(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        with patch(
            "oida.protocols.discovery.scanner.check_raw_socket_capability",
            return_value=(False, "permission_error"),
        ):
            results = s.discover(connection="eth0")
        assert results["devices"] == []

    def test_raw_socket_other_error(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        with patch(
            "oida.protocols.discovery.scanner.check_raw_socket_capability",
            return_value=(False, "some other error"),
        ):
            results = s.discover(connection="eth0")
        assert results["devices"] == []


# ---------------------------------------------------------------------------
# Rate limiting init path
# ---------------------------------------------------------------------------
class TestRateLimitInit:
    def test_rate_limit_configured(self, scanner_class):
        with patch("oida.protocols.discovery.scanner.set_rate_limit") as mock_set:
            s = scanner_class({"target": "eth0", "active": True, "rate_limit": 10})
        assert s.rate_limit_pps == 10.0
        mock_set.assert_called_once_with(10.0)


# ---------------------------------------------------------------------------
# _run_scanner registry dispatch
# ---------------------------------------------------------------------------
class TestRunScanner:
    def test_unknown_scanner_returns_empty(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        assert s._run_scanner("does-not-exist") == {}

    @staticmethod
    def _patch_registry(name, fake_cls):
        """Patch the class in _SCANNER_CONFIGS for `name`.

        The registry tuple captures the real scanner class at import time, so
        patching the module-level name has no effect. We swap the class in the
        tuple instead (the only external dependency: the real scapy scanner).
        """
        from oida.protocols.discovery import scanner as scanner_mod

        orig = scanner_mod._SCANNER_CONFIGS[name]
        new_tuple = (fake_cls,) + tuple(orig[1:])
        return patch.dict(scanner_mod._SCANNER_CONFIGS, {name: new_tuple})

    def test_dispatches_to_registry_class(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        fake = MagicMock(
            return_value=MagicMock(
                scan=MagicMock(
                    return_value={
                        "00:11:22:33:44:55": device_class(mac_address="00:11:22:33:44:55")
                    }
                )
            )
        )
        # "cdp" is a passive listener in the registry
        with self._patch_registry("cdp", fake):
            out = s._run_scanner("cdp")
        assert "00:11:22:33:44:55" in out
        fake.assert_called_once()

    def test_arp_small_subnet_no_prompt(self, scanner_class):
        s = scanner_class({"target": "eth0", "active": True, "subnet": "10.0.0.0/30"})
        instance = MagicMock()
        instance.scan.return_value = {}
        fake = MagicMock(return_value=instance)
        with self._patch_registry("arp", fake):
            # /30 has 2 hosts, well under the 255 prompt threshold
            s._run_scanner("arp")
        instance.scan.assert_called_once()

    def test_arp_large_subnet_declined(self, scanner_class):
        s = scanner_class({"target": "eth0", "active": True, "subnet": "10.0.0.0/16"})
        fake = MagicMock()
        with self._patch_registry("arp", fake):
            with patch("builtins.input", return_value="n"):
                out = s._run_scanner("arp")
        # User declined -> scanner class never instantiated, empty result
        assert out == {}
        fake.assert_not_called()

    def test_arp_large_subnet_forced(self, scanner_class):
        s = scanner_class(
            {"target": "eth0", "active": True, "subnet": "10.0.0.0/16", "force": True}
        )
        instance = MagicMock()
        instance.scan.return_value = {}
        fake = MagicMock(return_value=instance)
        with self._patch_registry("arp", fake):
            s._run_scanner("arp")
        # force=True bypasses the prompt and runs
        instance.scan.assert_called_once()


# ---------------------------------------------------------------------------
# _get_arp_host_count
# ---------------------------------------------------------------------------
class TestArpHostCount:
    def test_slash_24(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        assert s._get_arp_host_count("10.0.0.0/24") == 254

    def test_invalid_returns_zero(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        assert s._get_arp_host_count("garbage") == 0


# ---------------------------------------------------------------------------
# _resolve_macs_via_arp (scapy srp is the external dependency)
# ---------------------------------------------------------------------------
class TestResolveMacsViaArp:
    def test_no_ip_only_devices_returns_zero(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        s.discovered_devices["aa:bb:cc:dd:ee:ff"] = device_class(
            mac_address="aa:bb:cc:dd:ee:ff", ip_addresses=["10.0.0.1"]
        )
        assert s._resolve_macs_via_arp() == 0

    def test_resolves_via_arp_probe(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0"})
        s.discovered_devices["ip:10.0.0.50"] = device_class(ip_addresses=["10.0.0.50"])

        recv = MagicMock()
        recv.hwsrc = "66:77:88:99:AA:BB"
        with patch("oida.protocols.discovery.scanner.scapy_srp", return_value=([(None, recv)], [])):
            resolved = s._resolve_macs_via_arp()

        assert resolved == 1
        assert "66:77:88:99:aa:bb" in s.discovered_devices
        assert "ip:10.0.0.50" not in s.discovered_devices


# ---------------------------------------------------------------------------
# discover() full happy path with mocked scanners
# ---------------------------------------------------------------------------
class TestDiscoverHappyPath:
    def test_active_scan_produces_results(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0", "active": True, "no-passive": True})

        def fake_run_scanner(name):
            if name == "arp":
                return {
                    "66:77:88:99:aa:bb": device_class(
                        mac_address="66:77:88:99:aa:bb",
                        ip_addresses=["192.168.1.40"],
                        discovered_by=["arp"],
                        arp_data={"reply": True},
                    )
                }
            return {}

        with (
            patch(
                "oida.protocols.discovery.scanner.check_raw_socket_capability",
                return_value=(True, None),
            ),
            patch.object(s, "_run_scanner", side_effect=fake_run_scanner),
            patch.object(s, "_run_dcp_active", return_value={}),
            patch.object(s, "_resolve_macs_from_arp_cache", return_value=0),
            patch.object(s, "_resolve_macs_via_arp", return_value=0),
            patch.object(s, "_resolve_ipv4_for_mac_only", return_value=0),
            patch.object(s, "_run_ipv4_resolve_scanner", return_value=0),
            patch.object(s, "_ping_eui64_addresses", return_value=0),
            patch("oida.protocols.discovery.scanner.export_data"),
        ):
            results = s.discover(connection="eth0")

        assert "active" in results["scan_mode"]
        macs = [d["mac_address"] for d in results["devices"]]
        assert "66:77:88:99:aa:bb" in macs
        assert results["statistics"]["total_devices"] >= 1
        # Security analysis aggregates ARP responders
        assert any("ARP" in f for f in results["security_analysis"]["findings"])

    def test_industrial_filter_applied(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0", "active": True, "no-passive": True, "ics-only": True})

        def fake_run_scanner(name):
            if name == "arp":
                return {
                    "66:77:88:99:aa:bb": device_class(
                        mac_address="66:77:88:99:aa:bb",
                        manufacturer="Siemens",
                        name="S7-PLC",
                        discovered_by=["arp"],
                    ),
                    "66:77:88:99:aa:cc": device_class(
                        mac_address="66:77:88:99:aa:cc",
                        manufacturer="Samsung",
                        name="Smart TV",
                        discovered_by=["arp"],
                    ),
                }
            return {}

        with (
            patch(
                "oida.protocols.discovery.scanner.check_raw_socket_capability",
                return_value=(True, None),
            ),
            patch.object(s, "_run_scanner", side_effect=fake_run_scanner),
            patch.object(s, "_run_dcp_active", return_value={}),
            patch.object(s, "_resolve_macs_from_arp_cache", return_value=0),
            patch.object(s, "_resolve_macs_via_arp", return_value=0),
            patch.object(s, "_resolve_ipv4_for_mac_only", return_value=0),
            patch.object(s, "_run_ipv4_resolve_scanner", return_value=0),
            patch.object(s, "_ping_eui64_addresses", return_value=0),
            patch("oida.protocols.discovery.scanner.export_data"),
        ):
            results = s.discover(connection="eth0")

        # Only the Siemens PLC survives the ics-only filter
        names = [d.get("name") for d in results["devices"]]
        assert "S7-PLC" in names
        assert "Smart TV" not in names


# ---------------------------------------------------------------------------
# _run_continuous (continuous mode loop + finalization)
# ---------------------------------------------------------------------------
class TestRunContinuous:
    def test_finalizes_after_stop(self, scanner_class, device_class):
        s = scanner_class({"target": "eth0", "continuous": True})
        # Seed a device so finalization has something to report/serialize
        s.discovered_devices["66:77:88:99:aa:bb"] = device_class(
            mac_address="66:77:88:99:aa:bb",
            ip_addresses=["192.168.1.30"],
            discovered_by=["arp"],
        )
        # Stop immediately so the while loop body is skipped and we go straight
        # to the finally/finalization block.
        s._stop_event.set()

        with (
            patch.object(s, "_run_lldp_passive", return_value={}),
            patch.object(s, "_run_scanner", return_value={}),
            patch("oida.protocols.discovery.scanner.export_data"),
        ):
            results = s._run_continuous(
                {
                    "devices": [],
                    "protocols_used": [],
                    "scan_mode": [],
                    "statistics": {},
                    "security_analysis": {},
                }
            )

        assert results["scan_mode"] == ["continuous"]
        assert results["statistics"]["total_devices"] == 1
        macs = [d["mac_address"] for d in results["devices"]]
        assert "66:77:88:99:aa:bb" in macs

    def test_one_iteration_then_stop(self, scanner_class, device_class):
        s = scanner_class(
            {"target": "eth0", "continuous": True, "active": True, "scan-interval": 0}
        )

        call_count = {"n": 0}

        def fake_run_scanner(name):
            if name == "arp":
                call_count["n"] += 1
                return {
                    "66:77:88:99:aa:cc": device_class(
                        mac_address="66:77:88:99:aa:cc",
                        ip_addresses=["192.168.1.31"],
                        discovered_by=["arp"],
                    )
                }
            return {}

        real_merge = s._merge_devices_live

        def merge_then_stop(devices, source):
            # Let the real merge run, THEN request stop. Only stop after the ARP
            # task merges, so its device survives (other tasks return {} and may
            # complete first).
            real_merge(devices, source)
            if source == "arp":
                s._stop_event.set()

        with (
            patch.object(s, "_run_lldp_passive", return_value={}),
            patch.object(s, "_run_dcp_active", return_value={}),
            patch.object(s, "_run_scanner", side_effect=fake_run_scanner),
            patch.object(s, "_merge_devices_live", side_effect=merge_then_stop),
            patch("oida.protocols.discovery.scanner.export_data"),
        ):
            results = s._run_continuous(
                {
                    "devices": [],
                    "protocols_used": [],
                    "scan_mode": [],
                    "statistics": {},
                    "security_analysis": {},
                }
            )

        assert call_count["n"] >= 1
        macs = [d["mac_address"] for d in results["devices"]]
        assert "66:77:88:99:aa:cc" in macs
        assert "arp" in results["protocols_used"]


# ---------------------------------------------------------------------------
# _get_local_mac
# ---------------------------------------------------------------------------
class TestGetLocalMac:
    def test_returns_lowercased_mac(self, scanner_class):
        s = scanner_class({"target": "eth0"})
        # eth0 mock -> 00:11:22:33:44:55
        assert s.local_mac == "00:11:22:33:44:55"

    def test_loopback_has_no_mac(self, scanner_class):
        # lo's AF_LINK is 00:00:00:00:00:00 -> filtered to None
        s = scanner_class({"target": "lo"})
        assert s.local_mac is None


# ---------------------------------------------------------------------------
# NXC-style discovery connection class
# ---------------------------------------------------------------------------
class TestDiscoveryNxcClass:
    def _make_args(self, **over):
        ns = MagicMock()
        ns.target = "eth0"
        ns.interface = None
        ns.debug = False
        ns.verbose = 0
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def test_proto_flow_runs_scan(self):
        from oida.protocols.discovery.scanner import discovery

        # Avoid SerialConnection.__init__ side effects by constructing without
        # calling __init__, then wiring the attributes proto_flow needs.
        d = discovery.__new__(discovery)
        d.protocol_name = "DISCOVERY"
        d.default_port = None
        d._scan_results = None
        d.interface = "eth0"
        d.logger = MagicMock()
        d.args = self._make_args()

        fake_scanner = MagicMock()
        fake_scanner.connect.return_value = "eth0"
        fake_scanner.discover.return_value = {"devices": [{"mac_address": "aa:bb:cc:dd:ee:ff"}]}

        with (
            patch.object(discovery, "_convert_args_to_dict", return_value={"interface": "eth0"}),
            patch("oida.protocols.discovery.scanner.DiscoveryScanner", return_value=fake_scanner),
        ):
            d.proto_flow()

        assert fake_scanner.discover.called
        assert d._scan_results["devices"][0]["mac_address"] == "aa:bb:cc:dd:ee:ff"

    def test_proto_flow_aborts_on_bad_interface(self):
        from oida.protocols.discovery.scanner import discovery

        d = discovery.__new__(discovery)
        d.interface = "eth0"
        d.logger = MagicMock()
        d.args = self._make_args()
        d._scan_results = None

        fake_scanner = MagicMock()
        fake_scanner.connect.return_value = None  # interface invalid

        with (
            patch.object(discovery, "_convert_args_to_dict", return_value={"interface": "eth0"}),
            patch("oida.protocols.discovery.scanner.DiscoveryScanner", return_value=fake_scanner),
        ):
            d.proto_flow()

        # discover() must not be called when create_conn_obj returns False
        assert not fake_scanner.discover.called

    def test_get_results_success(self):
        from oida.protocols.discovery.scanner import discovery

        d = discovery.__new__(discovery)
        d.interface = "eth0"
        d._scan_results = {"devices": [{"mac_address": "x"}]}
        out = d.get_results()
        assert out["success"] is True
        assert out["protocol"] == "discovery"
        assert out["data"]["devices"][0]["mac_address"] == "x"

    def test_get_results_failure(self):
        from oida.protocols.discovery.scanner import discovery

        d = discovery.__new__(discovery)
        d.interface = "eth0"
        d._scan_results = None
        out = d.get_results()
        assert out["success"] is False

    def test_cleanup_calls_disconnect(self):
        from oida.protocols.discovery.scanner import discovery

        d = discovery.__new__(discovery)
        d.scanner = MagicMock()
        d.cleanup()
        d.scanner.disconnect.assert_called_once_with(None)

    def test_create_conn_obj_success(self):
        from oida.protocols.discovery.scanner import discovery

        d = discovery.__new__(discovery)
        d.interface = "eth0"
        d.logger = MagicMock()
        d.scanner = MagicMock()
        d.scanner.connect.return_value = "eth0"
        assert d.create_conn_obj() is True

    def test_create_conn_obj_failure(self):
        from oida.protocols.discovery.scanner import discovery

        d = discovery.__new__(discovery)
        d.interface = "eth0"
        d.logger = MagicMock()
        d.scanner = MagicMock()
        d.scanner.connect.return_value = None
        assert d.create_conn_obj() is False

    def test_execute_scan_handles_exception(self):
        from oida.protocols.discovery.scanner import discovery

        d = discovery.__new__(discovery)
        d.interface = "eth0"
        d.logger = MagicMock()
        d.scanner = MagicMock()
        d.scanner.discover.side_effect = RuntimeError("boom")
        d._connection = "eth0"
        d._execute_scan()  # must swallow the error
        d.logger.fail.assert_called()
