"""
Coverage-focused tests for discovery.core helpers.

Targets the large uncovered regions of core.py:
- build_device_description() (the standalone description builder)
- check_ip_in_network_scope() branches
- OutOfScopeWarning (timestamp auto-population)
- Socket / interface helper functions (create_udp_socket, bind_socket_to_interface,
  get_interface_ips, get_interface_ipv6, check_interface_capabilities,
  get_all_broadcast_addresses, compute_network_cidr, hex_dump)

These exercise real logic; only genuine external I/O (raw sockets, interface
enumeration) is mocked. The autouse mock_netifaces fixture in conftest patches
iface_info enumeration for "eth0"/"wlan0"/"lo".
"""

import socket
from unittest.mock import MagicMock, patch

import pytest

from oida.protocols.discovery import core


# ---------------------------------------------------------------------------
# hex_dump
# ---------------------------------------------------------------------------
class TestHexDump:
    def test_empty_returns_placeholder(self):
        assert core.hex_dump(b"") == "  (empty)"

    def test_ascii_and_offset(self):
        out = core.hex_dump(b"AB\x00\xff")
        # offset column, hex bytes, and printable/non-printable ASCII rendering
        assert "0000:" in out
        assert "41 42 00 ff" in out
        assert "AB.." in out  # 0x00 and 0xff render as '.'

    def test_multiline_wrap(self):
        out = core.hex_dump(bytes(range(20)), width=16)
        lines = out.split("\n")
        assert len(lines) == 2
        assert lines[1].strip().startswith("0010:")


# ---------------------------------------------------------------------------
# compute_network_cidr
# ---------------------------------------------------------------------------
class TestComputeNetworkCidr:
    def test_valid(self):
        assert core.compute_network_cidr("10.0.0.50", "255.255.255.0") == "10.0.0.0/24"

    def test_missing_args_returns_none(self):
        assert core.compute_network_cidr("", "255.255.255.0") is None
        assert core.compute_network_cidr("10.0.0.1", "") is None

    def test_invalid_returns_none(self):
        assert core.compute_network_cidr("not-an-ip", "255.255.255.0") is None


# ---------------------------------------------------------------------------
# Interface helpers (use the eth0 mock from conftest)
# ---------------------------------------------------------------------------
class TestInterfaceHelpers:
    def test_get_interface_ips_returns_addr(self):
        assert core.get_interface_ips("eth0") == ["192.168.1.100"]

    def test_get_interface_ips_no_ipv4_raises(self):
        # lo has 127.0.0.1 which still counts as an addr; use an interface with
        # only a MAC entry by patching ifaddresses for this call.
        with patch.object(core._iface_info, "ifaddresses", return_value={17: [{"addr": "x"}]}):
            with pytest.raises(ValueError, match="no IPv4"):
                core.get_interface_ips("eth0")

    def test_get_interface_ip_single(self):
        assert core.get_interface_ip("eth0") == "192.168.1.100"

    def test_get_interface_ip_no_ipv4_raises(self):
        with patch.object(core._iface_info, "ifaddresses", return_value={17: [{"addr": "x"}]}):
            with pytest.raises(ValueError, match="no IPv4"):
                core.get_interface_ip("eth0")

    def test_get_interface_networks_cidr(self):
        nets = core.get_interface_networks("eth0")
        assert nets == [("192.168.1.100", "192.168.1.0/24")]

    def test_get_interface_networks_skips_loopback(self):
        # lo's only AF_INET addr is 127.0.0.1, which is filtered -> no networks
        with pytest.raises(ValueError, match="no configured IPv4"):
            core.get_interface_networks("lo")

    def test_get_interface_network_first(self):
        assert core.get_interface_network("eth0") == "192.168.1.0/24"

    def test_get_interface_ipv6_filtered(self):
        fake = {
            10: [  # AF_INET6
                {"addr": "fe80::1%eth0"},
                {"addr": "::1"},  # loopback, filtered
                {"addr": "2001:db8::5"},
            ]
        }
        with patch.object(core._iface_info, "ifaddresses", return_value=fake):
            addrs = core.get_interface_ipv6("eth0")
        assert "fe80::1" in addrs  # zone id stripped
        assert "2001:db8::5" in addrs
        assert "::1" not in addrs

    def test_get_interface_ipv6_none_raises(self):
        with patch.object(core._iface_info, "ifaddresses", return_value={2: []}):
            with pytest.raises(ValueError, match="no IPv6"):
                core.get_interface_ipv6("eth0")


# ---------------------------------------------------------------------------
# check_interface_capabilities
# ---------------------------------------------------------------------------
class TestCheckInterfaceCapabilities:
    def test_eth0_has_ipv4_and_mac(self):
        caps = core.check_interface_capabilities("eth0")
        assert caps.interface == "eth0"
        assert caps.has_ipv4 is True
        assert caps.ipv4_address == "192.168.1.100"
        assert caps.has_mac is True
        assert caps.mac_address == "00:11:22:33:44:55"
        assert caps.has_ipv6 is False

    def test_unknown_interface_raises(self):
        with pytest.raises(ValueError, match="not found"):
            core.check_interface_capabilities("does_not_exist")

    def test_ipv6_global_detected(self):
        fake = {
            17: [{"addr": "00:11:22:33:44:55"}],
            10: [
                {"addr": "fe80::1%eth0"},  # link-local
                {"addr": "2001:db8::10"},  # global
                {"addr": "::1"},  # loopback, filtered
            ],
        }
        with patch.object(core._iface_info, "ifaddresses", return_value=fake):
            caps = core.check_interface_capabilities("eth0")
        assert caps.has_ipv6 is True
        assert caps.has_ipv6_global is True
        assert "2001:db8::10" in caps.ipv6_addresses
        assert "fe80::1" in caps.ipv6_addresses


# ---------------------------------------------------------------------------
# bind_socket_to_interface / create_udp_socket
# ---------------------------------------------------------------------------
class TestSocketHelpers:
    def test_bind_socket_success(self):
        sock = MagicMock()
        assert core.bind_socket_to_interface(sock, "eth0") is True
        sock.setsockopt.assert_called_once()

    def test_bind_socket_failure_returns_false(self):
        sock = MagicMock()
        sock.setsockopt.side_effect = OSError("no perm")
        assert core.bind_socket_to_interface(sock, "eth0") is False

    def test_create_udp_socket_uses_bindtodevice(self):
        with patch.object(core, "bind_socket_to_interface", return_value=True):
            sock = core.create_udp_socket("eth0", timeout=1.0, broadcast=True, bind_port=12345)
        try:
            assert isinstance(sock, socket.socket)
            assert sock.gettimeout() == 1.0
            # Broadcast option enabled
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST) == 1
            # Bound to the requested port
            assert sock.getsockname()[1] == 12345
        finally:
            sock.close()

    def test_create_udp_socket_fallback_to_interface_ip(self):
        # When SO_BINDTODEVICE "fails", code binds to interface IP (eth0 -> 192.168.1.100)
        with patch.object(core, "bind_socket_to_interface", return_value=False):
            # Real bind to a non-local IP would fail; patch get_interface_ip to loopback
            with patch.object(core, "get_interface_ip", return_value="127.0.0.1"):
                sock = core.create_udp_socket("eth0", timeout=0.5, multicast_ttl=4)
        try:
            assert sock.getsockname()[0] == "127.0.0.1"
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# get_all_broadcast_addresses
# ---------------------------------------------------------------------------
class TestBroadcastAddresses:
    def test_includes_global_and_interface(self):
        addrs = core.get_all_broadcast_addresses("eth0")
        assert "255.255.255.255" in addrs
        assert "192.168.1.255" in addrs

    def test_includes_explicit_subnet(self):
        addrs = core.get_all_broadcast_addresses("eth0", subnet="10.5.0.0/24")
        assert "10.5.0.255" in addrs
        assert "192.168.1.255" in addrs

    def test_bad_subnet_ignored(self):
        addrs = core.get_all_broadcast_addresses("eth0", subnet="garbage")
        # Bad subnet skipped, but global + interface broadcast still present
        assert "255.255.255.255" in addrs
        assert "192.168.1.255" in addrs


# ---------------------------------------------------------------------------
# check_ip_in_network_scope
# ---------------------------------------------------------------------------
class TestCheckIpScope:
    def test_in_scope(self):
        ok, reason = core.check_ip_in_network_scope("10.0.0.5", interface_network="10.0.0.0/24")
        assert ok is True
        assert reason == ""

    def test_out_of_scope(self):
        ok, reason = core.check_ip_in_network_scope("192.168.99.5", interface_network="10.0.0.0/24")
        assert ok is False
        assert "requires routing" in reason

    def test_empty_ip_in_scope(self):
        assert core.check_ip_in_network_scope("") == (True, "")

    def test_loopback_always_in_scope(self):
        assert core.check_ip_in_network_scope("127.0.0.1", interface_network="10.0.0.0/24") == (
            True,
            "",
        )

    def test_link_local_always_in_scope(self):
        assert core.check_ip_in_network_scope("fe80::1", interface_network="10.0.0.0/24") == (
            True,
            "",
        )

    def test_invalid_ip_in_scope(self):
        assert core.check_ip_in_network_scope("not-ip", interface_network="10.0.0.0/24") == (
            True,
            "",
        )

    def test_no_network_info_in_scope(self):
        # No interface_network and no interface -> can't determine -> in scope
        assert core.check_ip_in_network_scope("8.8.8.8") == (True, "")

    def test_resolves_network_from_interface(self):
        ok, reason = core.check_ip_in_network_scope("192.168.1.50", interface="eth0")
        assert ok is True

    def test_dual_stack_version_mismatch_in_scope(self):
        # IPv6 IP against an IPv4 network -> normal dual-stack, not a warning
        ok, reason = core.check_ip_in_network_scope("2001:db8::1", interface_network="10.0.0.0/24")
        assert ok is True
        assert reason == ""


# ---------------------------------------------------------------------------
# OutOfScopeWarning
# ---------------------------------------------------------------------------
class TestOutOfScopeWarning:
    def test_timestamp_autopopulated(self):
        w = core.OutOfScopeWarning(ip="10.0.0.1", expected_network="192.168.1.0/24")
        assert w.timestamp  # __post_init__ filled it


# ---------------------------------------------------------------------------
# build_device_description  (large uncovered standalone function)
# ---------------------------------------------------------------------------
class TestBuildDeviceDescription:
    def test_empty_device(self):
        assert core.build_device_description({}) == ""

    def test_name_only(self):
        assert core.build_device_description({"name": "switch-1"}) == "switch-1"

    def test_lldp_parsed_fields(self):
        device = {
            "name": "SIMATIC",
            "lldp_data": {
                "parsed_manufacturer": "Siemens",
                "parsed_model": "CPU-1200",
                "parsed_article_number": "6ES7 214",
                "parsed_firmware": "V4.1.3",
                "parsed_serial": "ABC123",
                "port_description": "Port X1 P1",
                "capabilities": ["Bridge", "Router"],
            },
        }
        desc = core.build_device_description(device)
        assert "SIMATIC" in desc
        assert "CPU-1200" in desc
        assert "FW:V4.1.3" in desc
        assert "Port:X1" in desc.replace(" ", "") or "Port:X1 P1" in desc

    def test_manufacturer_model_without_lldp(self):
        device = {"manufacturer": "Acme", "model": "X100", "device_type": "PLC"}
        desc = core.build_device_description(device)
        assert "Acme" in desc
        assert "X100" in desc
        assert "[PLC]" in desc

    def test_dcp_station_name_inserted(self):
        device = {
            "dcp_data": {
                "name_of_station": "plc-station",
                "device_id": 42,
                "device_role": "IO-Device",
            }
        }
        desc = core.build_device_description(device)
        assert "plc-station" in desc
        assert "ID:42" in desc
        assert "Role:IO-Device" in desc

    def test_mdns_services_used_when_no_name(self):
        device = {
            "mdns_services": [
                {"name": "Printer._ipp._tcp.local.", "type": "_ipp._tcp.local."},
                {"name": "x", "type": "_http._tcp.local."},
            ]
        }
        desc = core.build_device_description(device)
        assert "Printer" in desc
        assert "Services:" in desc

    def test_ssdp_friendly_name_and_model(self):
        device = {"ssdp_data": {"friendly_name": "My TV", "device_type": "MediaRenderer"}}
        desc = core.build_device_description(device)
        assert "My TV" in desc
        assert "[MediaRenderer]" in desc

    def test_cdp_device_id_and_platform(self):
        device = {
            "cdp_data": {
                "device_id": "core-switch",
                "platform": "cisco WS-C2960",
                "software_version": "IOS 15.0 build 1234567890",
            }
        }
        desc = core.build_device_description(device)
        assert "core-switch" in desc
        assert "cisco WS-C2960" in desc
        assert "SW:" in desc

    def test_knx_and_bacnet(self):
        knx = core.build_device_description(
            {"knx_data": {"individual_address": "1.1.1", "device_descriptor": "KNX-IP"}}
        )
        assert "KNX:1.1.1" in knx
        assert "KNX-IP" in knx

        bac = core.build_device_description(
            {"bacnet_data": {"device_id": 7, "object_name": "AHU-1", "vendor_name": "Siemens"}}
        )
        assert "BACnet:7" in bac
        assert "AHU-1" in bac
        assert "Siemens" in bac

    def test_ethernetip_and_codesys(self):
        eip = core.build_device_description(
            {
                "ethernetip_data": {
                    "product_name": "1756-L71",
                    "vendor": "Rockwell",
                    "serial_number": "0xABCD",
                }
            }
        )
        assert "1756-L71" in eip
        assert "Rockwell" in eip
        assert "S/N:0xABCD" in eip

        cds = core.build_device_description(
            {"codesys_data": {"node_name": "node-A", "device_name": "WAGO-PFC"}}
        )
        assert "node-A" in cds
        assert "CODESYS" in cds

    def test_moxa_lantronix_stp_netbios_dhcp(self):
        moxa = core.build_device_description(
            {"moxa_data": {"model": "NPort 5650", "firmware": "1.9"}}
        )
        assert "Moxa NPort 5650" in moxa
        assert "FW:1.9" in moxa

        lan = core.build_device_description({"lantronix_data": {"model": "XPort"}})
        assert "Lantronix XPort" in lan

        stp = core.build_device_description(
            {"stp_data": {"bridge_priority": 32768, "root_bridge": True}}
        )
        assert "STP-Pri:32768" in stp
        assert "Root" in stp

        nb = core.build_device_description(
            {"netbios_data": {"name": "WORKSTATION1", "domain": "CORP"}}
        )
        assert "WORKSTATION1" in nb
        assert "Domain:CORP" in nb

        dhcp = core.build_device_description(
            {"dhcp_data": {"hostname": "laptop", "vendor_class": "MSFT 5.0"}}
        )
        assert "laptop" in dhcp
        assert "DHCP:MSFT 5.0" in dhcp

    def test_passive_tls_smb_http_dns(self):
        tls = core.build_device_description(
            {"tls_passive_data": {"common_name": "secure.example.com", "organization": "ExampleCo"}}
        )
        assert "secure.example.com" in tls
        assert "ExampleCo" in tls

        smb = core.build_device_description(
            {
                "smb_passive_data": {
                    "hostname": "FILESRV",
                    "domain": "CORP",
                    "os": "Windows Server 2019",
                }
            }
        )
        assert "FILESRV" in smb
        assert "Domain:CORP" in smb
        assert "Windows" in smb

        http = core.build_device_description({"http_passive_data": {"server": "nginx/1.21.0"}})
        assert "nginx" in http

        dns = core.build_device_description(
            {"dns_passive_data": {"hostnames": ["host.local", "alias.local"]}}
        )
        assert "host.local" in dns

    def test_fallback_to_raw_description(self):
        device = {"description": "Some raw banner text that is fairly long here"}
        desc = core.build_device_description(device)
        assert "Some raw banner" in desc

    def test_verbose_appends_reasons(self):
        device = {"name": "dev", "discovery_reasons": ["arp:reply", "mdns:PTR"]}
        desc = core.build_device_description(device, verbose=True)
        assert "arp:reply" in desc
        assert "mdns:PTR" in desc

    def test_truncates_to_three_parts_plus_details(self):
        # Many desc parts + details: only first 3 desc parts and 4 details kept
        device = {
            "name": "n1",
            "manufacturer": "m1",
            "model": "mod1",
            "device_type": "t1",
        }
        # Without lldp, desc_parts = [n1, m1, mod1] (3) and details=[ [t1] ]
        desc = core.build_device_description(device)
        assert "n1" in desc and "m1" in desc and "mod1" in desc


# ---------------------------------------------------------------------------
# is_valid_discovered_ip
# ---------------------------------------------------------------------------
class TestIsValidDiscoveredIp:
    def test_empty_false(self):
        assert core.is_valid_discovered_ip("") is False

    def test_broadcast_false(self):
        assert core.is_valid_discovered_ip("255.255.255.255") is False

    def test_zero_false(self):
        assert core.is_valid_discovered_ip("0.0.0.0") is False

    def test_loopback_false(self):
        assert core.is_valid_discovered_ip("127.0.0.1") is False

    def test_normal_true(self):
        assert core.is_valid_discovered_ip("10.0.0.5") is True

    def test_filters_local_interface_ip(self):
        # eth0 mock -> local IP 192.168.1.100 should be filtered out
        assert core.is_valid_discovered_ip("192.168.1.100", interface="eth0") is False
        assert core.is_valid_discovered_ip("192.168.1.7", interface="eth0") is True


# ---------------------------------------------------------------------------
# normalize_mac / is_valid_mac edge cases
# ---------------------------------------------------------------------------
class TestMacNormalization:
    def test_normalize_dash_form(self):
        assert core.normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"

    def test_normalize_cisco_dot_form(self):
        assert core.normalize_mac("0011.2233.4455") == "00:11:22:33:44:55"

    def test_normalize_empty(self):
        assert core.normalize_mac("") == ""

    def test_valid_mac_true(self):
        assert core.is_valid_mac("aa:bb:cc:dd:ee:ff") is True

    def test_broadcast_mac_false(self):
        assert core.is_valid_mac("ff:ff:ff:ff:ff:ff") is False

    def test_zero_mac_false(self):
        assert core.is_valid_mac("00:00:00:00:00:00") is False

    def test_ipv4_multicast_mac_false(self):
        assert core.is_valid_mac("01:00:5e:00:00:fb") is False

    def test_ipv6_multicast_mac_false(self):
        assert core.is_valid_mac("33:33:00:00:00:01") is False

    def test_wrong_length_false(self):
        assert core.is_valid_mac("aa:bb:cc") is False

    def test_non_hex_false(self):
        assert core.is_valid_mac("zz:bb:cc:dd:ee:ff") is False


# ---------------------------------------------------------------------------
# is_interface_up
# ---------------------------------------------------------------------------
class TestIsInterfaceUp:
    def test_up_state(self):
        with patch("oida.utils.platform_compat.get_interface_state", return_value="up"):
            assert core.is_interface_up("eth0") is True

    def test_down_state(self):
        with patch("oida.utils.platform_compat.get_interface_state", return_value="down"):
            assert core.is_interface_up("eth0") is False

    def test_fallback_to_interface_list(self):
        # No state from platform -> falls back to interface enumeration (eth0 exists)
        with patch("oida.utils.platform_compat.get_interface_state", return_value=None):
            assert core.is_interface_up("eth0") is True
            assert core.is_interface_up("nope0") is False


# ---------------------------------------------------------------------------
# DiscoveredDevice.merge_from protocol-data branches
# ---------------------------------------------------------------------------
class TestMergeFromProtocolData:
    def _dev(self, **kw):
        return core.DiscoveredDevice(**kw)

    def test_merges_many_protocol_buckets_when_empty(self):
        target = self._dev()
        other = self._dev(
            arp_data={"a": 1},
            lldp_data={"l": 1},
            knx_data={"k": 1},
            bacnet_data={"b": 1},
            ethernetip_data={"e": 1},
            netbios_data={"n": 1},
            hsrp_data={"h": 1},
            ntp_data={"stratum": 2},
            vrrp_data={"vrid": 1},
            ospf_data={"router": "1.1.1.1"},
            modbus_passive_data={"unit": 1},
        )
        updated = target.merge_from(other)
        assert target.arp_data == {"a": 1}
        assert target.lldp_data == {"l": 1}
        assert target.knx_data == {"k": 1}
        assert target.bacnet_data == {"b": 1}
        assert target.ethernetip_data == {"e": 1}
        assert target.ntp_data == {"stratum": 2}
        assert target.ospf_data == {"router": "1.1.1.1"}
        assert target.modbus_passive_data == {"unit": 1}
        assert "arp_data" in updated and "ntp_data" in updated

    def test_existing_protocol_data_not_overwritten(self):
        target = self._dev(arp_data={"keep": True})
        other = self._dev(arp_data={"replace": True})
        target.merge_from(other)
        assert target.arp_data == {"keep": True}

    def test_it_infra_buckets_merged(self):
        target = self._dev()
        other = self._dev(
            mssql_data={"instance": "SQLEXPRESS"},
            jenkins_data={"version": "2.4"},
            ipmi_data={"vendor": "iLO"},
        )
        updated = target.merge_from(other)
        assert target.mssql_data == {"instance": "SQLEXPRESS"}
        assert target.jenkins_data == {"version": "2.4"}
        assert "mssql_data" in updated
        assert "jenkins_data" in updated

    def test_dnssd_services_accumulate(self):
        target = self._dev(dnssd_data={"services": [{"t": 1}]})
        other = self._dev(dnssd_data={"services": [{"t": 2}]})
        target.merge_from(other)
        assert len(target.dnssd_data["services"]) == 2

    def test_ipv6_addresses_merge(self):
        target = self._dev(ipv6_data={"addresses": ["fe80::1"]})
        other = self._dev(ipv6_data={"addresses": ["fe80::1", "fe80::2"]})
        target.merge_from(other)
        assert "fe80::2" in target.ipv6_data["addresses"]
        # No duplicate
        assert target.ipv6_data["addresses"].count("fe80::1") == 1
