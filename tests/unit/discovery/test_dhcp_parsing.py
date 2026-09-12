#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Behavioral parsing tests for the DHCP discovery code.

These tests build *real* DHCP packets with scapy (Ether/IP/UDP/BOOTP/DHCP),
round-trip them through ``bytes()`` so the option blob is genuinely dissected,
and then feed them through the real parsing code paths in
``oida.protocols.discovery.dhcp``. No parsing logic is mocked away. Only the
two pure-network helpers that touch the live host (``is_valid_discovered_ip``
and ``get_interface_networks``) are patched, because they query real interfaces.
"""

from unittest.mock import MagicMock, patch

from tests.service_gate import require_import

scapy_all = require_import("scapy.all")

from scapy.all import BOOTP, DHCP, IP, UDP, Ether  # noqa: E402

import oida.protocols.discovery.dhcp as dhcpmod  # noqa: E402
from oida.protocols.discovery.dhcp import (  # noqa: E402
    DHCPPassiveListener,
    DHCPServerScanner,
)

CLIENT_MAC = "aa:bb:cc:dd:ee:01"
CLIENT_MAC_BYTES = bytes.fromhex("aabbccddee01")
SERVER_MAC = "00:11:22:33:44:55"


# ---------------------------------------------------------------------------
# Packet builders (real scapy packets, round-tripped through bytes())
# ---------------------------------------------------------------------------


def build_client(msg_type="discover", options=None, xid=0x1234, src_mac=CLIENT_MAC):
    opts = [("message-type", msg_type)]
    if options:
        opts.extend(options)
    opts.append("end")
    pkt = (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex(src_mac.replace(":", "")), xid=xid)
        / DHCP(options=opts)
    )
    return Ether(bytes(pkt))


def build_server_response(
    msg_type="offer",
    yiaddr="192.168.1.50",
    options=None,
    xid=0x1234,
    bootp_kw=None,
):
    opts = [("message-type", msg_type)]
    if options:
        opts.extend(options)
    opts.append("end")
    bootp_fields = dict(
        chaddr=CLIENT_MAC_BYTES,
        yiaddr=yiaddr,
        xid=xid,
        op=2,
    )
    if bootp_kw:
        bootp_fields.update(bootp_kw)
    pkt = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src="192.168.1.1", dst=yiaddr)
        / UDP(sport=67, dport=68)
        / BOOTP(**bootp_fields)
        / DHCP(options=opts)
    )
    return Ether(bytes(pkt))


def _patch_network():
    """Patch the live-host helpers so server tracking does not hit real ifaces."""
    return (
        patch.object(dhcpmod, "is_valid_discovered_ip", return_value=True),
        patch.object(
            dhcpmod, "get_interface_networks", return_value=[("192.168.1.5", "192.168.1.0/24")]
        ),
    )


# ---------------------------------------------------------------------------
# DHCPPassiveListener: client message processing
# ---------------------------------------------------------------------------


class TestDHCPPassiveClient:
    def test_discover_creates_device(self):
        listener = DHCPPassiveListener("eth0")
        listener.feed_packet(
            build_client(
                "discover",
                [("hostname", b"laptop-01"), ("vendor_class_id", b"MSFT 5.0")],
            )
        )
        assert CLIENT_MAC in listener.discovered_devices
        device = listener.discovered_devices[CLIENT_MAC]
        assert device.name == "laptop-01"
        assert device.discovery_reasons == ["dhcp:DISCOVER"]
        assert device.dhcp_data["hostname"] == "laptop-01"
        assert device.dhcp_data["vendor_class"] == "MSFT 5.0"
        assert device.dhcp_data["message_type"] == "DISCOVER"

    def test_request_with_requested_addr(self):
        listener = DHCPPassiveListener("eth0")
        listener.feed_packet(
            build_client(
                "request",
                [("hostname", b"host-2"), ("requested_addr", "192.168.1.77")],
            )
        )
        device = listener.discovered_devices[CLIENT_MAC]
        assert "192.168.1.77" in device.ip_addresses
        assert device.dhcp_data["requested_ip"] == "192.168.1.77"
        assert device.discovery_reasons == ["dhcp:REQUEST"]

    def test_param_request_list_captured(self):
        listener = DHCPPassiveListener("eth0")
        listener.feed_packet(build_client("discover", [("param_req_list", [1, 3, 6, 15, 51])]))
        device = listener.discovered_devices[CLIENT_MAC]
        assert device.dhcp_data["param_request_list"] == [1, 3, 6, 15, 51]

    def test_inform_message_processed(self):
        listener = DHCPPassiveListener("eth0")
        listener.feed_packet(build_client("inform", [("hostname", b"informer")]))
        device = listener.discovered_devices[CLIENT_MAC]
        assert device.discovery_reasons == ["dhcp:INFORM"]

    def test_repeated_client_messages_dedup_and_accumulate_reasons(self):
        listener = DHCPPassiveListener("eth0")
        listener.feed_packet(build_client("discover", [("hostname", b"box")]))
        listener.feed_packet(build_client("request", [("hostname", b"box")]))
        assert len(listener.discovered_devices) == 1
        device = listener.discovered_devices[CLIENT_MAC]
        assert "dhcp:DISCOVER" in device.discovery_reasons
        assert "dhcp:REQUEST" in device.discovery_reasons

    def test_client_id_ethernet_type(self):
        listener = DHCPPassiveListener("eth0")
        listener.feed_packet(
            build_client("discover", [("client_id", b"\x01\xaa\xbb\xcc\xdd\xee\x01")])
        )
        device = listener.discovered_devices[CLIENT_MAC]
        assert device.dhcp_data["client_id"] == "aa:bb:cc:dd:ee:01"
        assert device.dhcp_data["client_id_type"] == "mac"

    def test_two_clients_two_devices(self):
        listener = DHCPPassiveListener("eth0")
        listener.feed_packet(build_client("discover", src_mac="aa:bb:cc:dd:ee:01"))
        listener.feed_packet(build_client("discover", src_mac="aa:bb:cc:dd:ee:02"))
        assert len(listener.discovered_devices) == 2


# ---------------------------------------------------------------------------
# DHCPPassiveListener: server response processing
# ---------------------------------------------------------------------------


class TestDHCPPassiveServer:
    def test_offer_tracks_server_and_updates_client(self):
        listener = DHCPPassiveListener("eth0")
        # First the client appears.
        listener.feed_packet(build_client("discover", [("hostname", b"box")]))

        p1, p2 = _patch_network()
        with p1, p2:
            listener.feed_packet(
                build_server_response(
                    "offer",
                    yiaddr="192.168.1.50",
                    options=[("server_id", "192.168.1.1"), ("subnet_mask", "255.255.255.0")],
                )
            )

        assert "192.168.1.1" in listener.dhcp_servers
        device = listener.discovered_devices[CLIENT_MAC]
        assert "192.168.1.50" in device.ip_addresses
        assert device.dhcp_data["assigned_ip"] == "192.168.1.50"
        assert device.dhcp_data["dhcp_server"] == "192.168.1.1"
        # Server is also recorded as its own discovered device.
        assert "ip:192.168.1.1" in listener.discovered_devices
        assert listener.discovered_devices["ip:192.168.1.1"].device_type == "DHCP Server"

    def test_ack_message_also_treated_as_server(self):
        listener = DHCPPassiveListener("eth0")
        p1, p2 = _patch_network()
        with p1, p2:
            listener.feed_packet(
                build_server_response(
                    "ack",
                    yiaddr="192.168.1.60",
                    options=[("server_id", "192.168.1.1")],
                )
            )
        assert "192.168.1.1" in listener.dhcp_servers

    def test_server_ip_falls_back_to_ip_src_when_no_option(self):
        listener = DHCPPassiveListener("eth0")
        p1, p2 = _patch_network()
        with p1, p2:
            # No server_id option -> uses IP source (192.168.1.1 from builder).
            listener.feed_packet(
                build_server_response("offer", options=[("subnet_mask", "255.255.255.0")])
            )
        assert "192.168.1.1" in listener.dhcp_servers

    def test_network_mismatch_warns(self):
        mock_logger = MagicMock()
        listener = DHCPPassiveListener("eth0", nxc_logger=mock_logger)
        with (
            patch.object(dhcpmod, "is_valid_discovered_ip", return_value=True),
            patch.object(
                dhcpmod,
                "get_interface_networks",
                return_value=[("192.168.1.5", "192.168.1.0/24")],
            ),
        ):
            listener.feed_packet(
                build_server_response(
                    "offer",
                    yiaddr="10.99.0.50",
                    options=[("server_id", "10.99.0.1"), ("subnet_mask", "255.255.255.0")],
                )
            )
        mock_logger.warning.assert_called_once()
        msg = mock_logger.warning.call_args[0][0]
        assert "10.99.0.0/24" in msg


# ---------------------------------------------------------------------------
# DHCPPassiveListener: client-id parsing branches
# ---------------------------------------------------------------------------


class TestDHCPClientIdParsing:
    def setup_method(self):
        self.listener = DHCPPassiveListener("eth0")

    def test_ethernet_mac(self):
        assert self.listener._parse_client_id(b"\x01\xaa\xbb\xcc\xdd\xee\x01") == (
            "aa:bb:cc:dd:ee:01",
            "mac",
        )

    def test_string_type_zero(self):
        assert self.listener._parse_client_id(b"\x00host-name\x00") == ("host-name", "string")

    def test_guid_type(self):
        cid, kind = self.listener._parse_client_id(b"\xff" + bytes(range(16)))
        assert kind == "guid"
        assert cid == "00010203-0405-0607-0809-0a0b0c0d0e0f"

    def test_string_passthrough(self):
        assert self.listener._parse_client_id("rawstring") == ("rawstring", "string")

    def test_too_short_returns_empty(self):
        assert self.listener._parse_client_id(b"\x01") == ("", "")

    def test_other_hw_type_printable(self):
        assert self.listener._parse_client_id(b"\x05abc") == ("abc", "type5")

    def test_unsupported_input_type(self):
        assert self.listener._parse_client_id(12345) == ("", "")


# ---------------------------------------------------------------------------
# DHCPPassiveListener: option parsing & invalid input
# ---------------------------------------------------------------------------


class TestDHCPOptionParsing:
    def test_parse_options_stops_at_end(self):
        listener = DHCPPassiveListener("eth0")
        opts = [("message-type", 1), ("hostname", b"h"), "end", ("ignored", b"x")]
        parsed = listener._parse_dhcp_options(opts)
        assert parsed == {"message-type": 1, "hostname": b"h"}
        assert "ignored" not in parsed

    def test_invalid_mac_packet_ignored(self):
        listener = DHCPPassiveListener("eth0")
        # chaddr all-zero -> normalize_mac -> 00:00:00:00:00:00 is invalid.
        pkt = build_client("discover", src_mac="00:00:00:00:00:00")
        listener.feed_packet(pkt)
        assert listener.discovered_devices == {}

    def test_non_dhcp_packet_not_processed(self):
        listener = DHCPPassiveListener("eth0")
        plain = Ether(src=CLIENT_MAC) / IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=53, dport=53)
        plain = Ether(bytes(plain))
        assert listener.should_process_packet(plain) is False
        listener.feed_packet(plain)
        assert listener.discovered_devices == {}

    def test_should_process_packet_true_for_dhcp(self):
        listener = DHCPPassiveListener("eth0")
        assert listener.should_process_packet(build_client("discover")) is True


# ---------------------------------------------------------------------------
# DHCPServerScanner: rich offer parsing
# ---------------------------------------------------------------------------


class TestDHCPServerScannerOffer:
    def _scanner(self):
        return DHCPServerScanner("eth0", nxc_logger=MagicMock())

    def test_rich_offer_populates_dhcp_data(self):
        scanner = self._scanner()
        offer = build_server_response(
            "offer",
            yiaddr="192.168.1.50",
            options=[
                ("server_id", "192.168.1.1"),
                ("subnet_mask", "255.255.255.0"),
                ("router", "192.168.1.254"),
                ("name_server", "8.8.8.8"),
                ("domain", b"corp.local"),
                ("lease_time", 86400),
                ("NTP_server", "192.168.1.10"),
                ("vendor_class_id", b"PXEClient"),
            ],
            bootp_kw=dict(siaddr="192.168.1.2", sname=b"dhcp-srv", file=b"pxelinux.0"),
        )
        p1, p2 = _patch_network()
        with p1, p2, patch.object(dhcpmod, "lookup_mac_vendor", return_value="TestVendor"):
            scanner._process_offer(offer)

        assert "192.168.1.1" in scanner.servers
        device = scanner.servers["192.168.1.1"]
        assert device.mac_address == SERVER_MAC
        assert device.ip_addresses == ["192.168.1.1"]
        assert device.name == "dhcp-srv"
        assert device.manufacturer == "TestVendor"
        data = device.dhcp_data
        assert data["subnet_mask"] == "255.255.255.0"
        assert data["router"] == "192.168.1.254"
        assert data["dns_servers"] == ["8.8.8.8"]
        assert data["domain"] == "corp.local"
        assert data["lease_time"] == 86400
        assert data["ntp_servers"] == ["192.168.1.10"]
        assert data["bootfile"] == "pxelinux.0"
        assert data["next_server"] == "192.168.1.2"
        assert data["server_name"] == "dhcp-srv"
        assert data["vendor_class"] == "PXEClient"
        assert data["is_server"] is True

    def test_offer_with_full_option_set(self):
        # Exercises the large optional-field assembly + NXC logging branches.
        scanner = self._scanner()
        offer = build_server_response(
            "offer",
            yiaddr="192.168.1.50",
            options=[
                ("server_id", "192.168.1.1"),
                ("subnet_mask", "255.255.255.0"),
                ("router", "192.168.1.254"),
                ("name_server", "8.8.8.8"),
                ("domain", b"corp.local"),
                ("lease_time", 86400),
                ("NTP_server", "192.168.1.10"),
                ("NetBIOS_server", "192.168.1.20"),
                ("NetBIOS_node_type", 8),
                ("time_server", "192.168.1.30"),
                ("log_server", "192.168.1.40"),
                ("NIS_domain", b"nis.local"),
                ("NIS_server", "192.168.1.50"),
                ("tftp_server_address", "192.168.1.60"),
                ("broadcast_address", "192.168.1.255"),
                ("renewal_time", 43200),
                ("rebinding_time", 75600),
                ("vendor_class_id", b"PXEClient"),
            ],
            bootp_kw=dict(siaddr="192.168.1.2", sname=b"srv", file=b"pxe.0"),
        )
        p1, p2 = _patch_network()
        with p1, p2, patch.object(dhcpmod, "lookup_mac_vendor", return_value="V"):
            scanner._process_offer(offer)

        data = scanner.servers["192.168.1.1"].dhcp_data
        assert data["ntp_servers"] == ["192.168.1.10"]
        assert data["wins_servers"] == ["192.168.1.20"]
        assert data["netbios_node_type"] == 8
        assert data["time_servers"] == ["192.168.1.30"]
        assert data["log_servers"] == ["192.168.1.40"]
        assert data["nis_domain"] == "nis.local"
        assert data["nis_servers"] == ["192.168.1.50"]
        assert data["tftp_server"] == "192.168.1.60"
        assert data["broadcast_address"] == "192.168.1.255"
        assert data["renewal_time"] == 43200
        assert data["rebinding_time"] == 75600
        assert data["vendor_class"] == "PXEClient"
        # The NXC logger received the per-field success lines.
        assert scanner.nxc_logger.success.call_count >= 5

    def test_offer_without_server_id_uses_ip_source(self):
        scanner = self._scanner()
        offer = build_server_response(
            "offer", yiaddr="192.168.1.51", options=[("subnet_mask", "255.255.255.0")]
        )
        p1, p2 = _patch_network()
        with p1, p2, patch.object(dhcpmod, "lookup_mac_vendor", return_value="Unknown"):
            scanner._process_offer(offer)
        # IP source from builder is 192.168.1.1
        assert "192.168.1.1" in scanner.servers

    def test_offer_with_zero_server_ip_skipped(self):
        scanner = self._scanner()
        # server_id 0.0.0.0 and IP src forced to 0.0.0.0 -> nothing recorded.
        pkt = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(chaddr=CLIENT_MAC_BYTES, yiaddr="0.0.0.0", op=2)
            / DHCP(options=[("message-type", "offer"), ("server_id", "0.0.0.0"), "end"])
        )
        pkt = Ether(bytes(pkt))
        p1, p2 = _patch_network()
        with p1, p2:
            scanner._process_offer(pkt)
        assert scanner.servers == {}

    def test_duplicate_offer_does_not_overwrite(self):
        scanner = self._scanner()
        offer = build_server_response(
            "offer", options=[("server_id", "192.168.1.1"), ("subnet_mask", "255.255.255.0")]
        )
        p1, p2 = _patch_network()
        with p1, p2, patch.object(dhcpmod, "lookup_mac_vendor", return_value="V1"):
            scanner._process_offer(offer)
            first = scanner.servers["192.168.1.1"]
        with p1, p2, patch.object(dhcpmod, "lookup_mac_vendor", return_value="V2"):
            scanner._process_offer(offer)
        # Same object retained (no overwrite on duplicate server IP).
        assert scanner.servers["192.168.1.1"] is first
        assert len(scanner.servers) == 1

    def test_optional_fields_omitted_when_absent(self):
        scanner = self._scanner()
        offer = build_server_response(
            "offer", options=[("server_id", "192.168.1.1"), ("subnet_mask", "255.255.255.0")]
        )
        p1, p2 = _patch_network()
        with p1, p2, patch.object(dhcpmod, "lookup_mac_vendor", return_value="Unknown"):
            scanner._process_offer(offer)
        data = scanner.servers["192.168.1.1"].dhcp_data
        # No NTP / domain / bootfile supplied -> those keys must not be present.
        assert "ntp_servers" not in data
        assert "domain" not in data
        assert "bootfile" not in data
        assert "vendor_class" not in data


# ---------------------------------------------------------------------------
# DHCPServerScanner: small normalization helpers
# ---------------------------------------------------------------------------


class TestDHCPServerScannerHelpers:
    def _scanner(self):
        return DHCPServerScanner("eth0")

    def test_normalize_ip_list(self):
        s = self._scanner()
        assert s._normalize_ip_list(["1.1.1.1", "2.2.2.2"]) == ["1.1.1.1", "2.2.2.2"]
        assert s._normalize_ip_list("9.9.9.9") == ["9.9.9.9"]
        assert s._normalize_ip_list([]) == []
        assert s._normalize_ip_list(None) == []

    def test_get_first_ip(self):
        s = self._scanner()
        assert s._get_first_ip(["a", "b"]) == "a"
        assert s._get_first_ip("solo") == "solo"
        assert s._get_first_ip([]) == ""
        assert s._get_first_ip(None) == ""

    def test_decode_string(self):
        s = self._scanner()
        assert s._decode_string(b"hello\x00") == "hello"
        assert s._decode_string("plain") == "plain"
        assert s._decode_string(b"") == ""
        assert s._decode_string(None) == ""

    def test_parse_options_stops_at_end(self):
        s = self._scanner()
        parsed = s._parse_dhcp_options([("a", 1), "end", ("b", 2)])
        assert parsed == {"a": 1}
