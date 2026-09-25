"""
Behavioral coverage tests for oida.protocols.discovery.network.

Targets the parse/processing methods that the existing network tests do not
exercise: NetBIOSScanner._parse_nbstat_response (raw NBSTAT bytes),
NetBIOSPassiveListener feed paths (scapy NBNS / datagram frames),
STPPassiveListener._parse_bpdu (scapy BPDU frames), CDP address extraction,
and LLMNR response parsing. Only scapy packet construction is "synthetic" -
the code under test (parsers, dedup, device merge) runs for real.
"""

import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from tests.service_gate import require_import

scapy_all = require_import("scapy.all")


# ---------------------------------------------------------------------------
# NetBIOSScanner._parse_nbstat_response  (manual byte parser)
# ---------------------------------------------------------------------------
def _label(name: str) -> bytes:
    """Encode a single DNS-style label (length prefix + bytes + null terminator)."""
    b = name.encode("ascii")
    return bytes([len(b)]) + b + b"\x00"


def _nbstat_response(names, mac=(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)):
    """Build a NetBIOS Node Status response the manual parser can walk.

    names: list of (name, suffix, flags) tuples.
    """
    header = struct.pack(">HHHHHH", 0x1234, 0x8400, 1, 1, 0, 0)
    question = _label("ENCNAME") + struct.pack(">HH", 0x0021, 0x0001)
    answer = _label("ENCNAME") + struct.pack(">HHIH", 0x0021, 0x0001, 0, 0)

    body = bytes([len(names)])
    for name, suffix, flags in names:
        body += name.encode("ascii").ljust(15, b" ")[:15]
        body += bytes([suffix])
        body += struct.pack(">H", flags)
    body += bytes(mac)
    return header + question + answer + body


class TestNetBIOSParseNbstat:
    @pytest.fixture
    def scanner(self):
        from oida.protocols.discovery.network import NetBIOSScanner

        return NetBIOSScanner(interface="eth0")

    def test_parses_computer_name_workgroup_mac(self, scanner):
        data = _nbstat_response(
            [
                ("TESTPC", 0x00, 0x0400),  # workstation, not group
                ("WORKGROUP", 0x00, 0x8400),  # group flag set
                ("TESTPC", 0x20, 0x0400),  # file server service
            ]
        )
        device = scanner._parse_nbstat_response(data, "10.0.0.5")

        assert device is not None
        assert device.ip_addresses == ["10.0.0.5"]
        assert device.name == "TESTPC"
        assert device.mac_address == "aa:bb:cc:dd:ee:ff"
        assert device.device_type == "Windows/SMB Host"
        nb = device.netbios_data
        assert nb["computer_name"] == "TESTPC"
        assert nb["workgroup"] == "WORKGROUP"
        # File Server (0x20) is tracked as a service
        assert "File Server" in nb["services"]
        # All three name records preserved
        assert len(nb["names"]) == 3

    def test_suffix_descriptions_resolved(self, scanner):
        data = _nbstat_response([("DC01", 0x1C, 0x8400)])  # Domain Controllers
        device = scanner._parse_nbstat_response(data, "10.0.0.6")
        assert device is not None
        names = device.netbios_data["names"]
        assert names[0]["suffix_desc"] == "Domain Controllers"
        assert names[0]["is_group"] is True

    def test_too_short_returns_none(self, scanner):
        assert scanner._parse_nbstat_response(b"\x00" * 10, "10.0.0.5") is None

    def test_malformed_after_header_returns_none(self, scanner):
        # 57+ bytes but structurally garbage -> parser bails gracefully
        assert scanner._parse_nbstat_response(b"\xff" * 80, "10.0.0.5") is None


class TestNetBIOSScannerScanFlow:
    """Exercise NetBIOSScanner.scan() end-to-end with a mocked UDP socket."""

    @pytest.fixture
    def scanner(self):
        from oida.protocols.discovery.network import NetBIOSScanner

        return NetBIOSScanner(interface="eth0", subnet="192.168.1.0/24", timeout=1)

    def test_scan_collects_parsed_device(self, scanner):
        response = _nbstat_response([("SCANPC", 0x00, 0x0400)])

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            # First recvfrom returns a real response, then timeouts end the loop
            mock_sock.recvfrom.side_effect = [
                (response, ("192.168.1.42", 137)),
                socket.timeout(),
                socket.timeout(),
                socket.timeout(),
            ]
            devices = scanner.scan()

        assert mock_sock.sendto.called
        assert "192.168.1.42" in devices
        assert devices["192.168.1.42"].name == "SCANPC"

    def test_scan_dedups_same_ip(self, scanner):
        response = _nbstat_response([("DUPPC", 0x00, 0x0400)])

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (response, ("192.168.1.50", 137)),
                (response, ("192.168.1.50", 137)),  # same IP -> skipped (seen_ips)
                socket.timeout(),
                socket.timeout(),
            ]
            devices = scanner.scan()

        assert list(devices.keys()) == ["192.168.1.50"]


# ---------------------------------------------------------------------------
# NetBIOSPassiveListener  (scapy native layers)
# ---------------------------------------------------------------------------
class TestNetBIOSPassiveListener:
    @pytest.fixture
    def listener(self):
        from oida.protocols.discovery.network import NetBIOSPassiveListener

        return NetBIOSPassiveListener(interface="eth0")

    def _node_status_packet(self, src_ip="10.0.0.7", mac="11:22:33:44:55:66"):
        from scapy.all import Ether, IP, UDP
        from scapy.layers.netbios import (
            NBNSHeader,
            NBNSNodeStatusResponse,
            NBNSNodeStatusResponseService,
        )

        svc1 = NBNSNodeStatusResponseService(
            NETBIOS_NAME=b"PASSIVEPC".ljust(15), SUFFIX=0x00, NAME_FLAGS=0x04
        )
        svc2 = NBNSNodeStatusResponseService(
            NETBIOS_NAME=b"FILESRV".ljust(15), SUFFIX=0x20, NAME_FLAGS=0x04
        )
        resp = NBNSNodeStatusResponse(
            RR_NAME=b"*".ljust(15),
            NUM_NAMES=2,
            NODE_NAME=[svc1, svc2],
            MAC_ADDRESS=mac,
        )
        pkt = (
            Ether(src=mac)
            / IP(src=src_ip, dst="10.0.0.255")
            / UDP(sport=137, dport=137)
            / NBNSHeader(OPCODE=0)
            / resp
        )
        return Ether(bytes(pkt))

    def test_node_status_response_creates_device(self, listener):
        listener.feed_packet(self._node_status_packet())
        assert len(listener.discovered_devices) == 1
        device = next(iter(listener.discovered_devices.values()))
        assert device.name == "PASSIVEPC"
        assert device.mac_address == "11:22:33:44:55:66"
        names = [n["name"] for n in device.netbios_data["names"]]
        assert "PASSIVEPC" in names and "FILESRV" in names
        assert "netbios-passive" in device.discovered_by

    def test_node_status_dedup_updates_last_seen(self, listener):
        pkt = self._node_status_packet()
        listener.feed_packet(pkt)
        first_seen = next(iter(listener.discovered_devices.values())).first_seen
        listener.feed_packet(self._node_status_packet())
        # Still one device (keyed by MAC), first_seen unchanged
        assert len(listener.discovered_devices) == 1
        device = next(iter(listener.discovered_devices.values()))
        assert device.first_seen == first_seen

    def test_registration_request(self, listener):
        from scapy.all import Ether, IP, UDP
        from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest

        reg = NBNSRegistrationRequest(
            QUESTION_NAME=b"REGHOST".ljust(15), SUFFIX=0x00, NB_ADDRESS="10.0.0.8"
        )
        pkt = (
            Ether(src="aa:00:00:00:00:01")
            / IP(src="10.0.0.8", dst="10.0.0.255")
            / UDP(sport=137, dport=137)
            / NBNSHeader(OPCODE=5, NM_FLAGS=0x10)
            / reg
        )
        listener.feed_packet(Ether(bytes(pkt)))
        devices = list(listener.discovered_devices.values())
        assert len(devices) == 1
        assert devices[0].name == "REGHOST"
        assert devices[0].netbios_data.get("registration") is True

    def test_datagram_service_port_138(self, listener):
        from scapy.all import Ether, IP, UDP
        from scapy.layers.netbios import NBTDatagram

        dgm = NBTDatagram(SourceName=b"DGMHOST".ljust(15), SUFFIX1=0x00)
        pkt = (
            Ether(src="aa:00:00:00:00:02")
            / IP(src="10.0.0.9", dst="10.0.0.255")
            / UDP(sport=138, dport=138)
            / dgm
        )
        listener.feed_packet(Ether(bytes(pkt)))
        devices = list(listener.discovered_devices.values())
        assert len(devices) == 1
        assert devices[0].name == "DGMHOST"

    def test_query_response(self, listener):
        from scapy.all import Ether, IP, UDP
        from scapy.layers.netbios import NBNSHeader, NBNSQueryResponse

        resp = NBNSQueryResponse(RR_NAME=b"QRHOST".ljust(15), SUFFIX=0x00)
        pkt = (
            Ether(src="cc:00:00:00:00:01")
            / IP(src="10.0.0.20", dst="10.0.0.21")
            / UDP(sport=137, dport=137)
            / NBNSHeader(OPCODE=0, NM_FLAGS=0)
            / resp
        )
        # Feed the constructed packet directly; a bytes() round-trip can make
        # scapy mis-dissect the answer record as a bare NBNSHeader.
        listener.feed_packet(pkt)
        devices = list(listener.discovered_devices.values())
        assert len(devices) == 1
        assert devices[0].name == "QRHOST"

    def test_non_netbios_packet_ignored(self, listener):
        from scapy.all import Ether, IP, UDP

        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=53)
        listener.feed_packet(pkt)
        assert listener.discovered_devices == {}

    def test_packet_without_ip_ignored(self, listener):
        from scapy.all import Ether

        listener.feed_packet(Ether())
        assert listener.discovered_devices == {}

    def test_decode_scapy_suffix(self, listener):
        # Encoded form: 0x00 -> 'AA' (0x4141), 0x20 -> 'CA' (0x4341)
        assert listener._decode_scapy_suffix(0x4141) == 0x00
        assert listener._decode_scapy_suffix(0x4341) == 0x20
        # Already-decoded single byte passes through
        assert listener._decode_scapy_suffix(0x20) == 0x20
        # Non-int -> 0x00
        assert listener._decode_scapy_suffix(None) == 0x00


# ---------------------------------------------------------------------------
# STPPassiveListener._parse_bpdu  (scapy STP frames)
# ---------------------------------------------------------------------------
class TestSTPParseBpdu:
    @pytest.fixture
    def listener(self):
        from oida.protocols.discovery.network import STPPassiveListener

        return STPPassiveListener(interface="eth0")

    def _bpdu(self, version=2, bpdutype=2, bridgemac="00:aa:bb:cc:dd:ee", rootmac=None, flags=0x0C):
        from scapy.all import LLC, STP, Dot3

        rootmac = rootmac or bridgemac
        return (
            Dot3(src=bridgemac, dst="01:80:c2:00:00:00")
            / LLC(dsap=0x42, ssap=0x42, ctrl=3)
            / STP(
                version=version,
                bpdutype=bpdutype,
                bpduflags=flags,
                rootid=4096,
                rootmac=rootmac,
                bridgeid=8192,
                bridgemac=bridgemac,
                pathcost=10,
                portid=0x8001,
            )
        )

    def test_rstp_config_bpdu_creates_switch(self, listener):
        from scapy.all import Dot3

        pkt = Dot3(bytes(self._bpdu(version=2, bpdutype=2)))
        listener.feed_packet(pkt)
        assert len(listener.discovered_devices) == 1
        device = listener.discovered_devices["00:aa:bb:cc:dd:ee"]
        assert device.device_type == "Network Switch"
        assert device.stp_data["protocol"] == "RSTP (802.1w)"
        assert device.stp_data["bridge_mac"] == "00:aa:bb:cc:dd:ee"
        # rootmac == bridgemac -> this bridge is the root
        assert device.stp_data["is_root_bridge"] is True
        # RSTP exposes a parsed port role from flag bits
        assert device.stp_data["port_role"] is not None
        assert "stp" in device.discovered_by

    def test_legacy_stp_version0(self, listener):
        from scapy.all import Dot3

        pkt = Dot3(bytes(self._bpdu(version=0, bpdutype=0)))
        listener.feed_packet(pkt)
        device = next(iter(listener.discovered_devices.values()))
        assert device.stp_data["protocol"] == "STP (802.1D)"
        # No RSTP port role for legacy STP
        assert device.stp_data["port_role"] is None

    def test_non_root_bridge(self, listener):
        from scapy.all import Dot3

        pkt = Dot3(
            bytes(
                self._bpdu(
                    bridgemac="00:aa:bb:cc:dd:ee",
                    rootmac="00:11:11:11:11:11",
                )
            )
        )
        listener.feed_packet(pkt)
        device = listener.discovered_devices["00:aa:bb:cc:dd:ee"]
        assert device.stp_data["is_root_bridge"] is False
        assert device.stp_data["root_mac"] == "00:11:11:11:11:11"

    def test_dedup_same_bridge(self, listener):
        from scapy.all import Dot3

        listener.feed_packet(Dot3(bytes(self._bpdu())))
        listener.feed_packet(Dot3(bytes(self._bpdu())))
        assert len(listener.discovered_devices) == 1

    def test_non_stp_packet_ignored(self, listener):
        from scapy.all import IP, UDP, Ether

        listener.feed_packet(Ether() / IP() / UDP())
        assert listener.discovered_devices == {}

    def test_should_process_packet_matches_multicast(self, listener):
        from scapy.all import Dot3

        pkt = Dot3(bytes(self._bpdu()))
        assert listener.should_process_packet(pkt) is True


# ---------------------------------------------------------------------------
# CDP address extraction + capability bitmask  (network.py copies)
# ---------------------------------------------------------------------------
class TestCDPAddressExtraction:
    @pytest.fixture
    def listener(self):
        from oida.protocols.discovery.network import CDPPassiveListener

        return CDPPassiveListener(interface="eth0")

    def test_extract_ipv4_from_raw_bytes_record(self, listener):
        # The extractor reads addr_record.addr expecting 4 raw bytes for IPv4
        # and converts via inet_ntoa. Build a record whose .addr is 4 bytes.
        class _Rec:
            addr = bytes([192, 168, 10, 1])

        class _Msg:
            addr = [_Rec()]

        addrs = listener._extract_cdp_addresses(_Msg())
        assert addrs == ["192.168.10.1"]

    def test_extract_skips_non_ipv4_length(self, listener):
        class _Rec:
            addr = bytes([1, 2, 3])  # not 4 bytes -> skipped

        class _Msg:
            addr = [_Rec()]

        assert listener._extract_cdp_addresses(_Msg()) == []

    def test_extract_handles_empty(self, listener):
        from scapy.contrib.cdp import CDPMsgAddr

        msg = CDPMsgAddr(naddr=0, addr=[])
        assert listener._extract_cdp_addresses(msg) == []

    def test_full_cdp_frame_populates_device(self, listener):
        from scapy.all import Ether
        from scapy.contrib.cdp import (
            CDPv2_HDR,
            CDPMsgDeviceID,
            CDPMsgPlatform,
            CDPMsgCapabilities,
        )

        cdp = CDPv2_HDR(vers=2, ttl=180)
        cdp /= CDPMsgDeviceID(val=b"Switch1.example.com")
        cdp /= CDPMsgPlatform(val=b"cisco WS-C2960")
        cdp /= CDPMsgCapabilities(cap=0x08)  # Switch
        pkt = Ether(src="00:de:ad:be:ef:01", dst="01:00:0c:cc:cc:cc") / cdp

        listener.feed_packet(pkt)
        assert "00:de:ad:be:ef:01" in listener.discovered_devices
        device = listener.discovered_devices["00:de:ad:be:ef:01"]
        assert device.manufacturer == "Cisco"
        assert device.name == "Switch1.example.com"
        assert device.model == "cisco WS-C2960"
        assert "Switch" in device.device_type
        assert device.cdp_data["version"] == 2
        assert device.cdp_data["ttl"] == 180


# ---------------------------------------------------------------------------
# LLMNR response parsing
# ---------------------------------------------------------------------------
class TestLLMNRParse:
    @pytest.fixture
    def scanner(self):
        from oida.protocols.discovery.network import LLMNRScanner

        return LLMNRScanner(interface="eth0", timeout=1)

    def test_parse_llmnr_query_creates_device(self, scanner):
        from scapy.layers.dns import DNS, DNSQR

        # An LLMNR query for "WORKSTATION" from 10.0.0.50
        query = DNS(id=0x1234, qr=0, qd=DNSQR(qname="WORKSTATION", qtype="A", qclass="IN"))
        scanner._parse_llmnr_response(bytes(query), "10.0.0.50")

        assert "10.0.0.50" in scanner.discovered_devices
        device = scanner.discovered_devices["10.0.0.50"]
        assert device.name == "WORKSTATION"
        assert device.llmnr_data["name"] == "WORKSTATION"
        assert device.llmnr_data["is_response"] is False
        assert device.llmnr_data["transaction_id"] == 0x1234
        assert "llmnr" in device.discovered_by

    def test_parse_llmnr_response_flag(self, scanner):
        from scapy.layers.dns import DNS, DNSQR

        resp = DNS(id=0x4321, qr=1, qd=DNSQR(qname="SERVER", qtype="A", qclass="IN"))
        scanner._parse_llmnr_response(bytes(resp), "10.0.0.51")
        device = scanner.discovered_devices["10.0.0.51"]
        assert device.llmnr_data["is_response"] is True

    def test_parse_llmnr_updates_existing(self, scanner):
        from scapy.layers.dns import DNS, DNSQR

        q1 = DNS(id=1, qr=0, qd=DNSQR(qname="HOST1", qtype="A", qclass="IN"))
        scanner._parse_llmnr_response(bytes(q1), "10.0.0.60")
        q2 = DNS(id=2, qr=1, qd=DNSQR(qname="HOST1", qtype="A", qclass="IN"))
        scanner._parse_llmnr_response(bytes(q2), "10.0.0.60")
        # Same IP -> single device, llmnr_data updated to the latest
        assert len(scanner.discovered_devices) == 1
        assert scanner.discovered_devices["10.0.0.60"].llmnr_data["is_response"] is True

    def test_too_short_packet_ignored(self, scanner):
        scanner._parse_llmnr_response(b"\x00\x01", "10.0.0.70")
        assert scanner.discovered_devices == {}


class TestLLMNRScanFlow:
    """Drive LLMNRScanner.scan() active + passive paths with mocked sockets."""

    @pytest.fixture
    def scanner(self):
        from oida.protocols.discovery.network import LLMNRScanner

        return LLMNRScanner(interface="eth0", subnet="192.168.1.0/24", timeout=1)

    def test_scan_active_and_passive_collect_device(self, scanner):
        from scapy.layers.dns import DNS, DNSQR
        import oida.protocols.discovery.network as net

        response = bytes(DNS(id=1, qr=1, qd=DNSQR(qname="WPADHOST", qtype="A", qclass="IN")))

        mock_sock = MagicMock()
        # One real response then timeouts (both active + passive loops use recvfrom)
        seq = [(response, ("192.168.1.200", 5355))] + [socket.timeout()] * 200

        def _recvfrom(_n):
            item = seq.pop(0) if seq else socket.timeout()
            if isinstance(item, BaseException):
                raise item
            return item

        mock_sock.recvfrom.side_effect = _recvfrom

        with (
            patch("socket.socket", return_value=mock_sock),
            patch.object(net, "get_interface_ip", return_value="192.168.1.100"),
            patch.object(net, "bind_socket_to_interface", return_value=True),
        ):
            devices = scanner.scan()

        assert mock_sock.sendto.called
        assert "192.168.1.200" in devices
        assert devices["192.168.1.200"].name == "WPADHOST"

    def test_passive_skipped_when_no_iface_ip(self, scanner):
        import oida.protocols.discovery.network as net

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout()
        with (
            patch("socket.socket", return_value=mock_sock),
            patch.object(net, "get_interface_ip", return_value=None),
            patch.object(net, "bind_socket_to_interface", return_value=False),
        ):
            devices = scanner.scan()
        # No crash; passive path bails on missing IP, active still runs
        assert isinstance(devices, dict)
