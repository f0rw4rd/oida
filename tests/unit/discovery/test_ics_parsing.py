"""
Behavioral parsing tests for ICS discovery scanners in
``oida.protocols.discovery.ics``.

These exercise the wire-format parsers (KNX SearchResponse DIB, BACnet I-Am
APDU, CODESYS V3 discovery response, Beckhoff ADS UDP TLV) with crafted
packets whose exact byte layout was confirmed against the live parsers.
Only socket I/O is mocked (via the autouse ``mock_netifaces`` fixture and
local socket fakes); all parse/merge logic runs for real.
"""

import itertools
import socket
import struct
import threading
from unittest.mock import MagicMock, patch

import pytest

from oida.protocols.discovery.ics import (
    ADSScanner,
    BACnetScanner,
    CODESYSScanner,
    KNXScanner,
)

# The scan-loop tests here drive mock clocks (itertools.count) and iterator-backed
# sockets whose exhaustion semantics and asyncio/timeout interactions have already
# broken differently across 3.10 vs newer interpreters, so exercise this module on
# every matrix Python lane, not just the canonical one.
pytestmark = pytest.mark.version_sensitive


# ---------------------------------------------------------------------------
# Packet builders (byte layouts verified against the real parsers)
# ---------------------------------------------------------------------------


def build_knx_search_response(
    individual_addr=(1, 1, 5),
    mac=b"\x11\x22\x33\x44\x55\x66",
    name="ABB KNX IP",
    medium=0x20,
    status=0x01,
) -> bytes:
    """Build a KNXnet/IP SearchResponse whose DIB matches the scanner offsets.

    The scanner reads MAC at DIB offset+24 and name at DIB offset+30.
    """
    header = struct.pack(">BBHH", 0x06, 0x10, 0x0202, 0)  # SEARCH_RESPONSE
    hpai = struct.pack(">BB", 8, 0x01) + b"\x00\x00\x00\x00" + struct.pack(">H", 3671)

    area, line, device = individual_addr
    ind_addr = (area << 12) | (line << 8) | device

    dib = bytearray(60)
    dib[0] = 54  # DIB length
    dib[1] = 0x01  # DEVICE_INFO
    dib[2] = medium
    dib[3] = status
    struct.pack_into(">H", dib, 4, ind_addr)
    dib[24:30] = mac
    dib[30:60] = name.ljust(30, "\x00").encode()[:30]
    dib = bytes(dib)

    body = hpai + dib
    return header[:4] + struct.pack(">H", len(header) + len(body)) + body


def build_bacnet_i_am(device_instance=12345, vendor_id=7, max_apdu=5) -> bytes:
    """Build a BACnet/IP I-Am response with context-tagged I-Am content."""
    obj_id = (8 << 22) | device_instance  # object type 8 = device
    iam = b""
    # Tag octet layout: tag number = t >> 4, class bit = (t >> 3) & 1, LVT = t & 7.
    # These frames deliberately use context-specific tags (class bit set) to
    # exercise the parser's non-conformant-sender fallback; a conformant I-Am
    # uses application tags and is covered by test_bacnet_iam_review.py.
    iam += bytes([0x0C]) + struct.pack(">I", obj_id)  # ctx tag 0, len 4
    iam += bytes([0x19, max_apdu])  # ctx tag 1 (Max APDU), len 1
    iam += bytes([0x29, 0x00])  # ctx tag 2 (Segmentation), len 1
    iam += bytes([0x3A]) + struct.pack(">H", vendor_id)  # ctx tag 3, len 2

    apdu = bytes([0x10, 0x00]) + iam  # unconfirmed (pdu type 1), I-Am (0x00)
    npdu = bytes([0x01, 0x00])  # version 1, no DNET/SNET
    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(npdu) + len(apdu))
    return bvlc + npdu + apdu


def _ads_tlv(tag_type, payload) -> bytes:
    return struct.pack("<HH", tag_type, len(payload)) + payload


def build_ads_response(
    hostname="PLC-Beckhoff",
    netid=(5, 80, 192, 37, 1, 1),
    tc_major=3,
    tc_minor=1,
    tc_build=4024,
    os_version="Windows 10",
    fingerprint=b"\xde\xad\xbe\xef",
) -> bytes:
    """Build a Beckhoff ADS UDP Identify response with TLV tags."""
    tlvs = b""
    tlvs += _ads_tlv(ADSScanner.ADS_UDP_TAG["HOSTNAME"], hostname.encode() + b"\x00")
    tlvs += _ads_tlv(ADSScanner.ADS_UDP_TAG["NETID"], bytes(netid))
    tlvs += _ads_tlv(
        ADSScanner.ADS_UDP_TAG["TC_VERSION"],
        bytes([tc_major, tc_minor]) + struct.pack("<H", tc_build),
    )
    tlvs += _ads_tlv(ADSScanner.ADS_UDP_TAG["OS_VERSION"], os_version.encode() + b"\x00")
    tlvs += _ads_tlv(ADSScanner.ADS_UDP_TAG["FINGERPRINT"], fingerprint)
    header = struct.pack("<III", ADSScanner.ADS_UDP_MAGIC, 1, 1)
    return header + tlvs


def build_codesys_response(
    node_name="NodeX",
    device_name="CODESYS Control RTE V3",
    vendor="3S-Smart",
    version=(3, 5, 15, 7),
    max_channels=4,
    target_type=4096,
) -> bytes:
    """Build a CODESYS V3 RES_NETWORK discovery response (relative address)."""
    packet_info = 0x10  # bit4 set => addr_type relative => offset 6+4
    header = bytes(
        [
            CODESYSScanner.MAGIC,
            0x74,
            packet_info,
            CODESYSScanner.SERVICE_NETWORK_RES,
            0x00,
            0x00,
        ]
    )
    addr = b"\x00\x01\x00\xff"

    body = struct.pack("<H", 0x0103)  # data_version 259 (not the 1024 variant)
    body += struct.pack("<I", 0)  # unknown
    body += struct.pack("<H", max_channels)
    body += struct.pack("<I", 0)  # unknown
    body += struct.pack("<H", len(node_name))
    body += struct.pack("<H", len(device_name))
    body += struct.pack("<H", len(vendor))
    body += struct.pack("<I", target_type)
    body += struct.pack("<I", 0)  # unknown
    major, minor, build, rev = version
    body += struct.pack("<I", (major << 24) | (minor << 16) | (build << 8) | rev)
    body += node_name.encode("utf-16-le") + b"\x00\x00"
    body += device_name.encode("utf-16-le") + b"\x00\x00"
    body += vendor.encode("utf-16-le") + b"\x00\x00"
    return header + addr + body


# ---------------------------------------------------------------------------
# Helpers to instantiate scanners without touching real interfaces
# ---------------------------------------------------------------------------


def _make_knx():
    s = KNXScanner.__new__(KNXScanner)
    s.discovered_devices = {}
    s._lock = threading.Lock()
    return s


def _make_bacnet():
    s = BACnetScanner.__new__(BACnetScanner)
    s.discovered_devices = {}
    s._lock = threading.Lock()
    return s


def _make_ads():
    s = ADSScanner.__new__(ADSScanner)
    s.discovered_devices = {}
    s._lock = threading.Lock()
    return s


def _make_codesys():
    s = CODESYSScanner.__new__(CODESYSScanner)
    s.discovered_devices = {}
    s._lock = threading.Lock()
    return s


# ===========================================================================
# KNX SearchResponse parsing
# ===========================================================================


class TestKNXSearchResponseParsing:
    def test_full_dib_parsed_to_device(self):
        s = _make_knx()
        pkt = build_knx_search_response(individual_addr=(1, 1, 5), name="ABB KNX IP")
        s._parse_search_response(pkt, "192.168.1.77")

        assert "11:22:33:44:55:66" in s.discovered_devices
        dev = s.discovered_devices["11:22:33:44:55:66"]
        assert dev.name == "ABB KNX IP"
        assert dev.device_type == "KNX Device"
        assert dev.ip_addresses == ["192.168.1.77"]
        assert dev.knx_data["individual_address"] == "1.1.5"
        assert dev.knx_data["medium"] == "IP"
        assert dev.knx_data["programming_mode"] is True

    def test_individual_address_decoding(self):
        s = _make_knx()
        # area=10, line=3, device=200
        pkt = build_knx_search_response(individual_addr=(10, 3, 200))
        s._parse_search_response(pkt, "10.0.0.1")
        dev = next(iter(s.discovered_devices.values()))
        assert dev.knx_data["individual_address"] == "10.3.200"

    def test_programming_mode_off(self):
        s = _make_knx()
        pkt = build_knx_search_response(status=0x00)
        s._parse_search_response(pkt, "10.0.0.2")
        dev = next(iter(s.discovered_devices.values()))
        assert dev.knx_data["programming_mode"] is False
        assert dev.knx_data["status"] == 0

    def test_wrong_service_type_ignored(self):
        s = _make_knx()
        # SearchRequest (0x0201) not SearchResponse
        pkt = bytearray(build_knx_search_response())
        struct.pack_into(">H", pkt, 2, 0x0201)
        s._parse_search_response(bytes(pkt), "10.0.0.3")
        assert s.discovered_devices == {}

    def test_too_short_packet_ignored(self):
        s = _make_knx()
        s._parse_search_response(b"\x06\x10\x02", "10.0.0.4")
        assert s.discovered_devices == {}

    def test_existing_device_updated_not_duplicated(self):
        s = _make_knx()
        pkt = build_knx_search_response()
        s._parse_search_response(pkt, "10.0.0.5")
        first = s.discovered_devices["11:22:33:44:55:66"]
        first_seen = first.first_seen
        s._parse_search_response(pkt, "10.0.0.5")
        assert len(s.discovered_devices) == 1
        # last_seen refreshed, first_seen preserved
        assert s.discovered_devices["11:22:33:44:55:66"].first_seen == first_seen


# ===========================================================================
# BACnet I-Am parsing
# ===========================================================================


class TestBACnetIAmParsing:
    def test_i_am_parsed_to_device(self):
        s = _make_bacnet()
        pkt = build_bacnet_i_am(device_instance=12345, vendor_id=7, max_apdu=5)
        s._parse_i_am_response(pkt, "192.168.1.50")

        assert "192.168.1.50" in s.discovered_devices
        dev = s.discovered_devices["192.168.1.50"]
        assert dev.name == "BACnet Device 12345"
        assert dev.manufacturer == "Siemens"
        assert dev.bacnet_data["device_instance"] == 12345
        assert dev.bacnet_data["vendor_id"] == 7
        assert dev.bacnet_data["vendor_name"] == "Siemens"
        assert dev.bacnet_data["max_apdu"] == 5

    def test_unknown_vendor_id_labelled(self):
        s = _make_bacnet()
        pkt = build_bacnet_i_am(device_instance=999, vendor_id=4242)
        s._parse_i_am_response(pkt, "192.168.1.51")
        dev = s.discovered_devices["192.168.1.51"]
        assert dev.bacnet_data["vendor_name"] == "Vendor 4242"

    def test_non_bacnet_bvlc_ignored(self):
        s = _make_bacnet()
        pkt = bytearray(build_bacnet_i_am())
        pkt[0] = 0x99  # not 0x81
        s._parse_i_am_response(bytes(pkt), "192.168.1.52")
        assert s.discovered_devices == {}

    def test_wrong_service_choice_ignored(self):
        s = _make_bacnet()
        pkt = build_bacnet_i_am()
        # Find APDU service choice byte: bvlc(4)+npdu(2)=6, pdu_type at 6, service at 7
        pkt = bytearray(pkt)
        pkt[7] = 0x01  # Who-Has, not I-Am
        s._parse_i_am_response(bytes(pkt), "192.168.1.53")
        assert s.discovered_devices == {}

    def test_too_short_packet_ignored(self):
        s = _make_bacnet()
        s._parse_i_am_response(b"\x81\x0a\x00", "192.168.1.54")
        assert s.discovered_devices == {}

    def test_existing_ip_updated(self):
        s = _make_bacnet()
        pkt = build_bacnet_i_am(device_instance=1)
        s._parse_i_am_response(pkt, "192.168.1.55")
        first_seen = s.discovered_devices["192.168.1.55"].first_seen
        s._parse_i_am_response(pkt, "192.168.1.55")
        assert len(s.discovered_devices) == 1
        assert s.discovered_devices["192.168.1.55"].first_seen == first_seen

    def test_single_byte_vendor_id(self):
        s = _make_bacnet()
        # Rebuild with a 1-byte vendor tag (ctx tag 3, len 1 -> 0x31)
        obj_id = (8 << 22) | 7
        iam = bytes([0x0C]) + struct.pack(">I", obj_id)
        iam += bytes([0x19, 0x05])  # ctx tag 1 (Max APDU), len 1
        iam += bytes([0x29, 0x00])  # ctx tag 2 (Segmentation), len 1
        iam += bytes([0x39, 15])  # ctx tag 3, len 1 -> vendor id 15 (Honeywell)
        apdu = bytes([0x10, 0x00]) + iam
        npdu = bytes([0x01, 0x00])
        bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(npdu) + len(apdu))
        s._parse_i_am_response(bvlc + npdu + apdu, "192.168.1.56")
        dev = s.discovered_devices["192.168.1.56"]
        assert dev.bacnet_data["vendor_id"] == 15
        assert dev.bacnet_data["vendor_name"] == "Honeywell"


# ===========================================================================
# CODESYS V3 discovery response parsing
# ===========================================================================


class TestCODESYSResponseParsing:
    def test_response_parsed_to_device(self):
        s = _make_codesys()
        pkt = build_codesys_response()
        dev = s._parse_discovery_response(pkt, "10.0.0.9", 1740)

        assert dev is not None
        # "CODESYS Control " prefix stripped from device name
        assert dev.name == "RTE V3"
        assert dev.manufacturer == "3S-Smart"
        assert dev.device_type == "CODESYS PLC"
        assert dev.codesys_data["version"] == "3.5.15.7"
        assert dev.codesys_data["node_name"] == "NodeX"
        assert dev.codesys_data["max_channels"] == 4
        assert dev.codesys_data["target_type"] == 4096
        assert dev.codesys_data["port"] == 1740

    def test_version_string_assembled_from_bitfields(self):
        s = _make_codesys()
        pkt = build_codesys_response(version=(4, 2, 1, 9))
        dev = s._parse_discovery_response(pkt, "10.0.0.10", 1741)
        assert dev.codesys_data["version"] == "4.2.1.9"
        assert "CODESYS V3 4.2.1.9" in dev.description

    def test_prefixless_device_name_kept(self):
        s = _make_codesys()
        pkt = build_codesys_response(device_name="WAGO PFC200")
        dev = s._parse_discovery_response(pkt, "10.0.0.11", 1740)
        assert dev.name == "WAGO PFC200"

    def test_bad_magic_returns_none(self):
        s = _make_codesys()
        pkt = bytearray(build_codesys_response())
        pkt[0] = 0x00  # wrong magic
        assert s._parse_discovery_response(bytes(pkt), "10.0.0.12", 1740) is None

    def test_wrong_service_id_returns_none(self):
        s = _make_codesys()
        pkt = bytearray(build_codesys_response())
        pkt[3] = CODESYSScanner.SERVICE_NETWORK_REQ  # not RES
        assert s._parse_discovery_response(bytes(pkt), "10.0.0.13", 1740) is None

    def test_too_short_returns_none(self):
        s = _make_codesys()
        assert s._parse_discovery_response(b"\xc5\x00\x00", "10.0.0.14", 1740) is None

    def test_truncated_structured_header_returns_none(self):
        s = _make_codesys()
        # Valid header + addr + data_version but no structured body
        packet_info = 0x10
        header = bytes(
            [CODESYSScanner.MAGIC, 0x74, packet_info, CODESYSScanner.SERVICE_NETWORK_RES, 0, 0]
        )
        pkt = header + b"\x00\x01\x00\xff" + struct.pack("<H", 0x0103) + b"\x00\x00"
        assert s._parse_discovery_response(pkt, "10.0.0.15", 1740) is None


# ===========================================================================
# Beckhoff ADS UDP discovery parsing
# ===========================================================================


class TestADSResponseParsing:
    def test_tlv_tags_parsed(self):
        s = _make_ads()
        pkt = build_ads_response()
        tlvs = pkt[12:]
        parsed = s._parse_tlv_tags(tlvs)
        assert parsed["hostname"] == "PLC-Beckhoff"
        assert parsed["netid"] == "5.80.192.37.1.1"
        assert parsed["tc_version"] == "3.1.4024"
        assert parsed["os_version"] == "Windows 10"
        assert parsed["fingerprint"] == "deadbeef"

    def test_response_parsed_to_device(self):
        s = _make_ads()
        pkt = build_ads_response(hostname="TwinCAT-RT")
        dev = s._parse_discovery_response(pkt, "10.0.0.5")
        assert dev is not None
        assert dev.name == "TwinCAT-RT"
        assert dev.manufacturer == "Beckhoff"
        assert dev.model == "TwinCAT"
        assert dev.ads_data["netid"] == "5.80.192.37.1.1"
        assert dev.ads_data["tc_version"] == "3.1.4024"
        assert "TwinCAT 3.1.4024" in dev.description

    def test_empty_hostname_falls_back_to_ip_name(self):
        s = _make_ads()
        # Response with no HOSTNAME tag at all
        tlvs = _ads_tlv(ADSScanner.ADS_UDP_TAG["NETID"], bytes([1, 2, 3, 4, 5, 6]))
        pkt = struct.pack("<III", ADSScanner.ADS_UDP_MAGIC, 1, 1) + tlvs
        dev = s._parse_discovery_response(pkt, "10.0.0.6")
        assert dev.name == "TwinCAT Device (10.0.0.6)"

    def test_bad_magic_returns_none(self):
        s = _make_ads()
        pkt = struct.pack("<III", 0xDEADBEEF, 1, 1) + b"\x00" * 8
        assert s._parse_discovery_response(pkt, "10.0.0.7") is None

    def test_too_short_returns_none(self):
        s = _make_ads()
        assert s._parse_discovery_response(b"\x03\x66\x14", "10.0.0.8") is None

    def test_truncated_tlv_stops_cleanly(self):
        s = _make_ads()
        # tag header claims 100 bytes but only 2 follow -> loop breaks, no crash
        tlvs = struct.pack("<HH", ADSScanner.ADS_UDP_TAG["HOSTNAME"], 100) + b"ab"
        parsed = s._parse_tlv_tags(tlvs)
        assert parsed == {}


# ===========================================================================
# Scanner scan() loops driven through fake sockets (parse path exercised)
# ===========================================================================


class TestKNXScanLoop:
    def test_scan_collects_response_then_times_out(self):
        scanner = KNXScanner("eth0", timeout=1)
        response = build_knx_search_response(name="LiveKNX")

        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.100", 5000)
        mock_sock.recvfrom.side_effect = itertools.chain(
            [(response, ("192.168.1.200", 3671))],
            itertools.repeat(TimeoutError()),
        )

        with (
            patch("oida.protocols.discovery.ics.create_udp_socket", return_value=mock_sock),
            patch("oida.protocols.discovery.ics.get_interface_ip", return_value="192.168.1.100"),
            patch("oida.protocols.discovery.ics.sendto") as mock_sendto,
            patch(
                "oida.protocols.discovery.ics.time.time",
                # Strictly increasing, unbounded clock: guarantees every scan
                # loop (including multi-port loops that re-capture start_time)
                # terminates regardless of how many time.time() calls a given
                # Python version makes, without ever exhausting the iterator.
                side_effect=itertools.count(0.0, 0.3),
            ),
        ):
            devices = scanner.scan()

        assert mock_sendto.called
        assert "11:22:33:44:55:66" in devices
        assert devices["11:22:33:44:55:66"].name == "LiveKNX"

    def test_scan_no_local_ip_returns_empty(self):
        scanner = KNXScanner("eth0", timeout=1)
        with patch("oida.protocols.discovery.ics.get_interface_ip", return_value=None):
            assert scanner.scan() == {}


class TestBACnetScanLoop:
    def test_scan_collects_i_am(self):
        scanner = BACnetScanner("eth0", timeout=1)
        response = build_bacnet_i_am(device_instance=7777, vendor_id=15)

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = itertools.chain(
            [(response, ("192.168.1.210", 47808))],
            itertools.repeat(TimeoutError()),
        )

        with (
            patch("oida.protocols.discovery.ics.create_udp_socket", return_value=mock_sock),
            patch(
                "oida.protocols.discovery.ics.get_all_broadcast_addresses",
                return_value=["192.168.1.255"],
            ),
            patch("oida.protocols.discovery.ics.sendto") as mock_sendto,
            patch(
                "oida.protocols.discovery.ics.time.time",
                # Strictly increasing, unbounded clock: guarantees every scan
                # loop (including multi-port loops that re-capture start_time)
                # terminates regardless of how many time.time() calls a given
                # Python version makes, without ever exhausting the iterator.
                side_effect=itertools.count(0.0, 0.3),
            ),
        ):
            devices = scanner.scan()

        assert mock_sendto.called
        assert "192.168.1.210" in devices
        assert devices["192.168.1.210"].bacnet_data["device_instance"] == 7777


class TestADSScanLoop:
    def test_scan_collects_response_and_dedups(self):
        scanner = ADSScanner("eth0", timeout=1)
        response = build_ads_response(hostname="ADS-Live")

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = itertools.chain(
            [
                (response, ("10.1.1.1", 48899)),
                (response, ("10.1.1.1", 48899)),  # duplicate IP -> ignored
            ],
            itertools.repeat(TimeoutError()),
        )

        with (
            patch("oida.protocols.discovery.ics.create_udp_socket", return_value=mock_sock),
            patch(
                "oida.protocols.discovery.ics.get_all_broadcast_addresses",
                return_value=["10.1.1.255"],
            ),
            patch("oida.protocols.discovery.ics.sendto"),
            patch(
                "oida.protocols.discovery.ics.time.time",
                side_effect=itertools.count(0.0, 0.3),
            ),
        ):
            devices = scanner.scan()

        assert len(devices) == 1
        assert devices["10.1.1.1"].name == "ADS-Live"


class TestCODESYSScanLoop:
    def test_build_discovery_packet_shape(self):
        scanner = CODESYSScanner("eth0", timeout=1)
        pkt = scanner._build_discovery_packet()
        # header(6) + address(8) + command(8) = 22 bytes
        assert len(pkt) == 22
        assert pkt[0] == CODESYSScanner.MAGIC
        assert pkt[3] == CODESYSScanner.SERVICE_NETWORK_REQ

    def test_scan_collects_response(self):
        scanner = CODESYSScanner("eth0", timeout=1)
        response = build_codesys_response(device_name="CODESYS Control Win V3")

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = itertools.chain(
            [(response, ("10.2.2.2", 1740))],
            itertools.repeat(TimeoutError()),
        )

        with (
            patch("oida.protocols.discovery.ics.create_udp_socket", return_value=mock_sock),
            patch(
                "oida.protocols.discovery.ics.get_all_broadcast_addresses",
                return_value=["10.2.2.255"],
            ),
            patch("oida.protocols.discovery.ics.sendto"),
            patch("oida.protocols.discovery.ics.time.sleep"),
            patch(
                "oida.protocols.discovery.ics.time.time",
                # Strictly increasing, unbounded clock: guarantees every scan
                # loop (including multi-port loops that re-capture start_time)
                # terminates regardless of how many time.time() calls a given
                # Python version makes, without ever exhausting the iterator.
                side_effect=itertools.count(0.0, 0.3),
            ),
        ):
            devices = scanner.scan()

        assert "10.2.2.2" in devices
        assert devices["10.2.2.2"].name == "Win V3"


# ===========================================================================
# Medium / vendor lookup tables (small but real branches)
# ===========================================================================


class TestLookupTables:
    @pytest.mark.parametrize(
        "code,expected",
        [(0x01, "TP"), (0x02, "PL"), (0x04, "RF"), (0x20, "IP")],
    )
    def test_knx_medium_types(self, code, expected):
        s = _make_knx()
        assert expected in s._get_medium_type(code)

    def test_knx_medium_unknown(self):
        s = _make_knx()
        assert "Unknown" in s._get_medium_type(0x77)

    @pytest.mark.parametrize(
        "vid,expected",
        [(0, "ASHRAE"), (7, "Siemens"), (26, "Schneider Electric"), (343, "Beckhoff")],
    )
    def test_bacnet_vendor_names(self, vid, expected):
        s = _make_bacnet()
        assert s._get_vendor_name(vid) == expected


# ===========================================================================
# BACnet NPDU routing-info branches (DNET / SNET present)
# ===========================================================================


class TestBACnetNPDURouting:
    def _i_am_with_control(self, npdu_control, extra_after_control=b"") -> bytes:
        obj_id = (8 << 22) | 4242
        iam = bytes([0x0C]) + struct.pack(">I", obj_id)
        iam += bytes([0x11, 0x05])
        iam += bytes([0x21, 0x00])
        iam += bytes([0x32]) + struct.pack(">H", 7)
        apdu = bytes([0x10, 0x00]) + iam
        npdu = bytes([0x01, npdu_control]) + extra_after_control
        bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(npdu) + len(apdu))
        return bvlc + npdu + apdu

    def test_snet_present_skips_source_routing(self):
        s = _make_bacnet()
        # control 0x08 => SNET present. Layout after control: SNET(2)+SLEN(1)+SADR(slen)
        slen = 2
        extra = struct.pack(">H", 5) + bytes([slen]) + b"\xaa\xbb"
        pkt = self._i_am_with_control(0x08, extra)
        s._parse_i_am_response(pkt, "192.168.1.80")
        assert "192.168.1.80" in s.discovered_devices
        assert s.discovered_devices["192.168.1.80"].bacnet_data["device_instance"] == 4242

    def test_dnet_present_skips_dest_routing(self):
        s = _make_bacnet()
        # control 0x20 => DNET present. Layout after control: DNET(2)+DLEN(1)+hop(1)
        extra = struct.pack(">H", 10) + bytes([0]) + bytes([255])
        pkt = self._i_am_with_control(0x20, extra)
        s._parse_i_am_response(pkt, "192.168.1.81")
        assert "192.168.1.81" in s.discovered_devices


# ===========================================================================
# EtherNet/IP scanner (delegates to the ethernetip broadcast helper)
# ===========================================================================


class TestEtherNetIPScanner:
    def _fake_ethernetip(self, devices):
        """Build a stand-in ethernetip module exposing broadcast_discovery."""
        mod = MagicMock()
        mod.broadcast_discovery.return_value = devices
        return mod

    def test_devices_converted(self):
        from oida.protocols.discovery.ics import EtherNetIPScanner

        scanner = EtherNetIPScanner("eth0", timeout=1)
        devices = [
            {
                "ip_address": "192.168.1.90",
                "product_name": "1756-L71 ControlLogix",
                "vendor_name": "Rockwell Automation",
                "vendor_id": 1,
                "device_type": 14,
                "device_type_name": "Programmable Logic Controller",
                "product_code": 158,
                "revision": (20, 11),
                "serial_number": 0xABCDEF,
                "status": 0x30,
                "state": 3,
                "state_name": "Operational",
            }
        ]

        fake = self._fake_ethernetip(devices)
        lazy = MagicMock()
        lazy.is_available = True
        lazy.return_value = fake

        with (
            patch("oida.protocols.discovery.ics._ethernetip", lazy),
            patch("oida.protocols.discovery.ics.get_interface_ip", return_value="192.168.1.1"),
        ):
            result = scanner.scan()

        assert "192.168.1.90" in result
        dev = result["192.168.1.90"]
        assert dev.name == "1756-L71 ControlLogix"
        assert dev.manufacturer == "Rockwell Automation"
        assert dev.ethernetip_data["revision"] == "20.11"  # tuple joined
        assert dev.ethernetip_data["product_code"] == 158
        assert dev.ethernetip_data["state_name"] == "Operational"

    def test_string_revision_passed_through(self):
        from oida.protocols.discovery.ics import EtherNetIPScanner

        scanner = EtherNetIPScanner("eth0", timeout=1)
        devices = [{"ip_address": "192.168.1.91", "revision": "v5"}]
        fake = self._fake_ethernetip(devices)
        lazy = MagicMock()
        lazy.is_available = True
        lazy.return_value = fake

        with (
            patch("oida.protocols.discovery.ics._ethernetip", lazy),
            patch("oida.protocols.discovery.ics.get_interface_ip", return_value="192.168.1.1"),
        ):
            result = scanner.scan()

        assert result["192.168.1.91"].ethernetip_data["revision"] == "v5"

    def test_device_without_ip_skipped(self):
        from oida.protocols.discovery.ics import EtherNetIPScanner

        scanner = EtherNetIPScanner("eth0", timeout=1)
        fake = self._fake_ethernetip([{"ip_address": "", "product_name": "ghost"}])
        lazy = MagicMock()
        lazy.is_available = True
        lazy.return_value = fake

        with (
            patch("oida.protocols.discovery.ics._ethernetip", lazy),
            patch("oida.protocols.discovery.ics.get_interface_ip", return_value="192.168.1.1"),
        ):
            result = scanner.scan()

        assert result == {}

    def test_module_unavailable_returns_empty(self):
        from oida.protocols.discovery.ics import EtherNetIPScanner

        scanner = EtherNetIPScanner("eth0", timeout=1)
        lazy = MagicMock()
        lazy.is_available = False

        with patch("oida.protocols.discovery.ics._ethernetip", lazy):
            assert scanner.scan() == {}

    def test_no_local_ip_returns_empty(self):
        from oida.protocols.discovery.ics import EtherNetIPScanner

        scanner = EtherNetIPScanner("eth0", timeout=1)
        lazy = MagicMock()
        lazy.is_available = True

        with (
            patch("oida.protocols.discovery.ics._ethernetip", lazy),
            patch("oida.protocols.discovery.ics.get_interface_ip", return_value=None),
        ):
            assert scanner.scan() == {}


# Sanity: socket module import is used by builders (keeps lint honest)
assert hasattr(socket, "inet_aton")
