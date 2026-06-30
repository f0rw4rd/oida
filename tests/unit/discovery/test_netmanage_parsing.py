"""
Behavioral tests for the Schneider Electric NetManage discovery protocol in
``oida.protocols.discovery.netmanage``.

Covers the XOR codec, RFC-1071 checksum, header/data-block (de)serialization,
ResponsePublish field parsing, the active scanner request/response round trip,
and the scapy-based passive listener. Only the raw socket and sniffer I/O are
faked; all protocol parsing runs for real. Packet layouts were validated
against the live decoders.
"""

import struct
import threading
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from oida.protocols.discovery import netmanage as nm
from oida.protocols.discovery.netmanage import (
    NetManageDataBlock,
    NetManageDevice,
    NetManageHeader,
    NetManagePassiveListener,
    NetManageScanner,
)


# ---------------------------------------------------------------------------
# Packet builders (validated against the real decoders)
# ---------------------------------------------------------------------------

_RESPONSE_VALUES = [
    "00:11:22:33:44:55",  # mac_address
    "M580-PLC",  # device_name
    "1",  # ip_mode (1 = DHCP)
    "192.168.10.20",  # ip_address
    "255.255.255.0",  # subnet_mask
    "192.168.10.1",  # gateway
    "PLC-NETBIOS",  # netbios_name
    "Normal",  # boot_mode
    "v2.10",  # firmware_version
    "Modicon M580",  # device_type
    "SN12345",  # serial_number
]


def build_response_publish(values=None, mac="00:11:22:33:44:55", version=1) -> bytes:
    """Build an XOR-encoded ResponsePublish packet with a string data block."""
    values = values if values is not None else _RESPONSE_VALUES
    text = "\n".join(values)
    payload = text.encode("iso-8859-1") + b"\x00"
    block_size = 6 + len(payload)
    block = struct.pack("<ih", block_size, 0) + payload  # format 0 = string

    header = NetManageHeader(
        mac_address=mac,
        command=nm.CMD_RESPONSE_PUBLISH,
        version=version,
        checksum=0,
        size_of_all=nm.HEADER_SIZE + block_size,
    )
    full = bytearray(header.to_bytes()) + block
    cs = nm.calculate_checksum(bytes(full))
    struct.pack_into("<H", full, nm.CHECKSUM_OFFSET, cs)
    return nm.xor_encode_decode(bytes(full))


# ===========================================================================
# XOR codec
# ===========================================================================


class TestXorCodec:
    def test_roundtrip_symmetric(self):
        data = b"the quick brown fox jumps over 13 lazy PLCs" * 3
        assert nm.xor_encode_decode(nm.xor_encode_decode(data)) == data

    def test_empty_input(self):
        assert nm.xor_encode_decode(b"") == b""

    def test_key_applied_modulo_length(self):
        # First byte XORs with key[0]
        out = nm.xor_encode_decode(b"\x00")
        assert out[0] == nm.NETMANAGE_KEY[0]
        # Byte at key-length index wraps to key[0] again
        long = b"\x00" * (nm.NETMANAGE_KEY_LEN + 1)
        out = nm.xor_encode_decode(long)
        assert out[0] == nm.NETMANAGE_KEY[0]
        assert out[nm.NETMANAGE_KEY_LEN] == nm.NETMANAGE_KEY[0]


# ===========================================================================
# Checksum (RFC 1071 Internet checksum)
# ===========================================================================


class TestChecksum:
    def test_calculate_and_verify_roundtrip(self):
        buf = bytearray(40)
        buf[0:5] = b"hello"
        cs = nm.calculate_checksum(bytes(buf))
        struct.pack_into("<H", buf, nm.CHECKSUM_OFFSET, cs)
        assert nm.verify_checksum(bytes(buf)) is True

    def test_checksum_field_zeroed_during_calc(self):
        # Stuffing garbage into the checksum field must not change the result.
        buf = bytearray(40)
        buf[0:4] = b"\x01\x02\x03\x04"
        cs1 = nm.calculate_checksum(bytes(buf))
        struct.pack_into("<H", buf, nm.CHECKSUM_OFFSET, 0xBEEF)
        cs2 = nm.calculate_checksum(bytes(buf))
        assert cs1 == cs2

    def test_verify_fails_on_corruption(self):
        buf = bytearray(40)
        cs = nm.calculate_checksum(bytes(buf))
        struct.pack_into("<H", buf, nm.CHECKSUM_OFFSET, cs)
        buf[0] ^= 0xFF  # corrupt a byte outside checksum field
        assert nm.verify_checksum(bytes(buf)) is False

    def test_verify_too_short_returns_false(self):
        assert nm.verify_checksum(b"\x00" * 4) is False

    def test_odd_length_buffer_handled(self):
        # Odd length triggers the trailing-byte branch.
        buf = bytearray(31)
        buf[30] = 0xAB
        cs = nm.calculate_checksum(bytes(buf))
        assert 0 <= cs <= 0xFFFF


# ===========================================================================
# Header serialization
# ===========================================================================


class TestNetManageHeader:
    def test_to_bytes_then_from_bytes_roundtrip(self):
        h = NetManageHeader(
            mac_address="AA:BB:CC:DD:EE:FF",
            command=nm.CMD_REQUEST_PUBLISH,
            version=2,
            checksum=0x1234,
            size_of_all=64,
        )
        raw = h.to_bytes()
        assert len(raw) == nm.HEADER_SIZE
        parsed = NetManageHeader.from_bytes(raw)
        assert parsed.mac_address == "AA:BB:CC:DD:EE:FF"
        assert parsed.command == nm.CMD_REQUEST_PUBLISH
        assert parsed.version == 2
        assert parsed.checksum == 0x1234
        assert parsed.size_of_all == 64

    def test_command_name_mapping(self):
        for cmd, name in nm.COMMAND_NAMES.items():
            h = NetManageHeader("00:00:00:00:00:00", cmd, 1, 0, nm.HEADER_SIZE)
            assert h.command_name == name

    def test_command_name_unknown(self):
        h = NetManageHeader("00:00:00:00:00:00", 9999, 1, 0, nm.HEADER_SIZE)
        assert h.command_name == "Unknown(9999)"

    def test_from_bytes_too_short_returns_none(self):
        assert NetManageHeader.from_bytes(b"\x00" * 10) is None


# ===========================================================================
# Data block parsing
# ===========================================================================


class TestNetManageDataBlock:
    def test_string_values_split_on_newline(self):
        payload = b"alpha\nbeta\ngamma\x00"
        block = struct.pack("<ih", 6 + len(payload), 0) + payload
        db = NetManageDataBlock.from_bytes(block, 0)
        assert db.format == 0
        assert db.get_string_values() == ["alpha", "beta", "gamma"]

    def test_non_string_format_yields_empty(self):
        payload = b"\x01\x02\x03\x04"
        block = struct.pack("<ih", 6 + len(payload), 1) + payload  # format 1 = structure
        db = NetManageDataBlock.from_bytes(block, 0)
        assert db.get_string_values() == []

    def test_too_short_returns_none(self):
        assert NetManageDataBlock.from_bytes(b"\x00\x00", 0) is None

    def test_bogus_size_clamped_to_remaining(self):
        # Declared size far exceeds the buffer -> data clamped, no exception.
        payload = b"hi"
        block = struct.pack("<ih", 9999, 0) + payload
        db = NetManageDataBlock.from_bytes(block, 0)
        assert db is not None
        assert db.data == b"hi"


# ===========================================================================
# parse_response_values field mapping
# ===========================================================================


class TestParseResponseValues:
    def test_named_fields_extracted(self):
        fields = nm.parse_response_values(_RESPONSE_VALUES)
        assert fields["mac_address"] == "00:11:22:33:44:55"
        assert fields["device_name"] == "M580-PLC"
        assert fields["ip_address"] == "192.168.10.20"
        assert fields["subnet_mask"] == "255.255.255.0"
        assert fields["gateway"] == "192.168.10.1"
        assert fields["firmware_version"] == "v2.10"
        assert fields["device_type"] == "Modicon M580"
        assert fields["serial_number"] == "SN12345"

    def test_short_value_list_partial(self):
        fields = nm.parse_response_values(["mac", "name"])
        assert fields == {"mac_address": "mac", "device_name": "name"}

    def test_empty_list_yields_empty_dict(self):
        assert nm.parse_response_values([]) == {}


# ===========================================================================
# NetManageDevice -> DiscoveredDevice conversion
# ===========================================================================


class TestNetManageDeviceConversion:
    def test_to_discovered_device_fields(self):
        dev = NetManageDevice(
            ip_address="192.168.10.20",
            mac_address="00:11:22:33:44:55",
            device_name="M580-PLC",
            device_type="Modicon M580",
            firmware_version="v2.10",
            serial_number="SN12345",
            ip_mode="DHCP",
            subnet_mask="255.255.255.0",
            gateway="192.168.10.1",
            netbios_name="PLC-NETBIOS",
        )
        dd = dev.to_discovered_device()
        assert dd.mac_address == "00:11:22:33:44:55"  # lowercased (already lower)
        assert dd.ip_addresses == ["192.168.10.20"]
        assert dd.name == "M580-PLC"
        assert dd.manufacturer == "Schneider Electric"
        assert dd.device_type == "Modicon M580"
        assert dd.discovered_by == ["netmanage"]
        assert dd.netmanage_data["firmware_version"] == "v2.10"
        assert dd.netmanage_data["gateway"] == "192.168.10.1"

    def test_mac_lowercased(self):
        dev = NetManageDevice(ip_address="1.2.3.4", mac_address="AA:BB:CC:DD:EE:FF")
        assert dev.to_discovered_device().mac_address == "aa:bb:cc:dd:ee:ff"

    def test_name_falls_back_to_netbios(self):
        dev = NetManageDevice(
            ip_address="1.2.3.4", mac_address="aa:bb:cc:dd:ee:ff", netbios_name="FALLBACK"
        )
        assert dev.to_discovered_device().name == "FALLBACK"

    def test_iso_timestamps(self):
        dev = NetManageDevice(
            ip_address="1.2.3.4",
            mac_address="aa:bb:cc:dd:ee:ff",
            first_seen=datetime(2024, 1, 1, 12, 0, 0),
        )
        dd = dev.to_discovered_device()
        assert dd.first_seen == "2024-01-01T12:00:00"


# ===========================================================================
# decode_netmanage_packet convenience helper
# ===========================================================================


class TestDecodePacket:
    def test_decodes_header_and_block(self):
        encoded = build_response_publish()
        result = nm.decode_netmanage_packet(encoded)
        assert result is not None
        header, block = result
        assert header.command == nm.CMD_RESPONSE_PUBLISH
        assert block is not None
        assert block.get_string_values()[1] == "M580-PLC"

    def test_invalid_packet_returns_none(self):
        # Too short to decode a header at all.
        assert nm.decode_netmanage_packet(b"\x00" * 5) is None

    def test_header_only_packet_has_no_block(self):
        scanner = NetManageScanner.__new__(NetManageScanner)
        # _create_discovery_request builds a header-only RequestPublish
        scanner.active = True
        req = scanner._create_discovery_request()
        header, block = nm.decode_netmanage_packet(req)
        assert header.command == nm.CMD_REQUEST_PUBLISH
        assert block is None


# ===========================================================================
# Active scanner request / response handling
# ===========================================================================


class TestNetManageScannerRequest:
    def test_discovery_request_decodes_to_request_publish(self):
        scanner = NetManageScanner.__new__(NetManageScanner)
        req = scanner._create_discovery_request("FF:FF:FF:FF:FF:FF")
        decoded = nm.xor_encode_decode(req)
        header = NetManageHeader.from_bytes(decoded)
        assert header.command == nm.CMD_REQUEST_PUBLISH
        assert header.mac_address == "FF:FF:FF:FF:FF:FF"
        # Checksum must validate on the decoded request.
        assert nm.verify_checksum(decoded) is True

    def test_parse_response_extracts_device(self):
        scanner = NetManageScanner.__new__(NetManageScanner)
        encoded = build_response_publish()
        dev = scanner._parse_response(encoded, ("192.168.10.20", 27126))
        assert dev is not None
        assert dev.ip_address == "192.168.10.20"
        assert dev.device_name == "M580-PLC"
        assert dev.device_type == "Modicon M580"
        assert dev.ip_mode == "DHCP"
        assert dev.firmware_version == "v2.10"

    def test_parse_response_static_ip_mode(self):
        scanner = NetManageScanner.__new__(NetManageScanner)
        vals = list(_RESPONSE_VALUES)
        vals[2] = "0"  # static
        dev = scanner._parse_response(build_response_publish(values=vals), ("10.0.0.1", 27126))
        assert dev.ip_mode == "Static"

    def test_parse_response_wrong_command_ignored(self):
        scanner = NetManageScanner.__new__(NetManageScanner)
        # Build a RequestSignal (1001) packet -> not a response, should be None
        header = NetManageHeader("00:11:22:33:44:55", nm.CMD_REQUEST_SIGNAL, 1, 0, nm.HEADER_SIZE)
        buf = bytearray(header.to_bytes())
        cs = nm.calculate_checksum(bytes(buf))
        struct.pack_into("<H", buf, nm.CHECKSUM_OFFSET, cs)
        encoded = nm.xor_encode_decode(bytes(buf))
        assert scanner._parse_response(encoded, ("10.0.0.2", 27126)) is None

    def test_parse_response_invalid_header_none(self):
        scanner = NetManageScanner.__new__(NetManageScanner)
        # 8 bytes of garbage XOR'd -> header parse must fail gracefully
        assert scanner._parse_response(b"\x00" * 8, ("10.0.0.3", 27126)) is None


class TestNetManageScannerScanLoop:
    def test_scan_active_collects_device(self):
        scanner = NetManageScanner("eth0", timeout=1, active=True)
        encoded = build_response_publish()

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = [
            (encoded, ("192.168.10.20", 27127)),
            TimeoutError(),
        ]

        with (
            patch("oida.protocols.discovery.netmanage.socket.socket", return_value=mock_sock),
            patch("oida.protocols.discovery.netmanage.sendto") as mock_sendto,
            patch(
                "oida.protocols.discovery.netmanage.time.time",
                side_effect=[0, 0, 0.5, 2.0],
            ),
        ):
            devices = scanner.scan()

        assert mock_sendto.called  # active mode sends a request
        assert "192.168.10.20" in devices
        dd = devices["192.168.10.20"]
        assert dd.name == "M580-PLC"
        assert dd.manufacturer == "Schneider Electric"
        # Raw device retained too
        raw = scanner.get_raw_devices()
        assert raw["192.168.10.20"].firmware_version == "v2.10"

    def test_scan_passive_does_not_send(self):
        scanner = NetManageScanner("eth0", timeout=1, active=False)
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = [TimeoutError()]

        with (
            patch("oida.protocols.discovery.netmanage.socket.socket", return_value=mock_sock),
            patch("oida.protocols.discovery.netmanage.sendto") as mock_sendto,
            patch("oida.protocols.discovery.netmanage.time.time", side_effect=[0, 0, 2.0]),
        ):
            devices = scanner.scan()

        assert not mock_sendto.called
        assert devices == {}

    def test_scan_dedupes_repeated_ip(self):
        scanner = NetManageScanner("eth0", timeout=1, active=True)
        encoded = build_response_publish()

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = [
            (encoded, ("192.168.10.20", 27127)),
            (encoded, ("192.168.10.20", 27127)),
            TimeoutError(),
        ]

        with (
            patch("oida.protocols.discovery.netmanage.socket.socket", return_value=mock_sock),
            patch("oida.protocols.discovery.netmanage.sendto"),
            patch(
                "oida.protocols.discovery.netmanage.time.time",
                side_effect=[0, 0, 0.3, 0.6, 2.0],
            ),
        ):
            devices = scanner.scan()

        assert len(devices) == 1


# ===========================================================================
# Passive listener (scapy packet processing)
# ===========================================================================


def _make_passive():
    listener = NetManagePassiveListener.__new__(NetManagePassiveListener)
    listener._lock = threading.Lock()
    listener.discovered_devices = {}
    listener.netmanage_devices = {}
    listener.nxc_logger = None
    return listener


def _scapy_packet(encoded: bytes, src_ip: str, sport: int = nm.NETMANAGE_SEND_PORT):
    """Build a scapy UDP/Raw packet carrying a NetManage payload."""
    from scapy.all import IP, UDP, Raw

    return IP(src=src_ip) / UDP(sport=sport, dport=nm.NETMANAGE_RECV_PORT) / Raw(load=encoded)


class TestNetManagePassiveListener:
    def test_response_packet_creates_device(self):
        pytest.importorskip("scapy")
        listener = _make_passive()
        encoded = build_response_publish()
        pkt = _scapy_packet(encoded, "192.168.10.20")
        listener.process_packet(pkt)

        assert "192.168.10.20" in listener.netmanage_devices
        assert "192.168.10.20" in listener.discovered_devices
        nm_dev = listener.netmanage_devices["192.168.10.20"]
        assert nm_dev.device_name == "M580-PLC"
        dd = listener.discovered_devices["192.168.10.20"]
        assert dd.manufacturer == "Schneider Electric"

    def test_nxc_logger_success_called(self):
        pytest.importorskip("scapy")
        listener = _make_passive()
        listener.nxc_logger = MagicMock()
        pkt = _scapy_packet(build_response_publish(), "192.168.10.21")
        listener.process_packet(pkt)
        assert listener.nxc_logger.success.called

    def test_non_netmanage_port_ignored(self):
        pytest.importorskip("scapy")
        from scapy.all import IP, UDP, Raw

        listener = _make_passive()
        pkt = IP(src="10.0.0.9") / UDP(sport=12345, dport=80) / Raw(load=build_response_publish())
        listener.process_packet(pkt)
        assert listener.discovered_devices == {}

    def test_packet_without_raw_ignored(self):
        pytest.importorskip("scapy")
        from scapy.all import IP, UDP

        listener = _make_passive()
        pkt = IP(src="10.0.0.10") / UDP(sport=nm.NETMANAGE_SEND_PORT, dport=nm.NETMANAGE_RECV_PORT)
        listener.process_packet(pkt)
        assert listener.discovered_devices == {}

    def test_short_payload_ignored(self):
        pytest.importorskip("scapy")
        listener = _make_passive()
        pkt = _scapy_packet(b"\x00" * 10, "10.0.0.11")
        listener.process_packet(pkt)
        assert listener.discovered_devices == {}

    def test_request_publish_logged_not_stored(self):
        pytest.importorskip("scapy")
        listener = _make_passive()
        scanner = NetManageScanner.__new__(NetManageScanner)
        req = scanner._create_discovery_request()  # RequestPublish, no data block
        pkt = _scapy_packet(req, "10.0.0.12")
        listener.process_packet(pkt)
        # A request is parsed but not a ResponsePublish -> no device recorded
        assert listener.discovered_devices == {}

    def test_repeated_response_updates_last_seen(self):
        pytest.importorskip("scapy")
        listener = _make_passive()
        encoded = build_response_publish()
        listener.process_packet(_scapy_packet(encoded, "192.168.10.30"))
        first = listener.netmanage_devices["192.168.10.30"].first_seen
        listener.process_packet(_scapy_packet(encoded, "192.168.10.30"))
        assert len(listener.netmanage_devices) == 1
        assert listener.netmanage_devices["192.168.10.30"].first_seen == first


# ===========================================================================
# Module-level convenience function
# ===========================================================================


class TestDiscoverNetmanage:
    def test_active_uses_scanner(self):
        with patch.object(nm.NetManageScanner, "scan", return_value={"x": "dev"}) as mock_scan:
            result = nm.discover_netmanage(interface="eth0", timeout=1, active=True)
        assert mock_scan.called
        assert result == {"x": "dev"}

    def test_passive_uses_listener(self):
        with patch.object(
            nm.NetManagePassiveListener, "scan", return_value={"y": "dev"}
        ) as mock_scan:
            result = nm.discover_netmanage(interface="eth0", timeout=1, active=False)
        assert mock_scan.called
        assert result == {"y": "dev"}
