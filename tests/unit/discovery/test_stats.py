"""
Tests for oida.protocols.discovery.stats.PassiveStatistics.

PassiveStatistics is a pure packet-processing collector (no I/O): it takes
PyShark-style packet objects and tracks protocol hierarchy, MAC/IP
conversations, and open ports. These tests feed it lightweight fake packet
objects that mimic PyShark's attribute-access layer API and assert on the
collector's internal state and ``to_dict()`` export.
"""

from datetime import datetime

import pytest

from oida.protocols.discovery.stats import (
    COMMON_SERVER_PORTS,
    EPHEMERAL_PORT_MIN,
    SERVICE_PORTS,
    WELL_KNOWN_PORT_MAX,
    Conversation,
    OpenPort,
    PassiveStatistics,
    ProtocolCount,
    _int,
    _is_server_port,
    _resolve,
    _str,
)


# ---------------------------------------------------------------------------
# Fake PyShark packet model
# ---------------------------------------------------------------------------
class _Layer:
    """Mimics a PyShark layer with a ``layer_name`` and arbitrary fields."""

    def __init__(self, layer_name, **fields):
        self.layer_name = layer_name
        for k, v in fields.items():
            setattr(self, k, v)


class _Packet:
    """Mimics a PyShark packet: ``.layers`` list + attribute access per layer.

    Each keyword arg is a layer; ``hasattr(packet, "ip")`` and
    ``packet.ip.src`` work because the layer object is set as an attribute.
    Layer order in ``.layers`` follows insertion order of the kwargs.
    """

    def __init__(self, length=100, sniff_timestamp=None, **layers):
        self.length = length
        if sniff_timestamp is not None:
            self.sniff_timestamp = sniff_timestamp
        self.layers = []
        for name, layer in layers.items():
            setattr(self, name, layer)
            self.layers.append(layer)


def _eth(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb"):
    return _Layer("eth", src=src, dst=dst)


def _ip(src="10.0.0.1", dst="10.0.0.2"):
    return _Layer("ip", src=src, dst=dst)


def _tcp(srcport, dstport, flags_hex=None, stream=None, flags=None):
    layer = _Layer("tcp", srcport=str(srcport), dstport=str(dstport))
    if flags_hex is not None:
        layer.flags_hex = flags_hex
    if flags is not None:
        layer.flags = flags
    if stream is not None:
        layer.stream = str(stream)
    return layer


def _udp(srcport, dstport):
    return _Layer("udp", srcport=str(srcport), dstport=str(dstport))


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------
class TestResolveHelpers:
    def test_resolve_plain_value_passthrough(self):
        assert _resolve("hello") == "hello"
        assert _resolve(None, default="d") == "d"

    def test_resolve_unwraps_ekmultifield(self):
        class _EK:
            def __init__(self, value):
                self.value = value
                self._containing_layer = object()

        assert _resolve(_EK("1.2.3.4")) == "1.2.3.4"
        # value None -> default
        assert _resolve(_EK(None), default="x") == "x"

    def test_str_helper(self):
        assert _str(123) == "123"
        assert _str(None, default="") == ""

    def test_int_helper_valid_and_invalid(self):
        assert _int("42") == 42
        assert _int("not-a-number", default=7) == 7
        assert _int(None, default=0) == 0


class TestIsServerPort:
    def test_well_known_ports_are_server(self):
        assert _is_server_port(80) is True
        assert _is_server_port(WELL_KNOWN_PORT_MAX) is True

    def test_ephemeral_ports_are_not_server(self):
        assert _is_server_port(EPHEMERAL_PORT_MIN) is False
        assert _is_server_port(55000) is False

    def test_service_port_above_well_known(self):
        # Modbus 502 is well-known; pick a registered service > 1023
        assert (1883, "tcp") in SERVICE_PORTS  # MQTT
        assert _is_server_port(1883, "tcp") is True

    def test_common_server_port(self):
        # 8888 is in COMMON_SERVER_PORTS, in the 1024-49151 mid range
        assert 8888 in COMMON_SERVER_PORTS
        assert _is_server_port(8888) is True
        # 8080 is registered as HTTP-Alt in SERVICE_PORTS, so also a server port
        assert _is_server_port(8080, "tcp") is True

    def test_unknown_mid_range_port_not_server(self):
        # 12001 is not well-known, not ephemeral, not registered/common
        assert _is_server_port(12001, "tcp") is False


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
class TestDataclasses:
    def test_protocol_count_defaults(self):
        pc = ProtocolCount(name="TCP")
        assert pc.packets == 0 and pc.bytes == 0 and pc.parent is None

    def test_conversation_defaults(self):
        c = Conversation(src="a", dst="b")
        assert c.packets == 0 and c.src_port is None

    def test_open_port_defaults(self):
        op = OpenPort(ip="1.1.1.1", port=80, transport="tcp", service="HTTP", evidence="x")
        assert op.packets == 1


# ---------------------------------------------------------------------------
# Protocol hierarchy
# ---------------------------------------------------------------------------
class TestProtocolHierarchy:
    def test_eth_ip_tcp_http_hierarchy(self):
        stats = PassiveStatistics()
        pkt = _Packet(
            length=200,
            eth=_eth(),
            ip=_ip(),
            tcp=_tcp(50000, 80, flags_hex="0x0018", stream=1),
            http=_Layer("http"),
        )
        stats.process_pyshark_packet(pkt)

        pc = stats.protocol_counts
        assert "Ethernet" in pc and pc["Ethernet"].parent is None
        assert pc["IPv4"].parent == "Ethernet"
        assert pc["TCP"].parent == "IPv4"
        assert pc["HTTP"].parent == "TCP"
        # Byte accounting: every layer of the packet gets the packet length
        assert pc["Ethernet"].bytes == 200
        assert stats.total_packets == 1
        assert stats.total_bytes == 200

    def test_udp_dns_hierarchy(self):
        stats = PassiveStatistics()
        pkt = _Packet(
            eth=_eth(),
            ip=_ip(),
            udp=_udp(50000, 53),
            dns=_Layer("dns"),
        )
        stats.process_pyshark_packet(pkt)
        pc = stats.protocol_counts
        assert pc["UDP"].parent == "IPv4"
        assert pc["DNS"].parent == "UDP"

    def test_unknown_layer_uses_uppercase_name(self):
        stats = PassiveStatistics()
        pkt = _Packet(eth=_eth(), ip=_ip(), tcp=_tcp(50000, 80), frobozz=_Layer("frobozz"))
        stats.process_pyshark_packet(pkt)
        # Unknown layer name uppercased and parented to previous layer (TCP)
        assert "FROBOZZ" in stats.protocol_counts
        assert stats.protocol_counts["FROBOZZ"].parent == "TCP"

    def test_l2_protocol_over_ethernet(self):
        stats = PassiveStatistics()
        pkt = _Packet(eth=_eth(), lldp=_Layer("lldp"))
        stats.process_pyshark_packet(pkt)
        assert stats.protocol_counts["LLDP"].parent == "Ethernet"


# ---------------------------------------------------------------------------
# MAC + IP conversations
# ---------------------------------------------------------------------------
class TestConversations:
    def test_mac_conversation_normalized_and_counted(self):
        stats = PassiveStatistics()
        a, b = "00:00:00:00:00:01", "00:00:00:00:00:02"
        # Two packets in opposite directions should land in one conversation
        stats.process_pyshark_packet(_Packet(length=100, eth=_eth(a, b), ip=_ip()))
        stats.process_pyshark_packet(_Packet(length=50, eth=_eth(b, a), ip=_ip()))
        assert len(stats.mac_conversations) == 1
        conv = next(iter(stats.mac_conversations.values()))
        assert conv.packets == 2
        assert conv.bytes == 150
        # Key is sorted tuple of the two MACs
        assert (conv.src, conv.dst) == tuple(sorted([a, b]))

    def test_ip_conversation_client_server_identified(self):
        stats = PassiveStatistics()
        # client 10.0.0.9:50000 -> server 10.0.0.1:502 (Modbus, well-known)
        pkt = _Packet(
            eth=_eth(),
            ip=_ip("10.0.0.9", "10.0.0.1"),
            tcp=_tcp(50000, 502, flags_hex="0x0002", stream=5),
        )
        stats.process_pyshark_packet(pkt)
        assert len(stats.ip_conversations) == 1
        conv = next(iter(stats.ip_conversations.values()))
        # Server side (502) recognised as dst, client is the ephemeral side
        assert conv.dst == "10.0.0.1"
        assert conv.dst_port == 502
        assert conv.src == "10.0.0.9"
        assert conv.src_port == 50000
        # 502/tcp resolves to Modbus via SERVICE_PORTS
        assert conv.protocol == "Modbus"

    def test_ip_conversation_protocol_from_layer(self):
        stats = PassiveStatistics()
        # Non-standard ports, but an opcua layer present -> labelled OPC UA
        pkt = _Packet(
            eth=_eth(),
            ip=_ip("10.0.0.9", "10.0.0.1"),
            tcp=_tcp(50000, 12345, stream=2),
            opcua=_Layer("opcua"),
        )
        stats.process_pyshark_packet(pkt)
        conv = next(iter(stats.ip_conversations.values()))
        assert conv.protocol == "OPC UA"

    def test_ip_to_mac_learned(self):
        stats = PassiveStatistics()
        pkt = _Packet(
            eth=_eth("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"),
            ip=_ip("10.0.0.9", "10.0.0.1"),
            tcp=_tcp(50000, 80, stream=3),
        )
        stats.process_pyshark_packet(pkt)
        assert stats._ip_to_mac["10.0.0.9"] == "aa:aa:aa:aa:aa:aa"
        assert stats._ip_to_mac["10.0.0.1"] == "bb:bb:bb:bb:bb:bb"

    def test_conversation_without_ports_uses_ip_key(self):
        stats = PassiveStatistics()
        # ICMP-style: IP only, no TCP/UDP
        pkt = _Packet(eth=_eth(), ip=_ip("10.0.0.1", "10.0.0.2"), icmp=_Layer("icmp"))
        stats.process_pyshark_packet(pkt)
        conv = next(iter(stats.ip_conversations.values()))
        assert conv.src_port is None and conv.dst_port is None
        assert {conv.src, conv.dst} == {"10.0.0.1", "10.0.0.2"}


# ---------------------------------------------------------------------------
# Open port detection
# ---------------------------------------------------------------------------
class TestOpenPortDetection:
    def test_tcp_syn_ack_records_server_port(self):
        stats = PassiveStatistics()
        # SYN-ACK from server 10.0.0.1:502 -> client. flags 0x12 = SYN+ACK
        pkt = _Packet(
            eth=_eth(),
            ip=_ip("10.0.0.1", "10.0.0.9"),
            tcp=_tcp(502, 50000, flags_hex="0x0012", stream=7),
        )
        stats.process_pyshark_packet(pkt)
        key = ("10.0.0.1", 502, "tcp")
        assert key in stats.open_ports
        op = stats.open_ports[key]
        assert op.service == "Modbus"
        assert op.evidence == "SYN-ACK received"

    def test_tcp_syn_then_data_tracks_stream(self):
        stats = PassiveStatistics()
        # SYN: client 10.0.0.9:50000 -> server 10.0.0.1:80, flags 0x02
        syn = _Packet(
            eth=_eth(),
            ip=_ip("10.0.0.9", "10.0.0.1"),
            tcp=_tcp(50000, 80, flags_hex="0x0002", stream=11),
        )
        stats.process_pyshark_packet(syn)
        # Data on same stream (PSH+ACK) -> server port recorded as active
        data = _Packet(
            eth=_eth(),
            ip=_ip("10.0.0.1", "10.0.0.9"),
            tcp=_tcp(80, 50000, flags_hex="0x0018", stream=11),
        )
        stats.process_pyshark_packet(data)
        key = ("10.0.0.1", 80, "tcp")
        assert key in stats.open_ports
        assert stats.open_ports[key].service == "HTTP"

    def test_open_port_deduplicated_increments_packets(self):
        stats = PassiveStatistics()
        for _ in range(3):
            pkt = _Packet(
                eth=_eth(),
                ip=_ip("10.0.0.1", "10.0.0.9"),
                tcp=_tcp(443, 50000, flags_hex="0x0010", stream=21),
            )
            stats.process_pyshark_packet(pkt)
        key = ("10.0.0.1", 443, "tcp")
        assert key in stats.open_ports
        # First creates, remaining two increment
        assert stats.open_ports[key].packets == 3

    def test_udp_server_port_recorded(self):
        stats = PassiveStatistics()
        # client 10.0.0.9:50000 -> SNMP server 10.0.0.1:161
        pkt = _Packet(eth=_eth(), ip=_ip("10.0.0.9", "10.0.0.1"), udp=_udp(50000, 161))
        stats.process_pyshark_packet(pkt)
        key = ("10.0.0.1", 161, "udp")
        assert key in stats.open_ports
        assert stats.open_ports[key].service == "SNMP"

    def test_string_flags_syn_parsed(self):
        stats = PassiveStatistics()
        # No flags_hex; string flags "SYN" only -> treated as SYN, no port yet
        syn = _Packet(
            eth=_eth(),
            ip=_ip("10.0.0.9", "10.0.0.1"),
            tcp=_tcp(50000, 22, flags="SYN", stream=33),
        )
        stats.process_pyshark_packet(syn)
        # SYN alone does not record an open port (only tracks the stream)
        assert ("10.0.0.1", 22, "tcp") not in stats.open_ports
        # Now a data packet on the stream records it
        data = _Packet(
            eth=_eth(),
            ip=_ip("10.0.0.1", "10.0.0.9"),
            tcp=_tcp(22, 50000, flags="ACK", stream=33),
        )
        stats.process_pyshark_packet(data)
        assert ("10.0.0.1", 22, "tcp") in stats.open_ports

    def test_record_open_port_unknown_service_label(self):
        stats = PassiveStatistics()
        ts = datetime.now()
        stats._record_open_port("10.0.0.1", 7777, "tcp", "data", ts)
        op = stats.open_ports[("10.0.0.1", 7777, "tcp")]
        # No SERVICE_PORTS match -> "tcp/7777"
        assert op.service == "tcp/7777"


# ---------------------------------------------------------------------------
# Timestamp handling
# ---------------------------------------------------------------------------
class TestTimestamps:
    def test_epoch_float_timestamp(self):
        stats = PassiveStatistics()
        pkt = _Packet(eth=_eth(), ip=_ip(), sniff_timestamp="1000000.5")
        stats.process_pyshark_packet(pkt)
        assert stats.start_time == datetime.fromtimestamp(1000000.5)
        assert stats.end_time == stats.start_time

    def test_iso8601_timestamp_with_z(self):
        stats = PassiveStatistics()
        # tshark 4.6+ EK output style with trailing Z and nanoseconds
        pkt = _Packet(eth=_eth(), ip=_ip(), sniff_timestamp="2009-09-01T23:29:28.262123456Z")
        stats.process_pyshark_packet(pkt)
        assert stats.start_time is not None
        assert stats.start_time.year == 2009
        assert stats.start_time.month == 9
        # nanoseconds truncated to microseconds
        assert stats.start_time.microsecond == 262123


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------
class TestRobustness:
    def test_malformed_packet_does_not_raise(self):
        stats = PassiveStatistics()

        class _Broken:
            length = "100"

            @property
            def layers(self):
                raise RuntimeError("boom")

        # Should swallow the error and still count the packet
        stats.process_pyshark_packet(_Broken())
        assert stats.total_packets == 1

    def test_packet_without_eth_skips_mac_conversation(self):
        stats = PassiveStatistics()
        pkt = _Packet(ip=_ip("10.0.0.1", "10.0.0.2"), icmp=_Layer("icmp"))
        stats.process_pyshark_packet(pkt)
        assert stats.mac_conversations == {}
        # But IP conversation still tracked
        assert len(stats.ip_conversations) == 1


# ---------------------------------------------------------------------------
# Export / formatting
# ---------------------------------------------------------------------------
class TestToDict:
    def _populate(self):
        stats = PassiveStatistics()
        # Client SYN: 10.0.0.9:50000 -> 10.0.0.1:502
        stats.process_pyshark_packet(
            _Packet(
                length=200,
                eth=_eth("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"),
                ip=_ip("10.0.0.9", "10.0.0.1"),
                tcp=_tcp(50000, 502, flags_hex="0x0002", stream=99),
                modbus=_Layer("modbus"),
                sniff_timestamp="1000.0",
            )
        )
        # Server SYN-ACK back: 10.0.0.1:502 -> 10.0.0.9:50000
        stats.process_pyshark_packet(
            _Packet(
                length=100,
                eth=_eth("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa"),
                ip=_ip("10.0.0.1", "10.0.0.9"),
                tcp=_tcp(502, 50000, flags_hex="0x0012", stream=99),
                modbus=_Layer("modbus"),
                sniff_timestamp="1002.0",
            )
        )
        return stats

    def test_to_dict_structure(self):
        stats = self._populate()
        d = stats.to_dict()

        assert d["summary"]["total_packets"] == 2
        assert d["summary"]["total_bytes"] == 300
        assert d["summary"]["duration_seconds"] == 2.0

        # Protocol hierarchy has percentages summing sanely
        assert "Modbus" in d["protocol_hierarchy"]
        assert d["protocol_hierarchy"]["Ethernet"]["packets"] == 2
        assert d["protocol_hierarchy"]["Ethernet"]["percent"] == 100.0

        # One MAC conversation, one IP conversation
        assert len(d["mac_conversations"]) == 1
        assert d["mac_conversations"][0]["packets"] == 2

        assert len(d["ip_conversations"]) == 1
        ip_conv = d["ip_conversations"][0]
        assert ip_conv["protocol"] == "Modbus"
        assert ip_conv["packets"] == 2

        # Open port for Modbus server detected via SYN-ACK
        assert any(
            op["ip"] == "10.0.0.1" and op["port"] == 502 and op["service"] == "Modbus"
            for op in d["open_ports"]
        )

    def test_to_dict_empty(self):
        stats = PassiveStatistics()
        d = stats.to_dict()
        assert d["summary"]["total_packets"] == 0
        assert d["summary"]["duration_seconds"] == 0
        assert d["protocol_hierarchy"] == {}
        assert d["open_ports"] == []


class TestFormatting:
    @pytest.mark.parametrize(
        "num,expected",
        [
            (512, "512 B"),
            (2048, "2.0 KB"),
            (5 * 1024 * 1024, "5.0 MB"),
            (3 * 1024 * 1024 * 1024, "3.0 GB"),
        ],
    )
    def test_format_bytes(self, num, expected):
        assert PassiveStatistics._format_bytes(num) == expected

    @pytest.mark.parametrize(
        "secs,expected",
        [
            (5.0, "5.0s"),
            (125, "2m 5s"),
            (3661, "1h 1m"),
            (90061, "1d 1h 1m"),
        ],
    )
    def test_format_duration(self, secs, expected):
        assert PassiveStatistics._format_duration(secs) == expected


# ---------------------------------------------------------------------------
# print_summary (exercises the console-rendering paths)
# ---------------------------------------------------------------------------
class _RecordingLogger:
    """Captures messages emitted by PassiveStatistics rendering paths."""

    def __init__(self):
        self.messages = []

    def display(self, msg):
        self.messages.append(("display", msg))

    def info(self, msg):
        self.messages.append(("info", msg))

    def success(self, msg):
        self.messages.append(("success", msg))


class TestPrintSummary:
    def test_print_summary_empty_is_noop(self):
        stats = PassiveStatistics()
        log = _RecordingLogger()
        stats.print_summary(logger=log)
        assert log.messages == []

    def test_print_summary_renders_sections(self):
        stats = PassiveStatistics()
        # Build a packet tree with a gap node (TCP > sum of children)
        stats.process_pyshark_packet(
            _Packet(
                length=100,
                eth=_eth(),
                ip=_ip("10.0.0.9", "10.0.0.1"),
                tcp=_tcp(50000, 502, flags_hex="0x0012", stream=1),
                modbus=_Layer("modbus"),
                sniff_timestamp="1000.0",
            )
        )
        # A plain TCP packet (no app layer) so TCP has unaccounted "Segments"
        stats.process_pyshark_packet(
            _Packet(
                length=60,
                eth=_eth(),
                ip=_ip("10.0.0.9", "10.0.0.1"),
                tcp=_tcp(50000, 502, flags_hex="0x0010", stream=1),
                sniff_timestamp="1001.0",
            )
        )

        log = _RecordingLogger()
        stats.print_summary(logger=log)
        rendered = " ".join(m for _, m in log.messages)
        assert "Traffic Statistics" in rendered
        assert "Protocol Hierarchy" in rendered
        # gap node label appears when parent packets exceed child sum
        assert "TCP Segments" in rendered

    def test_print_summary_calls_table_methods(self):
        # Populate MAC + IP conversations and open ports, then render every
        # table section (export_data uses the global logger when logger=None).
        stats = PassiveStatistics()
        stats.process_pyshark_packet(
            _Packet(
                length=100,
                eth=_eth("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"),
                ip=_ip("10.0.0.9", "10.0.0.1"),
                tcp=_tcp(502, 50000, flags_hex="0x0012", stream=1),
                sniff_timestamp="1000.0",
            )
        )
        assert stats.mac_conversations and stats.ip_conversations and stats.open_ports
        log = _RecordingLogger()
        # Should not raise; renders all four sections
        stats.print_summary(logger=log)
        assert any("Traffic Statistics" in m for _, m in log.messages)


# ---------------------------------------------------------------------------
# Protocol labelling from detected layers (cross-reference branch)
# ---------------------------------------------------------------------------
class TestProtocolLabelFromLayer:
    @pytest.mark.parametrize(
        "layer_name,expected",
        [
            ("s7comm", "S7comm"),
            ("dnp3", "DNP3"),
            ("bacapp", "BACnet"),
            ("http", "HTTP"),
            ("tls", "TLS"),
            ("dns", "DNS"),
            ("smb2", "SMB"),
            ("mqtt", "MQTT"),
            ("mms", "MMS"),
            ("enip", "EtherNet/IP"),
            ("iec60870_104", "IEC 104"),
        ],
    )
    def test_layer_overrides_transport_label(self, layer_name, expected):
        stats = PassiveStatistics()
        layers = {
            "eth": _eth(),
            "ip": _ip("10.0.0.9", "10.0.0.1"),
            "tcp": _tcp(50000, 40000, stream=1),  # both non-server ports
            layer_name: _Layer(layer_name),
        }
        stats.process_pyshark_packet(_Packet(**layers))
        conv = next(iter(stats.ip_conversations.values()))
        assert conv.protocol == expected


# ---------------------------------------------------------------------------
# UDP open-port detection fallbacks
# ---------------------------------------------------------------------------
class TestUDPFallbacks:
    def test_udp_non_ephemeral_src_to_ephemeral_dst(self):
        # src 5000 (non-ephemeral, not a known service) -> dst 50000 (ephemeral)
        stats = PassiveStatistics()
        pkt = _Packet(eth=_eth(), ip=_ip("10.0.0.1", "10.0.0.9"), udp=_udp(5000, 50000))
        stats.process_pyshark_packet(pkt)
        assert ("10.0.0.1", 5000, "udp") in stats.open_ports

    def test_udp_ephemeral_src_to_non_ephemeral_dst(self):
        stats = PassiveStatistics()
        pkt = _Packet(eth=_eth(), ip=_ip("10.0.0.9", "10.0.0.1"), udp=_udp(50000, 5000))
        stats.process_pyshark_packet(pkt)
        assert ("10.0.0.1", 5000, "udp") in stats.open_ports

    def test_ipv6_packet_conversation(self):
        stats = PassiveStatistics()
        ipv6 = _Layer("ipv6", src="fe80::1", dst="fe80::2")
        pkt = _Packet(eth=_eth(), ipv6=ipv6, udp=_udp(50000, 53), dns=_Layer("dns"))
        stats.process_pyshark_packet(pkt)
        conv = next(iter(stats.ip_conversations.values()))
        assert {conv.src, conv.dst} == {"fe80::1", "fe80::2"}
        assert conv.protocol == "DNS"
