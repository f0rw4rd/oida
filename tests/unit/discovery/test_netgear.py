"""
Tests for BMC / network-equipment discovery scanners.

- IPMI (oida.protocols.discovery.infra.IPMIScanner)
- Ubiquiti + MikroTik MNDP (oida.protocols.discovery.netgear)

Golden bytes are built from the documented packet layouts:
- IPMI/ASF: DMTF DSP0136 + https://github.com/google/gopacket layers/asf*.go
- Ubiquiti: https://github.com/nmap/nmap/blob/master/scripts/ubiquiti-discovery.nse
- MNDP: https://gitlab.com/wireshark/wireshark/-/raw/master/epan/dissectors/packet-mndp.c
"""

import struct

import pytest


# ---------------------------------------------------------------------------
# IPMI / ASF-RMCP
# ---------------------------------------------------------------------------
def _asf_pong(entities=0x81, interactions=0xA0, enterprise=343):
    """Build a 28-byte ASF Presence Pong (RMCP + ASF hdr + 16-byte block)."""
    rmcp = b"\x06\x00\xff\x06"
    asf_hdr = struct.pack(">I", 4542) + b"\x40\x10\x00\x10"  # type=Pong, tag, rsv, len=16
    block = (
        struct.pack(">I", enterprise)
        + b"\x00\x00\x00\x00"  # OEM
        + bytes((entities,))
        + bytes((interactions,))
        + b"\x00" * 6
    )
    return rmcp + asf_hdr + block


class TestIPMIProbe:
    def test_probe_exact_bytes(self):
        from oida.protocols.discovery.infra import IPMIScanner

        scanner = IPMIScanner(interface="eth0")
        probe = scanner._build_probe()
        # 06 00 FF 06 | 00 00 11 BE | 80(ping) tag 00 00
        assert probe[:4] == b"\x06\x00\xff\x06"
        assert struct.unpack(">I", probe[4:8])[0] == 4542
        assert probe[8] == 0x80  # Presence Ping
        assert probe[10:12] == b"\x00\x00"  # reserved + data-len 0
        assert len(probe) == 12


class TestIPMIParseResponse:
    def test_golden_pong_ipmi_supported(self):
        from oida.protocols.discovery.infra import IPMIScanner

        scanner = IPMIScanner(interface="eth0")
        device = scanner._parse_response(_asf_pong(), "10.0.0.5")

        assert device is not None
        assert device.ip_addresses == ["10.0.0.5"]
        assert device.manufacturer == "Intel"  # enterprise 343
        assert device.device_type == "BMC (IPMI)"
        assert device.ipmi_data["ipmi_supported"] is True
        assert device.ipmi_data["asf_v1"] is True
        assert device.ipmi_data["dash"] is True
        assert "ipmi" in device.discovered_by

    def test_pong_without_ipmi_bit(self):
        from oida.protocols.discovery.infra import IPMIScanner

        scanner = IPMIScanner(interface="eth0")
        device = scanner._parse_response(_asf_pong(entities=0x01), "10.0.0.6")
        assert device is not None
        assert device.ipmi_data["ipmi_supported"] is False
        assert device.device_type == "ASF-RMCP Device"

    def test_rejects_non_pong(self):
        from oida.protocols.discovery.infra import IPMIScanner

        scanner = IPMIScanner(interface="eth0")
        # Right RMCP/ASF framing but message type 0x00 (not a Pong).
        assert scanner._parse_response(b"\x06\x00\xff\x06" + b"\x00" * 16, "1.2.3.4") is None
        assert scanner._parse_response(b"random", "1.2.3.4") is None
        assert scanner._parse_response(b"", "1.2.3.4") is None


# ---------------------------------------------------------------------------
# Ubiquiti
# ---------------------------------------------------------------------------
def _utlv(t, v):
    return bytes([t]) + struct.pack(">H", len(v)) + v


def _ubiquiti_reply():
    body = (
        _utlv(0x02, bytes.fromhex("0418d6aabbcc") + bytes([192, 168, 1, 20]))
        + _utlv(0x0B, b"UAP-AC")
        + _utlv(0x14, b"U7PG2")
        + _utlv(0x03, b"BZ.qca956x.v3.7.58")
        + _utlv(0x0A, struct.pack(">I", 123456))
    )
    return bytes([0x01, 0x00]) + struct.pack(">H", len(body)) + body


class TestUbiquitiParse:
    def test_golden_reply(self):
        from oida.protocols.discovery.netgear import UbiquitiScanner

        scanner = UbiquitiScanner(interface="eth0")
        device = scanner._parse_response(_ubiquiti_reply(), "192.168.1.20")

        assert device is not None
        assert device.mac_address == "04:18:d6:aa:bb:cc"
        assert device.ip_addresses == ["192.168.1.20"]
        assert device.manufacturer == "Ubiquiti"
        assert device.model == "U7PG2"
        assert device.ubiquiti_data["firmware"] == "BZ.qca956x.v3.7.58"
        assert device.ubiquiti_data["uptime"] == 123456
        assert device.ubiquiti_data["hostname"] == "UAP-AC"

    def test_probe_constants(self):
        from oida.protocols.discovery.netgear import UbiquitiScanner

        assert UbiquitiScanner.PORT == 10001
        assert UbiquitiScanner.PROBE_V1 == b"\x01\x00\x00\x00"
        assert UbiquitiScanner.PROBE_V2 == b"\x02\x08\x00\x00"

    def test_rejects_bad_version(self):
        from oida.protocols.discovery.netgear import UbiquitiScanner

        scanner = UbiquitiScanner(interface="eth0")
        assert scanner._parse_response(b"\x09\x00\x00\x00", "1.2.3.4") is None
        assert scanner._parse_response(b"", "1.2.3.4") is None


# ---------------------------------------------------------------------------
# MikroTik MNDP
# ---------------------------------------------------------------------------
def _mtlv(t, v):
    return struct.pack(">HH", t, len(v)) + v


def _mndp_announce():
    body = (
        _mtlv(1, bytes.fromhex("cc2de0aabbcc"))
        + _mtlv(5, b"MyRouter")
        + _mtlv(7, b"6.48.6")
        + _mtlv(8, b"MikroTik")
        + _mtlv(12, b"RB750Gr3")
        + _mtlv(17, bytes([192, 168, 88, 1]))
        + _mtlv(10, struct.pack(">I", 98765))
    )
    return b"\x00\x00\x00\x01" + body  # 2-byte header + seq


class TestMNDPParse:
    def test_golden_announce(self):
        from oida.protocols.discovery.netgear import MNDPScanner

        scanner = MNDPScanner(interface="eth0")
        device = scanner._parse_response(_mndp_announce(), "192.168.88.1")

        assert device is not None
        assert device.mac_address == "cc:2d:e0:aa:bb:cc"
        assert device.ip_addresses == ["192.168.88.1"]
        assert device.name == "MyRouter"
        assert device.manufacturer == "MikroTik"
        assert device.model == "RB750Gr3"
        assert device.mndp_data["version"] == "6.48.6"
        assert device.mndp_data["platform"] == "MikroTik"
        assert device.mndp_data["uptime"] == 98765

    def test_rejects_header_only_and_junk(self):
        from oida.protocols.discovery.netgear import MNDPScanner

        scanner = MNDPScanner(interface="eth0")
        assert scanner._parse_response(b"\x00\x00\x00\x01", "1.2.3.4") is None
        assert scanner._parse_response(b"\x00", "1.2.3.4") is None


# ---------------------------------------------------------------------------
# scan() round-trips + registration
# ---------------------------------------------------------------------------
class _FakeSocket:
    def __init__(self, reply, reply_from):
        self.reply = reply
        self.reply_from = reply_from
        self.sent = []
        self._served = False
        self.closed = False

    def sendto(self, data, addr):
        self.sent.append((data, addr))
        return len(data)

    def recvfrom(self, _n):
        if not self._served:
            self._served = True
            return self.reply, self.reply_from
        raise TimeoutError()

    def settimeout(self, _t):
        pass

    def setsockopt(self, *_a):
        pass

    def close(self):
        self.closed = True


class TestScanRoundTrips:
    def test_ipmi_scan(self, monkeypatch):
        import oida.protocols.discovery.infra as infra
        from oida.protocols.discovery.infra import IPMIScanner

        fake = _FakeSocket(_asf_pong(), ("10.0.0.5", 623))
        monkeypatch.setattr(infra, "create_udp_socket", lambda *a, **k: fake)
        monkeypatch.setattr(infra, "sendto", lambda s, d, a: s.sendto(d, a))
        monkeypatch.setattr(
            infra, "get_all_broadcast_addresses", lambda *a, **k: ["255.255.255.255"]
        )

        devices = IPMIScanner(interface="eth0", timeout=1).scan()
        assert "10.0.0.5" in devices
        assert devices["10.0.0.5"].ipmi_data["ipmi_supported"] is True
        assert fake.sent[0][1] == ("255.255.255.255", 623)

    def test_mndp_scan(self, monkeypatch):
        import oida.protocols.discovery.netgear as netgear
        from oida.protocols.discovery.netgear import MNDPScanner

        fake = _FakeSocket(_mndp_announce(), ("192.168.88.1", 5678))
        monkeypatch.setattr(netgear, "create_udp_socket", lambda *a, **k: fake)
        monkeypatch.setattr(netgear, "sendto", lambda s, d, a: s.sendto(d, a))
        monkeypatch.setattr(
            netgear, "get_all_broadcast_addresses", lambda *a, **k: ["192.168.88.255"]
        )

        devices = MNDPScanner(interface="eth0", timeout=1).scan()
        assert "192.168.88.1" in devices
        assert devices["192.168.88.1"].name == "MyRouter"
        assert fake.sent[0][1] == ("192.168.88.255", 5678)


class TestRegistration:
    @pytest.mark.parametrize("name", ["ipmi", "ubiquiti", "mndp"])
    def test_registered(self, name):
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS

        assert name in _SCANNER_CONFIGS
