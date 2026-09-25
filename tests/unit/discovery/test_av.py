"""
Tests for AV / lighting-control discovery scanners (oida.protocols.discovery.av).

Golden response bytes are constructed strictly from the documented field
offsets / regexes of the authoritative sources (no captured blob was published):
- Crestron: https://github.com/StephenGenusa/Crestron-List-Devices-On-Network
            https://github.com/Phenomite/AMP-Research (Port 41794 - Crestron CIP)
- Art-Net:  https://github.com/jsimonetti/go-artnet (packet/artpollreply.go)
"""

import struct


# ---------------------------------------------------------------------------
# Crestron CIP
# ---------------------------------------------------------------------------
def _crestron_reply(hostname: bytes, firmware: bytes) -> bytes:
    """Build a 394-byte CIP reply: control 0x15, hostname@[9:40], fw@[265:350]."""
    buf = bytearray(b"\x00" * 394)
    buf[0] = 0x15
    host = b"\x00" + hostname + b"\x00"
    buf[9 : 9 + len(host)] = host
    fw = b"\x00" + firmware + b"\x00"
    buf[265 : 265 + len(fw)] = fw
    return bytes(buf)


GOLDEN_CRESTRON = _crestron_reply(b"DIN-AP-7F74F65F", b"DIN-AP3 [v1.503.3318.26859 (Feb 01 2018)]")


class TestCrestronProbe:
    def test_probe_exact_bytes(self):
        from oida.protocols.discovery.av import CrestronCIPScanner

        scanner = CrestronCIPScanner(interface="eth0")
        probe = scanner._build_probe()
        # Verbatim from List_Crestron_Devices.py: prefix + "feed" + 252 nulls.
        assert probe[:10] == b"\x14\x00\x00\x00\x01\x04\x00\x03\x00\x00"
        assert probe[10:14] == b"feed"
        assert len(probe) == 266
        assert probe[14:] == b"\x00" * 252

    def test_constants(self):
        from oida.protocols.discovery.av import CrestronCIPScanner

        assert CrestronCIPScanner.PORT == 41794


class TestCrestronParseResponse:
    def test_golden_reply(self):
        from oida.protocols.discovery.av import CrestronCIPScanner

        scanner = CrestronCIPScanner(interface="eth0")
        device = scanner._parse_response(GOLDEN_CRESTRON, "192.168.1.7")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.7"]
        assert device.name == "DIN-AP-7F74F65F"
        assert device.manufacturer == "Crestron"
        assert device.model == "DIN-AP3"  # parsed from the firmware string prefix
        assert device.device_type == "AV Control System"
        assert "crestron" in device.discovered_by
        assert "v1.503" in device.crestron_data["firmware"]

    def test_rejects_wrong_control_byte(self):
        from oida.protocols.discovery.av import CrestronCIPScanner

        scanner = CrestronCIPScanner(interface="eth0")
        # Control byte 0x14 is the probe, not a reply.
        assert scanner._parse_response(b"\x14" + b"\x00" * 393, "1.2.3.4") is None

    def test_rejects_short_and_empty(self):
        from oida.protocols.discovery.av import CrestronCIPScanner

        scanner = CrestronCIPScanner(interface="eth0")
        assert scanner._parse_response(b"\x15short", "1.2.3.4") is None
        assert scanner._parse_response(b"", "1.2.3.4") is None


# ---------------------------------------------------------------------------
# Art-Net
# ---------------------------------------------------------------------------
def _artpollreply(ip, short_name: bytes, long_name: bytes, mac: bytes, oem=0x01A3, esta=0x7068):
    buf = bytearray(b"\x00" * 239)
    buf[0:8] = b"Art-Net\x00"
    struct.pack_into("<H", buf, 8, 0x2100)  # OpPollReply, LE on wire
    buf[10:14] = bytes(int(x) for x in ip.split("."))
    struct.pack_into("<H", buf, 14, 0x1936)  # Port 6454
    struct.pack_into(">H", buf, 20, oem)
    # EstaManLo/EstaManHi: the ESTA code is little-endian on the wire, unlike
    # the OemHi/OemLo field just above it.
    struct.pack_into("<H", buf, 24, esta)
    buf[26 : 26 + len(short_name)] = short_name
    buf[44 : 44 + len(long_name)] = long_name
    buf[201:207] = mac
    return bytes(buf)


GOLDEN_ARTNET = _artpollreply(
    "192.168.1.40", b"mynode", b"My Art-Net Node", bytes.fromhex("001122334455")
)


class TestArtNetProbe:
    def test_probe_exact_bytes(self):
        from oida.protocols.discovery.av import ArtNetScanner

        scanner = ArtNetScanner(interface="eth0")
        probe = scanner._build_probe()
        assert probe[:8] == b"Art-Net\x00"
        assert probe[8:10] == b"\x00\x20"  # OpPoll 0x2000, little-endian on wire
        assert probe[10:12] == b"\x00\x0e"  # ProtVer 14
        assert len(probe) == 14

    def test_constants(self):
        from oida.protocols.discovery.av import ArtNetScanner

        assert ArtNetScanner.PORT == 6454


class TestArtNetParseResponse:
    def test_golden_artpollreply(self):
        from oida.protocols.discovery.av import ArtNetScanner

        scanner = ArtNetScanner(interface="eth0")
        device = scanner._parse_response(GOLDEN_ARTNET, "192.168.1.40")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.40"]
        assert device.mac_address == "00:11:22:33:44:55"
        assert device.name == "mynode"
        assert device.model == "My Art-Net Node"
        assert device.artnet_data["esta_manufacturer"] == "0x7068"
        assert device.artnet_data["oem"] == "0x01a3"
        assert "artnet" in device.discovered_by

    def test_rejects_artpoll_not_reply(self):
        from oida.protocols.discovery.av import ArtNetScanner

        scanner = ArtNetScanner(interface="eth0")
        # An ArtPoll (OpCode 0x2000) is the request, not a reply.
        artpoll = b"Art-Net\x00" + struct.pack("<H", 0x2000) + b"\x00" * 229
        assert scanner._parse_response(artpoll, "1.2.3.4") is None

    def test_rejects_non_artnet(self):
        from oida.protocols.discovery.av import ArtNetScanner

        scanner = ArtNetScanner(interface="eth0")
        assert scanner._parse_response(b"not artnet", "1.2.3.4") is None
        assert scanner._parse_response(b"", "1.2.3.4") is None


class TestAVRegistration:
    def test_registered(self):
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS
        from oida.protocols.discovery.av import CrestronCIPScanner, ArtNetScanner

        assert _SCANNER_CONFIGS["crestron"][0] is CrestronCIPScanner
        assert _SCANNER_CONFIGS["artnet"][0] is ArtNetScanner
