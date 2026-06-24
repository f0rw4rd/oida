"""
Tests for Digi ADDP and SLP discovery scanners.

Golden bytes / probe layouts taken verbatim from the authoritative sources:
- ADDP: https://raw.githubusercontent.com/christophgysin/addp/master/doc/protocol
        request `44 49 47 49 00 01 00 06 FF FF FF FF FF FF` is quoted verbatim.
- SLP:  RFC 2608 https://www.ietf.org/rfc/rfc2608.txt
        the 54-byte SrvRqst is computed per the RFC SrvRqst diagram.
"""

import struct


# ---------------------------------------------------------------------------
# Digi ADDP
# ---------------------------------------------------------------------------
def _addp_tlv(t, v):
    return bytes([t, len(v)]) + v


def _addp_response():
    payload = (
        _addp_tlv(0x01, bytes.fromhex("00409dabcdef"))  # MAC
        + _addp_tlv(0x02, bytes([192, 168, 1, 30]))  # IP
        + _addp_tlv(0x03, bytes([255, 255, 255, 0]))  # netmask
        + _addp_tlv(0x0B, bytes([192, 168, 1, 1]))  # gateway
        + _addp_tlv(0x0D, b"Digi Connect")  # device name
        + _addp_tlv(0x06, b"Digi Connect ME")  # hardware type
        + _addp_tlv(0x08, b"82000856_F")  # firmware
        + _addp_tlv(0x12, bytes([1]))  # serial-port count
    )
    return b"DIGI" + struct.pack(">HH", 0x0002, len(payload)) + payload


class TestADDPProbe:
    def test_probe_is_verbatim_reference(self):
        from oida.protocols.discovery.vendor import ADDPScanner

        scanner = ADDPScanner(interface="eth0")
        # Verbatim from christophgysin/addp doc/protocol hex dump.
        assert scanner._build_probe() == bytes.fromhex("4449474900010006ffffffffffff")

    def test_constants(self):
        from oida.protocols.discovery.vendor import ADDPScanner

        assert ADDPScanner.MULTICAST_ADDR == "224.0.5.128"
        assert ADDPScanner.PORT == 2362


class TestADDPParse:
    def test_golden_response(self):
        from oida.protocols.discovery.vendor import ADDPScanner

        scanner = ADDPScanner(interface="eth0")
        device = scanner._parse_response(_addp_response(), "192.168.1.30")

        assert device is not None
        assert device.mac_address == "00:40:9d:ab:cd:ef"
        assert device.ip_addresses == ["192.168.1.30"]
        assert device.manufacturer == "Digi"
        assert device.model == "Digi Connect ME"
        assert device.name == "Digi Connect"
        assert device.addp_data["firmware"] == "82000856_F"
        assert device.addp_data["gateway"] == "192.168.1.1"
        assert device.addp_data["serial_ports"] == 1
        assert "addp" in device.discovered_by

    def test_rejects_request_type_and_junk(self):
        from oida.protocols.discovery.vendor import ADDPScanner

        scanner = ADDPScanner(interface="eth0")
        # Discovery Request type 0x0001 is not a response.
        assert scanner._parse_response(b"DIGI" + struct.pack(">HH", 0x0001, 0), "1.2.3.4") is None
        assert scanner._parse_response(b"XXXX1234", "1.2.3.4") is None
        assert scanner._parse_response(b"", "1.2.3.4") is None


# ---------------------------------------------------------------------------
# SLP
# ---------------------------------------------------------------------------
def _slp_srvrply(url="service:service-agent://192.168.1.10"):
    url_b = url.encode()
    entry = b"\x00" + struct.pack(">H", 0xFFFF) + struct.pack(">H", len(url_b)) + url_b + b"\x00"
    body = struct.pack(">H", 0) + struct.pack(">H", 1) + entry  # error=0, count=1
    header = (
        bytes((2, 2))  # version, function-id=SrvRply
        + (14 + 2 + len(body)).to_bytes(3, "big")
        + struct.pack(">H", 0)  # flags
        + (0).to_bytes(3, "big")  # next-ext
        + struct.pack(">H", 1)  # XID
        + struct.pack(">H", 2)  # lang-tag len
        + b"en"
    )
    return header + body


class TestSLPProbe:
    def test_probe_matches_rfc_computed_golden(self):
        from oida.protocols.discovery.infra import SLPScanner

        scanner = SLPScanner(interface="eth0")
        # 54-byte SrvRqst for service:service-agent / scope DEFAULT (RFC 2608).
        expected = bytes.fromhex(
            "0201000036200000000000010002656e"  # "en"
        ) + (
            struct.pack(">H", 0)
            + struct.pack(">H", 21)
            + b"service:service-agent"
            + struct.pack(">H", 7)
            + b"DEFAULT"
            + struct.pack(">H", 0)
            + struct.pack(">H", 0)
        )
        assert scanner._build_probe() == expected
        assert len(scanner._build_probe()) == 54

    def test_constants(self):
        from oida.protocols.discovery.infra import SLPScanner

        assert SLPScanner.MULTICAST_ADDR == "239.255.255.253"
        assert SLPScanner.PORT == 427


class TestSLPParse:
    def test_srvrply_urls(self):
        from oida.protocols.discovery.infra import SLPScanner

        scanner = SLPScanner(interface="eth0")
        device = scanner._parse_response(_slp_srvrply(), "192.168.1.10")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.10"]
        assert device.device_type == "SLP Service Agent"
        assert device.slp_data["message"] == "SrvRply"
        assert device.slp_data["urls"] == ["service:service-agent://192.168.1.10"]
        assert "slp" in device.discovered_by

    def test_rejects_wrong_version(self):
        from oida.protocols.discovery.infra import SLPScanner

        scanner = SLPScanner(interface="eth0")
        assert scanner._parse_response(b"\x01" + b"\x00" * 20, "1.2.3.4") is None
        assert scanner._parse_response(b"", "1.2.3.4") is None


class TestRegistration:
    def test_registered(self):
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS
        from oida.protocols.discovery.vendor import ADDPScanner
        from oida.protocols.discovery.infra import SLPScanner

        assert _SCANNER_CONFIGS["addp"][0] is ADDPScanner
        assert _SCANNER_CONFIGS["slp"][0] is SLPScanner
