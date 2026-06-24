"""
Tests for IP-camera active discovery scanners (oida.protocols.discovery.cameras).

Golden response bytes are modeled on the real Hikvision SADP ProbeMatch
documents described by three independent implementations:
- https://sergei.nz/reverse-engineering-hikvision-sadp-tool/
- https://github.com/4n4nk3/HikPwn/blob/master/hikpwn.py
- https://github.com/julienblitte/UniversalScanner/blob/master/UniversalScanner/Hikvision.cs
"""

import json
import re
import struct

import pytest


# Real-format SADP ProbeMatch reply (field set per the references above).
GOLDEN_PROBEMATCH = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b"<ProbeMatch>"
    b"<Uuid>13A888A9-F1B1-4020-AE9F-05607682D23B</Uuid>"
    b"<Types>inquiry</Types>"
    b"<DeviceType>1</DeviceType>"
    b"<DeviceDescription>DS-2CD2432F-IW</DeviceDescription>"
    b"<DeviceSN>DS-2CD2432F-IW20150101AAWR123456</DeviceSN>"
    b"<CommandPort>8000</CommandPort>"
    b"<HttpPort>80</HttpPort>"
    b"<MAC>44-19-b6-aa-bb-cc</MAC>"
    b"<IPv4Address>192.168.1.64</IPv4Address>"
    b"<IPv4SubnetMask>255.255.255.0</IPv4SubnetMask>"
    b"<IPv4Gateway>192.168.1.1</IPv4Gateway>"
    b"<IPv6Address>::</IPv6Address>"
    b"<DHCP>false</DHCP>"
    b"<SoftwareVersion>V5.3.0build 150513</SoftwareVersion>"
    b"<DSPVersion>V5.0build 150327</DSPVersion>"
    b"<BootTime>2024-01-15 08:30:00</BootTime>"
    b"<Activated>true</Activated>"
    b"<PasswordResetAbility>true</PasswordResetAbility>"
    b"</ProbeMatch>"
)


class TestHikvisionSADPInit:
    def test_valid_init(self):
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        scanner = HikvisionSADPScanner(interface="eth0", timeout=10)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 10
        assert scanner.discovered_devices == {}

    def test_init_invalid_interface_empty(self):
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        with pytest.raises(ValueError, match="cannot be empty"):
            HikvisionSADPScanner(interface="")

    def test_init_invalid_timeout(self):
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        with pytest.raises(ValueError, match="must be positive"):
            HikvisionSADPScanner(interface="eth0", timeout=0)

    def test_constants(self):
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        assert HikvisionSADPScanner.MULTICAST_ADDR == "239.255.255.250"
        assert HikvisionSADPScanner.PORT == 37020


class TestHikvisionSADPProbe:
    def test_probe_is_valid_inquiry(self):
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        scanner = HikvisionSADPScanner(interface="eth0")
        probe = scanner._build_probe()
        assert probe.startswith(b'<?xml version="1.0" encoding="utf-8"?>')
        assert b"<Types>inquiry</Types>" in probe
        # A real, parseable UUID is embedded as the session id.
        m = re.search(rb"<Uuid>([0-9A-F-]{36})</Uuid>", probe)
        assert m is not None

    def test_probe_uuid_is_fresh_each_call(self):
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        scanner = HikvisionSADPScanner(interface="eth0")
        assert scanner._build_probe() != scanner._build_probe()


class TestHikvisionSADPParseResponse:
    def test_golden_probematch(self):
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        scanner = HikvisionSADPScanner(interface="eth0")
        device = scanner._parse_response(GOLDEN_PROBEMATCH, "192.168.1.64")

        assert device is not None
        # Self-reported IPv4 wins over the packet source.
        assert device.ip_addresses == ["192.168.1.64"]
        assert device.mac_address == "44-19-b6-aa-bb-cc"
        assert device.manufacturer == "Hikvision"
        assert device.model == "DS-2CD2432F-IW"
        assert device.device_type == "Camera"
        assert "sadp" in device.discovered_by
        assert device.discovery_reasons == ["sadp:ProbeMatch"]

        data = device.sadp_data
        assert data["DeviceSN"] == "DS-2CD2432F-IW20150101AAWR123456"
        assert data["SoftwareVersion"] == "V5.3.0build 150513"
        assert data["DSPVersion"] == "V5.0build 150327"
        assert data["HttpPort"] == "80"
        assert data["CommandPort"] == "8000"
        assert data["IPv4Gateway"] == "192.168.1.1"
        assert data["Activated"] == "true"

    def test_falls_back_to_source_ip_when_no_ipv4(self):
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        scanner = HikvisionSADPScanner(interface="eth0")
        resp = (
            b"<ProbeMatch><DeviceDescription>DS-7608NI</DeviceDescription>"
            b"<MAC>aa-bb-cc-dd-ee-ff</MAC></ProbeMatch>"
        )
        device = scanner._parse_response(resp, "10.0.0.9")
        assert device is not None
        assert device.ip_addresses == ["10.0.0.9"]
        assert device.model == "DS-7608NI"

    def test_rejects_non_xml(self):
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        scanner = HikvisionSADPScanner(interface="eth0")
        assert scanner._parse_response(b"not xml at all", "1.2.3.4") is None
        assert scanner._parse_response(b"", "1.2.3.4") is None

    def test_rejects_our_own_probe(self):
        """A Probe (request) must not be mistaken for a ProbeMatch (reply)."""
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        scanner = HikvisionSADPScanner(interface="eth0")
        assert scanner._parse_response(scanner._build_probe(), "1.2.3.4") is None

    def test_rejects_empty_probematch(self):
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        scanner = HikvisionSADPScanner(interface="eth0")
        # Well-formed ProbeMatch but no recognizable device fields.
        resp = b"<ProbeMatch><Uuid>x</Uuid><Types>inquiry</Types></ProbeMatch>"
        assert scanner._parse_response(resp, "1.2.3.4") is None

    def test_malformed_xml_is_safe(self):
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        scanner = HikvisionSADPScanner(interface="eth0")
        # Contains the marker but is not well-formed XML.
        resp = b"<ProbeMatch><DeviceDescription>broken"
        assert scanner._parse_response(resp, "1.2.3.4") is None


class _FakeSADPSocket:
    """Minimal UDP socket stand-in that answers one SADP inquiry.

    Records what the scanner sends, then yields the golden ProbeMatch once
    (as if a camera replied), and raises TimeoutError thereafter so scan()'s
    recv loop terminates deterministically.
    """

    def __init__(self, reply: bytes, reply_from):
        self.reply = reply
        self.reply_from = reply_from
        self.sent = []
        self._served = False
        self.closed = False

    def sendto(self, data, addr):
        self.sent.append((data, addr))
        return len(data)

    def recvfrom(self, _bufsize):
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


class TestHikvisionSADPScanRoundTrip:
    """Exercise the full scan() loop against a fake responder (no kernel I/O)."""

    def test_scan_discovers_camera_end_to_end(self, monkeypatch):
        import oida.protocols.discovery.cameras as cameras
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        fake = _FakeSADPSocket(GOLDEN_PROBEMATCH, ("192.168.1.64", 37020))
        monkeypatch.setattr(cameras, "create_udp_socket", lambda *a, **k: fake)
        # Use the module-level rate-limited sendto seam so the probe is recorded.
        monkeypatch.setattr(cameras, "sendto", lambda sock, data, addr: sock.sendto(data, addr))

        scanner = HikvisionSADPScanner(interface="eth0", timeout=1)
        devices = scanner.scan()

        # Probe went to the SADP multicast group:port as an inquiry.
        assert fake.sent, "scanner sent no probe"
        probe, addr = fake.sent[0]
        assert addr == ("239.255.255.250", 37020)
        assert b"<Types>inquiry</Types>" in probe

        # The camera was discovered and keyed by its self-reported IP.
        assert "192.168.1.64" in devices
        device = devices["192.168.1.64"]
        assert device.manufacturer == "Hikvision"
        assert device.model == "DS-2CD2432F-IW"
        assert device.sadp_data["DeviceSN"] == "DS-2CD2432F-IW20150101AAWR123456"
        assert fake.closed, "socket should be closed after scan"

    def test_scan_ignores_unrelated_traffic(self, monkeypatch):
        import oida.protocols.discovery.cameras as cameras
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        fake = _FakeSADPSocket(b"unrelated multicast chatter", ("10.0.0.5", 37020))
        monkeypatch.setattr(cameras, "create_udp_socket", lambda *a, **k: fake)
        monkeypatch.setattr(cameras, "sendto", lambda sock, data, addr: sock.sendto(data, addr))

        scanner = HikvisionSADPScanner(interface="eth0", timeout=1)
        assert scanner.scan() == {}


# ---------------------------------------------------------------------------
# Dahua DHDiscover
# ---------------------------------------------------------------------------
def _dhip_frame(payload: bytes) -> bytes:
    """Wrap a JSON payload in the DHIP 32-byte header (per mcw0/DahuaConsole)."""
    n = len(payload)
    header = (
        b"\x20\x00\x00\x00DHIP"
        + b"\x00" * 8
        + struct.pack("<I", n)
        + b"\x00" * 4
        + struct.pack("<I", n)
        + b"\x00" * 4
    )
    return header + payload


# Real-format client.notifyDevInfo reply (deviceInfo field set per
# bozzzzo/dahua-tools + mcw0/DahuaConsole).
GOLDEN_DAHUA_JSON = json.dumps(
    {
        "mac": "3c:ef:8c:aa:bb:cc",
        "method": "client.notifyDevInfo",
        "params": {
            "deviceInfo": {
                "DeviceType": "IPC-HDW5421S",
                "SerialNo": "2K03A12YAZ00123",
                "Version": "2.400.0.8",
                "Vendor": "General",
                "HttpPort": 80,
                "Port": 37777,
                "IPv4Address": {
                    "IPAddress": "192.168.1.108",
                    "DefaultGateway": "192.168.1.1",
                    "SubnetMask": "255.255.255.0",
                    "DhcpEnable": False,
                },
            }
        },
    }
).encode()
GOLDEN_DAHUA = _dhip_frame(GOLDEN_DAHUA_JSON)


class TestDahuaInit:
    def test_valid_init(self):
        from oida.protocols.discovery.cameras import DahuaDHDiscoverScanner

        scanner = DahuaDHDiscoverScanner(interface="eth0", timeout=10)
        assert scanner.interface == "eth0"
        assert scanner.discovered_devices == {}

    def test_init_invalid_timeout(self):
        from oida.protocols.discovery.cameras import DahuaDHDiscoverScanner

        with pytest.raises(ValueError, match="must be positive"):
            DahuaDHDiscoverScanner(interface="eth0", timeout=0)

    def test_constants(self):
        from oida.protocols.discovery.cameras import DahuaDHDiscoverScanner

        assert DahuaDHDiscoverScanner.MULTICAST_ADDR == "239.255.255.251"
        assert DahuaDHDiscoverScanner.PORT == 37810


class TestDahuaProbe:
    def test_dhip_framing(self):
        from oida.protocols.discovery.cameras import DahuaDHDiscoverScanner

        scanner = DahuaDHDiscoverScanner(interface="eth0")
        probe = scanner._build_probe()
        # 32-byte DHIP header: magic + zeros + len + zeros + len + zeros
        assert probe[:8] == b"\x20\x00\x00\x00DHIP"
        assert probe[8:16] == b"\x00" * 8
        body = probe[32:]
        assert struct.unpack("<I", probe[16:20])[0] == len(body)
        assert struct.unpack("<I", probe[24:28])[0] == len(body)
        # Body is the DHDiscover.search request.
        obj = json.loads(body)
        assert obj["method"] == "DHDiscover.search"
        assert obj["params"] == {"mac": "", "uni": 1}


class TestDahuaParseResponse:
    def test_golden_dhip_framed(self):
        from oida.protocols.discovery.cameras import DahuaDHDiscoverScanner

        scanner = DahuaDHDiscoverScanner(interface="eth0")
        device = scanner._parse_response(GOLDEN_DAHUA, "192.168.1.108")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.108"]
        assert device.mac_address == "3c:ef:8c:aa:bb:cc"
        assert device.manufacturer == "Dahua"
        assert device.model == "IPC-HDW5421S"
        assert device.device_type == "Camera"
        assert "dahua" in device.discovered_by

        data = device.dahua_data
        assert data["SerialNo"] == "2K03A12YAZ00123"
        assert data["Version"] == "2.400.0.8"
        assert data["DefaultGateway"] == "192.168.1.1"
        assert data["Vendor"] == "General"

    def test_bare_json_without_dhip_header(self):
        """Some firmware replies without the DHIP header — still parse it."""
        from oida.protocols.discovery.cameras import DahuaDHDiscoverScanner

        scanner = DahuaDHDiscoverScanner(interface="eth0")
        device = scanner._parse_response(GOLDEN_DAHUA_JSON, "192.168.1.108")
        assert device is not None
        assert device.model == "IPC-HDW5421S"

    def test_rejects_non_dahua(self):
        from oida.protocols.discovery.cameras import DahuaDHDiscoverScanner

        scanner = DahuaDHDiscoverScanner(interface="eth0")
        assert scanner._parse_response(b"random udp chatter", "1.2.3.4") is None
        assert scanner._parse_response(b"", "1.2.3.4") is None
        # Valid JSON but no deviceInfo block.
        assert scanner._parse_response(b'{"params":{}}', "1.2.3.4") is None
        assert scanner._parse_response(_dhip_frame(b"{not json"), "1.2.3.4") is None


class TestDahuaScanRoundTrip:
    def test_scan_discovers_camera_end_to_end(self, monkeypatch):
        import oida.protocols.discovery.cameras as cameras
        from oida.protocols.discovery.cameras import DahuaDHDiscoverScanner

        fake = _FakeSADPSocket(GOLDEN_DAHUA, ("192.168.1.108", 37810))
        monkeypatch.setattr(cameras, "create_udp_socket", lambda *a, **k: fake)
        monkeypatch.setattr(cameras, "sendto", lambda sock, data, addr: sock.sendto(data, addr))

        scanner = DahuaDHDiscoverScanner(interface="eth0", timeout=1)
        devices = scanner.scan()

        probe, addr = fake.sent[0]
        assert addr == ("239.255.255.251", 37810)
        assert probe[:8] == b"\x20\x00\x00\x00DHIP"

        assert "192.168.1.108" in devices
        device = devices["192.168.1.108"]
        assert device.manufacturer == "Dahua"
        assert device.dahua_data["SerialNo"] == "2K03A12YAZ00123"
        assert fake.closed


class TestRegistration:
    def test_sadp_registered_in_scanner_configs(self):
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS
        from oida.protocols.discovery.cameras import HikvisionSADPScanner

        assert "sadp" in _SCANNER_CONFIGS
        cls = _SCANNER_CONFIGS["sadp"][0]
        assert cls is HikvisionSADPScanner

    def test_dahua_registered_in_scanner_configs(self):
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS
        from oida.protocols.discovery.cameras import DahuaDHDiscoverScanner

        assert "dahua" in _SCANNER_CONFIGS
        assert _SCANNER_CONFIGS["dahua"][0] is DahuaDHDiscoverScanner
