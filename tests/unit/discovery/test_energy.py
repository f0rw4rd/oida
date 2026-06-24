"""
Tests for energy/solar active discovery scanners (oida.protocols.discovery.energy).

Probe + discovery-response magic are taken verbatim from the FHEM SMA-Speedwire
tool: https://github.com/kettenbach-it/FHEM-SMA-Speedwire/blob/master/discover.py
"""

import pytest


# Verbatim probe + discovery-response prefix from the FHEM reference.
SMA_PROBE = bytes.fromhex("534d4100000402a0ffffffff0000002000000000")
SMA_DISCOVERY_RESPONSE = bytes.fromhex("534d4100000402a000000001000200000001") + b"\x00" * 20


class _FakeSMASocket:
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


class TestSMAInit:
    def test_valid_init(self):
        from oida.protocols.discovery.energy import SMASpeedwireScanner

        scanner = SMASpeedwireScanner(interface="eth0", timeout=10)
        assert scanner.interface == "eth0"
        assert scanner.discovered_devices == {}

    def test_init_invalid_timeout(self):
        from oida.protocols.discovery.energy import SMASpeedwireScanner

        with pytest.raises(ValueError, match="must be positive"):
            SMASpeedwireScanner(interface="eth0", timeout=0)

    def test_constants(self):
        from oida.protocols.discovery.energy import SMASpeedwireScanner

        assert SMASpeedwireScanner.MULTICAST_ADDR == "239.12.255.254"
        assert SMASpeedwireScanner.PORT == 9522
        assert SMASpeedwireScanner.SMA_MAGIC == b"SMA\x00"


class TestSMAProbe:
    def test_probe_is_exact_reference_bytes(self):
        from oida.protocols.discovery.energy import SMASpeedwireScanner

        scanner = SMASpeedwireScanner(interface="eth0")
        assert scanner._build_probe() == SMA_PROBE
        assert scanner._build_probe().startswith(b"SMA\x00")
        assert len(scanner._build_probe()) == 20


class TestSMAParseResponse:
    def test_discovery_response_recognized(self):
        from oida.protocols.discovery.energy import SMASpeedwireScanner

        scanner = SMASpeedwireScanner(interface="eth0")
        device = scanner._parse_response(SMA_DISCOVERY_RESPONSE, "192.168.1.50")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.50"]
        assert device.manufacturer == "SMA"
        assert device.device_type == "Solar Inverter / Energy Meter"
        assert "sma" in device.discovered_by
        assert device.sma_data["discovery_response"] is True

    def test_any_sma_magic_datagram_recognized(self):
        """Energy-meter datagrams also start with SMA\\0 — recognize them too."""
        from oida.protocols.discovery.energy import SMASpeedwireScanner

        scanner = SMASpeedwireScanner(interface="eth0")
        # An energy-meter style datagram (SMA\0 magic, different tag payload).
        meter = b"SMA\x00" + bytes.fromhex("00046069") + b"\x00" * 40
        device = scanner._parse_response(meter, "192.168.1.51")
        assert device is not None
        assert device.manufacturer == "SMA"
        assert device.sma_data["discovery_response"] is False

    def test_rejects_non_sma(self):
        from oida.protocols.discovery.energy import SMASpeedwireScanner

        scanner = SMASpeedwireScanner(interface="eth0")
        assert scanner._parse_response(b"not an sma packet", "1.2.3.4") is None
        assert scanner._parse_response(b"", "1.2.3.4") is None
        assert scanner._parse_response(b"SMB\x00xxxx", "1.2.3.4") is None


class TestSMAScanRoundTrip:
    def test_scan_discovers_device_end_to_end(self, monkeypatch):
        import oida.protocols.discovery.energy as energy
        from oida.protocols.discovery.energy import SMASpeedwireScanner

        fake = _FakeSMASocket(SMA_DISCOVERY_RESPONSE, ("192.168.1.50", 9522))
        monkeypatch.setattr(energy, "create_udp_socket", lambda *a, **k: fake)
        monkeypatch.setattr(energy, "sendto", lambda sock, data, addr: sock.sendto(data, addr))

        scanner = SMASpeedwireScanner(interface="eth0", timeout=1)
        devices = scanner.scan()

        probe, addr = fake.sent[0]
        assert addr == ("239.12.255.254", 9522)
        assert probe == SMA_PROBE

        assert "192.168.1.50" in devices
        assert devices["192.168.1.50"].manufacturer == "SMA"
        assert fake.closed


class TestSMARegistration:
    def test_sma_registered(self):
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS
        from oida.protocols.discovery.energy import SMASpeedwireScanner

        assert "sma" in _SCANNER_CONFIGS
        assert _SCANNER_CONFIGS["sma"][0] is SMASpeedwireScanner
