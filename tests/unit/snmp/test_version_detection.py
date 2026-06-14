"""
Unit tests for VersionDetectionMixin.

Covers the pure RFC 3411 engine-ID decoder across every format indicator, and
the version-selection / finding logic of _detect_versions with the parallel
probe coroutine mocked at asyncio.run.
"""

from __future__ import annotations

import socket
import struct
from unittest.mock import patch


def _pen_bytes(pen: int) -> bytes:
    """Encode an enterprise PEN with the RFC 3411 high bit set in 4 bytes."""
    return struct.pack("!I", pen | 0x80000000)


class TestDecodeEngineId:
    def test_ipv4_format(self):
        from oida.protocols.snmp.scanner import SNMPScanner

        raw = _pen_bytes(8072) + bytes([1]) + socket.inet_aton("10.20.30.40")
        info = SNMPScanner._decode_engine_id(raw)
        assert info["enterprise"] == 8072
        assert info["format"] == 1
        assert info["format_name"] == "IPv4"
        assert info["decoded"] == "10.20.30.40"

    def test_mac_format(self):
        from oida.protocols.snmp.scanner import SNMPScanner

        raw = _pen_bytes(9) + bytes([3]) + bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        info = SNMPScanner._decode_engine_id(raw)
        assert info["format_name"] == "MAC"
        assert info["decoded"] == "aa:bb:cc:dd:ee:ff"
        # PEN 9 is Cisco in VENDOR_OIDS
        assert info["enterprise"] == 9

    def test_text_format(self):
        from oida.protocols.snmp.scanner import SNMPScanner

        raw = _pen_bytes(4329) + bytes([4]) + b"plc-01"
        info = SNMPScanner._decode_engine_id(raw)
        assert info["format_name"] == "text"
        assert info["decoded"] == "plc-01"
        assert info["enterprise"] == 4329

    def test_octets_format(self):
        from oida.protocols.snmp.scanner import SNMPScanner

        raw = _pen_bytes(1) + bytes([5]) + bytes([0xDE, 0xAD, 0xBE, 0xEF])
        info = SNMPScanner._decode_engine_id(raw)
        assert info["format_name"] == "octets"
        assert info["decoded"] == "deadbeef"

    def test_ipv6_format(self):
        from oida.protocols.snmp.scanner import SNMPScanner

        addr = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        raw = _pen_bytes(311) + bytes([2]) + addr
        info = SNMPScanner._decode_engine_id(raw)
        assert info["format_name"] == "IPv6"
        assert info["decoded"] == "2001:db8::1"

    def test_unknown_format_falls_back_to_hex(self):
        from oida.protocols.snmp.scanner import SNMPScanner

        raw = _pen_bytes(99999) + bytes([7]) + bytes([0x01, 0x02])
        info = SNMPScanner._decode_engine_id(raw)
        assert "enterprise-specific(7)" in info["format_name"]
        assert info["decoded"] == "0102"

    def test_too_short_raw_returns_hex_only(self):
        from oida.protocols.snmp.scanner import SNMPScanner

        raw = bytes([0x01, 0x02, 0x03])
        info = SNMPScanner._decode_engine_id(raw)
        assert info["hex"] == "010203"
        assert info["decoded"] == "010203"
        assert "enterprise" not in info

    def test_enterprise_name_resolves_known_vendor(self):
        from oida.protocols.snmp.scanner import SNMPScanner

        # 4329 -> Siemens in VENDOR_OIDS
        raw = _pen_bytes(4329) + bytes([4]) + b"x"
        info = SNMPScanner._decode_engine_id(raw)
        assert info["enterprise_name"] == "Siemens"

    def test_high_bit_is_masked_off(self):
        from oida.protocols.snmp.scanner import SNMPScanner

        # If the high bit were not masked, enterprise would be huge.
        raw = _pen_bytes(8) + bytes([4]) + b"a"
        info = SNMPScanner._decode_engine_id(raw)
        assert info["enterprise"] == 8


class TestDetectVersions:
    def _make(self, **kw):
        from oida.protocols.snmp.scanner import SNMPScanner

        args = {"host": "10.0.0.5", "port": 161, "timeout": 1, "snmp_version": "auto"}
        args.update(kw)
        return SNMPScanner(args)

    def test_prefers_v2c_over_v3_and_v1(self):
        s = self._make()
        results = [("1", True, "x"), ("2c", True, "y"), ("3", True, "z")]
        with patch(
            "oida.protocols.snmp.mixins.version_detection.asyncio.run", return_value=results
        ):
            out = s._detect_versions()
        assert out["best_version"] == "2c"
        assert out["supported_versions"] == ["1", "2c", "3"]

    def test_v3_only_selected_when_no_v2c(self):
        s = self._make()
        results = [("1", False, None), ("2c", False, None), ("3", True, "engine")]
        with patch(
            "oida.protocols.snmp.mixins.version_detection.asyncio.run", return_value=results
        ):
            out = s._detect_versions()
        assert out["best_version"] == "3"
        assert out["supported_versions"] == ["3"]

    def test_v1_finding_emitted(self):
        s = self._make()
        s.logger = _RecLogger()
        results = [("1", True, "x"), ("2c", False, None), ("3", False, None)]
        with patch(
            "oida.protocols.snmp.mixins.version_detection.asyncio.run", return_value=results
        ):
            s._detect_versions()
        assert "Legacy protocol" in s.logger.titles

    def test_no_versions_supported_falls_back_to_current(self):
        s = self._make()
        results = [("1", False, None), ("2c", False, None), ("3", False, None)]
        with patch(
            "oida.protocols.snmp.mixins.version_detection.asyncio.run", return_value=results
        ):
            out = s._detect_versions()
        assert out["supported_versions"] == []
        assert out["best_version"] == s.version

    def test_exceptions_in_probe_results_are_ignored(self):
        s = self._make()
        results = [RuntimeError("boom"), ("2c", True, "ok"), ("3", False, None)]
        with patch(
            "oida.protocols.snmp.mixins.version_detection.asyncio.run", return_value=results
        ):
            out = s._detect_versions()
        assert out["best_version"] == "2c"


class _RecLogger:
    def __init__(self):
        self.titles = []

    def security_finding(self, title, *a, **k):
        self.titles.append(title)

    def __getattr__(self, name):
        return lambda *a, **k: None
