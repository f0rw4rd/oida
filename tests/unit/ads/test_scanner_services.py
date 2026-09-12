#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for the ADS scanner's SystemService / License / IO / UDP
discovery paths and the TwinCAT-2 security branch.

Targets previously-uncovered methods of
src/oida/protocols/ads/scanner.py:

- _scan_routes (route-list parsing + 1814 "no more entries" termination)
- _get_target_desc (XML description retrieval over SystemService)
- _check_secure_ads (Secure ADS / TLS probe on port 8016)
- _query_license_info (License Service on port 30)
- _enumerate_io_devices (IO port 300 device walk)
- _udp_discovery + _parse_udp_response (Beckhoff UDP identify)
- _detect_twincat_version / TC2 clear-text security branch

Only the pyads boundary and the raw socket boundary are mocked; the
real ADS framing/parsing logic runs against realistic buffers.
"""

import ctypes
import struct
import unittest
from unittest.mock import Mock, patch

from oida.protocols.ads import ADSScanner
from oida.protocols.ads.constants import (
    ADS_IDX_GRP,
    ADS_UDP_MAGIC,
    ADS_UDP_TAG,
)


def _ctype_bytes(payload: bytes):
    """Return a ctypes c_byte array initialised from *payload*.

    Mirrors what pyads Connection.read(..., return_ctypes=True) yields, so
    the real _read_raw() helper (which wraps the result in bytes()) runs
    unchanged against our mock connection.
    """
    arr = (ctypes.c_byte * len(payload))()
    for i, b in enumerate(payload):
        arr[i] = b - 256 if b > 127 else b
    return arr


class FakeSysConn:
    """Mock pyads Connection driven by a per-(group, offset) response table.

    Keys may be (group, offset) for an exact match or (group,) as a wildcard
    over any offset. A callable value is invoked with (offset, size); a
    bytes value is returned (zero-padded/truncated to size); an Exception
    instance is raised.
    """

    def __init__(self, table):
        self.table = table
        self.opened = False
        self.closed = False
        self.timeout_ms = None

    def open(self):
        self.opened = True

    def close(self):
        self.closed = True

    def set_timeout(self, ms):
        self.timeout_ms = ms

    def read(self, group, offset, ctype, return_ctypes=False):
        size = ctypes.sizeof(ctype)
        resp = self.table.get((group, offset), self.table.get((group,)))
        if resp is None:
            raise Exception("ADS error 1793: device not found")
        if isinstance(resp, Exception):
            raise resp
        if callable(resp):
            resp = resp(offset, size)
        if isinstance(resp, Exception):
            raise resp
        payload = bytes(resp)[:size].ljust(size, b"\x00")
        return _ctype_bytes(payload)


def _make_scanner():
    return ADSScanner({"host": "192.168.1.100", "port": 48898})


# ---------------------------------------------------------------------------
# _scan_routes
# ---------------------------------------------------------------------------


class TestScanRoutes(unittest.TestCase):
    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_scan_routes_parses_named_routes(self, mock_get_pyads):
        """Two valid route entries are parsed, then 1814 ends the walk."""
        scanner = _make_scanner()

        def route_resp(name):
            # 44-byte header + null-terminated route name string
            return b"\x00" * 44 + name.encode() + b"\x00"

        group = ADS_IDX_GRP["ROUTE_LIST"]
        table = {
            (group, 0): route_resp("EngineeringStation"),
            (group, 1): route_resp("HMI-Panel"),
            (group, 2): Exception("ADS error 1814: no more entries"),
        }
        sys_conn = FakeSysConn(table)
        mock_pyads = Mock()
        mock_pyads.Connection.return_value = sys_conn
        mock_get_pyads.return_value = mock_pyads

        routes = scanner._scan_routes(Mock())

        # SystemService connection used on port 10000
        mock_pyads.Connection.assert_called_with("192.168.1.100.1.1", 10000)
        self.assertTrue(sys_conn.closed)
        names = [r["name"] for r in routes["discovered"]]
        self.assertEqual(names, ["EngineeringStation", "HMI-Panel"])
        self.assertEqual(routes["target"]["netid"], "192.168.1.100.1.1")
        # No probe fallback since routes were discovered
        self.assertNotIn("discovered_by_probe", routes)

    @patch("oida.protocols.ads.scanner._probe_netid")
    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_scan_routes_falls_back_to_probe(self, mock_get_pyads, mock_probe):
        """SystemService connect failure triggers the Net ID probe fallback."""
        scanner = _make_scanner()
        scanner.ads_timeout_ms = 100

        mock_pyads = Mock()
        mock_pyads.Connection.side_effect = Exception("SystemService refused")
        mock_get_pyads.return_value = mock_pyads

        # First probed extension is active, rest inactive
        def probe(_pyads, netid, _port, timeout_ms=0):
            if netid.endswith("1.2"):
                return {"active": True, "type": "device_info", "detail": "TC3", "broken": False}
            return {"active": False, "type": "timeout", "detail": "no answer", "broken": False}

        mock_probe.side_effect = probe

        routes = scanner._scan_routes(Mock())

        self.assertIn("error", routes)
        self.assertIn("discovered_by_probe", routes)
        self.assertEqual(len(routes["discovered_by_probe"]), 1)
        self.assertEqual(routes["discovered_by_probe"][0]["ext"], "1.2")

    @patch("oida.protocols.ads.scanner._probe_netid")
    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_scan_routes_aborts_after_consecutive_errors(self, mock_get_pyads, mock_probe):
        """3 consecutive non-1814 read errors abort the walk and trigger probe."""
        scanner = _make_scanner()
        group = ADS_IDX_GRP["ROUTE_LIST"]
        # Every offset raises a generic (non-1814) error -> 3 strikes -> abort
        sys_conn = FakeSysConn({(group,): Exception("ADS error 1793: timeout")})
        mock_pyads = Mock()
        mock_pyads.Connection.return_value = sys_conn
        mock_get_pyads.return_value = mock_pyads
        mock_probe.return_value = {
            "active": False,
            "type": "timeout",
            "detail": "no answer",
            "broken": False,
        }

        routes = scanner._scan_routes(Mock())

        self.assertEqual(routes["discovered"], [])
        # Probe fallback was attempted (sysservice_failed set after 3 errors)
        self.assertTrue(mock_probe.called)

    @patch("oida.protocols.ads.scanner._probe_netid")
    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_scan_routes_probe_stops_on_broken_router(self, mock_get_pyads, mock_probe):
        """A 'broken' probe result aborts the extension sweep immediately."""
        scanner = _make_scanner()

        mock_pyads = Mock()
        mock_pyads.Connection.side_effect = Exception("denied")
        mock_get_pyads.return_value = mock_pyads
        mock_probe.return_value = {
            "active": False,
            "type": "broken",
            "detail": "router lost",
            "broken": True,
        }

        routes = scanner._scan_routes(Mock())

        # Sweep aborted after first broken result -> only one probe attempted
        self.assertEqual(mock_probe.call_count, 1)
        self.assertEqual(routes.get("discovered_by_probe"), None)


# ---------------------------------------------------------------------------
# _get_target_desc
# ---------------------------------------------------------------------------


class TestGetTargetDesc(unittest.TestCase):
    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_get_target_desc_parses_xml(self, mock_get_pyads):
        scanner = _make_scanner()
        xml = b"<Device><Name>CX2040</Name><Version>3.1.4024</Version></Device>"
        group = ADS_IDX_GRP["TC_XML"]

        def resp(offset, size):
            if size == 4:  # length probe
                return struct.pack("<I", len(xml))
            return xml

        sys_conn = FakeSysConn({(group, 0x00000001): resp})
        mock_pyads = Mock()
        mock_pyads.Connection.return_value = sys_conn
        mock_get_pyads.return_value = mock_pyads

        result = scanner._get_target_desc(Mock())

        self.assertTrue(result["success"])
        self.assertIn("CX2040", result["xml"])
        self.assertEqual(result["parsed"]["name"], "CX2040")
        self.assertEqual(result["parsed"]["version"], "3.1.4024")

    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_get_target_desc_rejects_insane_length(self, mock_get_pyads):
        """A length over the 1,000,000 sanity cap is not read as XML."""
        scanner = _make_scanner()
        group = ADS_IDX_GRP["TC_XML"]
        sys_conn = FakeSysConn({(group, 0x00000001): struct.pack("<I", 5_000_000)})
        mock_pyads = Mock()
        mock_pyads.Connection.return_value = sys_conn
        mock_get_pyads.return_value = mock_pyads

        result = scanner._get_target_desc(Mock())

        self.assertFalse(result["success"])
        self.assertIsNone(result["xml"])


# ---------------------------------------------------------------------------
# _check_secure_ads
# ---------------------------------------------------------------------------


class TestCheckSecureADS(unittest.TestCase):
    @patch("oida.utils.socket_helpers.build_tls_context")
    @patch("socket.create_connection")
    def test_secure_ads_available(self, mock_create_conn, mock_build_ctx):
        scanner = _make_scanner()

        raw_sock = Mock()
        mock_create_conn.return_value = raw_sock

        tls_sock = Mock()
        tls_sock.version.return_value = "TLSv1.2"
        tls_sock.getpeercert.return_value = None  # skip cert analysis branch
        ctx = Mock()
        ctx.wrap_socket.return_value = tls_sock
        mock_build_ctx.return_value = ctx

        result = scanner._check_secure_ads()

        self.assertTrue(result["available"])
        self.assertEqual(result["port"], 8016)
        self.assertEqual(result["tls_version"], "TLSv1.2")
        mock_create_conn.assert_called_once()
        tls_sock.close.assert_called_once()

    @patch("oida.utils.socket_helpers.build_tls_context")
    @patch("socket.create_connection")
    def test_secure_ads_connection_refused(self, mock_create_conn, mock_build_ctx):
        scanner = _make_scanner()
        mock_build_ctx.return_value = Mock()
        mock_create_conn.side_effect = ConnectionRefusedError()

        result = scanner._check_secure_ads()

        self.assertFalse(result["available"])
        self.assertEqual(result["error"], "Connection refused")

    @patch("oida.utils.security_findings.display_cert_info")
    @patch("oida.utils.socket_helpers.build_tls_context")
    @patch("socket.create_connection")
    def test_secure_ads_collects_cert_issues(
        self, mock_create_conn, mock_build_ctx, mock_cert_info
    ):
        """When a peer cert is present, its issues are folded into the result."""
        scanner = _make_scanner()
        scanner.args = Mock(verbose=0)

        mock_create_conn.return_value = Mock()
        tls_sock = Mock()
        tls_sock.version.return_value = "TLSv1.2"
        tls_sock.getpeercert.return_value = b"\x30\x82DERCERT"
        ctx = Mock()
        ctx.wrap_socket.return_value = tls_sock
        mock_build_ctx.return_value = ctx
        mock_cert_info.return_value = {"issues": ["Self-signed certificate"]}

        result = scanner._check_secure_ads()

        self.assertTrue(result["available"])
        self.assertIn("Self-signed certificate", result["issues"])
        mock_cert_info.assert_called_once()

    @patch("oida.utils.socket_helpers.build_tls_context")
    @patch("socket.create_connection")
    def test_secure_ads_tls_handshake_error(self, mock_create_conn, mock_build_ctx):
        import ssl

        scanner = _make_scanner()
        raw_sock = Mock()
        mock_create_conn.return_value = raw_sock
        ctx = Mock()
        ctx.wrap_socket.side_effect = ssl.SSLError("handshake failed")
        mock_build_ctx.return_value = ctx

        result = scanner._check_secure_ads()

        self.assertFalse(result["available"])
        self.assertIn("TLS error", result["error"])
        raw_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# _query_license_info
# ---------------------------------------------------------------------------


class TestQueryLicenseInfo(unittest.TestCase):
    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_query_license_info_full(self, mock_get_pyads):
        scanner = _make_scanner()
        dev = ADS_IDX_GRP["LIC_DEV_INFO"]
        online = ADS_IDX_GRP["LIC_ONLINE"]

        table = {
            (dev, 0x1): bytes(range(16)),  # SystemID GUID (16 bytes)
            (dev, 0x2): struct.pack("<H", 50),  # PlatformID
            (dev, 0x5): struct.pack("<I", 12345),  # VolumeNo
            (online, 0x0): struct.pack("<I", 7),  # License count
        }
        lic_conn = FakeSysConn(table)
        mock_pyads = Mock()
        mock_pyads.Connection.return_value = lic_conn
        mock_get_pyads.return_value = mock_pyads

        result = scanner._query_license_info(Mock())

        mock_pyads.Connection.assert_called_with("192.168.1.100.1.1", 30)
        self.assertTrue(result["success"])
        self.assertEqual(result["platform_id"], 50)
        self.assertEqual(result["volume_no"], 12345)
        self.assertEqual(result["license_count"], 7)
        self.assertEqual(result["system_id"], bytes(range(16)).hex())
        self.assertTrue(lic_conn.closed)

    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_query_license_info_per_field_failures(self, mock_get_pyads):
        """Individual field reads can fail; the count read still drives success."""
        scanner = _make_scanner()
        dev = ADS_IDX_GRP["LIC_DEV_INFO"]
        online = ADS_IDX_GRP["LIC_ONLINE"]

        table = {
            (dev, 0x1): Exception("systemid denied"),
            (dev, 0x2): Exception("platform denied"),
            (dev, 0x5): Exception("volume denied"),
            (online, 0x0): struct.pack("<I", 3),  # only the count succeeds
        }
        lic_conn = FakeSysConn(table)
        mock_pyads = Mock()
        mock_pyads.Connection.return_value = lic_conn
        mock_get_pyads.return_value = mock_pyads

        result = scanner._query_license_info(Mock())

        self.assertTrue(result["success"])
        self.assertIsNone(result["system_id"])
        self.assertIsNone(result["platform_id"])
        self.assertEqual(result["license_count"], 3)
        self.assertTrue(lic_conn.closed)

    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_query_license_info_connect_fails(self, mock_get_pyads):
        scanner = _make_scanner()
        mock_pyads = Mock()
        mock_pyads.Connection.side_effect = Exception("license service down")
        mock_get_pyads.return_value = mock_pyads

        result = scanner._query_license_info(Mock())

        self.assertFalse(result["success"])
        self.assertIn("license service down", result["error"])


# ---------------------------------------------------------------------------
# _enumerate_io_devices
# ---------------------------------------------------------------------------


class TestEnumerateIODevices(unittest.TestCase):
    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_enumerate_io_devices_two_devices(self, mock_get_pyads):
        scanner = _make_scanner()
        base = ADS_IDX_GRP["IO_DEV_STATE"]

        # Device count = 2; id table = count(2) + ids [10, 20]
        id_table = struct.pack("<H", 2) + struct.pack("<HH", 10, 20)

        table = {
            (base, 0x2): struct.pack("<I", 2),  # device count
            (base, 0x1): id_table,  # device id list
            # Per-device type (offset 0x7) and name (offset 0x1) at base+dev_id
            (base + 10, 0x7): struct.pack("<H", 1),
            (base + 10, 0x1): b"EK1100\x00",
            (base + 20, 0x7): struct.pack("<H", 2),
            (base + 20, 0x1): b"EL2008\x00",
        }
        io_conn = FakeSysConn(table)
        mock_pyads = Mock()
        mock_pyads.Connection.return_value = io_conn
        mock_get_pyads.return_value = mock_pyads

        result = scanner._enumerate_io_devices(Mock())

        mock_pyads.Connection.assert_called_with("192.168.1.100.1.1", 300)
        self.assertTrue(result["success"])
        self.assertEqual(result["device_count"], 2)
        names = sorted(d.get("name") for d in result["devices"])
        self.assertEqual(names, ["EK1100", "EL2008"])

    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_enumerate_io_devices_redirects_non_plc_netid(self, mock_get_pyads):
        """Targeting .2.1 (EtherCAT) redirects IO enumeration to .1.1."""
        scanner = ADSScanner(
            {"host": "192.168.1.100", "port": 48898, "ams-netid": "192.168.1.100.2.1"}
        )
        io_conn = FakeSysConn({(ADS_IDX_GRP["IO_DEV_STATE"], 0x2): struct.pack("<I", 0)})
        mock_pyads = Mock()
        mock_pyads.Connection.return_value = io_conn
        mock_get_pyads.return_value = mock_pyads

        scanner._enumerate_io_devices(Mock())

        # Redirected to the .1.1 runtime NetID
        mock_pyads.Connection.assert_called_with("192.168.1.100.1.1", 300)

    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_enumerate_io_devices_connect_fails(self, mock_get_pyads):
        scanner = _make_scanner()
        mock_pyads = Mock()
        mock_pyads.Connection.side_effect = Exception("io port closed")
        mock_get_pyads.return_value = mock_pyads

        result = scanner._enumerate_io_devices(Mock())

        self.assertFalse(result["success"])
        self.assertIn("io port closed", result["error"])


# ---------------------------------------------------------------------------
# _udp_discovery + _parse_udp_response
# ---------------------------------------------------------------------------


class FakeUDPSocket:
    """Minimal datagram socket double that replays a fixed response then times out."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = []

    def settimeout(self, _t):
        pass

    def setsockopt(self, *_a):
        pass

    def sendto(self, data, dest):
        self.sent.append((data, dest))

    def recvfrom(self, _bufsize):
        if self._responses:
            return self._responses.pop(0)
        raise TimeoutError()

    def close(self):
        pass


def _build_udp_response(hostname="CX-012345", netid="192.168.1.100.1.1"):
    """Build a Beckhoff UDP identify reply in the real wire layout.

    Layout cross-checked against pyads ``adsGetNetIdForPLC`` (NetID at bytes
    12-18, response flag 0x80 at byte 11) and ICSSecurityScripts
    BeckhoffScan.py ``getDevices`` (hostname length LE16 at bytes 26-28,
    hostname at byte 28, kernel/TC-version fixed fields, then <HH> TLV
    blocks). The old helper emitted header + bare TLVs, which no real device
    sends.
    """
    header = struct.pack("<III", ADS_UDP_MAGIC, 1, 0x80000001)

    def tlv(tag, payload):
        return struct.pack("<HH", tag, len(payload)) + payload

    nid = bytes(int(x) for x in netid.split("."))
    name = hostname.encode() + b"\x00"
    body = b""
    body += nid  # [12:18] device AMS NetID (fixed position)
    body += struct.pack("<H", 10000)  # [18:20] device AMS port
    body += b"\x00\x00\x00\x0c\x00\x00"  # [20:26] static block
    body += struct.pack("<H", len(name))  # [26:28] hostname length
    body += name  # [28:..] hostname + NUL
    body += b"\x00\x00\x00\x00"  # reserved
    body += struct.pack("<III", 10, 0, 19041)  # kernel 10.0.19041
    body += struct.pack("<BBH", 3, 1, 4024)  # TwinCAT version
    body += tlv(ADS_UDP_TAG["FINGERPRINT"], b"\xab\xcd")
    return header + body


class TestUDPDiscovery(unittest.TestCase):
    @patch("socket.socket")
    def test_udp_discovery_parses_device(self, mock_socket_cls):
        scanner = _make_scanner()
        resp = _build_udp_response()
        fake = FakeUDPSocket([(resp, ("192.168.1.100", 48899))])
        mock_socket_cls.return_value = fake

        result = scanner._udp_discovery()

        self.assertTrue(result["success"])
        self.assertEqual(len(result["devices"]), 1)
        dev = result["devices"][0]
        self.assertEqual(dev["ip"], "192.168.1.100")
        self.assertEqual(dev["hostname"], "CX-012345")
        self.assertEqual(dev["netid"], "192.168.1.100.1.1")
        self.assertEqual(dev["tc_version"], "3.1.4024")
        # OS version comes from the fixed-position kernel triple (10.0.19041),
        # matching BeckhoffScan.py's WINVER parsing of a real reply.
        self.assertEqual(dev["os_version"], "10.0.19041")
        self.assertEqual(dev["fingerprint"], "abcd")
        # The identify request carried the Beckhoff magic
        sent_data, _dest = fake.sent[0]
        self.assertEqual(struct.unpack("<I", sent_data[:4])[0], ADS_UDP_MAGIC)

    @patch("socket.socket")
    def test_udp_discovery_no_response(self, mock_socket_cls):
        scanner = _make_scanner()
        mock_socket_cls.return_value = FakeUDPSocket([])  # immediate timeout

        result = scanner._udp_discovery()

        self.assertFalse(result["success"])
        self.assertEqual(result["devices"], [])

    @patch("socket.socket")
    def test_udp_discovery_ignores_wrong_magic(self, mock_socket_cls):
        scanner = _make_scanner()
        bad = struct.pack("<III", 0xDEADBEEF, 1, 1) + b"\x00" * 16
        mock_socket_cls.return_value = FakeUDPSocket([(bad, ("10.0.0.5", 48899))])

        result = scanner._udp_discovery()

        # Non-Beckhoff magic dropped
        self.assertEqual(result["devices"], [])

    def test_parse_udp_response_partial_tlv(self):
        """A truncated TLV (length exceeds remaining bytes) stops parsing cleanly."""
        scanner = _make_scanner()
        device = {}
        # Hostname tag claims 50 bytes but only 3 follow
        data = struct.pack("<HH", ADS_UDP_TAG["HOSTNAME"], 50) + b"abc"

        scanner._parse_udp_response(data, device)

        # No hostname captured; no exception raised
        self.assertNotIn("hostname", device)


# ---------------------------------------------------------------------------
# TwinCAT version detection + TC2 security branch
# ---------------------------------------------------------------------------


class TestTwinCATVersionAndSecurity(unittest.TestCase):
    def test_detect_twincat_version_by_name(self):
        scanner = _make_scanner()
        self.assertEqual(scanner._detect_twincat_version({"device_name": "TwinCAT 2 PLC"}), 2)
        self.assertEqual(scanner._detect_twincat_version({"device_name": "TC3 Runtime"}), 3)

    def test_detect_twincat_version_by_major(self):
        scanner = _make_scanner()
        self.assertEqual(scanner._detect_twincat_version({"major_version": 2}), 2)
        self.assertEqual(scanner._detect_twincat_version({"major_version": 3}), 3)
        # Unknown -> defaults to 3
        self.assertEqual(scanner._detect_twincat_version({}), 3)

    def test_analyze_security_tc2_clear_text_branch(self):
        """TwinCAT 2 device should yield the clear-text 'No encryption' finding."""
        scanner = _make_scanner()
        results = {
            "device_info": {"device_name": "TwinCAT 2 Runtime", "major_version": 2},
            "symbols": {"symbols": {}},
            "memory_access": {"accessible": []},
        }

        scanner.logger = Mock()
        analysis = scanner._analyze_security(results)

        # TC2 issue recorded
        self.assertTrue(any("TwinCAT 2.x clear text" in issue for issue in analysis["issues"]))
        # 'No encryption' security finding emitted (TC2 branch, not TC3 static-key)
        finding_titles = [c.args[0] for c in scanner.logger.security_finding.call_args_list]
        self.assertIn("No encryption", finding_titles)
        self.assertNotIn("Insecure configuration", finding_titles)

    def test_analyze_security_tc3_static_key_branch(self):
        """TwinCAT 3 device yields the static-key + credential-exposure findings."""
        scanner = _make_scanner()
        results = {
            "device_info": {"device_name": "TC3 Runtime", "major_version": 3},
            "symbols": {
                "symbols": {
                    "v1": {"readable": True, "writable": True},
                }
            },
            "memory_access": {"accessible": [{"name": "M"}]},
        }

        scanner.logger = Mock()
        analysis = scanner._analyze_security(results)

        finding_titles = [c.args[0] for c in scanner.logger.security_finding.call_args_list]
        self.assertIn("Insecure configuration", finding_titles)
        self.assertIn("No authentication", finding_titles)
        # Writable + accessible-memory findings present
        self.assertIn("Writable access", finding_titles)
        self.assertTrue(any("writable" in i.lower() for i in analysis["issues"]))


if __name__ == "__main__":
    unittest.main()
