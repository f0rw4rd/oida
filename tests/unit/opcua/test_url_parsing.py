"""URL normalisation and parsing tests for the OPC UA helpers.

Covers CODE_REVIEW.md HIGH:
- _normalize_opcua_url doubled port on bracketed IPv6 with explicit port
- _parse_opcua_url put '[::1' into host and lost the brackets/zone
- scanner.get_target_info() crashed on opc.tcp://host:port/path
  (ValueError from int("4840/path"))
"""

import unittest


class TestNormalizeOpcuaUrl(unittest.TestCase):
    def test_bare_host_adds_scheme_and_port(self):
        from oida.protocols.opcua.helpers import _normalize_opcua_url

        self.assertEqual(_normalize_opcua_url("host"), "opc.tcp://host:4840")

    def test_host_with_port(self):
        from oida.protocols.opcua.helpers import _normalize_opcua_url

        self.assertEqual(_normalize_opcua_url("host:4840"), "opc.tcp://host:4840")

    def test_fully_qualified_url_passthrough(self):
        from oida.protocols.opcua.helpers import _normalize_opcua_url

        for url in [
            "opc.tcp://host:4840",
            "opc.tcp://host:4840/path",
            "opc.tcp://host:4840/UA/Server",
        ]:
            self.assertEqual(_normalize_opcua_url(url), url)

    def test_ipv6_without_port_adds_default(self):
        from oida.protocols.opcua.helpers import _normalize_opcua_url

        self.assertEqual(_normalize_opcua_url("[::1]"), "opc.tcp://[::1]:4840")
        self.assertEqual(_normalize_opcua_url("[2001:db8::1]"), "opc.tcp://[2001:db8::1]:4840")

    def test_ipv6_with_port_does_not_double(self):
        """Old bug: '[::1]:4840' became 'opc.tcp://[::1]:4840:4840'."""
        from oida.protocols.opcua.helpers import _normalize_opcua_url

        self.assertEqual(_normalize_opcua_url("[::1]:4840"), "opc.tcp://[::1]:4840")
        self.assertEqual(
            _normalize_opcua_url("[2001:db8::1]:4840"),
            "opc.tcp://[2001:db8::1]:4840",
        )


class TestParseOpcuaUrl(unittest.TestCase):
    def test_ipv4_host(self):
        from oida.protocols.opcua.helpers import _parse_opcua_url

        host, port, path = _parse_opcua_url("opc.tcp://192.0.2.1:4840")
        self.assertEqual(host, "192.0.2.1")
        self.assertEqual(port, 4840)
        self.assertEqual(path, "")

    def test_host_with_path(self):
        from oida.protocols.opcua.helpers import _parse_opcua_url

        host, port, path = _parse_opcua_url("opc.tcp://h.local:4840/UA/Server")
        self.assertEqual(host, "h.local")
        self.assertEqual(port, 4840)
        self.assertEqual(path, "/UA/Server")

    def test_ipv6_keeps_brackets(self):
        """Old bug: rsplit(':',1) put '[::1' into host and lost ']'."""
        from oida.protocols.opcua.helpers import _parse_opcua_url

        host, port, path = _parse_opcua_url("opc.tcp://[::1]:4840")
        self.assertEqual(host, "[::1]")
        self.assertEqual(port, 4840)
        self.assertEqual(path, "")

    def test_ipv6_with_path(self):
        from oida.protocols.opcua.helpers import _parse_opcua_url

        host, port, path = _parse_opcua_url("opc.tcp://[2001:db8::1]:4840/UA")
        self.assertEqual(host, "[2001:db8::1]")
        self.assertEqual(port, 4840)
        self.assertEqual(path, "/UA")

    def test_ipv6_no_port_uses_default(self):
        from oida.protocols.opcua.helpers import _parse_opcua_url

        # Round-trips via _normalize first, so default port lands on the addr.
        host, port, path = _parse_opcua_url("[::1]")
        self.assertEqual(host, "[::1]")
        self.assertEqual(port, 4840)


class TestScannerGetTargetInfo(unittest.TestCase):
    """Old bug: get_target_info() crashed on opc.tcp://host:4840/path."""

    def test_url_with_path_does_not_crash(self):
        from oida.protocols.opcua.scanner import OPCUAScanner

        s = OPCUAScanner({"rhost": "opc.tcp://host:4840/UA/Server", "rport": 4840})
        host, port = s.get_target_info()
        self.assertEqual(port, 4840)
        self.assertIn("opc.tcp://host:4840", host)

    def test_url_ipv6_with_port(self):
        from oida.protocols.opcua.scanner import OPCUAScanner

        s = OPCUAScanner({"rhost": "opc.tcp://[::1]:4840", "rport": 4840})
        _, port = s.get_target_info()
        self.assertEqual(port, 4840)


if __name__ == "__main__":
    unittest.main()
