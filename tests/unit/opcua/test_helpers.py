#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for OPC UA helper functions.
"""

import unittest
from unittest.mock import Mock, patch
import threading


class TestNormalizeOpcuaUrl(unittest.TestCase):
    """Test OPC UA URL normalization"""

    def setUp(self):
        from oida.protocols.opcua.helpers import _normalize_opcua_url

        self.normalize = _normalize_opcua_url

    def test_already_has_scheme(self):
        """URLs with opc.tcp:// scheme should be returned unchanged"""
        url = "opc.tcp://192.168.1.100:4840"
        self.assertEqual(self.normalize(url), url)

    def test_already_has_scheme_with_path(self):
        """URLs with scheme and path should be preserved"""
        url = "opc.tcp://192.168.1.100:4840/path/to/server"
        self.assertEqual(self.normalize(url), url)

    def test_host_and_port(self):
        """Host:port should get opc.tcp:// prefix"""
        result = self.normalize("192.168.1.100:4840")
        self.assertEqual(result, "opc.tcp://192.168.1.100:4840")

    def test_host_only(self):
        """Host only should get scheme and default port"""
        result = self.normalize("192.168.1.100")
        self.assertEqual(result, "opc.tcp://192.168.1.100:4840")

    def test_host_only_custom_default_port(self):
        """Host only with custom default port"""
        result = self.normalize("192.168.1.100", default_port=5840)
        self.assertEqual(result, "opc.tcp://192.168.1.100:5840")

    def test_host_and_path(self):
        """Host with path should get scheme and default port"""
        result = self.normalize("192.168.1.100:4840/path")
        self.assertEqual(result, "opc.tcp://192.168.1.100:4840/path")

    def test_hostname(self):
        """Hostname should work same as IP"""
        result = self.normalize("myserver.local")
        self.assertEqual(result, "opc.tcp://myserver.local:4840")

    def test_whitespace_trimmed(self):
        """Leading/trailing whitespace should be trimmed"""
        result = self.normalize("  192.168.1.100:4840  ")
        self.assertEqual(result, "opc.tcp://192.168.1.100:4840")

    def test_case_insensitive_scheme(self):
        """Scheme check should be case-insensitive"""
        url = "OPC.TCP://192.168.1.100:4840"
        self.assertEqual(self.normalize(url), url)


class TestParseOpcuaUrl(unittest.TestCase):
    """Test OPC UA URL parsing"""

    def setUp(self):
        from oida.protocols.opcua.helpers import _parse_opcua_url

        self.parse = _parse_opcua_url

    def test_full_url(self):
        """Parse full URL with scheme, host, port, path"""
        host, port, path = self.parse("opc.tcp://192.168.1.100:4840/path")
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 4840)
        self.assertEqual(path, "/path")

    def test_url_without_path(self):
        """Parse URL without path"""
        host, port, path = self.parse("opc.tcp://192.168.1.100:4840")
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 4840)
        self.assertEqual(path, "")

    def test_host_only(self):
        """Parse host only (will be normalized first)"""
        host, port, path = self.parse("192.168.1.100")
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 4840)
        self.assertEqual(path, "")

    def test_custom_port(self):
        """Parse URL with custom port"""
        host, port, path = self.parse("opc.tcp://192.168.1.100:5840")
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 5840)

    def test_hostname_with_subdomain(self):
        """Parse hostname with subdomain"""
        host, port, path = self.parse("opc.tcp://server.factory.local:4840/opcua")
        self.assertEqual(host, "server.factory.local")
        self.assertEqual(port, 4840)
        self.assertEqual(path, "/opcua")

    def test_invalid_port_defaults(self):
        """Invalid port string should default to 4840"""
        host, port, path = self.parse("opc.tcp://192.168.1.100:invalid")
        self.assertEqual(host, "192.168.1.100")
        self.assertEqual(port, 4840)


class TestDangerousKeywords(unittest.TestCase):
    """Test dangerous keywords list"""

    def test_dangerous_keywords_exist(self):
        """Verify dangerous keywords list is populated"""
        from oida.protocols.opcua.helpers import DANGEROUS_KEYWORDS

        self.assertIsInstance(DANGEROUS_KEYWORDS, list)
        self.assertGreater(len(DANGEROUS_KEYWORDS), 0)

    def test_common_dangerous_keywords(self):
        """Check common dangerous keywords are in list"""
        from oida.protocols.opcua.helpers import DANGEROUS_KEYWORDS

        expected = ["start", "stop", "reset", "write", "execute", "delete"]
        for keyword in expected:
            self.assertIn(keyword, DANGEROUS_KEYWORDS)


class TestLazyUaModule(unittest.TestCase):
    """Test lazy UA module proxy"""

    def test_lazy_proxy_exists(self):
        """Verify ua proxy is available"""
        from oida.protocols.opcua.helpers import ua

        self.assertIsNotNone(ua)

    @patch("oida.protocols.opcua.helpers._get_ua_module")
    def test_lazy_proxy_forwards_attributes(self, mock_get_ua):
        """Verify proxy forwards attribute access"""
        mock_ua_module = Mock()
        mock_ua_module.AttributeIds = "test_value"
        mock_get_ua.return_value = mock_ua_module

        from oida.protocols.opcua.helpers import _LazyUaModule

        proxy = _LazyUaModule()
        result = proxy.AttributeIds

        self.assertEqual(result, "test_value")
        mock_get_ua.assert_called()


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of caching functions"""

    def test_asyncua_cache_lock_exists(self):
        """Verify asyncua cache has a lock"""
        from oida.protocols.opcua.helpers import _AsyncuaCache

        self.assertIsInstance(_AsyncuaCache._lock, type(threading.Lock()))

    def test_security_policies_lock_exists(self):
        """Verify security policies cache has a lock"""
        from oida.protocols.opcua.helpers import _SecurityPoliciesCache

        self.assertIsInstance(_SecurityPoliciesCache._lock, type(threading.Lock()))


class TestOpcuaScheme(unittest.TestCase):
    """Test OPC UA scheme constant"""

    def test_scheme_value(self):
        """Verify scheme constant value"""
        from oida.protocols.opcua.helpers import OPCUA_SCHEME

        self.assertEqual(OPCUA_SCHEME, "opc.tcp://")


if __name__ == "__main__":
    unittest.main()
