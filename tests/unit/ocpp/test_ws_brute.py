#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for OCPP WebSocket path brute-forcing functionality.

Tests the ws_brute_force method in DiscoveryMixin and the _probe_path
method in OCPPScanner without requiring actual network connections.
"""

import os
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Wordlist loading tests
# ---------------------------------------------------------------------------


class TestWordlistLoading(unittest.TestCase):
    """Test WebSocket path wordlist loading"""

    def _make_mixin(self, ws_brute=True):
        """Create a DiscoveryMixin instance with mocked attributes."""
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin

        mixin = DiscoveryMixin()
        mixin.args = Mock()
        mixin.args.ws_brute = ws_brute
        mixin.logger = Mock()
        return mixin

    def test_get_default_ws_paths_returns_list(self):
        """Default paths list should contain common OCPP paths."""
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin

        paths = DiscoveryMixin._get_default_ws_paths()
        assert isinstance(paths, list)
        assert len(paths) > 10
        assert "/" in paths
        assert "/ocpp" in paths
        assert "/ws" in paths
        assert "/steve/websocket/CentralSystemService" in paths

    def test_get_default_ws_paths_no_empty_entries(self):
        """Default paths should not contain empty strings."""
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin

        paths = DiscoveryMixin._get_default_ws_paths()
        for path in paths:
            assert path.strip() != "", "Empty path found in default list"

    def test_read_wordlist_file(self):
        """Read paths from a wordlist file."""
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# Comment line\n")
            f.write("/ocpp\n")
            f.write("/ws\n")
            f.write("\n")  # blank line
            f.write("# Another comment\n")
            f.write("/steve/websocket/CentralSystemService\n")
            f.write("/custom/path\n")
            tmp_path = f.name

        try:
            paths = DiscoveryMixin._read_wordlist_file(tmp_path)
            assert len(paths) == 4
            assert "/ocpp" in paths
            assert "/ws" in paths
            assert "/steve/websocket/CentralSystemService" in paths
            assert "/custom/path" in paths
        finally:
            os.unlink(tmp_path)

    def test_read_wordlist_file_missing_falls_back(self):
        """Missing wordlist file should fall back to defaults."""
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin

        paths = DiscoveryMixin._read_wordlist_file("/nonexistent/path/ws_paths.txt")
        # Should return the default list
        assert len(paths) > 10
        assert "/ocpp" in paths

    def test_read_wordlist_file_empty_falls_back(self):
        """Empty wordlist file should fall back to defaults."""
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# Only comments\n")
            f.write("# Nothing here\n")
            tmp_path = f.name

        try:
            paths = DiscoveryMixin._read_wordlist_file(tmp_path)
            # Should fall back since no actual paths were found
            assert len(paths) > 10
        finally:
            os.unlink(tmp_path)

    def test_load_ws_paths_custom_file(self):
        """--ws-brute /path/to/file should load that file."""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/my/custom/path\n")
            f.write("/another/path\n")
            tmp_path = f.name

        try:
            mixin = self._make_mixin(ws_brute=tmp_path)
            paths = mixin._load_ws_paths()
            assert len(paths) == 2
            assert "/my/custom/path" in paths
            assert "/another/path" in paths
        finally:
            os.unlink(tmp_path)

    def test_load_ws_paths_bare_flag_uses_defaults(self):
        """--ws-brute (no file) should use built-in or fallback list."""
        mixin = self._make_mixin(ws_brute=True)
        paths = mixin._load_ws_paths()
        assert len(paths) > 0


class TestBuiltinWordlist(unittest.TestCase):
    """Test the built-in src/oida/data/ocpp/ws_paths.txt wordlist"""

    def _find_wordlist(self):
        """Find the built-in wordlist packaged with OIDA."""
        from oida.utils.platform_compat import _pkg_root

        return str(_pkg_root() / "data" / "ocpp" / "ws_paths.txt")

    def test_builtin_wordlist_exists(self):
        """The built-in wordlist file should exist when ref/ is checked out."""
        wordlist_path = self._find_wordlist()
        if not os.path.isfile(wordlist_path):
            pytest.fail("Built-in wordlist not found")

    def test_builtin_wordlist_has_entries(self):
        """The built-in wordlist should contain substantial entries."""
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin

        wordlist_path = self._find_wordlist()
        if not os.path.isfile(wordlist_path):
            pytest.fail("Built-in wordlist not found")

        paths = DiscoveryMixin._read_wordlist_file(wordlist_path)
        assert len(paths) > 50, f"Expected 50+ paths, got {len(paths)}"

    def test_builtin_wordlist_contains_known_paths(self):
        """The built-in wordlist should contain paths from known implementations."""
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin

        wordlist_path = self._find_wordlist()
        if not os.path.isfile(wordlist_path):
            pytest.fail("Built-in wordlist not found")

        paths = DiscoveryMixin._read_wordlist_file(wordlist_path)
        assert "/steve/websocket/CentralSystemService" in paths
        assert "/ocpp" in paths
        assert "/ws" in paths
        assert "/" in paths

    def test_builtin_wordlist_no_duplicates(self):
        """The built-in wordlist should not have duplicate entries."""
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin

        wordlist_path = self._find_wordlist()
        if not os.path.isfile(wordlist_path):
            pytest.fail("Built-in wordlist not found")

        paths = DiscoveryMixin._read_wordlist_file(wordlist_path)
        seen = set()
        duplicates = []
        for p in paths:
            if p in seen:
                duplicates.append(p)
            seen.add(p)
        assert len(duplicates) == 0, f"Duplicate paths found: {duplicates}"


# ---------------------------------------------------------------------------
# Scanner _probe_path tests
# ---------------------------------------------------------------------------


class TestProbePathMethod(unittest.TestCase):
    """Test OCPPScanner._probe_path URL construction"""

    @patch("oida.protocols.ocpp.scanner._websockets")
    def test_probe_path_url_construction_basic(self, mock_ws):
        """Probe should construct correct URLs from base + path + cpId."""
        mock_ws.dependencies_missing = False
        mock_ws.get_module.return_value = MagicMock()

        from oida.protocols.ocpp.scanner import OCPPScanner

        scanner = OCPPScanner(
            {
                "target-url": "ws://localhost:9000/CP_001",
                "version": "auto",
                "rhost": "localhost",
                "rport": 9000,
            }
        )
        scanner.timeout = 5

        import asyncio

        with patch.object(asyncio, "new_event_loop") as mock_new_loop:
            mock_loop = MagicMock()
            mock_new_loop.return_value = mock_loop

            mock_loop.run_until_complete.return_value = {
                "reachable": False,
                "subprotocol": None,
                "version": None,
                "status_code": 404,
                "url": "ws://localhost:9000/ocpp/TEST_CP",
                "reason": "not found",
            }

            result = scanner._probe_path("ws://localhost:9000", "/ocpp", "TEST_CP")
            assert result["url"] == "ws://localhost:9000/ocpp/TEST_CP"

    @patch("oida.protocols.ocpp.scanner._websockets")
    def test_probe_path_normalizes_trailing_slash(self, mock_ws):
        """Probe should handle paths with trailing slashes."""
        mock_ws.dependencies_missing = False
        mock_ws.get_module.return_value = MagicMock()

        from oida.protocols.ocpp.scanner import OCPPScanner

        scanner = OCPPScanner(
            {
                "target-url": "ws://localhost:9000/CP_001",
                "version": "auto",
                "rhost": "localhost",
                "rport": 9000,
            }
        )
        scanner.timeout = 5

        import asyncio

        with patch.object(asyncio, "new_event_loop") as mock_new_loop:
            mock_loop = MagicMock()
            mock_new_loop.return_value = mock_loop

            mock_loop.run_until_complete.return_value = {
                "reachable": False,
                "subprotocol": None,
                "version": None,
                "status_code": 404,
                "url": "ws://localhost:9000/ocpp/CP_001",
                "reason": "not found",
            }

            result = scanner._probe_path("ws://localhost:9000", "/ocpp/", "CP_001")
            assert result is not None

    @patch("oida.protocols.ocpp.scanner._websockets")
    def test_probe_path_steve_path(self, mock_ws):
        """Probe should handle the full SteVe path correctly."""
        mock_ws.dependencies_missing = False
        mock_ws.get_module.return_value = MagicMock()

        from oida.protocols.ocpp.scanner import OCPPScanner

        scanner = OCPPScanner(
            {
                "target-url": "ws://localhost:8180/CP_001",
                "version": "auto",
                "rhost": "localhost",
                "rport": 8180,
            }
        )
        scanner.timeout = 5

        import asyncio

        with patch.object(asyncio, "new_event_loop") as mock_new_loop:
            mock_loop = MagicMock()
            mock_new_loop.return_value = mock_loop

            mock_loop.run_until_complete.return_value = {
                "reachable": True,
                "subprotocol": "ocpp1.6",
                "version": "1.6",
                "status_code": None,
                "url": "ws://localhost:8180/steve/websocket/CentralSystemService/CP_001",
                "reason": "connected",
            }

            result = scanner._probe_path(
                "ws://localhost:8180",
                "/steve/websocket/CentralSystemService",
                "CP_001",
            )
            assert result["reachable"] is True
            assert (
                result["url"] == "ws://localhost:8180/steve/websocket/CentralSystemService/CP_001"
            )


# ---------------------------------------------------------------------------
# WS Brute Force integration tests (mocked)
# ---------------------------------------------------------------------------


class TestWsBruteForce(unittest.TestCase):
    """Test the ws_brute_force method in DiscoveryMixin"""

    def _make_ocpp_instance(self, ws_brute=True):
        """Create a mock OCPP NXC instance with DiscoveryMixin."""
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin

        instance = DiscoveryMixin()
        instance.args = Mock()
        instance.args.target = "192.168.1.100"
        instance.args.port = 9000
        instance.args.charge_point_id = "CP_TEST_001"
        instance.args.ws_brute = ws_brute
        instance.args.brute_rate = 0  # No delay in tests
        instance.args.tls = False

        instance.ip = "192.168.1.100"
        instance.logger = Mock()
        instance.results = {"data": {}}
        instance.scanner = Mock()
        instance._add_finding = Mock()

        return instance

    def test_ws_brute_stores_results(self):
        """ws_brute_force should store results in self.results."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/ocpp\n/ws\n/\n")
            tmp_path = f.name

        try:
            instance = self._make_ocpp_instance(ws_brute=tmp_path)
            instance.scanner._probe_path.return_value = {
                "reachable": False,
                "subprotocol": None,
                "version": None,
                "status_code": 404,
                "url": "ws://192.168.1.100:9000/ocpp/CP_TEST_001",
                "reason": "not found",
            }

            instance.ws_brute_force()

            assert "ws_brute" in instance.results["data"]
            ws_data = instance.results["data"]["ws_brute"]
            assert ws_data["paths_tested"] == 3
            assert ws_data["endpoints_found"] == 0
            assert ws_data["base_url"] == "ws://192.168.1.100:9000"
            assert ws_data["charge_point_id"] == "CP_TEST_001"
        finally:
            os.unlink(tmp_path)

    def test_ws_brute_finds_endpoints(self):
        """ws_brute_force should report found endpoints."""

        def mock_probe(base_url, path, cp_id):
            if path == "/ocpp":
                return {
                    "reachable": True,
                    "subprotocol": "ocpp1.6",
                    "version": "1.6",
                    "status_code": None,
                    "url": f"{base_url}{path}/{cp_id}",
                    "reason": "connected",
                }
            return {
                "reachable": False,
                "subprotocol": None,
                "version": None,
                "status_code": 404,
                "url": f"{base_url}{path}/{cp_id}",
                "reason": "not found",
            }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/ocpp\n/ws\n/websocket\n")
            tmp_path = f.name

        try:
            instance = self._make_ocpp_instance(ws_brute=tmp_path)
            instance.scanner._probe_path.side_effect = mock_probe

            instance.ws_brute_force()

            ws_data = instance.results["data"]["ws_brute"]
            assert ws_data["endpoints_found"] == 1
            assert ws_data["open_endpoints"] == 1
            assert ws_data["auth_required_endpoints"] == 0
            assert len(ws_data["endpoints"]) == 1
            assert ws_data["endpoints"][0]["path"] == "/ocpp"
            assert ws_data["endpoints"][0]["version"] == "1.6"

            instance.logger.success.assert_called()
        finally:
            os.unlink(tmp_path)

    def test_ws_brute_detects_auth_required(self):
        """ws_brute_force should distinguish between open and auth-required endpoints."""

        def mock_probe(base_url, path, cp_id):
            if path == "/ocpp":
                return {
                    "reachable": True,
                    "subprotocol": "ocpp1.6",
                    "version": "1.6",
                    "status_code": None,
                    "url": f"{base_url}{path}/{cp_id}",
                    "reason": "connected",
                }
            elif path == "/ws":
                return {
                    "reachable": True,
                    "subprotocol": None,
                    "version": None,
                    "status_code": 401,
                    "url": f"{base_url}{path}/{cp_id}",
                    "reason": "auth required (401)",
                }
            return {
                "reachable": False,
                "subprotocol": None,
                "version": None,
                "status_code": 404,
                "url": f"{base_url}{path}/{cp_id}",
                "reason": "not found",
            }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/ocpp\n/ws\n/websocket\n")
            tmp_path = f.name

        try:
            instance = self._make_ocpp_instance(ws_brute=tmp_path)
            instance.scanner._probe_path.side_effect = mock_probe

            instance.ws_brute_force()

            ws_data = instance.results["data"]["ws_brute"]
            assert ws_data["endpoints_found"] == 2
            assert ws_data["open_endpoints"] == 1
            assert ws_data["auth_required_endpoints"] == 1
        finally:
            os.unlink(tmp_path)

    def test_ws_brute_shows_progress(self):
        """ws_brute_force should call logger.progress()."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/ocpp\n/ws\n")
            tmp_path = f.name

        try:
            instance = self._make_ocpp_instance(ws_brute=tmp_path)
            instance.scanner._probe_path.return_value = {
                "reachable": False,
                "subprotocol": None,
                "version": None,
                "status_code": 404,
                "url": "x",
                "reason": "not found",
            }

            instance.ws_brute_force()

            # progress called at least once per path + final
            assert instance.logger.progress.call_count >= 2
        finally:
            os.unlink(tmp_path)

    def test_ws_brute_with_ws_url_target(self):
        """ws_brute_force should parse ws:// URLs correctly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/ocpp\n")
            tmp_path = f.name

        try:
            instance = self._make_ocpp_instance(ws_brute=tmp_path)
            instance.args.target = "ws://charger.local:8180/some/path"
            instance.scanner._probe_path.return_value = {
                "reachable": False,
                "subprotocol": None,
                "version": None,
                "status_code": 404,
                "url": "ws://charger.local:8180/ocpp/CP_TEST_001",
                "reason": "not found",
            }

            instance.ws_brute_force()

            ws_data = instance.results["data"]["ws_brute"]
            assert ws_data["base_url"] == "ws://charger.local:8180"
        finally:
            os.unlink(tmp_path)

    def test_ws_brute_handles_probe_exceptions(self):
        """ws_brute_force should handle probe exceptions gracefully."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/ocpp\n/ws\n")
            tmp_path = f.name

        try:
            instance = self._make_ocpp_instance(ws_brute=tmp_path)
            instance.scanner._probe_path.side_effect = Exception("Connection refused")

            instance.ws_brute_force()

            ws_data = instance.results["data"]["ws_brute"]
            assert ws_data["endpoints_found"] == 0
            assert ws_data["paths_tested"] == 2
        finally:
            os.unlink(tmp_path)

    def test_ws_brute_adds_security_finding(self):
        """ws_brute_force should add a security finding for open endpoints."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/ocpp\n")
            tmp_path = f.name

        try:
            instance = self._make_ocpp_instance(ws_brute=tmp_path)
            instance.scanner._probe_path.return_value = {
                "reachable": True,
                "subprotocol": "ocpp1.6",
                "version": "1.6",
                "status_code": None,
                "url": "ws://192.168.1.100:9000/ocpp/CP_TEST_001",
                "reason": "connected",
            }

            instance.ws_brute_force()

            instance._add_finding.assert_called_once()
            call_args = instance._add_finding.call_args
            assert call_args[0][0] == "MEDIUM"
            assert "brute-force" in call_args[0][1].lower()
        finally:
            os.unlink(tmp_path)

    def test_ws_brute_no_finding_when_no_open_endpoints(self):
        """ws_brute_force should NOT add finding when only auth-required endpoints found."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/ocpp\n")
            tmp_path = f.name

        try:
            instance = self._make_ocpp_instance(ws_brute=tmp_path)
            instance.scanner._probe_path.return_value = {
                "reachable": True,
                "subprotocol": None,
                "version": None,
                "status_code": 401,
                "url": "ws://192.168.1.100:9000/ocpp/CP_TEST_001",
                "reason": "auth required (401)",
            }

            instance.ws_brute_force()

            instance._add_finding.assert_not_called()
        finally:
            os.unlink(tmp_path)

    def test_ws_brute_with_plain_ip_and_port(self):
        """ws_brute_force should handle plain IP:port target."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/ocpp\n")
            tmp_path = f.name

        try:
            instance = self._make_ocpp_instance(ws_brute=tmp_path)
            instance.args.target = "10.0.0.1:8080"
            instance.scanner._probe_path.return_value = {
                "reachable": False,
                "subprotocol": None,
                "version": None,
                "status_code": 404,
                "url": "ws://10.0.0.1:8080/ocpp/CP_TEST_001",
                "reason": "not found",
            }

            instance.ws_brute_force()

            ws_data = instance.results["data"]["ws_brute"]
            assert ws_data["base_url"] == "ws://10.0.0.1:8080"
        finally:
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Proto args tests
# ---------------------------------------------------------------------------


class TestWsBruteProtoArgs(unittest.TestCase):
    """Test that --ws-brute CLI argument is registered correctly."""

    def _make_parser(self):
        """Create a parser using the OCPP proto_args function."""
        import argparse
        from oida.protocols.ocpp.proto_args import proto_args

        root = argparse.ArgumentParser()
        subparsers = root.add_subparsers()
        parents = [argparse.ArgumentParser(add_help=False)]
        return proto_args(subparsers, parents)

    def test_ws_brute_bare_flag(self):
        """--ws-brute without argument should set True."""
        parser = self._make_parser()
        args = parser.parse_args(["192.168.1.100", "--ws-brute"])
        assert args.ws_brute is True

    def test_ws_brute_with_file(self):
        """--ws-brute with file path should set the path string."""
        parser = self._make_parser()
        args = parser.parse_args(["192.168.1.100", "--ws-brute", "/tmp/test.txt"])
        assert args.ws_brute == "/tmp/test.txt"

    def test_ws_brute_default_none(self):
        """--ws-brute should default to None when not specified."""
        parser = self._make_parser()
        args = parser.parse_args(["192.168.1.100"])
        assert args.ws_brute is None


# ---------------------------------------------------------------------------
# NXC dispatch tests
# ---------------------------------------------------------------------------


class TestWsBruteDispatch(unittest.TestCase):
    """Test that --ws-brute is dispatched correctly in the NXC flow."""

    def test_ws_brute_in_operation_flags(self):
        """ws_brute should be in the _OPERATION_FLAGS list."""
        from oida.protocols.ocpp import ocpp

        assert "ws_brute" in ocpp._OPERATION_FLAGS

    def test_ws_brute_is_recognized_as_operation(self):
        """_has_any_operation_flag should return True when ws_brute is set."""
        from oida.protocols.ocpp import ocpp

        instance = ocpp.__new__(ocpp)
        instance.args = Mock()

        for flag in ocpp._OPERATION_FLAGS:
            setattr(instance.args, flag, None)
        instance.args.ws_brute = True

        assert instance._has_any_operation_flag() is True


if __name__ == "__main__":
    unittest.main()
