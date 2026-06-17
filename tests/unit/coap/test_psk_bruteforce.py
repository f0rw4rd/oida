"""
Unit tests for CoAP DTLS-PSK bruteforce and probe-paths wordlist features.

Tests the bruteforce logic, wordlist loading, and path probing
without requiring actual network connections or a running CoAP server.
"""

import os
import tempfile
import unittest
from unittest.mock import Mock, patch


# ---------------------------------------------------------------------------
# PSK Bruteforce Tests
# ---------------------------------------------------------------------------


class TestPSKBruteforce(unittest.TestCase):
    """Test DTLS-PSK bruteforce logic in the CoAP NXC class."""

    def _make_coap_instance(self, psk=None, psk_identity=None, port=5684, timeout=3):
        """Create a coap NXC instance with mocked internals (no proto_flow)."""
        from oida.protocols.coap import coap as CoAPClass

        args = Mock()
        args.port = port
        args.timeout = timeout
        args.psk = psk
        args.psk_identity = psk_identity
        args.dtls = bool(psk)
        args.confirm = False
        args.debug = False
        args.verbose = 0
        args.quiet = False
        args.probe_paths = False
        args.lwm2m = False
        args.lwm2m_full = False
        args.methods = False
        args.observe = False
        args.put = None
        args.post = None
        args.delete = None
        args.observe_count = 5

        # Prevent super().__init__ from calling proto_flow
        with patch.object(CoAPClass, "__init__", lambda self, *a, **kw: None):
            instance = CoAPClass.__new__(CoAPClass)

        instance.args = args
        instance.host = "127.0.0.1"
        instance.port = port
        instance.conn = None
        instance.results = {"data": {}}
        instance.logger = Mock()
        instance.scanner = Mock()
        instance.scanner.timeout = timeout

        return instance

    def test_single_psk_success(self):
        """Single PSK value succeeds on first try."""
        instance = self._make_coap_instance(psk="0102030405060708", psk_identity="client1")

        async def mock_try(host, port, identity, key, timeout=5):
            return True, Mock(), "2.05 Content"

        # Use synchronous mock
        with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
            mock_ctx = Mock()
            mock_run.return_value = (True, mock_ctx, "2.05 Content")

            result = instance._bruteforce_dtls_psk("0102030405060708", "client1")

        assert result is True
        assert instance.conn is mock_ctx
        assert instance.results["data"]["dtls_psk"]["identity"] == "client1"
        assert instance.results["data"]["dtls_psk"]["key"] == "0102030405060708"
        instance.logger.success.assert_called()

    def test_single_psk_failure(self):
        """Single PSK value fails."""
        instance = self._make_coap_instance(psk="badkey", psk_identity="badid")

        with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
            mock_run.return_value = (False, None, "handshake failed")
            result = instance._bruteforce_dtls_psk("badkey", "badid")

        assert result is False
        assert instance.conn is None
        instance.logger.fail.assert_called()

    def test_wordlist_bruteforce_success_on_third(self):
        """Wordlist bruteforce succeeds on the third combination."""
        instance = self._make_coap_instance()

        # Create temp wordlist files
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("key1\nkey2\ncorrect_key\n")
            key_file = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("identity1\n")
            id_file = f.name

        try:
            call_count = 0

            def mock_run(coro):
                nonlocal call_count
                call_count += 1
                if call_count == 3:
                    return (True, Mock(), "2.05 Content")
                return (False, None, "handshake failed")

            with patch("oida.protocols.coap.nxc_connection.run_async", side_effect=mock_run):
                result = instance._bruteforce_dtls_psk(key_file, id_file)

            assert result is True
            assert instance.conn is not None
            # Should have tried 3 combinations (identity1 x key1, key2, correct_key)
            assert call_count == 3
        finally:
            os.unlink(key_file)
            os.unlink(id_file)

    def test_wordlist_bruteforce_all_fail(self):
        """Wordlist bruteforce exhausts all combinations without success."""
        instance = self._make_coap_instance()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("key1\nkey2\nkey3\n")
            key_file = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("id1\nid2\n")
            id_file = f.name

        try:
            with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
                mock_run.return_value = (False, None, "denied")
                result = instance._bruteforce_dtls_psk(key_file, id_file)

            assert result is False
            assert instance.conn is None
            # 2 identities x 3 keys = 6 calls
            assert mock_run.call_count == 6
            instance.logger.fail.assert_called()
        finally:
            os.unlink(key_file)
            os.unlink(id_file)

    def test_no_psk_key_skips_bruteforce(self):
        """When no PSK key is provided, bruteforce is skipped."""
        instance = self._make_coap_instance()

        result = instance._bruteforce_dtls_psk(None, "some-identity")

        assert result is False
        instance.logger.debug.assert_any_call("No PSK key provided, skipping DTLS bruteforce")

    def test_wordlist_with_comments_and_blanks(self):
        """Wordlist files with comments and blank lines are parsed correctly."""
        instance = self._make_coap_instance()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# This is a comment\n")
            f.write("key1\n")
            f.write("\n")
            f.write("# Another comment\n")
            f.write("key2\n")
            f.write("\n")
            key_file = f.name

        try:
            call_count = 0

            def mock_run(coro):
                nonlocal call_count
                call_count += 1
                return (False, None, "failed")

            with patch("oida.protocols.coap.nxc_connection.run_async", side_effect=mock_run):
                result = instance._bruteforce_dtls_psk(key_file, "id1")

            assert result is False
            # Only 2 actual keys (comments and blanks skipped)
            assert call_count == 2
        finally:
            os.unlink(key_file)

    def test_progress_reported_for_multiple_combinations(self):
        """Progress is reported when there are multiple combinations."""
        instance = self._make_coap_instance()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("key1\nkey2\n")
            key_file = f.name

        try:
            with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
                mock_run.return_value = (False, None, "failed")
                instance._bruteforce_dtls_psk(key_file, "id1")

            # Should have called progress for multi-combination bruteforce
            instance.logger.progress.assert_called()
        finally:
            os.unlink(key_file)


# ---------------------------------------------------------------------------
# Probe Paths Wordlist Tests
# ---------------------------------------------------------------------------


class TestProbePathsWordlist(unittest.TestCase):
    """Test probe-paths wordlist loading and path enumeration."""

    def _make_coap_instance(self):
        """Create a coap NXC instance with mocked internals."""
        from oida.protocols.coap import coap as CoAPClass

        with patch.object(CoAPClass, "__init__", lambda self, *a, **kw: None):
            instance = CoAPClass.__new__(CoAPClass)

        instance.args = Mock()
        instance.host = "127.0.0.1"
        instance.port = 5683
        instance.conn = Mock()
        instance.results = {"data": {}}
        instance.logger = Mock()
        instance.scanner = Mock()
        instance.scanner.get_target_info.return_value = ("127.0.0.1", 5683)
        instance.scanner.timeout = 5

        return instance

    def test_wordlist_paths_all_found(self):
        """All paths from wordlist are found."""
        instance = self._make_coap_instance()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/sensor/temperature\n")
            f.write("/actuator/led\n")
            wordlist_path = f.name

        try:
            with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
                mock_run.return_value = {
                    "code": "2.05 Content",
                    "success": True,
                    "payload": b"42.5",
                }
                found = instance._probe_paths_wordlist(wordlist_path)

            assert len(found) == 2
            assert found[0]["path"] == "/sensor/temperature"
            assert found[1]["path"] == "/actuator/led"
            assert found[0]["code"] == "2.05 Content"
        finally:
            os.unlink(wordlist_path)

    def test_wordlist_paths_none_found(self):
        """No paths from wordlist are found."""
        instance = self._make_coap_instance()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/nonexistent1\n")
            f.write("/nonexistent2\n")
            f.write("/nonexistent3\n")
            wordlist_path = f.name

        try:
            with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
                mock_run.return_value = {
                    "code": "4.04 Not Found",
                    "success": False,
                    "payload": b"",
                }
                found = instance._probe_paths_wordlist(wordlist_path)

            assert len(found) == 0
            # Should have logged debug for each path not found
            assert instance.logger.debug.call_count >= 3
        finally:
            os.unlink(wordlist_path)

    def test_wordlist_mixed_results(self):
        """Some paths found, some not found."""
        instance = self._make_coap_instance()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/sensor/temperature\n")
            f.write("/nonexistent\n")
            f.write("/actuator/led\n")
            wordlist_path = f.name

        try:
            call_count = 0

            def mock_run(coro):
                nonlocal call_count
                call_count += 1
                if call_count in (1, 3):  # 1st and 3rd paths exist
                    return {"code": "2.05 Content", "success": True, "payload": b"data"}
                return {"code": "4.04 Not Found", "success": False, "payload": b""}

            with patch("oida.protocols.coap.nxc_connection.run_async", side_effect=mock_run):
                found = instance._probe_paths_wordlist(wordlist_path)

            assert len(found) == 2
            assert found[0]["path"] == "/sensor/temperature"
            assert found[1]["path"] == "/actuator/led"
        finally:
            os.unlink(wordlist_path)

    def test_wordlist_file_not_found(self):
        """Non-existent wordlist file logs warning and returns empty."""
        instance = self._make_coap_instance()

        found = instance._probe_paths_wordlist("/nonexistent/wordlist.txt")

        assert found == []
        instance.logger.warning.assert_called()

    def test_wordlist_adds_leading_slash(self):
        """Paths without leading slash get one added."""
        instance = self._make_coap_instance()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("sensor/temperature\n")
            f.write("/actuator/led\n")
            wordlist_path = f.name

        try:
            with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
                mock_run.return_value = {
                    "code": "2.05 Content",
                    "success": True,
                    "payload": b"data",
                }
                found = instance._probe_paths_wordlist(wordlist_path)

            assert len(found) == 2
            # First path should have / prepended
            assert found[0]["path"] == "/sensor/temperature"
            assert found[1]["path"] == "/actuator/led"
        finally:
            os.unlink(wordlist_path)

    def test_wordlist_payload_size_recorded(self):
        """Payload size is recorded for found resources."""
        instance = self._make_coap_instance()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/sensor/temperature\n")
            wordlist_path = f.name

        try:
            with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
                mock_run.return_value = {
                    "code": "2.05 Content",
                    "success": True,
                    "payload": b"temperature=42.5",
                }
                found = instance._probe_paths_wordlist(wordlist_path)

            assert len(found) == 1
            assert found[0]["size"] == len(b"temperature=42.5")
        finally:
            os.unlink(wordlist_path)

    def test_wordlist_comments_and_blanks_skipped(self):
        """Comments and blank lines in wordlist are ignored."""
        instance = self._make_coap_instance()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# Comment line\n")
            f.write("\n")
            f.write("/sensor/temperature\n")
            f.write("# Another comment\n")
            f.write("\n")
            wordlist_path = f.name

        try:
            with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
                mock_run.return_value = {
                    "code": "2.05 Content",
                    "success": True,
                    "payload": b"data",
                }
                found = instance._probe_paths_wordlist(wordlist_path)

            # Only 1 actual path (comments and blanks skipped)
            assert len(found) == 1
            assert mock_run.call_count == 1
        finally:
            os.unlink(wordlist_path)


# ---------------------------------------------------------------------------
# Proto Args Tests
# ---------------------------------------------------------------------------


class TestProtoArgs(unittest.TestCase):
    """Test that proto_args.py defines the expected arguments."""

    def test_probe_paths_accepts_optional_wordlist(self):
        """--probe-paths should accept an optional wordlist file argument."""
        import argparse
        from oida.protocols.coap.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        # Test bare flag
        args = main_parser.parse_args(["coap", "127.0.0.1", "-R"])
        assert args.probe_paths is True

        # Test with wordlist
        args = main_parser.parse_args(["coap", "127.0.0.1", "-R", "/path/to/wordlist"])
        assert args.probe_paths == "/path/to/wordlist"

        # Test not provided
        args = main_parser.parse_args(["coap", "127.0.0.1"])
        assert args.probe_paths is False

    def test_psk_accepts_string(self):
        """--psk should accept a string value."""
        import argparse
        from oida.protocols.coap.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["coap", "127.0.0.1", "-P", "0102030405060708"])
        assert args.psk == "0102030405060708"

    def test_psk_identity_accepts_string(self):
        """--psk-identity should accept a string value."""
        import argparse
        from oida.protocols.coap.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["coap", "127.0.0.1", "-u", "my-client"])
        assert args.psk_identity == "my-client"


# ---------------------------------------------------------------------------
# Credential Parsing Integration Tests
# ---------------------------------------------------------------------------


class TestCredentialParsing(unittest.TestCase):
    """Test that parse_credential_input works correctly with PSK values."""

    def test_single_value_not_file(self):
        """A single hex string should not be treated as a file."""
        from oida.utils.default_credentials import parse_credential_input

        values, is_file = parse_credential_input("0102030405060708")
        assert values == ["0102030405060708"]
        assert is_file is False

    def test_file_path_loads_values(self):
        """A valid file path should load lines from the file."""
        from oida.utils.default_credentials import parse_credential_input

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("key1\nkey2\nkey3\n")
            path = f.name

        try:
            values, is_file = parse_credential_input(path)
            assert values == ["key1", "key2", "key3"]
            assert is_file is True
        finally:
            os.unlink(path)

    def test_file_skips_comments(self):
        """Comments in wordlist files should be skipped."""
        from oida.utils.default_credentials import parse_credential_input

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# comment\nkey1\n# another\nkey2\n")
            path = f.name

        try:
            values, is_file = parse_credential_input(path)
            assert values == ["key1", "key2"]
            assert is_file is True
        finally:
            os.unlink(path)

    def test_none_returns_empty(self):
        """None input should return empty list."""
        from oida.utils.default_credentials import parse_credential_input

        values, is_file = parse_credential_input(None)
        assert values == []
        assert is_file is False
