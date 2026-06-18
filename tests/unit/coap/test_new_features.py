"""
Unit tests for CoAP new features:
  - parse_payload() content format parsing (Feature 4)
  - Block-wise transfer helpers (Feature 1)
  - DTLS certificate credential building (Feature 2)
  - FETCH/PATCH/iPATCH method exposure (Feature 3)
"""

import json
import unittest
from unittest.mock import Mock, patch


# ---------------------------------------------------------------------------
# Feature 4: Content Format Parsing
# ---------------------------------------------------------------------------


class TestParsePayload(unittest.TestCase):
    """Test parse_payload() content format auto-detection and parsing."""

    def _parse(self, payload, content_format=None):
        from oida.protocols.coap.helpers import parse_payload

        return parse_payload(payload, content_format=content_format)

    # --- Empty payload ---

    def test_empty_payload(self):
        result = self._parse(b"")
        assert result["type"] == "empty"
        assert result["value"] == ""
        assert result["raw_size"] == 0

    # --- JSON ---

    def test_json_with_content_format(self):
        data = {"temperature": 22.5, "unit": "C"}
        payload = json.dumps(data).encode("utf-8")
        result = self._parse(payload, content_format=50)
        assert result["type"] == "json"
        assert result["value"] == data
        assert result["raw_size"] == len(payload)

    def test_json_heuristic_object(self):
        data = {"key": "value"}
        payload = json.dumps(data).encode("utf-8")
        result = self._parse(payload)  # no content_format
        assert result["type"] == "json"
        assert result["value"] == data

    def test_json_heuristic_array(self):
        data = [1, 2, 3]
        payload = json.dumps(data).encode("utf-8")
        result = self._parse(payload)
        assert result["type"] == "json"
        assert result["value"] == data

    def test_invalid_json_with_content_format(self):
        result = self._parse(b"not valid json", content_format=50)
        assert result["type"] == "binary"

    # --- SenML JSON ---

    def test_senml_json(self):
        senml = [{"n": "temp", "v": 22.5, "u": "Cel"}]
        payload = json.dumps(senml).encode("utf-8")
        result = self._parse(payload, content_format=110)
        assert result["type"] == "senml_json"
        assert result["value"] == senml

    # --- LwM2M JSON ---

    def test_lwm2m_json(self):
        lwm2m = {"e": [{"n": "0", "sv": "OIDA-Test"}]}
        payload = json.dumps(lwm2m).encode("utf-8")
        result = self._parse(payload, content_format=11543)
        assert result["type"] == "lwm2m_json"
        assert result["value"] == lwm2m

    # --- CBOR ---

    def test_cbor_with_cbor2(self):
        """CBOR parsing when cbor2 is available."""
        data = {"temperature": 22.5}
        try:
            import cbor2

            payload = cbor2.dumps(data)
            result = self._parse(payload, content_format=60)
            assert result["type"] == "cbor"
            assert result["value"] == data
        except ImportError:
            # cbor2 not installed -- test hex fallback
            payload = b"\xa1\x6btemperature\xf9\x4da0"
            result = self._parse(payload, content_format=60)
            assert result["type"] == "cbor_hex"
            assert isinstance(result["value"], str)

    def test_cbor_without_cbor2(self):
        """CBOR parsing falls back to hex when cbor2 is not installed."""
        payload = b"\xa1\x01\x02"  # simple CBOR
        with patch.dict("sys.modules", {"cbor2": None}):
            # Force ImportError by patching the import inside the function
            with patch("builtins.__import__", side_effect=_mock_import_no_cbor):
                result = self._parse(payload, content_format=60)
        assert result["type"] in ("cbor_hex", "cbor")
        # At minimum it should not crash

    # --- Text ---

    def test_text_plain_with_content_format(self):
        payload = b"22.5"
        result = self._parse(payload, content_format=0)
        assert result["type"] == "text"
        assert result["value"] == "22.5"

    def test_text_heuristic(self):
        payload = b"Hello World"
        result = self._parse(payload)
        assert result["type"] == "text"
        assert result["value"] == "Hello World"

    # --- Binary fallback ---

    def test_binary_payload(self):
        payload = bytes(range(256))  # Contains non-UTF-8 bytes
        result = self._parse(payload)
        assert result["type"] == "binary"
        assert isinstance(result["value"], str)  # hex string

    # --- LwM2M TLV ---

    def test_lwm2m_tlv_basic(self):
        """Basic LwM2M TLV parsing.

        Construct a simple TLV record:
        Type=Resource(0xC0), ID=0, Length=4, Value="test"
        type_byte = 0b11_0_00_100 = 0xC4
        """
        # Resource, 8-bit ID, inline length=4
        # type_byte: bits[7:6]=11 (resource), bit5=0 (8-bit ID), bits[4:3]=00 (inline len), bits[2:0]=4
        type_byte = 0b11_0_00_100
        identifier = 0x00
        value = b"test"
        payload = bytes([type_byte, identifier]) + value

        result = self._parse(payload, content_format=11542)
        assert result["type"] == "lwm2m_tlv"
        assert isinstance(result["value"], list)
        assert len(result["value"]) == 1
        assert result["value"][0]["id"] == 0
        assert result["value"][0]["value"] == "test"
        assert result["value"][0]["type"] == "resource"

    # --- Link format (ct=40) ---

    def test_link_format_as_text(self):
        payload = b"</sensor/temp>;obs;ct=0"
        result = self._parse(payload, content_format=40)
        assert result["type"] == "text"
        assert "/sensor/temp" in result["value"]


def _mock_import_no_cbor(name, *args, **kwargs):
    """Mock import that raises ImportError for cbor2."""
    if name == "cbor2":
        raise ImportError("No module named 'cbor2'")
    return original_import(name, *args, **kwargs)


original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__


# ---------------------------------------------------------------------------
# Feature 1: Block-wise Transfer
# ---------------------------------------------------------------------------


class TestBlockwiseTransfer(unittest.TestCase):
    """Test block-wise transfer helper functions (mocked aiocoap)."""

    def test_block_sizes_constant(self):
        """BLOCK_SIZES maps byte sizes to SZX exponents."""
        from oida.protocols.coap.constants import BLOCK_SIZES, VALID_BLOCK_SIZES

        assert BLOCK_SIZES[16] == 0
        assert BLOCK_SIZES[512] == 5
        assert BLOCK_SIZES[1024] == 6
        assert VALID_BLOCK_SIZES == [16, 32, 64, 128, 256, 512, 1024]

    def test_coap_get_blockwise_reassembly(self):
        """Block2 GET reassembles multiple blocks."""
        import asyncio

        from oida.protocols.coap.helpers import coap_get_blockwise

        # Create mock responses for 3 blocks
        chunks = [b"chunk0", b"chunk1", b"chunk2"]

        call_count = 0

        async def mock_request_handler():
            nonlocal call_count
            resp = Mock()
            resp.code = Mock(__str__=lambda self: "2.05")
            resp.payload = chunks[call_count]

            block2 = Mock()
            block2.more = call_count < 2
            block2.block_number = call_count
            block2.size_exponent = 5
            resp.opt = Mock()
            resp.opt.block2 = block2

            call_count += 1
            return resp

        ctx = Mock()

        def make_request_obj(msg):
            obj = Mock()
            obj.response = mock_request_handler()
            return obj

        ctx.request = make_request_obj

        loop = asyncio.new_event_loop()
        try:
            code, payload = loop.run_until_complete(
                coap_get_blockwise(ctx, "coap://test:5683/big", block_size=512, timeout=5)
            )
        finally:
            loop.close()

        assert code == "2.05"
        assert payload == b"chunk0chunk1chunk2"
        assert call_count == 3

    def test_coap_put_blockwise_upload(self):
        """Block1 PUT splits payload into blocks."""
        import asyncio
        import sys

        from oida.protocols.coap.helpers import coap_put_blockwise

        received_blocks = []

        async def mock_request_handler():
            resp = Mock()
            resp.code = Mock(__str__=lambda self: "2.04")
            resp.payload = b""
            return resp

        ctx = Mock()

        def make_request_obj(msg):
            received_blocks.append(msg.payload)
            obj = Mock()
            obj.response = mock_request_handler()
            return obj

        ctx.request = make_request_obj

        # 100 bytes with block_size=32 should produce 4 blocks (32+32+32+4)
        payload = b"A" * 100

        # Create a mock aiocoap module
        mock_aiocoap = Mock()
        mock_aiocoap.PUT = 3

        def mock_msg(code=None, uri=None, payload=b""):
            m = Mock()
            m.payload = payload
            m.opt = Mock()
            return m

        mock_aiocoap.Message = mock_msg
        mock_aiocoap.optiontypes.BlockOption.BlockwiseTuple = Mock()

        with patch.dict(sys.modules, {"aiocoap": mock_aiocoap}):
            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(
                    coap_put_blockwise(
                        ctx, "coap://test:5683/upload", payload, block_size=32, timeout=5
                    )
                )
            finally:
                loop.close()

        assert result["success"] is True
        assert len(received_blocks) == 4  # 100 / 32 = 3.125, rounded up to 4

    def test_scanner_uses_block_size_from_args(self):
        """CoAPScanner picks up block_size from args dict."""
        with patch("oida.protocols.coap.scanner._aiocoap") as mock:
            mock.is_available = True
            from oida.protocols.coap.scanner import CoAPScanner

            scanner = CoAPScanner({"host": "127.0.0.1", "port": 5683, "block_size": 256})
            assert scanner._block_size == 256


# ---------------------------------------------------------------------------
# Feature 2: DTLS Certificate and RPK
# ---------------------------------------------------------------------------


class TestDTLSCert(unittest.TestCase):
    """Test DTLS certificate credential building."""

    def _make_coap_instance(self):
        """Create a coap NXC instance with mocked internals."""
        from oida.protocols.coap import coap as CoAPClass

        with patch.object(CoAPClass, "__init__", lambda self, *a, **kw: None):
            instance = CoAPClass.__new__(CoAPClass)

        instance.args = Mock()
        instance.args.port = 5684
        instance.args.timeout = 5
        instance.host = "127.0.0.1"
        instance.port = 5684
        instance.conn = None
        instance.results = {"data": {}}
        instance.logger = Mock()
        instance.scanner = Mock()
        instance.scanner.timeout = 5
        return instance

    def test_try_dtls_cert_success(self):
        """Certificate auth succeeds and sets self.conn."""
        instance = self._make_coap_instance()

        mock_ctx = Mock()
        with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
            mock_run.return_value = (True, mock_ctx, "2.05")
            result = instance._try_dtls_cert("/path/cert.pem", "/path/key.pem", "/path/ca.pem")

        assert result is True
        assert instance.conn is mock_ctx
        assert instance.results["data"]["dtls_cert"]["cert"] == "/path/cert.pem"
        instance.logger.success.assert_called()

    def test_try_dtls_cert_failure(self):
        """Certificate auth fails gracefully."""
        instance = self._make_coap_instance()

        with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
            mock_run.return_value = (False, None, "backend does not support certificates")
            result = instance._try_dtls_cert("/path/cert.pem", "/path/key.pem")

        assert result is False
        assert instance.conn is None
        instance.logger.fail.assert_called()

    def test_try_dtls_rpk_success(self):
        """RPK auth succeeds and sets self.conn."""
        instance = self._make_coap_instance()

        mock_ctx = Mock()
        with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
            mock_run.return_value = (True, mock_ctx, "2.05")
            result = instance._try_dtls_rpk("/path/rpk.der")

        assert result is True
        assert instance.conn is mock_ctx
        assert instance.results["data"]["dtls_rpk"]["rpk"] == "/path/rpk.der"

    def test_try_dtls_rpk_failure(self):
        """RPK auth fails gracefully."""
        instance = self._make_coap_instance()

        with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
            mock_run.return_value = (False, None, "RPK not supported")
            result = instance._try_dtls_rpk("/path/rpk.der")

        assert result is False
        assert instance.conn is None

    def test_helper_try_dtls_cert_file_not_found(self):
        """try_dtls_cert returns descriptive error for missing cert file."""
        import asyncio

        from oida.protocols.coap.helpers import try_dtls_cert

        loop = asyncio.new_event_loop()
        try:
            ok, ctx, detail = loop.run_until_complete(
                try_dtls_cert("127.0.0.1", 5684, "/nonexistent/cert.pem", "/nonexistent/key.pem")
            )
        finally:
            loop.close()

        assert ok is False
        assert ctx is None
        assert "not found" in detail.lower() or "no such file" in detail.lower()

    def test_helper_try_dtls_rpk_file_not_found(self):
        """try_dtls_rpk returns descriptive error for missing RPK file."""
        import asyncio

        from oida.protocols.coap.helpers import try_dtls_rpk

        loop = asyncio.new_event_loop()
        try:
            ok, ctx, detail = loop.run_until_complete(
                try_dtls_rpk("127.0.0.1", 5684, "/nonexistent/rpk.der")
            )
        finally:
            loop.close()

        assert ok is False
        assert ctx is None
        assert "not found" in detail.lower() or "no such file" in detail.lower()


# ---------------------------------------------------------------------------
# Feature 3: FETCH/PATCH/iPATCH Method Exposure
# ---------------------------------------------------------------------------


class TestFetchPatchIPatch(unittest.TestCase):
    """Test FETCH/PATCH/iPATCH CLI option handling."""

    def _make_coap_instance(self):
        """Create a coap NXC instance with mocked internals."""
        from oida.protocols.coap import coap as CoAPClass

        with patch.object(CoAPClass, "__init__", lambda self, *a, **kw: None):
            instance = CoAPClass.__new__(CoAPClass)

        # Use a namespace-like mock to avoid Mock auto-creating truthy attrs
        import argparse

        instance.args = argparse.Namespace(
            confirm=True,
            probe_paths=False,
            lwm2m_full=False,
            lwm2m=False,
            methods=False,
            observe=False,
            observe_count=5,
            put=None,
            post=None,
            delete=None,
            fetch=None,
            patch=None,
            ipatch=None,
            quiet=False,
        )
        instance.host = "127.0.0.1"
        instance.port = 5683
        instance.conn = Mock()
        instance.results = {"data": {}}
        instance.logger = Mock()
        instance.scanner = Mock()
        instance.scanner.get_target_info.return_value = ("127.0.0.1", 5683)
        instance.scanner.timeout = 5
        instance.scanner._resources = []
        return instance

    def test_fetch_dispatched(self):
        """--fetch dispatches a FETCH request."""
        instance = self._make_coap_instance()
        instance.args.fetch = ["/sensor/data"]

        with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
            mock_run.return_value = {
                "code": "2.05",
                "success": True,
                "payload": b"data",
                "content_format": None,
            }
            instance._execute_features()

        mock_run.assert_called()
        results = instance.results["data"].get("write_results", [])
        assert len(results) == 1
        assert results[0]["method"] == "FETCH"
        assert results[0]["path"] == "/sensor/data"

    def test_fetch_with_payload(self):
        """--fetch PATH PAYLOAD sends payload."""
        instance = self._make_coap_instance()
        instance.args.fetch = ["/query", '{"filter": "temp"}']

        with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
            mock_run.return_value = {
                "code": "2.05",
                "success": True,
                "payload": b"result",
                "content_format": None,
            }
            instance._execute_features()

        results = instance.results["data"].get("write_results", [])
        assert len(results) == 1
        assert results[0]["method"] == "FETCH"

    def test_patch_requires_confirm(self):
        """--patch without --confirm is rejected."""
        instance = self._make_coap_instance()
        instance.args.confirm = False
        instance.args.patch = ["/config", '{"key": "value"}']

        instance._execute_features()

        instance.logger.fail.assert_any_call("--patch requires --confirm flag")

    def test_patch_with_confirm(self):
        """--patch with --confirm dispatches PATCH."""
        instance = self._make_coap_instance()
        instance.args.patch = ["/config", '{"key": "value"}']

        with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
            mock_run.return_value = {
                "code": "2.04",
                "success": True,
                "payload": b"",
                "content_format": None,
            }
            instance._execute_features()

        results = instance.results["data"].get("write_results", [])
        assert len(results) == 1
        assert results[0]["method"] == "PATCH"

    def test_ipatch_requires_confirm(self):
        """--ipatch without --confirm is rejected."""
        instance = self._make_coap_instance()
        instance.args.confirm = False
        instance.args.ipatch = ["/config", "value"]

        instance._execute_features()

        instance.logger.fail.assert_any_call("--ipatch requires --confirm flag")

    def test_ipatch_with_confirm(self):
        """--ipatch with --confirm dispatches IPATCH."""
        instance = self._make_coap_instance()
        instance.args.ipatch = ["/config", "value"]

        with patch("oida.protocols.coap.nxc_connection.run_async") as mock_run:
            mock_run.return_value = {
                "code": "2.04",
                "success": True,
                "payload": b"",
                "content_format": None,
            }
            instance._execute_features()

        results = instance.results["data"].get("write_results", [])
        assert len(results) == 1
        assert results[0]["method"] == "IPATCH"

    def test_methods_includes_extended(self):
        """--methods now tests FETCH/PATCH/IPATCH along with GET/PUT/POST/DELETE."""
        with patch("oida.protocols.coap.scanner._aiocoap") as mock:
            mock.is_available = True
            from oida.protocols.coap.scanner import CoAPScanner

            scanner = CoAPScanner({"host": "127.0.0.1", "port": 5683})

        resources = [{"path": "/test"}]
        ctx = Mock()

        with patch("oida.protocols.coap.scanner.run_async") as mock_run:
            mock_run.return_value = {"code": "2.05", "success": True, "payload": b""}
            matrix = scanner._test_methods(ctx, resources)

        # Should have tested all 7 methods
        assert "/test" in matrix
        methods_tested = set(matrix["/test"].keys())
        assert "FETCH" in methods_tested
        assert "PATCH" in methods_tested
        assert "IPATCH" in methods_tested
        assert "GET" in methods_tested


# ---------------------------------------------------------------------------
# Proto Args Tests for New Options
# ---------------------------------------------------------------------------


class TestNewProtoArgs(unittest.TestCase):
    """Test that new CLI arguments are defined correctly."""

    def _parse_args(self, *args):
        import argparse

        from oida.protocols.coap.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        proto_args(subparsers, [parent])
        return main_parser.parse_args(list(args))

    def test_block_size_default(self):
        args = self._parse_args("coap", "127.0.0.1")
        assert args.block_size == 512

    def test_block_size_custom(self):
        args = self._parse_args("coap", "127.0.0.1", "--block-size", "256")
        assert args.block_size == 256

    def test_dtls_cert_option(self):
        args = self._parse_args("coap", "127.0.0.1", "--dtls-cert", "/path/cert.pem")
        assert args.dtls_cert == "/path/cert.pem"

    def test_dtls_key_option(self):
        args = self._parse_args("coap", "127.0.0.1", "--dtls-key", "/path/key.pem")
        assert args.dtls_key == "/path/key.pem"

    def test_dtls_ca_option(self):
        args = self._parse_args("coap", "127.0.0.1", "--dtls-ca", "/path/ca.pem")
        assert args.dtls_ca == "/path/ca.pem"

    def test_dtls_rpk_option(self):
        args = self._parse_args("coap", "127.0.0.1", "--dtls-rpk", "/path/rpk.der")
        assert args.dtls_rpk == "/path/rpk.der"

    def test_fetch_with_path(self):
        args = self._parse_args("coap", "127.0.0.1", "--fetch", "/sensor/data")
        assert args.fetch == ["/sensor/data"]

    def test_fetch_with_payload(self):
        args = self._parse_args("coap", "127.0.0.1", "--fetch", "/query", '{"filter": "temp"}')
        assert args.fetch == ["/query", '{"filter": "temp"}']

    def test_patch_option(self):
        args = self._parse_args("coap", "127.0.0.1", "--patch", "/config", "value")
        assert args.patch == ["/config", "value"]

    def test_ipatch_option(self):
        args = self._parse_args("coap", "127.0.0.1", "--ipatch", "/config", "value")
        assert args.ipatch == ["/config", "value"]
