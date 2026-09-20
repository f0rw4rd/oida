"""
Extended unit tests for CoAP helper functions (oida.protocols.coap.helpers).

Drives the real parsing / dispatch / async-bridge logic. The only thing
mocked is the external boundary: the aiocoap library (reached through the
module-level ``_aiocoap`` lazy-import proxy and the aiocoap.credentials
module) and raw UDP sockets. The functions under test run unmodified.

Pure functions (parse_link_format, the _parse_* payload helpers,
_dtls_supports_kwargs) are exercised with real inputs and no mocking at
all.  No monkey-patching of the code under test.
"""

import asyncio
import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from oida.protocols.coap import helpers


# ---------------------------------------------------------------------------
# Async helpers
# ---------------------------------------------------------------------------


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _fake_aiocoap():
    """A minimal stand-in for the aiocoap module used by helpers.

    GET/POST/PUT/DELETE are sentinel ints; Message records its kwargs so the
    caller's request construction can be inspected.
    """
    mod = SimpleNamespace()
    mod.GET = 1
    mod.POST = 2
    mod.PUT = 3
    mod.DELETE = 4

    class _Opt:
        def __init__(self):
            self.content_format = None

    class _Message:
        def __init__(self, code=None, uri=None, payload=b""):
            self.code = code
            self.uri = uri
            self.payload = payload
            self.opt = _Opt()

    mod.Message = _Message
    # _get_method_map probes aiocoap.numbers.codes.Code for an iPATCH code;
    # provide the attribute chain (without iPATCH) so the lookup is exercised.
    mod.numbers = SimpleNamespace(codes=SimpleNamespace(Code=SimpleNamespace()))
    return mod


def _ctx_returning(response=None, exc=None):
    """Build a fake aiocoap context whose request(...).response awaits to
    *response* (or raises *exc*)."""
    ctx = MagicMock(name="ctx")

    async def _resp():
        if exc is not None:
            raise exc
        return response

    request_obj = SimpleNamespace(response=_resp())
    ctx.request = MagicMock(return_value=request_obj)
    return ctx


def _response(code="2.05", payload=b"", content_format=None):
    opt = SimpleNamespace(content_format=content_format)
    resp = SimpleNamespace()
    resp.code = code  # str() of "2.05" is "2.05"
    resp.payload = payload
    resp.opt = opt
    return resp


# ===========================================================================
# coap_ping (raw UDP socket -- error path exercised against a closed port)
# ===========================================================================


class TestCoapPing:
    def test_ping_unreachable_returns_false(self):
        # Nothing is listening; the recvfrom times out -> OSError -> False.
        # This drives the real socket send/recv/except/finally path.
        result = helpers.coap_ping("127.0.0.1", 1, timeout=0.2)
        assert result is False

    def test_ping_success_with_mock_socket(self):
        fake_sock = MagicMock()
        fake_sock.recvfrom.return_value = (b"\x60\x00\x00\x01", ("127.0.0.1", 5683))
        with patch("oida.protocols.coap.helpers.socket.socket", return_value=fake_sock):
            result = helpers.coap_ping("127.0.0.1", 5683, timeout=0.2)
        assert result is True
        fake_sock.sendto.assert_called_once()
        fake_sock.close.assert_called_once()

    def test_ping_empty_response_is_false(self):
        fake_sock = MagicMock()
        fake_sock.recvfrom.return_value = (b"", ("127.0.0.1", 5683))
        with patch("oida.protocols.coap.helpers.socket.socket", return_value=fake_sock):
            result = helpers.coap_ping("127.0.0.1", 5683, timeout=0.2)
        assert result is False

    def test_ping_verbatim_echo_reply_is_false(self):
        # A UDP echo/reflector service returns our CON ping byte-for-byte:
        # version and MID checks pass, but Type is still CON(0). A real CoAP
        # endpoint answers a CON with ACK(2) or RST(3), never a same-MID CON.
        fake_sock = MagicMock()
        fake_sock.recvfrom.return_value = (b"\x40\x00\x00\x01", ("127.0.0.1", 5683))
        with patch("oida.protocols.coap.helpers.socket.socket", return_value=fake_sock):
            result = helpers.coap_ping("127.0.0.1", 5683, timeout=0.2)
        assert result is False

    def test_ping_rst_reply_is_true(self):
        # Proper RST echo of our MID: 0x70 = Ver1/Type3(RST)/TKL0.
        fake_sock = MagicMock()
        fake_sock.recvfrom.return_value = (b"\x70\x00\x00\x01", ("127.0.0.1", 5683))
        with patch("oida.protocols.coap.helpers.socket.socket", return_value=fake_sock):
            result = helpers.coap_ping("127.0.0.1", 5683, timeout=0.2)
        assert result is True


# ===========================================================================
# coap_get
# ===========================================================================


class TestCoapGet:
    def test_get_success_returns_code_and_payload(self):
        ctx = _ctx_returning(_response("2.05", b"hello"))
        with patch.object(helpers, "_get_aiocoap", _fake_aiocoap):
            code, payload = _run(helpers.coap_get(ctx, "coap://h/r", timeout=1))
        assert code == "2.05"
        assert payload == b"hello"

    def test_get_timeout(self):
        ctx = _ctx_returning(exc=asyncio.TimeoutError())
        with patch.object(helpers, "_get_aiocoap", _fake_aiocoap):
            code, payload = _run(helpers.coap_get(ctx, "coap://h/r", timeout=0.01))
        assert code == "timeout"
        assert payload == b""

    def test_get_generic_error(self):
        ctx = _ctx_returning(exc=ValueError("boom"))
        with patch.object(helpers, "_get_aiocoap", _fake_aiocoap):
            code, payload = _run(helpers.coap_get(ctx, "coap://h/r", timeout=1))
        assert code.startswith("error:")
        assert "boom" in code
        assert payload == b""


# ===========================================================================
# _get_method_map + coap_request
# ===========================================================================


class TestMethodMapAndRequest:
    def setup_method(self):
        # Clear the module-level cache so each test rebuilds the map.
        helpers._method_map_cache.clear()

    def test_method_map_core_methods(self):
        with patch.object(helpers, "_get_aiocoap", _fake_aiocoap):
            m = helpers._get_method_map()
        assert m["GET"] == 1
        assert m["DELETE"] == 4
        # cached on the second call
        with patch.object(helpers, "_get_aiocoap", _fake_aiocoap):
            m2 = helpers._get_method_map()
        assert m2 is m

    def test_request_unsupported_method(self):
        with patch.object(helpers, "_get_aiocoap", _fake_aiocoap):
            result = _run(helpers.coap_request(MagicMock(), "BOGUS", "coap://h/r"))
        assert result["code"] == "unsupported"
        assert result["success"] is False

    def test_request_success_with_content_format(self):
        ctx = _ctx_returning(_response("2.04", b"ok", content_format=50))
        with patch.object(helpers, "_get_aiocoap", _fake_aiocoap):
            result = _run(
                helpers.coap_request(ctx, "post", "coap://h/r", payload=b"x", content_format=50)
            )
        assert result["code"] == "2.04"
        assert result["success"] is True
        assert result["content_format"] == 50
        # the request was constructed with our content_format
        sent = ctx.request.call_args.args[0]
        assert sent.opt.content_format == 50

    def test_request_non_2xx_is_not_success(self):
        ctx = _ctx_returning(_response("4.05", b""))
        with patch.object(helpers, "_get_aiocoap", _fake_aiocoap):
            result = _run(helpers.coap_request(ctx, "GET", "coap://h/r"))
        assert result["code"] == "4.05"
        assert result["success"] is False

    def test_request_timeout(self):
        ctx = _ctx_returning(exc=asyncio.TimeoutError())
        with patch.object(helpers, "_get_aiocoap", _fake_aiocoap):
            result = _run(helpers.coap_request(ctx, "GET", "coap://h/r", timeout=0.01))
        assert result["code"] == "timeout"
        assert result["success"] is False

    def test_request_generic_error(self):
        ctx = _ctx_returning(exc=RuntimeError("nope"))
        with patch.object(helpers, "_get_aiocoap", _fake_aiocoap):
            result = _run(helpers.coap_request(ctx, "GET", "coap://h/r"))
        assert result["code"].startswith("error:")
        assert result["success"] is False


# ===========================================================================
# parse_link_format (pure -- no mocking)
# ===========================================================================


class TestParseLinkFormat:
    def test_empty_returns_empty(self):
        assert helpers.parse_link_format("") == []
        assert helpers.parse_link_format("   ") == []

    def test_single_resource_attributes(self):
        out = helpers.parse_link_format('</sensor/temp>;rt="temperature";ct=0;if="sensor"')
        assert len(out) == 1
        r = out[0]
        assert r["path"] == "/sensor/temp"
        assert r["rt"] == "temperature"
        assert r["ct"] == 0
        assert r["if"] == "sensor"

    def test_obs_flag(self):
        out = helpers.parse_link_format("</s>;obs")
        assert out[0]["obs"] is True

    def test_multiple_resources(self):
        payload = '</a>;rt="x",</b>;ct=40,</c>;sz=128'
        out = helpers.parse_link_format(payload)
        paths = [r["path"] for r in out]
        assert paths == ["/a", "/b", "/c"]
        assert out[1]["ct"] == 40
        assert out[2]["sz"] == 128

    def test_non_numeric_ct_kept_as_string(self):
        out = helpers.parse_link_format("</a>;ct=abc")
        assert out[0]["ct"] == "abc"

    def test_entry_without_path_skipped(self):
        # Leading entry has no <...> bracket; it is dropped, the valid one kept
        out = helpers.parse_link_format("noangle;rt=x")
        assert out == []

    def test_empty_entry_between_commas(self):
        out = helpers.parse_link_format("</a>;rt=x")
        assert len(out) == 1


# ===========================================================================
# _parse_* payload helper error branches
# ===========================================================================


class TestParsePayloadHelpers:
    def test_parse_text_invalid_utf8_falls_back_to_hex(self):
        result = helpers._parse_text_payload(b"\xff\xfe", {"raw_size": 2})
        assert result["type"] == "binary"
        assert result["value"] == "fffe"

    def test_parse_json_invalid_falls_back_to_hex(self):
        result = helpers._parse_json_payload(b"\xff\xff", {"raw_size": 2}, 50)
        assert result["type"] == "binary"
        assert result["value"] == "ffff"

    def test_parse_json_senml_name(self):
        result = helpers._parse_json_payload(b'{"k":1}', {"raw_size": 7}, 110)
        assert result["type"] == "senml_json"
        assert result["value"] == {"k": 1}

    def test_parse_cbor_without_cbor2(self):
        fake_cbor2 = SimpleNamespace(is_available=False)
        with patch.object(helpers, "_cbor2", fake_cbor2):
            result = helpers._parse_cbor_payload(b"\x01\x02", {"raw_size": 2})
        assert result["type"] == "cbor_hex"
        assert result["value"] == "0102"

    def test_parse_cbor_with_cbor2(self):
        fake_cbor2 = SimpleNamespace(is_available=True, loads=lambda b: {"ok": True})
        with patch.object(helpers, "_cbor2", fake_cbor2):
            result = helpers._parse_cbor_payload(b"\xa1", {"raw_size": 1})
        assert result["type"] == "cbor"
        assert result["value"] == {"ok": True}

    def test_parse_cbor_decode_error_falls_back(self):
        def _raise(_b):
            raise ValueError("bad cbor")

        fake_cbor2 = SimpleNamespace(is_available=True, loads=_raise)
        with patch.object(helpers, "_cbor2", fake_cbor2):
            result = helpers._parse_cbor_payload(b"\xff", {"raw_size": 1})
        assert result["type"] == "binary"
        assert result["value"] == "ff"

    def test_parse_lwm2m_tlv_16bit_identifier(self):
        # type byte 0x28: type=00, id-len 16bit (0x20), len-type=01 (0x08)
        # id = 0x0102, then 1 length byte = 2, then 2 value bytes "AB"
        payload = bytes([0x28, 0x01, 0x02, 0x02]) + b"AB"
        result = helpers._parse_lwm2m_tlv(payload, {"raw_size": len(payload)})
        assert result["type"] == "lwm2m_tlv"
        rec = result["value"][0]
        assert rec["id"] == 0x0102
        assert rec["value"] == "AB"

    def test_parse_lwm2m_tlv_inline_length(self):
        # type byte 0xC3: type=11 (resource), 8-bit id, len-type=00 inline len=3
        payload = bytes([0xC3, 0x05]) + b"xyz"
        result = helpers._parse_lwm2m_tlv(payload, {"raw_size": len(payload)})
        rec = result["value"][0]
        assert rec["type"] == "resource"
        assert rec["id"] == 5
        assert rec["value"] == "xyz"


# ===========================================================================
# parse_payload top-level heuristics
# ===========================================================================


class TestParsePayloadDispatch:
    def test_text_plain_content_format(self):
        result = helpers.parse_payload(b"hello", content_format=0)
        assert result["type"] == "text"
        assert result["value"] == "hello"

    def test_heuristic_text(self):
        result = helpers.parse_payload(b"plain words")
        assert result["type"] == "text"

    def test_heuristic_binary_fallback(self):
        result = helpers.parse_payload(b"\x00\x01\x02\xff")
        assert result["type"] == "binary"
        assert result["value"] == "000102ff"

    def test_heuristic_json(self):
        result = helpers.parse_payload(b'{"a": 1}')
        assert result["type"] == "json"
        assert result["value"] == {"a": 1}

    def test_empty(self):
        result = helpers.parse_payload(b"")
        assert result["type"] == "empty"
        assert result["raw_size"] == 0


# ===========================================================================
# _dtls_supports_kwargs (signature introspection -- pure)
# ===========================================================================


class TestDtlsSupportsKwargs:
    def test_psk_only_backend_rejects_cert(self):
        class _DTLS:
            def __init__(self, psk=None, client_identity=None):
                pass

        creds = SimpleNamespace(DTLS=_DTLS)
        assert helpers._dtls_supports_kwargs(creds, "psk") is True
        assert helpers._dtls_supports_kwargs(creds, "client_cert") is False

    def test_var_keyword_backend_accepts_anything(self):
        class _DTLS:
            def __init__(self, **kwargs):
                pass

        creds = SimpleNamespace(DTLS=_DTLS)
        assert helpers._dtls_supports_kwargs(creds, "raw_public_key") is True

    def test_missing_dtls_class(self):
        creds = SimpleNamespace(DTLS=None)
        assert helpers._dtls_supports_kwargs(creds, "psk") is False

    def test_uninspectable_signature_falls_back_to_call(self):
        # A builtin-like callable whose signature can't be introspected.
        class _DTLS:
            def __init__(self, *a, **k):
                # accepts the probe call (k = {kw: b""}) -> supported
                pass

        # Force the signature path to raise so the fallback call runs.
        creds = SimpleNamespace(DTLS=_DTLS)
        with patch.object(inspect, "signature", side_effect=ValueError("no sig")):
            assert helpers._dtls_supports_kwargs(creds, "psk") is True


# ===========================================================================
# try_dtls_psk (async; aiocoap + aiocoap.credentials mocked)
# ===========================================================================


class TestTryDtlsPsk:
    def _patch_creds(self, dtls_cls=None):
        """Return a patch context for importlib.import_module returning a fake
        aiocoap.credentials module."""

        class _CredsMap(dict):
            pass

        class _DTLS:
            def __init__(self, psk=None, client_identity=None):
                self.psk = psk
                self.client_identity = client_identity

        fake_creds = SimpleNamespace(CredentialsMap=_CredsMap, DTLS=dtls_cls or _DTLS)
        return patch(
            "oida.protocols.coap.helpers.importlib.import_module",
            return_value=fake_creds,
        )

    def _fake_aiocoap_ctx(self, response=None, exc=None):
        mod = _fake_aiocoap()
        ctx = _ctx_returning(response, exc)

        async def _create_client_context():
            return ctx

        ctx.shutdown = AsyncMock(return_value=None)
        mod.Context = SimpleNamespace(create_client_context=_create_client_context)
        return mod, ctx

    def test_psk_success_hex_key(self):
        mod, ctx = self._fake_aiocoap_ctx(_response("2.05", b""))
        with patch.object(helpers, "_get_aiocoap", lambda: mod), self._patch_creds():
            ok, returned_ctx, detail = _run(
                helpers.try_dtls_psk("h", 5684, "ident", "deadbeef", timeout=1)
            )
        assert ok is True
        assert returned_ctx is ctx
        assert detail == "2.05"

    def test_psk_success_with_4xx_response(self):
        # A 4.xx is still a real CoAP reply => DTLS handshake succeeded.
        mod, ctx = self._fake_aiocoap_ctx(_response("4.01", b""))
        with patch.object(helpers, "_get_aiocoap", lambda: mod), self._patch_creds():
            ok, _ctx, detail = _run(
                helpers.try_dtls_psk("h", 5684, "ident", "notahexkey", timeout=1)
            )
        assert ok is True
        assert detail == "4.01"

    def test_psk_unexpected_response_closes(self):
        mod, ctx = self._fake_aiocoap_ctx(_response("5.00", b""))
        with patch.object(helpers, "_get_aiocoap", lambda: mod), self._patch_creds():
            ok, returned_ctx, detail = _run(
                helpers.try_dtls_psk("h", 5684, "ident", "aa", timeout=1)
            )
        assert ok is False
        assert returned_ctx is None
        assert "unexpected response" in detail

    def test_psk_timeout(self):
        mod, ctx = self._fake_aiocoap_ctx(exc=asyncio.TimeoutError())
        with patch.object(helpers, "_get_aiocoap", lambda: mod), self._patch_creds():
            ok, returned_ctx, detail = _run(
                helpers.try_dtls_psk("h", 5684, "ident", "aa", timeout=0.01)
            )
        assert ok is False
        assert detail == "timeout"

    def test_psk_generic_error(self):
        mod, ctx = self._fake_aiocoap_ctx(exc=RuntimeError("handshake fail"))
        with patch.object(helpers, "_get_aiocoap", lambda: mod), self._patch_creds():
            ok, returned_ctx, detail = _run(
                helpers.try_dtls_psk("h", 5684, "ident", "aa", timeout=1)
            )
        assert ok is False
        assert "handshake fail" in detail


# ===========================================================================
# try_dtls_cert / try_dtls_rpk -- unsupported-backend honest reporting
# ===========================================================================


class TestTryDtlsCertRpkUnsupported:
    def _patch_psk_only_creds(self):
        class _CredsMap(dict):
            pass

        class _DTLS:  # PSK-only signature, rejects cert / rpk kwargs
            def __init__(self, psk=None, client_identity=None):
                pass

        fake_creds = SimpleNamespace(CredentialsMap=_CredsMap, DTLS=_DTLS)
        return patch(
            "oida.protocols.coap.helpers.importlib.import_module",
            return_value=fake_creds,
        )

    def test_cert_unsupported_backend(self):
        mod = _fake_aiocoap()
        with patch.object(helpers, "_get_aiocoap", lambda: mod), self._patch_psk_only_creds():
            ok, ctx, detail = _run(helpers.try_dtls_cert("h", 5684, "/no/cert.pem", "/no/key.pem"))
        assert ok is False
        assert ctx is None
        assert "not supported" in detail.lower()

    def test_rpk_unsupported_backend(self):
        mod = _fake_aiocoap()
        with patch.object(helpers, "_get_aiocoap", lambda: mod), self._patch_psk_only_creds():
            ok, ctx, detail = _run(helpers.try_dtls_rpk("h", 5684, "/no/rpk.der"))
        assert ok is False
        assert ctx is None
        assert "not supported" in detail.lower()

    def test_cert_missing_dtls_class(self):
        mod = _fake_aiocoap()
        fake_creds = SimpleNamespace(CredentialsMap=dict)  # no DTLS attribute
        with (
            patch.object(helpers, "_get_aiocoap", lambda: mod),
            patch(
                "oida.protocols.coap.helpers.importlib.import_module",
                return_value=fake_creds,
            ),
        ):
            ok, ctx, detail = _run(helpers.try_dtls_cert("h", 5684, "/no/cert.pem", "/no/key.pem"))
        assert ok is False
        assert "DTLS" in detail


# ===========================================================================
# try_dtls_cert -- cert auth supported, exercises file reading + success
# ===========================================================================


class TestTryDtlsCertSupported:
    def _fake_creds_with_cert_support(self):
        class _CredsMap(dict):
            pass

        class _DTLS:  # accepts cert kwargs
            def __init__(self, client_cert=None, private_key=None, ca_certs=None):
                self.client_cert = client_cert
                self.private_key = private_key

        return SimpleNamespace(CredentialsMap=_CredsMap, DTLS=_DTLS)

    def test_cert_file_not_found(self):
        mod = _fake_aiocoap()
        creds = self._fake_creds_with_cert_support()
        with (
            patch.object(helpers, "_get_aiocoap", lambda: mod),
            patch(
                "oida.protocols.coap.helpers.importlib.import_module",
                return_value=creds,
            ),
        ):
            ok, ctx, detail = _run(
                helpers.try_dtls_cert("h", 5684, "/definitely/missing/cert.pem", "/missing/key.pem")
            )
        assert ok is False
        assert "not found" in detail.lower()

    def test_cert_success(self, tmp_path):
        cert = tmp_path / "c.pem"
        key = tmp_path / "k.pem"
        cert.write_bytes(b"CERT")
        key.write_bytes(b"KEY")

        mod = _fake_aiocoap()
        ctx = _ctx_returning(_response("2.05", b""))

        async def _create_client_context():
            return ctx

        ctx.shutdown = AsyncMock(return_value=None)
        mod.Context = SimpleNamespace(create_client_context=_create_client_context)
        creds = self._fake_creds_with_cert_support()

        with (
            patch.object(helpers, "_get_aiocoap", lambda: mod),
            patch(
                "oida.protocols.coap.helpers.importlib.import_module",
                return_value=creds,
            ),
        ):
            ok, returned_ctx, detail = _run(helpers.try_dtls_cert("h", 5684, str(cert), str(key)))
        assert ok is True
        assert returned_ctx is ctx
        assert detail == "2.05"

    def _cert_with_response(self, tmp_path, response=None, exc=None):
        cert = tmp_path / "c.pem"
        key = tmp_path / "k.pem"
        cert.write_bytes(b"CERT")
        key.write_bytes(b"KEY")
        mod = _fake_aiocoap()
        ctx = _ctx_returning(response, exc)

        async def _create_client_context():
            return ctx

        ctx.shutdown = AsyncMock(return_value=None)
        mod.Context = SimpleNamespace(create_client_context=_create_client_context)
        creds = self._fake_creds_with_cert_support()
        return mod, ctx, str(cert), str(key), creds

    def test_cert_unexpected_response(self, tmp_path):
        mod, ctx, cert, key, creds = self._cert_with_response(
            tmp_path, response=_response("5.00", b"")
        )
        with (
            patch.object(helpers, "_get_aiocoap", lambda: mod),
            patch(
                "oida.protocols.coap.helpers.importlib.import_module",
                return_value=creds,
            ),
        ):
            ok, returned_ctx, detail = _run(helpers.try_dtls_cert("h", 5684, cert, key))
        assert ok is False
        assert returned_ctx is None
        assert "unexpected response" in detail
        ctx.shutdown.assert_awaited_once()

    def test_cert_timeout(self, tmp_path):
        mod, ctx, cert, key, creds = self._cert_with_response(tmp_path, exc=asyncio.TimeoutError())
        with (
            patch.object(helpers, "_get_aiocoap", lambda: mod),
            patch(
                "oida.protocols.coap.helpers.importlib.import_module",
                return_value=creds,
            ),
        ):
            ok, _ctx, detail = _run(helpers.try_dtls_cert("h", 5684, cert, key))
        assert ok is False
        assert detail == "timeout"

    def test_cert_generic_error(self, tmp_path):
        mod, ctx, cert, key, creds = self._cert_with_response(
            tmp_path, exc=RuntimeError("tls blew up")
        )
        with (
            patch.object(helpers, "_get_aiocoap", lambda: mod),
            patch(
                "oida.protocols.coap.helpers.importlib.import_module",
                return_value=creds,
            ),
        ):
            ok, _ctx, detail = _run(helpers.try_dtls_cert("h", 5684, cert, key))
        assert ok is False
        assert "tls blew up" in detail


# ===========================================================================
# try_dtls_rpk -- RPK auth supported path
# ===========================================================================


class TestTryDtlsRpkSupported:
    def _creds_with_rpk_support(self):
        class _CredsMap(dict):
            pass

        class _DTLS:
            def __init__(self, raw_public_key=None):
                self.raw_public_key = raw_public_key

        return SimpleNamespace(CredentialsMap=_CredsMap, DTLS=_DTLS)

    def test_rpk_file_not_found(self):
        mod = _fake_aiocoap()
        creds = self._creds_with_rpk_support()
        with (
            patch.object(helpers, "_get_aiocoap", lambda: mod),
            patch(
                "oida.protocols.coap.helpers.importlib.import_module",
                return_value=creds,
            ),
        ):
            ok, ctx, detail = _run(helpers.try_dtls_rpk("h", 5684, "/missing/rpk.der"))
        assert ok is False
        assert "not found" in detail.lower()

    def test_rpk_success(self, tmp_path):
        rpk = tmp_path / "rpk.der"
        rpk.write_bytes(b"RAWKEY")
        mod = _fake_aiocoap()
        ctx = _ctx_returning(_response("2.05", b""))

        async def _create_client_context():
            return ctx

        ctx.shutdown = AsyncMock(return_value=None)
        mod.Context = SimpleNamespace(create_client_context=_create_client_context)
        creds = self._creds_with_rpk_support()

        with (
            patch.object(helpers, "_get_aiocoap", lambda: mod),
            patch(
                "oida.protocols.coap.helpers.importlib.import_module",
                return_value=creds,
            ),
        ):
            ok, returned_ctx, detail = _run(helpers.try_dtls_rpk("h", 5684, str(rpk)))
        assert ok is True
        assert returned_ctx is ctx
        assert detail == "2.05"

    def test_rpk_timeout(self, tmp_path):
        rpk = tmp_path / "rpk.der"
        rpk.write_bytes(b"RAWKEY")
        mod = _fake_aiocoap()
        ctx = _ctx_returning(exc=asyncio.TimeoutError())

        async def _create_client_context():
            return ctx

        ctx.shutdown = AsyncMock(return_value=None)
        mod.Context = SimpleNamespace(create_client_context=_create_client_context)
        creds = self._creds_with_rpk_support()

        with (
            patch.object(helpers, "_get_aiocoap", lambda: mod),
            patch(
                "oida.protocols.coap.helpers.importlib.import_module",
                return_value=creds,
            ),
        ):
            ok, _ctx, detail = _run(helpers.try_dtls_rpk("h", 5684, str(rpk)))
        assert ok is False
        assert detail == "timeout"


# ===========================================================================
# _get_method_map with extended methods (FETCH/PATCH/iPATCH present)
# ===========================================================================


class TestMethodMapExtended:
    def setup_method(self):
        helpers._method_map_cache.clear()

    def teardown_method(self):
        helpers._method_map_cache.clear()

    def test_extended_methods_included(self):
        mod = _fake_aiocoap()
        mod.FETCH = 5
        mod.PATCH = 6
        mod.iPATCH = 7
        with patch.object(helpers, "_get_aiocoap", lambda: mod):
            m = helpers._get_method_map()
        assert m["FETCH"] == 5
        assert m["PATCH"] == 6
        assert m["IPATCH"] == 7

    def test_ipatch_from_numbers_codes(self):
        mod = _fake_aiocoap()
        # No top-level iPATCH; provided via numbers.codes.Code.iPATCH
        mod.numbers = SimpleNamespace(codes=SimpleNamespace(Code=SimpleNamespace(iPATCH=9)))
        with patch.object(helpers, "_get_aiocoap", lambda: mod):
            m = helpers._get_method_map()
        assert m["IPATCH"] == 9


# ---------------------------------------------------------------------------
# misc helpers
# ---------------------------------------------------------------------------


class TestModuleHelpers:
    def test_is_aiocoap_available_reflects_proxy(self):
        fake = MagicMock()
        fake.is_available = True
        with patch.object(helpers, "_aiocoap", fake):
            assert helpers.is_aiocoap_available() is True
        fake.is_available = False
        with patch.object(helpers, "_aiocoap", fake):
            assert helpers.is_aiocoap_available() is False

    def test_event_loop_holder_reuses_loop(self):
        loop1 = helpers._EventLoopHolder.get()
        loop2 = helpers._EventLoopHolder.get()
        assert loop1 is loop2

    def test_run_async_executes_coroutine(self):
        async def _add():
            return 3 + 4

        assert helpers.run_async(_add()) == 7
