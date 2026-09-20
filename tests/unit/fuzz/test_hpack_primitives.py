"""
Tests for HPACK encoding via the hpack library

Verifies that the hpack library integration used by the HTTP/2 fuzzer
works correctly:
- hpack.Encoder with disabled dynamic table produces correct output
- The _hpack_encode() module-level function in http2.py works
- Encoded headers can be decoded back correctly
- Edge cases (empty headers, long values, special chars) are handled

Note: hpack.Decoder.decode() returns list[tuple[str, str]], not bytes tuples.
"""

from tests.service_gate import require_import, require_service

hpack = require_import("hpack", reason="hpack library not installed")


class TestHpackEncoderBasics:
    """Tests for hpack.Encoder with disabled dynamic table."""

    def test_encoder_creates(self):
        """Encoder can be instantiated."""
        encoder = hpack.Encoder()
        assert encoder is not None

    def test_encoder_table_size_zero(self):
        """Encoder with table_size=0 produces stateless output."""
        encoder = hpack.Encoder()
        encoder.header_table_size = 0

        headers = [(b":method", b"GET"), (b":path", b"/")]
        encoded = encoder.encode(headers)
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

    def test_stateless_encoding(self):
        """Two separate Encoder instances produce identical output."""
        headers = [(b":method", b"GET"), (b":path", b"/"), (b":scheme", b"https")]

        enc1 = hpack.Encoder()
        enc1.header_table_size = 0
        result1 = enc1.encode(headers)

        enc2 = hpack.Encoder()
        enc2.header_table_size = 0
        result2 = enc2.encode(headers)

        assert result1 == result2

    def test_encode_decode_roundtrip(self):
        """Encoded headers can be decoded back correctly.

        hpack.Decoder.decode() returns str tuples, not bytes.
        """
        headers = [
            (b":method", b"GET"),
            (b":path", b"/test"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
        ]
        expected = [
            (":method", "GET"),
            (":path", "/test"),
            (":scheme", "https"),
            (":authority", "example.com"),
        ]

        encoder = hpack.Encoder()
        encoder.header_table_size = 0
        encoded = encoder.encode(headers)

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == expected

    def test_encode_custom_headers(self):
        """Custom (non-pseudo) headers encode correctly."""
        headers = [
            (b":method", b"POST"),
            (b":path", b"/api"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b"content-type", b"application/json"),
            (b"x-custom-header", b"custom-value"),
        ]
        expected = [
            (":method", "POST"),
            (":path", "/api"),
            (":scheme", "https"),
            (":authority", "localhost"),
            ("content-type", "application/json"),
            ("x-custom-header", "custom-value"),
        ]

        encoder = hpack.Encoder()
        encoder.header_table_size = 0
        encoded = encoder.encode(headers)

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == expected

    def test_empty_header_list(self):
        """Empty header list produces decodable output (may include table size update)."""
        encoder = hpack.Encoder()
        encoder.header_table_size = 0
        encoded = encoder.encode([])
        # With table_size=0, encoder may emit a dynamic table size update (0x20).
        # Verify it's still valid HPACK by decoding it.
        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == []

    def test_empty_header_value(self):
        """Header with empty value encodes correctly."""
        headers = [(b"x-empty", b"")]

        encoder = hpack.Encoder()
        encoder.header_table_size = 0
        encoded = encoder.encode(headers)

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == [("x-empty", "")]

    def test_long_header_value(self):
        """Long header values encode correctly."""
        long_value = "A" * 8192
        headers = [(b"x-long", long_value.encode())]

        encoder = hpack.Encoder()
        encoder.header_table_size = 0
        encoded = encoder.encode(headers)

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == [("x-long", long_value)]

    def test_many_headers(self):
        """Many headers encode correctly."""
        headers = [(f"x-header-{i}".encode(), f"value-{i}".encode()) for i in range(50)]
        expected = [(f"x-header-{i}", f"value-{i}") for i in range(50)]

        encoder = hpack.Encoder()
        encoder.header_table_size = 0
        encoded = encoder.encode(headers)

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == expected

    def test_sensitive_header(self):
        """NeverIndexedHeaderTuple marks sensitive headers."""
        headers = [
            hpack.NeverIndexedHeaderTuple(b"authorization", b"Bearer secret"),
        ]

        encoder = hpack.Encoder()
        encoder.header_table_size = 0
        encoded = encoder.encode(headers)

        # Should still decode correctly (decoder returns str tuples)
        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded[0] == ("authorization", "Bearer secret")


class TestHpackDecoder:
    """Tests for hpack.Decoder."""

    def test_decoder_creates(self):
        """Decoder can be instantiated."""
        decoder = hpack.Decoder()
        assert decoder is not None

    def test_decode_indexed_header(self):
        """Indexed header reference decodes correctly."""
        # 0x82 = indexed representation, index 2 = ":method: GET"
        encoded = bytes([0x82])
        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == [(":method", "GET")]

    def test_decode_multiple_indexed(self):
        """Multiple indexed headers decode correctly."""
        # 0x82 = :method GET, 0x84 = :path /, 0x86 = :scheme http
        encoded = bytes([0x82, 0x84, 0x86])
        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == [
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "http"),
        ]


class TestHpackHTTP2FuzzerIntegration:
    """Tests for the _hpack_encode function used by the HTTP/2 fuzzer."""

    def test_import_http2_fuzzer(self):
        """HTTP/2 fuzzer module can be imported."""
        try:
            from oida.fuzz.protocols.http2 import _hpack_encode

            assert callable(_hpack_encode)
        except ImportError:
            require_service("HTTP/2 fuzzer not available (boofuzz may not be installed)")

    def test_hpack_encode_basic(self):
        """_hpack_encode produces valid HPACK bytes."""
        try:
            from oida.fuzz.protocols.http2 import _hpack_encode
        except ImportError:
            require_service("HTTP/2 fuzzer not available")

        encoded = _hpack_encode(
            [
                (":method", "GET"),
                (":path", "/"),
                (":scheme", "https"),
                (":authority", "localhost"),
            ]
        )
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

        # Should be decodable (decoder returns str tuples)
        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert len(decoded) == 4
        assert decoded[0] == (":method", "GET")
        assert decoded[1] == (":path", "/")
        assert decoded[2] == (":scheme", "https")
        assert decoded[3] == (":authority", "localhost")

    def test_hpack_encode_post_with_content_type(self):
        """_hpack_encode handles POST request headers."""
        try:
            from oida.fuzz.protocols.http2 import _hpack_encode
        except ImportError:
            require_service("HTTP/2 fuzzer not available")

        encoded = _hpack_encode(
            [
                (":method", "POST"),
                (":path", "/api/data"),
                (":scheme", "https"),
                (":authority", "example.com"),
                ("content-type", "application/json"),
            ]
        )

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert len(decoded) == 5
        assert decoded[4] == ("content-type", "application/json")

    def test_hpack_encode_single_header(self):
        """_hpack_encode works for a single header pair."""
        try:
            from oida.fuzz.protocols.http2 import _hpack_encode
        except ImportError:
            require_service("HTTP/2 fuzzer not available")

        encoded = _hpack_encode([("x-test", "value")])
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == [("x-test", "value")]

    def test_hpack_encode_empty_list(self):
        """_hpack_encode handles empty header list."""
        try:
            from oida.fuzz.protocols.http2 import _hpack_encode
        except ImportError:
            require_service("HTTP/2 fuzzer not available")

        encoded = _hpack_encode([])
        assert isinstance(encoded, bytes)
        # Verify no headers decoded
        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == []

    def test_hpack_encode_user_agent(self):
        """_hpack_encode handles long User-Agent strings."""
        try:
            from oida.fuzz.protocols.http2 import _hpack_encode
        except ImportError:
            require_service("HTTP/2 fuzzer not available")

        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        encoded = _hpack_encode(
            [
                (":method", "GET"),
                (":path", "/"),
                (":scheme", "https"),
                (":authority", "test.com"),
                ("user-agent", ua),
            ]
        )

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded[4] == ("user-agent", ua)

    def test_hpack_encode_cookie(self):
        """_hpack_encode handles cookie headers."""
        try:
            from oida.fuzz.protocols.http2 import _hpack_encode
        except ImportError:
            require_service("HTTP/2 fuzzer not available")

        encoded = _hpack_encode(
            [
                (":method", "GET"),
                (":path", "/"),
                (":scheme", "https"),
                (":authority", "test.com"),
                ("cookie", "session=abc123; tracking=xyz"),
            ]
        )

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded[4] == ("cookie", "session=abc123; tracking=xyz")

    def test_hpack_encode_authorization(self):
        """_hpack_encode handles authorization headers."""
        try:
            from oida.fuzz.protocols.http2 import _hpack_encode
        except ImportError:
            require_service("HTTP/2 fuzzer not available")

        token = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc"
        encoded = _hpack_encode(
            [
                (":method", "GET"),
                (":path", "/api"),
                (":scheme", "https"),
                (":authority", "test.com"),
                ("authorization", token),
            ]
        )

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded[4] == ("authorization", token)

    def test_hpack_encode_duplicate_cookies(self):
        """_hpack_encode handles duplicate cookie headers (RFC 7540 Section 8.1.2.5)."""
        try:
            from oida.fuzz.protocols.http2 import _hpack_encode
        except ImportError:
            require_service("HTTP/2 fuzzer not available")

        encoded = _hpack_encode(
            [
                (":method", "GET"),
                (":path", "/"),
                (":scheme", "https"),
                (":authority", "test.com"),
                ("cookie", "session=abc"),
                ("cookie", "tracking=xyz"),
            ]
        )

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        # Both cookie headers should be preserved
        cookie_headers = [(n, v) for n, v in decoded if n == "cookie"]
        assert len(cookie_headers) == 2


class TestHpackEdgeCases:
    """Edge cases for hpack encoding."""

    def test_special_characters_in_value(self):
        """Special characters in header values encode correctly."""
        encoder = hpack.Encoder()
        encoder.header_table_size = 0

        headers = [(b"x-test", b'value with "quotes" and <brackets>')]
        encoded = encoder.encode(headers)

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == [("x-test", 'value with "quotes" and <brackets>')]

    def test_printable_ascii_value(self):
        """Printable ASCII header values encode correctly."""
        encoder = hpack.Encoder()
        encoder.header_table_size = 0

        printable = "".join(chr(c) for c in range(32, 127))
        headers = [(b"x-printable", printable.encode())]
        encoded = encoder.encode(headers)

        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == [("x-printable", printable)]

    def test_unicode_in_string_headers(self):
        """String input is handled by _hpack_encode."""
        try:
            from oida.fuzz.protocols.http2 import _hpack_encode
        except ImportError:
            require_service("HTTP/2 fuzzer not available")

        # _hpack_encode accepts str tuples and converts to bytes
        encoded = _hpack_encode([("x-test", "hello")])
        decoder = hpack.Decoder()
        decoded = decoder.decode(encoded)
        assert decoded == [("x-test", "hello")]

    def test_max_header_table_entry(self):
        """Encoder with large table size still works."""
        encoder = hpack.Encoder()
        encoder.header_table_size = 65535

        headers = [(b":method", b"GET"), (b":path", b"/")]
        encoded = encoder.encode(headers)
        assert len(encoded) > 0

    def test_repeated_encoding(self):
        """Stateless encoder produces same result each call."""
        headers = [
            (b":method", b"GET"),
            (b":path", b"/test"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
        ]

        results = []
        for _ in range(5):
            encoder = hpack.Encoder()
            encoder.header_table_size = 0
            results.append(encoder.encode(headers))

        # All should be identical since we use fresh encoders with no dynamic table
        for r in results[1:]:
            assert r == results[0]
