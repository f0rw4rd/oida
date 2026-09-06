"""
Tests for transformer classes.

Tests cover:
- BaseTransformer: Abstract interface and to_encoder_func()
- TransformerChain: Chaining multiple transformers
- Base64Transformer: Standard and URL-safe variants
- URLEncodeTransformer: Percent encoding variants
- HexTransformer: Hex encoding with options
- HTMLEntityTransformer: HTML entity escaping
- JSONEscapeTransformer: JSON string escaping
- XMLEscapeTransformer: XML special character escaping
- GzipTransformer: Gzip compression
- DeflateTransformer: Deflate compression (raw and zlib)
- BrotliTransformer: Brotli compression (optional)
- IdentityTransformer: Pass-through transformer
"""

import pytest
import gzip
import zlib
import base64


# =============================================================================
# Test BaseTransformer Interface
# =============================================================================


class TestBaseTransformerInterface:
    """Tests for BaseTransformer abstract class."""

    def test_cannot_instantiate_base_transformer(self):
        """BaseTransformer cannot be instantiated directly."""
        from oida.fuzz.primitives.transformers.base import BaseTransformer

        with pytest.raises(TypeError):
            BaseTransformer()

    def test_base_transformer_requires_encode(self):
        """Subclass must implement encode."""
        from oida.fuzz.primitives.transformers.base import BaseTransformer

        class IncompleteTransformer(BaseTransformer):
            def decode(self, data):
                return data

            @property
            def name(self):
                return "incomplete"

        with pytest.raises(TypeError):
            IncompleteTransformer()

    def test_base_transformer_requires_decode(self):
        """Subclass must implement decode."""
        from oida.fuzz.primitives.transformers.base import BaseTransformer

        class IncompleteTransformer(BaseTransformer):
            def encode(self, data):
                return data

            @property
            def name(self):
                return "incomplete"

        with pytest.raises(TypeError):
            IncompleteTransformer()

    def test_base_transformer_requires_name(self):
        """Subclass must implement name property."""
        from oida.fuzz.primitives.transformers.base import BaseTransformer

        class IncompleteTransformer(BaseTransformer):
            def encode(self, data):
                return data

            def decode(self, data):
                return data

        with pytest.raises(TypeError):
            IncompleteTransformer()


class TestBaseTransformerEncoderFunc:
    """Tests for BaseTransformer.to_encoder_func()."""

    def test_to_encoder_func_returns_callable(self):
        """to_encoder_func() returns a callable."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()
        encoder_func = transformer.to_encoder_func()
        assert callable(encoder_func)

    def test_encoder_func_encodes_bytes(self):
        """Encoder function handles bytes input."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()
        encoder_func = transformer.to_encoder_func()

        result = encoder_func(b"test data")
        assert result == b"dGVzdCBkYXRh"

    def test_encoder_func_encodes_str(self):
        """Encoder function converts str to bytes."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()
        encoder_func = transformer.to_encoder_func()

        result = encoder_func("test data")
        assert result == b"dGVzdCBkYXRh"

    def test_encoder_func_handles_bytearray(self):
        """Encoder function handles bytearray input."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()
        encoder_func = transformer.to_encoder_func()

        result = encoder_func(bytearray(b"test"))
        assert result == b"dGVzdA=="

    def test_encoder_func_returns_original_on_error(self):
        """Encoder function returns original data on encoding error."""
        from oida.fuzz.primitives.transformers.base import BaseTransformer

        class FailingTransformer(BaseTransformer):
            def encode(self, data):
                raise ValueError("Encoding failed")

            def decode(self, data):
                return data

            @property
            def name(self):
                return "failing"

        transformer = FailingTransformer()
        encoder_func = transformer.to_encoder_func()

        result = encoder_func(b"test")
        assert result == b"test"  # Returns original on error


class TestBaseTransformerRepr:
    """Tests for BaseTransformer string representation."""

    def test_repr_includes_class_name(self):
        """__repr__ includes class name."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()
        repr_str = repr(transformer)

        assert "Base64Transformer" in repr_str
        assert "Base64" in repr_str


# =============================================================================
# Test TransformerChain
# =============================================================================


class TestTransformerChainCreation:
    """Tests for TransformerChain instantiation."""

    def test_basic_creation(self):
        """TransformerChain can be created with transformers."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        chain = TransformerChain(Base64Transformer())
        assert chain is not None
        assert len(chain.transformers) == 1

    def test_creation_with_multiple_transformers(self):
        """TransformerChain accepts multiple transformers."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer, HexTransformer

        chain = TransformerChain(HexTransformer(), Base64Transformer())
        assert len(chain.transformers) == 2

    def test_creation_empty_raises(self):
        """TransformerChain raises if no transformers provided."""
        from oida.fuzz.primitives.transformers.base import TransformerChain

        with pytest.raises(ValueError, match="requires at least one"):
            TransformerChain()

    def test_creation_with_invalid_transformer_raises(self):
        """TransformerChain raises for non-transformer objects."""
        from oida.fuzz.primitives.transformers.base import TransformerChain

        with pytest.raises(ValueError, match="Expected BaseTransformer"):
            TransformerChain("not a transformer")


class TestTransformerChainEncode:
    """Tests for TransformerChain encode method."""

    def test_encode_applies_transformers_in_order(self):
        """Transformers are applied in order during encode."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.compression import GzipTransformer
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        # Gzip then Base64
        chain = TransformerChain(GzipTransformer(), Base64Transformer())

        data = b"test data"
        encoded = chain.encode(data)

        # Verify by decoding in reverse order
        base64_decoded = base64.b64decode(encoded)
        gzip_decoded = gzip.decompress(base64_decoded)
        assert gzip_decoded == data

    def test_encode_single_transformer(self):
        """Single transformer chain works correctly."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        chain = TransformerChain(HexTransformer())
        result = chain.encode(b"AB")

        assert result == b"4142"


class TestTransformerChainDecode:
    """Tests for TransformerChain decode method."""

    def test_decode_applies_transformers_in_reverse_order(self):
        """Transformers are applied in reverse order during decode."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.compression import GzipTransformer
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        # Gzip then Base64 during encode
        chain = TransformerChain(GzipTransformer(), Base64Transformer())

        data = b"test data for chain"
        encoded = chain.encode(data)
        decoded = chain.decode(encoded)

        assert decoded == data

    def test_round_trip(self):
        """encode() followed by decode() returns original data."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.encoding import (
            Base64Transformer,
            URLEncodeTransformer,
        )

        chain = TransformerChain(URLEncodeTransformer(), Base64Transformer())

        data = b"Hello World! & more"
        assert chain.decode(chain.encode(data)) == data


class TestTransformerChainProperties:
    """Tests for TransformerChain properties."""

    def test_name_combines_transformer_names(self):
        """name property combines all transformer names."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.compression import GzipTransformer
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        chain = TransformerChain(GzipTransformer(level=6), Base64Transformer())

        assert "Gzip" in chain.name
        assert "Base64" in chain.name
        assert "->" in chain.name

    def test_repr_lists_transformers(self):
        """__repr__ lists all transformers."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        chain = TransformerChain(HexTransformer())
        repr_str = repr(chain)

        assert "TransformerChain" in repr_str
        assert "Hex" in repr_str

    def test_to_encoder_func(self):
        """to_encoder_func() returns working encoder."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        chain = TransformerChain(Base64Transformer())
        encoder = chain.to_encoder_func()

        result = encoder(b"test")
        assert result == b"dGVzdA=="


# =============================================================================
# Test Base64Transformer
# =============================================================================


class TestBase64TransformerCreation:
    """Tests for Base64Transformer instantiation."""

    def test_default_creation(self):
        """Default Base64Transformer can be created."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()
        assert transformer.urlsafe is False
        assert transformer.strip_padding is False

    def test_urlsafe_creation(self):
        """URL-safe Base64Transformer can be created."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(urlsafe=True)
        assert transformer.urlsafe is True

    def test_strip_padding_creation(self):
        """Strip-padding Base64Transformer can be created."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(strip_padding=True)
        assert transformer.strip_padding is True

    def test_prefix_suffix_creation(self):
        """Base64Transformer with prefix/suffix can be created."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(prefix=b"Basic ", suffix=b"\r\n")
        assert transformer.prefix == b"Basic "
        assert transformer.suffix == b"\r\n"


class TestBase64TransformerEncode:
    """Tests for Base64Transformer encode method."""

    def test_encode_standard(self):
        """Standard Base64 encoding works."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()
        result = transformer.encode(b"admin:password123")

        assert result == b"YWRtaW46cGFzc3dvcmQxMjM="

    def test_encode_urlsafe(self):
        """URL-safe Base64 uses - and _ instead of + and /."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(urlsafe=True)
        # Data that produces + and / in standard Base64
        data = b"\xfb\xff\xfe"  # Would be +//+ in standard

        result = transformer.encode(data)

        assert b"+" not in result
        assert b"/" not in result

    def test_encode_strip_padding(self):
        """Strip padding removes trailing = characters."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(strip_padding=True)
        result = transformer.encode(b"a")  # "YQ==" with padding

        assert b"=" not in result
        assert result == b"YQ"

    def test_encode_with_prefix(self):
        """Prefix is prepended to encoded data."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(prefix=b"Basic ")
        result = transformer.encode(b"user:pass")

        assert result.startswith(b"Basic ")

    def test_encode_empty(self):
        """Empty data encodes to empty string."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()
        result = transformer.encode(b"")

        assert result == b""


class TestBase64TransformerDecode:
    """Tests for Base64Transformer decode method."""

    def test_decode_standard(self):
        """Standard Base64 decoding works."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()
        result = transformer.decode(b"YWRtaW46cGFzc3dvcmQxMjM=")

        assert result == b"admin:password123"

    def test_decode_urlsafe(self):
        """URL-safe Base64 decoding works."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(urlsafe=True)
        # URL-safe encoded data
        encoded = base64.urlsafe_b64encode(b"\xfb\xff\xfe")
        result = transformer.decode(encoded)

        assert result == b"\xfb\xff\xfe"

    def test_decode_strip_padding_adds_padding_back(self):
        """Decoding with strip_padding adds padding back."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(strip_padding=True)
        result = transformer.decode(b"YQ")  # "YQ==" without padding

        assert result == b"a"

    def test_decode_removes_prefix_suffix(self):
        """Decoding removes prefix and suffix."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(prefix=b"Basic ", suffix=b"\r\n")
        result = transformer.decode(b"Basic dXNlcjpwYXNz\r\n")

        assert result == b"user:pass"

    def test_decode_invalid_raises(self):
        """Invalid Base64 raises ValueError."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()

        with pytest.raises(ValueError, match="Invalid Base64"):
            transformer.decode(b"!!!not valid base64!!!")


class TestBase64TransformerRoundTrip:
    """Tests for Base64Transformer round-trip encoding."""

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"Hello World!",
            b"\x00\xff\xfe\xfd",
            b"A" * 1000,
        ],
    )
    def test_round_trip_standard(self, data):
        """Standard Base64 round-trip works for various inputs."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()
        assert transformer.decode(transformer.encode(data)) == data

    @pytest.mark.parametrize(
        "data",
        [
            b"test",
            b"\xfb\xff\xfe",
            b"special+chars/here",
        ],
    )
    def test_round_trip_urlsafe(self, data):
        """URL-safe Base64 round-trip works."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(urlsafe=True, strip_padding=True)
        assert transformer.decode(transformer.encode(data)) == data


class TestBase64TransformerName:
    """Tests for Base64Transformer name property."""

    def test_name_standard(self):
        """Standard variant has simple name."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer()
        assert transformer.name == "Base64"

    def test_name_urlsafe(self):
        """URL-safe variant includes urlsafe in name."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(urlsafe=True)
        assert "urlsafe" in transformer.name

    def test_name_nopad(self):
        """Strip padding variant includes nopad in name."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        transformer = Base64Transformer(strip_padding=True)
        assert "nopad" in transformer.name


# =============================================================================
# Test URLEncodeTransformer
# =============================================================================


class TestURLEncodeTransformerCreation:
    """Tests for URLEncodeTransformer instantiation."""

    def test_default_creation(self):
        """Default URLEncodeTransformer can be created."""
        from oida.fuzz.primitives.transformers.encoding import URLEncodeTransformer

        transformer = URLEncodeTransformer()
        assert transformer.plus_encoding is False
        assert transformer.safe == ""

    def test_plus_encoding_creation(self):
        """Plus-encoding URLEncodeTransformer can be created."""
        from oida.fuzz.primitives.transformers.encoding import URLEncodeTransformer

        transformer = URLEncodeTransformer(plus_encoding=True)
        assert transformer.plus_encoding is True

    def test_safe_chars_creation(self):
        """URLEncodeTransformer with safe chars can be created."""
        from oida.fuzz.primitives.transformers.encoding import URLEncodeTransformer

        transformer = URLEncodeTransformer(safe="/")
        assert transformer.safe == "/"


class TestURLEncodeTransformerEncode:
    """Tests for URLEncodeTransformer encode method."""

    def test_encode_spaces_as_percent(self):
        """Standard encoding uses %20 for spaces."""
        from oida.fuzz.primitives.transformers.encoding import URLEncodeTransformer

        transformer = URLEncodeTransformer()
        result = transformer.encode(b"Hello World")

        assert result == b"Hello%20World"

    def test_encode_spaces_as_plus(self):
        """Plus encoding uses + for spaces."""
        from oida.fuzz.primitives.transformers.encoding import URLEncodeTransformer

        transformer = URLEncodeTransformer(plus_encoding=True)
        result = transformer.encode(b"Hello World")

        assert result == b"Hello+World"

    def test_encode_special_chars(self):
        """Special characters are encoded."""
        from oida.fuzz.primitives.transformers.encoding import URLEncodeTransformer

        transformer = URLEncodeTransformer()
        result = transformer.encode(b"key=value&other=123")

        assert b"%3D" in result  # =
        assert b"%26" in result  # &

    def test_encode_safe_chars_not_encoded(self):
        """Safe characters are not encoded."""
        from oida.fuzz.primitives.transformers.encoding import URLEncodeTransformer

        transformer = URLEncodeTransformer(safe="/")
        result = transformer.encode(b"path/to/resource")

        assert b"/" in result
        assert b"%2F" not in result


class TestURLEncodeTransformerDecode:
    """Tests for URLEncodeTransformer decode method."""

    def test_decode_percent_encoded(self):
        """Percent-encoded data is decoded."""
        from oida.fuzz.primitives.transformers.encoding import URLEncodeTransformer

        transformer = URLEncodeTransformer()
        result = transformer.decode(b"Hello%20World%21")

        assert result == b"Hello World!"

    def test_decode_plus_encoded(self):
        """Plus-encoded data is decoded."""
        from oida.fuzz.primitives.transformers.encoding import URLEncodeTransformer

        transformer = URLEncodeTransformer(plus_encoding=True)
        result = transformer.decode(b"Hello+World")

        assert result == b"Hello World"


class TestURLEncodeTransformerRoundTrip:
    """Tests for URLEncodeTransformer round-trip."""

    @pytest.mark.parametrize(
        "data",
        [
            b"simple",
            b"Hello World",
            b"key=value&foo=bar",
            b"special!@#$%^&*()",
            b"unicode: \xc3\xa9",  # UTF-8 é
        ],
    )
    def test_round_trip(self, data):
        """Round-trip encoding/decoding preserves data."""
        from oida.fuzz.primitives.transformers.encoding import URLEncodeTransformer

        transformer = URLEncodeTransformer()
        assert transformer.decode(transformer.encode(data)) == data


# =============================================================================
# Test HexTransformer
# =============================================================================


class TestHexTransformerCreation:
    """Tests for HexTransformer instantiation."""

    def test_default_creation(self):
        """Default HexTransformer uses lowercase."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer()
        assert transformer.uppercase is False

    def test_uppercase_creation(self):
        """Uppercase HexTransformer can be created."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer(uppercase=True)
        assert transformer.uppercase is True

    def test_prefix_creation(self):
        """HexTransformer with prefix can be created."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer(prefix=b"0x")
        assert transformer.prefix == b"0x"

    def test_delimiter_creation(self):
        """HexTransformer with delimiter can be created."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer(delimiter=b":")
        assert transformer.delimiter == b":"


class TestHexTransformerEncode:
    """Tests for HexTransformer encode method."""

    def test_encode_lowercase(self):
        """Default encoding produces lowercase hex."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer()
        result = transformer.encode(b"\xab\xcd\xef")

        assert result == b"abcdef"

    def test_encode_uppercase(self):
        """Uppercase encoding produces uppercase hex."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer(uppercase=True)
        result = transformer.encode(b"\xab\xcd\xef")

        assert result == b"ABCDEF"

    def test_encode_with_prefix(self):
        """Prefix is prepended to hex string."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer(prefix=b"0x")
        result = transformer.encode(b"\x01\x02")

        assert result == b"0x0102"

    def test_encode_with_delimiter(self):
        """Delimiter separates byte pairs."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer(delimiter=b":")
        result = transformer.encode(b"\x01\x02\x03")

        assert result == b"01:02:03"

    def test_encode_mac_address_style(self):
        """MAC address style encoding works."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer(uppercase=True, delimiter=b":")
        result = transformer.encode(b"\xaa\xbb\xcc\xdd\xee\xff")

        assert result == b"AA:BB:CC:DD:EE:FF"


class TestHexTransformerDecode:
    """Tests for HexTransformer decode method."""

    def test_decode_lowercase(self):
        """Lowercase hex is decoded."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer()
        result = transformer.decode(b"48656c6c6f")

        assert result == b"Hello"

    def test_decode_uppercase(self):
        """Uppercase hex is decoded."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer(uppercase=True)
        result = transformer.decode(b"48656C6C6F")

        assert result == b"Hello"

    def test_decode_removes_prefix(self):
        """Prefix is removed during decode."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer(prefix=b"0x")
        result = transformer.decode(b"0x4142")

        assert result == b"AB"

    def test_decode_removes_delimiter(self):
        """Delimiter is removed during decode."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer(delimiter=b":")
        result = transformer.decode(b"41:42:43")

        assert result == b"ABC"

    def test_decode_invalid_raises(self):
        """Invalid hex raises ValueError."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer()

        with pytest.raises(ValueError, match="Invalid hex"):
            transformer.decode(b"not valid hex!")


class TestHexTransformerRoundTrip:
    """Tests for HexTransformer round-trip."""

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"\x00",
            b"\xff",
            b"Hello",
            b"\x00\x01\x02\x03\x04\x05",
            b"A" * 100,
        ],
    )
    def test_round_trip(self, data):
        """Round-trip encoding/decoding preserves data."""
        from oida.fuzz.primitives.transformers.encoding import HexTransformer

        transformer = HexTransformer()
        assert transformer.decode(transformer.encode(data)) == data


# =============================================================================
# Test HTMLEntityTransformer
# =============================================================================


class TestHTMLEntityTransformerEncode:
    """Tests for HTMLEntityTransformer encode method."""

    def test_encode_angle_brackets(self):
        """Angle brackets are escaped."""
        from oida.fuzz.primitives.transformers.encoding import HTMLEntityTransformer

        transformer = HTMLEntityTransformer()
        result = transformer.encode(b"<script>alert(1)</script>")

        assert b"&lt;" in result
        assert b"&gt;" in result
        assert b"<" not in result

    def test_encode_ampersand(self):
        """Ampersand is escaped."""
        from oida.fuzz.primitives.transformers.encoding import HTMLEntityTransformer

        transformer = HTMLEntityTransformer()
        result = transformer.encode(b"foo & bar")

        assert b"&amp;" in result

    def test_encode_quotes(self):
        """Quotes are escaped by default."""
        from oida.fuzz.primitives.transformers.encoding import HTMLEntityTransformer

        transformer = HTMLEntityTransformer(quote_style=True)
        result = transformer.encode(b'Say "hello"')

        assert b"&quot;" in result

    def test_encode_no_quote_escaping(self):
        """Quotes are not escaped when quote_style=False."""
        from oida.fuzz.primitives.transformers.encoding import HTMLEntityTransformer

        transformer = HTMLEntityTransformer(quote_style=False)
        result = transformer.encode(b'Say "hello"')

        assert b"&quot;" not in result
        assert b'"' in result


class TestHTMLEntityTransformerDecode:
    """Tests for HTMLEntityTransformer decode method."""

    def test_decode_entities(self):
        """HTML entities are decoded."""
        from oida.fuzz.primitives.transformers.encoding import HTMLEntityTransformer

        transformer = HTMLEntityTransformer()
        result = transformer.decode(b"&lt;script&gt;alert(1)&lt;/script&gt;")

        assert result == b"<script>alert(1)</script>"


class TestHTMLEntityTransformerRoundTrip:
    """Tests for HTMLEntityTransformer round-trip."""

    def test_round_trip(self):
        """Round-trip preserves data."""
        from oida.fuzz.primitives.transformers.encoding import HTMLEntityTransformer

        transformer = HTMLEntityTransformer()
        data = b'<div class="test">Hello & World</div>'

        assert transformer.decode(transformer.encode(data)) == data


# =============================================================================
# Test JSONEscapeTransformer
# =============================================================================


class TestJSONEscapeTransformerEncode:
    """Tests for JSONEscapeTransformer encode method."""

    def test_encode_quotes(self):
        """Quotes are escaped."""
        from oida.fuzz.primitives.transformers.encoding import JSONEscapeTransformer

        transformer = JSONEscapeTransformer()
        result = transformer.encode(b'He said "hello"')

        assert b'\\"' in result

    def test_encode_backslash(self):
        """Backslashes are escaped."""
        from oida.fuzz.primitives.transformers.encoding import JSONEscapeTransformer

        transformer = JSONEscapeTransformer()
        result = transformer.encode(b"path\\to\\file")

        assert b"\\\\" in result

    def test_encode_newline(self):
        """Newlines are escaped."""
        from oida.fuzz.primitives.transformers.encoding import JSONEscapeTransformer

        transformer = JSONEscapeTransformer()
        result = transformer.encode(b"line1\nline2")

        assert b"\\n" in result


class TestJSONEscapeTransformerDecode:
    """Tests for JSONEscapeTransformer decode method."""

    def test_decode_escaped(self):
        """Escaped sequences are decoded."""
        from oida.fuzz.primitives.transformers.encoding import JSONEscapeTransformer

        transformer = JSONEscapeTransformer()
        result = transformer.decode(b'He said \\"hello\\"')

        assert result == b'He said "hello"'


class TestJSONEscapeTransformerRoundTrip:
    """Tests for JSONEscapeTransformer round-trip."""

    def test_round_trip(self):
        """Round-trip preserves data."""
        from oida.fuzz.primitives.transformers.encoding import JSONEscapeTransformer

        transformer = JSONEscapeTransformer()
        data = b'{"key": "value with "quotes" and \\backslash"}'

        assert transformer.decode(transformer.encode(data)) == data


# =============================================================================
# Test XMLEscapeTransformer
# =============================================================================


class TestXMLEscapeTransformerEncode:
    """Tests for XMLEscapeTransformer encode method."""

    def test_encode_all_special_chars(self):
        """All XML special characters are escaped."""
        from oida.fuzz.primitives.transformers.encoding import XMLEscapeTransformer

        transformer = XMLEscapeTransformer()
        result = transformer.encode(b'<tag attr="val\'ue">data & more</tag>')

        assert b"&lt;" in result
        assert b"&gt;" in result
        assert b"&quot;" in result
        assert b"&apos;" in result
        assert b"&amp;" in result


class TestXMLEscapeTransformerDecode:
    """Tests for XMLEscapeTransformer decode method."""

    def test_decode_entities(self):
        """XML entities are decoded."""
        from oida.fuzz.primitives.transformers.encoding import XMLEscapeTransformer

        transformer = XMLEscapeTransformer()
        result = transformer.decode(b"&lt;tag&gt;data &amp; more&lt;/tag&gt;")

        assert result == b"<tag>data & more</tag>"


class TestXMLEscapeTransformerRoundTrip:
    """Tests for XMLEscapeTransformer round-trip."""

    def test_round_trip(self):
        """Round-trip preserves data."""
        from oida.fuzz.primitives.transformers.encoding import XMLEscapeTransformer

        transformer = XMLEscapeTransformer()
        data = b"<root attr='value'>Text & \"quotes\"</root>"

        assert transformer.decode(transformer.encode(data)) == data


# =============================================================================
# Test GzipTransformer
# =============================================================================


class TestGzipTransformerCreation:
    """Tests for GzipTransformer instantiation."""

    def test_default_creation(self):
        """Default GzipTransformer uses level 9."""
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        transformer = GzipTransformer()
        assert transformer.level == 9

    def test_custom_level(self):
        """Custom compression level can be set."""
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        transformer = GzipTransformer(level=6)
        assert transformer.level == 6

    def test_invalid_level_raises(self):
        """Invalid compression level raises ValueError."""
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        with pytest.raises(ValueError, match="level must be"):
            GzipTransformer(level=10)

    def test_level_minus_one_valid(self):
        """Level -1 (default) is valid."""
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        transformer = GzipTransformer(level=-1)
        assert transformer.level == -1


class TestGzipTransformerEncode:
    """Tests for GzipTransformer encode method."""

    def test_encode_produces_gzip_data(self):
        """Encoded data is valid gzip."""
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        transformer = GzipTransformer()
        data = b"Hello World!"
        compressed = transformer.encode(data)

        # Verify it's valid gzip by decompressing with standard library
        assert gzip.decompress(compressed) == data

    def test_encode_compresses_data(self):
        """Repetitive data is compressed smaller."""
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        transformer = GzipTransformer(level=9)
        data = b"A" * 10000

        compressed = transformer.encode(data)
        assert len(compressed) < len(data)


class TestGzipTransformerDecode:
    """Tests for GzipTransformer decode method."""

    def test_decode_gzip_data(self):
        """Gzip data is decompressed."""
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        transformer = GzipTransformer()
        data = b"Test decompression"
        compressed = gzip.compress(data)

        result = transformer.decode(compressed)
        assert result == data

    def test_decode_invalid_raises(self):
        """Invalid gzip data raises ValueError."""
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        transformer = GzipTransformer()

        with pytest.raises(ValueError, match="Gzip decompression error"):
            transformer.decode(b"not valid gzip data")


class TestGzipTransformerRoundTrip:
    """Tests for GzipTransformer round-trip."""

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"short",
            b"A" * 10000,
            b"\x00\xff" * 1000,
            b"{'key': 'value', 'nested': {'array': [1, 2, 3]}}",
        ],
    )
    def test_round_trip(self, data):
        """Round-trip preserves data."""
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        transformer = GzipTransformer()
        assert transformer.decode(transformer.encode(data)) == data


class TestGzipTransformerName:
    """Tests for GzipTransformer name property."""

    def test_name_includes_level(self):
        """Name includes compression level."""
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        transformer = GzipTransformer(level=6)
        assert transformer.name == "Gzip-6"


# =============================================================================
# Test DeflateTransformer
# =============================================================================


class TestDeflateTransformerCreation:
    """Tests for DeflateTransformer instantiation."""

    def test_default_creation(self):
        """Default DeflateTransformer uses raw deflate."""
        from oida.fuzz.primitives.transformers.compression import DeflateTransformer

        transformer = DeflateTransformer()
        assert transformer.level == 9
        assert transformer.wbits == -15  # Raw deflate

    def test_zlib_wrapper(self):
        """DeflateTransformer can use zlib wrapper."""
        from oida.fuzz.primitives.transformers.compression import DeflateTransformer

        transformer = DeflateTransformer(wbits=15)
        assert transformer.wbits == 15

    def test_invalid_level_raises(self):
        """Invalid compression level raises ValueError."""
        from oida.fuzz.primitives.transformers.compression import DeflateTransformer

        with pytest.raises(ValueError, match="level must be"):
            DeflateTransformer(level=10)

    def test_invalid_wbits_raises(self):
        """Invalid wbits raises ValueError."""
        from oida.fuzz.primitives.transformers.compression import DeflateTransformer

        # Valid ranges are -15 to 15 or 24 to 31
        # 16-23 are invalid
        with pytest.raises(ValueError, match="Invalid wbits"):
            DeflateTransformer(wbits=20)


class TestDeflateTransformerEncode:
    """Tests for DeflateTransformer encode method."""

    def test_encode_raw_deflate(self):
        """Raw deflate encoding works."""
        from oida.fuzz.primitives.transformers.compression import DeflateTransformer

        transformer = DeflateTransformer(wbits=-15)
        data = b"Test data for deflate"
        compressed = transformer.encode(data)

        # Decompress with raw deflate
        decompressor = zlib.decompressobj(wbits=-15)
        decompressed = decompressor.decompress(compressed) + decompressor.flush()
        assert decompressed == data

    def test_encode_zlib_wrapper(self):
        """Zlib-wrapped deflate encoding works."""
        from oida.fuzz.primitives.transformers.compression import DeflateTransformer

        transformer = DeflateTransformer(wbits=15)
        data = b"Test data for zlib"
        compressed = transformer.encode(data)

        # Decompress with zlib
        assert zlib.decompress(compressed) == data


class TestDeflateTransformerDecode:
    """Tests for DeflateTransformer decode method."""

    def test_decode_raw_deflate(self):
        """Raw deflate data is decompressed."""
        from oida.fuzz.primitives.transformers.compression import DeflateTransformer

        transformer = DeflateTransformer(wbits=-15)
        data = b"Decompress this"

        # Compress with raw deflate
        compressor = zlib.compressobj(level=9, wbits=-15)
        compressed = compressor.compress(data) + compressor.flush()

        result = transformer.decode(compressed)
        assert result == data

    def test_decode_invalid_raises(self):
        """Invalid deflate data raises ValueError."""
        from oida.fuzz.primitives.transformers.compression import DeflateTransformer

        transformer = DeflateTransformer()

        with pytest.raises(ValueError, match="Deflate decompression error"):
            transformer.decode(b"not valid deflate")


class TestDeflateTransformerRoundTrip:
    """Tests for DeflateTransformer round-trip."""

    @pytest.mark.parametrize("wbits", [-15, 15])
    def test_round_trip(self, wbits):
        """Round-trip works for both raw and zlib formats."""
        from oida.fuzz.primitives.transformers.compression import DeflateTransformer

        transformer = DeflateTransformer(wbits=wbits)
        data = b"Round-trip test data"

        assert transformer.decode(transformer.encode(data)) == data


class TestDeflateTransformerName:
    """Tests for DeflateTransformer name property."""

    def test_name_raw(self):
        """Name indicates raw deflate."""
        from oida.fuzz.primitives.transformers.compression import DeflateTransformer

        transformer = DeflateTransformer(wbits=-15)
        assert "raw" in transformer.name

    def test_name_zlib(self):
        """Name indicates zlib wrapper."""
        from oida.fuzz.primitives.transformers.compression import DeflateTransformer

        transformer = DeflateTransformer(wbits=15)
        assert "zlib" in transformer.name


# =============================================================================
# Test BrotliTransformer (optional)
# =============================================================================


class TestBrotliTransformerCreation:
    """Tests for BrotliTransformer instantiation."""

    def test_creation_without_brotli_raises(self):
        """BrotliTransformer raises ImportError if brotli not installed."""
        # We can't easily test this without uninstalling brotli
        # Just verify the class exists and can be imported
        try:
            from oida.fuzz.primitives.transformers.compression import BrotliTransformer
            # If we get here, brotli is installed
        except ImportError:
            pytest.skip("Brotli not installed")

    @pytest.fixture
    def brotli_available(self):
        """Skip if brotli is not available."""
        try:
            import brotli

            return True
        except ImportError:
            pytest.skip("Brotli not installed")

    def test_default_creation(self, brotli_available):
        """Default BrotliTransformer uses quality 11."""
        from oida.fuzz.primitives.transformers.compression import BrotliTransformer

        transformer = BrotliTransformer()
        assert transformer.quality == 11

    def test_invalid_quality_raises(self, brotli_available):
        """Invalid quality raises ValueError."""
        from oida.fuzz.primitives.transformers.compression import BrotliTransformer

        with pytest.raises(ValueError, match="quality must be"):
            BrotliTransformer(quality=12)

    def test_invalid_lgwin_raises(self, brotli_available):
        """Invalid lgwin raises ValueError."""
        from oida.fuzz.primitives.transformers.compression import BrotliTransformer

        with pytest.raises(ValueError, match="lgwin must be"):
            BrotliTransformer(lgwin=5)


class TestBrotliTransformerRoundTrip:
    """Tests for BrotliTransformer round-trip."""

    @pytest.fixture
    def brotli_available(self):
        """Skip if brotli is not available."""
        try:
            import brotli

            return True
        except ImportError:
            pytest.skip("Brotli not installed")

    def test_round_trip(self, brotli_available):
        """Round-trip preserves data."""
        from oida.fuzz.primitives.transformers.compression import BrotliTransformer

        transformer = BrotliTransformer()
        data = b"Test data for brotli compression"

        assert transformer.decode(transformer.encode(data)) == data


# =============================================================================
# Test IdentityTransformer
# =============================================================================


class TestIdentityTransformer:
    """Tests for IdentityTransformer."""

    def test_encode_returns_same_data(self):
        """encode() returns data unchanged."""
        from oida.fuzz.primitives.transformers.compression import IdentityTransformer

        transformer = IdentityTransformer()
        data = b"unchanged data"

        assert transformer.encode(data) == data

    def test_decode_returns_same_data(self):
        """decode() returns data unchanged."""
        from oida.fuzz.primitives.transformers.compression import IdentityTransformer

        transformer = IdentityTransformer()
        data = b"unchanged data"

        assert transformer.decode(data) == data

    def test_name(self):
        """name is 'Identity'."""
        from oida.fuzz.primitives.transformers.compression import IdentityTransformer

        transformer = IdentityTransformer()
        assert transformer.name == "Identity"


# =============================================================================
# Test Complex Chains
# =============================================================================


class TestComplexTransformerChains:
    """Tests for complex transformer chain scenarios."""

    def test_gzip_then_base64(self):
        """Common pattern: compress then base64 encode."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.compression import GzipTransformer
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer

        chain = TransformerChain(GzipTransformer(), Base64Transformer())
        data = b"This is a test of compression and encoding"

        encoded = chain.encode(data)
        # Result should be base64 (ASCII safe)
        encoded.decode("ascii")  # Should not raise

        decoded = chain.decode(encoded)
        assert decoded == data

    def test_url_encode_then_base64(self):
        """URL encode then base64 for double encoding."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.encoding import (
            URLEncodeTransformer,
            Base64Transformer,
        )

        chain = TransformerChain(URLEncodeTransformer(), Base64Transformer())
        data = b"key=value&foo=bar"

        assert chain.decode(chain.encode(data)) == data

    def test_three_transformer_chain(self):
        """Chain of three transformers."""
        from oida.fuzz.primitives.transformers.base import TransformerChain
        from oida.fuzz.primitives.transformers.compression import GzipTransformer
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer, HexTransformer

        # Gzip -> Base64 -> Hex
        chain = TransformerChain(GzipTransformer(level=6), Base64Transformer(), HexTransformer())

        data = b"Triple encoded data"
        assert chain.decode(chain.encode(data)) == data


# =============================================================================
# Test Edge Cases
# =============================================================================


class TestTransformerEdgeCases:
    """Tests for edge cases in transformers."""

    def test_empty_data_handling(self):
        """All transformers handle empty data."""
        from oida.fuzz.primitives.transformers.encoding import (
            Base64Transformer,
            URLEncodeTransformer,
            HexTransformer,
            HTMLEntityTransformer,
            JSONEscapeTransformer,
            XMLEscapeTransformer,
        )
        from oida.fuzz.primitives.transformers.compression import (
            GzipTransformer,
            DeflateTransformer,
            IdentityTransformer,
        )

        transformers = [
            Base64Transformer(),
            URLEncodeTransformer(),
            HexTransformer(),
            HTMLEntityTransformer(),
            JSONEscapeTransformer(),
            XMLEscapeTransformer(),
            GzipTransformer(),
            DeflateTransformer(),
            IdentityTransformer(),
        ]

        for transformer in transformers:
            # Empty input must round-trip back to empty, not raise or corrupt.
            encoded = transformer.encode(b"")
            assert transformer.decode(encoded) == b"", (
                f"{type(transformer).__name__} did not round-trip empty data"
            )

    def test_large_data_handling(self):
        """Transformers handle large data."""
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        transformer = GzipTransformer()
        large_data = b"X" * 1000000  # 1MB

        compressed = transformer.encode(large_data)
        decompressed = transformer.decode(compressed)

        assert decompressed == large_data

    def test_binary_data_handling(self):
        """Transformers handle arbitrary binary data."""
        from oida.fuzz.primitives.transformers.encoding import Base64Transformer, HexTransformer
        from oida.fuzz.primitives.transformers.compression import GzipTransformer

        binary_data = bytes(range(256))  # All possible byte values

        for transformer in [Base64Transformer(), HexTransformer(), GzipTransformer()]:
            assert transformer.decode(transformer.encode(binary_data)) == binary_data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
