"""
Encoding Transformers

This module provides transformers for common encoding schemes used in
network protocols: Base64, URL encoding, Hex, HTML entities, JSON escaping, etc.

These transformers are commonly used for:
- HTTP headers (Base64 for Authorization)
- Query parameters and form data (URL encoding)
- Binary data representation (Hex)
- Web content (HTML entities, JSON escaping)
"""

import base64
import html
import json
import binascii
from urllib.parse import quote, unquote, quote_plus, unquote_plus
from .base import BaseTransformer


class Base64Transformer(BaseTransformer):
    """
    Base64 encoding transformer (RFC 4648).

    Supports both standard and URL-safe Base64 variants.
    Optionally strips padding '=' characters.

    Common uses:
    - HTTP Basic Authentication (Authorization: Basic <base64>)
    - Embedded binary data in text protocols
    - Email attachments (MIME)

    Example:
        >>> transformer = Base64Transformer()
        >>> transformer.encode(b"admin:password123")
        b'YWRtaW46cGFzc3dvcmQxMjM='

        >>> # URL-safe variant (JWT tokens)
        >>> transformer = Base64Transformer(urlsafe=True, strip_padding=True)
        >>> transformer.encode(b'{"sub":"user"}')
        b'eyJzdWIiOiJ1c2VyIn0'
    """

    def __init__(
        self,
        urlsafe: bool = False,
        strip_padding: bool = False,
        prefix: bytes = b"",
        suffix: bytes = b"",
    ):
        """
        Initialize Base64 transformer.

        Args:
            urlsafe: Use URL-safe Base64 (- and _ instead of + and /)
            strip_padding: Remove trailing = padding characters
            prefix: Bytes to prepend before encoded data
            suffix: Bytes to append after encoded data

        Example:
            >>> # HTTP Basic Auth: "Basic <base64>"
            >>> Base64Transformer(prefix=b"Basic ")
        """
        self.urlsafe = urlsafe
        self.strip_padding = strip_padding
        self.prefix = prefix
        self.suffix = suffix

    def encode(self, data: bytes) -> bytes:
        """Encode data to Base64"""
        if self.urlsafe:
            encoded = base64.urlsafe_b64encode(data)
        else:
            encoded = base64.b64encode(data)

        if self.strip_padding:
            encoded = encoded.rstrip(b"=")

        return self.prefix + encoded + self.suffix

    def decode(self, data: bytes) -> bytes:
        """Decode Base64 data"""
        # Remove prefix/suffix
        data = data.removeprefix(self.prefix).removesuffix(self.suffix)

        # Add padding if stripped
        if self.strip_padding:
            padding = (4 - len(data) % 4) % 4
            data += b"=" * padding

        try:
            if self.urlsafe:
                return base64.urlsafe_b64decode(data)
            else:
                return base64.b64decode(data)
        except binascii.Error as e:
            raise ValueError(f"Invalid Base64 data: {e}")

    @property
    def name(self) -> str:
        variant = "-urlsafe" if self.urlsafe else ""
        padding = "-nopad" if self.strip_padding else ""
        return f"Base64{variant}{padding}"


class URLEncodeTransformer(BaseTransformer):
    """
    URL percent-encoding transformer (RFC 3986).

    Encodes special characters as %XX hex sequences.
    Supports both standard and plus-encoding variants.

    Common uses:
    - Query parameters: ?name=John%20Doe
    - Form data: application/x-www-form-urlencoded
    - Path components with special chars

    Example:
        >>> transformer = URLEncodeTransformer()
        >>> transformer.encode(b"Hello World!")
        b'Hello%20World%21'

        >>> # Plus-encoding (spaces as +)
        >>> transformer = URLEncodeTransformer(plus_encoding=True)
        >>> transformer.encode(b"Hello World")
        b'Hello+World'
    """

    def __init__(self, plus_encoding: bool = False, safe: str = ""):
        """
        Initialize URL encoding transformer.

        Args:
            plus_encoding: Use + for spaces (form encoding style)
            safe: Characters that should NOT be encoded

        Example:
            >>> # Don't encode slashes in paths
            >>> URLEncodeTransformer(safe="/")
        """
        self.plus_encoding = plus_encoding
        self.safe = safe

    def encode(self, data: bytes) -> bytes:
        """Encode data with percent-encoding"""
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")

        if self.plus_encoding:
            encoded = quote_plus(text, safe=self.safe)
        else:
            encoded = quote(text, safe=self.safe)

        return encoded.encode("utf-8")

    def decode(self, data: bytes) -> bytes:
        """Decode percent-encoded data"""
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")

        if self.plus_encoding:
            decoded = unquote_plus(text)
        else:
            decoded = unquote(text)

        return decoded.encode("utf-8")

    @property
    def name(self) -> str:
        variant = "-plus" if self.plus_encoding else ""
        return f"URLEncode{variant}"


class HexTransformer(BaseTransformer):
    """
    Hexadecimal encoding transformer.

    Converts binary data to hex string representation.
    Supports uppercase and lowercase variants.

    Common uses:
    - Binary data in text protocols
    - Checksums and hashes
    - Debug output

    Example:
        >>> transformer = HexTransformer()
        >>> transformer.encode(b"Hello")
        b'48656c6c6f'

        >>> transformer = HexTransformer(uppercase=True)
        >>> transformer.encode(b"\\x01\\x02\\x03")
        b'010203'
    """

    def __init__(self, uppercase: bool = False, prefix: bytes = b"", delimiter: bytes = b""):
        """
        Initialize hex transformer.

        Args:
            uppercase: Use uppercase hex digits (A-F instead of a-f)
            prefix: Prefix for hex string (e.g., b"0x")
            delimiter: Delimiter between hex pairs (e.g., b":")

        Example:
            >>> # C-style: 0x48, 0x65, 0x6c
            >>> HexTransformer(prefix=b"0x", delimiter=b", 0x")

            >>> # MAC address style: 48:65:6C:6C:6F
            >>> HexTransformer(uppercase=True, delimiter=b":")
        """
        self.uppercase = uppercase
        self.prefix = prefix
        self.delimiter = delimiter

    def encode(self, data: bytes) -> bytes:
        """Encode data to hexadecimal"""
        hex_str = binascii.hexlify(data).decode("ascii")

        if self.uppercase:
            hex_str = hex_str.upper()

        # Add delimiter between byte pairs
        if self.delimiter:
            hex_pairs = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]
            hex_str = self.delimiter.decode("ascii").join(hex_pairs)

        return self.prefix + hex_str.encode("ascii")

    def decode(self, data: bytes) -> bytes:
        """Decode hexadecimal data"""
        # Remove prefix
        data = data.removeprefix(self.prefix)

        # Remove delimiters
        if self.delimiter:
            data = data.replace(self.delimiter, b"")

        try:
            return binascii.unhexlify(data)
        except binascii.Error as e:
            raise ValueError(f"Invalid hex data: {e}")

    @property
    def name(self) -> str:
        case = "Upper" if self.uppercase else "Lower"
        return f"Hex-{case}"


class HTMLEntityTransformer(BaseTransformer):
    """
    HTML entity encoding transformer.

    Escapes HTML special characters to entities.

    Common uses:
    - XSS testing (encode <script> to &lt;script&gt;)
    - HTML content fuzzing
    - Attribute value encoding

    Example:
        >>> transformer = HTMLEntityTransformer()
        >>> transformer.encode(b'<script>alert("xss")</script>')
        b'&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
    """

    def __init__(self, quote_style: bool = True):
        """
        Initialize HTML entity transformer.

        Args:
            quote_style: Also escape quotes (True = &quot;, False = ")
        """
        self.quote_style = quote_style

    def encode(self, data: bytes) -> bytes:
        """Encode HTML entities"""
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")

        encoded = html.escape(text, quote=self.quote_style)
        return encoded.encode("utf-8")

    def decode(self, data: bytes) -> bytes:
        """Decode HTML entities"""
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")

        decoded = html.unescape(text)
        return decoded.encode("utf-8")

    @property
    def name(self) -> str:
        return "HTMLEntity"


class JSONEscapeTransformer(BaseTransformer):
    """
    JSON string escaping transformer.

    Escapes special characters for JSON string values.
    Handles quotes, backslashes, control characters, etc.

    Common uses:
    - JSON payload fuzzing
    - API request bodies
    - WebSocket messages

    Example:
        >>> transformer = JSONEscapeTransformer()
        >>> transformer.encode(b'He said "hello"\\nNew line')
        b'He said \\"hello\\"\\nNew line'
    """

    def encode(self, data: bytes) -> bytes:
        """Encode for JSON string"""
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")

        # Use json.dumps to properly escape, then remove outer quotes
        encoded = json.dumps(text)[1:-1]
        return encoded.encode("utf-8")

    def decode(self, data: bytes) -> bytes:
        """Decode JSON-escaped string"""
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")

        # Wrap in quotes and parse as JSON
        decoded = json.loads(f'"{text}"')
        return decoded.encode("utf-8")

    @property
    def name(self) -> str:
        return "JSONEscape"


class XMLEscapeTransformer(BaseTransformer):
    """
    XML special character escaping transformer.

    Escapes XML special characters: <, >, &, ', "

    Common uses:
    - XML payload fuzzing
    - SOAP requests
    - RSS/Atom feeds

    Example:
        >>> transformer = XMLEscapeTransformer()
        >>> transformer.encode(b'<tag attr="value">data & more</tag>')
        b'&lt;tag attr=&quot;value&quot;&gt;data &amp; more&lt;/tag&gt;'
    """

    def encode(self, data: bytes) -> bytes:
        """Escape XML special characters"""
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")

        # Escape XML special characters
        replacements = {
            "&": "&amp;",  # Must be first
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&apos;",
        }

        for char, entity in replacements.items():
            text = text.replace(char, entity)

        return text.encode("utf-8")

    def decode(self, data: bytes) -> bytes:
        """Unescape XML entities"""
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")

        # Unescape XML entities
        replacements = {
            "&lt;": "<",
            "&gt;": ">",
            "&quot;": '"',
            "&apos;": "'",
            "&amp;": "&",  # Must be last
        }

        for entity, char in replacements.items():
            text = text.replace(entity, char)

        return text.encode("utf-8")

    @property
    def name(self) -> str:
        return "XMLEscape"
