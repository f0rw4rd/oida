"""
Compression Transformers

This module provides transformers for data compression schemes used in
HTTP and other protocols: Gzip, Deflate, and Brotli.

These transformers enable testing of compressed content handling, including:
- Content-Encoding: gzip, deflate, br
- Compressed request/response fuzzing
- Compression bomb attacks
- Malformed compression stream testing
"""

import gzip
import zlib
from .base import BaseTransformer

from ....utils.ics_logger import get_logger

_log = get_logger("COMPRESS", "transform", 0)


class GzipTransformer(BaseTransformer):
    """
    Gzip compression transformer (RFC 1952).

    Compresses data using gzip format (deflate + gzip wrapper).
    Commonly used for HTTP Content-Encoding: gzip.

    Compression levels:
    - 0: No compression (store only)
    - 1-9: Increasing compression (9 = maximum)
    - -1: Default compression (usually 6)

    Common uses:
    - Content-Encoding: gzip
    - Compressed API payloads
    - Bandwidth reduction

    Security testing:
    - Compression bombs (small compressed, huge decompressed)
    - Malformed gzip streams
    - Missing headers/trailers
    - Incorrect checksums

    Example:
        >>> transformer = GzipTransformer(level=9)
        >>> compressed = transformer.encode(b"Hello World! " * 1000)
        >>> len(compressed) < len(b"Hello World! " * 1000)
        True

    Usage with boofuzz:
        >>> Block("Body", encoder=GzipTransformer(level=9).to_encoder_func(),
        ...       children=(
        ...           SmartString("json_data", '{"key": "value"}'),
        ...       ))
    """

    def __init__(self, level: int = 9, mtime: int = 0):
        """
        Initialize Gzip transformer.

        Args:
            level: Compression level (0-9, -1 for default, 9 = best)
            mtime: Modification time for gzip header (0 = no timestamp)

        Example:
            >>> # Maximum compression
            >>> GzipTransformer(level=9)

            >>> # Fast compression
            >>> GzipTransformer(level=1)

            >>> # No compression (for testing)
            >>> GzipTransformer(level=0)
        """
        if not -1 <= level <= 9:
            raise ValueError(f"Compression level must be 0-9 or -1, got {level}")

        self.level = level
        self.mtime = mtime

    def encode(self, data: bytes) -> bytes:
        """Compress data with gzip"""
        try:
            return gzip.compress(data, compresslevel=self.level, mtime=self.mtime)
        except Exception as e:
            _log.fail(f"Gzip compression failed: {e}")
            raise ValueError(f"Gzip compression error: {e}")

    def decode(self, data: bytes) -> bytes:
        """Decompress gzip data"""
        try:
            return gzip.decompress(data)
        except Exception as e:
            _log.fail(f"Gzip decompression failed: {e}")
            raise ValueError(f"Gzip decompression error: {e}")

    @property
    def name(self) -> str:
        return f"Gzip-{self.level}"


class DeflateTransformer(BaseTransformer):
    """
    Deflate compression transformer (RFC 1951).

    Compresses data using raw deflate format (no wrapper).
    Used for HTTP Content-Encoding: deflate.

    Note: HTTP "deflate" encoding has two interpretations:
    1. Raw deflate (RFC 1951) - this implementation
    2. Zlib-wrapped deflate (RFC 1950) - use wbits=15

    Compression levels:
    - 0: No compression
    - 1-9: Increasing compression (9 = maximum)
    - -1: Default compression

    Common uses:
    - Content-Encoding: deflate
    - Alternative to gzip (less overhead)
    - ZIP archives

    Security testing:
    - Decompression bombs
    - Malformed deflate streams
    - Inconsistent wbits parameter confusion

    Example:
        >>> transformer = DeflateTransformer(level=9)
        >>> compressed = transformer.encode(b"Test data " * 100)
        >>> len(compressed) < len(b"Test data " * 100)
        True

        >>> # Zlib-wrapped deflate
        >>> transformer = DeflateTransformer(level=9, wbits=15)

    Usage with boofuzz:
        >>> Block("Body", encoder=DeflateTransformer(level=9).to_encoder_func(),
        ...       children=(
        ...           SmartString("payload", "compressed_content"),
        ...       ))
    """

    def __init__(self, level: int = 9, wbits: int = -15):
        """
        Initialize Deflate transformer.

        Args:
            level: Compression level (0-9, -1 for default)
            wbits: Window bits parameter:
                   - Negative (-15 to -9): Raw deflate (no wrapper)
                   - Positive (9 to 15): Zlib wrapper
                   - Add 16: Gzip wrapper

        Common wbits values:
            -15: Raw deflate (RFC 1951)
            15: Zlib deflate (RFC 1950)
            15+16=31: Gzip format

        Example:
            >>> # Raw deflate (common for HTTP)
            >>> DeflateTransformer(wbits=-15)

            >>> # Zlib-wrapped deflate
            >>> DeflateTransformer(wbits=15)
        """
        if not -1 <= level <= 9:
            raise ValueError(f"Compression level must be 0-9 or -1, got {level}")

        if not (-15 <= wbits <= 15 or 24 <= wbits <= 31):
            raise ValueError(f"Invalid wbits: {wbits}")

        self.level = level
        self.wbits = wbits

    def encode(self, data: bytes) -> bytes:
        """Compress data with deflate"""
        try:
            compressor = zlib.compressobj(level=self.level, wbits=self.wbits)
            compressed = compressor.compress(data)
            compressed += compressor.flush()
            return compressed
        except Exception as e:
            _log.fail(f"Deflate compression failed: {e}")
            raise ValueError(f"Deflate compression error: {e}")

    def decode(self, data: bytes) -> bytes:
        """Decompress deflate data"""
        try:
            decompressor = zlib.decompressobj(wbits=self.wbits)
            decompressed = decompressor.decompress(data)
            decompressed += decompressor.flush()
            return decompressed
        except Exception as e:
            _log.fail(f"Deflate decompression failed: {e}")
            raise ValueError(f"Deflate decompression error: {e}")

    @property
    def name(self) -> str:
        wrapper = "raw" if self.wbits < 0 else "zlib"
        return f"Deflate-{wrapper}-{self.level}"


class BrotliTransformer(BaseTransformer):
    """
    Brotli compression transformer (RFC 7932).

    Modern compression algorithm with better compression ratios than gzip.
    Used for HTTP Content-Encoding: br.

    Requires: pip install brotli (or brotlipy)

    Quality levels:
    - 0: Fastest, lowest compression
    - 1-11: Increasing compression
    - 11: Maximum compression (slowest)

    Common uses:
    - Content-Encoding: br
    - Modern web applications
    - Better compression than gzip

    Security testing:
    - Compression bombs
    - Malformed brotli streams
    - Large window size attacks

    Example:
        >>> try:
        ...     transformer = BrotliTransformer(quality=11)
        ...     compressed = transformer.encode(b"Data " * 1000)
        ... except ImportError:
        ...     print("Brotli not available, install with: pip install brotli")

    Usage with boofuzz:
        >>> try:
        ...     Block("Body", encoder=BrotliTransformer(quality=11).to_encoder_func(),
        ...           children=(SmartString("data", "content"),))
        ... except ImportError:
        ...     pass  # Skip if brotli not installed
    """

    def __init__(self, quality: int = 11, lgwin: int = 22):
        """
        Initialize Brotli transformer.

        Args:
            quality: Compression quality (0-11, 11 = best)
            lgwin: Base-2 log of window size (10-24)

        Example:
            >>> # Maximum compression
            >>> BrotliTransformer(quality=11)

            >>> # Fast compression
            >>> BrotliTransformer(quality=4)
        """
        try:
            import brotli

            self.brotli = brotli
        except ImportError:
            try:
                import brotlipy as brotli

                self.brotli = brotli
            except ImportError:
                raise ImportError(
                    "Brotli compression requires the 'brotli' package. "
                    "Install with: pip install brotli"
                )

        if not 0 <= quality <= 11:
            raise ValueError(f"Brotli quality must be 0-11, got {quality}")

        if not 10 <= lgwin <= 24:
            raise ValueError(f"Brotli lgwin must be 10-24, got {lgwin}")

        self.quality = quality
        self.lgwin = lgwin

    def encode(self, data: bytes) -> bytes:
        """Compress data with Brotli"""
        try:
            return self.brotli.compress(data, quality=self.quality, lgwin=self.lgwin)
        except Exception as e:
            _log.fail(f"Brotli compression failed: {e}")
            raise ValueError(f"Brotli compression error: {e}")

    def decode(self, data: bytes) -> bytes:
        """Decompress Brotli data"""
        try:
            return self.brotli.decompress(data)
        except Exception as e:
            _log.fail(f"Brotli decompression failed: {e}")
            raise ValueError(f"Brotli decompression error: {e}")

    @property
    def name(self) -> str:
        return f"Brotli-{self.quality}"


class IdentityTransformer(BaseTransformer):
    """
    Identity transformer (no compression).

    Pass-through transformer that returns data unchanged.
    Useful for testing and as a placeholder.

    Example:
        >>> transformer = IdentityTransformer()
        >>> data = b"unchanged"
        >>> transformer.encode(data) == data
        True
    """

    def encode(self, data: bytes) -> bytes:
        """Return data unchanged"""
        return data

    def decode(self, data: bytes) -> bytes:
        """Return data unchanged"""
        return data

    @property
    def name(self) -> str:
        return "Identity"
