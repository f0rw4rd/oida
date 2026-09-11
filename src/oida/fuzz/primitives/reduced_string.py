"""
Reduced String primitive for OIDA fuzzer - optimized for network protocol fuzzing.

This is a custom String primitive with a reduced payload set focused on protocol fuzzing,
removing ~84% of irrelevant test cases (XSS, command injection, etc.) while keeping
payloads useful for finding protocol implementation bugs.

Reduction summary:
- Fuzz library: 109 → 27 payloads (75% reduction)
- Long strings: 1,680 → 480 combinations (71% reduction)
- Total per field: ~1,789 → ~507 test cases (72% reduction)
"""

import logging

from boofuzz import String

from ...utils.ics_logger import get_logger

_log = get_logger("STRING", "reduced", 0)


class ReducedString(String):
    """
    String primitive with reduced payload set optimized for protocol fuzzing.

    Removes command injection, XSS, and other web-focused payloads that are not
    relevant for network protocol implementations. Focuses on:
    - Binary boundaries (NULL bytes, 0xFF, etc.)
    - Protocol delimiters (CRLF, spaces, dots)
    - Path traversal (for file-based protocols)
    - Length boundaries (power-of-2 sizes)
    - Control characters

    Usage:
        ReducedString(name="field", default_value="test", max_len=256)

    Reduction can be further customized via class variables:
        ReducedString.reduction_level = "balanced"  # or "aggressive"
    """

    # Reduced fuzz library - removed command injection and XSS
    _fuzz_library = [
        # Empty and boundary
        "",
        # URL encoding / NULL bytes
        "%00",
        "%00/",
        "%01%02%03%04%0a%0d%0aADSF",
        "%01%02%03@%04%0a%0d%0aADSF",
        "%\xfe\xf0%\x00\xff",
        "%\xfe\xf0%\x01\xff" * 20,
        "%u0000",
        # NULL-terminated strings (tests C string handling)
        "A" * 10 + "\x00",
        "A" * 100 + "\x00",
        # CRLF injection (critical for text protocols like HTTP, FTP, SMTP)
        "\r\n" * 100,
        # Binary sequences
        "\x01\x02\x03\x04",
        "\xde\xad\xbe\xef",
        "\xde\xad\xbe\xef" * 10,
        "\xde\xad\xbe\xef" * 100,
        "\xde\xad\xbe\xef" * 1000,
        "\xde\xad\xbe\xef" * 10000,
        # Format strings - crafted attack patterns (boundary testing via seeds)
        "%p",  # Pointer leak (not in seeds)
        "AAAA%08x%08x%08x%n",  # Classic stack read + write attack
        "%.1000d",  # Width specifier DoS
        "%n" * 4 + "\x00",  # NULL-terminated format string
        "%99999$n",  # Positional parameter write - skips stack
        "%99999$s",  # Positional parameter read
        "%*.*s",  # Dynamic width/precision from stack
        # Malformed UTF-8 (parser crashes - universal)
        "\xc0\x80",  # Overlong NULL - security bypass
        "\xed\xa0\x80",  # UTF-16 surrogate - crashes parsers
        "%ef%bb%bf",  # BOM - parsing issues
    ]

    # Reduced seeds - protocol-relevant characters only
    # These get expanded to boundary lengths (7,8,9,15,16,17,127,128,129,255,256,257...)
    long_string_seeds = [
        "\x00",  # NULL byte - critical for C-style string bugs
        "\xff",  # High byte - boundary testing
        "\xfe",  # Near-max byte
        "A",  # Standard character for readability
        "/",  # Path separator
        "\r",  # CR - important for text protocols (HTTP, FTP, SMTP)
        "\n",  # LF - important for text protocols
        " ",  # Space - delimiter in many protocols
        ".",  # Dot - DNS, paths, decimal separators
        "../",  # Unix path traversal - boundary tested
        "..\\",  # Windows path traversal - boundary tested
        "./",  # Deep relative path nesting - boundary tested
        "%n",  # Format string write - boundary tested
        "%s",  # Format string read - boundary tested
        "%hhn",  # Single-byte format write - boundary tested
        "%x",  # Format string stack leak - boundary tested
    ]

    # Reduced lengths - power-of-2 boundaries and key protocol sizes
    _long_string_lengths = [
        8,  # Small boundary
        16,  # Common header size
        32,  #
        64,  # Cache line size
        128,  #
        256,  # Common buffer size
        512,  #
        1024,  # 1KB
        4096,  # 4KB page size
        65535,  # Max 16-bit unsigned int
    ]

    # Reduced deltas - just boundary testing
    _long_string_deltas = [
        -1,  # Just under boundary (off-by-one)
        0,  # Exact boundary
        1,  # Just over boundary (overflow)
    ]

    # Remove extra long strings (too slow for most protocol fuzzing)
    _extra_long_string_lengths = []

    # Reduction level configuration
    reduction_level = "balanced"  # "balanced" or "aggressive"

    @classmethod
    def set_reduction_level(cls, level: str):
        """
        Set reduction level for all ReducedString instances.

        Args:
            level: "balanced" (507 mutations) or "aggressive" (38 mutations)
        """
        if level == "aggressive":
            # Further reduce for speed
            cls._fuzz_library = [
                "",
                "%00",
                "%\xfe\xf0%\x00\xff",
                "/etc/passwd",
                "\\\\?\\C:\\",
                "\r\n" * 100,
                "\x01\x02\x03\x04",
                "\xde\xad\xbe\xef",
                "\xde\xad\xbe\xef" * 1000,
                "%n",
            ]

            cls.long_string_seeds = ["\x00", "\xff", "A", "../", "..\\", "%n", "%s"]

            cls._long_string_lengths = [256, 1024, 4096, 65535]

            cls._long_string_deltas = [0]  # Only exact boundaries

            cls.reduction_level = "aggressive"

        elif level == "balanced":
            # Use default reduced settings (reset if needed)
            cls._fuzz_library = ReducedString.__dict__["_fuzz_library"]
            cls.long_string_seeds = ReducedString.__dict__["long_string_seeds"]
            cls._long_string_lengths = ReducedString.__dict__["_long_string_lengths"]
            cls._long_string_deltas = ReducedString.__dict__["_long_string_deltas"]
            cls.reduction_level = "balanced"

        else:
            raise ValueError(f"Unknown reduction level: {level}. Use 'balanced' or 'aggressive'")

    @classmethod
    def get_stats(cls):
        """
        Return statistics about current mutation counts.

        Returns:
            Dictionary with mutation statistics
        """
        fuzz_count = len(cls._fuzz_library)
        long_count = (
            len(cls.long_string_seeds)
            * len(cls._long_string_lengths)
            * len(cls._long_string_deltas)
        )

        return {
            "reduction_level": cls.reduction_level,
            "fuzz_library_count": fuzz_count,
            "long_string_count": long_count,
            "extra_long_count": len(cls._extra_long_string_lengths),
            "total_per_field": fuzz_count + long_count,
        }

    def encode(self, value, mutation_context=None):
        """Encode a mutation to bytes.

        boofuzz's ``String.encode()`` unconditionally does
        ``value.encode(self.encoding, "replace")`` with ``self.encoding`` defaulting to
        ``"utf-8"``. Our curated payloads above (e.g. ``"\\xde\\xad\\xbe\\xef"``,
        ``"\\xc0\\x80"``, the ``\\xff``/``\\xfe`` long-string seeds) use characters in
        U+0080-U+00FF as literal RAW BYTES, not as Unicode codepoints. UTF-8-encoding
        them expands each such character into two bytes, which both mangles the
        intended byte sequence and silently doubles every non-ASCII long-string
        boundary length.

        Only the *default* ``"utf-8"`` encoding is affected: this is what silently
        mangles the raw-byte payloads above with no explicit opt-in from the field
        author. If a field explicitly configures a non-default ``encoding`` (e.g.
        ``encoding="ascii"``, which some callers rely on to collapse non-ASCII
        payloads to ``"?"`` on purpose), that configured encoding is an intentional
        choice and must still be honored via the boofuzz base implementation.

        For the default-utf-8 case, render any ``str`` payload whose characters are
        all <= U+00FF via latin-1, which maps codepoints 0x00-0xFF onto bytes
        0x00-0xFF one-to-one and therefore reproduces the intended bytes exactly.
        Payloads containing genuine Unicode (any character > U+00FF, e.g.
        homoglyphs) keep using utf-8 via the boofuzz base implementation.
        Pure-ASCII payloads are unaffected: latin-1 and utf-8 agree on every
        codepoint <= 0x7F, so output stays byte-for-byte identical to before this
        override existed.
        """
        if isinstance(value, bytes):
            if self.size is not None and len(value) < self.size:
                value = value + self.padding * (self.size - len(value))
            return value

        if (
            isinstance(value, str)
            and self.encoding.lower() == "utf-8"
            and all(ord(ch) <= 0xFF for ch in value)
        ):
            encoded = value.encode("latin-1")
            if self.size is not None and len(encoded) < self.size:
                encoded = encoded + self.padding * (self.size - len(encoded))
            return encoded

        return super().encode(value, mutation_context)


# Convenience function for getting statistics
def get_reduction_stats():
    """
    Print statistics about ReducedString mutations.

    Example:
        >>> from oida.fuzz.primitives.reduced_string import get_reduction_stats
        >>> get_reduction_stats()
    """
    from boofuzz import String as OriginalString

    _log.display("=== String Mutation Statistics ===\n")

    # Original boofuzz stats
    orig_fuzz = len(OriginalString._fuzz_library)
    orig_long = (
        len(OriginalString.long_string_seeds)
        * len(OriginalString._long_string_lengths)
        * len(OriginalString._long_string_deltas)
    )
    orig_total = orig_fuzz + orig_long

    _log.display("Original boofuzz.String:")
    _log.display(f"  Fuzz library: {orig_fuzz}")
    _log.display(f"  Long strings: {orig_long}")
    _log.display(f"  Total per field: {orig_total}")

    # Reduced stats
    reduced_stats = ReducedString.get_stats()
    red_total = reduced_stats["total_per_field"]

    _log.display(f"\nReducedString (level={reduced_stats['reduction_level']}):")
    _log.display(f"  Fuzz library: {reduced_stats['fuzz_library_count']}")
    _log.display(f"  Long strings: {reduced_stats['long_string_count']}")
    _log.display(f"  Total per field: {red_total}")

    _log.display(
        f"\nReduction: {orig_total} → {red_total} ({100 - red_total * 100 // orig_total}% reduction)"
    )
    _log.display(f"Speed improvement: ~{orig_total // red_total}x faster\n")


if __name__ == "__main__":
    # Configure logging for direct execution
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    get_reduction_stats()

    _log.display("\n=== Aggressive Mode ===")
    ReducedString.set_reduction_level("aggressive")
    get_reduction_stats()
