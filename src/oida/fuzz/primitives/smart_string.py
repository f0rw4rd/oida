"""
SmartString primitive with context-aware mutations for protocol fuzzing.

This primitive extends ReducedString with:
1. Context-specific security payloads
2. Composite contexts (e.g., HOST = IP_ADDRESS | HOSTNAME)
3. Limited Radamsa integration for creative mutations

Usage:
    # Single context
    SmartStringPrimitive("path", "/home", context=StringContext.PATH)

    # Predefined composite context
    SmartStringPrimitive("target", "example.com", context=StringContext.HOST)
    # Gets payloads from BOTH IP_ADDRESS and HOSTNAME contexts

    # Custom composite context
    SmartStringPrimitive("addr", "1.2.3.4:80", context=StringContext.IP_ADDRESS | StringContext.PORT)

Mutation counts:
    - ReducedString base: ~560 (length testing + filtered payloads)
    - + Context-specific: +10-40 (depends on context)
    - + Radamsa: +10-25
    - Total: ~580-650 per field
"""

from enum import Flag, auto
from typing import Optional, List, Dict

from .reduced_string import ReducedString
from ..core.mutation import NativeRadamsaMutator, get_mutation_seed
from ...utils.ics_logger import get_logger

_log = get_logger("STRING", "smart", 0)


class StringContext(Flag):
    """Context types for string fields. Can be combined with | operator.

    Base contexts:
        PATH, FILENAME, CREDENTIAL, IP_ADDRESS, PORT, NUMERIC, HOSTNAME, COMMAND, GENERIC

    Predefined composites:
        HOST = IP_ADDRESS | HOSTNAME  - Fields accepting either IP or hostname
        NETWORK_TARGET = IP_ADDRESS | HOSTNAME | PORT  - Full network targets

    Custom composites:
        context = StringContext.PATH | StringContext.FILENAME
    """

    # Base contexts (auto assigns powers of 2)
    PATH = auto()  # File paths, directories
    FILENAME = auto()  # Filenames without path
    CREDENTIAL = auto()  # Usernames, passwords
    IP_ADDRESS = auto()  # IPv4/IPv6 addresses
    PORT = auto()  # Port numbers as strings
    NUMERIC = auto()  # Numeric strings (sizes, counts, offsets)
    HOSTNAME = auto()  # Hostnames, FQDNs
    COMMAND = auto()  # Protocol commands
    GENERIC = auto()  # Default fallback (no context-specific payloads)

    # Predefined composite contexts
    HOST = IP_ADDRESS | HOSTNAME  # Fields accepting IP or hostname
    NETWORK_TARGET = IP_ADDRESS | HOSTNAME | PORT  # Full network targets (host:port)
    FILE_PATH = PATH | FILENAME  # Full file paths


# Context-specific payloads
_CONTEXT_PAYLOADS: Dict[StringContext, List[str]] = {
    StringContext.PATH: [
        # Path traversal variants
        "../",
        "..\\",
        "../" * 10,
        "..\\..\\..\\..\\..\\..\\..\\..\\",
        "....//....//....//",
        "..%00/",
        "..%252f",
        "%2e%2e%2f",
        "%2e%2e/",
        "..%c0%af",
        "..%c1%9c",
        # Absolute paths
        "/etc/passwd",
        "/etc/shadow",
        "C:\\Windows\\System32\\config\\SAM",
        "\\\\?\\C:\\",
        "\\\\*",
        # Special files
        "/dev/null",
        "/dev/random",
        "/proc/self/environ",
        # Windows reserved names
        "CON",
        "NUL",
        "COM1",
        "LPT1",
        # Long paths
        "A" * 256,
        "/" + "A" * 4096,
        # NULL in path (C string bugs)
        "/\x00",
        "\x00/",
        "../" * 10 + "\x00",
        "..\\" * 10 + "\x00",
        # Overlong UTF-8 dot (path traversal bypass)
        "\xc0\xae",
        "%c0%ae",
        # Double encoding
        "%2500",
    ],
    StringContext.FILENAME: [
        # NULL injection (C string truncation)
        "test\x00.txt",
        "test\x00",
        "\x00test.txt",
        "test%00.txt",
        # Path separator injection (parser confusion)
        "test/file.txt",
        "test\\file.txt",
        "../test.txt",
        "..\\test.txt",
        # Special characters that break parsers
        "test:file.txt",  # Colon (Windows drive/NTFS stream)
        "test<file.txt",  # Angle brackets
        "test>file.txt",
        "test|file.txt",  # Pipe
        "test?file.txt",  # Wildcard
        "test*file.txt",  # Wildcard
        'test"file.txt',  # Quote
        # Dot edge cases
        ".",
        "..",
        "...",
        "." * 100,
        # Windows reserved names (cause errors)
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "LPT1",
        "CON.txt",  # Reserved + extension
        # NTFS alternate data streams
        "test.txt::$DATA",
        "test.txt:stream",
        # Control characters
        "test\x01.txt",
        "test\x7f.txt",
        "test\t.txt",
        "test\n.txt",
        "test\r.txt",
    ],
    StringContext.CREDENTIAL: [
        # NULL truncation (bypass password check)
        "admin\x00",
        "admin\x00wrongpassword",
        "\x00admin",
        "admin%00",
        # Unicode normalization (strcmp bypass)
        "ⓐⓓⓜⓘⓝ",  # Circled letters
        "ＡＤＭＩＮ",  # Fullwidth
        "аdmin",  # Cyrillic 'а' (homoglyph)
        "ɑdmin",  # Latin alpha
        # Control characters (parser confusion)
        "admin\x01",
        "admin\x7f",
        "admin\r\n",
        # Whitespace tricks (trimming bugs)
        " admin",
        "admin ",
    ],
    StringContext.IP_ADDRESS: [
        # Boundary IPs
        "0.0.0.0",
        "255.255.255.255",
        "127.0.0.1",
        "127.1",  # Short form
        # Alternative encodings (parser confusion)
        "2130706433",  # 127.0.0.1 as decimal
        "0x7f000001",  # 127.0.0.1 as hex
        "0177.0.0.1",  # Octal
        "0x7f.0.0.1",  # Mixed hex
        # IPv6
        "::1",
        "::ffff:127.0.0.1",  # IPv4-mapped
        "[::]",
        "[::1]",
        "0000:0000:0000:0000:0000:0000:0000:0001",
        # Malformed (parser crashes)
        "1.1.1.1.1",  # Too many octets
        "256.256.256.256",  # Out of range
        "-1.-1.-1.-1",  # Negative
        "1.1.1.",  # Trailing dot
        ".1.1.1",  # Leading dot
        "1..1.1",  # Empty octet
        "127.0.0.1\x00",  # NULL terminated
        "127.0.0.1%00",  # URL-encoded NULL
        # Port/fragment injection
        "127.0.0.1:80",
        "127.0.0.1#fragment",
        "127.0.0.1?query",
        "@127.0.0.1",  # User injection
    ],
    StringContext.PORT: [
        # Boundary values (16-bit)
        "0",
        "1",
        "1023",  # Privileged boundary -1
        "1024",  # Privileged boundary
        "32767",  # Signed 16-bit max
        "32768",  # Signed overflow
        "65535",  # Unsigned 16-bit max
        "65536",  # Unsigned overflow
        # Integer overflow
        "-1",
        "2147483647",  # INT32_MAX
        "2147483648",  # INT32 overflow
        "4294967295",  # UINT32_MAX
        # Non-numeric (parser confusion)
        "abc",
        "80abc",  # Trailing garbage
        "abc80",  # Leading garbage
        "80.5",  # Float
        "8e1",  # Scientific (80)
        "0x50",  # Hex (80)
        "+80",  # Explicit positive
        " 80",  # Leading space
        "80 ",  # Trailing space
        "80\x00",  # NULL terminated
    ],
    StringContext.NUMERIC: [
        # Integer boundaries (signed/unsigned)
        "0",
        "-1",
        "127",  # INT8_MAX
        "128",  # INT8 overflow
        "-128",  # INT8_MIN
        "-129",  # INT8 underflow
        "255",  # UINT8_MAX
        "256",  # UINT8 overflow
        "32767",  # INT16_MAX
        "32768",  # INT16 overflow
        "-32768",  # INT16_MIN
        "-32769",  # INT16 underflow
        "65535",  # UINT16_MAX
        "65536",  # UINT16 overflow
        "2147483647",  # INT32_MAX
        "2147483648",  # INT32 overflow
        "-2147483648",  # INT32_MIN
        "-2147483649",  # INT32 underflow
        "4294967295",  # UINT32_MAX
        "4294967296",  # UINT32 overflow
        # Float edge cases
        "NaN",
        "Infinity",
        "-Infinity",
        "1e308",  # Near DBL_MAX
        "1e309",  # DBL overflow
        "1e-308",  # Near DBL_MIN
        "1e-324",  # Subnormal
        # Alternative representations
        "0x7FFFFFFF",  # INT32_MAX hex
        "0xFFFFFFFF",  # UINT32_MAX hex
        "0777",  # Octal
        "+1",  # Explicit positive
        " 1",  # Leading space
        "1 ",  # Trailing space
        "1\x00",  # NULL terminated
    ],
    StringContext.HOSTNAME: [
        # Localhost variants
        "localhost",
        "localhost.",  # FQDN form
        "localhost.localdomain",
        # Special/invalid
        ".",
        "..",
        "*",  # Wildcard
        "-hostname",  # Leading hyphen (invalid)
        "hostname-",  # Trailing hyphen (invalid)
        # IDN homograph (parser confusion)
        "еxample.com",  # Cyrillic 'е'
        "xn--e1afmkfd.xn--p1ai",  # Punycode
        # Label edge cases
        "example..com",  # Empty label
        ".example.com",  # Leading dot
        "example.com.",  # Trailing dot (FQDN)
        # NULL injection
        "example.com\x00",
        "example.com\x00.evil",
        "example.com%00.evil",
        # DNS label limits (63 chars max)
        "A" * 63 + ".com",  # Max label
        "A" * 64 + ".com",  # Over max label
        # Total length (253 chars max)
        ("a" * 63 + ".") * 3 + "a" * 61,  # Near 253
    ],
    StringContext.COMMAND: [
        # Line/command injection (protocol-specific)
        "\r\n",
        "\r\nINJECTED\r\n",
        "\r\n\r\n",
        "\n",
        "\r",
        "\x00",  # NULL terminator
        # Control characters (terminal/protocol confusion)
        "\x1b",  # ESC
        "\x1b[2J",  # ANSI clear screen
        "\x03",  # ETX (Ctrl+C)
        "\x04",  # EOT (Ctrl+D)
        "\x7f",  # DEL
        # Command terminators/separators
        ";",
        "&&",
        "||",
        "|",
        "&",
        # Quoting (parser state confusion)
        "'",
        '"',
        "`",
        "\\",
    ],
    StringContext.GENERIC: [
        # =============================================================
        # IMPORTANT: DO NOT ADD PAYLOADS HERE!
        # =============================================================
        # ReducedString (the base class) already provides ALL universal
        # fuzzing payloads including:
        #   - Format strings (%n, %s, %x, %p, %99999$n, etc.)
        #   - Length boundaries (via seeds at 8,16,32,64,128,256,512,1024,4096,65535)
        #   - NULL bytes, control characters
        #   - CRLF injection
        #   - Malformed UTF-8
        #   - Binary sequences
        #
        # Adding payloads here would be REDUNDANT and slow down fuzzing.
        #
        # Only add context-specific payloads to the OTHER contexts
        # (PATH, FILENAME, CREDENTIAL, etc.) that test bugs unique to
        # that field type.
        #
        # If you think something is missing universally, add it to
        # ReducedString._fuzz_library or ReducedString.long_string_seeds
        # =============================================================
    ],
}


class SmartStringPrimitive(ReducedString):
    """
    String primitive with context-aware mutations.

    Extends ReducedString with:
    - Context-specific security payloads
    - Limited Radamsa mutations for creative fuzzing

    Example:
        SmartStringPrimitive("username", "admin", context="credential")
        SmartStringPrimitive("path", "/home", context=StringContext.PATH)
    """

    # Default Radamsa mutation count per context
    _radamsa_counts: Dict[StringContext, int] = {
        StringContext.PATH: 20,
        StringContext.FILENAME: 15,
        StringContext.CREDENTIAL: 25,
        StringContext.IP_ADDRESS: 15,
        StringContext.PORT: 10,
        StringContext.NUMERIC: 15,
        StringContext.HOSTNAME: 15,
        StringContext.COMMAND: 20,
        StringContext.GENERIC: 20,
    }

    def __init__(
        self,
        name: Optional[str] = None,
        default_value: str = "",
        context: Optional[StringContext] = None,
        radamsa_count: Optional[int] = None,
        *args,
        **kwargs,
    ):
        """
        Initialize SmartStringPrimitive.

        Args:
            name: Field name
            default_value: Default string value
            context: StringContext enum value. Defaults to GENERIC if not specified.
            radamsa_count: Number of Radamsa mutations (None = use default for context)
            *args, **kwargs: Passed to ReducedString
        """
        super().__init__(name=name, default_value=default_value, *args, **kwargs)

        # Set context (enum only)
        self.context = context if context is not None else StringContext.GENERIC

        # Set Radamsa count (for composites, use max of constituents)
        self.radamsa_count = radamsa_count or self._get_radamsa_count(self.context)

        # Initialize Radamsa mutator (lazy-loaded)
        self._mutator: Optional[NativeRadamsaMutator] = None

    @classmethod
    def _get_radamsa_count(cls, context: StringContext) -> int:
        """Get Radamsa mutation count for a context (including composites).

        For composite contexts, returns the maximum count of any constituent.
        """
        base_contexts = [
            StringContext.PATH,
            StringContext.FILENAME,
            StringContext.CREDENTIAL,
            StringContext.IP_ADDRESS,
            StringContext.PORT,
            StringContext.NUMERIC,
            StringContext.HOSTNAME,
            StringContext.COMMAND,
            StringContext.GENERIC,
        ]

        max_count = 0
        for base_ctx in base_contexts:
            if base_ctx in context:
                count = cls._radamsa_counts.get(base_ctx, 20)
                max_count = max(max_count, count)

        return max_count if max_count > 0 else 20

    def _get_mutator(self) -> NativeRadamsaMutator:
        """Get or create the Radamsa mutator."""
        if self._mutator is None:
            self._mutator = NativeRadamsaMutator()
        return self._mutator

    def _context_payloads(self) -> List[str]:
        """Get context-specific payloads as strings.

        For composite contexts (e.g., HOST = IP_ADDRESS | HOSTNAME),
        combines payloads from all constituent contexts without duplication.

        Boofuzz String expects strings (not bytes) - it calls .encode() internally.
        """
        result = []
        seen = set()

        # Base contexts to check (excludes composites)
        base_contexts = [
            StringContext.PATH,
            StringContext.FILENAME,
            StringContext.CREDENTIAL,
            StringContext.IP_ADDRESS,
            StringContext.PORT,
            StringContext.NUMERIC,
            StringContext.HOSTNAME,
            StringContext.COMMAND,
            StringContext.GENERIC,
        ]

        # Check which base contexts are part of our (possibly composite) context
        for base_ctx in base_contexts:
            if base_ctx in self.context:  # Flag membership check
                for p in _CONTEXT_PAYLOADS.get(base_ctx, []):
                    payload_str = self._to_string(p)
                    if payload_str not in seen:
                        seen.add(payload_str)
                        result.append(payload_str)

        return result

    def _to_string(self, value) -> str:
        """Convert bytes to string if needed."""
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return value.decode("latin-1", errors="replace")
        return value

    def _radamsa_mutations(self, default_value) -> List[str]:
        """Generate Radamsa mutations of the default value.

        Radamsa works with bytes, but we return strings for boofuzz compatibility.
        """
        if not default_value or self.radamsa_count <= 0:
            return []

        # Convert to bytes for Radamsa
        if isinstance(default_value, str):
            default_bytes = default_value.encode("utf-8", errors="replace")
        else:
            default_bytes = default_value

        mutator = self._get_mutator()
        mutations = []

        for i in range(self.radamsa_count):
            try:
                # Use global seed from CLI --seed for reproducibility
                base_seed = get_mutation_seed() or 0
                mutation_seed = base_seed + i
                mutated = mutator.mutate(default_bytes, seed=mutation_seed)
                # Skip if identical to original
                if mutated != default_bytes:
                    # Decode back to string for boofuzz
                    try:
                        mutations.append(mutated.decode("utf-8"))
                    except UnicodeDecodeError:
                        mutations.append(mutated.decode("latin-1", errors="replace"))
            except Exception:
                # Radamsa can occasionally fail on edge cases
                pass

        return mutations

    def mutations(self, default_value):
        """
        Generate all mutations for this field.

        Yields:
            1. ReducedString mutations (length + filtered payloads + format strings)
            2. Context-specific payloads
            3. Radamsa creative mutations

        Args:
            default_value: The default value to mutate (str or bytes)

        Yields:
            Mutated string values (boofuzz String expects strings, not bytes)
        """
        seen = set()

        def to_string(value):
            """Convert bytes to string if needed."""
            if isinstance(value, bytes):
                try:
                    return value.decode("utf-8")
                except UnicodeDecodeError:
                    return value.decode("latin-1", errors="replace")
            return value

        # 1. ReducedString base mutations (includes format strings now)
        # Note: boofuzz String can yield both strings and bytes, convert all to strings
        for mutation in super().mutations(default_value):
            mutation_str = to_string(mutation)
            if mutation_str not in seen:
                seen.add(mutation_str)
                yield mutation_str

        # 2. Context-specific payloads (strings)
        for payload in self._context_payloads():
            if payload not in seen:
                seen.add(payload)
                yield payload

        # 3. Radamsa creative mutations (strings)
        for mutation in self._radamsa_mutations(default_value):
            if mutation not in seen:
                seen.add(mutation)
                yield mutation

    def num_mutations(self, default_value=None):
        """
        Return approximate number of mutations.

        This is an estimate since Radamsa may produce duplicates that get filtered.
        """
        base_count = super().num_mutations(default_value)
        context_count = 0
        for ctx in StringContext:
            if ctx in self.context and ctx in _CONTEXT_PAYLOADS:
                context_count += len(_CONTEXT_PAYLOADS[ctx])
        radamsa_count = self.radamsa_count

        return base_count + context_count + radamsa_count

    @classmethod
    def get_context_stats(cls) -> Dict[str, int]:
        """Get mutation counts per context."""
        stats = {}
        for ctx in StringContext:
            payloads = len(_CONTEXT_PAYLOADS.get(ctx, []))
            radamsa = cls._radamsa_counts.get(ctx, 20)
            stats[ctx.value] = {
                "context_payloads": payloads,
                "radamsa_mutations": radamsa,
                "total_context_specific": payloads + radamsa,
            }
        return stats


# Convenience function
def smart_string(
    name: Optional[str] = None,
    default_value: str = "",
    context: Optional[StringContext] = None,
    **kwargs,
) -> SmartStringPrimitive:
    """
    Create a SmartStringPrimitive instance.

    This is a convenience function that provides a simpler interface.

    Args:
        name: Field name
        default_value: Default value
        context: StringContext enum value (defaults to GENERIC if not specified)
        **kwargs: Additional arguments

    Returns:
        SmartStringPrimitive instance
    """
    return SmartStringPrimitive(name=name, default_value=default_value, context=context, **kwargs)
