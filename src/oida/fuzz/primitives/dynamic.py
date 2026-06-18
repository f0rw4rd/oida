"""
Dynamic primitives that switch between boofuzz and Radamsa

These primitives automatically choose the mutation strategy based on
global configuration, eliminating the need for duplicate fuzzer code.

Usage:
    # Instead of:
    from boofuzz import String

    # Use:
    from oida.fuzz.primitives.dynamic import SmartString
    from oida.fuzz.primitives.smart_string import StringContext

    # Specify context for targeted mutations:
    SmartString("username", "admin", context=StringContext.CREDENTIAL)
    SmartString("path", "/home/user", context=StringContext.PATH)

    # Enable Radamsa globally for even more mutations:
    from oida.fuzz.core.mutation.config import enable_radamsa
    enable_radamsa(mutation_count=500)
"""

from typing import Callable, Optional

from boofuzz import Bytes as BoofuzzBytes, DWord, Static, Word

from ..core.mutation.config import (
    is_radamsa_enabled,
    get_radamsa_mutation_count,
)
from .smart_string import StringContext


class DynamicWord(Word):
    """Word whose non-fuzzed value comes from a callable at render time.

    When boofuzz is fuzzing this field, mutations work normally.
    When not being fuzzed, value_func() provides the current value.
    """

    def __init__(self, name: str, value_func: Callable[[], int], **kwargs):
        super().__init__(name=name, default_value=0, **kwargs)
        self._value_func = value_func

    def original_value(self, test_case_context=None):
        return self._value_func()


class DynamicDWord(DWord):
    """DWord whose non-fuzzed value comes from a callable at render time.

    When boofuzz is fuzzing this field, mutations work normally.
    When not being fuzzed, value_func() provides the current value.
    """

    def __init__(self, name: str, value_func: Callable[[], int], **kwargs):
        super().__init__(name=name, default_value=0, **kwargs)
        self._value_func = value_func

    def original_value(self, test_case_context=None):
        return self._value_func()


class DynamicBytes(Static):
    """Static whose value comes from a callable at render time.

    Always non-fuzzable (like Static), but the bytes are dynamic.
    """

    def __init__(self, name: str, value_func: Callable[[], bytes]):
        super().__init__(name=name, default_value=b"")
        self._value_func = value_func

    def original_value(self, test_case_context=None):
        return self._value_func()


def SmartString(
    name: Optional[str] = None,
    default_value: str = "",
    size: Optional[int] = None,
    padding: bytes = b"\x00",
    encoding: str = "ascii",
    fuzzable: bool = True,
    max_len: Optional[int] = None,
    context: Optional[StringContext] = None,
    radamsa_count: Optional[int] = None,
    radamsa_mutation_count: Optional[int] = None,  # Deprecated alias
    **kwargs,
):
    """
    Smart String primitive with context-aware mutations.

    Uses SmartStringPrimitive which provides:
    - Reduced payload set (no useless web payloads)
    - Format string payloads for memory corruption
    - Context-specific security payloads (path traversal, SSRF, etc.)
    - Limited Radamsa mutations for creativity

    Args:
        name: Field name
        default_value: Default string value
        size: Static size (None for dynamic)
        padding: Padding character
        encoding: String encoding
        fuzzable: Enable/disable fuzzing
        max_len: Maximum length
        context: StringContext enum value. Defaults to GENERIC if not specified.
        radamsa_count: Number of Radamsa mutations (default varies by context)
        radamsa_mutation_count: Deprecated alias for radamsa_count
        **kwargs: Additional arguments passed to underlying primitive

    Returns:
        SmartStringPrimitive instance

    Context types and what they test:
        - PATH: Path traversal, null injection, absolute paths
        - FILENAME: Special chars, reserved names, extension tricks
        - CREDENTIAL: Format strings, length boundaries, bypass attempts
        - IP_ADDRESS: Reserved ranges, SSRF bypass, IPv6
        - PORT: Boundary values (0, 65535, overflow)
        - NUMERIC: Integer boundaries, floats, NaN/Infinity
        - HOSTNAME: IDN, wildcards, label injection
        - COMMAND: Control chars, line injection
        - GENERIC: Format strings, control chars (default)

    Example:
        SmartString("username", "admin", context=StringContext.CREDENTIAL)
        SmartString("path", "/home/user", context=StringContext.PATH)
        SmartString("port", "8080", context=StringContext.PORT)
    """
    # Handle deprecated alias
    if radamsa_mutation_count is not None and radamsa_count is None:
        radamsa_count = radamsa_mutation_count

    # Import here to avoid circular imports
    from .smart_string import SmartStringPrimitive

    return SmartStringPrimitive(
        name=name,
        default_value=default_value,
        size=size,
        padding=padding,
        encoding=encoding,
        fuzzable=fuzzable,
        max_len=max_len,
        context=context,
        radamsa_count=radamsa_count,
        **kwargs,
    )


def SmartBytes(
    name: Optional[str] = None,
    default_value: bytes = b"",
    size: Optional[int] = None,
    padding: bytes = b"\x00",
    fuzzable: bool = True,
    max_len: Optional[int] = None,
    radamsa_mutation_count: Optional[int] = None,
    **kwargs,
):
    """
    Smart Bytes primitive that switches between boofuzz and Radamsa

    Args:
        name: Field name
        default_value: Default bytes value
        size: Static size (None for dynamic)
        padding: Padding bytes
        fuzzable: Enable/disable fuzzing
        max_len: Maximum length
        radamsa_mutation_count: Override global mutation count (Radamsa mode only)
        **kwargs: Additional arguments

    Returns:
        Either BoofuzzBytes or RadamsaBytes instance

    Note:
        min_len is not supported by boofuzz Bytes and will be ignored.
    """
    # Remove min_len if passed - boofuzz Bytes doesn't support it
    kwargs.pop("min_len", None)

    if is_radamsa_enabled():
        # Use radamsa-style mutations (native implementation)
        from .radamsa_primitives import RadamsaBytes

        mutation_count = radamsa_mutation_count or get_radamsa_mutation_count()

        return RadamsaBytes(
            name=name,
            default_value=default_value,
            mutation_count=mutation_count,
            max_len=max_len,
            **kwargs,
        )

    # Use boofuzz default
    return BoofuzzBytes(
        name=name,
        default_value=default_value,
        size=size,
        padding=padding,
        fuzzable=fuzzable,
        max_len=max_len,
        **kwargs,
    )


# Convenience aliases
s_smart_string = SmartString
s_smart_bytes = SmartBytes
