"""
Central fuzzing utility for ICS protocols.

Type-aware generator-based fuzzer for producing test cases.
Supports common ICS/protocol data types for targeted boundary testing.
"""

import os
import random
from collections import OrderedDict
from functools import lru_cache
from typing import Iterator, Optional, List, Tuple

from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

# NativeRadamsaMutator is lazy-imported in _get_radamsa() to avoid pulling in
# oida.fuzz (which eagerly imports sqlalchemy/boofuzz) at CLI startup time.
HAS_RADAMSA = True  # Always available with native implementation

# Singleton mutator instance
_radamsa = None

# Global flag to track if random seed was set (for deterministic fuzzing)
_random_seeded = False


class LRUSet:
    """Bounded set with LRU eviction for deduplication without unbounded memory growth."""

    def __init__(self, maxsize: int = 10000):
        self._maxsize = maxsize
        self._dict: OrderedDict = OrderedDict()

    def add(self, item: bytes) -> None:
        """Add item to set, evicting oldest if at capacity."""
        if item in self._dict:
            self._dict.move_to_end(item)
        else:
            self._dict[item] = None
            if len(self._dict) > self._maxsize:
                self._dict.popitem(last=False)

    def __contains__(self, item: bytes) -> bool:
        return item in self._dict

    def __len__(self) -> int:
        return len(self._dict)


# Type aliases for cross-protocol compatibility
TYPE_ALIASES = {
    # CIP types
    "BOOL": "bool",
    "USINT": "uint8",
    "SINT": "int8",
    "BYTE": "uint8",
    "UINT": "uint16",
    "INT": "int16",
    "WORD": "uint16",
    "UDINT": "uint32",
    "DINT": "int32",
    "DWORD": "uint32",
    "REAL": "float32",
    "ULINT": "uint64",
    "LINT": "int64",
    "LWORD": "uint64",
    "LREAL": "float64",
    "STRING": "string",
    "SHORT_STRING": "string",
    # OPC UA types
    "Boolean": "bool",
    "SByte": "int8",
    "Byte": "uint8",
    "Int16": "int16",
    "UInt16": "uint16",
    "Int32": "int32",
    "UInt32": "uint32",
    "Int64": "int64",
    "UInt64": "uint64",
    "Float": "float32",
    "Double": "float64",
    "String": "string",
    # Modbus types
    "COIL": "bool",
    "DISCRETE": "bool",
    "HOLDING": "uint16",
    "INPUT": "uint16",
    # Generic
    "STRUCT": "struct",
    "EPATH": "struct",
}


def _get_radamsa():
    """Get native radamsa-style mutator instance (lazy import)"""
    global _radamsa
    if _radamsa is None:
        from oida.fuzz.core.mutation import NativeRadamsaMutator

        _radamsa = NativeRadamsaMutator()
    return _radamsa


def _generate_random_bytes(length: int) -> bytes:
    """Generate random bytes efficiently.

    Uses os.urandom() for speed when no seed is set (non-deterministic mode).
    Falls back to random.randint() when seeded for reproducibility.
    """
    if _random_seeded:
        # Deterministic mode: use seeded random
        return bytes([random.randint(0, 255) for _ in range(length)])
    else:
        # Fast mode: use OS randomness
        return os.urandom(length)


def _simple_mutate(data: bytes, seed: int) -> bytes:
    """Simple mutation strategies when radamsa is unavailable"""
    if not data:
        return _generate_random_bytes(4)

    data = bytearray(data)
    strategy = seed % 8

    if strategy == 0 and data:
        # Bit flip
        pos = random.randint(0, len(data) - 1)
        data[pos] ^= 1 << random.randint(0, 7)
    elif strategy == 1 and data:
        # Byte replacement
        pos = random.randint(0, len(data) - 1)
        data[pos] = random.randint(0, 255)
    elif strategy == 2:
        # All zeros
        data = bytearray(len(data))
    elif strategy == 3:
        # All 0xFF
        data = bytearray([0xFF] * len(data))
    elif strategy == 4 and len(data) > 1:
        # Truncate
        data = data[: len(data) // 2]
    elif strategy == 5:
        # Extend with random
        extend_len = random.randint(1, 8)
        data.extend(_generate_random_bytes(extend_len))
    elif strategy == 6 and len(data) >= 2:
        # Boundary values
        data[0] = 0x00
        data[-1] = 0xFF
    elif strategy == 7:
        # Random shuffle
        random.shuffle(data)

    return bytes(data)


def _get_type_boundaries(
    data_type: str, original: Optional[bytes] = None
) -> List[Tuple[bytes, str]]:
    """Get type-specific boundary test cases.

    Args:
        data_type: Data type string (CIP, OPC UA, Modbus, or generic)
        original: Original value for size reference

    Returns:
        List of (payload_bytes, description) tuples
    """
    # Normalize type
    normalized = TYPE_ALIASES.get(
        data_type.upper() if data_type else "", data_type.lower() if data_type else ""
    )
    len(original) if original else 4

    cases: List[Tuple[bytes, str]] = []

    # === Boolean ===
    if normalized == "bool":
        cases.extend(
            [
                (b"\x00", "false"),
                (b"\x01", "true"),
                (b"\x02", "invalid bool 0x02"),
                (b"\x7f", "invalid bool 0x7F"),
                (b"\x80", "invalid bool 0x80"),
                (b"\xff", "invalid bool 0xFF"),
                (b"\x00\x00", "bool overflow 2 bytes"),
            ]
        )

    # === 8-bit integers ===
    elif normalized in ("uint8", "int8"):
        cases.extend(
            [
                (b"\x00", "zero"),
                (b"\x01", "one"),
                (b"\x7e", "126"),
                (b"\x7f", "INT8_MAX (127)"),
                (b"\x80", "INT8_MIN (-128)"),
                (b"\x81", "-127"),
                (b"\xfe", "254 / -2"),
                (b"\xff", "UINT8_MAX (255) / -1"),
                (b"\x00\x00", "overflow 2 bytes"),
                (b"\xff\xff", "overflow 2 bytes 0xFF"),
            ]
        )

    # === 16-bit integers ===
    elif normalized in ("uint16", "int16"):
        cases.extend(
            [
                (b"\x00\x00", "zero"),
                (b"\x01\x00", "one (LE)"),
                (b"\x00\x01", "256 (LE)"),
                (b"\xff\x00", "255 (LE)"),
                (b"\x00\x7f", "0x7F00 (LE)"),
                (b"\xff\x7f", "INT16_MAX (32767)"),
                (b"\x00\x80", "INT16_MIN (-32768)"),
                (b"\x01\x80", "-32767"),
                (b"\xfe\xff", "65534 / -2"),
                (b"\xff\xff", "UINT16_MAX (65535) / -1"),
                (b"\x00\x00\x00", "overflow 3 bytes"),
                (b"\xff\xff\xff", "overflow 3 bytes 0xFF"),
                (b"\x00", "truncated 1 byte"),
            ]
        )

    # === 32-bit integers ===
    elif normalized in ("uint32", "int32"):
        cases.extend(
            [
                (b"\x00\x00\x00\x00", "zero"),
                (b"\x01\x00\x00\x00", "one (LE)"),
                (b"\xff\x00\x00\x00", "255 (LE)"),
                (b"\x00\x01\x00\x00", "256 (LE)"),
                (b"\xff\xff\x00\x00", "65535 (LE)"),
                (b"\x00\x00\x01\x00", "65536 (LE)"),
                (b"\xff\xff\xff\x7f", "INT32_MAX (2147483647)"),
                (b"\x00\x00\x00\x80", "INT32_MIN (-2147483648)"),
                (b"\xfe\xff\xff\xff", "UINT32_MAX-1 / -2"),
                (b"\xff\xff\xff\xff", "UINT32_MAX / -1"),
                (b"\x00\x00\x00\x00\x00", "overflow 5 bytes"),
                (b"\xff\xff\xff\xff\xff", "overflow 5 bytes 0xFF"),
                (b"\x00\x00\x00", "truncated 3 bytes"),
                (b"\x00\x00", "truncated 2 bytes"),
            ]
        )

    # === 64-bit integers ===
    elif normalized in ("uint64", "int64"):
        cases.extend(
            [
                (b"\x00" * 8, "zero"),
                (b"\x01" + b"\x00" * 7, "one (LE)"),
                (b"\xff" * 4 + b"\x00" * 4, "UINT32_MAX in UINT64"),
                (b"\xff\xff\xff\xff\xff\xff\xff\x7f", "INT64_MAX"),
                (b"\x00\x00\x00\x00\x00\x00\x00\x80", "INT64_MIN"),
                (b"\xfe" + b"\xff" * 7, "UINT64_MAX-1"),
                (b"\xff" * 8, "UINT64_MAX / -1"),
                (b"\x00" * 9, "overflow 9 bytes"),
                (b"\x00" * 4, "truncated 4 bytes"),
            ]
        )

    # === 32-bit float ===
    elif normalized == "float32":
        cases.extend(
            [
                (b"\x00\x00\x00\x00", "0.0"),
                (b"\x00\x00\x80\x3f", "1.0"),
                (b"\x00\x00\x80\xbf", "-1.0"),
                (b"\xff\xff\x7f\x7f", "FLT_MAX"),
                (b"\xff\xff\x7f\xff", "-FLT_MAX"),
                (b"\x00\x00\x80\x7f", "+Infinity"),
                (b"\x00\x00\x80\xff", "-Infinity"),
                (b"\x00\x00\xc0\x7f", "NaN"),
                (b"\x01\x00\x00\x00", "FLT_MIN (denormal)"),
                (b"\x00\x00\x00\x00\x00", "overflow 5 bytes"),
            ]
        )

    # === 64-bit float ===
    elif normalized == "float64":
        cases.extend(
            [
                (b"\x00" * 8, "0.0"),
                (b"\x00\x00\x00\x00\x00\x00\xf0\x3f", "1.0"),
                (b"\x00\x00\x00\x00\x00\x00\xf0\xbf", "-1.0"),
                (b"\xff\xff\xff\xff\xff\xff\xef\x7f", "DBL_MAX"),
                (b"\x00\x00\x00\x00\x00\x00\xf0\x7f", "+Infinity"),
                (b"\x00\x00\x00\x00\x00\x00\xf0\xff", "-Infinity"),
                (b"\x00\x00\x00\x00\x00\x00\xf8\x7f", "NaN"),
                (b"\x00" * 9, "overflow 9 bytes"),
            ]
        )

    # === Strings ===
    elif normalized == "string":
        cases.extend(
            [
                (b"\x00\x00", "empty (len=0)"),
                (b"\x01\x00A", "1 char 'A'"),
                (b"\x05\x00AAAAA", "5 chars"),
                (b"\x10\x00" + b"A" * 16, "16 chars"),
                (b"\x00\x01" + b"A" * 256, "256 chars"),
                (b"\xff\x00" + b"A" * 255, "255 chars (max short)"),
                (b"\xff\xff" + b"A" * 100, "length 65535, data 100"),
                (b"\x05\x00AB", "length 5, data 2 (short)"),
                (b"\x00\x00" + b"\x00" * 10, "nulls after len=0"),
                (b"\x05\x00\x00\x00\x00\x00\x00", "5 nulls"),
                (b"\x05\x00\xff\xff\xff\xff\xff", "5 x 0xFF"),
                (b"", "empty payload"),
            ]
        )

    # === Struct/complex (size-based) ===
    elif normalized == "struct" or not normalized:
        # Generic size-based mutations
        if original:
            # Bit flips at various positions
            if len(original) >= 1:
                flipped = bytearray(original)
                flipped[0] ^= 0x01
                cases.append((bytes(flipped), "bit flip byte 0"))
            if len(original) >= 2:
                flipped = bytearray(original)
                flipped[1] ^= 0x01
                cases.append((bytes(flipped), "bit flip byte 1"))
            if len(original) >= 4:
                flipped = bytearray(original)
                flipped[-1] ^= 0x80
                cases.append((bytes(flipped), "bit flip last byte MSB"))

            cases.extend(
                [
                    (b"\x00" * len(original), f"all 0x00 ({len(original)} bytes)"),
                    (b"\xff" * len(original), f"all 0xFF ({len(original)} bytes)"),
                    (b"\xaa" * len(original), f"all 0xAA ({len(original)} bytes)"),
                    (b"\x55" * len(original), f"all 0x55 ({len(original)} bytes)"),
                    (
                        original[: len(original) // 2] if len(original) > 1 else b"",
                        "truncated half",
                    ),
                    (original + b"\x00", "overflow +1 byte"),
                    (original + b"\x00" * 4, "overflow +4 bytes"),
                ]
            )

    return cases


@lru_cache(maxsize=32)
def _get_type_boundaries_cached(data_type: str) -> Tuple[Tuple[bytes, str], ...]:
    """Cached version of _get_type_boundaries for type-only lookups.

    When no original value is provided, the boundary cases depend only on
    the data type. Caching these avoids regenerating identical static
    boundary cases on every fuzz() call.

    Returns tuple of tuples for hashability (required by lru_cache).
    """
    return tuple(_get_type_boundaries(data_type, None))


def fuzz(
    original: Optional[bytes] = None,
    count: int = 100,
    min_len: int = 0,
    max_len: int = 256,
    data_type: str = "",
) -> Iterator[Tuple[bytes, str]]:
    """
    Generate fuzz test cases with type-aware boundary testing.

    Args:
        original: Original value to mutate (None for pure generation)
        count: Number of test cases to generate (default: 100)
        min_len: Minimum payload length (default: 0)
        max_len: Maximum payload length (default: 256)
        data_type: Data type for type-specific boundaries. Supports:
            - CIP: BOOL, USINT, SINT, UINT, INT, UDINT, DINT, REAL, STRING, etc.
            - OPC UA: Boolean, Byte, Int16, UInt32, Float, Double, String, etc.
            - Modbus: COIL, DISCRETE, HOLDING, INPUT
            - Generic: uint8, uint16, uint32, int8, int16, int32, float32, etc.

    Yields:
        Tuple[bytes, str]: (payload_bytes, description) tuples

    Example:
        # Type-aware fuzzing
        for payload, desc in fuzz(b"\\x01", data_type="BOOL", count=10):
            print(f"{payload.hex()} - {desc}")

        # With original value (generic)
        for payload, desc in fuzz(b"\\x01\\x02\\x03", count=10):
            send(payload)

        # Without original (pure generation)
        for payload, desc in fuzz(count=50, min_len=4, max_len=64):
            send(payload)
    """
    # Fail fast on an impossible length range instead of looping forever in PHASE 5.
    if min_len > max_len:
        raise ValueError(f"min_len ({min_len}) must not exceed max_len ({max_len})")

    # Use LRUSet for bounded memory during long fuzzing runs (P4 optimization)
    seen: LRUSet = LRUSet(maxsize=10000)
    yielded = 0
    orig_len = len(original) if original else max(min_len, 4)

    def emit(data: bytes, desc: str) -> bool:
        """Yield if unique and within bounds, return True if yielded"""
        nonlocal yielded
        if data in seen or yielded >= count:
            return False
        if len(data) < min_len or len(data) > max_len:
            return False
        seen.add(data)
        yielded += 1
        return True

    # === PHASE 1: Type-specific boundary test cases ===
    if data_type:
        # Use cached version when no original value (P1 optimization)
        if original is None:
            type_boundaries = _get_type_boundaries_cached(data_type)
        else:
            type_boundaries = _get_type_boundaries(data_type, original)
        for payload, desc in type_boundaries:
            if emit(payload, desc):
                yield (payload, desc)
            if yielded >= count:
                return

    # === PHASE 2: Generic boundary test cases ===
    generic_cases = [
        (b"", "empty"),
        (b"\x00", "single null"),
        (b"\xff", "single 0xFF"),
        (b"\x00" * orig_len, f"all 0x00 ({orig_len} bytes)"),
        (b"\xff" * orig_len, f"all 0xFF ({orig_len} bytes)"),
        (b"\x00" * min_len, f"min len zeros ({min_len} bytes)") if min_len > 0 else None,
        (b"\xff" * min_len, f"min len 0xFF ({min_len} bytes)") if min_len > 0 else None,
        (b"\x00\x00\x00\x00", "INT32 zero"),
        (b"\xff\xff\xff\xff", "UINT32_MAX"),
        (b"\xff\xff\xff\x7f", "INT32_MAX (LE)"),
        (b"\x00\x00\x00\x80", "INT32_MIN (LE)"),
    ]

    # Add original-based boundaries
    if original:
        generic_cases.extend(
            [
                (
                    original[: len(original) // 2] if len(original) > 1 else b"",
                    "truncated half",
                ),
                (original + b"\x00", "overflow +1"),
                (original + b"\x00" * 8, "overflow +8"),
                (original + b"\xff" * 4, "overflow +4 (0xFF)"),
            ]
        )
        # Bit flips
        if len(original) >= 1:
            flipped = bytearray(original)
            flipped[0] ^= 0x01
            generic_cases.append((bytes(flipped), "bit flip byte 0"))
        if len(original) >= 2:
            flipped = bytearray(original)
            flipped[-1] ^= 0x80
            generic_cases.append((bytes(flipped), "bit flip last byte MSB"))

    for case in generic_cases:
        if case is None:
            continue
        payload, desc = case
        if emit(payload, desc):
            yield (payload, desc)
        if yielded >= count:
            return

    # === PHASE 2b: Random mutations at original length ===
    if original and len(original) > 4:
        n = len(original)
        # Single random byte replacement at each quartile
        for i, label in [
            (0, "first"),
            (n // 4, "Q1"),
            (n // 2, "mid"),
            (3 * n // 4, "Q3"),
            (n - 1, "last"),
        ]:
            for val in (0x00, 0xFF, 0x41):
                mut = bytearray(original)
                mut[i] = val
                payload = bytes(mut)
                if emit(payload, f"byte {label}=0x{val:02X}"):
                    yield (payload, f"byte {label}=0x{val:02X}")
                if yielded >= count:
                    return

        # Multi-byte corruptions: zero/FF runs at different offsets
        for start_frac, length in [(0, 4), (0.25, 8), (0.5, 4), (0.5, 16), (0.75, 8), (0, n)]:
            offset = int(n * start_frac)
            end = min(offset + length, n)
            for fill, fill_name in [(0x00, "zero"), (0xFF, "FF")]:
                mut = bytearray(original)
                for j in range(offset, end):
                    mut[j] = fill
                payload = bytes(mut)
                desc = f"{fill_name} fill [{offset}:{end}]"
                if emit(payload, desc):
                    yield (payload, desc)
                if yielded >= count:
                    return

        # Random byte scatter (N random positions flipped)
        for scatter_count in (1, 2, 4, 8):
            for seed_val in range(3):
                rng = random.Random(seed_val)
                mut = bytearray(original)
                positions = rng.sample(range(n), min(scatter_count, n))
                for pos in positions:
                    mut[pos] = rng.randint(0, 255)
                payload = bytes(mut)
                desc = f"scatter {scatter_count} bytes (seed {seed_val})"
                if emit(payload, desc):
                    yield (payload, desc)
                if yielded >= count:
                    return

        # Sliding window bit flip (8-bit window across the data)
        for byte_pos in range(0, n, max(1, n // 16)):
            for bit in range(8):
                mut = bytearray(original)
                mut[byte_pos] ^= 1 << bit
                payload = bytes(mut)
                desc = f"bit flip [{byte_pos}].{bit}"
                if emit(payload, desc):
                    yield (payload, desc)
                if yielded >= count:
                    return

    # === PHASE 3: Radamsa-style mutations (native) ===
    mutator = _get_radamsa()
    if mutator and original:
        radamsa_count = 0
        while yielded < count and radamsa_count < count * 2:
            mutated = mutator.mutate(original, seed=radamsa_count)
            radamsa_count += 1
            if emit(mutated, f"radamsa mutation #{radamsa_count}"):
                yield (mutated, f"radamsa mutation #{radamsa_count}")

    # === PHASE 4: Simple mutations ===
    seed = 0
    base = original if original else bytes([0x41] * orig_len)
    mutation_names = [
        "bit flip",
        "byte replace",
        "all zeros",
        "all 0xFF",
        "truncate",
        "extend random",
        "boundary inject",
        "shuffle",
    ]
    while yielded < count:
        mutated = _simple_mutate(base, seed)
        desc = f"simple {mutation_names[seed % 8]} #{seed // 8 + 1}"
        if emit(mutated, desc):
            yield (mutated, desc)
        seed += 1
        if seed > count * 3:
            break

    # === PHASE 5: Random fill if still needed (P3 optimization) ===
    # Bounded attempts so an exhausted value space (e.g. min_len==max_len==1 has
    # only 256 distinct payloads) cannot spin forever once emit() always rejects.
    random_count = 0
    attempts = 0
    while yielded < count and attempts < count * 4:
        attempts += 1
        length = random.randint(min_len, max_len) if max_len > min_len else min_len
        data = _generate_random_bytes(length)
        random_count += 1
        if emit(data, f"random {length} bytes #{random_count}"):
            yield (data, f"random {length} bytes #{random_count}")
