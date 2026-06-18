"""
Native Python implementation of radamsa-style mutations.

This module provides a pure Python implementation of mutation algorithms
similar to those in radamsa, without requiring pyradamsa as a dependency.

Implemented mutations:
- Byte-level: drop, flip, insert, repeat, permute, inc, dec, random, seq_repeat, seq_delete
- Line-level: delete, duplicate, clone, repeat, swap, permute, insert, replace
- Fusion: fuse_self, fuse_samples
- Special: num_mutate, interesting_bytes, utf8_widen, ascii_num_insert, chunk_swap
"""

import random
import re
import struct
from typing import List, Optional, Callable, Tuple


# Interesting byte values for boundary testing (from AFL/radamsa)
INTERESTING_8 = [
    0,
    1,
    16,
    32,
    64,
    100,
    127,
    128,
    255,
]

INTERESTING_16 = [
    0,
    1,
    32,
    64,
    100,
    127,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    32768,
    65535,
]

INTERESTING_32 = [
    0,
    1,
    32,
    64,
    100,
    127,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    32768,
    65535,
    65536,
    100000,
    0x7FFFFFFF,
    0x80000000,
    0xFFFFFFFF,
]

# ASCII number strings for insertion
ASCII_NUMBERS = [
    b"0",
    b"1",
    b"-1",
    b"127",
    b"128",
    b"255",
    b"256",
    b"32767",
    b"32768",
    b"65535",
    b"65536",
    b"2147483647",
    b"2147483648",
    b"4294967295",
    b"-2147483648",
    b"0x0",
    b"0x1",
    b"0xFFFF",
    b"0xFFFFFFFF",
    b"NaN",
    b"Infinity",
    b"-Infinity",
    b"1e100",
    b"1e-100",
    b"0.0",
    b"-0.0",
    b"1.0",
    b"-1.0",
]


class NativeRadamsaMutator:
    """
    Pure Python mutation engine implementing radamsa-style mutations.

    This class provides deterministic, seed-based mutations without
    requiring external dependencies. Each mutation is reproducible
    given the same seed value.
    """

    def __init__(self, seed: Optional[int] = None):
        """
        Initialize the mutator.

        Args:
            seed: Random seed for reproducibility. If None, uses system entropy.
        """
        self.rng = random.Random(seed)
        self._samples: List[bytes] = []

        # Mutation registry with weights (higher = more likely)
        self._mutations: List[Tuple[Callable[[bytes], bytes], int]] = [
            # Byte-level mutations (weight: frequency)
            (self.byte_drop, 10),
            (self.byte_flip, 15),
            (self.byte_insert, 10),
            (self.byte_repeat, 8),
            (self.byte_permute, 5),
            (self.byte_inc, 8),
            (self.byte_dec, 8),
            (self.byte_random, 10),
            (self.seq_repeat, 5),
            (self.seq_delete, 8),
            # Line-level mutations
            (self.line_delete, 6),
            (self.line_duplicate, 6),
            (self.line_clone, 4),
            (self.line_repeat, 4),
            (self.line_swap, 5),
            (self.line_permute, 3),
            (self.line_insert, 4),
            (self.line_replace, 4),
            # Fusion mutations
            (self.fuse_self, 5),
            # Special mutations
            (self.num_mutate, 8),
            (self.interesting_bytes, 10),
            (self.utf8_widen, 3),
            (self.ascii_num_insert, 5),
            (self.chunk_swap, 6),
        ]

    def set_seed(self, seed: int) -> None:
        """Set the random seed for reproducible mutations."""
        self.rng = random.Random(seed)

    def add_sample(self, sample: bytes) -> None:
        """Add a sample for fusion mutations."""
        self._samples.append(sample)

    def clear_samples(self) -> None:
        """Clear stored samples."""
        self._samples.clear()

    def mutate(self, data: bytes, seed: Optional[int] = None) -> bytes:
        """
        Apply random mutation(s) to data.

        Args:
            data: Data to mutate
            seed: Optional seed for this specific mutation

        Returns:
            Mutated data
        """
        if seed is not None:
            self.rng = random.Random(seed)

        if not data:
            # For empty data, generate some random bytes
            return bytes([self.rng.randint(0, 255) for _ in range(self.rng.randint(1, 10))])

        # Select mutation based on weights
        mutations, weights = zip(*self._mutations)
        mutation_fn = self.rng.choices(mutations, weights=weights, k=1)[0]

        # Apply mutation
        result = mutation_fn(data)

        # Sometimes apply multiple mutations (20% chance)
        if self.rng.random() < 0.2:
            mutation_fn = self.rng.choices(mutations, weights=weights, k=1)[0]
            result = mutation_fn(result)

        return result

    def mutate_batch(self, data: bytes, count: int, start_seed: int = 0) -> List[bytes]:
        """
        Generate multiple mutations of the same data.

        Args:
            data: Data to mutate
            count: Number of mutations to generate
            start_seed: Starting seed value

        Returns:
            List of mutated data
        """
        return [self.mutate(data, seed=start_seed + i) for i in range(count)]

    # =========================================================================
    # Byte-level mutations
    # =========================================================================

    def byte_drop(self, data: bytes) -> bytes:
        """Delete random bytes from data."""
        if len(data) < 2:
            return data

        data = bytearray(data)
        # Drop 1-4 bytes at random position
        drop_count = min(self.rng.randint(1, 4), len(data) - 1)
        pos = self.rng.randint(0, len(data) - drop_count)
        del data[pos : pos + drop_count]
        return bytes(data)

    def byte_flip(self, data: bytes) -> bytes:
        """Flip random bits in data."""
        if not data:
            return data

        data = bytearray(data)
        # Flip 1-8 bits
        flip_count = self.rng.randint(1, 8)
        for _ in range(flip_count):
            pos = self.rng.randint(0, len(data) - 1)
            bit = 1 << self.rng.randint(0, 7)
            data[pos] ^= bit
        return bytes(data)

    def byte_insert(self, data: bytes) -> bytes:
        """Insert random bytes into data."""
        data = bytearray(data)
        pos = self.rng.randint(0, len(data))
        # Insert 1-4 random bytes
        insert_count = self.rng.randint(1, 4)
        insert_bytes = bytes([self.rng.randint(0, 255) for _ in range(insert_count)])
        data[pos:pos] = insert_bytes
        return bytes(data)

    def byte_repeat(self, data: bytes) -> bytes:
        """Repeat a byte sequence."""
        if not data:
            return data

        data = bytearray(data)
        pos = self.rng.randint(0, len(data) - 1)
        # Repeat 1-4 bytes, 2-8 times
        repeat_len = min(self.rng.randint(1, 4), len(data) - pos)
        repeat_count = self.rng.randint(2, 8)
        chunk = data[pos : pos + repeat_len]
        data[pos : pos + repeat_len] = chunk * repeat_count
        return bytes(data)

    def byte_permute(self, data: bytes) -> bytes:
        """Permute (shuffle) a range of bytes."""
        if len(data) < 2:
            return data

        data = bytearray(data)
        # Select range to permute (2-8 bytes)
        perm_len = min(self.rng.randint(2, 8), len(data))
        pos = self.rng.randint(0, len(data) - perm_len)

        chunk = list(data[pos : pos + perm_len])
        self.rng.shuffle(chunk)
        data[pos : pos + perm_len] = bytes(chunk)
        return bytes(data)

    def byte_inc(self, data: bytes) -> bytes:
        """Increment random bytes."""
        if not data:
            return data

        data = bytearray(data)
        # Increment 1-4 bytes
        inc_count = min(self.rng.randint(1, 4), len(data))
        positions = self.rng.sample(range(len(data)), inc_count)
        for pos in positions:
            data[pos] = (data[pos] + self.rng.randint(1, 16)) & 0xFF
        return bytes(data)

    def byte_dec(self, data: bytes) -> bytes:
        """Decrement random bytes."""
        if not data:
            return data

        data = bytearray(data)
        # Decrement 1-4 bytes
        dec_count = min(self.rng.randint(1, 4), len(data))
        positions = self.rng.sample(range(len(data)), dec_count)
        for pos in positions:
            data[pos] = (data[pos] - self.rng.randint(1, 16)) & 0xFF
        return bytes(data)

    def byte_random(self, data: bytes) -> bytes:
        """Replace bytes with random values."""
        if not data:
            return data

        data = bytearray(data)
        # Randomize 1-8 bytes
        rand_count = min(self.rng.randint(1, 8), len(data))
        positions = self.rng.sample(range(len(data)), rand_count)
        for pos in positions:
            data[pos] = self.rng.randint(0, 255)
        return bytes(data)

    def seq_repeat(self, data: bytes) -> bytes:
        """Repeat a larger sequence many times."""
        if len(data) < 2:
            return data

        # Select a chunk (4-32 bytes) and repeat it many times
        chunk_len = min(self.rng.randint(4, 32), len(data))
        pos = self.rng.randint(0, len(data) - chunk_len)
        chunk = data[pos : pos + chunk_len]

        # Repeat 8-64 times
        repeat_count = self.rng.randint(8, 64)
        repeated = chunk * repeat_count

        # Insert or replace
        if self.rng.random() < 0.5:
            # Insert
            return data[:pos] + repeated + data[pos:]
        else:
            # Replace
            return data[:pos] + repeated + data[pos + chunk_len :]

    def seq_delete(self, data: bytes) -> bytes:
        """Delete a range of bytes."""
        if len(data) < 4:
            return data

        # Delete 4-64 bytes
        del_len = min(self.rng.randint(4, 64), len(data) - 1)
        pos = self.rng.randint(0, len(data) - del_len)
        return data[:pos] + data[pos + del_len :]

    # =========================================================================
    # Line-level mutations
    # =========================================================================

    def _split_lines(self, data: bytes) -> Tuple[List[bytes], bytes]:
        """Split data into lines, preserving line endings."""
        # Try to detect line ending style
        if b"\r\n" in data:
            sep = b"\r\n"
        elif b"\n" in data:
            sep = b"\n"
        elif b"\r" in data:
            sep = b"\r"
        else:
            # No line endings - treat as single line
            return [data], b"\n"

        lines = data.split(sep)
        # Keep trailing empty line indicator
        if data.endswith(sep):
            lines = lines[:-1]  # Remove the empty trailing element
        return lines, sep

    def _join_lines(self, lines: List[bytes], sep: bytes) -> bytes:
        """Join lines with separator."""
        if not lines:
            return b""
        return sep.join(lines) + (sep if lines else b"")

    def line_delete(self, data: bytes) -> bytes:
        """Delete random lines."""
        lines, sep = self._split_lines(data)
        if len(lines) < 2:
            return data

        # Delete 1-3 lines
        del_count = min(self.rng.randint(1, 3), len(lines) - 1)
        indices_to_delete = set(self.rng.sample(range(len(lines)), del_count))
        lines = [line for i, line in enumerate(lines) if i not in indices_to_delete]
        return self._join_lines(lines, sep)

    def line_duplicate(self, data: bytes) -> bytes:
        """Duplicate random lines."""
        lines, sep = self._split_lines(data)
        if not lines:
            return data

        # Duplicate 1-3 lines
        dup_count = min(self.rng.randint(1, 3), len(lines))
        for _ in range(dup_count):
            idx = self.rng.randint(0, len(lines) - 1)
            lines.insert(idx + 1, lines[idx])
        return self._join_lines(lines, sep)

    def line_clone(self, data: bytes) -> bytes:
        """Clone a line to a different position."""
        lines, sep = self._split_lines(data)
        if len(lines) < 2:
            return data

        src_idx = self.rng.randint(0, len(lines) - 1)
        dst_idx = self.rng.randint(0, len(lines))
        lines.insert(dst_idx, lines[src_idx])
        return self._join_lines(lines, sep)

    def line_repeat(self, data: bytes) -> bytes:
        """Repeat a line many times."""
        lines, sep = self._split_lines(data)
        if not lines:
            return data

        idx = self.rng.randint(0, len(lines) - 1)
        repeat_count = self.rng.randint(4, 32)
        repeated_line = lines[idx]
        lines[idx : idx + 1] = [repeated_line] * repeat_count
        return self._join_lines(lines, sep)

    def line_swap(self, data: bytes) -> bytes:
        """Swap two lines."""
        lines, sep = self._split_lines(data)
        if len(lines) < 2:
            return data

        idx1 = self.rng.randint(0, len(lines) - 1)
        idx2 = self.rng.randint(0, len(lines) - 1)
        if idx1 != idx2:
            lines[idx1], lines[idx2] = lines[idx2], lines[idx1]
        return self._join_lines(lines, sep)

    def line_permute(self, data: bytes) -> bytes:
        """Permute (shuffle) all lines."""
        lines, sep = self._split_lines(data)
        if len(lines) < 2:
            return data

        self.rng.shuffle(lines)
        return self._join_lines(lines, sep)

    def line_insert(self, data: bytes) -> bytes:
        """Insert a mutated copy of an existing line."""
        lines, sep = self._split_lines(data)
        if not lines:
            return data

        src_idx = self.rng.randint(0, len(lines) - 1)
        # Mutate the line slightly
        mutated_line = self.byte_flip(lines[src_idx])
        dst_idx = self.rng.randint(0, len(lines))
        lines.insert(dst_idx, mutated_line)
        return self._join_lines(lines, sep)

    def line_replace(self, data: bytes) -> bytes:
        """Replace a line with a mutated version of another line."""
        lines, sep = self._split_lines(data)
        if len(lines) < 2:
            return data

        src_idx = self.rng.randint(0, len(lines) - 1)
        dst_idx = self.rng.randint(0, len(lines) - 1)
        # Mutate the source line before replacing
        mutated_line = self.byte_random(lines[src_idx])
        lines[dst_idx] = mutated_line
        return self._join_lines(lines, sep)

    # =========================================================================
    # Fusion mutations
    # =========================================================================

    def fuse_self(self, data: bytes) -> bytes:
        """Fuse data with itself at aligned positions."""
        if len(data) < 8:
            return data

        # Find a position to fuse (try to align on common boundaries)
        quarter = len(data) // 4
        pos1 = self.rng.randint(quarter, quarter * 2)
        pos2 = self.rng.randint(quarter * 2, quarter * 3)

        # Take prefix from one position, suffix from another
        if self.rng.random() < 0.5:
            return data[:pos1] + data[pos2:]
        else:
            return data[:pos2] + data[pos1:]

    def fuse_samples(self, data: bytes) -> bytes:
        """Fuse data with a stored sample."""
        if not self._samples:
            # No samples available, fall back to self-fusion
            return self.fuse_self(data)

        other = self.rng.choice(self._samples)
        if len(other) < 4 or len(data) < 4:
            return data

        # Find fusion points
        pos1 = self.rng.randint(1, len(data) - 1)
        pos2 = self.rng.randint(1, len(other) - 1)

        # Fuse: prefix of data + suffix of other (or vice versa)
        if self.rng.random() < 0.5:
            return data[:pos1] + other[pos2:]
        else:
            return other[:pos2] + data[pos1:]

    # =========================================================================
    # Special mutations
    # =========================================================================

    def num_mutate(self, data: bytes) -> bytes:
        """Mutate numeric values found in data."""
        # Try to find and mutate numbers in the data
        # Pattern matches decimal and hex numbers
        pattern = rb"-?\d+|0x[0-9a-fA-F]+"

        matches = list(re.finditer(pattern, data))
        if not matches:
            # No numbers found, fall back to byte mutation
            return self.byte_flip(data)

        # Select a random number to mutate
        match = self.rng.choice(matches)
        start, end = match.span()
        num_str = match.group()

        # Parse and mutate the number
        try:
            if num_str.startswith(b"0x") or num_str.startswith(b"0X"):
                num = int(num_str, 16)
                # Mutate hex number
                mutations = [
                    num + 1,
                    num - 1,
                    num * 2,
                    num // 2,
                    num ^ 0xFF,
                    num ^ 0xFFFF,
                    0,
                    1,
                    -1,
                    0x7FFFFFFF,
                    0xFFFFFFFF,
                ]
                new_num = self.rng.choice(mutations)
                new_str = f"0x{new_num & 0xFFFFFFFF:x}".encode()
            else:
                num = int(num_str)
                # Mutate decimal number
                mutations = [
                    num + 1,
                    num - 1,
                    num * 2,
                    num // 2 if num else 0,
                    -num,
                    num ^ 0xFF,
                    0,
                    1,
                    -1,
                    127,
                    128,
                    255,
                    256,
                    32767,
                    32768,
                    65535,
                    2147483647,
                    -2147483648,
                ]
                new_num = self.rng.choice(mutations)
                new_str = str(new_num).encode()

            return data[:start] + new_str + data[end:]
        except (ValueError, OverflowError):
            return self.byte_flip(data)

    def interesting_bytes(self, data: bytes) -> bytes:
        """Insert or replace with interesting boundary values."""
        if not data:
            return data

        data = bytearray(data)
        pos = self.rng.randint(0, len(data) - 1)

        # Choose size: 1, 2, or 4 bytes
        size_choice = self.rng.randint(0, 2)

        if size_choice == 0:
            # 8-bit interesting value
            val = self.rng.choice(INTERESTING_8)
            data[pos] = val
        elif size_choice == 1 and pos + 1 < len(data):
            # 16-bit interesting value
            val = self.rng.choice(INTERESTING_16)
            # Random endianness
            if self.rng.random() < 0.5:
                data[pos : pos + 2] = struct.pack("<H", val & 0xFFFF)
            else:
                data[pos : pos + 2] = struct.pack(">H", val & 0xFFFF)
        elif size_choice == 2 and pos + 3 < len(data):
            # 32-bit interesting value
            val = self.rng.choice(INTERESTING_32)
            # Random endianness
            if self.rng.random() < 0.5:
                data[pos : pos + 4] = struct.pack("<I", val & 0xFFFFFFFF)
            else:
                data[pos : pos + 4] = struct.pack(">I", val & 0xFFFFFFFF)

        return bytes(data)

    def utf8_widen(self, data: bytes) -> bytes:
        """Widen ASCII characters to overlong UTF-8 sequences."""
        if not data:
            return data

        data = bytearray(data)
        # Find an ASCII character to widen
        ascii_positions = [i for i, b in enumerate(data) if 0x20 <= b <= 0x7E]
        if not ascii_positions:
            return bytes(data)

        pos = self.rng.choice(ascii_positions)
        char = data[pos]

        # Create overlong UTF-8 encoding (2-byte form of ASCII)
        # Format: 110xxxxx 10xxxxxx
        overlong = bytes([0xC0 | (char >> 6), 0x80 | (char & 0x3F)])

        # Sometimes use 3-byte overlong form
        if self.rng.random() < 0.3:
            # Format: 1110xxxx 10xxxxxx 10xxxxxx
            overlong = bytes([0xE0, 0x80 | (char >> 6), 0x80 | (char & 0x3F)])

        return bytes(data[:pos]) + overlong + bytes(data[pos + 1 :])

    def ascii_num_insert(self, data: bytes) -> bytes:
        """Insert ASCII number strings at random positions."""
        pos = self.rng.randint(0, len(data)) if data else 0
        num_str = self.rng.choice(ASCII_NUMBERS)
        return data[:pos] + num_str + data[pos:]

    def chunk_swap(self, data: bytes) -> bytes:
        """Swap two chunks of data."""
        if len(data) < 8:
            return data

        # Define chunk sizes (4-32 bytes)
        chunk_size = min(self.rng.randint(4, 32), len(data) // 3)

        # Find two non-overlapping positions
        max_pos = len(data) - chunk_size
        if max_pos < chunk_size:
            return data

        pos1 = self.rng.randint(0, max_pos - chunk_size)
        pos2 = self.rng.randint(pos1 + chunk_size, max_pos)

        chunk1 = data[pos1 : pos1 + chunk_size]
        chunk2 = data[pos2 : pos2 + chunk_size]

        # Swap the chunks
        result = bytearray(data)
        result[pos1 : pos1 + chunk_size] = chunk2
        result[pos2 : pos2 + chunk_size] = chunk1

        return bytes(result)

    # =========================================================================
    # Utility methods for targeted mutation selection
    # =========================================================================

    def get_mutation_names(self) -> List[str]:
        """Get names of all available mutations."""
        return [fn.__name__ for fn, _ in self._mutations]

    def apply_mutation(self, name: str, data: bytes) -> bytes:
        """Apply a specific mutation by name."""
        for fn, _ in self._mutations:
            if fn.__name__ == name:
                return fn(data)
        raise ValueError(f"Unknown mutation: {name}")


def get_native_mutator(seed: Optional[int] = None) -> NativeRadamsaMutator:
    """Factory function to create a native mutator instance."""
    return NativeRadamsaMutator(seed=seed)
