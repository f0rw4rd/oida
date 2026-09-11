#!/usr/bin/env python3
"""
TCP Data_Offset Custom Primitive for OIDA fuzzer

This module provides a custom primitive for dynamically calculating the TCP
Data_Offset field, which specifies the TCP header length in 32-bit words.

The Data_Offset field is 4 bits and shares a byte with 3 reserved bits and
the NS (ECN-nonce) flag. This primitive calculates the correct header length
based on the size of the TCP options block.
"""

from boofuzz import Fuzzable


class TCPDataOffsetByte(Fuzzable):
    """
    Custom primitive that dynamically calculates TCP Data_Offset field
    and combines it with Reserved bits and NS flag into a single byte.

    TCP Data_Offset byte structure (8 bits):
      Bits 0-3:  Data_Offset (header length in 32-bit words, range 5-15)
      Bits 4-6:  Reserved (should be 0)
      Bit 7:     NS flag (ECN-nonce)

    The Data_Offset value represents the TCP header size in 32-bit words:
      - Minimum: 5 words = 20 bytes (no options)
      - Maximum: 15 words = 60 bytes (40 bytes of options)

    Args:
        options_block_name: Name of the block containing TCP options
        ns_flag: NS flag value (0 or 1)
        reserved: Reserved bits value (0-7, typically 0)
        fuzzable: Whether this field should be fuzzed
        name: Name for this primitive
    """

    def __init__(self, options_block_name, ns_flag=0, reserved=0, fuzzable=True, name=None):
        super().__init__(name=name, default_value=None, fuzzable=fuzzable)
        self.options_block_name = options_block_name
        self.ns_flag = ns_flag & 0x01  # Ensure 1 bit
        self.reserved = reserved & 0x07  # Ensure 3 bits
        self._options_size_cache = None

    def encode(self, value=None, mutation_context=None):
        """
        Render this primitive.

        boofuzz's ``Fuzzable.render()`` calls
        ``encode(value=self.get_value(mutation_context), ...)``, so ``value``
        carries the mutation produced by :meth:`mutations` whenever this node is
        the one being fuzzed. It must be honoured, otherwise every declared
        mutation renders as the same calculated byte and the field is never
        actually fuzzed.

        When ``value`` is ``None`` the field is not being mutated and the byte
        is calculated from the current size of the options block.

        Returns:
            bytes: Single byte containing Data_Offset + Reserved + NS flag
        """
        if value is not None:
            # mutations() yields single-byte ``bytes`` objects; tolerate a raw
            # int as well so the primitive also works with fuzz_values=[...].
            if isinstance(value, int):
                return bytes([value & 0xFF])
            return bytes(value)

        # Invalidate cache so we recalculate from the current options block
        self._options_size_cache = None

        # Calculate options size
        options_size = self._get_options_size()

        # Base TCP header is always 20 bytes (up to Data_Offset field)
        base_header_size = 20
        total_header_size = base_header_size + options_size

        # Convert bytes to 32-bit words (round up)
        # Formula: (size + 3) // 4 ensures rounding up
        data_offset = (total_header_size + 3) // 4

        # Clamp to valid range (5-15 words)
        data_offset = max(5, min(15, data_offset))

        # Combine fields into single byte
        # Bit layout: DDDD RRRN
        # D = Data_Offset (4 bits, upper nibble)
        # R = Reserved (3 bits)
        # N = NS flag (1 bit, least significant)
        byte_value = (data_offset << 4) | (self.reserved << 1) | self.ns_flag

        return bytes([byte_value])

    def _get_options_size(self):
        """
        Calculate the size of the TCP options block.

        Returns:
            int: Size of options block in bytes, or 0 if not found
        """
        if self._options_size_cache is not None:
            return self._options_size_cache

        options_block = self._find_options_block()

        if options_block:
            # Render the options block to get its size
            try:
                rendered = options_block.render()
                self._options_size_cache = len(rendered)
                return self._options_size_cache
            except Exception:
                # If rendering fails, assume no options
                return 0

        return 0

    def _find_options_block(self):
        """
        Locate the TCP options block in the request tree.

        This method navigates the boofuzz request tree to find the named
        options block, similar to how the Size primitive works.

        Returns:
            Block: The options block if found, None otherwise
        """
        # Check if we're attached to a request
        if not hasattr(self, "_request") or self._request is None:
            return None

        # boofuzz keys ``request.names`` by *qualified* name ("request.block"),
        # not by the bare name, so a bare lookup silently misses. Try the
        # qualified key first, then fall back to a recursive walk of the tree.
        names = getattr(self._request, "names", None)
        if names:
            qualified = f"{self._request.name}.{self.options_block_name}"
            block = names.get(qualified) or names.get(self.options_block_name)
            if block is not None:
                return block

        return self._find_block_recursive(self._request, self.options_block_name)

    def _find_block_recursive(self, node, target_name):
        """
        Recursively search for a named block in the request tree.

        Args:
            node: Current node to search
            target_name: Name of block to find

        Returns:
            Block: The block if found, None otherwise
        """
        # Check if this node is the target
        if hasattr(node, "name") and node.name == target_name:
            return node

        # Recursively search children
        if hasattr(node, "stack"):
            for child in node.stack:
                result = self._find_block_recursive(child, target_name)
                if result:
                    return result

        return None

    def num_mutations(self, default_value=None):
        """
        Return the number of mutations for fuzzing.

        Args:
            default_value: Default value (unused, for API compatibility)

        Returns:
            int: Number of mutation cases
        """
        if not self.fuzzable:
            return 0

        return 25  # 11 offsets + 4 boundaries + 7 reserved + 3 NS flag

    def mutations(self, default_value=None):
        """
        Generate mutations for fuzzing the Data_Offset byte.

        Args:
            default_value: Default value (unused, for API compatibility)

        Yields:
            bytes: Mutated byte values
        """
        # Yield various Data_Offset values (5-15 words)
        for offset in range(5, 16):
            # Test with normal reserved/NS values
            byte_value = (offset << 4) | (0 << 1) | 0
            yield bytes([byte_value])

        # Yield boundary cases
        yield bytes([0x50])  # 5 words, no options (minimum)
        yield bytes([0xF0])  # 15 words, maximum options
        yield bytes([0x00])  # Invalid: 0 words
        yield bytes([0xFF])  # Invalid: all bits set

        # Yield cases with reserved bits set (protocol violations)
        for reserved in range(1, 8):
            byte_value = (5 << 4) | (reserved << 1) | 0
            yield bytes([byte_value])

        # Yield cases with NS flag set
        for offset in [5, 10, 15]:
            byte_value = (offset << 4) | (0 << 1) | 1
            yield bytes([byte_value])

    def __repr__(self):
        """String representation of this primitive."""
        return (
            f"TCPDataOffsetByte(options_block='{self.options_block_name}', "
            f"ns={self.ns_flag}, reserved={self.reserved}, "
            f"fuzzable={self.fuzzable})"
        )

    def __len__(self):
        """Return the size of this primitive in bytes."""
        return 1


__all__ = ["TCPDataOffsetByte"]
