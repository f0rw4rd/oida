"""
Base Transformer Classes

This module provides the abstract base class and utilities for implementing
data transformers in OIDA fuzzer. Transformers encode/decode data before
fuzzing, enabling proper mutation of encoded content (Base64, URL encoding, etc.)

Architecture:
    Transformers integrate with boofuzz at the Block level using the encoder
    parameter. The mutation happens first, then the transformer encodes the
    mutated data before sending to the target.

Thread Safety:
    All transformers are stateless and thread-safe. They can be shared across
    multiple fuzzing sessions.

Example:
    >>> from oida.fuzz.primitives.transformers import Base64Transformer
    >>> transformer = Base64Transformer()
    >>>
    >>> # Use with boofuzz Block
    >>> Block("auth", encoder=transformer.to_encoder_func(), children=(
    ...     SmartString("username", "admin"),
    ...     Delim(":", ":"),
    ...     SmartString("password", "password123"),
    ... ))
"""

from abc import ABC, abstractmethod
from typing import Callable

from ....utils.ics_logger import get_logger

_log = get_logger("TRANSFORM", "base", 0)


class BaseTransformer(ABC):
    """
    Abstract base class for all transformers.

    Transformers provide bidirectional encoding/decoding of data. The encode()
    method is called by boofuzz before sending data to the target. The decode()
    method is used for checksum validation and testing.

    All transformers must be:
    - Stateless (no mutable instance variables)
    - Thread-safe (can be used concurrently)
    - Deterministic (same input = same output)

    Attributes:
        name: Human-readable transformer name for logging
    """

    @abstractmethod
    def encode(self, data: bytes) -> bytes:
        """
        Transform data before sending to target.

        This method is called by boofuzz after all mutations are applied.
        It should transform the data into the required encoding format.

        Args:
            data: Raw bytes to encode

        Returns:
            Encoded bytes ready to send to target

        Raises:
            ValueError: If data cannot be encoded
        """

    @abstractmethod
    def decode(self, data: bytes) -> bytes:
        """
        Reverse the transformation (decoding).

        This method is used for:
        - Checksum validation
        - Round-trip testing
        - Response parsing

        Args:
            data: Encoded bytes to decode

        Returns:
            Decoded raw bytes

        Raises:
            ValueError: If data cannot be decoded
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Human-readable transformer name.

        Used for logging and debugging. Should be concise and descriptive.

        Returns:
            Transformer name (e.g., "Base64", "Gzip-9", "JWT-HS256")
        """

    def to_encoder_func(self) -> Callable[[bytes], bytes]:
        """
        Convert transformer to boofuzz-compatible encoder function.

        boofuzz Block primitives accept an encoder parameter which must be
        a callable that takes bytes and returns bytes. This method wraps
        the transformer's encode() method for boofuzz integration.

        Returns:
            Callable encoder function for use with boofuzz Block

        Example:
            >>> transformer = Base64Transformer()
            >>> block = Block("data", encoder=transformer.to_encoder_func(), ...)
        """

        def encoder(x):
            # Handle both bytes and str input (boofuzz may pass either)
            if isinstance(x, str):
                x = x.encode("utf-8", errors="replace")
            elif not isinstance(x, bytes):
                x = bytes(x)

            try:
                encoded = self.encode(x)
                _log.debug(f"{self.name} encoded {len(x)} bytes -> {len(encoded)} bytes")
                return encoded
            except Exception as e:
                _log.fail(f"{self.name} encoding failed: {e}")
                # On error, return original data to avoid blocking fuzzing
                return x

        return encoder

    def __repr__(self) -> str:
        """String representation for debugging"""
        return f"<{self.__class__.__name__}: {self.name}>"


class TransformerChain:
    """
    Chain multiple transformers together.

    Transformers are applied in the order they are added to the chain.
    For example, a chain of [Gzip, Base64] will first compress the data
    with gzip, then Base64-encode the compressed result.

    Decoding happens in reverse order (Base64 decode -> Gzip decompress).

    The chain is also stateless and thread-safe.

    Example:
        >>> from oida.fuzz.primitives.transformers import TransformerChain
        >>> from oida.fuzz.primitives.transformers import GzipTransformer, Base64Transformer
        >>>
        >>> # Create chain: gzip then base64
        >>> chain = TransformerChain(
        ...     GzipTransformer(level=9),
        ...     Base64Transformer()
        ... )
        >>>
        >>> # Use with boofuzz
        >>> block = Block("payload", encoder=chain.to_encoder_func(), ...)
    """

    def __init__(self, *transformers: BaseTransformer):
        """
        Initialize transformer chain.

        Args:
            *transformers: Transformers to chain (applied in order)

        Raises:
            ValueError: If no transformers provided or invalid transformer
        """
        if not transformers:
            raise ValueError("TransformerChain requires at least one transformer")

        for transformer in transformers:
            if not isinstance(transformer, BaseTransformer):
                raise ValueError(f"Expected BaseTransformer, got {type(transformer)}")

        self.transformers = list(transformers)

    def encode(self, data: bytes) -> bytes:
        """
        Apply all transformers in order.

        Args:
            data: Raw bytes to encode

        Returns:
            Encoded bytes after all transformations

        Raises:
            ValueError: If any transformer fails
        """
        for transformer in self.transformers:
            data = transformer.encode(data)
        return data

    def decode(self, data: bytes) -> bytes:
        """
        Apply all transformers in reverse order.

        Args:
            data: Encoded bytes to decode

        Returns:
            Decoded raw bytes after all reverse transformations

        Raises:
            ValueError: If any transformer fails
        """
        for transformer in reversed(self.transformers):
            data = transformer.decode(data)
        return data

    def to_encoder_func(self) -> Callable[[bytes], bytes]:
        """
        Convert chain to boofuzz-compatible encoder function.

        Returns:
            Callable encoder function for use with boofuzz Block

        Example:
            >>> chain = TransformerChain(Gzip(), Base64())
            >>> block = Block("data", encoder=chain.to_encoder_func(), ...)
        """

        def encoder(x):
            # Handle both bytes and str input
            if isinstance(x, str):
                x = x.encode("utf-8", errors="replace")
            elif not isinstance(x, bytes):
                x = bytes(x)

            try:
                encoded = self.encode(x)
                _log.debug(f"TransformerChain encoded {len(x)} bytes -> {len(encoded)} bytes")
                return encoded
            except Exception as e:
                _log.fail(f"TransformerChain encoding failed: {e}")
                return x

        return encoder

    @property
    def name(self) -> str:
        """Chain name composed of all transformer names"""
        return " -> ".join(t.name for t in self.transformers)

    def __repr__(self) -> str:
        """String representation for debugging"""
        names = ", ".join(t.name for t in self.transformers)
        return f"<TransformerChain: [{names}]>"
