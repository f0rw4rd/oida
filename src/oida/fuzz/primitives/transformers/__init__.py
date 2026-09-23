"""
OIDA Fuzzer Transformers

This module provides data transformation capabilities for protocol fuzzing.
Transformers encode/decode data before fuzzing, enabling proper mutation of
encoded content (Base64, URL encoding, JWT tokens, compression, etc.)

Architecture:
    Transformers integrate with boofuzz at the Block level using the encoder
    parameter. Mutations are applied first, then transformers encode the
    mutated data before sending to the target.

Module Structure:
    - base: BaseTransformer abstract class and TransformerChain
    - encoding: Base64, URL, Hex, HTML, JSON, XML encoding
    - authentication: Basic Auth, Bearer, JWT, Digest (coming soon)
    - compression: Gzip, Deflate, Brotli (coming soon)
    - transfer: Chunked, Multipart (coming soon)

Quick Start:
    >>> from oida.fuzz.primitives.transformers import Base64Transformer
    >>> from boofuzz import Block, SmartString, Delim
    >>>
    >>> # Create transformer
    >>> auth = Base64Transformer(prefix=b"Basic ")
    >>>
    >>> # Use with boofuzz Block
    >>> block = Block("authorization", encoder=auth.to_encoder_func(), children=(
    ...     SmartString("username", "admin"),
    ...     Delim(":", ":"),
    ...     SmartString("password", "password123"),
    ... ))
    >>>
    >>> # Result: "Basic YWRtaW46cGFzc3dvcmQxMjM="

Example - Transformer Chain:
    >>> from oida.fuzz.primitives.transformers import TransformerChain
    >>> from oida.fuzz.primitives.transformers import GzipTransformer, Base64Transformer
    >>>
    >>> # Chain multiple transformers: gzip -> base64
    >>> chain = TransformerChain(
    ...     GzipTransformer(level=9),
    ...     Base64Transformer()
    ... )
    >>>
    >>> block = Block("payload", encoder=chain.to_encoder_func(), ...)

All transformers are:
    - Stateless (no mutable state)
    - Thread-safe (can be shared across fuzzing sessions)
    - Bidirectional (support encode and decode)
    - Composable (can be chained together)
"""

__version__ = "1.0.0"
__author__ = "f0rw4rd"

# Base classes
from oida.fuzz.primitives.transformers.base import BaseTransformer, TransformerChain

# Encoding transformers
from oida.fuzz.primitives.transformers.encoding import (
    Base64Transformer,
    URLEncodeTransformer,
    HexTransformer,
    HTMLEntityTransformer,
    JSONEscapeTransformer,
    XMLEscapeTransformer,
)

# Authentication transformers
from oida.fuzz.primitives.transformers.authentication import (
    BasicAuthTransformer,
    BearerTokenTransformer,
    JWTTransformer,
    DigestAuthTransformer,
)

# Compression transformers
from oida.fuzz.primitives.transformers.compression import (
    GzipTransformer,
    DeflateTransformer,
    BrotliTransformer,
    IdentityTransformer,
)

# Export all
__all__ = [
    # Base classes
    "BaseTransformer",
    "TransformerChain",
    # Encoding
    "Base64Transformer",
    "URLEncodeTransformer",
    "HexTransformer",
    "HTMLEntityTransformer",
    "JSONEscapeTransformer",
    "XMLEscapeTransformer",
    # Authentication
    "BasicAuthTransformer",
    "BearerTokenTransformer",
    "JWTTransformer",
    "DigestAuthTransformer",
    # Compression
    "GzipTransformer",
    "DeflateTransformer",
    "BrotliTransformer",
    "IdentityTransformer",
]


# Future imports (placeholder for documentation)
# from .transfer import (  # Coming soon
#     ChunkedTransferTransformer,
#     MultipartFormTransformer,
# )
