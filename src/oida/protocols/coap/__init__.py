"""CoAP (Constrained Application Protocol) scanner.

Provides scanning and security testing for CoAP IoT/ICS devices
with LwM2M fingerprinting support.
"""

# Re-export from scanner module
from .scanner import (
    CoAPScanner,
    metadata,
    run,
)

# Re-export from helpers module
from .helpers import (
    is_aiocoap_available,
    parse_link_format,
    parse_payload,
    coap_ping,
    coap_request,  # noqa: F401
    coap_get_blockwise,
    coap_put_blockwise,
    try_dtls_psk,
    try_dtls_cert,
    try_dtls_rpk,
    run_async,
)

# Re-export from constants module
from .constants import (
    BLOCK_SIZES,
    CONTENT_FORMATS,
    CONTENT_FORMAT_ALIASES,  # noqa: F401
    DEFAULT_PORT,
    DEFAULT_DTLS_PORT,
    LWM2M_OBJECTS,
    COMMON_PATHS,
    VALID_BLOCK_SIZES,
    protocol_options,
)

# Lazy import reference for dependency checking
from ...utils.lazy_import import lazy_import

_aiocoap = lazy_import("aiocoap", "CoAP")
_dtlssocket = lazy_import("DTLSSocket", "CoAP", install_hint="pip install DTLSSocket")

# Flag to indicate if dependencies are missing (for tests to mock)
dependencies_missing = not _aiocoap.is_available

# NXC-style callable class
from .nxc_connection import coap  # noqa: E402, F401

__all__ = [
    # Scanner
    "CoAPScanner",
    "coap",
    "metadata",
    "run",
    "protocol_options",
    # Helpers
    "is_aiocoap_available",
    "parse_link_format",
    "parse_payload",
    "coap_ping",
    "coap_get_blockwise",
    "coap_put_blockwise",
    "try_dtls_psk",
    "try_dtls_cert",
    "try_dtls_rpk",
    "run_async",
    # Constants
    "BLOCK_SIZES",
    "CONTENT_FORMATS",
    "DEFAULT_PORT",
    "DEFAULT_DTLS_PORT",
    "LWM2M_OBJECTS",
    "COMMON_PATHS",
    "VALID_BLOCK_SIZES",
]
