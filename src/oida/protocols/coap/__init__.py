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

# NXC-style callable class
from .cli_runner import coap  # noqa: F401

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
