"""CoAP (Constrained Application Protocol) scanner.

Provides scanning and security testing for CoAP IoT/ICS devices
with LwM2M fingerprinting support.
"""

# Re-export from scanner module
from oida.protocols.coap.scanner import CoAPScanner

# Re-export from helpers module
from oida.protocols.coap.helpers import (  # noqa: F401 - re-exported
    is_aiocoap_available,
    parse_link_format,
    parse_payload,
    coap_ping,
    coap_request,
    coap_get_blockwise,
    try_dtls_psk,
    try_dtls_cert,
    try_dtls_rpk,
    run_async,
)

# Re-export from constants module
from oida.protocols.coap.constants import (  # noqa: F401 - re-exported
    BLOCK_SIZES,
    CONTENT_FORMATS,
    CONTENT_FORMAT_ALIASES,
    DEFAULT_PORT,
    DEFAULT_DTLS_PORT,
    LWM2M_OBJECTS,
    COMMON_PATHS,
    VALID_BLOCK_SIZES,
    protocol_options,
)

# NXC-style callable class
from oida.protocols.coap.cli_runner import coap  # noqa: F401

__all__ = [
    # Scanner
    "CoAPScanner",
    "coap",
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
