"""Protocol encoding/decoding layer for fuzzing.

This module provides protocol codecs for:
- ASN.1/BER encoding with fuzzing helpers
- MMS (IEC 61850) protocol encoding
- OPC UA binary encoding
"""

from .asn1 import (
    ASN1Tag,
    ASN1Builder,
)
from .mms import MMSCodec
from .opcua import (
    NodeIdType,
    VariantType,
    NodeId,
    OPCUACodec,
)

__all__ = [
    # ASN.1
    "ASN1Tag",
    "ASN1Builder",
    # MMS
    "MMSCodec",
    # OPC UA
    "NodeIdType",
    "VariantType",
    "NodeId",
    "OPCUACodec",
]
