"""
BACnet Protocol Constants and Lazy Import Helpers

Contains BACnet object types, vendor IDs, control point types,
and lazy import infrastructure for BAC0/bacpypes3 libraries.
"""

import logging
import os
from typing import Any, Dict

from ...utils.lazy_import import lazy_import

# Suppress BAC0/bacpypes3 verbose logging BEFORE import
os.environ["BAC0_VERBOSE"] = "0"
os.environ["BAC0_LOG_LEVEL"] = "silence"
for _logger_name in [
    "BAC0",
    "bacpypes3",
    "BAC0.scripts",
    "BAC0.core",
    "BAC0.tasks",
    "bacpypes3.ipv4",
    "BAC0.core.app",
    "BAC0.scripts.Lite",
    "BAC0.scripts.Base",
]:
    logging.getLogger(_logger_name).setLevel(logging.CRITICAL)

# Lazy import for BAC0 - only loads when actually used
_bac0 = lazy_import("BAC0", "BACnet")

# Module state container (avoids global keyword)
_bac0_state = {"silenced": False, "available": None}


def _is_bac0_available() -> bool:
    """Check if BAC0 is available, caching the result."""
    if _bac0_state["available"] is None:
        _bac0_state["available"] = _bac0.is_available
    return _bac0_state["available"]


def _get_bac0():
    """Get BAC0 module, raising DependencyError if not available."""
    module = _bac0()
    if not _bac0_state["silenced"]:
        module.log_level("silence")
        _bac0_state["silenced"] = True
    return module


# Lazy import cache for bacpypes3 types - deferred until first use
_bp: Dict[str, Any] = {}


def _load_bacpypes3() -> Dict[str, Any]:
    """Lazily load bacpypes3 types on first use.

    Returns cached dict of bacpypes3 types. This delays the ~0.5s import
    until the scanner is actually used, speeding up CLI startup.
    """
    if _bp:
        return _bp

    # Import all required bacpypes3 types
    from bacpypes3.ipv4.app import NormalApplication
    from bacpypes3.local.device import DeviceObject
    from bacpypes3.pdu import Address, GlobalBroadcast
    from bacpypes3.primitivedata import (
        ObjectIdentifier,
        CharacterString,
        Unsigned,
        Real,
    )
    from bacpypes3.apdu import (
        AbortPDU,
        ErrorPDU,
        RejectPDU,
        Error,
        ReadPropertyRequest,
        ReadPropertyMultipleRequest,
        WritePropertyRequest,
        SubscribeCOVRequest,
        AtomicReadFileRequest,
        TimeSynchronizationRequest,
        DeviceCommunicationControlRequest,
        ReinitializeDeviceRequest,
        WhoHasRequest,
        WhoIsRequest,
    )
    from bacpypes3.basetypes import (
        DeviceStatus,
        PropertyIdentifier,
        Segmentation,
        DeviceCommunicationControlRequestEnableDisable,
        ReinitializeDeviceRequestReinitializedStateOfDevice,
        ReadAccessSpecification,
        PropertyReference,
    )
    from bacpypes3.constructeddata import AnyAtomic
    from bacpypes3.ipv4.bvll import (
        ReadBroadcastDistributionTable,
        ReadForeignDeviceTable,
        WriteBroadcastDistributionTable,
        RegisterForeignDevice,
    )
    from bacpypes3.npdu import WhoIsRouterToNetwork

    # Cache all types
    _bp.update(
        {
            "NormalApplication": NormalApplication,
            "DeviceObject": DeviceObject,
            "DeviceStatus": DeviceStatus,
            "PropertyIdentifier": PropertyIdentifier,
            "Segmentation": Segmentation,
            "DeviceCommunicationControlRequestEnableDisable": DeviceCommunicationControlRequestEnableDisable,
            "ReinitializeDeviceRequestReinitializedStateOfDevice": ReinitializeDeviceRequestReinitializedStateOfDevice,
            "ReadAccessSpecification": ReadAccessSpecification,
            "PropertyReference": PropertyReference,
            "AnyAtomic": AnyAtomic,
            "Address": Address,
            "GlobalBroadcast": GlobalBroadcast,
            "ObjectIdentifier": ObjectIdentifier,
            "CharacterString": CharacterString,
            "Unsigned": Unsigned,
            "Real": Real,
            "AbortPDU": AbortPDU,
            "ErrorPDU": ErrorPDU,
            "RejectPDU": RejectPDU,
            "Error": Error,
            "ReadPropertyRequest": ReadPropertyRequest,
            "ReadPropertyMultipleRequest": ReadPropertyMultipleRequest,
            "WritePropertyRequest": WritePropertyRequest,
            "SubscribeCOVRequest": SubscribeCOVRequest,
            "AtomicReadFileRequest": AtomicReadFileRequest,
            "TimeSynchronizationRequest": TimeSynchronizationRequest,
            "DeviceCommunicationControlRequest": DeviceCommunicationControlRequest,
            "ReinitializeDeviceRequest": ReinitializeDeviceRequest,
            "WhoHasRequest": WhoHasRequest,
            "WhoIsRequest": WhoIsRequest,
            "ReadBroadcastDistributionTable": ReadBroadcastDistributionTable,
            "ReadForeignDeviceTable": ReadForeignDeviceTable,
            "WriteBroadcastDistributionTable": WriteBroadcastDistributionTable,
            "RegisterForeignDevice": RegisterForeignDevice,
            "WhoIsRouterToNetwork": WhoIsRouterToNetwork,
        }
    )

    return _bp


def bp(name: str) -> Any:
    """Get a bacpypes3 type by name. Triggers lazy import on first call."""
    types = _load_bacpypes3()
    return types[name]


def _ensure_bacpypes3_globals():
    """Load bacpypes3 types and make them available as module globals.

    Called once at the start of proto_flow() to ensure all types are
    available for the scanner methods without changing 100+ lines.
    """
    types = _load_bacpypes3()
    # Inject into module globals for use in class methods
    g = globals()
    for name, cls in types.items():
        g[name] = cls


# BACnet Object Type Constants
OBJECT_TYPES = {
    0: "analogInput",
    1: "analogOutput",
    2: "analogValue",
    3: "binaryInput",
    4: "binaryOutput",
    5: "binaryValue",
    6: "calendar",
    7: "command",
    8: "device",
    9: "eventEnrollment",
    10: "file",
    11: "group",
    12: "loop",
    13: "multiStateInput",
    14: "multiStateOutput",
    15: "notificationClass",
    16: "program",
    17: "schedule",
    18: "averaging",
    19: "multiStateValue",
    20: "trendLog",
    21: "lifeSafetyPoint",
    22: "lifeSafetyZone",
    23: "accumulator",
    24: "pulseConverter",
    25: "eventLog",
    26: "globalGroup",
    27: "trendLogMultiple",
    28: "loadControl",
    29: "structuredView",
    30: "accessDoor",
    31: "timer",
    32: "accessCredential",
    33: "accessPoint",
    34: "accessRights",
    35: "accessUser",
    36: "accessZone",
    37: "credentialDataInput",
    38: "networkSecurity",
    39: "bitstringValue",
    40: "characterstringValue",
    41: "datePatternValue",
    42: "dateValue",
    43: "datetimePatternValue",
    44: "datetimeValue",
    45: "integerValue",
    46: "largeAnalogValue",
    47: "octetstringValue",
    48: "positiveIntegerValue",
    49: "timePatternValue",
    50: "timeValue",
    51: "notificationForwarder",
    52: "alertEnrollment",
    53: "channel",
    54: "lightingOutput",
    55: "binaryLightingOutput",
    56: "networkPort",
    57: "elevatorGroup",
    58: "escalator",
    59: "lift",
}

# Reverse mapping for lookups
OBJECT_TYPE_NAMES = {v: k for k, v in OBJECT_TYPES.items()}

# Shorthand aliases for object types (case-insensitive lookup)
OBJECT_TYPE_ALIASES = {
    "ai": "analogInput",
    "ao": "analogOutput",
    "av": "analogValue",
    "bi": "binaryInput",
    "bo": "binaryOutput",
    "bv": "binaryValue",
    "mi": "multiStateInput",
    "mo": "multiStateOutput",
    "mv": "multiStateValue",
    "dev": "device",
    "sch": "schedule",
    "cal": "calendar",
    "tl": "trendLog",
    "nc": "notificationClass",
    "lsp": "lifeSafetyPoint",
    "lsz": "lifeSafetyZone",
    "np": "networkPort",
    "sv": "structuredView",
    "prg": "program",
    "lp": "loop",
}

# Shorthand aliases for property identifiers (case-insensitive lookup)
PROPERTY_ALIASES = {
    "pv": "presentValue",
    "sf": "statusFlags",
    "oos": "outOfService",
    "desc": "description",
    "name": "objectName",
    "rel": "reliability",
    "es": "eventState",
    "pa": "priorityArray",
    "rd": "relinquishDefault",
    "cov": "covIncrement",
    "units": "units",
    "hi": "highLimit",
    "lo": "lowLimit",
    "res": "resolution",
    "sp": "setpoint",
    "type": "objectType",
    "id": "objectIdentifier",
}


def resolve_object_type(raw: str) -> str:
    """Resolve an object type alias or shorthand to its canonical BACnet name."""
    lower = raw.lower()
    if lower in OBJECT_TYPE_ALIASES:
        return OBJECT_TYPE_ALIASES[lower]
    if lower in OBJECT_TYPE_NAMES:
        return lower
    return raw


def resolve_property_name(raw: str) -> str:
    """Resolve a property alias or shorthand to its canonical BACnet name."""
    lower = raw.lower()
    if lower in PROPERTY_ALIASES:
        return PROPERTY_ALIASES[lower]
    return raw


# Control point object types (for --control-points filter)
CONTROL_POINT_TYPES = {
    "analogInput",
    "analogOutput",
    "analogValue",
    "binaryInput",
    "binaryOutput",
    "binaryValue",
    "multiStateInput",
    "multiStateOutput",
    "multiStateValue",
}

# BACnet priority levels (1=highest, 16=lowest)
BACNET_PRIORITY_LEVELS = {
    1: "Manual-Life Safety",
    2: "Automatic-Life Safety",
    3: "Available 3",
    4: "Available 4",
    5: "Critical Equipment Control",
    6: "Minimum On/Off",
    7: "Available 7",
    8: "Manual Operator",
    9: "Available 9",
    10: "Available 10",
    11: "Available 11",
    12: "Available 12",
    13: "Available 13",
    14: "Available 14",
    15: "Available 15",
    16: "Available 16 (lowest / default write)",
}

# BACnet Vendor IDs
VENDORS = {
    0: "ASHRAE",
    1: "NIST",
    2: "The Trane Company",
    3: "McQuay International",
    4: "Honeywell",
    5: "Johnson Controls",
    6: "Honeywell",
    7: "Siemens Building Technologies",
    8: "Delta Controls Inc.",
    9: "Automated Logic Corporation",
    10: "Carrier Corporation",
    15: "TAC",
    24: "Alerton Technologies",
    36: "ICONICS",
    55: "Novar",
    75: "Reliable Controls",
    78: "LOYTEC electronics",
    84: "Cimetrics",
    85: "Echelon Corporation",
    89: "Tridium",
    132: "Distech Controls",
    175: "KMC Controls",
    183: "Cylon Controls",
    222: "Schneider Electric",
    326: "Lutron Electronics",
    343: "Daikin Industries",
    381: "ABB",
    478: "Mitsubishi Electric",
}
