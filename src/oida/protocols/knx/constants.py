"""KNX protocol constants and configuration."""

import threading
from typing import Dict, Any

# Protocol defaults
DEFAULT_PORT = 3671
DEFAULT_MULTICAST = "224.0.23.12"

# Safety limits
MAX_BUS_ADDRESSES = 10000
MAX_KEY_RANGE = 100000

# Lazy import reference for dependency checking
from oida.utils.lazy_import import lazy_import

_xknx = lazy_import("xknx", "KNX")

# Thread-safe initialization lock for lazy loading xknx classes.
# Uses double-checked locking pattern to ensure thread-safety while avoiding
# import overhead until first use. All classes are loaded atomically.
_xknx_init_lock = threading.Lock()


# Namespace class for lazily-loaded xknx classes.
# Populated by _ensure_xknx_classes() on first use.
class _xknx_cls:
    loaded = False
    # Core classes
    XKNX = None
    ConnectionConfig = None
    ConnectionType = None
    GatewayScanner = None
    IndividualAddress = None
    Telegram = None
    GroupAddress = None
    nm_individual_address_check = None
    dm_restart = None
    # APCI classes
    DPTArray = None
    MemoryRead = None
    MemoryWrite = None
    MemoryResponse = None
    UserMemoryRead = None
    UserMemoryResponse = None
    DeviceDescriptorRead = None
    DeviceDescriptorResponse = None
    PropertyValueRead = None
    PropertyValueWrite = None
    PropertyValueResponse = None
    PropertyDescriptionRead = None
    PropertyDescriptionResponse = None
    ADCRead = None
    ADCResponse = None
    GroupValueWrite = None
    AuthorizeRequest = None
    AuthorizeResponse = None
    IndividualAddressSerialRead = None
    IndividualAddressSerialResponse = None
    MemoryExtendedRead = None
    MemoryExtendedReadResponse = None


def _ensure_xknx_classes():
    """Ensure xknx classes are loaded into _xknx_cls namespace (thread-safe)."""
    from oida.protocols.knx.helpers import (
        _get_xknx,
        _get_xknx_classes,
        _get_apci_classes,
        _get_memory_extended,
    )

    # Double-checked locking pattern for thread safety
    if _xknx_cls.loaded:
        return  # Already loaded

    with _xknx_init_lock:
        if _xknx_cls.loaded:
            return  # Already loaded by another thread

        # Get core classes from helpers (tpci is unpacked elsewhere directly)
        (
            _xknx_cls.XKNX,
            _xknx_cls.ConnectionConfig,
            _xknx_cls.ConnectionType,
            _xknx_cls.GatewayScanner,
            _xknx_cls.IndividualAddress,
            _xknx_cls.Telegram,
            _xknx_cls.GroupAddress,
            _,
        ) = _get_xknx_classes()

        # Get management procedures
        _get_xknx()
        from xknx.management.procedures import (
            nm_individual_address_check as _nm_check,
            dm_restart as _dm_restart,
        )

        _xknx_cls.nm_individual_address_check = _nm_check
        _xknx_cls.dm_restart = _dm_restart

        # Get APCI classes
        apci = _get_apci_classes()
        _xknx_cls.DPTArray = apci["DPTArray"]
        _xknx_cls.MemoryRead = apci["MemoryRead"]
        _xknx_cls.MemoryWrite = apci["MemoryWrite"]
        _xknx_cls.MemoryResponse = apci["MemoryResponse"]
        _xknx_cls.UserMemoryRead = apci["UserMemoryRead"]
        _xknx_cls.UserMemoryResponse = apci["UserMemoryResponse"]
        _xknx_cls.DeviceDescriptorRead = apci["DeviceDescriptorRead"]
        _xknx_cls.DeviceDescriptorResponse = apci["DeviceDescriptorResponse"]
        _xknx_cls.PropertyValueRead = apci["PropertyValueRead"]
        _xknx_cls.PropertyValueWrite = apci["PropertyValueWrite"]
        _xknx_cls.PropertyValueResponse = apci["PropertyValueResponse"]
        _xknx_cls.PropertyDescriptionRead = apci["PropertyDescriptionRead"]
        _xknx_cls.PropertyDescriptionResponse = apci["PropertyDescriptionResponse"]
        _xknx_cls.ADCRead = apci["ADCRead"]
        _xknx_cls.ADCResponse = apci["ADCResponse"]
        _xknx_cls.GroupValueWrite = apci["GroupValueWrite"]
        _xknx_cls.AuthorizeRequest = apci["AuthorizeRequest"]
        _xknx_cls.AuthorizeResponse = apci["AuthorizeResponse"]
        _xknx_cls.KeyWrite = apci["KeyWrite"]
        _xknx_cls.KeyResponse = apci["KeyResponse"]
        _xknx_cls.IndividualAddressSerialRead = apci["IndividualAddressSerialRead"]
        _xknx_cls.IndividualAddressSerialResponse = apci["IndividualAddressSerialResponse"]
        _xknx_cls.DomainAddressSerialNumberRead = apci["DomainAddressSerialNumberRead"]
        _xknx_cls.DomainAddressSerialNumberResponse = apci["DomainAddressSerialNumberResponse"]
        _xknx_cls.RestartMasterReset = apci["RestartMasterReset"]
        _xknx_cls.RestartMasterResetResponse = apci["RestartMasterResetResponse"]

        # Get extended memory classes (optional)
        _xknx_cls.MemoryExtendedRead, _xknx_cls.MemoryExtendedReadResponse = _get_memory_extended()

        _xknx_cls.loaded = True


# Protocol options dictionary for scanner registration
protocol_options: Dict[str, Dict[str, Any]] = {
    "interface": {
        "type": "string",
        "description": "Network interface for KNX communication",
        "required": False,
        "default": "",
    },
    "test-read": {
        "type": "bool",
        "description": "Test read access to device memory",
        "required": False,
        "default": True,
    },
    "test-write": {
        "type": "bool",
        "description": "Test write access to device memory",
        "required": False,
        "default": False,
    },
    "test-routing": {
        "type": "bool",
        "description": "Test KNX routing capabilities",
        "required": False,
        "default": False,
    },
    "discovery-timeout": {
        "type": "int",
        "description": "Timeout for bus discovery in seconds",
        "required": False,
        "default": 5,
    },
    "operation-timeout": {
        "type": "int",
        "description": "Timeout for individual operations in seconds",
        "required": False,
        "default": 30,
    },
}
