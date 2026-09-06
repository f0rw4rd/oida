"""KNX lazy imports and utility functions.

This module centralizes all lazy imports for the KNX protocol,
following the oida import standards.
"""

import re
from functools import lru_cache
from typing import TYPE_CHECKING, Optional, Any, Generator, Dict, Tuple

from ...utils.lazy_import import lazy_import
from ...utils import ics_logger as module
from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

if TYPE_CHECKING:
    from xknx.telegram import IndividualAddress

# ============================================================================
# Lazy imports for optional dependencies
# ============================================================================

_xknx = lazy_import("xknx", "KNX")
_xknxproject = lazy_import("xknxproject", "KNX")
_pyzipper = lazy_import("pyzipper", "KNX")


# ============================================================================
# Cached getters using lru_cache for thread safety
# ============================================================================


def _get_xknx():
    """Get xknx module, raising DependencyError if not available.

    ``lazy_import`` already memoises the resolved module behind a lock, so no
    extra ``lru_cache`` is needed here.
    """
    return _xknx()


def is_xknx_available() -> bool:
    """Check if xknx is installed."""
    return _xknx.is_available


def is_xknxproject_available() -> bool:
    """Check if xknxproject is installed."""
    return _xknxproject.is_available


def is_pyzipper_available() -> bool:
    """Check if pyzipper is installed."""
    return _pyzipper.is_available


# ============================================================================
# Lazy getters for xknx submodules
# ============================================================================


@lru_cache(maxsize=1)
def _get_xknx_classes() -> Tuple:
    """Get core XKNX classes.

    Returns:
        Tuple of (XKNX, ConnectionConfig, ConnectionType, GatewayScanner,
                  IndividualAddress, Telegram, GroupAddress, tpci)
    """
    _get_xknx()  # Ensure module is loaded
    from xknx import XKNX  # noqa: F811 - intentional lazy import
    from xknx.io import ConnectionConfig, ConnectionType, GatewayScanner
    from xknx.telegram import IndividualAddress, Telegram, GroupAddress, tpci

    return (
        XKNX,
        ConnectionConfig,
        ConnectionType,
        GatewayScanner,
        IndividualAddress,
        Telegram,
        GroupAddress,
        tpci,
    )


def _get_individual_address():
    """Get IndividualAddress class."""
    return _get_xknx_classes()[4]


@lru_cache(maxsize=1)
def _get_cemi_message_code():
    """Get the cEMI CEMIMessageCode class for frame handling."""
    _get_xknx()
    from xknx.cemi import CEMIMessageCode

    return CEMIMessageCode


@lru_cache(maxsize=1)
def _get_apci_classes() -> Dict[str, Any]:
    """Get APCI telegram classes.

    Returns:
        Dict mapping class names to classes
    """
    _get_xknx()
    from xknx.dpt import DPTArray
    from xknx.telegram.apci import (
        MemoryRead,
        MemoryWrite,
        MemoryResponse,
        UserMemoryRead,
        UserMemoryResponse,
        DeviceDescriptorRead,
        DeviceDescriptorResponse,
        PropertyValueRead,
        PropertyValueWrite,
        PropertyValueResponse,
        PropertyDescriptionRead,
        PropertyDescriptionResponse,
        ADCRead,
        ADCResponse,
        GroupValueWrite,
        AuthorizeRequest,
        AuthorizeResponse,
        IndividualAddressSerialRead,
        IndividualAddressSerialResponse,
    )

    return {
        "DPTArray": DPTArray,
        "MemoryRead": MemoryRead,
        "MemoryWrite": MemoryWrite,
        "MemoryResponse": MemoryResponse,
        "UserMemoryRead": UserMemoryRead,
        "UserMemoryResponse": UserMemoryResponse,
        "DeviceDescriptorRead": DeviceDescriptorRead,
        "DeviceDescriptorResponse": DeviceDescriptorResponse,
        "PropertyValueRead": PropertyValueRead,
        "PropertyValueWrite": PropertyValueWrite,
        "PropertyValueResponse": PropertyValueResponse,
        "PropertyDescriptionRead": PropertyDescriptionRead,
        "PropertyDescriptionResponse": PropertyDescriptionResponse,
        "ADCRead": ADCRead,
        "ADCResponse": ADCResponse,
        "GroupValueWrite": GroupValueWrite,
        "AuthorizeRequest": AuthorizeRequest,
        "AuthorizeResponse": AuthorizeResponse,
        "IndividualAddressSerialRead": IndividualAddressSerialRead,
        "IndividualAddressSerialResponse": IndividualAddressSerialResponse,
    }


def _get_memory_extended() -> Tuple[Optional[Any], Optional[Any]]:
    """Get extended memory classes (optional in some xknx versions).

    Returns:
        Tuple of (MemoryExtendedRead, MemoryExtendedReadResponse) or (None, None)
    """
    _get_xknx()
    import xknx.telegram.apci as apci

    MemoryExtendedRead = getattr(apci, "MemoryExtendedRead", None)
    MemoryExtendedReadResponse = getattr(apci, "MemoryExtendedReadResponse", None)
    return MemoryExtendedRead, MemoryExtendedReadResponse


def _get_xknxproject():
    """Get XKNXProj for ETS project parsing."""
    if not is_xknxproject_available():
        return None
    _xknxproject()  # Ensure module is imported
    from xknxproject import XKNXProj

    return XKNXProj


def _get_xknxproject_exceptions():
    """Get xknxproject exceptions."""
    if not is_xknxproject_available():
        return Exception
    _xknxproject()
    import xknxproject.exceptions as exc_module

    return getattr(exc_module, "InvalidPasswordException", Exception)


def _get_pyzipper():
    """Get pyzipper for encrypted ZIP handling."""
    if not is_pyzipper_available():
        return None
    return _pyzipper()


# ============================================================================
# Address utilities
# ============================================================================

# Safety limit imported from constants (MAX_KEY_RANGE used only in bcu.py)
from .constants import MAX_BUS_ADDRESSES  # noqa: E402


def parse_bus_ranges(bus_ranges: str) -> Generator["IndividualAddress", None, None]:
    """Parse KNX bus address ranges.

    Formats supported:
    - Single address: "1.1.1"
    - Range: "1.1.1-1.1.255"
    - Multiple ranges: "1.1.1-1.1.5,2.2.1-2.2.10"
    - Full scan: "-" (scans 1.0.0 to 15.15.255) - LIMITED to 10000 addresses

    Yields:
        IndividualAddress objects
    """
    if not is_xknx_available():
        logger.debug("parse_bus_ranges: xknx not available, skipping")
        return

    IndividualAddress = _get_individual_address()
    logger.debug(f"Parsing bus ranges: {bus_ranges}")

    if bus_ranges.strip() == "-":
        # Full range shortcut - but limited for safety
        logger.debug(f"Full scan mode, limited to {MAX_BUS_ADDRESSES} addresses")
        module.warn(f"Full scan limited to first {MAX_BUS_ADDRESSES} addresses for safety")
        start = IndividualAddress("1.0.0").raw
        end = IndividualAddress("15.15.255").raw
        count = 0
        for x in range(start, end + 1):
            if count >= MAX_BUS_ADDRESSES:
                break
            yield IndividualAddress(x)
            count += 1
    else:
        targets = set()
        for range_part in bus_ranges.split(","):
            parts = range_part.strip().split("-")
            if len(parts) == 1:
                # Single address
                targets.add(IndividualAddress(parts[0]).raw)
            else:
                # Range
                start = IndividualAddress(parts[0].strip()).raw
                end = IndividualAddress(parts[1].strip()).raw
                for x in range(start, end + 1):
                    targets.add(x)

        if len(targets) > MAX_BUS_ADDRESSES:
            raise ValueError(
                f"Bus range too large: {len(targets)} addresses (max {MAX_BUS_ADDRESSES})"
            )

        logger.debug(f"Parsed {len(targets)} addresses from range specification")
        for raw_addr in sorted(targets):
            yield IndividualAddress(raw_addr)


def validate_individual_address(addr_str: str) -> str:
    """Validate that a KNX individual address is a single address (not a range).

    Args:
        addr_str: Address string like "1.1.1"

    Returns:
        The validated address string

    Raises:
        ValueError: If address is a range or invalid format
    """
    addr_str = addr_str.strip()
    logger.debug(f"Validating individual address: {addr_str}")

    # Reject ranges
    if "-" in addr_str or "," in addr_str:
        raise ValueError(
            f"Individual address must be a single address, not a range: '{addr_str}'. "
            f"Use --scan-range (-r) for address ranges instead."
        )

    # Use xknx's IndividualAddress for validation
    IndividualAddress = _get_individual_address()
    try:
        IndividualAddress(addr_str)
    except Exception as e:
        raise ValueError(
            f"Invalid KNX address format: '{addr_str}'. Expected format: A.L.D (e.g., '1.1.1')"
        ) from e

    return addr_str


def validate_bcu_key(key: str) -> bool:
    """Validate BCU key is valid 8-character hex string.

    Args:
        key: BCU key string to validate

    Returns:
        True if valid 8-char hex string, False otherwise
    """
    if not isinstance(key, str):
        return False
    key = key.strip().upper()
    if len(key) != 8:
        return False
    return bool(re.match(r"^[0-9A-F]{8}$", key))
