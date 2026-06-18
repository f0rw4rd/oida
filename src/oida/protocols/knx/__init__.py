"""KNX/EIB building automation protocol scanner.

Provides scanning and security testing for KNX building automation systems.
"""

import warnings

# Suppress xknx asyncio warnings
warnings.filterwarnings("ignore", message=".*Future exception was never retrieved.*")

# Re-export from scanner module
from .scanner import (
    KNXScanner,
    metadata,
    run,
)
from . import scanner as _scanner_mod  # noqa: F401

# Re-export from helpers module
from .helpers import (
    is_xknx_available,
    is_xknxproject_available,
    is_pyzipper_available,
    parse_bus_ranges,
    validate_individual_address,
    validate_bcu_key,
)

# Re-export from constants module
from .constants import (
    DEFAULT_PORT,
    DEFAULT_MULTICAST,
    protocol_options,
)

# Re-export from bcu module
from .bcu import (
    load_keys_from_file,
    parse_key_range,
)

# Re-export from ets module
from .ets import (
    get_knxproj_info,
    parse_knxproj,
    crack_knxproj,
    extract_knxproj_hash,
)

# Re-export from cemi_handler module
from .cemi_handler import CustomCEMIHandler

# Re-export from data module
from .data import (
    COMMON_BCU_KEYS,
    get_vendor_name,
)

# Lazy import reference for dependency checking
from ...utils.lazy_import import lazy_import

_xknx = lazy_import("xknx", "KNX")

# Flag to indicate if dependencies are missing (for tests to mock)
dependencies_missing = not _xknx.is_available

# NXC-style callable class
from .nxc_connection import knx  # noqa: E402, F401

__all__ = [
    # Scanner
    "KNXScanner",
    "knx",
    "metadata",
    "run",
    "protocol_options",
    # Helpers
    "is_xknx_available",
    "is_xknxproject_available",
    "is_pyzipper_available",
    "parse_bus_ranges",
    "validate_individual_address",
    "validate_bcu_key",
    # Constants
    "DEFAULT_PORT",
    "DEFAULT_MULTICAST",
    # BCU
    "COMMON_BCU_KEYS",
    "load_keys_from_file",
    "parse_key_range",
    # ETS
    "get_knxproj_info",
    "parse_knxproj",
    "crack_knxproj",
    "extract_knxproj_hash",
    # cEMI
    "CustomCEMIHandler",
    # Data
    "get_vendor_name",
]
