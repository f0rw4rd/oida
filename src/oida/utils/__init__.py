#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OIDA Utilities

Common utilities and base classes for Industrial Control Systems scanners.

Only the most widely-used symbols are re-exported here.  For everything
else, import directly from the relevant submodule:

    from oida.utils.ics_logger import log_exc, mac_lookup, ICSLogger
    from oida.utils.export_utils import export_table, print_table, export_json
    from oida.utils.exceptions   import DependencyError, ModbusError, ...
    from oida.utils.common_types import parse_bool, safe_file_path
    from oida.utils.protocol_helpers import ConnectionHelper, DataFormatter
    from oida.utils.permissions  import check_raw_socket_capability
    from oida.utils.default_credentials import load_credentials
"""

from .base_scanner import (
    BaseScanner,
    NetworkScanner,
    SerialScanner,
)
from .protocol_registry import (
    register_protocol,
    create_protocol_module,
)
from .protocol_helpers import (
    ProtocolParser,
    SecurityAnalyzer,
    ProgressTracker,
    safe_int_conversion,
)
from .common_types import (
    parse_bool,
)

# Legacy 'module' alias - some files import `module` from utils
# and use module.log_exc(), module.warn(), etc.
from . import ics_logger as module

__all__ = [
    # Base scanner classes
    "BaseScanner",
    "NetworkScanner",
    "SerialScanner",
    # Protocol registry
    "register_protocol",
    "create_protocol_module",
    # Protocol helpers
    "ProtocolParser",
    "SecurityAnalyzer",
    "ProgressTracker",
    # Common parsing helpers
    "parse_bool",
    "safe_int_conversion",
    # Backward compat
    "module",
]
