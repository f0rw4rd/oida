#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OPC UA Protocol Module

This module provides comprehensive OPC UA scanning and interaction capabilities.
All components have been refactored into smaller, focused modules:

- helpers.py: Lazy imports and URL utilities
- handlers.py: Event and data change handlers
- scanner.py: OPCUAScanner class (traditional scanner pattern)
- nxc_connection.py: opcua class (NXC-style callable)

This __init__.py maintains backward compatibility by re-exporting all components.
"""

# Re-export from helpers
from .helpers import (
    asyncua,
    ua,
    _asyncua,
    _get_asyncua,
    _get_client_class,
    _get_ua_module,
    _get_bad_user_access_denied,
    _get_security_policies,
    _get_security_policies_cached,
    _normalize_opcua_url,
    _parse_opcua_url,
    _LazyUaModule,
    OPCUA_SCHEME,
    DANGEROUS_KEYWORDS,
)

# Re-export from handlers
from .handlers import (
    DataChangeHandler,
    EventHandler,
)

# Re-export from scanner
from .scanner import (
    OPCUAScanner,
    protocol_options,
    metadata,
    run,
)

# Re-export from nxc_connection
from .nxc_connection import opcua

# Define __all__ for explicit exports
__all__ = [
    # Lazy imports and helpers
    "asyncua",
    "ua",
    "_asyncua",
    "_get_asyncua",
    "_get_client_class",
    "_get_ua_module",
    "_get_bad_user_access_denied",
    "_get_security_policies",
    "_get_security_policies_cached",
    "_normalize_opcua_url",
    "_parse_opcua_url",
    "_LazyUaModule",
    "OPCUA_SCHEME",
    "DANGEROUS_KEYWORDS",
    # Handlers
    "DataChangeHandler",
    "EventHandler",
    # Scanner
    "OPCUAScanner",
    "protocol_options",
    "metadata",
    "run",
    # NXC-style callable
    "opcua",
]
