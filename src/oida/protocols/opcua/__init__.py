#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OPC UA Protocol Module

This module provides comprehensive OPC UA scanning and interaction capabilities.
All components have been refactored into smaller, focused modules:

- helpers.py: Lazy imports and URL utilities
- handlers.py: Event and data change handlers
- scanner.py: OPCUAScanner class (traditional scanner pattern)
- cli_runner.py: opcua class (NXC-style callable)

The package root re-exports only the names reached through it: the L1
``OPCUAScanner``, the NXC-style ``opcua`` callable (resolved by the protocol
loader via ``getattr(module, "opcua")``), and the ``asyncua`` patch anchor
plus its accessor. Everything else is imported directly from the submodules.
"""

# Re-export from helpers (asyncua is the mock.patch anchor used by the scanner
# tests via oida.protocols.opcua.asyncua).
from .helpers import (
    asyncua,
    _get_asyncua,
)

# Re-export from scanner
from .scanner import OPCUAScanner

# Re-export from cli_runner (loader resolves the protocol class by name)
from .cli_runner import opcua

# Define __all__ for explicit exports
__all__ = [
    "asyncua",
    "_get_asyncua",
    "OPCUAScanner",
    "opcua",
]
