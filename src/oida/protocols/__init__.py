import logging

logger = logging.getLogger(__name__)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OIDA Protocol Scanners

Individual protocol scanners for Industrial Control Systems.

Protocol modules are loaded lazily by ProtocolLoader to avoid importing
heavy dependencies (like c104 for IEC104) at package initialization time.
"""

# Lazy imports - protocols are loaded on demand via ProtocolLoader
__all__ = []


def get_available_protocols():
    """Get list of protocols with available scanners (checks lazily)"""
    from pathlib import Path

    protocols_dir = Path(__file__).parent
    available = []

    # Check each protocol file
    for proto_file in protocols_dir.glob("*.py"):
        if proto_file.name.startswith("__"):
            continue
        available.append(proto_file.stem)

    return sorted(available)


def get_protocol_scanner(protocol_name: str):
    """Get scanner class for a protocol (lazy import)"""
    import importlib

    try:
        module = importlib.import_module(f".{protocol_name}", __name__)
        # Try common class name patterns
        class_name = f"{protocol_name.capitalize()}Scanner"
        if hasattr(module, class_name):
            return getattr(module, class_name)
        if hasattr(module, protocol_name):
            return getattr(module, protocol_name)
        return None
    except ImportError as e:
        logger.debug(f"Failed to get module: {e}")
        return None


def check_protocol_dependencies(protocol_name: str = None) -> dict:
    """Check if dependencies are available for protocols (lazy check)"""
    if protocol_name:
        scanner = get_protocol_scanner(protocol_name)
        return {protocol_name: scanner is not None}
    else:
        return {name: get_protocol_scanner(name) is not None for name in get_available_protocols()}
