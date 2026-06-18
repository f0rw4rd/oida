#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Protocol Registry and Decorator System

This module provides a decorator-based system for registering protocol scanners,
eliminating the need for repetitive metadata dictionaries in each protocol file.
"""

from typing import Dict, List, Any, Callable, Type, Optional


# Global registry of protocols
_protocol_registry: Dict[str, Dict[str, Any]] = {}


def register_protocol(
    name: str,
    description: str,
    default_port: Optional[int] = None,
    authors: Optional[List[str]] = None,
    references: Optional[List[Dict[str, str]]] = None,
    protocol_options: Optional[Dict[str, Any]] = None,
    protocol_type: str = "network",  # "network" or "serial"
):
    """
    Decorator to register a protocol scanner with metadata.

    This eliminates the need for manual metadata dictionary creation
    and standardizes protocol registration.

    Args:
        name: Protocol name (e.g., "Modbus Scanner")
        description: Protocol description
        default_port: Default port number (for network protocols)
        authors: List of author names/emails
        references: List of reference dicts with 'type' and 'ref' keys
        protocol_options: Protocol-specific options dict
        protocol_type: "network" or "serial"

    Example:
        @register_protocol(
            name="Modbus Scanner",
            description="Modbus TCP/RTU scanner",
            default_port=502,
            authors=["f0rw4rd"],
            references=[{"type": "url", "ref": "https://modbus.org"}],
            protocol_options={
                "unit-id": {"type": "int", "default": 1, ...}
            }
        )
        class ModbusScanner(NetworkScanner):
            ...
    """

    def decorator(scanner_class: Type) -> Type:
        # Build metadata
        from .base_scanner import create_common_metadata, create_serial_metadata

        # Choose metadata creator based on protocol type
        if protocol_type == "serial":
            metadata = create_serial_metadata(
                name=name,
                description=description,
                authors=authors or [],
                references=references or [],
                additional_options=protocol_options,
            )
        else:
            metadata = create_common_metadata(
                name=name,
                description=description,
                authors=authors or [],
                references=references or [],
                additional_options=protocol_options,
            )

        # Set default port if provided
        if default_port is not None and "rport" in metadata.get("options", {}):
            metadata["options"]["rport"]["default"] = default_port

        # Store metadata on the class
        scanner_class._protocol_metadata = metadata

        # Register in global registry
        protocol_key = scanner_class.__name__.replace("Scanner", "").lower()
        _protocol_registry[protocol_key] = {
            "class": scanner_class,
            "metadata": metadata,
            "name": name,
            "default_port": default_port,
        }

        return scanner_class

    return decorator


def get_protocol_metadata(scanner_class: Type) -> Dict[str, Any]:
    """
    Get metadata for a registered protocol scanner.

    Args:
        scanner_class: The scanner class

    Returns:
        Metadata dictionary
    """
    if hasattr(scanner_class, "_protocol_metadata"):
        return scanner_class._protocol_metadata

    raise ValueError(f"Scanner class {scanner_class.__name__} is not registered")


def create_protocol_module(scanner_class: Type, dependencies_check_func: Optional[Callable] = None):
    """
    Create a complete protocol module with metadata and run function.

    This is a convenience function that combines metadata extraction
    and run function creation into one step.

    Args:
        scanner_class: The scanner class (must be decorated with @register_protocol)
        dependencies_check_func: Optional function that returns True if dependencies are missing

    Returns:
        Tuple of (metadata dict, run function)

    Example:
        @register_protocol(name="Modbus", default_port=502, ...)
        class ModbusScanner(NetworkScanner):
            ...

        # At bottom of file:
        metadata, run = create_protocol_module(
            ModbusScanner,
            lambda: dependencies_missing
        )
    """
    from .base_scanner import create_run_function

    # Get metadata
    metadata = get_protocol_metadata(scanner_class)

    # Extract protocol name from metadata
    protocol_name = metadata.get("name", scanner_class.__name__)

    # Create run function
    run = create_run_function(
        scanner_class=scanner_class,
        protocol_name=protocol_name,
        dependencies_check_func=dependencies_check_func,
    )

    return metadata, run
