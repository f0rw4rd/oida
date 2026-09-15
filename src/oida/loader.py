"""
Protocol loader for dynamic protocol discovery and loading

This module provides the ProtocolLoader class that discovers and loads
protocol modules dynamically from the protocols directory.
"""

import os
import sys

# Suppress c104 buffered mode warning
os.environ.setdefault("PYTHONUNBUFFERED", "1")

import importlib
import importlib.util
import importlib.machinery
from pathlib import Path
from typing import Dict, Any, Optional

from oida.utils.ics_logger import get_module_logger
from oida.utils.lazy_import import PROTOCOL_DEPENDENCIES


logger = get_module_logger(__name__)


def _is_frozen() -> bool:
    """True when running inside a frozen/compiled bundle.

    Covers PyInstaller (``sys.frozen`` + ``sys._MEIPASS``) AND Nuitka
    ``--standalone``/``--onefile`` (which does NOT set ``sys.frozen`` in
    standalone mode but injects ``__compiled__`` into every compiled module's
    globals). In all of these the protocol ``.py`` files are compiled into the
    bundle and cannot be discovered by scanning the filesystem, so discovery
    must fall back to importing the known protocol list by name.
    """
    return bool(getattr(sys, "frozen", False)) or ("__compiled__" in globals())


# All known protocol package names.  Used as the fallback discovery
# mechanism when running inside a PyInstaller frozen bundle where
# filesystem scanning is not possible.
# Derived from PROTOCOL_DEPENDENCIES; underscore-prefixed keys are
# shared/utility entries, not protocol directories.
_KNOWN_PROTOCOLS = sorted(k for k in PROTOCOL_DEPENDENCIES if not k.startswith("_"))


class ProtocolLoader:
    """
    Dynamically discover and load protocol modules

    Scans the protocols directory for available protocol modules and
    provides methods to load them dynamically. Follows the NXC pattern
    where each protocol can have:
    - <protocol>.py - Main protocol implementation
    - <protocol>/proto_args.py - Argument parser definition
    - <protocol>/database.py - Database schema (optional)
    """

    def __init__(self, protocols_dir: str):
        """
        Initialize protocol loader

        Args:
            protocols_dir: Path to protocols directory
        """
        self.protocols_dir = Path(protocols_dir)
        # In a frozen/compiled bundle (PyInstaller or Nuitka) the protocols
        # directory does not exist on disk — discovery imports the known list
        # by name instead — so the existence check only applies unfrozen.
        if not _is_frozen() and not self.protocols_dir.exists():
            raise ValueError(f"Protocols directory not found: {protocols_dir}")

        self._protocols_cache = None

    def get_protocols(self) -> Dict[str, Dict[str, str]]:
        """
        Discover all available protocols

        Scans the protocols directory for .py files and package directories
        (directories with __init__.py) and their associated subdirectories
        containing proto_args.py, database.py, etc.

        Returns:
            dict: Mapping of protocol names to their file paths
                {
                    'modbus': {
                        'path': '/path/to/modbus.py',
                        'argspath': '/path/to/modbus/proto_args.py',
                        'dbpath': '/path/to/modbus/database.py'
                    },
                    ...
                }
        """
        if self._protocols_cache is not None:
            return self._protocols_cache

        protocols = {}

        # When running inside a PyInstaller frozen bundle, .py files are
        # compiled into the PYZ archive and do not exist on the
        # filesystem.  Fall back to importing from the known list.
        if _is_frozen():
            protocols = self._discover_frozen()
            self._protocols_cache = protocols
            logger.debug(
                f"Discovered {len(protocols)} protocols (frozen): {list(protocols.keys())}"
            )
            return protocols

        # Scan for protocol files (.py files)
        for protocol_file in self.protocols_dir.glob("*.py"):
            # Skip __init__.py and other special files
            if protocol_file.name.startswith("__"):
                continue

            protocol_name = protocol_file.stem
            protocol_dir = self.protocols_dir / protocol_name

            protocol_info = {
                "path": str(protocol_file.resolve()),
                "argspath": None,
                "dbpath": None,
            }

            # Check for protocol subdirectory with additional files
            if protocol_dir.exists() and protocol_dir.is_dir():
                # Look for proto_args.py
                proto_args_file = protocol_dir / "proto_args.py"
                if proto_args_file.exists():
                    protocol_info["argspath"] = str(proto_args_file.resolve())

                # Look for database.py
                database_file = protocol_dir / "database.py"
                if database_file.exists():
                    protocol_info["dbpath"] = str(database_file.resolve())

            protocols[protocol_name] = protocol_info

        # Scan for protocol packages (directories with __init__.py)
        for protocol_dir in self.protocols_dir.iterdir():
            if not protocol_dir.is_dir():
                continue
            # Skip __pycache__ and internal modules (prefixed with _)
            if protocol_dir.name.startswith("_"):
                continue

            # Check if directory has __init__.py (is a package)
            init_file = protocol_dir / "__init__.py"
            if not init_file.exists():
                continue

            protocol_name = protocol_dir.name

            # Skip if already registered as .py file
            if protocol_name in protocols:
                continue

            protocol_info = {
                "path": str(init_file.resolve()),
                "argspath": None,
                "dbpath": None,
            }

            # Look for proto_args.py in the package
            proto_args_file = protocol_dir / "proto_args.py"
            if proto_args_file.exists():
                protocol_info["argspath"] = str(proto_args_file.resolve())

            # Look for database.py in the package
            database_file = protocol_dir / "database.py"
            if database_file.exists():
                protocol_info["dbpath"] = str(database_file.resolve())

            protocols[protocol_name] = protocol_info

        self._protocols_cache = protocols
        logger.debug(f"Discovered {len(protocols)} protocols: {list(protocols.keys())}")
        return protocols

    def _discover_frozen(self) -> Dict[str, Dict[str, str]]:
        """Discover protocols by CONVENTION from the known list (no imports).

        Used inside a PyInstaller frozen bundle where filesystem scanning is not
        available. This deliberately does NOT import each protocol package: doing
        so pulled the entire heavyweight dependency tree (scapy, pydicom, c104,
        snap7, ...) on every CLI invocation, making the frozen binary slow to
        boot even for ``--help``. The actual module is imported lazily only when
        its subcommand is selected (``load_proto_args``) or the scanner is run
        (``get_protocol_class``); both handle a missing/unimportable module
        gracefully, so listing by convention here is safe.
        """
        protocols: Dict[str, Dict[str, str]] = {}
        for name in _KNOWN_PROTOCOLS:
            module_name = f"oida.protocols.{name}"
            protocols[name] = {
                "path": module_name,
                # argspath is used as a module name directly in frozen mode
                # (see load_proto_args); the import is attempted lazily there.
                "argspath": f"{module_name}.proto_args",
                "dbpath": None,
            }
        return protocols

    def load_protocol(self, protocol_path: str) -> Any:
        """
        Dynamically load a protocol module from file path or module name.

        Uses importlib to load the module within the package context
        to support relative imports.

        Args:
            protocol_path: Absolute path to protocol .py file, or a
                dotted module name (e.g. ``oida.protocols.modbus``)
                when running in frozen mode.

        Returns:
            Module object with protocol classes and functions

        Raises:
            ImportError: If module cannot be loaded
        """
        # In frozen mode, protocol_path is already a module name
        if _is_frozen() and "." in protocol_path:
            try:
                module = importlib.import_module(protocol_path)
                logger.debug(f"Loaded frozen protocol module {protocol_path}")
                return module
            except Exception as e:
                logger.error(f"Failed to import frozen protocol {protocol_path}: {e}")
                raise ImportError(f"Could not load protocol: {e}") from e

        if not os.path.exists(protocol_path):
            raise ImportError(f"Protocol file not found: {protocol_path}")

        try:
            # Convert file path to module name
            # e.g., /path/to/oida/protocols/modbus.py -> oida.protocols.modbus
            # e.g., /path/to/oida/protocols/discovery/__init__.py -> oida.protocols.discovery
            path_obj = Path(protocol_path)

            # Find the module name by looking for the LAST oida in the path
            # (handles case where project dir is also named "oida")
            parts = path_obj.parts
            try:
                oida_index = len(parts) - 1 - list(reversed(parts)).index("oida")
                # For __init__.py, use parent directory name as module
                if path_obj.stem == "__init__":
                    module_parts = parts[oida_index:-1]
                else:
                    # Build module name from oida onwards, without .py extension
                    module_parts = parts[oida_index:-1] + (path_obj.stem,)
                module_name = ".".join(module_parts)
            except ValueError:
                # Fallback: just use the filename
                module_name = path_obj.stem

            # Use importlib.import_module which handles relative imports properly
            module = importlib.import_module(module_name)

            logger.debug(f"Loaded protocol module {module_name} from {protocol_path}")
            return module

        except Exception as e:
            logger.error(f"Failed to load protocol from {protocol_path}: {e}")
            raise ImportError(f"Could not load protocol: {e}") from e

    def get_protocol_class(self, protocol_name: str) -> Any:
        """
        Get the protocol scanner class for a given protocol

        Args:
            protocol_name: Name of the protocol (e.g., 'modbus')

        Returns:
            Protocol class object

        Raises:
            ValueError: If protocol not found
            AttributeError: If protocol class not found in module
        """
        protocols = self.get_protocols()

        if protocol_name not in protocols:
            available = ", ".join(sorted(protocols.keys()))
            raise ValueError(
                f"Protocol '{protocol_name}' not found. Available protocols: {available}"
            )

        # Load the protocol module
        protocol_module = self.load_protocol(protocols[protocol_name]["path"])

        # Single dispatch model: the exact-name class is the Layer-2
        # `connection` entrypoint (e.g. `modbus`, `s7`) that the CLI constructs
        # with (args, db, host) and which auto-scans via proto_flow. All 26
        # registered protocols resolve here.
        if hasattr(protocol_module, protocol_name):
            return getattr(protocol_module, protocol_name)

        # Legacy-only fallback: a bare `*Scanner` (Layer-1 BaseScanner) module
        # with no exact-name Layer-2 wrapper. No registered protocol takes this
        # path today — `*Scanner` classes are the internal implementation that
        # the Layer-2 entrypoint wraps, not a second dispatch entrypoint. Kept
        # for out-of-tree/legacy protocol modules.
        # Fallback: look for Scanner suffix (e.g. "modbus" -> "ModbusScanner")
        scanner_class_name = f"{protocol_name.capitalize()}Scanner"
        if hasattr(protocol_module, scanner_class_name):
            return getattr(protocol_module, scanner_class_name)

        # Case-insensitive fallback: handles acronym classes like SNMPScanner,
        # ADSScanner, OPCUAScanner where capitalize() produces wrong casing
        target_lower = f"{protocol_name.lower()}scanner"
        for name in dir(protocol_module):
            if name.lower() == target_lower and isinstance(getattr(protocol_module, name), type):
                return getattr(protocol_module, name)

        # List available classes for debugging
        available_classes = [
            name
            for name in dir(protocol_module)
            if not name.startswith("_") and isinstance(getattr(protocol_module, name), type)
        ]

        raise AttributeError(
            f"Could not find protocol class '{protocol_name}' or '{scanner_class_name}' "
            f"in module. Available classes: {available_classes}"
        )

    def load_proto_args(self, protocol_name: str) -> Optional[Any]:
        """
        Load the proto_args module for a protocol

        Args:
            protocol_name: Name of the protocol

        Returns:
            proto_args module or None if not found
        """
        protocols = self.get_protocols()

        if protocol_name not in protocols:
            return None

        argspath = protocols[protocol_name].get("argspath")
        if not argspath:
            return None

        try:
            # In frozen mode, argspath is already a module name
            if _is_frozen() and "." in argspath:
                module_name = argspath
            else:
                # Convert file path to module name for proper package context
                # This allows proto_args.py files to use relative imports
                path_obj = Path(argspath)
                parts = path_obj.parts
                try:
                    # Use rindex to find the LAST occurrence of "oida" (the package, not project dir)
                    oida_index = len(parts) - 1 - list(reversed(parts)).index("oida")
                    # Build module name: oida.protocols.<protocol>.proto_args
                    module_parts = parts[oida_index:-1] + (path_obj.stem,)
                    module_name = ".".join(module_parts)
                except ValueError:
                    # Fallback if oida not in path
                    module_name = f"proto_args_{protocol_name}"

            module = importlib.import_module(module_name)
            logger.debug(f"Loaded proto_args for {protocol_name}")
            return module

        except Exception as e:
            logger.warning(f"Could not load proto_args for {protocol_name}: {e}")
            raise
