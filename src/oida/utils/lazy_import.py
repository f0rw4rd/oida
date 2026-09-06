#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lazy Import Utilities for OIDA

Provides lazy import functionality to defer dependency loading until
the protocol is actually used. This allows the CLI to load and show
help for all protocols even if some dependencies are not installed.

Usage:
    # In protocol module
    from ..utils.lazy_import import lazy_import

    _pyads = lazy_import("pyads", "ADS")

    # Later, when actually needed
    pyads = _pyads()  # Will raise DependencyError if not installed
"""

from typing import Any, Optional, Dict
import importlib
import threading

import logging

logger = logging.getLogger(__name__)


def _default_install_hint(protocol: str) -> str:
    """Return the canonical install command for a protocol extra."""
    return f"pip install oida-ics[{protocol.lower()}]"


class LazyModule:
    """
    Lazy module loader that defers import until first attribute access.

    The module is only imported when an attribute is accessed or the
    object is called. If import fails, raises DependencyError with
    helpful installation instructions.
    """

    def __init__(
        self,
        module_name: str,
        protocol: str,
        install_hint: Optional[str] = None,
        submodules: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize lazy module loader.

        Args:
            module_name: Name of the module to import (e.g., "pyads")
            protocol: Protocol name for error messages (e.g., "ADS")
            install_hint: Optional pip install command (defaults to "pip install oida-ics[protocol]")
            submodules: Optional dict of submodule imports {attr_name: "module.path"}
        """
        self._module_name = module_name
        self._protocol = protocol
        self._install_hint = install_hint or _default_install_hint(protocol)
        self._submodules = submodules or {}
        self._module = None
        self._loaded = False
        self._available = None
        # _load() is racy without this: thread A sets _loaded=True before
        # _module is populated; thread B sees _loaded=True with
        # _module=None and raises DependencyError even though the install
        # is fine. Lock the load.
        self._load_lock = threading.Lock()

    def _load(self) -> Any:
        """Load the module, raising DependencyError if not available."""
        with self._load_lock:
            if self._loaded:
                if self._module is None:
                    from .exceptions import DependencyError

                    raise DependencyError(
                        f"{self._module_name} library required for {self._protocol} protocol.\n"
                        f"Install with: {self._install_hint}",
                        protocol=self._protocol,
                    )
                return self._module

            try:
                module = importlib.import_module(self._module_name)
                # Publish module BEFORE flipping _loaded so any other
                # thread that observes _loaded=True always sees a
                # populated _module.
                self._module = module
                self._available = True
                self._loaded = True
                return module
            except ImportError:
                self._module = None
                self._available = False
                self._loaded = True
                from .exceptions import DependencyError

                raise DependencyError(
                    f"{self._module_name} library required for {self._protocol} protocol.\n"
                    f"Install with: {self._install_hint}",
                    protocol=self._protocol,
                )

    def __getattr__(self, name: str) -> Any:
        """Get attribute from loaded module.

        Raises AttributeError (not DependencyError) when the underlying
        module is unavailable.  This satisfies the Python data model
        contract for __getattr__ and lets hasattr(), getattr(..., default),
        unittest.mock.patch, and inspect machinery work correctly.

        Code that explicitly wants the user-friendly DependencyError should
        call the LazyModule instance (``_mod()``) via __call__ instead.
        """
        # Check if it's a registered submodule
        if name in self._submodules:
            return self._load_submodule(name)
        try:
            module = self._load()
        except Exception as exc:
            raise AttributeError(
                f"Cannot access {name!r} on lazy module {self._module_name!r}: {exc}"
            ) from exc
        return getattr(module, name)

    def _load_submodule(self, name: str) -> Any:
        """Load a specific submodule."""
        if not self._loaded:
            self._load()
        if self._module is None:
            from .exceptions import DependencyError

            raise DependencyError(
                f"{self._module_name} library required for {self._protocol} protocol.\n"
                f"Install with: {self._install_hint}",
                protocol=self._protocol,
            )
        submodule_path = self._submodules[name]
        return importlib.import_module(submodule_path)

    def __call__(self) -> Any:
        """Return the loaded module when called."""
        return self._load()

    @property
    def is_available(self) -> bool:
        """Check if module is available without raising exception."""
        if self._available is not None:
            return self._available
        try:
            importlib.import_module(self._module_name)
            self._available = True
        except ImportError:
            self._available = False
        return self._available


def lazy_import(
    module_name: str,
    protocol: str,
    install_hint: Optional[str] = None,
    submodules: Optional[Dict[str, str]] = None,
) -> LazyModule:
    """
    Create a lazy module loader.

    Args:
        module_name: Name of the module to import (e.g., "pyads")
        protocol: Protocol name for error messages (e.g., "ADS")
        install_hint: Optional pip install command (defaults to "pip install oida-ics[protocol]")
        submodules: Optional dict mapping attribute names to submodule paths

    Returns:
        LazyModule instance that loads the module on first access

    Example:
        _pyads = lazy_import("pyads", "ADS")

        # Later, when needed:
        pyads = _pyads()  # Loads and returns module
        # Or access attributes directly:
        connection = _pyads.Connection(...)
    """
    return LazyModule(module_name, protocol, install_hint, submodules)


def check_dependency(module_name: str) -> bool:
    """
    Check if a dependency is available without importing it fully.

    Args:
        module_name: Name of the module to check

    Returns:
        True if available, False otherwise
    """
    try:
        importlib.import_module(module_name)
        return True
    except ImportError as e:
        logger.debug(f"importlib.import_module(module_name): {e}")
        return False


# ── Derive PROTOCOL_DEPENDENCIES from installed package metadata ──
# pyproject.toml is the single source of truth: each per-protocol extra
# (e.g. [project.optional-dependencies] ads = ["pyads>=3.4.0"]) maps
# directly to a protocol directory name.  At runtime we read the
# installed metadata via importlib.metadata so no hardcoded list is
# needed here.

# Packages where pip name != Python import name
_IMPORT_OVERRIDES: Dict[str, str] = {
    "bac0": "BAC0",
    "paho-mqtt": "paho.mqtt",
    "python-snap7": "snap7",
    "yadnp3": "opendnp3",
    "profinet-py": "profinet",
    "hartip-py": "hartip",
    "pyiec61850-ng": "pyiec61850",
    "python-can": "can",
    "pyyaml": "yaml",
}

# Extras that are NOT protocol directories.
#  * "serial": a shared transport dependency (pyserial) consumed by IEC-101/104
#    serial, DNP3 serial and the serial discovery CLI — no protocols/serial/.
#  * "bacnetsc": BACnet/SC is no longer a standalone protocol; it folded into
#    the bacnet command as the `--sc` transport mode. The extra is retained as
#    the install target for the SC-only deps (websockets, cryptography) but has
#    no protocols/bacnetsc/ package, so it must not be discovered as a command.
_SKIP_EXTRAS = frozenset({"dev", "docs", "all", "fuzz", "serial", "bacnetsc"})


def _build_protocol_dependencies() -> Dict[str, Dict[str, Any]]:
    """Build PROTOCOL_DEPENDENCIES from installed oida package metadata."""
    import re

    try:
        from importlib.metadata import requires, metadata
    except ImportError:
        from importlib_metadata import requires, metadata  # type: ignore[no-redef]

    result: Dict[str, Dict[str, Any]] = {}

    # Get all declared extras (includes empty-dep protocols like astm, ocpp)
    all_extras = set(metadata("oida-ics").get_all("Provides-Extra") or [])

    # Seed every protocol extra with an empty entry
    for extra in sorted(all_extras):
        if extra in _SKIP_EXTRAS:
            continue
        result[extra] = {"protocol": extra}

    # Parse "Requires-Dist" lines to fill in module/pip_name/install
    #   e.g.  "pyads>=3.4.0 ; extra == \"ads\""
    _extra_re = re.compile(r'extra\s*==\s*"([^"]+)"')

    for line in requires("oida-ics") or []:
        m = _extra_re.search(line)
        if not m:
            continue
        extra_name = m.group(1)
        if extra_name in _SKIP_EXTRAS:
            continue
        if extra_name not in result:
            continue

        # Already filled the primary dep for this extra — skip secondary deps
        if "module" in result[extra_name]:
            continue

        # Extract pip package name (everything before version specifier / markers)
        pip_name = line.split(";")[0].split(">")[0].split("<")[0].split("=")[0].split("!")[0]
        pip_name = pip_name.split("[")[0].strip()

        import_name = _IMPORT_OVERRIDES.get(pip_name.lower(), pip_name)
        result[extra_name] = {
            "module": import_name,
            "protocol": extra_name,
            "install": f"pip install oida-ics[{extra_name}]",
            "pip_name": pip_name,
        }

    return result


try:
    PROTOCOL_DEPENDENCIES: Dict[str, Any] = _build_protocol_dependencies()
except Exception:
    # Fallback: package metadata not yet available (e.g. during build)
    PROTOCOL_DEPENDENCIES = {}
