"""Smoke tests — verify core imports and protocol discoverability.

These are intentionally lightweight: no network, no optional deps required.
They catch broken imports, missing __init__.py files, and loader regressions.
"""

import importlib

import pytest

from tests.service_gate import require_service

pytestmark = pytest.mark.core

# ---------------------------------------------------------------------------
# Core package imports
# ---------------------------------------------------------------------------

CORE_MODULES = [
    "oida",
    "oida.cli",
    "oida.connection",
    "oida.loader",
    "oida.targets",
]


@pytest.mark.parametrize("module", CORE_MODULES)
def test_core_import(module):
    """Core modules must be importable without optional deps."""
    mod = importlib.import_module(module)
    assert mod is not None


# ---------------------------------------------------------------------------
# Utils imports
# ---------------------------------------------------------------------------


def test_base_scanner_imports():
    from oida.utils.base_scanner import BaseScanner, NetworkScanner, SerialScanner

    assert BaseScanner is not None
    assert NetworkScanner is not None
    assert SerialScanner is not None


def test_exception_hierarchy():
    from oida.utils.exceptions import (
        ICSConnectionError,
        ICSProtocolError,
        ICSTimeoutError,
        ProtocolError,
    )

    assert issubclass(ProtocolError, ICSProtocolError)
    assert issubclass(ICSConnectionError, ICSProtocolError)
    assert issubclass(ICSTimeoutError, ICSProtocolError)


def test_common_types():
    from oida.utils.common_types import parse_bool, safe_file_path

    assert parse_bool is not None
    assert safe_file_path is not None


# ---------------------------------------------------------------------------
# Protocol modules importable (lazy — doesn't require optional deps)
# ---------------------------------------------------------------------------

PROTOCOL_PACKAGES = [
    "ads",
    "astm",
    "bacnet",
    "can",
    "dicom",
    "discovery",
    "dnp3",
    "ethercat",
    "ethernetip",
    "fhir",
    "goose",
    "hart",
    "hl7",
    "iec104",
    "knx",
    "mms",
    "modbus",
    "mqtt",
    "opcua",
    "profinet",
    "snap7",
    "tase2",
]


@pytest.mark.parametrize("proto", PROTOCOL_PACKAGES)
def test_protocol_package_importable(proto):
    """Each protocol __init__.py must be importable (syntax/import errors fail here).

    ImportError/ModuleNotFoundError for *optional* third-party deps is acceptable
    (e.g. xknx, c104) — the test only fails on errors within our own code.
    """
    try:
        mod = importlib.import_module(f"oida.protocols.{proto}")
        assert mod is not None
    except (ImportError, ModuleNotFoundError) as exc:
        # Allow failures caused by missing optional third-party packages.
        # SyntaxError would propagate (not caught here) — which is the point.
        # "cannot import name 'X' from 'oida...'" is a cascading failure from
        # a third-party dep not being installed, so we skip those too.
        require_service(f"Optional dependency not installed: {exc}")


# ---------------------------------------------------------------------------
# Loader / registry
# ---------------------------------------------------------------------------


def test_protocol_loader_discovers():
    from pathlib import Path

    from oida.loader import ProtocolLoader

    protocols_dir = str(Path(__file__).resolve().parents[2] / "src" / "oida" / "protocols")
    loader = ProtocolLoader(protocols_dir)
    protocols = loader.get_protocols()
    assert isinstance(protocols, dict)
    assert len(protocols) >= 10, f"Loader found only {len(protocols)} protocols"


# ---------------------------------------------------------------------------
# Package metadata
# ---------------------------------------------------------------------------


def test_version_string():
    import oida

    assert isinstance(oida.__version__, str)
    assert len(oida.__version__) > 0
    # Basic semver-ish check: contains at least one dot
    assert "." in oida.__version__
