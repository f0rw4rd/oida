"""The package's own distribution metadata must be reachable at runtime.

The import package and the CLI command are both ``oida``, but the published
distribution is ``oida-ics``. Code that asked importlib.metadata for "oida"
got nothing back and failed silently: PROTOCOL_DEPENDENCIES came out empty
(so frozen builds lost every protocol and dependency hints went missing) and
``oida --bug`` crashed with PackageNotFoundError. These tests pin the lookup
so a future distribution rename is a test failure, not a silent regression.
"""

from importlib.metadata import PackageNotFoundError, metadata

import pytest

from oida.utils.lazy_import import PROTOCOL_DEPENDENCIES, dist_name

# version_sensitive: importlib.metadata resolution is a packaging-layer
# behaviour that can differ across interpreters, so run it on every matrix
# Python, not only the canonical lane.
pytestmark = [pytest.mark.core, pytest.mark.version_sensitive]


def test_dist_name_resolves_to_an_installed_distribution():
    name = dist_name()
    try:
        meta = metadata(name)
    except PackageNotFoundError:  # pragma: no cover - the bug this test pins
        pytest.fail(f"dist_name() returned {name!r}, which is not installed")
    # The resolved name must be one of the known candidates, and the metadata
    # record returned must actually describe this distribution (not some
    # unrelated package that happened to resolve).
    assert name in ("oida-ics", "oida")
    assert meta["Name"].lower() == name.lower()


def test_protocol_dependencies_is_populated_from_extras():
    # Empty means the metadata lookup silently failed.
    assert PROTOCOL_DEPENDENCIES, "PROTOCOL_DEPENDENCIES is empty -- metadata lookup failed"
    assert "modbus" in PROTOCOL_DEPENDENCIES

    entry = PROTOCOL_DEPENDENCIES["modbus"]
    assert entry["module"] == "pymodbus"
    assert entry["pip_name"] == "pymodbus"
    assert entry["install"] == f"pip install {dist_name()}[modbus]"


def test_install_hints_name_the_real_distribution():
    # A hint pointing at a non-existent distribution is worse than none: the
    # operator runs it and pip fails.
    hints = {e["install"] for e in PROTOCOL_DEPENDENCIES.values() if e.get("install")}
    assert hints
    assert all(h.startswith(f"pip install {dist_name()}[") for h in hints)
