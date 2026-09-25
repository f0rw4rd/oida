"""Import-smoke: every ``oida.*`` module must import on every supported Python.

The cheapest, highest-value cross-version guard we have. Syntax that a new
interpreter rejects, a stdlib symbol removed in a later release, or a
``match``/generic-syntax feature unavailable on an older one all surface here
as an ImportError long before any behavioural test runs -- and this test needs
no maintenance as modules are added, because it discovers them by walking the
package tree.

Marked ``version_sensitive`` so it runs on the non-canonical matrix lanes
(3.10/3.11/3.12/3.14), where the full unit suite does not. See the
``version_sensitive`` marker docs in pyproject.toml.
"""

from __future__ import annotations

import importlib
import pkgutil

import pytest

import oida

# Optional third-party backends are imported lazily by the code that needs them
# (see oida.utils.lazy_import), so importing the module itself must not drag
# them in. If a module here *does* hard-import an optional dep that isn't in the
# current environment, that is a real portability bug worth surfacing -- but a
# handful of entry points legitimately require a runtime we don't have in the
# unit lane. Keep this list tight and justified; do not use it to paper over a
# stray top-level ``import``.
_KNOWN_UNIMPORTABLE: frozenset[str] = frozenset()


def _iter_module_names() -> list[str]:
    names: list[str] = []
    for info in pkgutil.walk_packages(oida.__path__, prefix="oida."):
        names.append(info.name)
    return sorted(names)


@pytest.mark.version_sensitive
@pytest.mark.parametrize("module_name", _iter_module_names())
def test_module_imports(module_name: str) -> None:
    if module_name in _KNOWN_UNIMPORTABLE:
        pytest.skip(f"{module_name} requires a runtime not present in the unit lane")
    importlib.import_module(module_name)
