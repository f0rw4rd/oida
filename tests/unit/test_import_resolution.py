"""Static-import-resolution contract.

Walks every `.py` under ``src/oida/``, finds every function-body
``ImportFrom`` (lazy imports deferred until call time), and statically
resolves each against ``importlib.util.find_spec``. Fails the test on
miss.

Catches the **import-depth-crash** class of bugs: a mixin writes
``from ...utils.X import Y`` (3 dots) but should be 4, because the
mixin is one package deeper than the author thought. The module-import
smoke tests pass because the import lives inside a function body and
never runs at import time — the bug only fires the first time the
feature is used in production.

Sub-second runtime, no protocol dependencies required (every target
in question is `oida.utils.*` or `oida.protocols.*` which are always
present in the dev install).
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib

import pytest

SRC_ROOT = pathlib.Path(__file__).resolve().parents[2] / "src" / "oida"


def _collect_function_level_relative_imports():
    """Walk every .py under src/oida, yield (file, lineno, level, module, pkg_parts)
    for each ImportFrom that lives inside a function/method body and uses a
    relative (dotted) import.
    """
    out = []
    for py in SRC_ROOT.rglob("*.py"):
        rel = py.relative_to(SRC_ROOT.parent)
        pkg_parts = list(rel.with_suffix("").parts[:-1])
        try:
            tree = ast.parse(py.read_text())
        except SyntaxError:
            continue
        for fn in (
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            for node in ast.walk(fn):
                if isinstance(node, ast.ImportFrom) and node.level and node.module:
                    out.append(
                        (str(py), node.lineno, node.level, node.module, pkg_parts)
                    )
    return out


_IMPORT_CASES = _collect_function_level_relative_imports()


@pytest.mark.parametrize(
    "path,lineno,level,module,pkg_parts",
    _IMPORT_CASES,
    ids=lambda v: str(v).rsplit("/", 1)[-1] if isinstance(v, str) else "",
)
def test_function_level_relative_import_resolves(
    path: str, lineno: int, level: int, module: str, pkg_parts: list
):
    """Function-body `from ...x import y` must resolve to a real package.

    Regression guard for the import-depth-crash class. Caught at original
    sites: dicom/mixins/reporting.py:312 (3 dots, needs 4), knx/mixins/
    properties.py:130 (same), opcua/mixins/fuzz.py:94, opcua/mixins/
    credentials.py:310, dicom/mixins/fuzz.py:40, ocpp/mixins/security.py:54,
    snap7/nxc_connection.py:634+727 (level=4 exceeds depth 3).
    """
    assert level <= len(pkg_parts), (
        f"{path}:{lineno}: relative level {level} exceeds package depth "
        f"{len(pkg_parts)} (pkg_parts={pkg_parts})"
    )
    base = pkg_parts[: len(pkg_parts) - (level - 1)]
    target = ".".join(base + module.split("."))
    try:
        spec = importlib.util.find_spec(target)
    except (ImportError, ModuleNotFoundError, ValueError) as exc:
        pytest.fail(
            f"{path}:{lineno}: `from {'.' * level}{module}` resolves to "
            f"non-existent {target!r}: {exc}"
        )
    assert spec is not None, (
        f"{path}:{lineno}: `from {'.' * level}{module}` resolves to "
        f"missing package {target!r}"
    )


def test_at_least_one_lazy_import_was_found():
    """Sanity check: if this test catches 0 lazy imports we have a parser bug,
    not a clean codebase. OIDA has many function-body lazy_import() patterns."""
    assert len(_IMPORT_CASES) >= 50, (
        f"Only found {len(_IMPORT_CASES)} function-body relative imports — "
        "the AST walker is probably broken."
    )
