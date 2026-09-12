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
import functools
import importlib
import importlib.util
import pathlib

from tests._ast_safe import safe_parse
from tests.service_gate import require_service

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
            tree = safe_parse(py.read_text())
        except SyntaxError:
            continue
        for fn in (
            n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            for node in ast.walk(fn):
                if isinstance(node, ast.ImportFrom) and node.level and node.module:
                    out.append((str(py), node.lineno, node.level, node.module, pkg_parts))
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
    snap7/cli_runner.py:634+727 (level=4 exceeds depth 3).
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
        f"{path}:{lineno}: `from {'.' * level}{module}` resolves to missing package {target!r}"
    )


def test_at_least_one_lazy_import_was_found():
    """Sanity check: if this test catches 0 lazy imports we have a parser bug,
    not a clean codebase. OIDA has many function-body lazy_import() patterns."""
    assert len(_IMPORT_CASES) >= 50, (
        f"Only found {len(_IMPORT_CASES)} function-body relative imports — "
        "the AST walker is probably broken."
    )


# ---------------------------------------------------------------------------
# Symbol-resolution contract
#
# The module-path test above only proves `from ..x import Y` reaches a real
# *module*. It does NOT prove Y *exists* in x. That hole is exactly how two
# dead lazy imports lurked in production until a feature path executed:
#   - modbus/mixins/read_write.py: `from ..decoder import MapNameResolver`
#     (the class never existed)
#   - utils/permissions.py: `from .platform_compat import check_l2_available`
#     (the function never existed)
# Lazy imports never run at load time and these files had near-zero coverage,
# so import smoke tests, ruff (F401 sees only the import line), vulture, and the
# coverage gate all missed them. This contract resolves the imported *symbol*
# for every internal lazy import — relative AND absolute (`from oida.…`).
# ---------------------------------------------------------------------------


def _resolve_internal_target(level: int, module: str, pkg_parts: list) -> str | None:
    """Return the absolute dotted target for an import, or None if it is not an
    oida-internal module (stdlib / third-party are out of scope here)."""
    if level == 0:
        return module if module and module.split(".")[0] == "oida" else None
    if level > len(pkg_parts):
        return None  # depth error — already flagged by the module-path test
    base = pkg_parts[: len(pkg_parts) - (level - 1)]
    target = ".".join(base + module.split("."))
    return target if target.split(".")[0] == "oida" else None


def _collect_internal_symbol_imports():
    """Yield (file, lineno, target_dotted, symbol) for every function-body
    `from <internal> import <symbol>` — both relative and absolute."""
    out = []
    for py in SRC_ROOT.rglob("*.py"):
        rel = py.relative_to(SRC_ROOT.parent)
        pkg_parts = list(rel.with_suffix("").parts[:-1])
        try:
            tree = safe_parse(py.read_text())
        except SyntaxError:
            continue
        for fn in (
            n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            for node in ast.walk(fn):
                if not isinstance(node, ast.ImportFrom) or node.module is None:
                    continue
                target = _resolve_internal_target(node.level, node.module, pkg_parts)
                if not target:
                    continue
                for alias in node.names:
                    if alias.name != "*":
                        out.append((str(py), node.lineno, target, alias.name))
    return out


_SYMBOL_CASES = _collect_internal_symbol_imports()


def _child_stmt_lists(node):
    """Statement lists that are still at module scope (so conditional / try-
    guarded top-level definitions count), excluding function/class bodies."""
    lists = []
    for attr in ("body", "orelse", "finalbody"):
        v = getattr(node, attr, None)
        if v:
            lists.append(v)
    for handler in getattr(node, "handlers", []) or []:
        if handler.body:
            lists.append(handler.body)
    return lists


@functools.lru_cache(maxsize=None)
def _module_defined_names(target: str):
    """Module-level names a target oida module exports, via static AST parse
    (no import executed). Returns None when the module can't be verified
    statically — missing/non-.py origin, a star import, or a module-level
    ``__getattr__`` (lazy re-export packages like fuzz.core.connections /
    fuzz.monitors) — so the caller falls back to an import-confirm instead of
    false-failing."""
    try:
        spec = importlib.util.find_spec(target)
    except (ImportError, ModuleNotFoundError, ValueError, AttributeError):
        return None
    if spec is None or not spec.origin or spec.origin in ("built-in", "frozen"):
        return None
    origin = pathlib.Path(spec.origin)
    if origin.suffix != ".py" or not origin.exists():
        return None
    try:
        tree = safe_parse(origin.read_text())
    except SyntaxError:
        return None

    names: set[str] = set()
    unverifiable = False

    def visit(body):
        nonlocal unverifiable
        for n in body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(n.name)
                if n.name == "__getattr__":
                    unverifiable = True
            elif isinstance(n, ast.ClassDef):
                names.add(n.name)
            elif isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        names.add(t.id)
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        for e in t.elts:
                            if isinstance(e, ast.Name):
                                names.add(e.id)
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                names.add(n.target.id)
            elif isinstance(n, ast.Import):
                for a in n.names:
                    names.add(a.asname or a.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom):
                for a in n.names:
                    if a.name == "*":
                        unverifiable = True
                    else:
                        names.add(a.asname or a.name)
            elif isinstance(
                n,
                (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While),
            ):
                for sub in _child_stmt_lists(n):
                    visit(sub)

    visit(tree.body)
    if unverifiable:
        return None

    if origin.name == "__init__.py":  # package: submodules are valid names
        for child in origin.parent.iterdir():
            if child.suffix == ".py" and child.name != "__init__.py":
                names.add(child.stem)
            elif child.is_dir() and (child / "__init__.py").exists():
                names.add(child.name)
    return names


@pytest.mark.parametrize(
    "path,lineno,target,symbol",
    _SYMBOL_CASES,
    ids=[f"{pathlib.Path(p).name}:{ln}:{sym}" for p, ln, _t, sym in _SYMBOL_CASES],
)
def test_function_level_import_symbol_resolves(path, lineno, target, symbol):
    """`from <internal> import <symbol>` must name a symbol that exists.

    Regression guard for the dead-internal-import class (MapNameResolver,
    check_l2_available). AST is the fast path; on an AST miss we confirm by
    actually importing the target (avoids false positives from dynamically
    defined names) and only fail if the import also lacks the symbol. If the
    target needs an optional dep that isn't installed, the case is skipped.
    """
    exports = _module_defined_names(target)
    if exports is not None and symbol in exports:
        return

    # AST couldn't confirm it — import the target and check for real.
    try:
        mod = importlib.import_module(target)
    except Exception as exc:  # noqa: BLE001 - optional dep / import error: inconclusive
        require_service(f"{target}: cannot import to confirm symbol ({type(exc).__name__}: {exc})")

    if hasattr(mod, symbol):
        return
    try:  # a submodule import (e.g. `from .pkg import submodule`)
        importlib.import_module(f"{target}.{symbol}")
        return
    except Exception:  # noqa: BLE001
        pass
    pytest.fail(
        f"{path}:{lineno}: `from {target} import {symbol}` — {symbol!r} is not "
        f"defined in {target} (dead internal import)"
    )


def test_symbol_resolver_verified_enough():
    """Sanity: the symbol checker must statically verify a healthy number of
    imports, else the collector/AST resolver silently regressed to a no-op."""
    assert len(_SYMBOL_CASES) >= 200, (
        f"Only collected {len(_SYMBOL_CASES)} internal symbol imports — "
        "the AST collector is probably broken."
    )
    verified = sum(
        1
        for _p, _l, target, symbol in _SYMBOL_CASES
        if (names := _module_defined_names(target)) is not None and symbol in names
    )
    assert verified >= 200, (
        f"Only {verified} symbol imports resolved statically — the AST name "
        "collector is probably broken."
    )
