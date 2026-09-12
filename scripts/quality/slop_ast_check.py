#!/usr/bin/env python3
"""Deterministic AST check for hallucinated imports and APIs in Python code.

This is the *deterministic* half of AI-slop detection: it catches the "plausible
but nonexistent" API — `pd.read_exel`, `from os import path_join`, `import reqeusts`
— that an LLM emits and that `mypy`/`ruff`/`pyflakes` routinely miss (they check
undefined *local* names and types, not whether `pd.read_exel` is a real pandas
attribute). Research (Khati et al., FORGE '26) reports this AST+introspection
approach at ~100% precision, which matters: a deterministic pre-pass with almost
no false positives is worth more than another LLM opinion in front of a human.

It flags two things, both by grounding against what is *actually installed* in the
current interpreter (run it under the project venv):

  1. HALLUCINATED_IMPORT — an imported top-level module/package that does not
     resolve via importlib.util.find_spec (typo'd dep, slopsquat, invented module).
  2. HALLUCINATED_API   — `alias.attr` or `from pkg import name` where the module
     imports cleanly but the attribute/name genuinely does not exist on it.

Precision guards (to keep the ~zero-false-positive property):
  * Relative imports (`from . import x`) are skipped — project-local, not resolvable
    in isolation.
  * An import alias that is ever *reassigned* or used as a function parameter in the
    file is skipped for attribute checks (it is shadowing a value, e.g. `df`, not the
    module). This is the main source of false positives, so we are strict about it.
  * Only the first attribute hop is checked (`mod.attr`, not `mod.sub.deep`) — deeper
    hops need submodule imports and risk noise.
  * A module that raises on import is reported as UNCHECKED (not hallucinated) — we
    never guess when we cannot introspect.

Exit code: 0 if no findings, 1 if any findings, 2 on usage/parse-fatal error.
The finding exit code is advisory — slop-check treats this as diagnostic, not a gate.

Usage:
    python scripts/quality/slop_ast_check.py <file.py> [more.py ...]
    python scripts/quality/slop_ast_check.py --json <file.py>
    git diff --name-only --diff-filter=d '*.py' | xargs python scripts/quality/slop_ast_check.py
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import sys
from dataclasses import asdict, dataclass


@dataclass
class Finding:
    file: str
    line: int
    col: int
    kind: str  # HALLUCINATED_IMPORT | HALLUCINATED_API | UNCHECKED | PARSE_ERROR
    symbol: str
    detail: str


def _full_module_resolves(dotted: str) -> bool:
    """True only if the *full* dotted path is an importable module/submodule.

    Distinguishes a real submodule (`os.path`, `collections.abc`) from a
    hallucinated attribute (`os.getcwdd`): find_spec on a non-module dotted name
    raises ModuleNotFoundError, whereas the top-level-only resolver would wrongly
    accept it because the parent package exists.
    """
    try:
        return importlib.util.find_spec(dotted) is not None
    except (ImportError, AttributeError, ValueError, ModuleNotFoundError):
        return False


def _safe_import(name: str):
    """Import a module for introspection, returning it or None on any failure."""
    try:
        return importlib.import_module(name)
    except Exception:
        return None


def _rebound_names(tree: ast.AST) -> set[str]:
    """Names that are assigned, walrus-bound, or used as params anywhere.

    If an import alias also appears here it is shadowing a runtime value, so we
    must not treat `alias.attr` as a module-attribute lookup.
    """
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                bound.update(_names_in_target(tgt))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            bound.update(_names_in_target(node.target))
        elif isinstance(node, ast.NamedExpr):
            bound.update(_names_in_target(node.target))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            bound.update(_names_in_target(node.target))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.args
            for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs):
                bound.add(arg.arg)
            if a.vararg:
                bound.add(a.vararg.arg)
            if a.kwarg:
                bound.add(a.kwarg.arg)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    bound.update(_names_in_target(item.optional_vars))
    return bound


def _names_in_target(node: ast.AST) -> set[str]:
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            out.add(sub.id)
    return out


# Attributes that legitimately exist only on another platform or only at runtime
# under a bundler — absent when this checker introspects, but not hallucinations.
PLATFORM_CONDITIONAL_ATTRS = frozenset(
    {
        "_MEIPASS",  # PyInstaller frozen-bundle temp dir, injected at runtime
        "windll",
        "oledll",
        "WinDLL",
        "OleDLL",  # Windows-only ctypes
        "getwindowsversion",
        "winver",
        "dllhandle",  # Windows-only sys
    }
)

# Exception types whose presence around an attribute access signals a deliberate
# "this attribute may not exist here" guard (platform/frozen/optional).
_DEFENSIVE_EXC = frozenset(
    {
        "Exception",
        "BaseException",
        "AttributeError",
        "ImportError",
        "ModuleNotFoundError",
        "OSError",
        "NameError",
    }
)


def _defensively_guarded_attrs(tree: ast.AST) -> set[int]:
    """id()s of Attribute nodes inside a try whose handler defensively catches.

    `ctypes.windll` under `try: ... except Exception:` is intentional platform
    code, not a hallucination — so we never flag an attribute accessed in a
    defensively-guarded try body.
    """
    guarded: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        defensive = False
        for handler in node.handlers:
            if handler.type is None:  # bare except
                defensive = True
                break
            t = handler.type
            names = (
                [e.id for e in t.elts if isinstance(e, ast.Name)]
                if isinstance(t, ast.Tuple)
                else [t.id]
                if isinstance(t, ast.Name)
                else []
            )
            if any(n in _DEFENSIVE_EXC for n in names):
                defensive = True
                break
        if not defensive:
            continue
        for stmt in node.body:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Attribute):
                    guarded.add(id(sub))
    return guarded


def check_file(path: str) -> list[Finding]:
    try:
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
    except OSError as exc:
        return [Finding(path, 0, 0, "PARSE_ERROR", path, f"cannot read: {exc}")]

    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [Finding(path, exc.lineno or 0, exc.offset or 0, "PARSE_ERROR", path, str(exc))]

    findings: list[Finding] = []

    # alias -> module name, for `import mod` / `import mod as alias`
    module_aliases: dict[str, str] = {}
    # (module, imported_name, alias) for `from mod import name [as alias]`
    from_imports: list[tuple[str, str, str, int, int]] = []

    # Only a *top-level, unguarded* unresolved import is treated as a hallucination.
    # A guarded/optional import (inside a function or try/except — OIDA's pattern for
    # optional protocol deps) that isn't installed looks identical to a hallucination,
    # so we downgrade it to advisory (UNCHECKED) rather than false-positive on it.
    top_level_imports = {id(n) for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))}

    def _emit_unresolved(node: ast.AST, mod: str) -> None:
        if id(node) in top_level_imports:
            findings.append(
                Finding(
                    path,
                    node.lineno,
                    node.col_offset,
                    "HALLUCINATED_IMPORT",
                    mod,
                    f"module '{mod}' does not resolve (not installed / typo)",
                )
            )
        else:
            findings.append(
                Finding(
                    path,
                    node.lineno,
                    node.col_offset,
                    "UNCHECKED",
                    mod,
                    f"module '{mod}' not installed — guarded/optional import, not verified",
                )
            )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                full = alias.name
                # `import a.b.c` binds the top name `a`; `import a.b.c as x` binds `x`
                # to the full submodule. Map the bound name to what it actually refers to.
                if alias.asname:
                    module_aliases[alias.asname] = full
                else:
                    top = full.split(".")[0]
                    module_aliases[top] = top
                if not _full_module_resolves(full):
                    _emit_unresolved(node, full)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # relative import — project-local, skip
            mod = node.module or ""
            if not mod:
                continue
            if not _full_module_resolves(mod):
                _emit_unresolved(node, mod)
                continue  # can't verify the names if the module itself is gone
            for alias in node.names:
                if alias.name == "*":
                    continue
                from_imports.append(
                    (mod, alias.name, alias.asname or alias.name, node.lineno, node.col_offset)
                )

    rebound = _rebound_names(tree)

    # Verify `from mod import name` — does `name` exist on `mod`?
    introspect_cache: dict[str, object] = {}
    for mod, name, _bind, lineno, col in from_imports:
        if mod not in introspect_cache:
            introspect_cache[mod] = _safe_import(mod)
        module = introspect_cache[mod]
        if module is None:
            findings.append(
                Finding(
                    path,
                    lineno,
                    col,
                    "UNCHECKED",
                    f"{mod}.{name}",
                    f"'{mod}' could not be imported for introspection",
                )
            )
            continue
        # A submodule import (`from pkg import submod`) resolves as a spec, not attr.
        if not hasattr(module, name) and not _full_module_resolves(f"{mod}.{name}"):
            findings.append(
                Finding(
                    path,
                    lineno,
                    col,
                    "HALLUCINATED_API",
                    f"{mod}.{name}",
                    f"'{name}' is not a member of module '{mod}'",
                )
            )

    # Verify `alias.attr` first-hop attribute access against real modules.
    checkable = {a: m for a, m in module_aliases.items() if a not in rebound}
    guarded_attrs = _defensively_guarded_attrs(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        base = node.value
        if not isinstance(base, ast.Name):
            continue
        alias = base.id
        if alias not in checkable:
            continue
        if node.attr in PLATFORM_CONDITIONAL_ATTRS or id(node) in guarded_attrs:
            continue  # platform/runtime-conditional or defensively guarded — not slop
        mod = checkable[alias]
        if mod not in introspect_cache:
            introspect_cache[mod] = _safe_import(mod)
        module = introspect_cache[mod]
        if module is None:
            continue  # UNCHECKED already covered if it was a from-import; stay quiet here
        if not hasattr(module, node.attr):
            # Guard: a submodule accessed as attribute (mod.sub) may resolve as a spec.
            if _full_module_resolves(f"{mod}.{node.attr}"):
                continue
            findings.append(
                Finding(
                    path,
                    node.lineno,
                    node.col_offset,
                    "HALLUCINATED_API",
                    f"{alias}.{node.attr}",
                    f"'{node.attr}' is not an attribute of '{mod}'",
                )
            )

    return findings


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("files", nargs="+", help="Python files to check")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = ap.parse_args(argv)

    all_findings: list[Finding] = []
    for path in args.files:
        if not path.endswith(".py"):
            continue
        all_findings.extend(check_file(path))

    real = [f for f in all_findings if f.kind in ("HALLUCINATED_IMPORT", "HALLUCINATED_API")]

    if args.json:
        print(json.dumps([asdict(f) for f in all_findings], indent=2))
    else:
        if not all_findings:
            print("slop-ast: clean — no hallucinated imports or APIs found")
        for f in all_findings:
            tag = {
                "HALLUCINATED_IMPORT": "IMPORT",
                "HALLUCINATED_API": "API",
                "UNCHECKED": "skip ",
                "PARSE_ERROR": "parse",
            }.get(f.kind, f.kind)
            print(f"[{tag}] {f.file}:{f.line}:{f.col}  {f.symbol}  — {f.detail}")
        if real:
            print(
                f"\nslop-ast: {len(real)} hallucination finding(s) "
                f"({len(all_findings) - len(real)} advisory/unchecked)"
            )

    return 1 if real else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
