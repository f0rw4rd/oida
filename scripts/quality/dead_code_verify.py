#!/usr/bin/env python3
"""Verify vulture candidates by looking for any real reference.

Vulture reports *suspicion*, not proof, and in this codebase most of its
high-confidence output is wrong: `__getattr__` is a lazy-import dunder Python
calls implicitly, the NXC protocol classes are loaded by name through
`ProtocolLoader`, and the shared CLI arg factories are re-exported. Deleting on
vulture's word alone would remove working code.

A symbol counts as REFERENCED if it appears anywhere in src/ or tests/ as:
  * a load of a bare name            (foo)
  * an attribute access              (x.foo)
  * a keyword argument name          (f(foo=...))
  * a string literal                 ("foo") - covers getattr()/registry lookup
  * a base class or decorator
...anywhere other than its own definition line.

Only symbols with zero such references are reported as removable.

Usage:
    dead_code_verify.py                       # summary + top removable symbols
    dead_code_verify.py --list                # every removable symbol
"""

from __future__ import annotations

import argparse
import ast
import collections
import pathlib
import re

BASELINE = ".quality/vulture-baseline.txt"
ROOTS = ("src", "tests")
ENTRY_RE = re.compile(r"unused (\w+) '([^']+)'")

# Never propose deleting these: Python or a framework calls them implicitly.
DUNDER = re.compile(r"^__\w+__$")

# Decorators that are language constructs, not framework registrations.
LANGUAGE_DECORATORS = {
    "staticmethod",
    "classmethod",
    "property",
    "abstractmethod",
    "setter",
    "getter",
    "deleter",
    "cached_property",
    "override",
    "wraps",
    "dataclass",
}


def build_reference_index() -> collections.Counter:
    """Count every use of every identifier across the tree, excluding def sites."""
    used: collections.Counter = collections.Counter()
    for root in ROOTS:
        for path in pathlib.Path(root).rglob("*.py"):
            if "__pycache__" in str(path):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    used[node.id] += 1
                elif isinstance(node, ast.Attribute):
                    used[node.attr] += 1
                elif isinstance(node, ast.keyword) and node.arg:
                    used[node.arg] += 1
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    # registry keys, getattr() names, __all__ entries
                    for tok in re.findall(r"\w+", node.value):
                        used[tok] += 1
                elif isinstance(node, ast.alias):
                    used[node.asname or node.name.split(".")[-1]] += 1
    return used


def definition_counts() -> collections.Counter:
    """How many times each name is *defined* (so we can subtract self-references)."""
    defined: collections.Counter = collections.Counter()
    for root in ROOTS:
        for path in pathlib.Path(root).rglob("*.py"):
            if "__pycache__" in str(path):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    defined[node.name] += 1
    return defined


def load_candidates():
    out = []
    for line in open(BASELINE, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        path, what = line.split("::", 1)
        m = ENTRY_RE.match(what)
        if m:
            out.append((path, m.group(1), m.group(2)))
    return out


def framework_owned(path: str) -> set:
    """Names a framework may call even though nothing in this repo does.

    Two shapes, both verified present in this tree:
      * a decorated def - the decorator registers it (`@event.listens_for`
        on `_set_sqlite_pragma`, SQLAlchemy calls it on connect);
      * a method of a class whose base is external - `MasterApp(dnp3.IMasterApplication)`
        has pydnp3 call `OnOpen`/`OnClose`/`OnTaskStart`, and asyncua drives
        `EventHandler.event_notification`.

    Neither is provably dead, so neither is proposed for deletion.
    """
    try:
        tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return set()

    local_classes = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    # Names imported from inside this project are NOT third-party interfaces.
    # `MMSCodec(ASN1Builder)` inherits our own codec base; its unused builders are
    # genuinely dead. Only a base from an outside package implies a foreign caller.
    project_imported: set = set()
    external_imported: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            local = node.level > 0 or (node.module or "").startswith("oida")
            for alias in node.names:
                (project_imported if local else external_imported).add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                external_imported.add(alias.asname or alias.name.split(".")[0])

    known_local = local_classes | project_imported
    owned = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.decorator_list:
            # staticmethod/classmethod/property/abstractmethod are language
            # constructs, not registrations - they imply no external caller.
            if any(
                ast.unparse(d).split("(")[0].split(".")[-1] not in LANGUAGE_DECORATORS
                for d in node.decorator_list
            ):
                owned.add(node.name)
        if isinstance(node, ast.ClassDef):
            external_base = False
            for base in node.bases:
                if isinstance(base, ast.Attribute):
                    # dotted: lib.Interface - external unless rooted in a project import
                    root = base
                    while isinstance(root, ast.Attribute):
                        root = root.value
                    if not (isinstance(root, ast.Name) and root.id in project_imported):
                        external_base = True
                elif isinstance(base, ast.Name) and base.id not in known_local:
                    external_base = True
            # A handler class with no bases still counts if its methods document
            # an external caller ("Called by asyncua on ...").
            for sub in node.body:
                if not isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                doc = ast.get_docstring(sub) or ""
                if external_base or re.search(r"\bcalled by\b", doc, re.I):
                    owned.add(sub.name)
    return owned


def symbol_spans(path: str):
    try:
        tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return {}
    spans = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.end_lineno:
            spans.setdefault(n.name, (n.end_lineno - n.lineno + 1, n.lineno))
    return spans


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print every removable symbol")
    args = ap.parse_args()

    used = build_reference_index()
    defined = definition_counts()
    candidates = load_candidates()

    removable, kept = [], collections.Counter()
    spans_cache: dict = {}
    fw_cache: dict = {}
    for path, kind, name in candidates:
        if DUNDER.match(name):
            kept["implicit dunder"] += 1
            continue
        # A definition contributes 0 to `used` (ast.FunctionDef stores a raw str),
        # so any count at all is a genuine reference.
        if used.get(name, 0) > 0:
            kept["referenced somewhere"] += 1
            continue
        if defined.get(name, 0) > 1:
            kept["defined in several places"] += 1
            continue
        if path not in fw_cache:
            fw_cache[path] = framework_owned(path)
        if name in fw_cache[path]:
            kept["framework callback"] += 1
            continue
        if path not in spans_cache:
            spans_cache[path] = symbol_spans(path)
        if name not in spans_cache[path]:
            # Already deleted; the vulture baseline just hasn't been regenerated.
            kept["stale baseline entry"] += 1
            continue
        lines, lineno = spans_cache[path][name]
        removable.append((lines, kind, name, path, lineno))

    removable.sort(reverse=True)
    total = sum(r[0] for r in removable)
    print(f"vulture candidates      : {len(candidates)}")
    for reason, n in kept.most_common():
        print(f"  ruled out ({reason:26s}): {n}")
    print(f"\nVERIFIED removable      : {len(removable)} symbols, ~{total} lines\n")

    by_area: collections.Counter = collections.Counter()
    for lines, _, _, path, _ in removable:
        parts = pathlib.Path(path).parts
        by_area["/".join(parts[:4]) if len(parts) > 3 else "/".join(parts[:3])] += lines
    print("--- by area ---")
    for area, n in by_area.most_common(12):
        print(f"  {n:5d}  {area}")

    show = removable if args.list else removable[:25]
    print(f"\n--- {'all' if args.list else 'largest 25'} removable symbols ---")
    for lines, kind, name, path, lineno in show:
        print(f"  {lines:4d} lines  {kind:8s} {name:36s} {path}:{lineno}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
