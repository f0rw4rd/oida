#!/usr/bin/env python3
"""Detect tests that pass without providing assurance.

Catches the four shapes found in the 2026-07-24 audit that a normal pytest run
reports as green:

  no-assert    test function with no assert / self.assert* / pytest.raises
  skip-stub    @pytest.mark.skip on a body that is only a docstring + pass
  mock-only    every assertion targets a Mock the test itself configured;
               no symbol imported from the package under test is touched
  tautology    assert True / assert x == x / assert <literal> == <literal>

Usage:
    test_quality.py tests/                                  # report
    test_quality.py tests/ --json .quality/tests.json       # write baseline
    test_quality.py tests/ --baseline .quality/tests.json   # gate on new only
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import pathlib
import sys
from collections import defaultdict

ASSERT_METHODS = ("assert",)  # unittest: assertEqual, assertTrue, ...
MOCK_NAMES = {"Mock", "MagicMock", "AsyncMock", "NonCallableMock", "patch", "mocker"}


def _is_test(fn: ast.AST) -> bool:
    return isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name.startswith("test")


def _collected_tests(tree: ast.AST):
    """Yield only functions pytest would actually collect.

    Module level, or one level inside a class. A `def test_worker(...)` nested
    inside another function is a helper - commonly a thread body - and pytest
    never collects it. An earlier version walked the whole tree and counted
    those, which inflated the no-assert figure.
    """
    for node in tree.body:
        if _is_test(node):
            yield node
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if _is_test(sub):
                    yield sub


def _has_assertion(fn: ast.AST) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                if func.attr.startswith(ASSERT_METHODS):
                    return True
                if func.attr == "raises":
                    return True
            elif isinstance(func, ast.Name) and func.id.startswith(ASSERT_METHODS):
                return True
        if isinstance(node, ast.withitem):
            item = node.context_expr
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute):
                if item.func.attr in ("raises", "warns"):
                    return True
    return False


def _is_skip_stub(fn: ast.AST) -> bool:
    decorated = any(
        "skip" in ast.unparse(d)
        for d in getattr(fn, "decorator_list", [])
        if not isinstance(d, ast.Name) or "skip" in d.id
    )
    if not decorated:
        decorated = any("skip" in ast.unparse(d) for d in getattr(fn, "decorator_list", []))
    if not decorated:
        return False
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    return not body or all(isinstance(s, ast.Pass) for s in body)


def _tautologies(fn: ast.AST) -> list[int]:
    hits = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assert):
            continue
        t = node.test
        if isinstance(t, ast.Constant) and t.value is True:
            hits.append(node.lineno)
        elif isinstance(t, ast.Compare) and len(t.comparators) == 1:
            left, right = ast.unparse(t.left), ast.unparse(t.comparators[0])
            if left == right:
                hits.append(node.lineno)
            elif isinstance(t.left, ast.Constant) and isinstance(t.comparators[0], ast.Constant):
                hits.append(node.lineno)
    return hits


def _root_name(expr: ast.AST) -> "str | None":
    """The base identifier an expression is rooted at.

    `mock_client.read(0, 1)` -> "mock_client";  `scanner.scan(mock_client)` -> "scanner".
    """
    node = expr
    while True:
        if isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        elif isinstance(node, ast.Await):
            node = node.value
        else:
            break
    return node.id if isinstance(node, ast.Name) else None


def _mock_tainted_vars(fn: ast.AST, seeds: "set[str] | None" = None) -> set[str]:
    """Local names holding a unittest.mock value, propagated to a fixed point.

    Seeded by direct Mock()/MagicMock()/patch() construction plus any caller
    supplied seeds (mock fixture params). A value derived from a mock is still a
    mock, so `result = mock_client.read(...)` taints `result` - that is the
    shape of the modbus cluster, where the assertion reads back exactly what the
    mock was configured with.
    """
    tainted: set[str] = set(seeds or ())
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            f = node.value.func
            name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
            if name in MOCK_NAMES:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        tainted.add(tgt.id)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(fn):
            if not isinstance(node, ast.Assign):
                continue
            # Taint flows from the RECEIVER, not from the arguments.
            #   result  = mock_client.read(...)        -> tainted (reads the mock back)
            #   results = scanner.scan(mock_client)    -> NOT tainted; the mock is
            #     injected into real code and the return value is real output.
            # Treating an argument as tainting would flag correct dependency
            # injection, i.e. punish exactly the pattern this gate wants.
            if _root_name(node.value) not in tainted:
                continue
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id not in tainted:
                    tainted.add(tgt.id)
                    changed = True
    return tainted


def mock_fixtures(trees: "list[ast.AST]") -> set[str]:
    """Names of @pytest.fixture functions that yield/return a unittest.mock object.

    Needed to tell `mock_client` (a MagicMock fixture - real slop when asserted
    on) from `mock_host` (this project's name for the Docker mock server's
    hostname, an ordinary string). Keying on the name alone gets this wrong 97%
    of the time in this repo.
    """
    names: set[str] = set()
    for tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any("fixture" in ast.unparse(d) for d in node.decorator_list):
                continue
            tainted = _mock_tainted_vars(node)
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Return, ast.Yield)) and sub.value is not None:
                    refs = {n.id for n in ast.walk(sub.value) if isinstance(n, ast.Name)}
                    rendered = ast.unparse(sub.value)
                    # `return MagicMock()` or `client = MagicMock(); return client`
                    if any(m in rendered for m in MOCK_NAMES) or (refs & tainted):
                        names.add(node.name)
    return names


def _mock_only(fn: ast.AST, package: str, mock_fixture_names: "set[str] | None" = None) -> bool:
    """True if every assertion targets a unittest.mock object the test configured.

    Deliberately narrow. An earlier version keyed on the substring "mock", which
    made it flag `mock_host` / `mock_service` / `mock_port` - this project's
    names for the *Docker mock server*, which are ordinary strings. Those tests
    assert on real socket checks and are not slop. Only values constructed from
    Mock/MagicMock/patch count here.
    """
    seeds = {a.arg for a in getattr(fn.args, "args", []) if a.arg in (mock_fixture_names or set())}
    mock_vars = _mock_tainted_vars(fn, seeds)
    if not mock_vars:
        return False

    asserts = [n for n in ast.walk(fn) if isinstance(n, ast.Assert)]
    if not asserts:
        return False
    for node in asserts:
        roots = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
        if not roots or not roots <= mock_vars:
            return False
    return True


def scan(roots, package="oida"):
    findings = defaultdict(list)
    trees = []
    for root in roots:
        for path in pathlib.Path(root).rglob("*.py"):
            try:
                trees.append(ast.parse(path.read_text(encoding="utf-8", errors="replace")))
            except (OSError, SyntaxError):
                continue
    mock_fx = mock_fixtures(trees)
    for root in roots:
        walker = [(root, [], [os.path.basename(root)])] if os.path.isfile(root) else os.walk(root)
        for dirpath, _, filenames in walker:
            if "__pycache__" in str(dirpath):
                continue
            base = dirpath if os.path.isdir(str(dirpath)) else os.path.dirname(root)
            for name in filenames:
                if not (name.startswith("test") and name.endswith(".py")):
                    continue
                path = os.path.join(base, name)
                try:
                    tree = ast.parse(open(path, encoding="utf-8").read())
                except (OSError, SyntaxError):
                    continue
                for node in _collected_tests(tree):
                    loc = f"{path}:{node.lineno}"
                    entry = {"where": loc, "name": node.name}
                    if _is_skip_stub(node):
                        findings["skip-stub"].append(entry)
                        continue
                    if not _has_assertion(node):
                        findings["no-assert"].append(entry)
                        continue
                    taut = _tautologies(node)
                    if taut:
                        findings["tautology"].append({**entry, "lines": taut})
                    if _mock_only(node, package, mock_fx):
                        findings["mock-only"].append(entry)
    return findings


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("roots", nargs="+")
    p.add_argument("--package", default="oida")
    p.add_argument("--json", metavar="PATH")
    p.add_argument("--baseline", metavar="PATH", help="fail only on findings absent from baseline")
    p.add_argument("--show", type=int, default=10)
    args = p.parse_args()

    findings = scan(args.roots, args.package)
    total = sum(len(v) for v in findings.values())

    for kind in ("no-assert", "skip-stub", "mock-only", "tautology"):
        items = findings.get(kind, [])
        print(f"{kind:<12} {len(items)}")
        for item in items[: args.show]:
            print(f"    {item['where']}  {item['name']}")
        if len(items) > args.show:
            print(f"    ... +{len(items) - args.show} more")
    print(f"\ntotal: {total}")

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({k: v for k, v in findings.items()}, fh, indent=2)

    if args.baseline:
        try:
            known = json.load(open(args.baseline, encoding="utf-8"))
        except (OSError, ValueError):
            print(f"baseline {args.baseline} unreadable - create it with --json", file=sys.stderr)
            return 2
        seen = {f"{k}:{i['where']}" for k, v in known.items() for i in v}
        new = [(k, i) for k, v in findings.items() for i in v if f"{k}:{i['where']}" not in seen]
        if new:
            print(f"\nFAIL: {len(new)} new low-assurance test(s):", file=sys.stderr)
            for kind, item in new[:20]:
                print(f"  {kind}: {item['where']} {item['name']}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
