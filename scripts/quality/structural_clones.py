#!/usr/bin/env python3
"""Cross-file structural (near-duplicate) clone detector.

Token-exact detectors (jscpd) find 0.58% duplication in this tree; an
AST-normalised pass finds ~12,000 duplicated lines. The difference is
copy-paste-then-rename, which is the shape duplication takes here.

Normalisation: strip docstrings, replace every identifier and literal with a
positional placeholder keyed by first occurrence, keep the AST structure.
Functions whose normalised signature matches are structural clones regardless
of naming.

Usage:
    structural_clones.py src/oida                      # report
    structural_clones.py src/oida --fail-over 4000     # CI gate
    structural_clones.py src/oida --baseline .quality/clones.json --fail-on-new
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sys
from collections import defaultdict

# Extension points: many near-identical bodies here are intended (one per
# protocol) and collapsing them is a design change, not a cleanup.
DEFAULT_ALLOW = {
    "_define_protocol",
    "_format_protocol_columns",
    "get_request_definitions",
}


def _normalise(fn: ast.AST) -> tuple[str | None, int]:
    """Return (structural signature, statement count) for a function node."""
    slots: dict[tuple[str, str], str] = {}

    def placeholder(kind: str, val: str) -> str:
        key = (kind, val)
        if key not in slots:
            slots[key] = f"{kind}{len(slots)}"
        return slots[key]

    out: list[str] = []

    def walk(node: ast.AST) -> None:
        if isinstance(node, ast.Name):
            out.append(f"N:{placeholder('n', node.id)}")
            return
        if isinstance(node, ast.Attribute):
            out.append(f"At:{placeholder('A', node.attr)}")
            walk(node.value)
            return
        if isinstance(node, ast.Constant):
            v = node.value
            kind = (
                "bool"
                if isinstance(v, bool)
                else "str"
                if isinstance(v, str)
                else "num"
                if isinstance(v, (int, float))
                else "o"
            )
            out.append(f"C:{kind}")
            return
        if isinstance(node, ast.arg):
            out.append(f"a:{placeholder('a', node.arg)}")
            return
        out.append(type(node).__name__)
        for child in ast.iter_child_nodes(node):
            walk(child)

    body = list(getattr(fn, "body", []))
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if not body:
        return None, 0
    for stmt in body:
        walk(stmt)
    return "|".join(out), sum(1 for s in body for _ in ast.walk(s) if isinstance(_, ast.stmt))


def _iter_python(roots: list[str]):
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, _, filenames in os.walk(root):
            if "__pycache__" in dirpath:
                continue
            for name in filenames:
                if name.endswith(".py"):
                    yield os.path.join(dirpath, name)


def find_clusters(roots, min_stmts=6, min_cluster=4, allow=DEFAULT_ALLOW):
    clusters: dict[str, list] = defaultdict(list)
    for path in _iter_python(roots):
        try:
            tree = ast.parse(open(path, encoding="utf-8").read())
        except (OSError, SyntaxError):
            continue

        def visit(node, cls=None):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    visit(child, child.name)
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if child.name not in allow:
                        sig, count = _normalise(child)
                        if sig and count >= min_stmts:
                            digest = hashlib.sha1(sig.encode()).hexdigest()[:12]
                            end = getattr(child, "end_lineno", child.lineno)
                            qual = f"{cls}.{child.name}" if cls else child.name
                            clusters[digest].append((path, child.lineno, end, qual))
                    visit(child, cls)
                else:
                    visit(child, cls)

        visit(tree)

    results = []
    for digest, members in clusters.items():
        if len(members) < min_cluster or len({m[0] for m in members}) < 3:
            continue
        spans = [m[2] - m[1] + 1 for m in members]
        results.append(
            {
                "id": digest,
                "members": len(members),
                "duplicated_lines": sum(spans) - max(spans),
                "names": sorted({m[3] for m in members})[:4],
                "sites": [f"{m[0]}:{m[1]}-{m[2]}" for m in sorted(members)],
            }
        )
    results.sort(key=lambda r: -r["duplicated_lines"])
    return results


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("roots", nargs="+")
    p.add_argument("--min-stmts", type=int, default=6)
    p.add_argument("--min-cluster", type=int, default=4)
    p.add_argument("--top", type=int, default=25)
    p.add_argument("--show", type=int, default=4)
    p.add_argument("--json", metavar="PATH", help="write full results as JSON")
    p.add_argument("--fail-over", type=int, help="exit 1 if total duplicated lines exceed this")
    p.add_argument("--baseline", metavar="PATH", help="compare against a saved JSON baseline")
    p.add_argument(
        "--fail-on-new", action="store_true", help="exit 1 on any cluster not in baseline"
    )
    args = p.parse_args()

    results = find_clusters(args.roots, args.min_stmts, args.min_cluster)
    total = sum(r["duplicated_lines"] for r in results)

    print(f"{len(results)} structural clone clusters, ~{total} duplicated lines\n")
    for r in results[: args.top]:
        print(
            f"[{r['id']}] {r['members']} copies, ~{r['duplicated_lines']} dup lines  {r['names']}"
        )
        for site in r["sites"][: args.show]:
            print(f"    {site}")
        if r["members"] > args.show:
            print(f"    ... +{r['members'] - args.show} more")
        print()

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"total_duplicated_lines": total, "clusters": results}, fh, indent=2)

    failed = False
    if args.baseline and args.fail_on_new:
        try:
            known = {c["id"] for c in json.load(open(args.baseline, encoding="utf-8"))["clusters"]}
        except (OSError, KeyError, ValueError):
            print(
                f"baseline {args.baseline} unreadable - run with --json to create it",
                file=sys.stderr,
            )
            return 2
        new = [r for r in results if r["id"] not in known]
        if new:
            failed = True
            print(f"FAIL: {len(new)} new clone cluster(s) not in baseline:", file=sys.stderr)
            for r in new:
                print(f"  [{r['id']}] {r['members']} copies - {r['sites'][0]}", file=sys.stderr)

    if args.fail_over is not None and total > args.fail_over:
        failed = True
        print(f"FAIL: {total} duplicated lines exceeds threshold {args.fail_over}", file=sys.stderr)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
