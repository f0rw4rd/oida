#!/usr/bin/env python3
"""Delete the symbols that dead_code_verify.py proves are unreferenced.

Removes each symbol's full AST span (decorators included) plus trailing blank
lines, bottom-up so line numbers stay valid. Refuses to run on a symbol whose
name is not exactly where the verifier said it was.

Usage:
    remove_dead.py --dry-run
    remove_dead.py
"""

from __future__ import annotations

import argparse
import ast
import collections
import pathlib
import subprocess
import sys

VERIFY = ["scripts/quality/dead_code_verify.py", "--list"]


def removable():
    out = subprocess.run(
        [sys.executable, *VERIFY], capture_output=True, text=True, check=True
    ).stdout
    targets = collections.defaultdict(list)
    started = False
    for line in out.splitlines():
        if "removable symbols" in line:
            started = True
            continue
        if not started or not line.strip():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        name, where = parts[3], parts[4]
        path, lineno = where.rsplit(":", 1)
        targets[path].append((int(lineno), name))
    return targets


def strip(path: str, items, dry_run: bool) -> tuple[int, int]:
    src = pathlib.Path(path).read_text(encoding="utf-8")
    tree = ast.parse(src)
    lines = src.splitlines(keepends=True)

    spans = []
    for lineno, name in items:
        node = next(
            (
                n
                for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and n.lineno == lineno
                and n.name == name
            ),
            None,
        )
        if node is None:
            print(f"  !! {path}:{lineno} {name} not found at that line - skipped", file=sys.stderr)
            continue
        start = node.lineno
        if node.decorator_list:
            start = min(d.lineno for d in node.decorator_list)
            while start > 1 and not lines[start - 1].lstrip().startswith("@"):
                start -= 1
        spans.append((start, node.end_lineno, name))

    removed = 0
    for start, end, _ in sorted(spans, reverse=True):
        e = end
        while e < len(lines) and not lines[e].strip():
            e += 1
        removed += e - (start - 1)
        del lines[start - 1 : e]

    if not dry_run and spans:
        pathlib.Path(path).write_text("".join(lines), encoding="utf-8")
    return len(spans), removed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    targets = removable()
    tot_sym = tot_lines = 0
    for path in sorted(targets):
        n, lines = strip(path, targets[path], args.dry_run)
        if n:
            verb = "would remove" if args.dry_run else "removed"
            print(f"  {verb} {n:2d} symbols, {lines:4d} lines  {path}")
        tot_sym += n
        tot_lines += lines
    print(
        f"\n{'WOULD REMOVE' if args.dry_run else 'REMOVED'}: {tot_sym} symbols, {tot_lines} lines"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
