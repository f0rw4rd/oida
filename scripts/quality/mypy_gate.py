#!/usr/bin/env python3
"""Mypy bug-shaped errors, gated against a shrinking baseline.

The project's mypy config in pyproject.toml is already strict, but it runs
informationally - the tree currently has ~10k errors across 500+ files, so a
hard global gate is impossible without a rewrite. Most of that is noise:
`attr-defined` (dynamic loader/connection pattern) and `no-untyped-def` (missing
annotations) carry no runtime risk.

This gate ignores that noise and enforces only the BUG-SHAPED codes - the
None/union/arg-type footguns that cause real crashes (calling `.get()` on a
`dict | str | None`, indexing something optional, passing `str | None` where a
`str` is required, bad overrides, ...). Findings present in the baseline are
allowed; anything NEW fails CI.

The baseline is meant to SHRINK - clear bug-shaped errors when you touch a file
(use `--report --code union-attr` to find them), then regenerate and commit the
smaller file. It must never grow: fix the type error, don't baseline it.

Usage:
    mypy_gate.py --write-baseline            # regenerate (after a paydown batch)
    mypy_gate.py                             # gate: fail on findings not in baseline
    mypy_gate.py --report                    # counts: found vs baselined
    mypy_gate.py --report --code union-attr  # list live sites for one code
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

BASELINE = ".quality/mypy-baseline.txt"
TARGETS = ["src/oida/"]

# The bug-shaped subset: type errors that indicate a real runtime defect rather
# than a missing annotation or a dynamic-attribute false positive. Everything
# NOT in this set (attr-defined, no-untyped-def, assignment, no-any-return,
# var-annotated, misc, unused-ignore, abstract, ...) is intentionally ignored.
BUG_CODES = frozenset(
    {
        "union-attr",
        "index",
        "arg-type",
        "operator",
        "list-item",
        "dict-item",
        "return-value",
        "name-defined",
        "has-type",
        "call-overload",
        "override",
        "valid-type",
        "str-unpack",
        "no-redef",
        "str-bytes-safe",
        "type-var",
        "call-arg",
    }
)

# "path:line: error: message  [code]" -> capture path, message, code. The line
# number is dropped from the baseline key so it survives edits elsewhere in the
# file (same approach as vulture_gate.py).
LINE_RE = re.compile(
    r"^(?P<path>[^:]+):(?P<line>\d+):(?:\d+:)?\s*error:\s*(?P<msg>.*?)\s*\[(?P<code>[a-z-]+)\]\s*$"
)


class Finding:
    __slots__ = ("path", "line", "msg", "code", "raw")

    def __init__(self, path: str, line: str, msg: str, code: str, raw: str) -> None:
        self.path = path
        self.line = line
        self.msg = msg
        self.code = code
        self.raw = raw

    def key(self) -> str:
        # path + code + message, line number dropped so the entry survives edits
        # elsewhere in the file (same approach as vulture_gate.py). Identical
        # messages in one file collapse to a single key.
        return f"{self.path}::{self.code}::{self.msg}"


def run_mypy() -> list[Finding]:
    proc = subprocess.run(
        [sys.executable, "-m", "mypy", *TARGETS],
        capture_output=True,
        text=True,
    )
    # mypy exits 0 (clean) or 1 (errors found). Anything else is a real failure
    # (bad config, crash) and must not be swallowed into a green gate.
    if proc.returncode not in (0, 1):
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"mypy failed with exit {proc.returncode}")
    findings: list[Finding] = []
    for ln in proc.stdout.splitlines():
        m = LINE_RE.match(ln)
        if not m:
            continue
        code = m.group("code")
        if code not in BUG_CODES:
            continue
        findings.append(Finding(m.group("path"), m.group("line"), m.group("msg"), code, ln.strip()))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--code", help="with --report, list live sites for one mypy code")
    args = ap.parse_args()

    findings = run_mypy()

    if args.write_baseline:
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        keys = sorted({f.key() for f in findings})
        with open(BASELINE, "w", encoding="utf-8") as fh:
            fh.write(
                "# mypy bug-shaped-error baseline (see scripts/quality/mypy_gate.py).\n"
                "# Only the bug-shaped codes are gated; noise codes are ignored.\n"
                "# This file should only ever get SHORTER. Fix the type error and\n"
                "# regenerate - never add a new entry to silence the gate.\n"
            )
            for k in keys:
                fh.write(k + "\n")
        print(f"baseline written: {len(keys)} entries -> {BASELINE}")
        return 0

    try:
        with open(BASELINE, encoding="utf-8") as fh:
            known = {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}
    except OSError:
        print(f"no baseline at {BASELINE}; create it with --write-baseline", file=sys.stderr)
        return 2

    if args.report:
        if args.code:
            sites = [f for f in findings if f.code == args.code]
            print(f"{len(sites)} live '{args.code}' finding(s):")
            for f in sites:
                print(f"  {f.raw}")
            return 0
        by_code: dict[str, int] = {}
        for f in findings:
            by_code[f.code] = by_code.get(f.code, 0) + 1
        print(f"{len(findings)} bug-shaped finding(s); {len(known)} baselined")
        for code in sorted(by_code, key=lambda c: -by_code[c]):
            print(f"  {by_code[code]:5d}  {code}")
        return 0

    new = [f for f in findings if f.key() not in known]
    if new:
        print(f"FAIL: {len(new)} new bug-shaped type error(s) not in baseline:", file=sys.stderr)
        for f in new[:30]:
            print(f"  {f.raw}", file=sys.stderr)
        if len(new) > 30:
            print(f"  ... and {len(new) - 30} more", file=sys.stderr)
        print(
            "\nFix the type error (guard the None, narrow the union, correct the\n"
            "argument type). Do NOT add it to the baseline - the baseline only shrinks.",
            file=sys.stderr,
        )
        return 1

    stale = len(known) - len({f.key() for f in findings})
    if stale > 0:
        print(f"{stale} baseline entrie(s) now clean - regenerate with --write-baseline")
    print(f"OK: {len(findings)} bug-shaped findings, all baselined")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
