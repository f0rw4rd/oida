#!/usr/bin/env python3
"""Vulture at --min-confidence 60, gated against a shrinking baseline.

The project gate previously ran at confidence 80, which reports only unused
variables. Every dead-code finding in AI_SLOP_AUDIT.md (247 unused methods,
95 unused classes) sits in the 60-79 band that 80 excludes.

Running at 60 outright would report ~1,366 findings, so this wraps it in a
ratchet: findings present in the baseline are allowed, anything new fails.
The baseline is meant to shrink — regenerate it after each cleanup batch and
commit the smaller file.

Usage:
    vulture_gate.py --write-baseline        # regenerate (after a cleanup)
    vulture_gate.py                         # gate: fail on findings not in baseline
    vulture_gate.py --report                # show what is still in the baseline
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

BASELINE = ".quality/vulture-baseline.txt"
TARGETS = ["src/oida/", ".vulture_whitelist.py"]
CONFIDENCE = "60"

# "path:line: unused method 'foo' (60% confidence)" -> drop the line number so
# the baseline survives edits elsewhere in the file.
LINE_RE = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+):\s*(?P<what>.*)$")


def run_vulture() -> list[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "vulture", *TARGETS, "--min-confidence", CONFIDENCE],
        capture_output=True,
        text=True,
    )
    if proc.returncode not in (0, 3):
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"vulture failed with exit {proc.returncode}")
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


def key(line: str) -> str:
    m = LINE_RE.match(line)
    return f"{m.group('path')}::{m.group('what')}" if m else line.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args()

    findings = run_vulture()

    if args.write_baseline:
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        with open(BASELINE, "w", encoding="utf-8") as fh:
            fh.write(
                "# vulture --min-confidence 60 baseline. This file should only\n"
                "# ever get SHORTER. Regenerate after each dead-code cleanup batch.\n"
            )
            for k in sorted({key(f) for f in findings}):
                fh.write(k + "\n")
        print(f"baseline written: {len({key(f) for f in findings})} entries -> {BASELINE}")
        return 0

    try:
        with open(BASELINE, encoding="utf-8") as fh:
            known = {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}
    except OSError:
        print(f"no baseline at {BASELINE}; create it with --write-baseline", file=sys.stderr)
        return 2

    if args.report:
        print(f"{len(findings)} findings at confidence {CONFIDENCE}; {len(known)} baselined")
        return 0

    new = [f for f in findings if key(f) not in known]
    if new:
        print(f"FAIL: {len(new)} dead-code finding(s) not in baseline:", file=sys.stderr)
        for f in new[:30]:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nDelete the dead symbol, or wire it to a caller. Do not add it to the\n"
            "baseline — the baseline only shrinks.",
            file=sys.stderr,
        )
        return 1

    stale = len(known) - len({key(f) for f in findings})
    if stale > 0:
        print(f"{stale} baseline entrie(s) now clean — regenerate with --write-baseline")
    print(f"OK: {len(findings)} findings, all baselined")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
