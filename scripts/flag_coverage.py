#!/usr/bin/env python3
"""CLI flag-coverage scorecard for the real-CLI integration suites.

Answers one question per module: *of the CLI flags this module exposes, how many
are actually exercised by a test that spawns the real `oida` binary?*

This is a coverage metric, not a gate — same spirit as `tests/coverage/`. Test
count is not the signal; flag coverage is.

Usage:
    python scripts/flag_coverage.py                 # scorecard for every module
    python scripts/flag_coverage.py tase2 bacnet    # only these modules
    python scripts/flag_coverage.py --missing tase2 # list uncovered flags
    python scripts/flag_coverage.py --json          # machine-readable

Covered = the flag string appears inside a test function that reaches the CLI
(the `cli_runner` fixture, `run_fuzz_cli`, or a raw subprocess of `oida`).
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROTO_DIR = REPO / "src" / "oida" / "protocols"
TEST_DIR = REPO / "tests" / "integration"

# Modules whose flags do not live in protocols/<name>/proto_args.py
EXTRA_SOURCES = {
    "fuzz": REPO / "src" / "oida" / "fuzz_cli.py",
}

FLAG_RE = re.compile(r'"(--[a-z0-9][a-z0-9-]*)"')
ADD_ARG_RE = re.compile(r'add_argument\(\s*((?:"[^"]+"\s*,\s*)*"[^"]+")')
REAL_CLI_RE = re.compile(r"run_fuzz_cli|_run_oida|subprocess\.(?:run|Popen)")


@dataclass
class ModuleCoverage:
    name: str
    flags: set[str] = field(default_factory=set)
    covered: set[str] = field(default_factory=set)
    test_files: list[str] = field(default_factory=list)

    @property
    def missing(self) -> list[str]:
        return sorted(self.flags - self.covered)

    @property
    def pct(self) -> float:
        return 100.0 * len(self.covered) / len(self.flags) if self.flags else 0.0


def discover_modules() -> list[str]:
    mods = sorted(p.name for p in PROTO_DIR.iterdir() if (p / "proto_args.py").exists())
    return mods + sorted(EXTRA_SOURCES)


def extract_flags(module: str) -> set[str]:
    source = EXTRA_SOURCES.get(module, PROTO_DIR / module / "proto_args.py")
    if not source.exists():
        return set()
    text = source.read_text(errors="replace")
    flags: set[str] = set()
    for match in ADD_ARG_RE.finditer(text):
        flags.update(FLAG_RE.findall(match.group(1)))
    return flags


def _real_cli_test_bodies(path: Path) -> list[str]:
    """Return the source of every test function in `path` that reaches the real CLI."""
    text = path.read_text(errors="replace")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    bodies = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith("test"):
            continue
        raw = lines[node.lineno - 1 : node.end_lineno]
        # Strip comments so a flag merely *named* in a comment never counts as covered.
        body = "\n".join(re.sub(r"#.*$", "", line) for line in raw)
        params = {a.arg for a in node.args.args}
        if params & {"cli_runner", "runner"} or REAL_CLI_RE.search(body):
            bodies.append(body)
    return bodies


def test_files_for(module: str) -> list[Path]:
    pattern = re.compile(r"(^|[_/])%s([_./]|$)" % re.escape(module))
    if module == "fuzz":
        return sorted((TEST_DIR / "fuzz").rglob("test_*.py"))
    return [p for p in sorted(TEST_DIR.rglob("test_*.py")) if pattern.search(p.name)]


def measure(module: str) -> ModuleCoverage:
    cov = ModuleCoverage(name=module, flags=extract_flags(module))
    for path in test_files_for(module):
        bodies = _real_cli_test_bodies(path)
        if not bodies:
            continue
        cov.test_files.append(str(path.relative_to(REPO)))
        blob = "\n".join(bodies)
        cov.covered |= {f for f in cov.flags if f'"{f}"' in blob or f"'{f}'" in blob}
    return cov


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("modules", nargs="*", help="Modules to measure (default: all)")
    parser.add_argument("--missing", action="store_true", help="List uncovered flags")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--min", type=float, default=None, help="Exit 1 below this percent")
    args = parser.parse_args()

    modules = args.modules or discover_modules()
    results = [measure(m) for m in modules]
    results.sort(key=lambda c: (c.pct, -len(c.flags)))

    if args.json:
        print(
            json.dumps(
                {
                    c.name: {
                        "flags": len(c.flags),
                        "covered": len(c.covered),
                        "percent": round(c.pct, 1),
                        "missing": c.missing,
                        "test_files": c.test_files,
                    }
                    for c in results
                },
                indent=2,
            )
        )
    else:
        total_flags = sum(len(c.flags) for c in results)
        total_cov = sum(len(c.covered) for c in results)
        for c in results:
            marker = "  <-- NO REAL-CLI TESTS" if not c.test_files else ""
            print(f"{c.name:12s} {len(c.covered):4d}/{len(c.flags):<4d} {c.pct:5.1f}%{marker}")
            if args.missing and c.missing:
                print(f"{'':12s} missing: {' '.join(c.missing)}")
        pct = 100.0 * total_cov / total_flags if total_flags else 0.0
        print(f"\nTOTAL        {total_cov:4d}/{total_flags:<4d} {pct:5.1f}%")

    if args.min is not None:
        below = [c.name for c in results if c.pct < args.min]
        if below:
            print(f"below --min {args.min}: {', '.join(below)}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
