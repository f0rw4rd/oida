"""Contract: every CLI flag whose help text says 'Requires --confirm' or
matches a dangerous-verb pattern is enforced by an explicit ``args.confirm``
/ ``self.confirm`` check somewhere in its protocol's code.

Catches the **confirm-gate-missing** gap class (TEST_GAP_AUDIT.md):
the audit found 22+ flags advertised as dangerous but never enforced —
DELETEs, writes, brute-force, master-reset, clock-write, fuzz, etc.
The pattern is always the same: ``proto_args.py`` carries the warning
in help text, the dispatcher / NXC connection / mixin forgets the
guard, no test ever invokes the flag end-to-end.

Single static-analysis test. No mocks, no proto_flow runs, no protocol
deps needed. Snapshot-locked to the current state — any drift
(new dangerous flag without enforcement, or a fix not reflected in the
snapshot) fails the test with an actionable diff.
"""

from __future__ import annotations

import ast
import pathlib
import re

from tests._ast_safe import safe_parse

import pytest

SRC_ROOT = pathlib.Path(__file__).resolve().parents[2] / "src" / "oida"
SNAPSHOT = pathlib.Path(__file__).resolve().parent / "confirm_gate_snapshot.txt"

# Help text patterns that mark a flag as dangerous and should be confirm-gated.
_DANGEROUS_HELP_PATTERNS = [
    re.compile(p, re.I)
    for p in [
        r"requires --confirm",
        r"dangerous",
        r"\bwrite[s]?\b",
        r"\bdelete[s]?\b",
        r"\bbrute[\s-]?force",
        r"\bfuzz",
        r"\boverwrite",
        r"\breset(?:s|ting)?\s+the\s",
    ]
]

# Dest names that are inherently dangerous regardless of help text.
_DANGEROUS_DEST_PATTERNS = [
    re.compile(p, re.I)
    for p in [
        r"^(write|delete|patch|put|brute|fuzz|store|move|raw[_-]?fc|raw[_-]?command|"
        r"clock[_-]?(?:read|write|sync)|time[_-]?sync|reset|restart|assess|audit|"
        r"probe[_-]?ops|test[_-]?write|test[_-]?dcc|test[_-]?reinit|methods|"
        r"id[_-]?scan|aet[_-]?brute|default[_-]?creds|send[_-]?patient|"
        r"send[_-]?order|set[_-]?state|cold[_-]?restart|warm[_-]?restart)\b",
        r"^(call[_-]?method|test[_-]?subscription[_-]?limits|enumerate[_-]?writable)$",
    ]
]


def _is_dangerous(dest: str, help_text: str) -> bool:
    if not dest:
        return False
    if any(p.search(dest) for p in _DANGEROUS_DEST_PATTERNS):
        return True
    if any(p.search(help_text or "") for p in _DANGEROUS_HELP_PATTERNS):
        return True
    return False


def _collect_dangerous_flag_dests() -> dict[str, set[str]]:
    """Return ``{protocol -> {dest, dest, ...}}`` of dangerous flags."""
    out: dict[str, set[str]] = {}
    for proto_args in SRC_ROOT.glob("protocols/*/proto_args.py"):
        protocol = proto_args.parent.name
        try:
            tree = safe_parse(proto_args.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            # Looking for `<group>.add_argument("--flag", ..., help="...", ...)`.
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument"):
                continue
            # Derive `dest`: explicit dest= kwarg, else first long-option arg with -- stripped.
            dest = None
            help_text = ""
            for kw in node.keywords:
                if kw.arg == "dest" and isinstance(kw.value, ast.Constant):
                    dest = kw.value.value
                elif kw.arg == "help" and isinstance(kw.value, ast.Constant):
                    help_text = kw.value.value or ""
            if dest is None:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if arg.value.startswith("--"):
                            dest = arg.value.lstrip("-").replace("-", "_")
                            break
            if dest and _is_dangerous(dest, help_text):
                out.setdefault(protocol, set()).add(dest)
    return out


def _enforced_dests_per_protocol() -> dict[str, set[str]]:
    """Return ``{protocol -> {dest, dest, ...}}`` of flags whose code body
    contains an explicit ``args.confirm`` / ``self.confirm`` / equivalent
    guard mentioning the dest name in the same function.

    Heuristic: for each src/oida/protocols/<proto>/**/*.py, find each
    function body that references both ``confirm`` AND a known dangerous
    dest name as ``args.<dest>`` / ``self.args.<dest>`` / ``getattr(self.args,
    "<dest>", ...)``. The dest is treated as enforced for that protocol.
    """
    out: dict[str, set[str]] = {}
    for py in SRC_ROOT.glob("protocols/*/**/*.py"):
        # proto_args.py declares the flags, so scanning its whole body would
        # self-credit every dest. The one exception is validate_args(): several
        # protocols (dnp3, ads) gate their dangerous ops centrally there, raising
        # before the scan runs — and the failure message below explicitly names
        # validate_args() as a valid gate location. Scan that function only.
        proto_args_file = py.name == "proto_args.py"
        protocol = py.relative_to(SRC_ROOT / "protocols").parts[0]
        try:
            tree = safe_parse(py.read_text())
        except SyntaxError:
            continue
        for fn in (
            n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            if proto_args_file and fn.name != "validate_args":
                continue
            try:
                body_src = ast.unparse(fn)
            except Exception:  # noqa: BLE001
                continue
            if "confirm" not in body_src:
                continue
            # Extract every args.<name> / self.args.<name> / getattr(args,"<name>"),
            # plus self.<name> (covers protocols like iec104/dnp3 that copy CLI
            # args into self.<flag> attributes in __init__ and dispatch on those).
            referenced = (
                set(re.findall(r"args\.([a-z_][a-z0-9_]*)", body_src))
                | set(
                    re.findall(
                        r"getattr\(\s*(?:self\.)?args\s*,\s*['\"]([a-z_][a-z0-9_]*)",
                        body_src,
                    )
                )
                | set(re.findall(r"\bself\.([a-z_][a-z0-9_]*)\b", body_src))
            )
            # The canonical gate helpers (ConfirmGateMixin.require_confirm /
            # _confirm_flag, in src/oida/utils/confirm_gate.py) read the
            # ``confirm`` flag internally, so a call to either enforces the
            # ``confirm`` dest even though the function body no longer contains a
            # literal ``args.confirm`` reference. This is the preferred idiom.
            if "require_confirm(" in body_src or "_confirm_flag(" in body_src:
                referenced.add("confirm")
            out.setdefault(protocol, set()).update(referenced)
    return out


def _compute_gate_gaps() -> set[tuple[str, str]]:
    """Return ``{(protocol, dest)}`` for every dangerous flag whose protocol's
    code does NOT show an explicit ``args.<dest>``-near-``confirm`` reference."""
    dangerous = _collect_dangerous_flag_dests()
    enforced = _enforced_dests_per_protocol()
    gaps = set()
    for proto, dests in dangerous.items():
        proto_enforced = enforced.get(proto, set())
        for d in dests:
            if d not in proto_enforced:
                gaps.add((proto, d))
    return gaps


def _load_snapshot() -> set[tuple[str, str]]:
    snap = set()
    for line in SNAPSHOT.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        proto, _, dest = line.partition(":")
        snap.add((proto, dest))
    return snap


def test_confirm_gate_snapshot_drift():
    """Snapshot lock — flag both regressions and unacknowledged fixes."""
    current = _compute_gate_gaps()
    snapshot = _load_snapshot()

    added = current - snapshot
    removed = snapshot - current

    msg = []
    if added:
        msg.append(
            "NEW confirm-gate-missing flags — either wire the guard "
            "(`if not args.confirm: raise ConfigurationError(...)` or "
            "`validate_args()`), or add to confirm_gate_snapshot.txt with "
            "the tracking issue:"
        )
        msg.extend(f"  + {proto}:{dest}" for proto, dest in sorted(added))
    if removed:
        msg.append(
            "\nSnapshot entries no longer detected — if you wired the guard, "
            "REMOVE them from confirm_gate_snapshot.txt:"
        )
        msg.extend(f"  - {proto}:{dest}" for proto, dest in sorted(removed))
    if msg:
        pytest.fail("\n".join(msg))


def test_at_least_one_dangerous_flag_was_found():
    """Sanity: predicate must hit SOMETHING — every protocol has dangerous flags."""
    dangerous = _collect_dangerous_flag_dests()
    total = sum(len(s) for s in dangerous.values())
    assert total >= 20, (
        f"Only found {total} dangerous flag dests across all protocols — "
        f"predicate is probably too tight."
    )


# Raw ``confirm`` reads that bypass the canonical gate. ``self.args.confirm``
# and ``getattr(self.args, "confirm", ...)`` inside scanner code are forbidden:
# the check plus its standard failure log belong in one place
# (``ConfirmGateMixin.require_confirm`` / ``_confirm_flag`` in
# ``src/oida/utils/confirm_gate.py``). Argument *validation* modules
# (``proto_args.py``) legitimately read ``args.confirm`` to raise before a scan,
# so they are exempt.
_RAW_CONFIRM_READ = re.compile(
    r"""getattr\(\s*self\.args\s*,\s*['"]confirm['"]"""
    r"""|self\.args\.confirm\b"""
)
_PROTOCOLS_ROOT = SRC_ROOT / "protocols"


def test_confirm_gate_idiom_is_the_only_reader():
    """Protocol scanners must gate via require_confirm / _confirm_flag, never a raw read."""
    offenders: list[str] = []
    for path in _PROTOCOLS_ROOT.rglob("*.py"):
        if path.name == "proto_args.py":
            continue  # validation layer may raise on args.confirm before scanning
        text = path.read_text(encoding="utf-8")
        if "confirm" not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if _RAW_CONFIRM_READ.search(line):
                rel = path.relative_to(SRC_ROOT.parent.parent)
                offenders.append(f"  {rel}:{lineno}: {line.strip()}")
    if offenders:
        pytest.fail(
            "Raw confirm reads found — replace with the canonical gate "
            '`self.require_confirm("--flag")` (hard gate) or '
            "`self._confirm_flag()` (soft read) from "
            "oida.utils.confirm_gate.ConfirmGateMixin:\n" + "\n".join(offenders)
        )
