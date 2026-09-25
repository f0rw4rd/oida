"""Contract: no logger call leaks an INPUT credential (operator-supplied).

The defensive-tool contract for OIDA distinguishes two credential
flavours, only one of which is a leak:

- **INPUT credentials** - the operator passed `--password`,
  `--credentials`, `--psk`, etc. These are the operator's secrets;
  they must NEVER appear in any log line, screen output, or JSON
  audit log. They're identified statically as f-string interpolations
  of `args.<X>` / `self.args.<X>` / `getattr(self.args, "<X>", ...)`
  where `<X>` is a credential-shaped name.

- **RECOVERED credentials** - a successful brute-force, default-creds
  match, or PCAP capture surfaces a third party's credential. The
  whole point of the scanner is to show these to the operator -
  hiding them would defeat the tool. They're typically interpolated
  as a local variable (`{found_password}`, `{test_password}`, etc.)
  and emitted via `.security_finding(...)` / `.success(...)`.

This contract flags only the INPUT class. The companion runtime
fixture (``tests/conftest.py::no_credential_leak``) seeds sentinel
values into the env vars and asserts none escape to logs - that
catches RECOVERED-credential leaks if (and only if) the operator's
input happened to BE the same string the scanner recovered.

Snapshot-locked: drift in either direction fails the test, forcing
the developer to either fix the bug or explicitly remove the line
from the snapshot.
"""

from __future__ import annotations

import ast
import pathlib

from tests._ast_safe import safe_parse

import pytest

SRC_ROOT = pathlib.Path(__file__).resolve().parents[2] / "src" / "oida"
SNAPSHOT = pathlib.Path(__file__).resolve().parent / "credential_log_leak_snapshot.txt"

_USER_FACING_METHODS = {
    "info",
    "display",
    "warning",
    "warn",
    "fail",
    "success",
    # NOTE: .security_finding is intentionally EXCLUDED. It is the
    # dedicated channel for showing recovered credentials, default-cred
    # matches, and other findings the operator must see - hiding them
    # there would defeat the tool.
}

_CREDENTIAL_NAME_FRAGMENTS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api_key",
    "psk",
    "community",
    "lockcode",
    "lock_code",
    "auth_string",
    "auth_passwd",
    "creds",
)


def _is_input_credential(expr_text: str) -> bool:
    """True iff the interpolated expression reads a credential from `args`.

    Matches `args.password`, `self.args.password`, `getattr(args, "password")`,
    `getattr(self.args, "password", default)`. Does NOT match bare local
    names like `test_password` / `found_password` / `recovered` - those
    are recovered credentials (the finding itself).
    """
    txt = expr_text.lower()
    for frag in _CREDENTIAL_NAME_FRAGMENTS:
        # args.<frag> or self.args.<frag>
        if f"args.{frag}" in txt:
            return True
        # getattr(args | self.args, "<frag>", ...)
        if "getattr(" in txt and f'"{frag}"' in txt and "args" in txt:
            return True
        if "getattr(" in txt and f"'{frag}'" in txt and "args" in txt:
            return True
    return False


def _fstring_mentions_input_credential(node: ast.JoinedStr) -> bool:
    for piece in node.values:
        if not isinstance(piece, ast.FormattedValue):
            continue
        try:
            expr_text = ast.unparse(piece.value)
        except Exception:  # noqa: BLE001
            continue
        if _is_input_credential(expr_text):
            return True
    return False


def _collect_credential_log_sites() -> set[tuple[str, int]]:
    found = set()
    for py in SRC_ROOT.rglob("*.py"):
        rel = py.relative_to(SRC_ROOT).as_posix()
        try:
            tree = safe_parse(py.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (
                isinstance(node.func, ast.Attribute) and node.func.attr in _USER_FACING_METHODS
            ):
                continue
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr) and _fstring_mentions_input_credential(arg):
                    found.add((rel, node.lineno))
                    break
    return found


def _load_snapshot() -> set[tuple[str, int]]:
    snap = set()
    for line in SNAPSHOT.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rel, _, lineno = line.rpartition(":")
        snap.add((rel, int(lineno)))
    return snap


def test_credential_log_leak_snapshot_drift():
    """Snapshot lock - flag both regressions and unacknowledged fixes."""
    current = _collect_credential_log_sites()
    snapshot = _load_snapshot()

    added = current - snapshot
    removed = snapshot - current

    msg = []
    if added:
        msg.append(
            "NEW credential-log-leak sites detected - either fix them, or "
            "add them to credential_log_leak_snapshot.txt with a comment "
            "explaining why (and a tracking issue):"
        )
        msg.extend(f"  + {rel}:{ln}" for rel, ln in sorted(added))
    if removed:
        msg.append(
            "\nSnapshot entries no longer present in the AST scan - "
            "if you fixed these, REMOVE them from "
            "credential_log_leak_snapshot.txt:"
        )
        msg.extend(f"  - {rel}:{ln}" for rel, ln in sorted(removed))
    if msg:
        pytest.fail("\n".join(msg))


def test_predicate_self_check():
    """Predicate must detect a planted leak in a synthetic AST.

    If 0 real sites exist (today: clean state), the test above passes
    trivially. This guards against the predicate quietly regressing to
    a no-op - a synthetic ``logger.info(f"pw={self.args.password}")``
    must still be flagged.
    """
    synthetic = safe_parse(
        'logger.info(f"pw={self.args.password}")\n'
        'logger.success(f"recovered={found_password}")\n'  # NOT a leak - local
    )
    leaks = []
    for node in ast.walk(synthetic):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in _USER_FACING_METHODS:
                for arg in node.args:
                    if isinstance(arg, ast.JoinedStr) and _fstring_mentions_input_credential(arg):
                        leaks.append(node.lineno)
    assert leaks == [1], (
        f"Predicate self-check failed: expected line 1 flagged "
        f"(self.args.password), got {leaks}. Line 2 (local `found_password`) "
        f"must NOT be flagged - that's the recovered-credential feature."
    )
