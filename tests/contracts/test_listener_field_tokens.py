"""Contract: passive-listener field tokens must resolve to real tshark fields.

OIDA's passive PCAP listeners (``src/oida/pcap/*.py``) read dissector fields via
``self.get_field(layer, "name")`` / ``get_field_any(layer, ...)``. ``get_field``
swallows a miss and returns the default, so a *wrong* field name (one that no
tshark dissector emits) silently extracts nothing — with no error, no log, and
(for most listeners) no test that would notice. A real audit found ~24 listeners
reading tokens that resolve to no field at all (cotp ``tsap_calling`` vs the real
``src-tsap``; tls ``handshake_ja3_hash`` vs ``tls.handshake.ja3``; glbp
``hello_hellotime`` vs ``glbp.hello.helloint`` …).

This guard parses every listener statically, extracts the ``get_field`` /
``get_field_any`` tokens it reads, and validates them against the *installed*
``tshark -G fields`` dictionary using the EK-mode reachability rule (verified
against OIDA's real ``get_field``):

    a dissector field ``proto.a.b-c`` is reachable at runtime as the token
    ``a_b-c`` — proto prefix stripped, dots -> underscores, **hyphens preserved**.

A token is accepted if it matches a reachable form of *any* dissector field
(global union). This deliberately errs toward false-negatives over
false-positives: a name that exists for some other protocol passes, but a name
that exists nowhere (the proven silent-failure mode) is caught. Only the safe
``get_field`` / ``get_field_any`` API is scanned — bare ``getattr`` reads are
skipped, since they also fetch pyshark internals and listener-synthesized keys.

A committed baseline (``listener_field_tokens_baseline.json``) records the tokens
known-bad today so this lands green and only ratchets down: the test fails if a
*new* unreachable token appears, or if a baselined token has since become valid
(forcing its removal when a listener is fixed). Reasons:
  - ``broken``    — wrong name; fix the listener, then drop the baseline entry.
  - ``synthetic`` — a value the listener constructs, not a tshark field
                    (e.g. modbus ``regval16`` fallback). Permanent.

Local-only: shelling out to ``tshark`` is slow and version-bound, so this skips
when tshark is absent (mirrors ``test_uv_lockfile_drift.py``). It is not wired
into CI; run it locally / pre-push.

Regenerate the baseline after fixing listeners:
    uv run python tests/contracts/test_listener_field_tokens.py > \
        tests/contracts/listener_field_tokens_baseline.json
"""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
from difflib import get_close_matches
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _ast_safe import safe_parse  # noqa: E402  (tests/_ast_safe.py)

_ROOT = Path(__file__).resolve().parent.parent.parent
_LISTENER_DIR = _ROOT / "src" / "oida" / "pcap"
_BASELINE = Path(__file__).resolve().parent / "listener_field_tokens_baseline.json"

# Listener files that are not protocol listeners (no PROTOCOL_NAME / not scanned).
_SKIP_FILES = frozenset(
    {"__init__.py", "pyshark_base.py", "listener_registry.py", "_iec_common.py"}
)


# ---------------------------------------------------------------------------
# tshark field dictionary  ->  per-layer set of EK-reachable token forms
# ---------------------------------------------------------------------------
def _tshark_fields() -> dict[str, list[str]]:
    """{layer-root: [filter_name, ...]} from ``tshark -G fields`` (col 3).

    Mirrors ``tools/audit_listener_fields.py::_get_all_dissector_fields`` but
    returns only the filter names, grouped by the first dotted component (the
    pyshark layer name).
    """
    r = subprocess.run(["tshark", "-G", "fields"], capture_output=True, text=True, timeout=90)
    if r.returncode != 0:
        raise RuntimeError(f"tshark -G fields failed: {r.stderr[:200]}")
    by_layer: dict[str, list[str]] = {}
    for line in r.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) < 5 or cols[0] != "F":
            continue
        filter_name = cols[2]
        if "." not in filter_name:
            continue
        root = filter_name.split(".", 1)[0]
        by_layer.setdefault(root, []).append(filter_name)
    return by_layer


def _reachable_tokens(by_layer: dict[str, list[str]]) -> set[str]:
    """Global set of every token suffix that resolves to *some* dissector field.

    For each abbrev we collapse dots to underscores (hyphens preserved, since EK
    keeps them) and add every underscore-bounded suffix. The suffixes model
    pyshark's nested resolution: a leaf token like ``szl_id`` resolves against the
    field ``s7comm.data.userdata.szl_id`` (EK key ...``_data_userdata_szl_id``),
    and a mid-path token like ``configure_request_password`` against
    ``cipsafety.ssupervisor.configure_request.password``. Generous on the valid
    side so only tokens that exist *nowhere* (the proven silent-failure mode) are
    flagged; matched against ``token.replace('.', '_')`` so hyphen/underscore form
    stays faithful to runtime (``dst-tsap`` resolves, ``dst_tsap`` does not).
    """
    out: set[str] = set()
    for names in by_layer.values():
        for abbr in names:
            parts = abbr.replace(".", "_").split("_")
            for i in range(len(parts)):
                out.add("_".join(parts[i:]))
    return out


# ---------------------------------------------------------------------------
# Static extraction of field-token lookups from a listener
# ---------------------------------------------------------------------------
def _literal(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _extract(path: Path) -> list[list[str]]:
    """Return the get_field / get_field_any lookups in one listener module.

    Each lookup is a list of candidate tokens; it is valid when ANY candidate
    resolves (get_field_any semantics; get_field has a single candidate). Bare
    ``getattr`` reads are intentionally NOT scanned — they also fetch pyshark
    internals (``_all_fields``) and listener-synthesized keys (``*_passive_data``).
    """
    tree = safe_parse(path.read_text())
    lookups: list[list[str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not (isinstance(fn, ast.Attribute) and fn.attr in ("get_field", "get_field_any")):
            continue
        if fn.attr == "get_field":
            if len(node.args) >= 2 and (s := _literal(node.args[1])):
                lookups.append([s])
        else:  # get_field_any(layer, "a", "b", ...)
            cands = [s for a in node.args[1:] if (s := _literal(a))]
            if cands:
                lookups.append(cands)
    return lookups


def _token_ok(token: str, reachable: set[str]) -> bool:
    if not token or token.replace("_", "").replace("-", "").isdigit():
        return True  # empty / numeric default slipped through
    return token.replace(".", "_") in reachable


def compute_invalid() -> dict[str, list[str]]:
    """{listener_file: sorted[unreachable token, ...]} for the current tree."""
    reachable = _reachable_tokens(_tshark_fields())
    result: dict[str, set[str]] = {}
    for path in sorted(_LISTENER_DIR.glob("*.py")):
        if path.name in _SKIP_FILES:
            continue
        for cands in _extract(path):
            if not any(_token_ok(c, reachable) for c in cands):
                result.setdefault(path.name, set()).add(cands[0])
    return {k: sorted(v) for k, v in sorted(result.items())}


def _nearest(token: str, reachable: set[str]) -> str:
    m = get_close_matches(token, reachable, n=1, cutoff=0.6)
    return m[0] if m else "?"


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def _tshark():
    if not shutil.which("tshark"):
        pytest.skip("tshark not installed — field-token guard is local-only")


@pytest.fixture(scope="module")
def _baseline() -> dict[str, list[str]]:
    if not _BASELINE.exists():
        return {}
    raw = json.loads(_BASELINE.read_text())
    # baseline schema: {listener: {token: reason}}  ->  {listener: {tokens}}
    return {k: set(v) for k, v in raw.items()}


class TestListenerFieldTokens:
    def test_no_unbaselined_invalid_tokens(self, _tshark, _baseline):
        """Every get_field token resolves to a real tshark field, or is baselined."""
        reachable = _reachable_tokens(_tshark_fields())
        current = compute_invalid()

        new_bad: list[str] = []
        for listener, tokens in current.items():
            for token in tokens:
                if token not in _baseline.get(listener, set()):
                    new_bad.append(
                        f"  {listener}: get_field({token!r}) -> no such tshark field "
                        f"(nearest: {_nearest(token, reachable)})"
                    )

        # baselined tokens that are now valid must be removed (ratchet down)
        stale: list[str] = []
        for listener, tokens in _baseline.items():
            still_bad = set(current.get(listener, []))
            for token in sorted(tokens):
                if token not in still_bad:
                    stale.append(f"  {listener}: {token!r}")

        msgs = []
        if new_bad:
            msgs.append(
                "New unreachable field token(s) — the listener reads a field name "
                "that no installed tshark dissector emits, so extraction is silently "
                "empty. Use the correct EK token (dots->_, hyphens kept):\n" + "\n".join(new_bad)
            )
        if stale:
            msgs.append(
                "Baselined token(s) now resolve — a listener was fixed. Remove these "
                "from listener_field_tokens_baseline.json so the guard stays tight:\n"
                + "\n".join(stale)
            )
        if msgs:
            pytest.fail("\n\n".join(msgs))


if __name__ == "__main__":
    # Regenerate the baseline: emit {listener: {token: "broken"}} for the
    # current tree. Existing 'synthetic' reasons are preserved if a baseline
    # already exists.
    prev = json.loads(_BASELINE.read_text()) if _BASELINE.exists() else {}
    out: dict[str, dict[str, str]] = {}
    for listener, tokens in compute_invalid().items():
        out[listener] = {}
        for tok in tokens:
            out[listener][tok] = prev.get(listener, {}).get(tok, "broken")
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
