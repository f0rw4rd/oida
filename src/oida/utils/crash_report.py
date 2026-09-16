"""Crash bug-catcher: turn an unexpected internal exception into a sanitized,
pre-filled GitHub "new issue" URL instead of a raw traceback.

Design summary
---------------
- **Bug vs. operational failure.** Fires only for exceptions that are not
  already part of OIDA's expected-failure vocabulary: subclasses of
  ``ICSProtocolError`` (typed protocol errors), ``OSError`` (covers
  ``ConnectionError``, ``TimeoutError``, ``PermissionError``,
  ``socket.gaierror``, etc. per Python 3.10+ convention), ``ImportError``
  (missing optional dependency), and control-flow exceptions
  (``KeyboardInterrupt``/``SystemExit``/``GeneratorExit``). Everything else
  (``AttributeError``, ``TypeError``, ``KeyError``, ...) is treated as a
  genuine internal bug.
- **Default-on, opt-out.** No flag is required to get a report; pass
  ``--no-bug-report`` or set ``OIDA_NO_BUG_REPORT=1`` to suppress it (e.g.
  for CI/scripted runs where the block would just be noise). The operator
  still has to click the printed link, and GitHub's new-issue form is fully
  editable before submit, so nothing ever leaves the machine automatically.
- **Never auto-opens a browser, never submits anything.** Only a URL is
  printed.
- **Permissive argv.** Target hosts, flag names and most flag values are
  reproduced verbatim (they're the repro context, and the operator reviews
  the form before submitting). The one exception: the *value* of any flag
  whose name matches ``password|passwd|secret|key|token|auth``
  (case-insensitively), plus the short flag ``-P``, is redacted — a
  credential is never useful for reproducing a crash.
- **Traceback text** keeps IPs/hostnames (also repro context) but strips the
  user's home directory prefix, and never includes local-variable dumps
  (plain ``traceback.format_exception`` doesn't capture them; keep it that
  way).
- **Threading:** a scan can hit the same bug on every target in a
  thread pool. Reports are deduplicated by a fingerprint (exception type +
  normalized message + deepest OIDA stack frame) so a bug fires once per
  unique fingerprint, not once per thread/target. Blocks are queued by
  :func:`record` and only emitted by an explicit :func:`flush` call, so the
  CLI can print them once, after the "Completed N targets" summary line,
  instead of interleaved with per-target progress output.
- **URL length.** GitHub new-issue URLs are safe up to roughly 6-8k chars in
  current browsers. If the sanitized report doesn't fit under
  :data:`MAX_URL_LENGTH`, the traceback is truncated (oldest lines first,
  keeping the frames closest to the failure) and the full, still-sanitized
  report is always written to :data:`CRASH_REPORT_DIR` so it can be
  attached manually.

This module must never itself raise or slow down the exception path it is
attached to: every public entry point is defensive (best-effort, silent
fallback on any internal failure).
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import quote

from oida.utils.exceptions import ICSProtocolError

GITHUB_REPO_URL = "https://github.com/f0rw4rd/oida"
MAX_URL_LENGTH = 6000
CRASH_REPORT_DIR = Path.home() / ".oida" / "crash_reports"

# Exceptions that represent expected operational failures, not bugs.
_OPERATIONAL_EXCEPTION_TYPES = (ICSProtocolError, OSError, ImportError, EOFError)
# Control-flow exceptions: never a "bug", never reported.
_NEVER_REPORT = (KeyboardInterrupt, SystemExit, GeneratorExit)

# Credential terms. A long flag's value is redacted when ANY of its
# hyphen/underscore-separated parts equals one of these. Whole-part (not
# substring) matching is deliberate: it catches --snmp-priv-pass, --psk and
# --tls-pin while NOT firing on --no-passive ("passive") or --no-ping ("ping"),
# which a naive `"pass" in flag` / `"pin" in flag` substring test would wrongly
# redact (and, for store_true flags, wrongly redact the following token). We err
# toward over-redaction for genuine credential parts — losing a bit of repro
# context is acceptable; leaking a passphrase into a crash report is not.
_CRED_TERMS = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "passphrase",
        "secret",
        "token",
        "psk",
        "pin",
        "priv",
        "cred",
        "creds",
        "credential",
        "credentials",
        "passwords",
        "key",
        "keys",
        "auth",
        "privatekey",
        "privkey",
        # Smashed (no-separator) forms the [-_] split would otherwise miss.
        "apikey",
        "secretkey",
        "keyfile",
        "keystore",
        "authtoken",
        "sessionkey",
    }
)
# Value-bearing credential short flags whose next token (or attached value) is
# redacted: -P (password, nxc convention), -X (SNMPv3 privacy passphrase).
_CRED_SHORT_FLAGS = {"-P", "-X"}


def _is_cred_flag(flag_name: str) -> bool:
    """True if *flag_name* (no leading dashes) names a credential-bearing flag."""
    return any(part in _CRED_TERMS for part in re.split(r"[-_]", flag_name.lower()))


_lock = threading.Lock()
_seen_fingerprints: set = set()
_pending_blocks: List[str] = []


def is_reportable_exception(exc: BaseException) -> bool:
    """Return True if *exc* looks like a genuine internal bug, not an
    expected operational failure (connection refused, timeout, missing
    optional dependency, bad target, permission denied, ...)."""
    if isinstance(exc, _NEVER_REPORT):
        return False
    if isinstance(exc, _OPERATIONAL_EXCEPTION_TYPES):
        return False
    return True


def _opt(args, name: str, default=None):
    """Best-effort read of *name* from an argparse Namespace, a plain dict,
    or BaseScanner's dict/attribute arg-bridge — whichever the caller
    happens to be holding."""
    if args is None:
        return default
    dashed = name.replace("_", "-")
    getter = getattr(args, "get", None)
    if callable(getter):
        try:
            sentinel = object()
            val = getter(name, sentinel)
            if val is sentinel:
                val = getter(dashed, sentinel)
            if val is not sentinel:
                return val
        except TypeError:
            pass
    if hasattr(args, name):
        return getattr(args, name)
    if hasattr(args, dashed):
        return getattr(args, dashed)
    return default


def is_suppressed(args=None) -> bool:
    """Return True if the crash reporter has been opted out via
    ``--no-bug-report`` or ``OIDA_NO_BUG_REPORT``."""
    if os.environ.get("OIDA_NO_BUG_REPORT"):
        return True
    return bool(_opt(args, "no_bug_report", False))


def sanitize_argv(argv: List[str]) -> List[str]:
    """Redact credential-looking flag values from *argv*.

    Everything else (targets, protocol name, non-credential flag values) is
    kept verbatim — it's the repro context, and the operator reviews the
    prefilled GitHub form before submitting.
    """
    out: List[str] = []
    redact_next = False
    for tok in argv:
        if redact_next:
            redact_next = False
            # A credential-*named* store_true flag (e.g. --default-creds,
            # --test-reinit-pass, or -X in hl7/pcap/iec104 where it is NOT the
            # SNMPv3 passphrase) consumes no value: the following token is the
            # next flag, not a secret. Only redact a token that actually looks
            # like a value — one that does not itself start with "-". Otherwise
            # fall through and process it as its own (possibly credential) flag,
            # so we never clobber, and thereby leak the value of, a real
            # credential flag that happens to follow a boolean one.
            if not tok.startswith("-"):
                out.append("***")
                continue
            # else: fall through to normal processing of this flag token.

        if tok.startswith("--") and "=" in tok:
            flag, _, _val = tok.partition("=")
            flag_name = flag.lstrip("-")
            if _is_cred_flag(flag_name):
                out.append(f"{flag}=***")
            else:
                out.append(tok)
            continue

        if tok.startswith("--"):
            flag_name = tok.lstrip("-")
            out.append(tok)
            if _is_cred_flag(flag_name):
                redact_next = True
            continue

        # Short flag forms: "-P" (value in the next token) or "-Pvalue"
        # (attached, argparse also accepts this for single-char options).
        if tok in _CRED_SHORT_FLAGS:
            out.append(tok)
            redact_next = True
            continue
        if any(tok.startswith(f) and len(tok) > 2 for f in _CRED_SHORT_FLAGS):
            out.append(f"{tok[:2]}***")
            continue

        out.append(tok)
    return out


def sanitize_traceback(tb_text: str) -> str:
    """Strip the user's home directory from traceback file paths. IPs and
    hostnames are intentionally left in place (repro context); no
    local-variable dump is ever included (plain ``traceback.format_exception``
    doesn't capture locals)."""
    home = os.path.expanduser("~")
    if home and home != "~":
        tb_text = tb_text.replace(home, "~")
    return tb_text


def truncate_traceback(tb_text: str, max_chars: int) -> Tuple[str, bool]:
    """Trim *tb_text* to at most *max_chars*, keeping the tail (the frames
    closest to the failure) and prepending a truncation marker. Returns
    ``(text, was_truncated)``."""
    if len(tb_text) <= max_chars:
        return tb_text, False
    marker = "... (earlier traceback lines omitted; see local file for full details) ...\n"
    keep_chars = max(max_chars - len(marker), 0)
    truncated = tb_text[-keep_chars:] if keep_chars else ""
    nl = truncated.find("\n")
    if nl != -1:
        truncated = truncated[nl + 1 :]
    return marker + truncated, True


def _normalized_message(exc: BaseException) -> str:
    msg = str(exc)
    return re.sub(r"\d+", "#", msg)


def _deepest_oida_frame(tb) -> Optional[traceback.FrameSummary]:
    frames = traceback.extract_tb(tb)
    for frame in reversed(frames):
        if "oida" in frame.filename and "site-packages" not in frame.filename:
            return frame
    return frames[-1] if frames else None


def _fingerprint(exc: BaseException, protocol: str) -> str:
    frame = _deepest_oida_frame(exc.__traceback__)
    frame_part = f"{frame.filename}:{frame.lineno}:{frame.name}" if frame else "?"
    return f"{protocol}:{type(exc).__name__}:{_normalized_message(exc)}:{frame_part}"


def build_issue_url(title: str, body: str) -> str:
    return f"{GITHUB_REPO_URL}/issues/new?title={quote(title)}&labels=bug&body={quote(body)}"


def _environment_lines() -> List[str]:
    """A fast, dependency-free environment summary. Deliberately lighter
    than ``oida.cli.print_bug_report()``, which imports every protocol
    module and shells out to list installed packages — too slow and
    non-deterministic to run inside an exception handler."""
    import platform

    from oida import __version__

    lines = [
        f"- OIDA version: {__version__}",
        f"- Python: {sys.version.split()[0]} ({sys.implementation.name})",
        f"- Platform: {platform.platform()}",
        f"- OS: {platform.system()} {platform.release()}",
    ]
    return lines


def _write_crash_file(fingerprint: str, content: str) -> Optional[Path]:
    try:
        CRASH_REPORT_DIR.mkdir(parents=True, exist_ok=True)
        digest = f"{abs(hash(fingerprint)) % 0xFFFFFFFF:08x}"
        path = CRASH_REPORT_DIR / f"oida-crash-{int(time.time())}-{digest}.txt"
        path.write_text(content, encoding="utf-8")
        return path
    except OSError:
        return None


def _format_block(
    exc: BaseException,
    *,
    protocol: str,
    args=None,
    context: str = "",
    argv: Optional[List[str]] = None,
) -> str:
    raw_argv = argv if argv is not None else sys.argv[1:]
    safe_argv = sanitize_argv(raw_argv)
    repro_cmd = "oida " + " ".join(safe_argv) if safe_argv else f"oida {protocol} <target>"

    full_tb = sanitize_traceback(
        "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    )

    title = f"[bug] {type(exc).__name__} in {protocol}"[:120]

    def _body(tb_text: str, crash_file_note: str) -> str:
        parts = [
            "## Summary",
            "",
            f"Unexpected `{type(exc).__name__}` while running the `{protocol}` scanner"
            + (f" ({context})" if context else "")
            + ".",
            "",
            "_Auto-generated by OIDA's crash reporter — please review/edit before submitting._",
            "",
            "## Reproduce",
            "",
            "```bash",
            repro_cmd,
            "```",
            "",
            "## Expected behaviour",
            "",
            "No unhandled exception.",
            "",
            "## Actual behaviour",
            "",
            "```",
            tb_text,
            "```",
            "",
            "## Environment",
            "",
            *_environment_lines(),
            "",
            "## Anything else",
            "",
            crash_file_note,
            "",
        ]
        return "\n".join(parts)

    fingerprint = _fingerprint(exc, protocol)
    crash_file = _write_crash_file(fingerprint, _body(full_tb, "(full report saved locally)"))
    crash_file_note = f"Full sanitized report saved locally at: {crash_file}" if crash_file else ""

    # Fit the URL under MAX_URL_LENGTH by shrinking the traceback budget.
    budget = len(full_tb)
    url = None
    body = None
    truncated = False
    while True:
        tb_text, was_truncated = truncate_traceback(full_tb, budget)
        body = _body(tb_text, crash_file_note)
        url = build_issue_url(title, body)
        truncated = truncated or was_truncated
        if len(url) <= MAX_URL_LENGTH or budget <= 200:
            break
        budget = int(budget * 0.6)

    lines = [
        "",
        f"[-] Unexpected error while scanning ({protocol}): {type(exc).__name__}: {exc}",
        "",
        "  This looks like a bug in OIDA, not your target.",
        "  A sanitized crash report has been prepared. Review it, then click (or copy)",
        "  the link below to open a pre-filled GitHub issue. Nothing is sent",
        "  automatically -- you control what gets submitted.",
        "",
    ]
    if crash_file:
        lines.append(f"  Full details (sanitized) saved to: {crash_file}")
        lines.append("")
    if truncated:
        lines.append("  (traceback truncated to keep the URL a reasonable length)")
        lines.append("")
    lines.append(f"  {url}")
    lines.append("")
    return "\n".join(lines)


def record(
    exc: BaseException,
    *,
    protocol: str = "unknown",
    args=None,
    argv: Optional[List[str]] = None,
    context: str = "",
) -> None:
    """Queue a crash report block for *exc*, if it looks like a genuine bug
    and hasn't already been reported this run. Never prints — call
    :func:`flush` to emit queued blocks. Never raises."""
    try:
        if is_suppressed(args):
            return
        if not is_reportable_exception(exc):
            return
        fingerprint = _fingerprint(exc, protocol)
        with _lock:
            if fingerprint in _seen_fingerprints:
                return
            _seen_fingerprints.add(fingerprint)
        block = _format_block(exc, protocol=protocol, args=args, context=context, argv=argv)
        with _lock:
            _pending_blocks.append(block)
    except Exception:
        # The crash reporter must never itself crash or mask the original
        # exception.
        return


def flush(print_fn=None) -> int:
    """Print and clear all queued crash-report blocks. Returns the number of
    blocks printed."""
    printer = print_fn or print
    with _lock:
        blocks, _pending_blocks_copy = _pending_blocks[:], None
        _pending_blocks.clear()
    for block in blocks:
        try:
            printer(block)
        except Exception:
            pass
    return len(blocks)


def reset_for_tests() -> None:
    """Test-only helper: clear dedup/queue state between test cases."""
    with _lock:
        _seen_fingerprints.clear()
        _pending_blocks.clear()
