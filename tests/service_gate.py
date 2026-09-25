"""Fail-by-default gate for availability / dependency / environment guards.

A defensive-security test suite that goes *green* while whole protocols are
silently skipped (because a mock wasn't started or an optional dependency isn't
installed) gives false confidence. So by default a missing service/dependency
is a **hard failure**.

Set ``OIDA_SKIP_MISSING_SERVICES=1`` in the environment to turn these back into
skips - useful for running a subset locally without the full mock + dependency
matrix. CI and ``scripts/run-all-tests.sh`` intentionally leave it unset.

This is a plain module (not a fixture) so it can be used at import time, e.g. as
a drop-in for ``pytest.importorskip`` at module scope.
"""

from __future__ import annotations

import importlib
import os
import socket
from types import ModuleType
from typing import Optional

import pytest

ENV_VAR = "OIDA_SKIP_MISSING_SERVICES"


def _strict() -> bool:
    """True when unavailability should fail; False when it should skip."""
    return os.environ.get(ENV_VAR) not in ("1", "true", "True", "yes")


def require_service(reason: str) -> None:
    """Fail (strict, default) or skip (escape hatch) because something is unavailable.

    Use for any availability / dependency / environment guard: a mock that is not
    reachable, an optional dependency that is not installed, a native library or
    kernel capability that is missing, or an unhealthy container.
    """
    if _strict():
        pytest.fail(reason, pytrace=False)
    else:
        pytest.skip(reason)


def require_import(modname: str, reason: Optional[str] = None) -> ModuleType:
    """Import ``modname`` or gate. Drop-in replacement for ``pytest.importorskip``.

    Returns the imported module so ``mod = require_import("x")`` keeps working.
    Unlike ``importorskip`` (which always skips), a missing module fails by
    default.
    """
    try:
        return importlib.import_module(modname)
    except ImportError as exc:
        msg = reason or f"missing optional dependency: {modname!r} ({exc})"
        require_service(msg)
        raise  # unreachable (require_service raises), but keeps type checkers happy


def require_port(host: str, port: int, name: str, timeout: int = 3) -> None:
    """Gate unless a TCP ``host:port`` accepts a connection.

    Replaces the ``if not check_port_open(...): pytest.skip(...)`` idiom that was
    duplicated across test modules.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return
    except (OSError, socket.timeout):
        require_service(
            f"{name} not reachable at {host}:{port} - run `python services.py up` first"
        )
