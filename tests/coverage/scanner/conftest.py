"""Shared fixtures for axis-1 scanner field-coverage tests.

Provides:
- ``container_target(name, port, proto)`` — check whether a docker mock
  container is reachable on the host; skips the test if not.
- ``scanner_result(protocol, host, port, **opts)`` — instantiate the
  Layer-2 NXC class against the target, return its ``results`` dict.
- ``flatten_surface(data)`` — flatten nested dict into dot-notation key
  set for set-difference comparison with expected surface.
"""

from __future__ import annotations

import argparse
import os
import socket
from contextlib import closing
from typing import Any, Iterable

import pytest


def _is_reachable(host: str, port: int, timeout: float = 1.0, udp: bool = False) -> bool:
    """Check whether a host:port is reachable.

    For TCP, a successful 3-way handshake counts. For UDP we can't
    test reachability without a protocol-aware probe, so we fall back
    to "is the container even up?" by checking whether the docker
    daemon reports a published port — handled by the caller via the
    ``OIDA_COVERAGE_HOST`` env var and the per-test scanner trying its
    own connection. Returns False for UDP only when no container at
    all is published on the host (no listening TCP control plane).
    """
    if udp:
        # UDP "connect" doesn't actually probe anything. We can't reliably
        # detect a missing UDP listener without sending a real protocol
        # frame, so trust the scanner to fail honestly and convert that
        # to a skip via ``ensure_protocol_dep``.
        return True
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            return True
    except OSError:
        return False


def ensure_protocol_dep(*module_names: str) -> None:
    """Skip the test if any required Python dep is missing.

    Many scanners (bacnet → bacpypes3, opcua → asyncua, ads → pyads) ship
    as optional extras. The coverage tests don't help if the dep isn't
    installed; skip rather than fail.
    """
    import importlib

    missing = []
    for name in module_names:
        try:
            importlib.import_module(name)
        except ImportError:
            missing.append(name)
    if missing:
        pytest.skip(
            f"missing optional dep(s): {missing}; install via `pip install -e .[<protocol>]`"
        )


@pytest.fixture(scope="session")
def coverage_results_dir() -> str:
    """Where scanner coverage JSON output lands."""
    root = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(root, exist_ok=True)
    return os.path.abspath(root)


def make_args(**overrides: Any) -> argparse.Namespace:
    """Construct an argparse.Namespace with sensible scanner defaults.

    Tests can override individual flags (``port``, ``timeout``, etc.)
    via keyword arguments. The defaults match what ``oida <proto> host``
    would produce on the CLI with no extra flags.
    """
    defaults = {
        "verbose": 0,
        "debug": False,
        "quiet": True,
        "timeout": 3,
        "threads": 1,
        "format": "json",
        "output": None,
        "port": None,
        "confirm": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _flatten(data: Any, prefix: str = "") -> Iterable[str]:
    """Yield dot-notation key paths for non-empty leaves of a nested dict.

    Lists count as a leaf at their parent path; we don't recurse into
    list elements — the goal is "which top-level capabilities were
    exercised", not "how many objects came back".
    """
    if isinstance(data, dict):
        if not data:
            return
        for k, v in data.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict) and v:
                yield path
                yield from _flatten(v, prefix=path)
            elif isinstance(v, (list, tuple)) and v:
                yield path
            elif v not in (None, "", 0, False):
                yield path
    elif data not in (None, "", 0, False):
        if prefix:
            yield prefix


def flatten_surface(results_data: dict) -> set[str]:
    """Return the set of populated ``results["data"]`` key paths."""
    return set(_flatten(results_data))


def container_target(
    *candidates: tuple[str, int],
    udp: bool = False,
) -> tuple[str, int, str]:
    """Try multiple (container_name, port) pairs and return the first reachable one.

    Returns ``(host, port, container_name)``. Calls ``pytest.skip`` if no
    candidate is reachable. Host is always ``127.0.0.1`` because
    `services.py up` publishes container ports to the host.

    Examples
    --------
    >>> # Prefer the Python mock, fall back to Conpot
    >>> host, port, name = container_target(
    ...     ("modbus-mock", 502),
    ...     ("modbus-conpot", 5503),
    ... )
    """
    host = os.environ.get("OIDA_COVERAGE_HOST", "127.0.0.1")
    tried = []
    for name, port in candidates:
        if _is_reachable(host, port, udp=udp):
            return host, port, name
        tried.append(f"{name}@{port}")
    pytest.skip(
        f"no candidate container reachable on {host} (udp={udp}); "
        f"tried {tried}; run `python services.py up` first"
    )
