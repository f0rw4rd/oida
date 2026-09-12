"""
Shared fixtures and helpers for fuzzer integration tests.

Consolidates duplicated helpers (timeout wrappers, config factories, port
checks) that were spread across test_definition_execution.py,
test_monitor_baseline.py, test_crash_detection_real.py, and the MMS test files.
"""

import os
import subprocess
import sys
import threading
from typing import Optional

import pytest

from tests.service_gate import require_port, require_service

from ..conftest import MOCK_HOST, MOCK_PORTS


# ============================================================================
# Timeout helpers
# ============================================================================


class FuzzTimeout(Exception):
    """Raised when a fuzz operation exceeds its time limit."""


def run_fuzz_with_timeout(func, timeout_seconds=30):
    """Run *func* in a daemon thread with a timeout.

    Returns a dict with keys:
      - exception: any exception raised by *func*, or None
      - completed: True if *func* returned normally
      - thread:    the Thread object (useful for checking ``is_alive()``)

    Raises ``FuzzTimeout`` if the thread is still running after
    *timeout_seconds*.
    """
    result = {"exception": None, "completed": False}

    def wrapper():
        try:
            func()
            result["completed"] = True
        except Exception as e:
            result["exception"] = e

    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)
    result["thread"] = thread

    if thread.is_alive():
        raise FuzzTimeout(f"Fuzz timed out after {timeout_seconds}s")

    if result["exception"]:
        raise result["exception"]

    return result


def run_fuzz_capture(fuzzer, timeout_seconds=60):
    """Run ``fuzzer.fuzz_all()`` and return the result dict **without** raising.

    Unlike ``run_fuzz_with_timeout`` this never raises — the caller inspects
    the returned dict to decide what happened.  Used by crash-detection tests
    that need the thread reference for ``is_alive()`` checks.

    Returns a dict with keys:
      - exception: any exception raised by ``fuzz_all()``, or None
      - completed: True if ``fuzz_all()`` returned normally
      - thread:    the Thread object
    """
    result = {"exception": None, "completed": False}

    def wrapper():
        try:
            fuzzer.fuzz_all()
            result["completed"] = True
        except Exception as e:
            result["exception"] = e

    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)
    result["thread"] = thread
    return result


# ============================================================================
# Config factory
# ============================================================================


def create_fuzzer_config(host, port, protocol, session_path, **overrides):
    """Build a ``FuzzerConfig`` with sensible test defaults.

    Keyword arguments in *overrides* are set as attributes on the returned
    config object, so callers can customise any field::

        cfg = create_fuzzer_config(
            host, port, "modbus", session,
            index_end=20,
            monitor_config=MonitorConfig.parse("modbus:5,socket"),
        )
    """
    from oida.fuzz.core.config import FuzzerConfig, MonitorConfig

    config = FuzzerConfig(
        target_ip=host,
        target_port=port,
        protocol=protocol,
        session_filename=session_path,
        index_end=overrides.pop("index_end", 5),
        log_session=overrides.pop("log_session", False),
        console_output=overrides.pop("console_output", False),
        web_interface=overrides.pop("web_interface", False),
        enumerate=overrides.pop("enumerate", False),
        skip_pre_send_checks=overrides.pop("skip_pre_send_checks", True),
        monitor_config=overrides.pop("monitor_config", MonitorConfig.parse("none")),
        boofuzz_db=overrides.pop("boofuzz_db", False),
        reuse_target_connection=overrides.pop("reuse_target_connection", True),
    )

    # Apply remaining overrides as attributes
    for key, value in overrides.items():
        if not hasattr(config, key):
            raise AttributeError(f"FuzzerConfig has no attribute '{key}'")
        setattr(config, key, value)

    return config


# ============================================================================
# Docker mock availability
# ============================================================================


def require_docker_mock(port_key):
    """Gate the current test if the Docker mock for *port_key* is not reachable."""
    port = MOCK_PORTS.get(port_key)
    if not port:
        require_service(f"Docker mock '{port_key}' has no configured port")
        return
    require_port(MOCK_HOST, port, f"Docker mock '{port_key}'")


# ============================================================================
# Session fixture
# ============================================================================


@pytest.fixture(autouse=True)
def _fuzz_logging_context():
    """Ensure the ICS logging context is set for fuzz tests.

    Several fuzzer internals (TestCaseManager, state machines) call
    ``get_context()`` and raise ``RuntimeError`` if no context exists.
    Set a default context so these paths succeed in test environments.
    """
    try:
        from oida.utils.ics_logger import set_context, get_context

        if get_context() is None:
            set_context("FUZZ-TEST", "127.0.0.1", 9999)
    except Exception:
        pass
    yield


@pytest.fixture
def fuzz_session(tmp_path):
    """Temp session path for fuzzer tests."""
    return str(tmp_path / "fuzz_session")


# ============================================================================
# CLI helper
# ============================================================================


class FuzzCLIResult:
    """Captured result from running ``oida fuzz`` as a subprocess."""

    def __init__(
        self,
        returncode: int,
        stdout: str,
        stderr: str,
        timed_out: bool = False,
    ):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


def run_fuzz_cli(
    *args: str,
    timeout: int = 30,
    env: Optional[dict] = None,
) -> FuzzCLIResult:
    """Run ``python -m oida.cli fuzz <args>`` as a subprocess.

    Returns a ``FuzzCLIResult`` even on timeout (with ``timed_out=True``).
    """
    cmd = [sys.executable, "-m", "oida.cli", "fuzz"] + list(args)

    run_env = os.environ.copy()
    if env:
        run_env.update(env)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=run_env,
        )
        return FuzzCLIResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode() if e.stdout else ""
        stderr = e.stderr.decode() if e.stderr else ""
        return FuzzCLIResult(
            returncode=-1,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
        )


# ============================================================================
# Protocol port fixtures
# ============================================================================


@pytest.fixture
def modbus_port(mock_ports):
    """Modbus Docker mock port."""
    return mock_ports.get("modbus", 502)


@pytest.fixture
def mms_port(mock_ports):
    """MMS Docker mock port."""
    return mock_ports.get("mms", 102)


@pytest.fixture
def mms_host(mock_host):
    """MMS Docker mock host."""
    return mock_host
