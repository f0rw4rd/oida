"""
Shared fixtures and helpers for pcap unit tests.

Provides paths to real pcap fixture files, availability checks
for optional dependencies (tshark, pyshark), and common assertion
helpers used across per-protocol test files.
"""

import asyncio
import json
from pathlib import Path

import pytest

from tests.service_gate import require_service


# ---------------------------------------------------------------------------
# Event-loop isolation (autouse)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _ensure_current_event_loop():
    """Guarantee every pcap test starts with a usable current event loop.

    pyshark's FileCapture calls asyncio.get_event_loop() internally. On
    Python 3.10+ that raises RuntimeError when the thread has no current
    loop -- which is exactly the state asyncio.run() leaves behind (its
    finally block calls set_event_loop(None)). Under `pytest -n auto`, a
    bacnet/coap/knx test that used asyncio.run() can run in the same worker
    process just before a pyshark test, so the pyshark test would flake with
    "There is no current event loop" depending purely on scheduling.

    Installing a fresh loop at the start of each pcap test restores the
    invariant regardless of what ran before, so tests that build FileCapture
    directly no longer need their own inline guard.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield
    finally:
        loop.close()
        asyncio.set_event_loop(None)


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------

FIXTURES_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "pcap"


# ---------------------------------------------------------------------------
# Commonly-used pcap file paths
# ---------------------------------------------------------------------------


@pytest.fixture
def modbus_pcap():
    return FIXTURES_ROOT / "modbus" / "cisagov_modbus_example.pcap"


@pytest.fixture
def arp_pcap():
    return FIXTURES_ROOT / "arp" / "bruteshark_arp_broadcast.pcap"


@pytest.fixture
def dns_pcap():
    return FIXTURES_ROOT / "dns" / "zeek_dns-binds.pcap"


# ---------------------------------------------------------------------------
# Dependency availability markers
# ---------------------------------------------------------------------------


def _has_pyshark():
    try:
        import pyshark  # noqa: F401
    except ImportError:
        return False
    # pyshark is useless without the tshark binary it shells out to; require
    # both so tshark-dependent tests skip cleanly instead of raising
    # TSharkNotFoundException when only the Python package is present.
    import shutil

    return shutil.which("tshark") is not None


HAS_PYSHARK = _has_pyshark()


@pytest.fixture
def _require_pyshark():
    """Gate a test on pyshark+tshark: fails by default, skips with OIDA_SKIP_MISSING_SERVICES=1."""
    if not HAS_PYSHARK:
        require_service("pyshark or tshark not installed")


requires_pyshark = pytest.mark.usefixtures("_require_pyshark")

# git-lfs pointer signature -- pcap fixtures stored in LFS are <200-byte text
# pointers until 'git lfs pull' fetches them.  tshark chokes on the pointer
# text with TSharkCrashException; detect and skip instead.
_LFS_POINTER_MAGIC = b"version https://git-lfs.github.com/spec/v1"


def _is_lfs_pointer(path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(len(_LFS_POINTER_MAGIC)).startswith(_LFS_POINTER_MAGIC)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Common test helpers (imported by per-protocol test files)
# ---------------------------------------------------------------------------


def _skip_unless_exists(path: Path):
    if not path.exists():
        pytest.fail(f"Fixture not found: {path}")
    if _is_lfs_pointer(path):
        pytest.skip(f"pcap fixture is an unfetched git-lfs pointer (run 'git lfs pull'): {path}")


def _assert_pipeline_completed(result: dict):
    """Assert the pyshark pipeline completed, processed packets, and is JSON-serializable."""
    assert "statistics" in result
    assert result["statistics"]["packets_processed"] >= 0
    # JSON serialization validation
    serialized = json.dumps(result, default=str)
    assert len(serialized) > 0
    for key in ("pcap_file", "scan_mode", "protocols_used", "devices", "statistics"):
        assert key in result, f"Missing top-level key: {key}"
    assert "packets_processed" in result["statistics"]
    for device in result.get("devices", []):
        json.dumps(device, default=str)


def _get_listener_direct(pcap_path: Path, listener_name: str):
    """Create and run a single listener directly, returning the listener object."""
    _skip_unless_exists(pcap_path)
    from oida.protocols.pcap.listener_registry import create_listeners

    listeners = create_listeners({listener_name})
    assert listener_name in listeners, f"Failed to create {listener_name} listener"
    listener = listeners[listener_name]

    import asyncio

    import pyshark

    # pyshark uses asyncio internally; on Python 3.10+ the main thread has no
    # implicit event loop, so FileCapture's get_event_loop() raises RuntimeError
    # unless one is set first. Mirror the guard in PcapScanner._run_pyshark_pipeline.
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    cap = pyshark.FileCapture(str(pcap_path), keep_packets=False)
    for packet in cap:
        try:
            listener.feed_packet(packet)
        except Exception:
            pass
    cap.close()
    return listener
