"""
Shared fixtures and helpers for pcap unit tests.

Provides paths to real pcap fixture files, availability checks
for optional dependencies (tshark, pyshark), and common assertion
helpers used across per-protocol test files.
"""

import json
from pathlib import Path

import pytest


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

        return True
    except ImportError:
        return False


HAS_PYSHARK = _has_pyshark()

requires_pyshark = pytest.mark.skipif(
    not HAS_PYSHARK,
    reason="pyshark not installed",
)


# ---------------------------------------------------------------------------
# Common test helpers (imported by per-protocol test files)
# ---------------------------------------------------------------------------


def _skip_unless_exists(path: Path):
    if not path.exists():
        pytest.fail(f"Fixture not found: {path}")


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
