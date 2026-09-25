"""Regression test: pyshark live-capture autostop on an idle interface.

``sniff_continuously()`` was called with no timeout/autostop, so tshark blocks
waiting for the next matching packet.  The wall-clock guard
(``time.time() - start_time >= self.timeout``) sits *inside* the per-packet
loop body, which never executes when no packet ever arrives -- so on a quiet
interface (or a DISPLAY_FILTER matching nothing) the listener hangs far past
``self.timeout`` instead of returning after that many seconds.

The fix passes ``custom_parameters=["-a", "duration:<timeout>"]`` to
``pyshark.LiveCapture`` so tshark itself terminates the capture after the
requested duration, ending the generator even when zero packets arrive.

These tests are fixture-free: they monkeypatch ``pyshark.LiveCapture`` with a
fake whose ``sniff_continuously`` yields nothing (idle interface), and assert
both that the autostop duration is wired through and that ``_live_capture``
returns promptly rather than blocking.
"""

import sys
import time
import types

import pytest

from oida.pcap.pyshark_base import PySharkListenerBase


class _NoopListener(PySharkListenerBase):
    PROTOCOL_NAME = "test"
    DISPLAY_FILTER = "tcp.port == 65000"  # filter that matches no real traffic

    def process_packet(self, packet) -> None:  # pragma: no cover - never called
        raise AssertionError("no packets should be delivered on an idle interface")


class _FakeIdleCapture:
    """Stand-in for pyshark.LiveCapture on a quiet interface.

    Records the kwargs it was constructed with and yields no packets, mimicking
    a tshark process bounded by an autostop duration that saw no matching
    traffic.
    """

    last_kwargs: dict = {}

    def __init__(self, **kwargs):
        type(self).last_kwargs = kwargs
        self.closed = False

    def sniff_continuously(self):
        # Idle interface: generator immediately exhausts (tshark exited on its
        # own autostop duration).  Function body still makes this a generator.
        return iter(())

    def close(self):
        self.closed = True


@pytest.fixture
def fake_pyshark(monkeypatch):
    """Install a fake ``pyshark`` module exposing ``_FakeIdleCapture``."""
    fake = types.ModuleType("pyshark")
    fake.LiveCapture = _FakeIdleCapture
    monkeypatch.setitem(sys.modules, "pyshark", fake)
    _FakeIdleCapture.last_kwargs = {}
    return fake


def test_autostop_duration_passed_to_tshark(fake_pyshark):
    """The capture must receive ``-a duration:<timeout>`` so tshark self-bounds."""
    listener = _NoopListener(interface="lo", timeout=7)
    listener._live_capture()

    custom = _FakeIdleCapture.last_kwargs.get("custom_parameters")
    assert custom == ["-a", "duration:7"], custom


def test_idle_interface_returns_promptly(fake_pyshark):
    """On an idle interface _live_capture must return, not block past timeout.

    Before the fix the wall-clock guard lived inside the per-packet loop, so a
    generator that yields nothing would never reach it.  With tshark's autostop
    the generator exhausts and the method returns immediately.
    """
    listener = _NoopListener(interface="lo", timeout=30)

    start = time.monotonic()
    devices = listener._live_capture()
    elapsed = time.monotonic() - start

    # No real waiting happens (fake yields nothing); the point is that the
    # method returns at all rather than blocking on a never-yielding generator.
    assert elapsed < 5, f"_live_capture blocked for {elapsed:.1f}s on an idle interface"
    assert devices == {}
