"""Regression: ModbusMonitor health-probe false positives must not halt fuzzing.

A live Modbus target that answers our FC03 health probe with a *legal exception*
(FC | 0x80), that answers a little slowly, or that goes briefly quiet before
recovering, is ALIVE -- not a crash. Before the fix the monitor's twitchy probe
(timeout=0.1, retry=1, thresh=1) scored each of these as DOWN and, because the
recovery burst drained in ~0.6s with no spacing, escalated straight to a
``BoofuzzFailure`` that halted the whole run.

These tests drive the monitor's real probe / recovery path against a controllable
fake Modbus TCP server:

* S1 legal exception reply (FC 0x83)  -> alive, no halt
* S2 slow-but-up reply within timeout -> alive, no halt
* S3 transient silent blip then healthy -> recovers, no halt
* genuinely dead port                 -> STILL halts (fix must not blind us)
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from boofuzz.exception import BoofuzzFailure

from oida.fuzz.monitors.industrial import ModbusMonitor

# FC03 read-holding-registers replies (MBAP + PDU).
NORMAL_REPLY = bytes.fromhex("0001000000050103020000")
EXCEPTION_REPLY = bytes.fromhex("000100000003018301")  # FC 0x83, exc code 0x01


class FakeModbusServer:
    """A tiny threaded TCP server whose per-request behaviour is switchable.

    ``mode`` controls what each accepted connection does:
      * "normal"     -> reply NORMAL_REPLY immediately
      * "exception"  -> reply EXCEPTION_REPLY immediately (legal Modbus error)
      * "slow"       -> sleep ``delay`` then reply NORMAL_REPLY
      * "silent"     -> accept, read, send nothing, close (looks unresponsive)
    """

    def __init__(self, mode: str = "normal", delay: float = 0.0):
        self.mode = mode
        self.delay = delay
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "FakeModbusServer":
        self._thread.start()
        return self

    def _serve(self):
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(1.0)
                try:
                    conn.recv(256)
                except OSError:
                    pass
                mode = self.mode
                if mode == "silent":
                    pass
                elif mode == "exception":
                    conn.sendall(EXCEPTION_REPLY)
                elif mode == "slow":
                    time.sleep(self.delay)
                    conn.sendall(NORMAL_REPLY)
                else:
                    conn.sendall(NORMAL_REPLY)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


def _fresh_probe(monitor: ModbusMonitor) -> bool:
    """Run a real health check, bypassing the 0.2s rate-limit."""
    monitor.last_check_time = None
    return monitor._check_alive(None)


def test_legal_exception_reply_is_alive_not_a_crash():
    """S1: a well-framed Modbus exception (FC 0x83) proves liveness."""
    srv = FakeModbusServer(mode="exception").start()
    try:
        mon = ModbusMonitor("127.0.0.1", srv.port)
        for _ in range(5):
            assert _fresh_probe(mon) is True
        assert mon.crashed is False
        assert mon.consecutive_failures == 0
    finally:
        srv.stop()


def test_slow_but_up_reply_within_timeout_is_alive():
    """S2: a reply slower than the old 0.1s probe but within the new timeout is up."""
    srv = FakeModbusServer(mode="slow", delay=0.25).start()
    try:
        mon = ModbusMonitor("127.0.0.1", srv.port)  # timeout now 0.5s
        for _ in range(3):
            assert _fresh_probe(mon) is True
        assert mon.crashed is False
    finally:
        srv.stop()


def test_transient_silent_blip_recovers_without_halting():
    """S3: a brief silent blip must be ridden out by the paced recovery burst."""
    srv = FakeModbusServer(mode="normal").start()
    try:
        mon = ModbusMonitor("127.0.0.1", srv.port)
        # Establish a healthy baseline first.
        assert _fresh_probe(mon) is True

        # Blip: go silent for ~0.8s, then heal in a background thread. The paced
        # recovery burst (escalating backoff, widened probe timeout) should probe
        # again after the blip clears rather than exhausting all attempts up front.
        srv.mode = "silent"

        def _heal():
            time.sleep(0.8)
            srv.mode = "normal"

        threading.Thread(target=_heal, daemon=True).start()

        # This drives crash-detection -> recovery. It must NOT raise BoofuzzFailure.
        try:
            _fresh_probe(mon)
        except BoofuzzFailure:
            pytest.fail("transient blip halted fuzzing (recovery burst too tight)")

        # After healing, a fresh probe confirms the target is up and recovery
        # cleared the crash state.
        time.sleep(0.2)
        assert _fresh_probe(mon) is True
        assert mon.crashed is False
    finally:
        srv.stop()


def test_genuinely_dead_target_still_halts():
    """The fix must not blind the monitor: a truly dead port still raises."""
    # Bind then close so the port is refused (nothing listening).
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()

    mon = ModbusMonitor("127.0.0.1", dead_port)
    with pytest.raises(BoofuzzFailure):
        # Enough probes to cross the failure threshold and exhaust recovery.
        for _ in range(20):
            _fresh_probe(mon)
