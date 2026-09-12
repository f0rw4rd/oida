"""Configurable misbehaving TCP target for crash-detection fidelity measurement.

A single in-process server that starts healthy (accept -> echo first byte) and, on
``trigger(mode)``, switches into one steady crash-of-service state. This lets a test
probe a monitor against each distinct *observable* failure mode and record whether the
monitor notices — quantifying what the fuzzer's crash detection can and cannot see.

Modes (the observable state after ``trigger``):

- ``healthy``       accept + echo first byte (control; every monitor should pass)
- ``hard_down``     stop listening -> TCP connect refused
- ``accept_close``  accept the connection then immediately close it (empty recv / RST)
- ``hang``          accept + recv but never reply, hold the socket open (recv blocks)
- ``slow``          accept + recv, reply only after ``slow_delay`` s (> probe timeout)
- ``garbage``       accept + recv, reply with bytes that are NOT a valid response

A genuine memory-corruption crash (the compiled ``strcpy`` server used elsewhere) is
equivalent to ``hard_down`` from a network monitor's point of view, so it is not needed
here.
"""

from __future__ import annotations

import socket
import threading
import time

HEALTHY = "healthy"
HARD_DOWN = "hard_down"
ACCEPT_CLOSE = "accept_close"
HANG = "hang"
SLOW = "slow"
GARBAGE = "garbage"

ALL_MODES = [HARD_DOWN, ACCEPT_CLOSE, HANG, SLOW, GARBAGE]


class MisbehavingServer:
    """Threaded TCP server that can switch into a chosen crash-of-service state."""

    def __init__(self, slow_delay: float = 5.0):
        self._mode = HEALTHY
        self._slow_delay = slow_delay
        self._stop = threading.Event()
        self._listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen.bind(("127.0.0.1", 0))
        self.port = self._listen.getsockname()[1]
        self._listen.listen(32)
        self._listen.settimeout(0.3)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "MisbehavingServer":
        self._thread.start()
        time.sleep(0.3)
        return self

    def trigger(self, mode: str) -> None:
        """Switch into a crash-of-service mode."""
        assert mode in (HEALTHY, *ALL_MODES), mode
        self._mode = mode
        if mode == HARD_DOWN:
            # Stop accepting entirely: close the listen socket.
            try:
                self._listen.close()
            except OSError:
                pass
        # Give the accept loop a beat to observe the new state.
        time.sleep(0.2)

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listen.close()
        except OSError:
            pass
        time.sleep(0.2)

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._mode == HARD_DOWN:
                time.sleep(0.1)
                continue
            try:
                conn, _ = self._listen.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        mode = self._mode
        try:
            if mode == ACCEPT_CLOSE:
                conn.close()
                return
            conn.settimeout(1.0)
            try:
                data = conn.recv(4096)
            except OSError:
                data = b""
            if mode == HANG:
                # Never reply; hold the connection open past the probe timeout.
                time.sleep(3.0)
                return
            if mode == SLOW:
                time.sleep(self._slow_delay)
                if data:
                    conn.sendall(data[:1])
                return
            if mode == GARBAGE:
                # Deliberately contains none of a typical expect-marker byte; a
                # valid-case probe must judge this a corrupt (non-matching) reply.
                conn.sendall(b"\xde\xad\xbe\xef\x00\x01\x02\x03")
                return
            # healthy: echo first byte
            if data:
                conn.sendall(data[:1])
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
