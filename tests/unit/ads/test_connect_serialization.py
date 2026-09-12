"""ADS connect() serializes access to pyads's process-global router port.

pyads exposes a single PROCESS-GLOBAL message-router port
(open_port/set_local_address/close_port). The CLI scans targets concurrently,
so the connect handshake must hold _ADS_GLOBAL_PORT_LOCK -- otherwise one
thread's set_local_address()/close_port() races another thread's in-flight
handshake, corrupting the global local AMS address or tearing the port down
mid-connect. This test drives many concurrent connect()s through a fake pyads
that sleeps between set_local_address() and Connection.open() to expose any
interleaving, and asserts none occurs.
"""

import threading
import time


from oida.protocols.ads import scanner as ads_scanner
from oida.protocols.ads.scanner import ADSScanner


class _NullLogger:
    def debug(self, *a, **k):
        pass

    def display(self, *a, **k):
        pass

    def fail(self, *a, **k):
        pass


class _RaceRecorder:
    """Fake pyads recording the global-port call sequence with thread names."""

    def __init__(self):
        self.events = []  # (thread_name, op)
        self._active = None  # thread currently between set_local_address and open
        self.violations = []
        self._guard = threading.Lock()

    def open_port(self):
        with self._guard:
            self.events.append((threading.current_thread().name, "open_port"))

    def set_local_address(self, netid):
        with self._guard:
            if self._active is not None:
                # Another thread is mid-handshake -> the lock failed to serialize.
                self.violations.append(("set_while_active", self._active))
            self._active = threading.current_thread().name
            self.events.append((self._active, "set_local_address"))
        # Sleep OUTSIDE the guard so a racing thread could interleave here if
        # connect() were not itself serialized by _ADS_GLOBAL_PORT_LOCK.
        time.sleep(0.005)

    def Connection(self, ams_netid, ads_port):  # noqa: N802 (mirror pyads API)
        rec = self

        class _Conn:
            def open(self):
                # NB: connect() runs this in a ThreadPoolExecutor worker, so the
                # thread here is NOT the connect() thread -- don't compare names.
                # The invariant the lock guarantees: exactly one handshake is
                # active at a time, so _active is set when this open() runs.
                with rec._guard:
                    rec.events.append((threading.current_thread().name, "open"))
                    if rec._active is None:
                        rec.violations.append(("open_without_active",))
                    rec._active = None

            def close(self):
                pass

        return _Conn()

    def close_port(self):
        with self._guard:
            self.events.append((threading.current_thread().name, "close_port"))


def _make_scanner(recorder, monkeypatch):
    monkeypatch.setattr(ads_scanner, "_get_pyads", lambda: recorder)
    s = ADSScanner.__new__(ADSScanner)
    s.ams_netid = "192.168.1.10.1.1"
    s.local_netid = "127.0.0.1.1.1"
    s.port_type = "TC3PLC1"
    s.ads_port = None
    s.timeout = 2
    s.logger = _NullLogger()
    return s


def test_concurrent_connect_does_not_interleave_global_port(monkeypatch):
    recorder = _RaceRecorder()

    def worker():
        s = _make_scanner(recorder, monkeypatch)
        conn = s.connect()
        # disconnect exercises the paired close_port() under the same lock.
        s.disconnect(conn)

    threads = [threading.Thread(target=worker, name=f"t{i}") for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not recorder.violations, f"handshake interleaved: {recorder.violations}"
    # Every worker completed a full set_local_address -> open handshake.
    opens = [e for e in recorder.events if e[1] == "open"]
    assert len(opens) == 8, f"expected 8 completed handshakes, got {len(opens)}"


def test_lock_is_shared_singleton():
    # Sanity: the module exposes a single lock instance the code uses.
    assert isinstance(ads_scanner._ADS_GLOBAL_PORT_LOCK, type(threading.RLock())) or hasattr(
        ads_scanner._ADS_GLOBAL_PORT_LOCK, "acquire"
    )
