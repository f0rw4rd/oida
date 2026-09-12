"""Tests for the `crashes` report and `reproduce` CLI commands.

`crashes` groups stored crashes by signature (read-only); `reproduce` re-sends a
stored crash payload to a live target and reports whether the monitor sees it go
down. These are the two pieces that make "the fuzzer found a crash" actionable.
"""

from __future__ import annotations

import os
import socket
import threading
import time

import pytest

from oida.fuzz.core.database.interface import Crash, TestCase
from oida.fuzz.core.database.orm import SQLAlchemyDatabase
import oida.fuzz_cli as cli

pytestmark = pytest.mark.core


class _Args:
    """Duck-typed argparse namespace for the handlers."""

    def __init__(self, session, **kw):
        self.session = session
        self.case = kw.get("case")
        self.export = kw.get("export")
        self.reproduce_target = kw.get("reproduce_target")
        self.port = kw.get("port")
        self.verbose = False


def _seed_session(tmp_path, crashes):
    """crashes: list of (test_id, name, payload, info, protocol, ip, port)."""
    sess = str(tmp_path / "s")
    db = SQLAlchemyDatabase(sess + ".db")
    db.init_schema()
    for tid, name, payload, info, proto, ip, port in crashes:
        db.store_test_case(
            TestCase(
                id=tid,
                name=name,
                timestamp="t",
                result="crash",
                crc32=tid,
                target_ip=ip,
                target_port=port,
                protocol=proto,
            )
        )
        db.store_crash(Crash(test_case_id=tid, payload=payload, crash_info=info, stack_trace=None))
    db.store_metadata("protocol_name", crashes[0][4] if crashes else "unknown")
    return sess, db


# --------------------------------------------------------------------------- #
# get_all_crashes + crashes report
# --------------------------------------------------------------------------- #


def test_get_all_crashes_returns_stored(tmp_path):
    _, db = _seed_session(
        tmp_path,
        [(1, "A", b"x", "boom", "modbus", "127.0.0.1", 502)],
    )
    got = db.get_all_crashes()
    assert len(got) == 1 and got[0].test_case_id == 1
    assert got[0].crash_hash  # populated by the storage layer


def test_crashes_report_groups_by_signature(tmp_path, capsys):
    sess, _ = _seed_session(
        tmp_path,
        [
            (10, "Req_A", b"\xde\xad", "Monitor detected failure X", "modbus", "127.0.0.1", 502),
            (20, "Req_A", b"\xca\xfe", "Monitor detected failure X", "modbus", "127.0.0.1", 502),
            (30, "Req_B", b"\x01", "Different failure Y", "modbus", "127.0.0.1", 502),
        ],
    )
    rc = cli.handle_crashes_command(_Args(sess))
    out = capsys.readouterr().out
    assert rc == 0
    assert "3 crash(es), 2 unique signature(s)" in out
    assert "x2" in out and "[10] Req_A" in out
    assert "[30] Req_B" in out


def test_crashes_case_dump_and_export(tmp_path, capsys):
    sess, _ = _seed_session(
        tmp_path,
        [(7, "Req", b"\xde\xad\xbe\xef", "boom", "modbus", "127.0.0.1", 502)],
    )
    export = str(tmp_path / "payload.bin")
    rc = cli.handle_crashes_command(_Args(sess, case=7, export=export))
    out = capsys.readouterr().out
    assert rc == 0
    assert "de ad be ef" in out  # hexdump
    assert "3q2+7w==" in out  # base64 of deadbeef
    assert os.path.exists(export)
    with open(export, "rb") as fh:
        assert fh.read() == b"\xde\xad\xbe\xef"


def test_crashes_missing_session(tmp_path, capsys):
    rc = cli.handle_crashes_command(_Args(str(tmp_path / "nope")))
    assert rc == 1


def test_crashes_empty_session(tmp_path, capsys):
    sess = str(tmp_path / "empty")
    SQLAlchemyDatabase(sess + ".db").init_schema()
    rc = cli.handle_crashes_command(_Args(sess))
    out = capsys.readouterr().out
    assert rc == 0 and "No crashes recorded" in out


# --------------------------------------------------------------------------- #
# reproduce
# --------------------------------------------------------------------------- #


class _Server:
    """A controllable TCP target: healthy echo, or 'crash' (stop listening) on a trigger."""

    def __init__(self, crash_on=None):
        self.crash_on = crash_on
        self._stop = threading.Event()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(16)
        self.sock.settimeout(0.3)
        self._t = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._t.start()
        time.sleep(0.3)
        return self

    def _run(self):
        while not self._stop.is_set():
            try:
                c, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                c.settimeout(0.5)
                data = c.recv(1024)
                if self.crash_on and data and self.crash_on in data:
                    c.close()
                    self._stop.set()
                    break
                if data:
                    c.sendall(data[:1])
            except OSError:
                pass
            finally:
                try:
                    c.close()
                except OSError:
                    pass
        try:
            self.sock.close()
        except OSError:
            pass

    def stop(self):
        self._stop.set()
        time.sleep(0.3)


@pytest.mark.slow
def test_reproduce_healthy_target_not_reproduced(tmp_path, capsys):
    srv = _Server().start()
    try:
        sess, _ = _seed_session(
            tmp_path,
            [(1, "Echo", b"HELLO", "boom", "echo", "127.0.0.1", srv.port)],
        )
        rc = cli.handle_reproduce_command(_Args(sess))
        out = capsys.readouterr().out
        assert "NOT-REPRODUCED" in out
        assert rc == 1  # nothing reproduced
    finally:
        srv.stop()


# --------------------------------------------------------------------------- #
# narrow: culprit bisection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("culprit_idx", [0, 3, 5])
def test_bisect_finds_culprit(culprit_idx):
    """Minimal-crashing-prefix bisection pins the case at culprit_idx (0-based)."""
    n = 6
    calls = []

    def oracle(k):
        calls.append(k)
        # prefix window[:k] crashes iff it includes the culprit (index culprit_idx)
        return k >= culprit_idx + 1

    k = cli._bisect_min_crashing_prefix(n, oracle)
    assert k - 1 == culprit_idx  # window[k-1] is the culprit
    assert len(calls) <= 3  # log2(6) trials, not linear


def test_bisect_inconclusive_returns_none():
    assert cli._bisect_min_crashing_prefix(5, lambda k: None) is None


def test_crash_context_stored_once_per_episode(tmp_path):
    """record_test_case stores a CrashEvent+window per crash EPISODE, re-armed on a pass."""
    from oida.fuzz.core.config import FuzzerConfig
    from oida.fuzz.core.session.manager import TestCaseManager
    from oida.utils.ics_logger import get_logger

    class _Fuzzer:
        def __init__(self, cfg):
            self.config = cfg
            self.log = get_logger("T", cfg.target_ip, cfg.target_port)
            self.session = None

    cfg = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=7,
        protocol="echo",
        monitor_check_interval=5,
        log_session=True,
    )
    db = SQLAlchemyDatabase(str(tmp_path / "s.db"))
    mgr = TestCaseManager(fuzzer=_Fuzzer(cfg), database=db)

    # Episode 1: 3 benign then a crash-flagged run of 2 -> ONE event.
    for i in range(1, 4):
        mgr.record_test_case(test_id=i, name="Echo", payload=b"ok", result="pass")
    mgr.record_test_case(test_id=4, name="Overflow", payload=b"A" * 500, result="crash")
    mgr.record_test_case(test_id=5, name="Overflow", payload=b"A" * 500, result="crash")
    # A pass re-arms; then a second crash -> a SECOND event.
    mgr.record_test_case(test_id=6, name="Echo", payload=b"ok", result="pass")
    mgr.record_test_case(test_id=7, name="Overflow", payload=b"A" * 500, result="crash")

    events = db.get_crash_events()
    assert len(events) == 2, f"expected one event per episode, got {len(events)}"
    # Newest first; the window carries payloads for narrowing.
    ev = db.get_crash_event(events[-1]["id"])  # first episode
    ids = sorted(c["test_case_id"] for c in ev["context"])
    assert 4 in ids
    assert db.get_crash_context_payload(events[-1]["id"], 4) == b"A" * 500


def test_narrow_no_context_is_graceful(tmp_path, capsys):
    sess = str(tmp_path / "empty")
    SQLAlchemyDatabase(sess + ".db").init_schema()
    rc = cli.handle_narrow_command(_Args(sess))
    out = capsys.readouterr().out
    assert rc == 1 and "No crash context stored" in out


@pytest.mark.slow
def test_reproduce_crashing_target_reproduced(tmp_path, capsys):
    srv = _Server(crash_on=b"CRASHME").start()
    try:
        sess, _ = _seed_session(
            tmp_path,
            [(1, "Echo", b"CRASHME", "boom", "echo", "127.0.0.1", srv.port)],
        )
        rc = cli.handle_reproduce_command(_Args(sess))
        out = capsys.readouterr().out
        assert "REPRODUCED" in out
        assert rc == 0
    finally:
        srv.stop()
