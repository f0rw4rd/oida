"""Regression tests for per-node effectiveness counters.

Locks in the counter plumbing added after the fuzzer evaluation found no way
to tell whether a request node was actually eliciting responses:

- Connection layer (ResilientTCPConnection.effectiveness): flat cumulative
  counters incremented on send/recv outcomes; silence after a reply-expected
  send scores a timeout, silence after a no-reply send does not.
- Session layer (TestCaseManager): per-case delta attribution to the active
  boofuzz node, flushed to session_metadata.effectiveness on save.
"""

import json
import socket

import pytest

from tests.unit.fuzz.test_reply_policy_wiring import _FakeLog


class TestConnectionCounters:
    """Counter classification over a real socketpair."""

    @pytest.fixture()
    def pair(self):
        a, b = socket.socketpair()
        yield a, b
        a.close()
        b.close()

    def _conn(self, pair):
        from oida.fuzz.core.connections.tcp import ResilientTCPConnection

        conn = ResilientTCPConnection("127.0.0.1", 1, recv_timeout=0.3)
        conn._sock = pair[0]
        conn._log = _FakeLog()
        pair[0].settimeout(0.3)
        pair[1].settimeout(0.3)
        return conn

    def test_counters_initialized_to_zero(self, pair):
        conn = self._conn(pair)
        assert conn.effectiveness["sent"] == 0
        assert conn.effectiveness["replies"] == 0
        assert conn.effectiveness["timeouts"] == 0
        assert conn.effectiveness["resets"] == 0
        assert conn.effectiveness["protocol_errors"] == 0

    def test_reply_scored_as_reply(self, pair):
        conn = self._conn(pair)
        conn.reply_expected = lambda d: True
        pair[1].sendall(b"ACK")
        conn.send(b"\x10\x00")
        conn.recv(1024)
        assert conn.effectiveness["sent"] == 1
        assert conn.effectiveness["wait_expected"] == 1
        assert conn.effectiveness["replies"] == 1
        assert conn.effectiveness["timeouts"] == 0

    def test_silence_after_reply_expected_is_timeout(self, pair):
        conn = self._conn(pair)
        conn.reply_expected = lambda d: True
        conn.send(b"\x10\x00")
        conn.recv(1024)  # nothing arrives -> timeout (fast: 0.3s recv timeout)
        assert conn.effectiveness["timeouts"] == 1
        assert conn.effectiveness["replies"] == 0

    def test_silence_after_no_reply_is_not_timeout(self, pair):
        conn = self._conn(pair)
        conn.reply_expected = lambda d: False
        conn.send(b"\x30\x00")
        conn.recv(1024)  # fast path, silence expected
        assert conn.effectiveness["timeouts"] == 0
        assert conn.effectiveness["sent"] == 1
        assert conn.effectiveness["wait_expected"] == 0

    def test_bytes_tracked(self, pair):
        conn = self._conn(pair)
        conn.reply_expected = lambda d: True
        pair[1].sendall(b"PONG" * 10)
        conn.send(b"\x10\x00rest")
        conn.recv(1024)
        assert conn.effectiveness["bytes_sent"] == 6  # b"\x10\x00rest"
        assert conn.effectiveness["bytes_recv"] == 40

    def test_empty_send_not_counted(self, pair):
        conn = self._conn(pair)
        n = conn.send(b"")
        assert n == 0
        assert conn.effectiveness["sent"] == 0


class TestSessionAttribution:
    """TestCaseManager delta attribution + flush."""

    def _manager(self, tmp_path, conn):
        from oida.fuzz.core.session.manager import TestCaseManager
        from oida.fuzz.core.config import FuzzerConfig

        class _F:
            pass

        f = _F()
        f.config = FuzzerConfig(
            target_ip="127.0.0.1", target_port=1, session_filename=str(tmp_path / "s")
        )
        f.log = _FakeLog()
        f._session = type("S", (), {"targets": [type("T", (), {"_target_connection": conn})()]})()
        mgr = TestCaseManager(f)  # creates the DB
        return mgr

    def _bump(self, conn, **kw):
        for k, v in kw.items():
            conn.effectiveness[k] += v

    def test_delta_attribution_and_flush(self, tmp_path):
        from oida.fuzz.core.connections.tcp import ResilientTCPConnection

        conn = ResilientTCPConnection("127.0.0.1", 1)
        conn._log = _FakeLog()
        mgr = self._manager(tmp_path, conn)

        # Case 1: node A sends 10, gets 5 replies.
        self._bump(conn, sent=10, wait_expected=10, replies=5)
        mgr._attribute_effectiveness("NodeA")
        # Case 2: node B sends 3, all silent (reply-expected).
        self._bump(conn, sent=3, wait_expected=3, timeouts=3)
        mgr._attribute_effectiveness("NodeB")
        # Case 3: no traffic (skipped case) -> no entry.
        mgr._attribute_effectiveness("NodeC")

        assert mgr._effectiveness["NodeA"]["sent"] == 10
        assert mgr._effectiveness["NodeA"]["replies"] == 5
        assert mgr._effectiveness["NodeB"]["sent"] == 3
        assert mgr._effectiveness["NodeB"]["timeouts"] == 3
        assert "NodeC" not in mgr._effectiveness

        mgr._flush_effectiveness()
        raw = mgr.database.get_all_metadata().get("effectiveness")
        assert raw is not None
        data = json.loads(raw)
        assert data["NodeA"]["replies"] == 5
        assert data["NodeB"]["timeouts"] == 3

    def test_flush_skipped_without_data(self, tmp_path):
        from oida.fuzz.core.connections.tcp import ResilientTCPConnection

        conn = ResilientTCPConnection("127.0.0.1", 1)
        conn._log = _FakeLog()
        mgr = self._manager(tmp_path, conn)
        mgr._flush_effectiveness()  # no attribution yet: must not raise
        assert "effectiveness" not in mgr.database.get_all_metadata()

    def test_read_only_never_flushes(self, tmp_path):
        from oida.fuzz.core.session.manager import TestCaseManager
        from oida.fuzz.core.config import FuzzerConfig

        class _F:
            pass

        f = _F()
        f.config = FuzzerConfig(
            target_ip="127.0.0.1", target_port=1, session_filename=str(tmp_path / "ro")
        )
        f.log = _FakeLog()
        mgr = TestCaseManager(f, read_only=True)
        mgr._effectiveness = {"NodeA": {"sent": 1}}
        mgr._flush_effectiveness()  # must not write
        assert "effectiveness" not in mgr.database.get_all_metadata()
        # The in-memory accumulator must also be left untouched (no attempt
        # to drain it on a no-op flush).
        assert mgr._effectiveness == {"NodeA": {"sent": 1}}
