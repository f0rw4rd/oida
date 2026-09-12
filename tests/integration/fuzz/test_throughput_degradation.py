"""Regression guards for the fuzzer's throughput-over-time degradation modes.

These lock in the fixes found during the fuzzer-performance evaluation. Each test
first *documents* the pre-fix behaviour (so the shape of the problem is captured),
then asserts the post-fix invariant. The assertions are about growth *shape*
(bounded vs. linear/quadratic), not absolute speed, so they are robust on both fast
and slow machines — matching ``test_database_perf.py``'s philosophy.

Mechanisms guarded:

1. **boofuzz in-memory results DB grew unbounded.** boofuzz always attaches a
   ``FuzzLoggerDb`` and, with ``num_log_cases=0`` (its default, which OIDA used to
   inherit), commits and keeps *every* passing case forever — a steady RAM leak on
   long campaigns (opcua ≈ 288k cases). OIDA now caps it via
   ``FuzzerConfig.fuzz_db_keep_pass_cases`` → ``Session(fuzz_db_keep_only_n_pass_cases)``.

2. **Crash-episode full-buffer re-flush.** While the target stays flagged crashed,
   every test case was flagged ``crash`` and re-flushed the *entire* rolling buffer
   (~2 × ``monitor_check_interval`` rows) to the on-disk session DB — an
   O(buffer_size)-per-case write storm. ``_flush_crash_context`` now skips context
   rows already persisted in the episode, so each flush is ~O(new cases).

3. **``SequenceManager._history`` grew unbounded** for stateful protocols
   (iec104/mms increment a sequence per request, nothing resets it per connection).
   It is now a bounded ``deque``.
"""

from __future__ import annotations

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.database.orm import SQLAlchemyDatabase
from oida.fuzz.core.session.manager import TestCaseManager
from oida.fuzz.core.session.sequence import SequenceConfig, SequenceManager

pytestmark = pytest.mark.core


@pytest.fixture(autouse=True)
def _ensure_logger_context():
    """The ORM / manager debug-log through ics_logger; tests need a context."""
    from oida.utils import ics_logger

    if ics_logger.get_context() is None:
        ics_logger.set_context("test", "127.0.0.1", 0)
    yield


# --------------------------------------------------------------------------- #
# 1. boofuzz in-memory results DB is bounded
# --------------------------------------------------------------------------- #


class TestBoofuzzDbCap:
    def test_config_default_is_bounded(self):
        """A fresh config must cap the boofuzz DB (0 would mean keep-everything)."""
        cfg = FuzzerConfig(target_ip="127.0.0.1", target_port=502)
        assert cfg.fuzz_db_keep_pass_cases > 0

    def test_session_receives_the_cap(self):
        """End-to-end wiring: config value reaches boofuzz's FuzzLoggerDb queue cap.

        Guards against silently dropping the ``fuzz_db_keep_only_n_pass_cases``
        kwarg from the ``Session(...)`` construction in ``_create_session``.
        """
        from oida.fuzz.core.connections import MockConnectionFactory
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        cls = PROTOCOL_FUZZERS["echo"]
        cfg = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=9999,
            protocol_type=ProtocolType.TCP,
            log_session=False,
            console_output=False,
            skip_pre_send_checks=True,
            web_interface=False,
            enumerate=False,
            fuzz_db_keep_pass_cases=123,
        )
        fuzzer = cls(config=cfg, connection_factory=MockConnectionFactory())
        session = fuzzer.session
        assert session._db_logger._queue_max_len == 123

    @pytest.mark.slow
    def test_db_logger_prunes_passing_cases(self):
        """With a cap, the DB keeps a bounded window; with 0 it grows unbounded."""
        from boofuzz.fuzz_logger_db import FuzzLoggerDb

        def _rows(num_log_cases: int, n: int) -> int:
            db = FuzzLoggerDb(db_filename=":memory:", num_log_cases=num_log_cases)
            for i in range(1, n + 1):
                db.open_test_case(i, name="req", index=i)
                db.log_send(b"\x00\x01\x02\x03")
                db.log_recv(b"\x00")
                db.log_pass("ok")
                db.close_test_case()
            return db._database_connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]

        n = 5000
        cap = 100
        capped = _rows(cap, n)
        unbounded = _rows(0, n)

        # Pre-fix behaviour (documents the leak): keep-all retains every case.
        assert unbounded == n
        # Post-fix invariant: bounded to roughly the window, independent of n.
        assert capped <= cap + 50, f"expected ~{cap} rows, got {capped}"
        assert capped < unbounded / 10

    @pytest.mark.slow
    def test_db_logger_retains_a_failing_case(self):
        """Capping passing cases must not drop crashes — those are always kept."""
        from boofuzz.fuzz_logger_db import FuzzLoggerDb

        db = FuzzLoggerDb(db_filename=":memory:", num_log_cases=10)
        # A run of passing cases, then one failure, then more passes.
        for i in range(1, 200):
            db.open_test_case(i, name="req", index=i)
            db.log_send(b"data")
            if i == 100:
                db.log_fail("boom")
            else:
                db.log_pass("ok")
            db.close_test_case()
        # The failing case must still be present.
        got = db._database_connection.execute(
            "SELECT COUNT(*) FROM cases WHERE number=?", (100,)
        ).fetchone()[0]
        assert got == 1


# --------------------------------------------------------------------------- #
# 2. Crash-episode flush is ~O(1) per case, not O(buffer_size)
# --------------------------------------------------------------------------- #


class _CountingDB(SQLAlchemyDatabase):
    """SQLAlchemyDatabase that tallies how many rows the crash-flush path writes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bulk_calls = 0
        self.bulk_rows = 0

    def store_test_cases_bulk(self, test_cases):
        self.bulk_calls += 1
        self.bulk_rows += len(test_cases)
        return super().store_test_cases_bulk(test_cases)


class _StubFuzzer:
    """Minimal duck-typed fuzzer: TestCaseManager only needs .config and .log."""

    def __init__(self, config):
        from oida.utils.ics_logger import get_logger

        self.config = config
        self.log = get_logger("FUZZ-TEST", config.target_ip, config.target_port, verbose=False)
        self.session = None


@pytest.mark.slow
class TestCrashStormFlush:
    def _manager(self, tmp_path, check_interval=10):
        cfg = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=502,
            protocol="modbus",
            monitor_check_interval=check_interval,
            log_session=True,
        )
        db = _CountingDB(str(tmp_path / "sess.db"))
        mgr = TestCaseManager(fuzzer=_StubFuzzer(cfg), database=db)
        return mgr, db

    def test_flush_work_is_linear_not_quadratic(self, tmp_path):
        mgr, db = self._manager(tmp_path)
        buf = mgr._buffer.maxsize  # max(2 * check_interval, 100) == 100

        # Prime the buffer with passing cases (buffered only, no DB writes).
        for i in range(1, buf + 1):
            mgr.record_test_case(test_id=i, name="req", payload=b"\x00\x01", result="pass")
        assert db.bulk_rows == 0, "passing cases must not hit the DB"

        # A sustained crash episode: every subsequent case is flagged crash.
        k = 500
        for i in range(buf + 1, buf + 1 + k):
            mgr.record_test_case(test_id=i, name="req", payload=b"\xde\xad", result="crash")

        # Post-fix: first flush writes the full buffer once, then ~1 new row/case.
        assert db.bulk_rows <= buf + 2 * k, f"flush work grew too fast: {db.bulk_rows}"
        # Not the pre-fix quadratic storm (which would be ~k * buf).
        assert db.bulk_rows < (buf * k) / 10, f"looks quadratic: {db.bulk_rows} rows"

    def test_all_crash_rows_are_recorded(self, tmp_path):
        mgr, db = self._manager(tmp_path)
        buf = mgr._buffer.maxsize
        for i in range(1, buf + 1):
            mgr.record_test_case(test_id=i, name="req", payload=b"\x00", result="pass")
        k = 50
        for i in range(buf + 1, buf + 1 + k):
            mgr.record_test_case(test_id=i, name="req", payload=b"\xff", result="crash")

        with db.get_session() as session:
            from oida.fuzz.core.database.models import TestCase as ORMTestCase

            crashes = session.query(ORMTestCase).filter(ORMTestCase.result == "crash").count()
        assert crashes == k, f"expected {k} crash rows, got {crashes}"


# --------------------------------------------------------------------------- #
# 3. SequenceManager history is bounded
# --------------------------------------------------------------------------- #


def test_sequence_history_is_bounded():
    mgr = SequenceManager()
    mgr.add_sequence(SequenceConfig(name="tx", initial=0, max_value=10_000_000))
    for _ in range(5000):
        mgr.get_and_increment("tx")
    assert len(mgr._history) <= 1000
    # Current value still tracks correctly despite the bounded trail.
    assert mgr.get("tx") == 5000
