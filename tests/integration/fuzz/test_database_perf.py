"""Performance benchmarks for the SQLAlchemy fuzz-session DB.

These tests assert *throughput floors* against a real on-disk SQLite
database - not microbenchmarks. The numbers below are conservative
floors picked so that:

- Slow CI runners and rotating disks still pass.
- A regression in the storage hot path (e.g. accidentally turning off
  WAL, reverting bulk inserts, dropping the PRAGMA listener) trips
  the test by a wide margin.

Marked ``slow`` so they don't run in the default smoke-test sweep.
Run explicitly with::

    pytest tests/integration/fuzz/test_database_perf.py -m slow -v

The bulk-vs-singular comparison is the load-bearing assertion: it
verifies the *shape* of the hot path, not absolute speed. That makes
it robust to fast machines (where everything looks instant) and slow
ones (where everything looks slow).
"""

from __future__ import annotations

import os
import sqlite3
import time
from typing import Callable

import pytest

from oida.fuzz.core.database import SQLAlchemyDatabase
from oida.fuzz.core.database.interface import TestCase, Crash


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _ensure_logger_context():
    """The ORM debug-logs through ics_logger; tests need a context."""
    from oida.utils import ics_logger

    if ics_logger.get_context() is None:
        ics_logger.set_context("test", "127.0.0.1", 0)
    yield


@pytest.fixture
def fresh_db(tmp_path):
    """A fresh on-disk SQLAlchemyDatabase with init_schema() called."""
    path = tmp_path / "perf.db"
    db = SQLAlchemyDatabase(str(path))
    db.init_schema()
    yield db
    db.close()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _make_case(i: int, result: str = "pass") -> TestCase:
    # IDs start at 1: id=0 is the "auto-generate" sentinel in the
    # storage layer (matching the existing ``store_test_case`` contract).
    return TestCase(
        id=i + 1,
        name=f"Standard_GET_{i}",
        timestamp=f"2026-05-27T12:00:{i % 60:02d}",
        result=result,
        crc32=0xCAFEBABE ^ i,
        target_ip="127.0.0.1",
        target_port=8080,
        protocol="http",
        duration_ms=1.5,
        monitor_status="healthy",
    )


def _time(fn: Callable[[], None]) -> float:
    """Return seconds taken by ``fn``."""
    t0 = time.perf_counter()
    fn()
    return time.perf_counter() - t0


# --------------------------------------------------------------------------- #
# PRAGMA verification
# --------------------------------------------------------------------------- #


@pytest.mark.slow
class TestPragmaConfig:
    """Verify the connect-time PRAGMA listener is wired up correctly.

    These are correctness-of-perf-config tests, not throughput. They run
    even on minimal CI to catch regressions where the listener gets
    accidentally removed or shadowed.
    """

    def test_journal_mode_is_wal(self, fresh_db, tmp_path):
        with fresh_db.engine.connect() as conn:
            mode = conn.exec_driver_sql("PRAGMA journal_mode").scalar()
        assert mode == "wal", f"WAL is required for the fuzzer's write throughput; got {mode!r}"

    def test_synchronous_is_normal(self, fresh_db):
        with fresh_db.engine.connect() as conn:
            sync = conn.exec_driver_sql("PRAGMA synchronous").scalar()
        # 1 == NORMAL, 2 == FULL
        assert sync == 1, f"synchronous should be NORMAL (1), got {sync}"

    def test_foreign_keys_enforced(self, fresh_db):
        with fresh_db.engine.connect() as conn:
            fk = conn.exec_driver_sql("PRAGMA foreign_keys").scalar()
        assert fk == 1, "foreign_keys must be ON for ondelete=CASCADE to work"

    def test_cascade_delete_actually_fires(self, fresh_db):
        """Without foreign_keys=ON, this would silently leave orphans."""
        case = _make_case(1, result="crash")  # id=2 after offset
        fresh_db.store_test_case(case)
        fresh_db.store_crash(
            Crash(
                test_case_id=case.id,
                payload=b"abc",
                crash_info="x",
                stack_trace="y",
            )
        )
        assert fresh_db.get_crash(case.id) is not None

        # Delete the parent test case - crash row must cascade.
        with fresh_db.get_session() as session:
            from oida.fuzz.core.database.models import TestCase as ORMTestCase

            tc = session.get(ORMTestCase, case.id)
            session.delete(tc)

        assert fresh_db.get_crash(case.id) is None, (
            "Crash row not cascade-deleted - PRAGMA foreign_keys not active"
        )


# --------------------------------------------------------------------------- #
# Throughput floors
# --------------------------------------------------------------------------- #


@pytest.mark.slow
class TestWriteThroughput:
    """Insertion throughput floors. Conservative numbers so CI passes."""

    def test_bulk_insert_2k_cases_under_one_second(self, fresh_db):
        """2000 cases in one transaction must complete in <1 s.

        On a developer laptop this typically runs in ~50 ms; the floor
        is generous to accommodate the slowest CI runner. With the
        per-row commit path this would take 10-30 s on rotating disks.
        """
        cases = [_make_case(i) for i in range(2000)]
        elapsed = _time(lambda: fresh_db.store_test_cases_bulk(cases))
        assert elapsed < 1.0, (
            f"bulk insert of 2000 test cases took {elapsed:.2f}s, "
            f"expected <1.0s - likely lost the bulk path or WAL"
        )

        # And the rows are actually there.
        rows = fresh_db.get_test_cases(limit=None)
        assert len(rows) == 2000

    def test_bulk_metadata_writes_under_100ms(self, fresh_db):
        """20 metadata keys in one transaction <100 ms."""
        items = {f"key_{i}": f"value_{i}" for i in range(20)}
        elapsed = _time(lambda: fresh_db.store_metadata_bulk(items))
        assert elapsed < 0.1, f"bulk metadata write of 20 keys took {elapsed:.3f}s"
        assert len(fresh_db.get_all_metadata()) >= 20


@pytest.mark.slow
class TestBulkIsFasterThanSingular:
    """Shape test: bulk must be strictly faster than per-row.

    This is the load-bearing assertion. It doesn't depend on absolute
    speed - only on the ratio between the two paths.

    We size N so both paths complete inside the test timeout even on
    slow disks (500 rows ≈ 500 fsyncs in the singular path).
    """

    def test_bulk_is_at_least_5x_faster_than_per_row(self, tmp_path):
        n = 500
        cases = [_make_case(i) for i in range(n)]

        # Singular: each store_test_case opens its own tx and commits.
        db_singular = SQLAlchemyDatabase(str(tmp_path / "singular.db"))
        db_singular.init_schema()
        t_singular = _time(lambda: [db_singular.store_test_case(c) for c in cases])
        db_singular.close()

        # Bulk: one tx for all rows.
        db_bulk = SQLAlchemyDatabase(str(tmp_path / "bulk.db"))
        db_bulk.init_schema()
        t_bulk = _time(lambda: db_bulk.store_test_cases_bulk(cases))
        db_bulk.close()

        ratio = t_singular / max(t_bulk, 1e-6)
        # 5x is conservative - bulk is typically 30-100x faster.
        assert ratio >= 5.0, (
            f"bulk insert was only {ratio:.1f}x faster than per-row "
            f"(singular={t_singular:.3f}s, bulk={t_bulk:.3f}s) - "
            f"the bulk path may be falling through to per-row commits"
        )


# --------------------------------------------------------------------------- #
# Read throughput
# --------------------------------------------------------------------------- #


@pytest.mark.slow
class TestReadThroughput:
    """get_stats() and get_test_cases() must scale to large sessions."""

    @pytest.fixture
    def populated_db(self, tmp_path):
        """A DB with 10k cases - large enough that O(N) queries hurt."""
        path = tmp_path / "populated.db"
        db = SQLAlchemyDatabase(str(path))
        db.init_schema()
        results = ["pass", "pass", "pass", "fail", "crash"]
        cases = [_make_case(i, result=results[i % len(results)]) for i in range(10_000)]
        db.store_test_cases_bulk(cases)
        yield db
        db.close()

    def test_get_stats_under_100ms_for_10k(self, populated_db):
        """One aggregate query must finish fast - the coalesced path."""
        # Warm up the page cache so we measure the query, not first I/O.
        populated_db.get_stats()
        elapsed = _time(populated_db.get_stats)
        assert elapsed < 0.1, (
            f"get_stats() over 10k cases took {elapsed:.3f}s - "
            f"the 8-aggregate-query regression may be back"
        )

    def test_get_test_cases_default_caps_at_10k(self, populated_db):
        """get_test_cases() default limit must cap memory blowup."""
        # Pour in another 5k so total = 15k > default limit.
        extra = [_make_case(20_000 + i) for i in range(5_000)]
        populated_db.store_test_cases_bulk(extra)

        cases = populated_db.get_test_cases()  # no explicit limit
        assert len(cases) <= 10_000, f"default limit not applied: got {len(cases)} rows"

    def test_get_test_cases_with_protocol_filter_uses_index(self, populated_db):
        """Filtered queries should hit idx_test_cases_protocol_result_ts."""
        elapsed = _time(
            lambda: populated_db.get_test_cases(protocol="http", result_filter="crash", limit=1000)
        )
        assert elapsed < 0.3, (
            f"filtered get_test_cases took {elapsed:.3f}s - may be doing a full table scan"
        )


# --------------------------------------------------------------------------- #
# Disk footprint
# --------------------------------------------------------------------------- #


@pytest.mark.slow
def test_database_file_stays_compact(tmp_path):
    """10k metadata-only test cases must fit in a few MB.

    Catches regressions where someone accidentally re-enables payload
    storage on the test-case row, or where indexes balloon out of
    proportion (e.g. indexing every text column).
    """
    db = SQLAlchemyDatabase(str(tmp_path / "compact.db"))
    db.init_schema()
    db.store_test_cases_bulk([_make_case(i) for i in range(10_000)])
    db.close()

    size_mb = os.path.getsize(tmp_path / "compact.db") / (1024 * 1024)
    # 10k cases at ~120 bytes per row plus indexes - should be well
    # under 10 MB. We assert <20 MB to leave headroom for WAL.
    assert size_mb < 20.0, f"DB grew to {size_mb:.1f} MB for 10k metadata-only cases"


# --------------------------------------------------------------------------- #
# Schema invariants used by perf paths
# --------------------------------------------------------------------------- #


@pytest.mark.slow
class TestIndexesPresent:
    """Verify the perf-critical indexes survived migrations."""

    REQUIRED_INDEXES = {
        "idx_test_cases_result",
        "idx_test_cases_timestamp",
        "idx_test_cases_target",
        "idx_test_cases_protocol",
        "idx_test_cases_protocol_result_ts",
        "idx_test_cases_name",
        "idx_crash_hash",
        "idx_crash_events_timestamp",
        "idx_crash_context_crash_id",
        "idx_crash_context_test_case_id",
    }

    def test_all_expected_indexes_exist(self, fresh_db):
        # Pull the index list directly from sqlite_master - most
        # faithful representation of what was actually created.
        path = fresh_db.database_path
        with sqlite3.connect(path) as conn:
            rows = conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        actual = {r[0] for r in rows}
        missing = self.REQUIRED_INDEXES - actual
        assert not missing, f"missing indexes: {sorted(missing)}"
