"""
Regression tests for the end-of-session 'pass' flush corrupting crash rows.

Bug (CODE_REVIEW MEDIUM): during a run, ``_flush_crash_context`` INSERTs every
buffered test case (the crash case + preceding 'pass' cases) keyed by id. The
rolling buffer is NOT cleared afterwards, so ``save_session_progress(final=True)``
re-inserts the *entire* current buffer as result='pass'. Because
``store_test_cases_bulk`` upserts on id, the previously persisted crash row was
downgraded to 'pass' (and its crash-specific fields nulled), erasing the record
of which case crashed.

These tests cover both layers of the fix:
- the manager skips already-persisted ids on the final flush, and
- the ORM bulk upsert refuses to downgrade a non-'pass' row to 'pass'.
"""

from datetime import datetime
from types import SimpleNamespace

import pytest

from src.oida.fuzz.core.database.interface import TestCase
from src.oida.fuzz.core.database.orm import SQLAlchemyDatabase
from src.oida.fuzz.core.session.manager import TestCaseManager


class _FakeLog:
    def display(self, *a, **k):
        pass

    success = warning = fail = debug = display


def _make_fuzzer(monitor_check_interval=2):
    config = SimpleNamespace(
        session_filename="unused",
        monitor_check_interval=monitor_check_interval,
        protocol="modbus",
        seed=None,
        options={},
        target_ip="127.0.0.1",
        target_port=502,
    )
    # session attr is read via getattr; absence is fine for these tests.
    return SimpleNamespace(config=config, log=_FakeLog(), session=None)


def _make_manager():
    db = SQLAlchemyDatabase(":memory:")
    db.init_schema(store_all_payloads=False)
    fuzzer = _make_fuzzer()
    mgr = TestCaseManager(fuzzer, database=db, store_all_payloads=False)
    return mgr, db


# ---------------------------------------------------------------------------
# ORM-layer guard
# ---------------------------------------------------------------------------


def test_bulk_upsert_does_not_downgrade_crash_to_pass():
    db = SQLAlchemyDatabase(":memory:")
    db.init_schema(store_all_payloads=False)

    ts = datetime.now().isoformat()
    crash_row = TestCase(
        id=42,
        name="case_42",
        timestamp=ts,
        result="crash",
        crc32=0xDEADBEEF,
        duration_ms=12.5,
        monitor_status="down",
    )
    db.store_test_cases_bulk([crash_row])

    # Re-insert the same id as a plain 'pass' (what the final flush does).
    pass_row = TestCase(id=42, name="case_42", timestamp=ts, result="pass", crc32=0xDEADBEEF)
    db.store_test_cases_bulk([pass_row])

    got = db.get_test_case(42)
    assert got is not None
    assert got.result == "crash", "crash row must NOT be downgraded to 'pass'"
    assert got.duration_ms == 12.5
    assert got.monitor_status == "down"


def test_bulk_upsert_still_applies_genuine_updates():
    """A non-downgrade update (pass->crash, or pass->pass) is still applied."""
    db = SQLAlchemyDatabase(":memory:")
    db.init_schema(store_all_payloads=False)

    ts = datetime.now().isoformat()
    db.store_test_cases_bulk([TestCase(id=7, name="c7", timestamp=ts, result="pass", crc32=1)])
    # Upgrade pass -> crash must apply.
    db.store_test_cases_bulk(
        [TestCase(id=7, name="c7", timestamp=ts, result="crash", crc32=1, monitor_status="x")]
    )
    got = db.get_test_case(7)
    assert got.result == "crash"
    assert got.monitor_status == "x"


# ---------------------------------------------------------------------------
# Manager-level end-to-end flow
# ---------------------------------------------------------------------------


def test_final_flush_preserves_crash_record():
    mgr, db = _make_manager()

    # A couple of passing cases, then a crash. monitor_check_interval=2 so the
    # buffer comfortably holds all of them (maxsize clamped to >=100).
    mgr.record_test_case(test_id=1, name="c1", payload=b"\x01", result="pass")
    mgr.record_test_case(test_id=2, name="c2", payload=b"\x02", result="pass")
    mgr.record_test_case(test_id=3, name="c3", payload=b"\x03", result="crash", crash_info="boom")

    # Sanity: crash persisted.
    crash_case = db.get_test_case(3)
    assert crash_case is not None and crash_case.result == "crash"
    assert db.get_crash(3) is not None

    # End of session: this used to re-insert id=3 as 'pass'.
    mgr.save_session_progress(final=True)

    crash_case = db.get_test_case(3)
    assert crash_case is not None
    assert crash_case.result == "crash", "final flush must not downgrade the crash row"
    assert db.get_crash(3) is not None, "crash payload/diagnostics must survive"

    # The passing cases that were flushed as crash-context should remain 'pass'.
    assert db.get_test_case(1).result == "pass"
    assert db.get_test_case(2).result == "pass"


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
