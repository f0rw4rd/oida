"""Parity tests between MockDatabase and SQLAlchemyDatabase.

Verifies two previously-reproduced bugs stay fixed:

1. ``get_stats()`` must return the same key set from both backends —
   ``TestCaseManager.list_test_cases()`` reads ``stats['errors']``, which
   only ``MockDatabase`` used to provide, causing the real (SQLAlchemy)
   backend to silently return ``[]`` via a swallowed ``KeyError``.
2. ``get_test_cases()`` ordering must match between backends (both
   newest-first) — otherwise, once a session exceeds the default
   ``limit=10_000``, the two backends return disjoint halves of the data.
"""

from types import SimpleNamespace

import pytest

from oida.fuzz.core.database.interface import TestCase
from oida.fuzz.core.database.mock import MockDatabase
from oida.fuzz.core.database.orm import SQLAlchemyDatabase


def _make_test_case(i: int, result: str) -> TestCase:
    return TestCase(
        id=i,
        name=f"tc{i}",
        timestamp=f"2026-01-01T00:00:{i:02d}",
        result=result,
        crc32=i,
        target_ip="10.0.0.1",
        target_port=502,
        protocol="modbus",
    )


def _results_cycle(n: int):
    cycle = ["pass", "crash", "pass", "error"]
    return [cycle[i % len(cycle)] for i in range(n)]


class TestGetStatsKeyParity:
    def test_get_stats_same_key_set(self):
        mock_db = MockDatabase()
        mock_db.init_schema()
        orm_db = SQLAlchemyDatabase(":memory:")
        orm_db.init_schema()

        for i, result in enumerate(_results_cycle(4), start=1):
            tc = _make_test_case(i, result)
            mock_db.store_test_case(tc)
            orm_db.store_test_case(tc)

        mock_keys = set(mock_db.get_stats().keys())
        orm_keys = set(orm_db.get_stats().keys())

        missing_from_orm = mock_keys - orm_keys
        assert not missing_from_orm, (
            f"SQLAlchemyDatabase.get_stats() is missing keys that MockDatabase "
            f"provides: {missing_from_orm}"
        )

    def test_get_stats_errors_key_matches_error_count(self):
        orm_db = SQLAlchemyDatabase(":memory:")
        orm_db.init_schema()
        for i, result in enumerate(_results_cycle(8), start=1):
            orm_db.store_test_case(_make_test_case(i, result))

        stats = orm_db.get_stats()
        assert stats["errors"] == stats["error_count"]
        assert stats["errors"] == 2  # 8 cases cycling pass/crash/pass/error -> 2 errors

    def test_get_stats_crashes_stored_and_db_size_bytes(self):
        orm_db = SQLAlchemyDatabase(":memory:")
        orm_db.init_schema()
        for i, result in enumerate(_results_cycle(8), start=1):
            orm_db.store_test_case(_make_test_case(i, result))

        stats = orm_db.get_stats()
        assert "crashes_stored" in stats
        assert "db_size_bytes" in stats
        # in-memory database has no file, so bytes/mb stay at their zero defaults
        assert stats["db_size_bytes"] == 0
        assert stats["db_size_mb"] == 0.0


class TestListTestCasesAgainstRealBackend:
    def test_list_test_cases_returns_all_stored_cases(self):
        from oida.utils import ics_logger
        from oida.fuzz.core.session.manager import TestCaseManager

        db = SQLAlchemyDatabase(":memory:")
        db.init_schema()
        for i, result in enumerate(_results_cycle(4), start=1):
            db.store_test_case(_make_test_case(i, result))

        cfg = SimpleNamespace(
            monitor_check_interval=50,
            options={},
            protocol="modbus",
            seed=1,
            session_filename="s",
            lightweight_mode=True,
        )
        fuzzer = SimpleNamespace(config=cfg, log=ics_logger)
        mgr = TestCaseManager(fuzzer=fuzzer, database=db)

        result = mgr.list_test_cases()

        assert len(result) == 4, (
            f"expected all 4 stored test cases, got {len(result)} "
            "(list_test_cases() should not silently return [] against the "
            "real SQLAlchemy backend)"
        )


class TestGetTestCasesOrderingParity:
    def test_order_matches_between_backends(self):
        mock_db = MockDatabase()
        mock_db.init_schema()
        orm_db = SQLAlchemyDatabase(":memory:")
        orm_db.init_schema()

        for i, result in enumerate(_results_cycle(6), start=1):
            tc = _make_test_case(i, result)
            mock_db.store_test_case(tc)
            orm_db.store_test_case(tc)

        mock_ids = [tc.id for tc in mock_db.get_test_cases()]
        orm_ids = [tc.id for tc in orm_db.get_test_cases()]
        assert mock_ids == orm_ids == [6, 5, 4, 3, 2, 1]

    def test_order_matches_under_limit(self):
        mock_db = MockDatabase()
        mock_db.init_schema()
        orm_db = SQLAlchemyDatabase(":memory:")
        orm_db.init_schema()

        for i, result in enumerate(_results_cycle(6), start=1):
            tc = _make_test_case(i, result)
            mock_db.store_test_case(tc)
            orm_db.store_test_case(tc)

        mock_ids = [tc.id for tc in mock_db.get_test_cases(limit=2)]
        orm_ids = [tc.id for tc in orm_db.get_test_cases(limit=2)]
        assert mock_ids == orm_ids == [6, 5]


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
