"""In-memory ``MockDatabase`` for fuzzer unit tests.

Implements :class:`DatabaseInterface` without touching disk. Used by tests
that exercise fuzzer control flow but do not care about persistence.
The production backend is :class:`oida.fuzz.core.database.orm.SQLAlchemyDatabase`.
"""

from typing import Any, Dict, List, Optional

from .interface import Crash, DatabaseInterface, TestCase


class MockDatabase(DatabaseInterface):
    """In-memory ``DatabaseInterface`` implementation for tests."""

    def __init__(self):
        self.test_cases: List[TestCase] = []
        self.crashes: Dict[int, Crash] = {}
        self.metadata: Dict[str, str] = {}
        self._initialized = False

    def init_schema(self, store_all_payloads: bool = False):
        self._initialized = True

    def store_test_case(self, test_case: TestCase) -> Optional[int]:
        self.test_cases.append(test_case)
        return test_case.id

    def store_test_cases_bulk(self, test_cases: List[TestCase]) -> None:
        self.test_cases.extend(test_cases)

    def store_crash(self, crash: Crash):
        # Populate crash_hash on store so tests see the same behaviour as the
        # production backend.
        if crash.crash_hash is None:
            try:
                from .models import Crash as ORMCrash

                crash.crash_hash = ORMCrash.compute_crash_hash(crash.crash_info, crash.stack_trace)
            except ImportError:
                pass  # sqlalchemy not installed; tests that need hash will fail explicitly
        self.crashes[crash.test_case_id] = crash

    def store_metadata(self, key: str, value: str):
        self.metadata[key] = value

    def store_metadata_bulk(self, items: Dict[str, str]) -> None:
        self.metadata.update(items)

    def get_test_cases(
        self,
        result_filter: Optional[str] = None,
        target_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        limit: Optional[int] = 10_000,
    ) -> List[TestCase]:
        rows = self.test_cases
        if result_filter:
            rows = [tc for tc in rows if tc.result == result_filter]
        if target_ip:
            rows = [tc for tc in rows if tc.target_ip == target_ip]
        if protocol:
            rows = [tc for tc in rows if tc.protocol == protocol]
        if limit is not None:
            rows = rows[:limit]
        return list(rows)

    def get_test_case(self, test_id: int) -> Optional[TestCase]:
        for tc in self.test_cases:
            if tc.id == test_id:
                return tc
        return None

    def get_crash(self, test_id: int) -> Optional[Crash]:
        return self.crashes.get(test_id)

    def get_metadata(self, key: str) -> Optional[str]:
        return self.metadata.get(key)

    def get_all_metadata(self) -> Dict[str, str]:
        return self.metadata.copy()

    def get_stats(self) -> Dict[str, Any]:
        by_result: Dict[str, int] = {}
        for tc in self.test_cases:
            by_result[tc.result] = by_result.get(tc.result, 0) + 1

        passed = by_result.get("pass", 0)
        failed = by_result.get("fail", 0)
        crashed = by_result.get("crash", 0)
        errors = by_result.get("error", 0)

        return {
            "total_test_cases": len(self.test_cases),
            "passed": passed,
            "failed": failed,
            "crashed": crashed,
            "errors": errors,
            "pass_count": passed,  # backward compatibility
            "fail_count": failed,  # backward compatibility
            "crashes_stored": len(self.crashes),
            "db_size_bytes": 0,
            "db_size_mb": 0.0,
        }
