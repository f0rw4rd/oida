"""
SQLite implementation of DatabaseInterface for OIDA fuzzer session storage.
"""

import sqlite3
import os
from typing import List, Optional, Dict, Any

from .interface import DatabaseInterface, TestCase, Crash
from ....utils.ics_logger import get_logger


_log = get_logger("DB", "sqlite", 0)


class SQLiteDatabase(DatabaseInterface):
    """Lightweight SQLite database implementation"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._initialized = False

    def _get_connection(self):
        """Create database connection with context management"""
        return sqlite3.connect(self.db_path)

    def init_schema(self, store_all_payloads: bool = False):
        """
        Initialize lightweight database schema.

        Args:
            store_all_payloads: If True, store all payloads (old behavior)
                               If False, store only crashes (lightweight mode)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Test cases table - lightweight metadata only
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_cases (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    result TEXT NOT NULL CHECK(result IN ('pass', 'fail', 'crash', 'error')),
                    crc32 INTEGER NOT NULL,
                    duration_ms REAL,
                    monitor_status TEXT
                )
            """)

            # Crashes table - full payload ONLY for crashes
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS crashes (
                    test_case_id INTEGER PRIMARY KEY,
                    payload BLOB NOT NULL,
                    crash_info TEXT,
                    stack_trace TEXT,
                    FOREIGN KEY(test_case_id) REFERENCES test_cases(id)
                )
            """)

            # Session metadata for replay validation
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS session_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)

            # Optional: Store all payloads table (for --store-all-payloads mode)
            if store_all_payloads:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS payloads (
                        test_case_id INTEGER PRIMARY KEY,
                        payload BLOB NOT NULL,
                        FOREIGN KEY(test_case_id) REFERENCES test_cases(id)
                    )
                """)
                _log.display(
                    "Initialized database with full payload storage (--store-all-payloads mode)"
                )
            else:
                _log.display("Initialized database with lightweight storage (default mode)")

            # Create indexes for performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_test_cases_result
                ON test_cases(result)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_test_cases_timestamp
                ON test_cases(timestamp)
            """)

            conn.commit()
            self._initialized = True

    def store_test_case(self, test_case: TestCase) -> Optional[int]:
        """Store lightweight test case metadata"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Use INSERT OR REPLACE to handle session resumption
            # This allows re-running the same test case without errors
            cursor.execute(
                """
                INSERT OR REPLACE INTO test_cases
                (id, name, timestamp, result, crc32, duration_ms, monitor_status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    test_case.id,
                    test_case.name,
                    test_case.timestamp,
                    test_case.result,
                    test_case.crc32,
                    test_case.duration_ms,
                    test_case.monitor_status,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def store_crash(self, crash: Crash):
        """Store crash with full payload"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Use INSERT OR REPLACE to handle session resumption
            cursor.execute(
                """
                INSERT OR REPLACE INTO crashes
                (test_case_id, payload, crash_info, stack_trace)
                VALUES (?, ?, ?, ?)
            """,
                (crash.test_case_id, crash.payload, crash.crash_info, crash.stack_trace),
            )
            conn.commit()

    def store_metadata(self, key: str, value: str):
        """Store session metadata"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO session_metadata (key, value)
                VALUES (?, ?)
            """,
                (key, value),
            )
            conn.commit()

    def get_test_cases(self, result_filter: Optional[str] = None) -> List[TestCase]:
        """Get all test cases, optionally filtered by result"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if result_filter:
                cursor.execute(
                    """
                    SELECT id, name, timestamp, result, crc32, duration_ms, monitor_status
                    FROM test_cases
                    WHERE result = ?
                    ORDER BY id
                """,
                    (result_filter,),
                )
            else:
                cursor.execute("""
                    SELECT id, name, timestamp, result, crc32, duration_ms, monitor_status
                    FROM test_cases
                    ORDER BY id
                """)

            results = cursor.fetchall()
            return [
                TestCase(
                    id=row[0],
                    name=row[1],
                    timestamp=row[2],
                    result=row[3],
                    crc32=row[4],
                    duration_ms=row[5],
                    monitor_status=row[6],
                )
                for row in results
            ]

    def get_test_case(self, test_id: int) -> Optional[TestCase]:
        """Get specific test case by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, name, timestamp, result, crc32, duration_ms, monitor_status
                FROM test_cases
                WHERE id = ?
            """,
                (test_id,),
            )

            result = cursor.fetchone()
            if not result:
                return None

            return TestCase(
                id=result[0],
                name=result[1],
                timestamp=result[2],
                result=result[3],
                crc32=result[4],
                duration_ms=result[5],
                monitor_status=result[6],
            )

    def get_crash(self, test_id: int) -> Optional[Crash]:
        """Get crash information with payload"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT test_case_id, payload, crash_info, stack_trace
                FROM crashes
                WHERE test_case_id = ?
            """,
                (test_id,),
            )

            result = cursor.fetchone()
            if not result:
                return None

            return Crash(
                test_case_id=result[0],
                payload=result[1],
                crash_info=result[2],
                stack_trace=result[3],
            )

    def get_metadata(self, key: str) -> Optional[str]:
        """Get session metadata value"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT value FROM session_metadata WHERE key = ?
            """,
                (key,),
            )

            result = cursor.fetchone()
            return result[0] if result else None

    def get_all_metadata(self) -> Dict[str, str]:
        """Get all session metadata"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM session_metadata")

            return {row[0]: row[1] for row in cursor.fetchall()}

    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Total test cases
            cursor.execute("SELECT COUNT(*) FROM test_cases")
            total = cursor.fetchone()[0]

            # Count by result
            cursor.execute("""
                SELECT result, COUNT(*)
                FROM test_cases
                GROUP BY result
            """)
            by_result = {row[0]: row[1] for row in cursor.fetchall()}

            # Database file size
            db_size_bytes = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0

            # Crash count
            cursor.execute("SELECT COUNT(*) FROM crashes")
            crashes_stored = cursor.fetchone()[0]

            passed = by_result.get("pass", 0)
            failed = by_result.get("fail", 0)
            crashed = by_result.get("crash", 0)
            errors = by_result.get("error", 0)

            return {
                "total_test_cases": total,
                "passed": passed,
                "failed": failed,
                "crashed": crashed,
                "errors": errors,
                "pass_count": passed,  # Alias for backward compatibility
                "fail_count": failed,  # Alias for backward compatibility
                "crashes_stored": crashes_stored,
                "db_size_bytes": db_size_bytes,
                "db_size_mb": round(db_size_bytes / 1024 / 1024, 2),
            }


class MockDatabase(DatabaseInterface):
    """Mock database for testing"""

    def __init__(self):
        self.test_cases = []
        self.crashes = {}  # test_case_id -> Crash
        self.metadata = {}
        self._initialized = False

    def init_schema(self, store_all_payloads: bool = False):
        """Initialize mock database"""
        self._initialized = True

    def store_test_case(self, test_case: TestCase) -> Optional[int]:
        """Store test case metadata"""
        self.test_cases.append(test_case)
        return test_case.id

    def store_crash(self, crash: Crash):
        """Store crash with full payload"""
        self.crashes[crash.test_case_id] = crash

    def store_metadata(self, key: str, value: str):
        """Store session metadata"""
        self.metadata[key] = value

    def get_test_cases(self, result_filter: Optional[str] = None) -> List[TestCase]:
        """Get all test cases, optionally filtered by result"""
        if result_filter:
            return [tc for tc in self.test_cases if tc.result == result_filter]
        return self.test_cases.copy()

    def get_test_case(self, test_id: int) -> Optional[TestCase]:
        """Get specific test case by ID"""
        for tc in self.test_cases:
            if tc.id == test_id:
                return tc
        return None

    def get_crash(self, test_id: int) -> Optional[Crash]:
        """Get crash information with payload"""
        return self.crashes.get(test_id)

    def get_metadata(self, key: str) -> Optional[str]:
        """Get session metadata value"""
        return self.metadata.get(key)

    def get_all_metadata(self) -> Dict[str, str]:
        """Get all session metadata"""
        return self.metadata.copy()

    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        by_result = {}
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
            "pass_count": passed,  # Alias for backward compatibility
            "fail_count": failed,  # Alias for backward compatibility
            "crashes_stored": len(self.crashes),
            "db_size_bytes": 0,
            "db_size_mb": 0.0,
        }

    def add_test_case(self, test_case: TestCase):
        """Backward compatibility wrapper for store_test_case"""
        self.store_test_case(test_case)

    def get_test_case_steps(self, test_id: int) -> List[Dict[str, Any]]:
        """Get test case steps (backward compatibility stub)"""
        return []

    def get_test_case_info(self, test_id: int) -> Optional[Dict[str, Any]]:
        """Get test case information with details"""
        tc = self.get_test_case(test_id)
        if not tc:
            return None

        info = {
            "id": tc.id,
            "name": tc.name,
            "timestamp": tc.timestamp,
            "result": tc.result,
            "crc32": tc.crc32,
            "duration_ms": tc.duration_ms,
            "monitor_status": tc.monitor_status,
        }

        # Add crash info if available
        crash = self.get_crash(test_id)
        if crash:
            info["crash_info"] = crash.crash_info
            info["stack_trace"] = crash.stack_trace
            info["payload_size"] = len(crash.payload)

        return info
