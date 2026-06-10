"""
SQLAlchemy ORM implementation of DatabaseInterface

This module provides an ORM-based implementation of the DatabaseInterface
using SQLAlchemy for improved type safety, maintainability, and query building.
"""

import json
import os
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from contextlib import contextmanager

from sqlalchemy import select, and_, func, insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.engine import Engine

from .interface import DatabaseInterface, TestCase as TestCaseDTO, Crash as CrashDTO
from .models import (
    TestCase,
    Crash,
    Payload,
    SessionMetadata,
    CrashEvent,
    CrashContext,
    create_database_engine,
    create_all_tables,
)
from ....utils import ics_logger


class SQLAlchemyDatabase(DatabaseInterface):
    """
    SQLAlchemy ORM implementation of the DatabaseInterface.

    Provides all database operations using SQLAlchemy ORM for improved
    type safety, automatic relationship handling, and cleaner query syntax.
    """

    def __init__(self, database_path: str, echo: bool = False):
        """
        Initialize the SQLAlchemy database connection.

        Args:
            database_path: Path to the SQLite database file or ':memory:'
            echo: Whether to log all SQL statements (useful for debugging)
        """
        self.database_path = database_path
        self.engine: Engine = create_database_engine(database_path, echo=echo)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self._store_all_payloads = False
        self._initialized = False

    @contextmanager
    def get_session(self) -> Session:
        """
        Context manager for database sessions.

        Ensures proper session lifecycle management with automatic
        commit on success and rollback on error.
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def init_schema(self, store_all_payloads: bool = False) -> None:
        """
        Initialize the database schema.

        Args:
            store_all_payloads: Whether to create the payloads table
        """
        self._store_all_payloads = store_all_payloads

        # Create all tables
        create_all_tables(self.engine)

        # Store metadata
        with self.get_session() as session:
            # Store initial metadata
            metadata_entries = [
                SessionMetadata(key="schema_version", value="2.0"),  # ORM version
                SessionMetadata(key="created_at", value=datetime.now().isoformat()),
                SessionMetadata(key="orm_backend", value="sqlalchemy"),
                SessionMetadata(key="store_all_payloads", value=str(store_all_payloads)),
            ]

            for entry in metadata_entries:
                # Use merge to avoid duplicates on re-initialization
                session.merge(entry)

        self._initialized = True
        ics_logger.debug(f"Database initialized: {self.database_path}")

    def store_test_case(self, test_case: TestCaseDTO) -> int:
        """
        Store a test case in the database.

        Args:
            test_case: TestCase data transfer object

        Returns:
            The ID of the stored test case
        """
        if not self._initialized:
            raise RuntimeError("Database not initialized. Call init_schema() first.")

        with self.get_session() as session:
            # Create ORM model from DTO
            # Use provided ID if set (non-zero), otherwise let DB auto-generate
            orm_test_case = TestCase(
                id=test_case.id if test_case.id else None,
                name=test_case.name,
                timestamp=test_case.timestamp,
                result=test_case.result,
                crc32=test_case.crc32,
                target_ip=test_case.target_ip,
                target_port=test_case.target_port,
                protocol=test_case.protocol,
                duration_ms=test_case.duration_ms,
                monitor_status=test_case.monitor_status,
            )

            # Use merge for upsert behavior (update if exists, insert if not)
            orm_test_case = session.merge(orm_test_case)
            session.flush()  # Get the ID before commit
            test_case_id = orm_test_case.id

            ics_logger.debug(
                f"Stored test case {test_case_id}: {test_case.name} ({test_case.protocol}@{test_case.target_ip}:{test_case.target_port})"
            )
            return test_case_id

    def store_test_cases_bulk(self, test_cases: List[TestCaseDTO]) -> None:
        """Insert many test cases in a single transaction.

        Uses SQLite ``INSERT OR REPLACE`` so existing rows with the same id
        are overwritten (same semantics as ``store_test_case``'s ``merge``),
        but without per-row SELECT/flush round-trips.
        """
        if not self._initialized:
            raise RuntimeError("Database not initialized. Call init_schema() first.")
        if not test_cases:
            return

        rows = [
            {
                "id": tc.id if tc.id else None,
                "name": tc.name,
                "timestamp": tc.timestamp,
                "result": tc.result,
                "crc32": tc.crc32,
                "target_ip": tc.target_ip,
                "target_port": tc.target_port,
                "protocol": tc.protocol,
                "duration_ms": tc.duration_ms,
                "monitor_status": tc.monitor_status,
            }
            for tc in test_cases
        ]

        with self.get_session() as session:
            stmt = sqlite_insert(TestCase).prefix_with("OR REPLACE")
            session.execute(stmt, rows)

    def store_crash(self, crash: CrashDTO) -> None:
        """
        Store crash information for a test case (upsert - update if exists).

        Args:
            crash: Crash data transfer object with test_case_id, payload, crash_info, stack_trace
        """
        with self.get_session() as session:
            # Check if crash already exists for this test case
            existing_crash = session.query(Crash).filter_by(test_case_id=crash.test_case_id).first()

            crash_hash = Crash.compute_crash_hash(crash.crash_info, crash.stack_trace)

            if existing_crash:
                # Update existing crash record
                existing_crash.payload = crash.payload
                existing_crash.crash_info = crash.crash_info
                existing_crash.stack_trace = crash.stack_trace
                existing_crash.crash_hash = crash_hash
                ics_logger.debug(f"Updated existing crash for test case {crash.test_case_id}")
            else:
                # Verify test case exists
                test_case = session.get(TestCase, crash.test_case_id)
                if not test_case:
                    raise ValueError(f"Test case {crash.test_case_id} not found")

                # Create new crash record
                orm_crash = Crash(
                    test_case_id=crash.test_case_id,
                    payload=crash.payload,
                    crash_info=crash.crash_info,
                    stack_trace=crash.stack_trace,
                    crash_hash=crash_hash,
                )
                session.add(orm_crash)
                ics_logger.debug(
                    f"Stored crash for test case {crash.test_case_id} (hash={crash_hash})"
                )

    def store_payload(
        self, test_case_id: int, request: bytes, response: Optional[bytes] = None
    ) -> None:
        """
        Store payload for a test case (when --store-all-payloads is enabled).

        Args:
            test_case_id: ID of the test case
            request: The request payload bytes
            response: The response payload bytes (optional)
        """
        if not self._store_all_payloads:
            ics_logger.debug("Payload storage disabled, skipping")
            return

        with self.get_session() as session:
            # Verify test case exists
            test_case = session.get(TestCase, test_case_id)
            if not test_case:
                raise ValueError(f"Test case {test_case_id} not found")

            # Store both request and response in a structured format
            payload_data = {
                "request": request.hex() if request else None,
                "response": response.hex() if response else None,
            }

            # Create payload record
            orm_payload = Payload(
                test_case_id=test_case_id, payload=json.dumps(payload_data).encode("utf-8")
            )

            session.add(orm_payload)
            ics_logger.debug(f"Stored payload for test case {test_case_id}")

    @staticmethod
    def _to_dto(tc: TestCase) -> TestCaseDTO:
        """Convert a TestCase ORM model to a TestCaseDTO."""
        return TestCaseDTO(
            id=tc.id,
            name=tc.name,
            timestamp=tc.timestamp,
            result=tc.result,
            crc32=tc.crc32,
            target_ip=tc.target_ip,
            target_port=tc.target_port,
            protocol=tc.protocol,
            duration_ms=tc.duration_ms,
            monitor_status=tc.monitor_status,
        )

    def get_test_case(self, test_case_id: int) -> Optional[TestCaseDTO]:
        """
        Retrieve a test case by ID.

        Args:
            test_case_id: The test case ID

        Returns:
            TestCase DTO or None if not found
        """
        with self.get_session() as session:
            test_case = session.get(TestCase, test_case_id)
            if test_case:
                return self._to_dto(test_case)
        return None

    def get_test_cases(
        self,
        result_filter: Optional[str] = None,
        target_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        limit: Optional[int] = 10_000,
    ) -> List[TestCaseDTO]:
        """
        Get test cases, optionally filtered by result, target, or protocol.

        Args:
            result_filter: Optional filter for test case result
            target_ip: Optional filter for target IP
            protocol: Optional filter for protocol name
            limit: Cap on number of rows returned. Defaults to 10k to
                prevent OOM on million-case sessions. Pass ``None`` to
                disable the cap (slow!).

        Returns:
            List of TestCase DTOs
        """
        with self.get_session() as session:
            query = select(TestCase)

            if result_filter:
                query = query.where(TestCase.result == result_filter)
            if target_ip:
                query = query.where(TestCase.target_ip == target_ip)
            if protocol:
                query = query.where(TestCase.protocol == protocol)

            query = query.order_by(TestCase.timestamp.desc())
            if limit is not None:
                query = query.limit(limit)

            test_cases = session.execute(query).scalars().all()
            return [self._to_dto(tc) for tc in test_cases]

    def get_crash(self, test_case_id: int) -> Optional[CrashDTO]:
        """
        Get crash information for a test case.

        Args:
            test_case_id: The test case ID

        Returns:
            Crash DTO or None if no crash found
        """
        with self.get_session() as session:
            crash = session.get(Crash, test_case_id)

            if crash:
                return CrashDTO(
                    test_case_id=crash.test_case_id,
                    payload=crash.payload,
                    crash_info=crash.crash_info,
                    stack_trace=crash.stack_trace,
                    crash_hash=crash.crash_hash,
                )

        return None

    def get_payload(self, test_case_id: int) -> Optional[dict]:
        """
        Get payload for a test case.

        Checks both the crashes table and payloads table (if enabled).

        Args:
            test_case_id: The test case ID

        Returns:
            Dict with 'request' and 'response' keys containing bytes, or None if not found
        """
        with self.get_session() as session:
            # First check crashes table
            crash = session.get(Crash, test_case_id)
            if crash:
                # Crash payload is stored as raw bytes (legacy format)
                return {"request": crash.payload, "response": None}

            # Then check payloads table if enabled
            if self._store_all_payloads:
                payload = session.get(Payload, test_case_id)
                if payload:
                    try:
                        # Try to parse as JSON (new format)
                        payload_data = json.loads(payload.payload.decode("utf-8"))
                        return {
                            "request": bytes.fromhex(payload_data["request"])
                            if payload_data.get("request")
                            else None,
                            "response": bytes.fromhex(payload_data["response"])
                            if payload_data.get("response")
                            else None,
                        }
                    except (json.JSONDecodeError, ValueError, AttributeError):
                        # Fall back to legacy format (raw bytes)
                        return {"request": payload.payload, "response": None}

        return None

    def store_metadata(self, key: str, value: str) -> None:
        """
        Store or update session metadata.

        Args:
            key: Metadata key
            value: Metadata value
        """
        with self.get_session() as session:
            # Use merge to update if exists, insert if not
            metadata = SessionMetadata(key=key, value=value)
            session.merge(metadata)
        ics_logger.debug(f"Stored metadata: {key}={value}")

    def store_metadata_bulk(self, items: Dict[str, str]) -> None:
        """Upsert many metadata keys in a single transaction."""
        if not items:
            return
        rows = [{"key": k, "value": v} for k, v in items.items()]
        with self.get_session() as session:
            stmt = sqlite_insert(SessionMetadata).prefix_with("OR REPLACE")
            session.execute(stmt, rows)

    def get_metadata(self, key: str) -> Optional[str]:
        """
        Get session metadata value.

        Args:
            key: Metadata key

        Returns:
            Metadata value or None if not found
        """
        with self.get_session() as session:
            metadata = session.get(SessionMetadata, key)
            return metadata.value if metadata else None

    def get_all_metadata(self) -> Dict[str, str]:
        """
        Get all session metadata.

        Returns:
            Dictionary of metadata key-value pairs
        """
        with self.get_session() as session:
            metadata_entries = session.execute(select(SessionMetadata)).scalars().all()
            return {entry.key: entry.value for entry in metadata_entries}

    def get_target_stats(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """
        Get statistics for a specific target.

        Args:
            target_ip: Target IP address
            target_port: Target port

        Returns:
            Dictionary with target-specific statistics
        """
        with self.get_session() as session:
            # Get test case count for this target
            total_count = (
                session.execute(
                    select(func.count(TestCase.id)).where(
                        and_(TestCase.target_ip == target_ip, TestCase.target_port == target_port)
                    )
                ).scalar()
                or 0
            )

            # Get last test case ID for this target
            last_id = session.execute(
                select(func.max(TestCase.id)).where(
                    and_(TestCase.target_ip == target_ip, TestCase.target_port == target_port)
                )
            ).scalar()

            # Get crash count for this target (join with test_cases)
            crash_count = (
                session.execute(
                    select(func.count(Crash.test_case_id))
                    .join(TestCase, Crash.test_case_id == TestCase.id)
                    .where(
                        and_(TestCase.target_ip == target_ip, TestCase.target_port == target_port)
                    )
                ).scalar()
                or 0
            )

            return {
                "total_count": total_count,
                "last_id": last_id,
                "crash_count": crash_count,
            }

    def get_stats(self) -> Dict[str, Any]:
        """
        Get database statistics.

        Returns:
            Dictionary with statistics about the database
        """
        with self.get_session() as session:
            # Single aggregate query over test_cases (was 8 round-trips).
            agg_row = session.execute(
                select(
                    func.count(TestCase.id).label("total"),
                    func.sum(func.iif(TestCase.result == "pass", 1, 0)).label("pass_count"),
                    func.sum(func.iif(TestCase.result == "fail", 1, 0)).label("fail_count"),
                    func.sum(func.iif(TestCase.result == "crash", 1, 0)).label("crash_count"),
                    func.sum(func.iif(TestCase.result == "error", 1, 0)).label("error_count"),
                    func.avg(TestCase.duration_ms).label("avg_duration"),
                    func.min(TestCase.timestamp).label("oldest"),
                    func.max(TestCase.timestamp).label("newest"),
                )
            ).one()

            total_count = agg_row.total or 0
            result_counts = {
                "pass": agg_row.pass_count or 0,
                "fail": agg_row.fail_count or 0,
                "crash": agg_row.crash_count or 0,
                "error": agg_row.error_count or 0,
            }
            avg_duration = agg_row.avg_duration
            oldest = agg_row.oldest
            newest = agg_row.newest

            crashes_with_payloads = session.execute(select(func.count(Crash.test_case_id))).scalar()

            total_payloads = 0
            if self._store_all_payloads:
                total_payloads = session.execute(select(func.count(Payload.test_case_id))).scalar()

            # Get metadata for session progress (from rolling buffer saves)
            last_test_case_meta = session.get(SessionMetadata, "last_test_case")
            total_processed_meta = session.get(SessionMetadata, "total_processed")
            crash_count_meta = session.get(SessionMetadata, "crash_count")
            final_mutant_index_meta = session.get(SessionMetadata, "final_mutant_index")
            resume_base_meta = session.get(SessionMetadata, "resume_base")

            # Use metadata values if DB has no test cases (rolling buffer mode)
            last_test_case = int(last_test_case_meta.value) if last_test_case_meta else total_count
            total_processed = (
                int(total_processed_meta.value) if total_processed_meta else total_count
            )
            # boofuzz's total_mutant_index at session end (mutation-space position; counts
            # cases that were sent PLUS mutations skipped by crash-threshold/resume). Falls
            # back to total_processed when absent so callers never see a value below the
            # sent count.
            final_mutant_index = (
                int(final_mutant_index_meta.value)
                if final_mutant_index_meta
                else total_processed
            )
            # Mutations covered by earlier sessions and fast-forwarded on resume
            # (index_start-1). Lets callers exclude resumed cases from "skipped".
            resume_base = int(resume_base_meta.value) if resume_base_meta else 0
            total_crashes = (
                int(crash_count_meta.value) if crash_count_meta else crashes_with_payloads
            )

            # Get database file size
            db_size_mb = 0.0
            if self.database_path and self.database_path != ":memory:":
                try:
                    db_size_mb = os.path.getsize(self.database_path) / (1024 * 1024)
                except OSError as e:
                    ics_logger.debug(f"Failed to get database file size: {e}")

            return {
                "total_test_cases": total_count,
                "last_test_case": last_test_case,  # From metadata (rolling buffer)
                "total_processed": total_processed,  # From metadata (rolling buffer)
                "final_mutant_index": final_mutant_index,  # boofuzz position = resume_base + sent + skipped
                "resume_base": resume_base,  # cases fast-forwarded from earlier sessions
                "total_crashes": total_crashes,  # From metadata (rolling buffer)
                "results": result_counts,
                "pass_count": result_counts.get("pass", 0),  # Alias for backward compatibility
                "fail_count": result_counts.get("fail", 0),  # Alias for backward compatibility
                "crash_count": result_counts.get("crash", 0),  # Alias for backward compatibility
                "error_count": result_counts.get("error", 0),  # Alias for backward compatibility
                "passed": result_counts.get("pass", 0),  # Alias
                "failed": result_counts.get("fail", 0),  # Alias
                "crashed": result_counts.get("crash", 0),  # Alias
                "average_duration_ms": float(avg_duration) if avg_duration else 0.0,
                "crashes_with_payloads": crashes_with_payloads,
                "total_payloads_stored": total_payloads,
                "date_range": {"oldest": oldest, "newest": newest},
                "database_path": self.database_path,
                "db_size_mb": db_size_mb,
                "orm_backend": "sqlalchemy",
                "store_all_payloads": self._store_all_payloads,
            }

    def search_test_cases(
        self,
        name_pattern: Optional[str] = None,
        result_filter: Optional[str] = None,
        target_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 100,
    ) -> List[TestCaseDTO]:
        """
        Search test cases with various filters.

        Args:
            name_pattern: Pattern to match in test case names (SQL LIKE syntax)
            result_filter: Filter by result type
            target_ip: Filter by target IP address
            protocol: Filter by protocol name
            start_date: Filter by start date (ISO format)
            end_date: Filter by end date (ISO format)
            limit: Maximum number of results

        Returns:
            List of matching TestCase DTOs
        """
        with self.get_session() as session:
            query = select(TestCase)

            # Apply filters
            conditions = []

            if name_pattern:
                # Escape backslash first, then LIKE wildcards, to avoid double-escaping
                escaped = name_pattern.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
                conditions.append(TestCase.name.like(f"%{escaped}%", escape="\\"))

            if result_filter:
                conditions.append(TestCase.result == result_filter)

            if target_ip:
                conditions.append(TestCase.target_ip == target_ip)

            if protocol:
                conditions.append(TestCase.protocol == protocol)

            if start_date:
                conditions.append(TestCase.timestamp >= start_date)

            if end_date:
                conditions.append(TestCase.timestamp <= end_date)

            if conditions:
                query = query.where(and_(*conditions))

            # Order and limit
            query = query.order_by(TestCase.timestamp.desc()).limit(limit)

            test_cases = session.execute(query).scalars().all()
            return [self._to_dto(tc) for tc in test_cases]

    def cleanup_old_data(self, days_to_keep: int = 30) -> int:
        """
        Remove test cases older than specified days.

        Args:
            days_to_keep: Number of days to keep data

        Returns:
            Number of deleted test cases
        """
        with self.get_session() as session:
            # Calculate cutoff date
            cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()

            # Find old test cases
            old_test_cases = (
                session.execute(select(TestCase).where(TestCase.timestamp < cutoff_date))
                .scalars()
                .all()
            )

            count = len(old_test_cases)

            # Delete them (cascades to crashes and payloads)
            for tc in old_test_cases:
                session.delete(tc)

            ics_logger.display(f"Cleaned up {count} test cases older than {days_to_keep} days")
            return count

    def store_crash_context(
        self,
        detected_at_id: int,
        crash_info: Optional[str],
        target_ip: Optional[str],
        target_port: Optional[int],
        protocol: Optional[str],
        buffer_contents: List[tuple],
    ) -> int:
        """
        Store crash event with full buffer context.

        This method stores a crash event along with all test cases that were
        in the rolling buffer at the time of crash detection.

        Args:
            detected_at_id: Test case ID where crash was detected
            crash_info: Crash description/error message
            target_ip: Target IP address
            target_port: Target port
            protocol: Protocol name
            buffer_contents: List of tuples (test_case_id, name, payload, timestamp, crc32)

        Returns:
            The ID of the created CrashEvent
        """
        with self.get_session() as session:
            # Create crash event
            crash_event = CrashEvent(
                detected_at_id=detected_at_id,
                crash_info=crash_info,
                timestamp=datetime.now().isoformat(),
                target_ip=target_ip,
                target_port=target_port,
                protocol=protocol,
                context_size=len(buffer_contents),
            )
            session.add(crash_event)
            session.flush()  # Get the ID

            # Bulk-insert all buffer contents (avoids ORM per-row overhead).
            if buffer_contents:
                session.execute(
                    insert(CrashContext),
                    [
                        {
                            "crash_event_id": crash_event.id,
                            "test_case_id": tc_id,
                            "name": tc_name,
                            "payload": tc_payload,
                            "timestamp": tc_timestamp,
                            "crc32": tc_crc32,
                        }
                        for tc_id, tc_name, tc_payload, tc_timestamp, tc_crc32 in buffer_contents
                    ],
                )

            ics_logger.display(
                f"Stored crash event {crash_event.id} with {len(buffer_contents)} context entries"
            )
            return crash_event.id

    def get_crash_event(self, crash_event_id: int) -> Optional[dict]:
        """
        Get crash event with its context entries.

        Args:
            crash_event_id: The crash event ID

        Returns:
            Dictionary with crash event and context, or None if not found
        """
        with self.get_session() as session:
            crash_event = session.get(CrashEvent, crash_event_id)

            if not crash_event:
                return None

            return {
                "event": crash_event.to_dict(),
                "context": [entry.to_dict() for entry in crash_event.context_entries],
            }

    def get_crash_events(
        self, protocol: Optional[str] = None, target_ip: Optional[str] = None, limit: int = 100
    ) -> List[dict]:
        """
        Get all crash events, optionally filtered.

        Args:
            protocol: Optional filter by protocol
            target_ip: Optional filter by target IP
            limit: Maximum number of results

        Returns:
            List of crash event dictionaries
        """
        with self.get_session() as session:
            query = select(CrashEvent)

            if protocol:
                query = query.where(CrashEvent.protocol == protocol)
            if target_ip:
                query = query.where(CrashEvent.target_ip == target_ip)

            query = query.order_by(CrashEvent.timestamp.desc()).limit(limit)

            crash_events = session.execute(query).scalars().all()

            return [event.to_dict() for event in crash_events]

    def get_crash_context_payload(self, crash_event_id: int, test_case_id: int) -> Optional[bytes]:
        """
        Get a specific payload from crash context.

        Args:
            crash_event_id: The crash event ID
            test_case_id: The test case ID within the context

        Returns:
            Payload bytes, or None if not found
        """
        with self.get_session() as session:
            context = session.execute(
                select(CrashContext).where(
                    and_(
                        CrashContext.crash_event_id == crash_event_id,
                        CrashContext.test_case_id == test_case_id,
                    )
                )
            ).scalar_one_or_none()

            return context.payload if context else None

    def close(self) -> None:
        """Close the database connection."""
        if hasattr(self, "engine"):
            self.engine.dispose()
            ics_logger.debug("Closed SQLAlchemy database connection")
