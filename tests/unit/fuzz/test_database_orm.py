"""
Tests for SQLAlchemy ORM database implementation.

Tests cover:
- ORM models: TestCase, Crash, Payload, SessionMetadata
- SQLAlchemyDatabase: initialization, schema creation
- SQLAlchemyDatabase: CRUD operations for test cases and crashes
- SQLAlchemyDatabase: session management (context manager)
- DatabaseInterface: abstract interface enforcement
- Database models: create_database_engine, create_all_tables
"""

import pytest
import os
import tempfile
from datetime import datetime


def _setup_logging_context():
    """Set up logging context needed by ORM operations."""
    from oida.utils.ics_logger import set_context

    try:
        set_context("TEST", "localhost", 0)
    except Exception:
        pass


# =============================================================================
# Test Database Models
# =============================================================================


class TestDatabaseModels:
    """Tests for ORM model definitions."""

    def test_test_case_model_fields(self):
        """TestCase model has expected fields."""
        from oida.fuzz.core.database.models import TestCase

        tc = TestCase(name="test_1", timestamp=datetime.now().isoformat(), result="pass")
        assert tc.name == "test_1"
        assert tc.result == "pass"

    def test_crash_model_fields(self):
        """Crash model has expected fields."""
        from oida.fuzz.core.database.models import Crash

        crash = Crash(test_case_id=1, payload=b"\x00\x01\x02", crash_info="segfault")
        assert crash.test_case_id == 1
        assert crash.payload == b"\x00\x01\x02"
        assert crash.crash_info == "segfault"

    def test_payload_model_fields(self):
        """Payload model has expected fields."""
        from oida.fuzz.core.database.models import Payload

        payload = Payload(test_case_id=1, payload=b"\x00\x01\x02")
        assert payload.test_case_id == 1
        assert payload.payload == b"\x00\x01\x02"

    def test_session_metadata_model(self):
        """SessionMetadata model has expected fields."""
        from oida.fuzz.core.database.models import SessionMetadata

        meta = SessionMetadata(key="protocol", value="modbus")
        assert meta.key == "protocol"
        assert meta.value == "modbus"


class TestCreateDatabaseEngine:
    """Tests for database engine creation."""

    def test_create_in_memory_engine(self):
        """Create in-memory SQLite engine."""
        from oida.fuzz.core.database.models import create_database_engine

        engine = create_database_engine(":memory:")
        assert engine is not None
        engine.dispose()

    def test_create_file_engine(self):
        """Create file-based SQLite engine."""
        from oida.fuzz.core.database.models import create_database_engine

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            engine = create_database_engine(db_path)
            assert engine is not None
            engine.dispose()
        finally:
            os.unlink(db_path)

    def test_create_all_tables(self):
        """create_all_tables creates tables without error."""
        from oida.fuzz.core.database.models import create_database_engine, create_all_tables

        engine = create_database_engine(":memory:")
        create_all_tables(engine)  # Should not raise
        engine.dispose()


# =============================================================================
# Test DatabaseInterface
# =============================================================================


class TestDatabaseInterface:
    """Tests for DatabaseInterface abstract class."""

    def test_cannot_instantiate_directly(self):
        """DatabaseInterface cannot be instantiated directly."""
        from oida.fuzz.core.database.interface import DatabaseInterface

        with pytest.raises(TypeError):
            DatabaseInterface()


# =============================================================================
# Test SQLAlchemyDatabase
# =============================================================================


class TestSQLAlchemyDatabaseInit:
    """Tests for SQLAlchemyDatabase initialization."""

    def test_create_in_memory(self):
        """Create in-memory database."""
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase

        db = SQLAlchemyDatabase(":memory:")
        assert db is not None
        assert db.database_path == ":memory:"

    def test_init_schema(self):
        """Initialize schema creates tables."""
        _setup_logging_context()
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase

        db = SQLAlchemyDatabase(":memory:")
        db.init_schema()
        assert db._initialized is True

    def test_init_schema_idempotent(self):
        """init_schema can be called multiple times."""
        _setup_logging_context()
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase

        db = SQLAlchemyDatabase(":memory:")
        db.init_schema()
        db.init_schema()  # Should not raise


class TestSQLAlchemyDatabaseSession:
    """Tests for database session context manager."""

    def test_get_session_context_manager(self):
        """Session context manager provides session."""
        _setup_logging_context()
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase

        db = SQLAlchemyDatabase(":memory:")
        db.init_schema()
        with db.get_session() as session:
            assert session is not None


class TestSQLAlchemyDatabaseTestCases:
    """Tests for test case CRUD operations."""

    @pytest.fixture
    def db(self):
        """Create initialized in-memory database."""
        _setup_logging_context()
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase

        database = SQLAlchemyDatabase(":memory:")
        database.init_schema()
        return database

    def test_store_test_case(self, db):
        """Store a test case."""
        from oida.fuzz.core.database.interface import TestCase as TestCaseDTO

        tc = TestCaseDTO(
            id=0,
            name="test_1",
            timestamp=datetime.now().isoformat(),
            result="pass",
            crc32=0,
            target_ip="192.168.1.100",
            target_port=502,
            protocol="modbus",
        )
        tc_id = db.store_test_case(tc)
        assert tc_id is not None
        assert tc_id > 0

    def test_get_test_case(self, db):
        """Store and retrieve a test case."""
        from oida.fuzz.core.database.interface import TestCase as TestCaseDTO

        tc = TestCaseDTO(
            id=0,
            name="test_2",
            timestamp=datetime.now().isoformat(),
            result="fail",
            crc32=0,
            target_ip="10.0.0.1",
            target_port=2404,
            protocol="iec104",
        )
        tc_id = db.store_test_case(tc)
        retrieved = db.get_test_case(tc_id)
        assert retrieved is not None
        assert retrieved.name == "test_2"
        assert retrieved.result == "fail"

    def test_get_nonexistent_test_case(self, db):
        """Get nonexistent test case returns None."""
        retrieved = db.get_test_case(9999)
        assert retrieved is None

    def test_get_test_cases_by_result(self, db):
        """Filter test cases by result."""
        from oida.fuzz.core.database.interface import TestCase as TestCaseDTO

        for i, result in enumerate(["pass", "pass", "fail", "crash"]):
            db.store_test_case(
                TestCaseDTO(
                    id=0,
                    name=f"test_{i}",
                    timestamp=datetime.now().isoformat(),
                    result=result,
                    crc32=0,
                    target_ip="10.0.0.1",
                    target_port=502,
                    protocol="modbus",
                )
            )

        passes = db.get_test_cases(result_filter="pass")
        assert len(passes) == 2

        fails = db.get_test_cases(result_filter="fail")
        assert len(fails) == 1

        crashes = db.get_test_cases(result_filter="crash")
        assert len(crashes) == 1


class TestSQLAlchemyDatabaseCrashes:
    """Tests for crash recording."""

    @pytest.fixture
    def db(self):
        """Create initialized in-memory database."""
        _setup_logging_context()
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase

        database = SQLAlchemyDatabase(":memory:")
        database.init_schema()
        return database

    def test_store_crash(self, db):
        """Store a crash associated with a test case."""
        from oida.fuzz.core.database.interface import TestCase as TestCaseDTO, Crash as CrashDTO

        # First create a test case
        tc = TestCaseDTO(
            id=0,
            name="crash_test",
            timestamp=datetime.now().isoformat(),
            result="crash",
            crc32=0,
            target_ip="10.0.0.1",
            target_port=502,
            protocol="modbus",
        )
        tc_id = db.store_test_case(tc)

        # Now store a crash
        crash = CrashDTO(
            test_case_id=tc_id,
            payload=b"\xde\xad\xbe\xef",
            crash_info="target unresponsive",
        )
        db.store_crash(crash)

        # Retrieve the crash
        retrieved = db.get_crash(tc_id)
        assert retrieved is not None
        assert retrieved.test_case_id == tc_id

    def test_bulk_rewrite_preserves_crash(self, db):
        """Bulk-rewriting a test case id must not cascade-delete its crash row.

        Regression for the OR-REPLACE bug: SQLite REPLACE deleted the parent
        test_cases row before re-insert, which cascaded (FK ondelete=CASCADE,
        PRAGMA foreign_keys=ON) and destroyed the already-persisted crash.
        The on_conflict_do_update upsert must update the row in place instead.
        """
        from oida.fuzz.core.database.interface import TestCase as TestCaseDTO, Crash as CrashDTO

        # Persist a test case, then attach a crash to it.
        tc = TestCaseDTO(
            id=5,
            name="crash_case",
            timestamp=datetime.now().isoformat(),
            result="crash",
            crc32=0,
            target_ip="10.0.0.1",
            target_port=502,
            protocol="modbus",
        )
        db.store_test_cases_bulk([tc])
        db.store_crash(CrashDTO(test_case_id=5, payload=b"\xde\xad\xbe\xef", crash_info="boom"))
        assert db.get_crash(5) is not None

        # Bulk-rewrite the SAME id (as the session-end flush does, with result='pass').
        rewritten = TestCaseDTO(
            id=5,
            name="crash_case",
            timestamp=datetime.now().isoformat(),
            result="pass",
            crc32=0,
            target_ip="10.0.0.1",
            target_port=502,
            protocol="modbus",
        )
        db.store_test_cases_bulk([rewritten])

        # Crash row must survive the re-write.
        survived = db.get_crash(5)
        assert survived is not None
        assert survived.test_case_id == 5
        assert survived.payload == b"\xde\xad\xbe\xef"


class TestSQLAlchemyDatabaseMetadata:
    """Tests for session metadata operations."""

    @pytest.fixture
    def db(self):
        """Create initialized in-memory database."""
        _setup_logging_context()
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase

        database = SQLAlchemyDatabase(":memory:")
        database.init_schema()
        return database

    def test_set_and_get_metadata(self, db):
        """Set and retrieve session metadata."""
        db.store_metadata("protocol", "modbus")
        db.store_metadata("target", "192.168.1.100")
        assert db.get_metadata("protocol") == "modbus"
        assert db.get_metadata("target") == "192.168.1.100"

    def test_get_missing_metadata(self, db):
        """Get missing metadata returns None."""
        result = db.get_metadata("nonexistent")
        assert result is None

    def test_update_metadata(self, db):
        """Update existing metadata."""
        db.store_metadata("count", "10")
        db.store_metadata("count", "20")
        assert db.get_metadata("count") == "20"

    def test_get_all_metadata(self, db):
        """Get all metadata returns dictionary."""
        db.store_metadata("key1", "value1")
        db.store_metadata("key2", "value2")
        all_meta = db.get_all_metadata()
        assert isinstance(all_meta, dict)
        assert all_meta.get("key1") == "value1"
        assert all_meta.get("key2") == "value2"
