"""
SQLAlchemy ORM Models for OIDA Fuzzing Sessions

This module defines the ORM models for the fuzzing session database,
providing type-safe, object-oriented access to test cases, crashes,
and session metadata.
"""

from datetime import datetime
from typing import Dict, Optional, List
from sqlalchemy import (
    Integer,
    String,
    Float,
    ForeignKey,
    CheckConstraint,
    LargeBinary,
    Text,
    Index,
    DateTime,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    """Base class for all ORM models"""


class TestCase(Base):
    """
    ORM Model for test cases in fuzzing sessions.

    Stores metadata about each test case executed during a fuzzing session,
    including result status, timing information, target information, and monitoring results.
    """

    __tablename__ = "test_cases"
    __table_args__ = (
        CheckConstraint("result IN ('pass', 'fail', 'crash', 'error')", name="check_result_values"),
        Index("idx_test_cases_result", "result"),
        Index("idx_test_cases_timestamp", "timestamp"),
        Index("idx_test_cases_target", "target_ip", "target_port"),
        Index("idx_test_cases_protocol", "protocol"),
    )

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Core fields
    name: Mapped[str] = mapped_column(String, nullable=False)
    timestamp: Mapped[str] = mapped_column(
        String, nullable=False
    )  # ISO format string for compatibility
    result: Mapped[str] = mapped_column(String, nullable=False)
    crc32: Mapped[int] = mapped_column(Integer, nullable=False)

    # Target identification - tracks which target/protocol each test case belongs to
    target_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv4/IPv6
    target_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Optional fields
    duration_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    monitor_status: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    crash: Mapped[Optional["Crash"]] = relationship(
        "Crash", back_populates="test_case", cascade="all, delete-orphan", uselist=False
    )
    payload: Mapped[Optional["Payload"]] = relationship(
        "Payload", back_populates="test_case", cascade="all, delete-orphan", uselist=False
    )

    def __repr__(self):
        return f"<TestCase(id={self.id}, name='{self.name}', target='{self.target_ip}:{self.target_port}', protocol='{self.protocol}', result='{self.result}')>"

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "name": self.name,
            "timestamp": self.timestamp,
            "result": self.result,
            "crc32": self.crc32,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "protocol": self.protocol,
            "duration_ms": self.duration_ms,
            "monitor_status": self.monitor_status,
            "has_crash": self.crash is not None,
            "has_payload": self.payload is not None,
        }


class Crash(Base):
    """
    ORM Model for crash information.

    Stores detailed information about crashes detected during fuzzing,
    including the payload that triggered the crash and diagnostic information.
    """

    __tablename__ = "crashes"

    # Foreign key as primary key (one-to-one relationship)
    test_case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("test_cases.id", ondelete="CASCADE"), primary_key=True
    )

    # Crash data
    payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    crash_info: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stack_trace: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationship back to test case
    test_case: Mapped["TestCase"] = relationship("TestCase", back_populates="crash")

    def __repr__(self):
        return f"<Crash(test_case_id={self.test_case_id}, info='{self.crash_info[:50] if self.crash_info else 'None'}...')>"

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses"""
        return {
            "test_case_id": self.test_case_id,
            "payload_size": len(self.payload) if self.payload else 0,
            "crash_info": self.crash_info,
            "stack_trace": self.stack_trace,
        }


class Payload(Base):
    """
    ORM Model for optional payload storage.

    When --store-all-payloads is enabled, stores the complete payload
    for every test case (not just crashes).
    """

    __tablename__ = "payloads"

    # Foreign key as primary key (one-to-one relationship)
    test_case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("test_cases.id", ondelete="CASCADE"), primary_key=True
    )

    # Payload data
    payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Relationship back to test case
    test_case: Mapped["TestCase"] = relationship("TestCase", back_populates="payload")

    def __repr__(self):
        return f"<Payload(test_case_id={self.test_case_id}, size={len(self.payload)})>"

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses"""
        return {
            "test_case_id": self.test_case_id,
            "payload_size": len(self.payload) if self.payload else 0,
        }


class CrashEvent(Base):
    """
    ORM Model for crash events with context tracking.

    When a crash is detected, this stores metadata about the crash event
    and links to all the test cases in the rolling buffer at the time
    of the crash (via CrashContext).
    """

    __tablename__ = "crash_events"
    __table_args__ = (Index("idx_crash_events_timestamp", "timestamp"),)

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Test case ID where crash was detected
    detected_at_id: Mapped[int] = mapped_column(Integer, nullable=False)

    # Crash details
    crash_info: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[str] = mapped_column(String, nullable=False)

    # Target info
    target_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    target_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Context buffer size at time of crash
    context_size: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    context_entries: Mapped[List["CrashContext"]] = relationship(
        "CrashContext", back_populates="crash_event", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<CrashEvent(id={self.id}, detected_at={self.detected_at_id}, context_size={self.context_size})>"

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "detected_at_id": self.detected_at_id,
            "crash_info": self.crash_info,
            "timestamp": self.timestamp,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "protocol": self.protocol,
            "context_size": self.context_size,
        }


class CrashContext(Base):
    """
    ORM Model for crash context entries.

    Stores the contents of the rolling buffer at the time of a crash,
    providing context for crash analysis. Each entry represents a test
    case that was in the buffer when the crash occurred.
    """

    __tablename__ = "crash_context"
    __table_args__ = (
        Index("idx_crash_context_crash_id", "crash_event_id"),
        Index("idx_crash_context_test_case_id", "test_case_id"),
    )

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Link to crash event
    crash_event_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("crash_events.id", ondelete="CASCADE"), nullable=False
    )

    # Original test case ID from the fuzzer
    test_case_id: Mapped[int] = mapped_column(Integer, nullable=False)

    # Test case details
    name: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    timestamp: Mapped[str] = mapped_column(String, nullable=False)
    crc32: Mapped[int] = mapped_column(Integer, nullable=False)

    # Relationship back to crash event
    crash_event: Mapped["CrashEvent"] = relationship("CrashEvent", back_populates="context_entries")

    def __repr__(self):
        return f"<CrashContext(crash_event_id={self.crash_event_id}, test_case_id={self.test_case_id})>"

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "crash_event_id": self.crash_event_id,
            "test_case_id": self.test_case_id,
            "name": self.name,
            "payload_size": len(self.payload) if self.payload else 0,
            "timestamp": self.timestamp,
            "crc32": self.crc32,
        }


class SessionMetadata(Base):
    """
    ORM Model for session metadata.

    Stores key-value pairs of metadata about the fuzzing session,
    such as configuration parameters and replay validation settings.
    """

    __tablename__ = "session_metadata"

    # Key as primary key
    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)

    # Optional timestamp for tracking when metadata was set
    created_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, server_default=func.now(), nullable=True
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=True
    )

    def __repr__(self):
        return f"<SessionMetadata(key='{self.key}', value='{self.value[:50]}...')>"

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses"""
        return {
            "key": self.key,
            "value": self.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# Helper functions for database creation and session management


def create_database_engine(database_path: str, echo: bool = False):
    """
    Create a SQLAlchemy engine for the database.

    Args:
        database_path: Path to the SQLite database file
        echo: Whether to log all SQL statements (for debugging)

    Returns:
        SQLAlchemy Engine instance
    """
    if database_path == ":memory:":
        # In-memory database for testing
        engine = create_engine("sqlite:///:memory:", echo=echo)
    else:
        # File-based database
        engine = create_engine(f"sqlite:///{database_path}", echo=echo)

    return engine


def create_all_tables(engine):
    """
    Create all tables in the database.

    Args:
        engine: SQLAlchemy Engine instance
    """
    Base.metadata.create_all(engine)


def drop_all_tables(engine):
    """
    Drop all tables in the database.

    Args:
        engine: SQLAlchemy Engine instance
    """
    Base.metadata.drop_all(engine)


# Type aliases for better type hints
TestCaseList = List[TestCase]
CrashList = List[Crash]
MetadataDict = Dict[str, str]
