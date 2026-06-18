"""Database layer for fuzzing session storage.

This module provides session storage for protocol fuzzing:
- Lightweight metadata storage (default)
- Full payload storage for crashes
- SQLAlchemy ORM for advanced queries

The interface and sqlite modules use only stdlib and are imported eagerly.
The ORM and models modules require sqlalchemy and are lazy-loaded.
"""

from .interface import (
    DatabaseInterface,
    TestCase,
    Crash,
    SessionMetadata,
)
from .sqlite import (
    SQLiteDatabase,
    MockDatabase,
)


def __getattr__(name):
    """Lazy imports for sqlalchemy-dependent modules (orm, models)."""
    _orm_attrs = {"SQLAlchemyDatabase"}
    _model_attrs = {
        "Base",
        "TestCaseORM",
        "CrashORM",
        "Payload",
        "CrashEvent",
        "CrashContext",
        "SessionMetadataORM",
        "create_database_engine",
        "create_all_tables",
        "drop_all_tables",
    }
    # Remap aliased names back to their actual attribute names in the models module
    _model_remap = {
        "TestCaseORM": "TestCase",
        "CrashORM": "Crash",
        "SessionMetadataORM": "SessionMetadata",
    }

    if name in _orm_attrs:
        from .orm import SQLAlchemyDatabase

        return SQLAlchemyDatabase

    if name in _model_attrs:
        import importlib

        models = importlib.import_module(".models", __package__)
        real_name = _model_remap.get(name, name)
        return getattr(models, real_name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Interface and DTOs
    "DatabaseInterface",
    "TestCase",
    "Crash",
    "SessionMetadata",
    # SQLite implementation
    "SQLiteDatabase",
    "MockDatabase",
    # SQLAlchemy ORM implementation (lazy)
    "SQLAlchemyDatabase",
    # ORM models (lazy)
    "Base",
    "TestCaseORM",
    "CrashORM",
    "Payload",
    "CrashEvent",
    "CrashContext",
    "SessionMetadataORM",
    "create_database_engine",
    "create_all_tables",
    "drop_all_tables",
]
