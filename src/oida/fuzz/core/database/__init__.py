"""Database layer for fuzzing session storage.

Single canonical backend:

- ``SQLAlchemyDatabase`` (orm.py) — production read/write path. All fuzzer
  components write through it. Defined as an :class:`DatabaseInterface`
  implementation backed by SQLAlchemy 2.x.

- ``MockDatabase`` (mock.py) — in-memory stub for unit tests.

The previous raw-SQL ``SQLiteDatabase`` was removed in 1.0 (it diverged in
schema from the ORM and was no longer used by the runtime). For replay of
legacy ``.db`` files from older OIDA versions, ``SQLAlchemyDatabase`` can
read the same on-disk schema — call ``init_schema()`` once on open.
"""

from .interface import (
    DatabaseInterface,
    TestCase,
    Crash,
    SessionMetadata,
)
from .mock import MockDatabase


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
    # In-memory test stub
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
