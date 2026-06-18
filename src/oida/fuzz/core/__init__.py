"""
OIDA Fuzzer Core Components

This module contains the core functionality of the OIDA fuzzing framework.
"""

# Lazy imports to avoid circular dependencies and speed up CLI startup


def __getattr__(name):
    """Lazy load core modules on first access."""
    if name in ("FuzzerConfig", "ProtocolType"):
        from .config import FuzzerConfig, ProtocolType

        return FuzzerConfig if name == "FuzzerConfig" else ProtocolType
    elif name == "FuzzerApplication":
        from .application import FuzzerApplication

        return FuzzerApplication
    elif name == "TestCaseManager":
        from .session.manager import TestCaseManager

        return TestCaseManager
    elif name in ("BaseFuzzer", "CommonState", "RequestInfo"):
        from .base_fuzzer import BaseFuzzer, CommonState, RequestInfo

        if name == "BaseFuzzer":
            return BaseFuzzer
        elif name == "CommonState":
            return CommonState
        return RequestInfo
    elif name == "StatefulFuzzer":
        from .stateful_fuzzer import StatefulFuzzer

        return StatefulFuzzer
    elif name in ("DatabaseInterface", "SQLiteDatabase", "MockDatabase"):
        from .database import DatabaseInterface, SQLiteDatabase, MockDatabase

        if name == "DatabaseInterface":
            return DatabaseInterface
        elif name == "SQLiteDatabase":
            return SQLiteDatabase
        return MockDatabase
    elif name == "SQLAlchemyDatabase":
        from .database.orm import SQLAlchemyDatabase

        return SQLAlchemyDatabase
    elif name in ("ConnectionFactory", "MockConnectionFactory"):
        from .connections import ConnectionFactory, MockConnectionFactory

        return ConnectionFactory if name == "ConnectionFactory" else MockConnectionFactory
    elif name in ("CommandRunner", "MockCommandRunner"):
        from .session.commands import CommandRunner, MockCommandRunner

        return CommandRunner if name == "CommandRunner" else MockCommandRunner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "FuzzerConfig",
    "ProtocolType",
    "FuzzerApplication",
    "TestCaseManager",
    "BaseFuzzer",
    "CommonState",
    "RequestInfo",
    "StatefulFuzzer",
    "DatabaseInterface",
    "SQLiteDatabase",
    "SQLAlchemyDatabase",
    "MockDatabase",
    "ConnectionFactory",
    "MockConnectionFactory",
    "CommandRunner",
    "MockCommandRunner",
]
