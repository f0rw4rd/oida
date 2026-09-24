"""
OIDA Fuzzer Core Components

This module contains the core functionality of the OIDA fuzzing framework.
"""

# Lazy imports to avoid circular dependencies and speed up CLI startup


def __getattr__(name):
    """Lazy load core modules on first access."""
    if name in ("FuzzerConfig", "ProtocolType"):
        from oida.fuzz.core.config import FuzzerConfig, ProtocolType

        return FuzzerConfig if name == "FuzzerConfig" else ProtocolType
    elif name == "FuzzerApplication":
        from oida.fuzz.core.application import FuzzerApplication

        return FuzzerApplication
    elif name == "TestCaseManager":
        from oida.fuzz.core.session.manager import TestCaseManager

        return TestCaseManager
    elif name in ("BaseFuzzer", "CommonState", "RequestInfo"):
        from oida.fuzz.core.base_fuzzer import BaseFuzzer, CommonState, RequestInfo

        if name == "BaseFuzzer":
            return BaseFuzzer
        elif name == "CommonState":
            return CommonState
        return RequestInfo
    elif name == "StatefulFuzzer":
        from oida.fuzz.core.stateful_fuzzer import StatefulFuzzer

        return StatefulFuzzer
    elif name in ("DatabaseInterface", "MockDatabase"):
        from oida.fuzz.core.database import DatabaseInterface, MockDatabase

        if name == "DatabaseInterface":
            return DatabaseInterface
        return MockDatabase
    elif name == "SQLAlchemyDatabase":
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase

        return SQLAlchemyDatabase
    elif name in ("ConnectionFactory", "MockConnectionFactory"):
        from oida.fuzz.core.connections import ConnectionFactory, MockConnectionFactory

        return ConnectionFactory if name == "ConnectionFactory" else MockConnectionFactory
    elif name in ("CommandRunner", "MockCommandRunner"):
        from oida.fuzz.core.session.commands import CommandRunner, MockCommandRunner

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
    "SQLAlchemyDatabase",
    "MockDatabase",
    "ConnectionFactory",
    "MockConnectionFactory",
    "CommandRunner",
    "MockCommandRunner",
]
