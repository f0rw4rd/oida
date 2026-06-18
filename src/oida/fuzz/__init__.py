"""
OIDA Fuzzing Framework

Protocol fuzzing based on boofuzz with session management and replay.

Usage:
    oida fuzz <protocol> <target> [options]
    oida fuzz list [--category <cat>]
    oida fuzz replay <session> [--range N-M]

All imports are lazy to avoid pulling in optional dependencies (sqlalchemy,
boofuzz) at CLI startup time.
"""


def __getattr__(name):
    """Lazy module-level attribute access for all exported symbols."""
    _lazy_map = {
        "FuzzerConfig": (".core.config", "FuzzerConfig"),
        "ProtocolType": (".core.config", "ProtocolType"),
        "BaseFuzzer": (".core.base_fuzzer", "BaseFuzzer"),
        "RequestInfo": (".core.base_fuzzer", "RequestInfo"),
        "SQLiteDatabase": (".core.database", "SQLiteDatabase"),
        "TestCase": (".core.database", "TestCase"),
        "Crash": (".core.database", "Crash"),
        "TestCaseManager": (".core.session.manager", "TestCaseManager"),
        "FuzzerApplication": (".core.application", "FuzzerApplication"),
    }

    if name in _lazy_map:
        import importlib

        module_path, attr_name = _lazy_map[name]
        module = importlib.import_module(module_path, __package__)
        return getattr(module, attr_name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "FuzzerConfig",
    "ProtocolType",
    "BaseFuzzer",
    "RequestInfo",
    "SQLiteDatabase",
    "TestCase",
    "Crash",
    "TestCaseManager",
    "FuzzerApplication",
]
