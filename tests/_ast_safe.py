"""Shared helper: ``ast.parse`` that survives a transient CPython 3.11 bug.

On CPython 3.11.5, ``ast.parse`` intermittently raises
``SystemError: AST constructor recursion depth mismatch`` when another
(daemon) thread left running by an earlier test mutates the interpreter's C
recursion counter mid-parse. The parse is deterministic, so retrying clears
it. Static-analysis tests that parse many source files in a worker process
(after threaded scanner/fuzzer tests have run) are the ones that trip it.
"""

from __future__ import annotations

import ast


def safe_parse(source: str, _retries: int = 10) -> ast.AST:
    """``ast.parse(source)`` retried past the transient 3.11 ``SystemError``."""
    for attempt in range(_retries):
        try:
            return ast.parse(source)
        except SystemError:
            if attempt == _retries - 1:
                raise
    raise AssertionError("unreachable")  # pragma: no cover
