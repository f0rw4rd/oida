#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression tests for a code-review finding in
``oida.protocols.dnp3.mixins.control.ControlMixin._assign_class``.

Bug: when every requested ``--assign-class`` entry is rejected by a
``continue`` branch (bad ``GROUP:START-END:CLASS`` shape, or an out-of-range
class number), ``operations_performed`` stays empty and
``all(op.get("success", False) for op in operations_performed)`` is
vacuously ``True`` for an empty list -- so the aggregate result reports
``success: True`` even though nothing was sent to the outstation.

``proto_args.validate_args`` already rejects both malformed shapes before
this code runs, so this is not reachable from the CLI today; this is a
defense-in-depth regression test for the aggregate itself.

Fixture/mocking style follows tests/unit/dnp3/test_control_mixin.py.
"""

from typing import Any, Dict

import pytest

opendnp3 = pytest.importorskip("opendnp3", reason="yadnp3 (opendnp3) not installed")

from oida.protocols.dnp3.scanner import DNP3Scanner


def _make_scanner(**overrides) -> DNP3Scanner:
    args = {"rhost": "127.0.0.1", "rport": 20000}
    args.update(overrides)
    scanner = DNP3Scanner(args)
    scanner._connected = True
    scanner._master = object()
    return scanner


def _arm_task(scanner, *, success=True):
    """Replace _sync_task so PerformFunction 'completes' with a bool."""

    class _FakeMaster:
        def PerformFunction(self, name, func_code, headers, config):
            pass

    def fake(task_fn, timeout=None):
        task_fn(_FakeMaster(), object())
        return success

    scanner._sync_task = fake


class TestAssignClassVacuousTruth:
    def test_all_entries_malformed_shape_reports_failure(self):
        """Every entry has the wrong colon-count -> all `continue`d.

        Before the fix: operations_performed == [] and all([]) == True,
        so the aggregate incorrectly reported success.
        """
        scanner = _make_scanner(**{"assign-class": ["garbage"]})
        _arm_task(scanner, success=True)
        results: Dict[str, Any] = {"operations": {}}
        scanner._assign_class(results)

        agg = results["operations"]["assign_class"]
        # The rejection is recorded (mirrors the except-handler shape), and the
        # aggregate must NOT be the vacuous all([]) == True.
        assert len(agg["operations"]) == 1
        assert agg["operations"][0]["success"] is False
        assert agg["success"] is False

    def test_all_entries_bad_class_number_reports_failure(self):
        """Well-shaped entry but class number outside 0-3 -> `continue`d."""
        scanner = _make_scanner(**{"assign-class": ["1:0-9:9"]})
        _arm_task(scanner, success=True)
        results: Dict[str, Any] = {"operations": {}}
        scanner._assign_class(results)

        agg = results["operations"]["assign_class"]
        assert len(agg["operations"]) == 1
        assert agg["operations"][0]["success"] is False
        assert agg["success"] is False

    def test_valid_entry_still_aggregates_success(self):
        """A genuinely valid entry that succeeds still reports success True."""
        scanner = _make_scanner(**{"assign-class": ["1:0-9:1"]})
        _arm_task(scanner, success=True)
        results: Dict[str, Any] = {"operations": {}}
        scanner._assign_class(results)

        agg = results["operations"]["assign_class"]
        assert len(agg["operations"]) == 1
        assert agg["operations"][0]["success"] is True
        assert agg["success"] is True

    def test_valid_entry_that_fails_aggregates_failure(self):
        """A well-formed entry whose PerformFunction fails still reports False."""
        scanner = _make_scanner(**{"assign-class": ["1:0-9:1"]})
        _arm_task(scanner, success=False)
        results: Dict[str, Any] = {"operations": {}}
        scanner._assign_class(results)

        agg = results["operations"]["assign_class"]
        assert len(agg["operations"]) == 1
        assert agg["operations"][0]["success"] is False
        assert agg["success"] is False


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
