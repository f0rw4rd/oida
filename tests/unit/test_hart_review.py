#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression tests for two confirmed HART bugs:

1. --command-range is parsed with an unguarded int()/split("-") at three
   sites (enumeration.py::enumerate_commands, cli_runner.py x2). A malformed
   value like "abc" or "1-2-3" raises an unhandled ValueError instead of
   surfacing a clean error.

2. fuzz_commands() computes count=iterations // len(base_payloads); with
   base_payloads of length 4, --fuzz-iterations 1/2/3 all floor-divide to 0,
   so fuzz() (real oida.utils.fuzzer.fuzz) yields zero payloads and nothing
   is ever sent to the device, yet the run "succeeds" reporting tested=0.

These tests call the real mixin methods (EnumerationMixin.enumerate_commands,
FuzzMixin.fuzz_commands) against a HARTScanner instance with a mocked
transport (`scanner.client`) -- no monkey-patching of the logic under test.
"""

from unittest.mock import MagicMock

import pytest

from oida.protocols.hart.scanner import HARTScanner


def _connected_scanner():
    scanner = HARTScanner({"rhost": "127.0.0.1", "rport": 5094})
    scanner.client = MagicMock()
    return scanner


class TestCommandRangeParsing:
    """BUG 1: malformed --command-range must not raise, per enumeration.py's
    existing {"error": [...]} convention for the not-connected case."""

    def test_non_numeric_range_returns_clean_error(self):
        scanner = _connected_scanner()
        result = scanner.enumerate_commands("abc")
        assert isinstance(result, dict)
        assert result.get("error"), f"expected an 'error' key, got: {result}"

    def test_triple_dash_range_returns_clean_error(self):
        scanner = _connected_scanner()
        result = scanner.enumerate_commands("1-2-3")
        assert isinstance(result, dict)
        assert result.get("error"), f"expected an 'error' key, got: {result}"

    def test_valid_range_still_works(self):
        """Sanity check: the fix must not break the happy path."""
        scanner = _connected_scanner()
        response = MagicMock()
        response.response_code = 0  # HARTResponseCode.SUCCESS
        scanner.client.send_command.return_value = response
        result = scanner.enumerate_commands("0-2")
        assert result["error"] == []
        assert set(result["supported"]) | set(result["unsupported"]) | set(
            result.get("skipped", [])
        ) <= {0, 1, 2}


class TestFuzzIterationsFloorDivision:
    """BUG 2: fuzz(count=iterations // len(base_payloads)) must not silently
    become count=0 for small --fuzz-iterations values."""

    def test_fuzz_iterations_one_actually_sends_payloads(self):
        scanner = _connected_scanner()

        response = MagicMock()
        response.response_code = 0
        response.device_status = 0
        scanner.client.send_command.return_value = response
        scanner.poll_address = 0

        results = scanner.fuzz_commands(iterations=1, command_list=[0])

        assert results["tested"] > 0, (
            f"fuzz_commands(iterations=1) sent no payloads; results={results}"
        )
        # send_command must have actually been called (real transport call).
        assert scanner.client.send_command.called


class TestMutatingCommandTableCompleteness:
    """BUG 3: MUTATING_UNIVERSAL_COMMANDS was missing several genuinely
    mutating HART commands (34 Write Damping Value, 36 Set Upper Range Value,
    37 Set Lower Range Value, 40 Enter/Exit Fixed Current Mode), so a plain
    ``--enumerate-commands`` run (no --confirm) sent them with an empty
    payload to a live device -- 36/37 take no write data at all and
    immediately recalibrate the device's range from the live loop reading,
    and 40 freezes the 4-20mA loop output. It also wrongly listed Command 50
    (Read Dynamic Variable Assignments), which is a read, not a write."""

    def test_dangerous_commands_are_skipped_without_confirm(self):
        scanner = _connected_scanner()
        response = MagicMock()
        response.response_code = 0
        scanner.client.send_command.return_value = response
        scanner.confirm = False

        result = scanner.enumerate_commands("0-48")

        sent_commands = {c.args[0] for c in scanner.client.send_command.call_args_list}
        for dangerous_cmd in (34, 36, 37, 40, 42):
            assert dangerous_cmd in result["skipped"], (
                f"command {dangerous_cmd} should be skipped without --confirm"
            )
            assert dangerous_cmd not in sent_commands, (
                f"command {dangerous_cmd} was sent to the device without --confirm"
            )

    def test_read_only_command_50_is_not_treated_as_mutating(self):
        scanner = _connected_scanner()
        response = MagicMock()
        response.response_code = 0
        scanner.client.send_command.return_value = response
        scanner.confirm = False

        result = scanner.enumerate_commands("50")

        assert 50 not in result["skipped"]
        assert 50 in result["supported"]


class TestSecurityAnalysisWriteCommandTable:
    """BUG 4: security_analysis()'s write_commands accessibility-probe list
    labeled command 50 as "Write Damping Value". Per the HART spec, Command
    50 is actually "Read Dynamic Variable Assignments" -- a read that nearly
    every compliant device implements and answers with response_code 0. That
    made the probe report a false-positive "Write command accessible: Write
    Damping Value" finding on virtually every device scanned (since it was
    reading response_code 0 for a benign read, not testing the real write
    command), while never actually probing the real Write Damping Value
    command, which is 34."""

    def test_command_50_is_not_probed_or_reported_as_a_write(self):
        scanner = _connected_scanner()
        scanner.confirm = True
        response = MagicMock()
        response.response_code = 0
        scanner.client.send_command.return_value = response

        findings = scanner.security_analysis(probe_categories=["write"])

        probed_commands = {c.args[0] for c in scanner.client.send_command.call_args_list}
        assert 50 not in probed_commands, "command 50 (a read) must not be probed as a write"
        assert 34 in probed_commands, "command 34 (the real Write Damping Value) must be probed"
        assert not any(f.get("command") == 50 for f in findings)
        damping_findings = [f for f in findings if "Write Damping Value" in f.get("issue", "")]
        assert damping_findings and damping_findings[0]["command"] == 34


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
