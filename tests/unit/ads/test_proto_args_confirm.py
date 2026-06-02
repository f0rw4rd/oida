"""Regression: every flag whose help text says 'Requires --confirm' must
actually be rejected by ``validate_args`` when ``--confirm`` is absent.

The audit found that the help text was advisory only: a user could drive a
state change on a live PLC without acknowledging the risk.  This file pins
the enforcement so we can't regress.
"""

import argparse

import pytest

from oida.protocols.ads.proto_args import (
    _CONFIRM_REQUIRED_FLAGS,
    proto_args,
    validate_args,
)
from oida.utils.exceptions import ConfigurationError


def _parse(*extra):
    parent = argparse.ArgumentParser(add_help=False)
    main = argparse.ArgumentParser()
    subparsers = main.add_subparsers()
    proto_args(subparsers, [parent])
    return main.parse_args(["ads", "127.0.0.1", *extra])


@pytest.mark.parametrize("dest,cli_flag", sorted(_CONFIRM_REQUIRED_FLAGS.items()))
class TestADSConfirmEnforcement:
    """One test per dangerous flag, both directions."""

    # Each dangerous flag's payload — argparse rejects bare flags without
    # required values.  Map each to a sensible placeholder.
    _PAYLOADS = {
        "--scan-coe": None,
        "--write-coe": "1003:0xFB00:1:01020304",
        "--add-route": "192.168.1.50.1.1:192.168.1.50",
        "--foe-write": "1001:/tmp/x:fw.bin",
        "--foe-delete": "1001:systrace",
        "--write-symbol": "MAIN.counter:42",
        "--memory-write": "0x4020:0:01",
        "--set-state": "RUN",
        "--fuzz": None,
        "--fuzz-coe": None,
    }

    def _build(self, cli_flag, *, with_confirm: bool):
        payload = self._PAYLOADS.get(cli_flag)
        extra = [cli_flag] if payload is None else [cli_flag, payload]
        if with_confirm:
            extra.append("--confirm")
        return _parse(*extra)

    def test_without_confirm_raises(self, dest, cli_flag):
        """{cli_flag} alone must raise ConfigurationError."""
        args = self._build(cli_flag, with_confirm=False)
        with pytest.raises(ConfigurationError, match="--confirm is required"):
            validate_args(args)

    def test_with_confirm_passes(self, dest, cli_flag):
        """{cli_flag} + --confirm must NOT raise."""
        args = self._build(cli_flag, with_confirm=True)
        validate_args(args)  # no raise


class TestADSConfirmBenignFlagsUnaffected:
    """Read-only flags must not trip the confirm gate."""

    def test_no_dangerous_flags_passes_without_confirm(self):
        args = _parse()
        validate_args(args)  # no raise

    def test_read_symbol_does_not_require_confirm(self):
        args = _parse("--read-symbol", "MAIN.counter")
        validate_args(args)  # no raise

    def test_state_query_does_not_require_confirm(self):
        # --state queries, --set-state changes.
        args = _parse("--state")
        validate_args(args)  # no raise

    def test_memory_read_does_not_require_confirm(self):
        args = _parse("--memory-read", "0x4020:0:4")
        validate_args(args)  # no raise


class TestADSConfirmErrorMessage:
    """Error message must list every triggered flag so the user knows what to drop."""

    def test_error_mentions_triggered_flag(self):
        args = _parse("--set-state", "RUN")
        with pytest.raises(ConfigurationError) as ei:
            validate_args(args)
        assert "--set-state" in str(ei.value)

    def test_error_lists_multiple_when_multiple_dangerous(self):
        args = _parse("--set-state", "RUN", "--write-symbol", "MAIN.counter:42")
        with pytest.raises(ConfigurationError) as ei:
            validate_args(args)
        msg = str(ei.value)
        assert "--set-state" in msg
        assert "--write-symbol" in msg
