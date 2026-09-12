#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for MockCLI boolean flags with a True default.

Bug (core bug hunt): ``MockCLI._add_options_to_parser`` builds its
``BooleanOptionalAction`` with ``const = not default``. For a boolean whose
default is True — exactly the shape of the safety option ``read-only`` — the
bare flag's "no explicit value" constant is ``False``:

    python -m oida.protocols.modbus.scanner -r 10.0.0.1 --read-only
        -> read-only = False

So a user who types ``--read-only`` to be explicit about safety silently turns
the protection OFF. ``const`` should be ``True`` for a positively-worded flag
(the flag's presence affirms the option), regardless of the default.

Reproduced before the fix against the REAL modbus metadata:
    standalone `--read-only` -> False (INVERTED a True default)
"""

import sys
import unittest

from oida.utils.cli import MockCLI

META = {
    "name": "t",
    "description": "t",
    "options": {
        "read-only": {"type": "bool", "default": True, "description": "safety"},
    },
}


class TestMockCliBoolDefaults(unittest.TestCase):
    def setUp(self):
        self._argv = sys.argv
        self.cli = MockCLI()

    def tearDown(self):
        sys.argv = self._argv

    def test_bare_flag_on_true_default_must_not_invert(self):
        """`--read-only` on a True default must keep it True (safety stays on)."""
        sys.argv = ["prog", "--read-only"]
        params = self.cli.parse(META)["params"]
        self.assertIs(params["read-only"], True)

    def test_explicit_false_still_disables(self):
        """Explicit opt-out must keep working."""
        sys.argv = ["prog", "--read-only", "false"]
        params = self.cli.parse(META)["params"]
        self.assertIs(params["read-only"], False)

    def test_absent_keeps_default(self):
        sys.argv = ["prog"]
        params = self.cli.parse(META)["params"]
        self.assertIs(params["read-only"], True)

    def test_bare_flag_on_false_default_enables(self):
        meta = {
            "name": "t",
            "options": {"verbose": {"type": "bool", "default": False,
                                    "description": "verbosity"}},
        }
        sys.argv = ["prog", "--verbose"]
        params = self.cli.parse(meta)["params"]
        self.assertIs(params["verbose"], True)

    def test_real_modbus_metadata_bare_read_only_is_true(self):
        """End-to-end against real scanner metadata (the documented standalone path)."""
        from oida.protocols.modbus import scanner as modbus_scanner

        sys.argv = ["prog", "-r", "10.0.0.1", "--read-only"]
        params = self.cli.parse(modbus_scanner.metadata)["params"]
        self.assertIs(params["read-only"], True)


if __name__ == "__main__":
    unittest.main()
