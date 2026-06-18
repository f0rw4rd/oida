#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NXC-Style CLI Integration Tests

Tests the new NXC-style CLI to ensure basic functionality works.
"""

import unittest
import sys
import os
import subprocess

# Add the package directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestNXCStyleCLI(unittest.TestCase):
    """Test NXC-style CLI integration"""

    def test_cli_help_works(self):
        """Test that the main CLI help command works"""
        result = subprocess.run(
            [sys.executable, "-m", "oida.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should not have AttributeError
        self.assertNotIn("AttributeError", result.stderr)

        # Should show usage
        output = result.stdout + result.stderr
        self.assertIn("usage:", output.lower())
        self.assertIn("protocol", output.lower())

    def test_protocol_help_works(self):
        """Test that protocol-specific help works"""
        # Test modbus as representative protocol
        result = subprocess.run(
            [sys.executable, "-m", "oida.cli", "modbus", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should not have AttributeError
        self.assertNotIn("AttributeError", result.stderr)

        # Should show modbus-specific help
        output = result.stdout + result.stderr
        self.assertIn("modbus", output.lower())
        self.assertIn("target", output.lower())

    def test_version_flag(self):
        """Test that --version flag works"""
        result = subprocess.run(
            [sys.executable, "-m", "oida.cli", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should show version
        output = result.stdout + result.stderr
        self.assertIn("oida", output.lower())
        # Optional dependencies warnings are OK
        self.assertNotIn("AttributeError", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
