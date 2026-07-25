#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression test for CODE_REVIEW.md finding #15 [HIGH]:
"Password-file brute-force in create_conn_obj bypasses the --confirm safety gate"

Source: src/oida/protocols/snap7/cli_runner.py (create_conn_obj)

A user who passes -P <wordlist-file> triggers the "smart -P" brute-force path.
Brute-forcing a live PLC is an active, lockout-inducing operation and must be
gated behind --confirm, exactly like --brute / --default-creds. Without
--confirm the brute-force must NOT run; with --confirm it must proceed.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from oida.protocols.snap7.cli_runner import s7


class _NoConfirmArgs(SimpleNamespace):
    """Args namespace with a real file path as password but no --confirm."""


def _make_s7(args, password_file):
    """Build an s7 instance without running NetworkConnection.__init__.

    create_conn_obj() only touches: self.args, self.logger, self.scanner,
    self.conn, self.ip, self.results. We wire those up directly so the test
    exercises create_conn_obj() in isolation.
    """
    obj = s7.__new__(s7)
    obj.args = args
    obj.logger = Mock()
    obj.ip = "192.168.1.100"
    obj.results = {"success": True, "data": {}}
    obj.scanner = Mock()
    # scanner.connect() returns a truthy connection object so the brute-force
    # branch is reachable.
    obj.scanner.connect.return_value = Mock(name="conn")
    obj.scanner.bruteforce_password.return_value = {"success": False}
    return obj


class TestPasswordFileConfirmGate(unittest.TestCase):
    def setUp(self):
        # A real existing file so os.path.isfile(password) is True.
        self._tmp = _TempFile("admin\n123456\n")
        self._tmp.__enter__()
        self.addCleanup(self._tmp.__exit__, None, None, None)
        self.password_file = self._tmp.path

    def test_no_confirm_refuses_bruteforce(self):
        """Without --confirm, the file-path brute-force must NOT run."""
        args = _NoConfirmArgs(
            port=102,
            password=self.password_file,
            confirm=False,
        )
        obj = _make_s7(args, self.password_file)

        obj.create_conn_obj()

        obj.scanner.bruteforce_password.assert_not_called()
        # A clear refusal was emitted.
        self.assertTrue(
            obj.logger.fail.called,
            "Expected a clear refusal via logger.fail when --confirm is absent",
        )
        self.assertNotIn("password_found", obj.results["data"])

    def test_confirm_proceeds_with_bruteforce(self):
        """With --confirm, the file-path brute-force proceeds."""
        args = _NoConfirmArgs(
            port=102,
            password=self.password_file,
            confirm=True,
            brute_rate=0.5,
            continue_on_success=False,
        )
        obj = _make_s7(args, self.password_file)
        obj.scanner.bruteforce_password.return_value = {
            "success": True,
            "password": "admin",
        }

        obj.create_conn_obj()

        obj.scanner.bruteforce_password.assert_called_once()
        _, kwargs = obj.scanner.bruteforce_password.call_args
        self.assertEqual(kwargs.get("wordlist_path"), self.password_file)
        self.assertEqual(obj.results["data"].get("password_found"), "admin")


class _TempFile:
    """Tiny context-manager temp file (avoids importing tempfile fixtures)."""

    def __init__(self, content: str):
        self._content = content
        self.path = ""

    def __enter__(self):
        import tempfile

        fd, self.path = tempfile.mkstemp(prefix="oida_s7_wl_", suffix=".txt")
        import os

        with os.fdopen(fd, "w") as f:
            f.write(self._content)
        return self

    def __exit__(self, *exc):
        import os

        try:
            os.unlink(self.path)
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
