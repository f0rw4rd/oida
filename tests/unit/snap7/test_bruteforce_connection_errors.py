"""Brute-force must not report untested passwords when the PLC is unreachable.

A dropped/refused S7 connection means the password was never actually tried,
so it must be counted as a connection error -- not as a tested attempt -- and
the run should abort once the device is clearly gone.
"""

import unittest
from unittest.mock import Mock, patch

from oida.protocols.snap7.mixins.security import SecurityMixin
from oida.utils.protocol_helpers import MAX_CONSECUTIVE_CONNECTION_ERRORS


def _make_instance():
    obj = SecurityMixin.__new__(SecurityMixin)
    obj.logger = Mock()
    obj.get_target_info = Mock(return_value=("192.0.2.1", 102))
    obj.clear_session = Mock()
    obj.report_credential = Mock()
    return obj


class TestBruteforceConnectionErrors(unittest.TestCase):
    def test_connection_errors_not_counted_and_aborts(self):
        obj = _make_instance()
        conn = Mock()
        # Every attempt loses the connection: never a real test.
        conn.get_cpu_state.side_effect = OSError("TCP : Connection reset by peer")

        with patch(
            "oida.utils.login_scanner.load_passwords",
            return_value=[f"p{i}" for i in range(50)],
        ):
            results = obj.bruteforce_password(conn, rate_limit=0)

        self.assertTrue(results["aborted"])
        self.assertEqual(results["attempts"], 0)
        self.assertEqual(results["connection_errors"], MAX_CONSECUTIVE_CONNECTION_ERRORS)
        self.assertFalse(results["success"])

    def test_wrong_passwords_counted_as_tested(self):
        obj = _make_instance()
        conn = Mock()
        # A refused CPU read (wrong password) is a genuine, evaluated attempt.
        conn.get_cpu_state.side_effect = Exception("CPU : Function refused")

        with patch(
            "oida.utils.login_scanner.load_passwords",
            return_value=["a", "b", "c"],
        ):
            results = obj.bruteforce_password(conn, rate_limit=0)

        self.assertFalse(results["aborted"])
        self.assertEqual(results["attempts"], 3)
        self.assertEqual(results["connection_errors"], 0)
        self.assertFalse(results["success"])


if __name__ == "__main__":
    unittest.main()
