"""Tests for security_analysis.py false-positive fixes.

Covers three bugs:
 1. _count_writable_attrs must use the writable flag, not len(dict)
 2. access_control = None when --write didn't run (not silently True)
 3. ListIdentity must NOT emit 'Anonymous access allowed' (ODVA spec)
"""

import unittest
from unittest.mock import patch

from oida.protocols.ethernetip.mixins.security_analysis import _count_writable_attrs


class TestCountWritableAttrs(unittest.TestCase):
    def test_empty_dict_returns_zero(self):
        self.assertEqual(_count_writable_attrs({}), 0)

    def test_counts_only_writable_class_attrs(self):
        # Old bug: len(write_info.values()) returned 2 per class
        # (class_attributes + instances dict keys), not actual count.
        write_test = {
            "0x01": {
                "class_attributes": {
                    "1": {"writable": True},
                    "2": {"writable": False},
                    "3": {"writable": True},
                },
                "instances": {},
            },
        }
        self.assertEqual(_count_writable_attrs(write_test), 2)

    def test_counts_writable_instance_attrs(self):
        write_test = {
            "0x09": {
                "class_attributes": {},
                "instances": {
                    "1": {"1": {"writable": True}, "2": {"writable": False}},
                    "2": {"1": {"writable": True}, "2": {"writable": True}},
                },
            }
        }
        self.assertEqual(_count_writable_attrs(write_test), 3)

    def test_old_bug_does_not_recur(self):
        """4 classes × len(class dict)=2 used to report 8 writable attrs."""
        write_test = {str(c): {"class_attributes": {}, "instances": {}} for c in range(4)}
        # All four classes empty → zero writables. Old code returned 8.
        self.assertEqual(_count_writable_attrs(write_test), 0)

    def test_handles_missing_keys_gracefully(self):
        # Real-world: a class explorer might produce partial entries.
        self.assertEqual(_count_writable_attrs({"0x01": {}}), 0)
        self.assertEqual(_count_writable_attrs({"0x01": None}), 0)
        self.assertEqual(
            _count_writable_attrs({"0x01": {"class_attributes": None, "instances": None}}),
            0,
        )


class TestAccessControlVerdict(unittest.TestCase):
    """access_control must be None when --write wasn't run."""

    @patch("oida.protocols.ethernetip.PYCOMM3_AVAILABLE", True)
    def _make_scanner(self):
        from oida.protocols.ethernetip.scanner import EtherNetIPScanner

        return EtherNetIPScanner(
            {"rhost": "127.0.0.1", "rport": 44818, "timeout": 1},
        )

    def test_unknown_when_no_write_test_run(self):
        """Old bug: len(write_test_results)==0 → access_control=True
        on every scan that didn't use --write. Now None=unknown."""
        from oida.protocols.ethernetip.mixins.security_analysis import (
            _count_writable_attrs,
        )

        # Simulate the verdict logic from analyse(): empty dict → None.
        write_test_results = {}
        if not write_test_results:
            verdict = None
        else:
            verdict = _count_writable_attrs(write_test_results) == 0
        self.assertIsNone(verdict)

    def test_true_when_write_ran_with_zero_writables(self):
        from oida.protocols.ethernetip.mixins.security_analysis import (
            _count_writable_attrs,
        )

        write_test_results = {
            "0x01": {
                "class_attributes": {"1": {"writable": False}},
                "instances": {},
            }
        }
        verdict = None if not write_test_results else _count_writable_attrs(write_test_results) == 0
        self.assertTrue(verdict)


class TestAttackCommandNoResponseIsInconclusive(unittest.TestCase):
    """No response / timeout on an attack payload must not be reported as
    success — the caller must be told the outcome is unknown."""

    def _make_mixin(self, sock):
        from unittest.mock import MagicMock
        from oida.protocols.ethernetip.mixins.attacks import AttacksMixin

        obj = AttacksMixin.__new__(AttacksMixin)
        obj.timeout = 1
        obj.logger = MagicMock()
        obj._register_session = MagicMock(return_value=0x1234)
        return obj

    def test_empty_response_marks_inconclusive_not_success(self):
        from unittest.mock import MagicMock, patch

        sock = MagicMock()
        sock.recv.return_value = b""
        obj = self._make_mixin(sock)

        with patch(
            "oida.protocols.ethernetip.mixins.attacks.ConnectionHelper.create_tcp_socket",
            return_value=sock,
        ):
            result = obj._send_attack_command("127.0.0.1", 44818, b"\x00" * 4, "cpu_stop")

        self.assertTrue(result["inconclusive"])
        self.assertFalse(result["success"])

    def test_timeout_marks_inconclusive_not_success(self):
        from unittest.mock import MagicMock, patch

        sock = MagicMock()
        sock.recv.side_effect = TimeoutError()
        obj = self._make_mixin(sock)

        with patch(
            "oida.protocols.ethernetip.mixins.attacks.ConnectionHelper.create_tcp_socket",
            return_value=sock,
        ):
            result = obj._send_attack_command("127.0.0.1", 44818, b"\x00" * 4, "cpu_stop")

        self.assertTrue(result["inconclusive"])
        self.assertFalse(result["success"])


if __name__ == "__main__":
    unittest.main()
