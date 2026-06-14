"""Regression: _fuzz_commands must unpack fuzz()'s (bytes, desc) tuples.

Previously `for i, payload in enumerate(fuzz(...))` bound `payload` to the whole
(bytes, str) tuple, so `payload.hex()` raised AttributeError on the very first
iteration whenever the c104 connection actually exposed a raw-send interface.
The send path was therefore dead. These tests drive a fake conn with send_raw
and assert real bytes are transmitted without error.
"""

import unittest
from unittest.mock import MagicMock

from oida.protocols.iec104 import IEC104Scanner


def make_scanner(**extra):
    args = {"rhost": "127.0.0.1", "rport": 2404, "timeout": 5}
    args.update(extra)
    return IEC104Scanner(args)


class TestFuzzCommandsSend(unittest.TestCase):
    def _scanner(self):
        s = make_scanner()
        s.confirm_dangerous = True
        s.fuzz_ioa = 100
        s.fuzz_iterations = 3
        s.logger = MagicMock()
        return s

    def test_send_raw_path_transmits_bytes_without_error(self):
        """With a send_raw interface, fuzzed payloads are sent as bytes."""
        scanner = self._scanner()
        sent = []
        conn = MagicMock()
        conn.send_raw.side_effect = lambda data: sent.append(data)

        results = scanner._fuzz_commands(MagicMock(), conn)

        # No AttributeError; the loop ran and counted real tests.
        self.assertGreater(results["tested"], 0)
        self.assertTrue(sent, "send_raw was never called")
        # Every transmitted APDU must be bytes (the bug passed a tuple).
        for apdu in sent:
            self.assertIsInstance(apdu, (bytes, bytearray))
        # No errors recorded from a tuple.hex() AttributeError.
        self.assertFalse(
            [e for e in results["errors"] if "tuple" in str(e.get("error", "")).lower()]
        )

    def test_confirm_gate_blocks_without_confirm(self):
        """Sanity: still gated on --confirm (no transmit when unconfirmed)."""
        scanner = self._scanner()
        scanner.confirm_dangerous = False
        conn = MagicMock()
        results = scanner._fuzz_commands(MagicMock(), conn)
        self.assertEqual(results["tested"], 0)
        conn.send_raw.assert_not_called()


if __name__ == "__main__":
    unittest.main()
