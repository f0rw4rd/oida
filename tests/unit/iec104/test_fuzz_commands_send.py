"""_fuzz_commands confirm-gate behaviour.

The c104 library exposes no raw-send interface, so _fuzz_commands bails loudly
and transmits nothing. The only contract left to assert is the --confirm gate:
without confirmation no work is done and nothing is sent.
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
