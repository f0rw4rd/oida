"""_test_commands (--test-commands) behaviour.

Regression: --test-commands used to be a wired-but-dead no-op. It now probes
control-command acceptance (C_SC/C_DC) at a target IOA and reports a finding
when the outstation activates a command. Contract:
  - confirm-gated (transmits live commands)
  - needs a target IOA (--test-command-ioa, or --write-single's IOA)
  - reports accepted vs rejected per command type
"""

import unittest
from unittest.mock import MagicMock

from oida.protocols.iec104 import IEC104Scanner


def make_scanner(**extra):
    args = {"rhost": "127.0.0.1", "rport": 2404, "timeout": 5}
    args.update(extra)
    return IEC104Scanner(args)


class TestTestCommands(unittest.TestCase):
    def _scanner(self, **extra):
        s = make_scanner(**extra)
        s.logger = MagicMock()
        return s

    def _conn_with_transmit(self, transmit_result):
        """Mock conn whose command point.transmit() returns transmit_result."""
        point = MagicMock()
        point.transmit.return_value = transmit_result
        station = MagicMock()
        station.get_point.return_value = None
        station.add_point.return_value = point
        conn = MagicMock()
        conn.get_station.return_value = station
        return conn, point

    def test_gated_without_confirm(self):
        s = self._scanner()
        s.confirm_dangerous = False
        s.test_command_ioa = 100
        conn, point = self._conn_with_transmit(True)
        result = s._test_commands(MagicMock(), conn)
        self.assertEqual(result["error"], "Missing --confirm")
        point.transmit.assert_not_called()

    def test_requires_target_ioa(self):
        s = self._scanner()
        s.confirm_dangerous = True
        s.test_command_ioa = None
        conn, point = self._conn_with_transmit(True)
        result = s._test_commands(MagicMock(), conn)
        self.assertEqual(result["error"], "No target IOA")
        point.transmit.assert_not_called()

    def test_accepted_command_reports_finding(self):
        s = self._scanner()
        s.confirm_dangerous = True
        s.test_command_ioa = 100
        conn, point = self._conn_with_transmit(True)
        result = s._test_commands(MagicMock(), conn)
        # Two probes (C_SC, C_DC), both accepted in this mock
        self.assertEqual(result["tested"], 2)
        self.assertIn("C_SC_NA_1 (Single command)", result["accepted"])
        self.assertEqual(result["rejected"], [])
        s.logger.security_finding.assert_called()

    def test_rejected_command_no_finding(self):
        s = self._scanner()
        s.confirm_dangerous = True
        s.test_command_ioa = 100
        conn, point = self._conn_with_transmit(False)
        result = s._test_commands(MagicMock(), conn)
        self.assertEqual(result["accepted"], [])
        self.assertEqual(len(result["rejected"]), 2)
        s.logger.security_finding.assert_not_called()

    def test_ioa_defaults_to_write_single(self):
        # --test-command-ioa unset falls back to --write-single's IOA.
        s = self._scanner(**{"write-single": "55"})
        self.assertEqual(s.test_command_ioa, 55)


if __name__ == "__main__":
    unittest.main()
