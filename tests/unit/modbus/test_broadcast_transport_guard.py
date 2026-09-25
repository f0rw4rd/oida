"""--broadcast (Unit ID 0) is Modbus-RTU only; reject on TCP/TLS/UDP.

modbus._execute_features() (src/oida/protocols/modbus/cli_runner.py:205-241)
checks self.broadcast_mode and, unless one of the serial-flavor flags
(serial_port, rtu_over_tcp, ascii_over_tcp) is set, logs a failure and
returns without overriding unit_id to 0. On a serial-flavor transport it
proceeds and forces unit_id to 0 for the broadcast write.

The scanner requires a live connection to construct normally, so these
tests build the object via __new__ (bypassing __init__) and populate only
the attributes _execute_features() actually reads: args, logger, conn.
"""

import argparse
import unittest
from unittest.mock import MagicMock

from oida.protocols.modbus.cli_runner import modbus


def _make_scanner(**arg_overrides):
    scanner = modbus.__new__(modbus)
    args = argparse.Namespace(
        broadcast=True,
        full=False,
        discover=False,
        identify=False,
        serial_port=None,
        rtu_over_tcp=False,
        ascii_over_tcp=False,
        unit_id=1,
    )
    for k, v in arg_overrides.items():
        setattr(args, k, v)
    scanner.args = args
    scanner.logger = MagicMock()
    scanner.conn = object()  # truthy, so _execute_features doesn't bail early
    return scanner


class TestBroadcastTransportRejection(unittest.TestCase):
    def test_broadcast_on_tcp_is_refused_and_unit_id_untouched(self):
        scanner = _make_scanner()  # no serial-flavor flags set -> TCP-like
        scanner._execute_features()

        fail_messages = [call.args[0] for call in scanner.logger.fail.call_args_list]
        self.assertTrue(
            any("--broadcast is Modbus-RTU only" in m for m in fail_messages),
            f"expected a broadcast-rejection failure, got: {fail_messages}",
        )
        self.assertEqual(scanner.args.unit_id, 1, "unit_id must not be forced to 0 on TCP")

    def test_broadcast_on_rtu_over_tcp_is_allowed(self):
        scanner = _make_scanner(rtu_over_tcp=True, discover=True)
        scanner._execute_features()

        fail_messages = [call.args[0] for call in scanner.logger.fail.call_args_list]
        self.assertFalse(
            any("--broadcast is Modbus-RTU only" in m for m in fail_messages),
            f"broadcast should be allowed over rtu_over_tcp, got failures: {fail_messages}",
        )
        self.assertEqual(scanner.args.unit_id, 0, "unit_id must be forced to 0 in broadcast mode")


if __name__ == "__main__":
    unittest.main()
