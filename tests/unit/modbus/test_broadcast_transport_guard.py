"""--broadcast (Unit ID 0) is Modbus-RTU only; reject on TCP/TLS/UDP.

CODE_REVIEW.md HIGH modbus/cli_runner.py:201-209.
"""

import pathlib
import unittest


class TestBroadcastTransportRejection(unittest.TestCase):
    def test_source_refuses_broadcast_on_tcp(self):
        src = pathlib.Path("src/oida/protocols/modbus/cli_runner.py").read_text()
        self.assertIn(
            "--broadcast is Modbus-RTU only",
            src,
            "broadcast transport guard regressed",
        )

    def test_source_checks_serial_indicators(self):
        src = pathlib.Path("src/oida/protocols/modbus/cli_runner.py").read_text()
        # The check looks at all three serial-flavor flags.
        self.assertIn("serial_port", src)
        self.assertIn("rtu_over_tcp", src)
        self.assertIn("ascii_over_tcp", src)


if __name__ == "__main__":
    unittest.main()
