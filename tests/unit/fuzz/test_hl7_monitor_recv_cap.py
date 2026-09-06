"""HL7Monitor must cap its recv buffer to prevent OOM.

CODE_REVIEW.md §-1 (deferred subsection): fuzz/monitors/medical.HL7Monitor
had an unbounded `sock.recv(1024)` loop that broke only on MLLP_END or
empty chunk. A fuzz target that ignores MLLP framing (the whole point
of fuzzing) could keep streaming, exhausting client memory. 16 MiB cap
matches the existing hl7/utils.py:send_probe pattern.
"""

import socket
import unittest
from unittest.mock import MagicMock


class _FakeFloodingSocket:
    """Mocks a socket that streams forever without sending MLLP_END.

    Returns 64 KiB regardless of the recv(n) request — keeps the test
    under 1s by reaching the 16 MiB cap in ~256 iterations instead
    of 16k, while still exercising the bound.
    """

    _CHUNK = b"A" * (64 * 1024)

    def __init__(self):
        self.timeout = 5
        self._bytes_sent = 0

    def settimeout(self, t):
        self.timeout = t

    def connect(self, addr):
        pass

    def send(self, data):
        return len(data)

    def recv(self, _n):
        self._bytes_sent += len(self._CHUNK)
        if self._bytes_sent > 50 * 1024 * 1024:
            # If we ever stream 50 MiB, the cap is broken — give up
            # so the test fails cleanly instead of OOMing the runner.
            return b""
        return self._CHUNK

    def close(self):
        pass


class TestHL7MonitorRecvCap(unittest.TestCase):
    def test_unbounded_target_does_not_run_to_oom(self):
        from oida.fuzz.monitors.medical import HL7Monitor

        mon = HL7Monitor("127.0.0.1", 2575, timeout=2)
        mon.logger = MagicMock()

        # Replace socket.socket with our fake
        flood = _FakeFloodingSocket()
        original = socket.socket
        socket.socket = lambda *a, **kw: flood
        try:
            response = mon._send_message()
        finally:
            socket.socket = original

        # The cap is 16 MiB; the recv loop appends a chunk and THEN
        # checks the cap, so allow up to one full chunk-size of overage.
        self.assertIsNotNone(response)
        self.assertLessEqual(
            len(response),
            16 * 1024 * 1024 + 128 * 1024,  # 16 MiB + room for two chunks
            "Recv loop did not honor 16 MiB cap — OOM risk",
        )
        # Must not have streamed close to the 50 MiB safety belt either.
        self.assertLess(flood._bytes_sent, 30 * 1024 * 1024)

    def test_source_contains_cap_constant(self):
        """Belt-and-braces: snapshot the cap so a refactor must keep it."""
        import pathlib

        src = pathlib.Path("src/oida/fuzz/monitors/medical.py").read_text()
        self.assertIn("MAX_HL7_RESPONSE", src)
        self.assertIn("16 * 1024 * 1024", src)


if __name__ == "__main__":
    unittest.main()
