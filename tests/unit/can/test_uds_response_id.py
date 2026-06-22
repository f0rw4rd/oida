"""Regression tests for UDS response-ID attribution.

Covers the bug where ``_recv_uds_response`` returned a *synthetic* response ID
(``COMMON_UDS_PAIRS.get(req, req + 0x08)``) instead of the real source
arbitration ID of the frame that actually answered. For OBD-II broadcast probes
(request 0x7DF), ``_isotp_id_matches`` accepts ANY frame in 0x7E8-0x7EF, so an
ECU answering on 0x7EA was previously reported as 0x7E8.
"""

import unittest

from oida.protocols.can.constants import (
    OBD2_REQUEST_ID,
    UDS_POSITIVE_RESPONSE_OFFSET,
)
from oida.protocols.can.mixins.isotp import ISOTPMixin
from oida.protocols.can.mixins.uds import UDSMixin


class _FakeMessage:
    def __init__(self, arbitration_id, data):
        self.arbitration_id = arbitration_id
        self.data = data


class _FakeBus:
    """Bus that yields a pre-seeded list of frames then None (timeout)."""

    def __init__(self, frames):
        self._frames = list(frames)
        self.sent = []

    def send(self, msg):
        self.sent.append(msg)

    def recv(self, timeout=None):
        if self._frames:
            return self._frames.pop(0)
        return None


class _Harness(UDSMixin, ISOTPMixin):
    """Minimal object combining the two mixins for direct testing."""

    def __init__(self):
        # _recv_uds_response / isotp_recv touch self.logger only on send paths.
        class _Logger:
            def debug(self, *a, **k):
                pass

        self.logger = _Logger()


class TestUDSRealResponderID(unittest.TestCase):
    def test_broadcast_probe_reports_actual_responder(self):
        """A 0x7DF probe answered by 0x7EA must report 0x7EA, not 0x7E8."""
        harness = _Harness()
        # Positive TesterPresent response (0x7E) as an ISO-TP single frame,
        # sourced from arbitration ID 0x7EA (an ECU other than 0x7E8).
        positive = 0x3E + UDS_POSITIVE_RESPONSE_OFFSET
        frame = _FakeMessage(0x7EA, bytes([0x02, positive, 0x00, 0, 0, 0, 0, 0]))
        bus = _FakeBus([frame])

        result = harness._recv_uds_response(bus, OBD2_REQUEST_ID, timeout=0.1)

        self.assertIsNotNone(result)
        resp_id, payload = result
        # Before the fix this was the synthetic 0x7E8; now it must be the real ID.
        self.assertEqual(resp_id, 0x7EA)
        self.assertEqual(payload[0], positive)

    def test_two_ecus_keep_distinct_response_ids(self):
        """Distinct ECUs answering the broadcast must not collapse together."""
        harness = _Harness()
        positive = 0x3E + UDS_POSITIVE_RESPONSE_OFFSET

        for src in (0x7E8, 0x7EB):
            bus = _FakeBus([_FakeMessage(src, bytes([0x02, positive, 0x00, 0, 0, 0, 0, 0]))])
            result = harness._recv_uds_response(bus, OBD2_REQUEST_ID, timeout=0.1)
            self.assertIsNotNone(result)
            self.assertEqual(result[0], src)

    def test_isotp_recv_returns_source_id_tuple(self):
        """isotp_recv now returns (arbitration_id, payload)."""
        harness = _Harness()
        frame = _FakeMessage(0x7EC, bytes([0x01, 0x7E, 0, 0, 0, 0, 0, 0]))
        bus = _FakeBus([frame])

        result = harness.isotp_recv(bus, OBD2_REQUEST_ID, 0x7E8, timeout=0.1)

        self.assertIsNotNone(result)
        source_id, payload = result
        self.assertEqual(source_id, 0x7EC)
        self.assertEqual(payload, bytes([0x7E]))


if __name__ == "__main__":
    unittest.main()
