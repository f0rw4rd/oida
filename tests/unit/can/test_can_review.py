"""Regression tests for ISO 14229 NRC 0x78 (responsePending) handling.

Covers the bug where ``_recv_uds_response`` (and therefore every caller:
``uds_ecu_reset``, ``_enumerate_uds_services``, ``uds_session_scan``,
``uds_did_scan``, ``uds_routine_scan``) treated NRC 0x78
(requestCorrectlyReceived-ResponsePending) as a final rejection. An ECU that
replied ``7F <sid> 78`` and then completed the operation was reported as
"ECU reset rejected" / "service not supported" -- a false negative for an
operation that actually succeeded.

Fixture style follows tests/unit/can/test_uds_response_id.py.
"""

import time
import unittest

from oida.protocols.can.constants import UDS_NEGATIVE_RESPONSE, UDS_POSITIVE_RESPONSE_OFFSET
from oida.protocols.can.mixins.isotp import ISOTPMixin
from oida.protocols.can.mixins.uds import (
    UDS_MAX_PENDING_RESPONSES,
    UDS_P2_STAR_TIMEOUT,
    UDSMixin,
)


class _FakeMessage:
    def __init__(self, arbitration_id, data):
        self.arbitration_id = arbitration_id
        self.data = data


class _FakeBus:
    """Bus that yields pre-seeded frames then None (timeout)."""

    def __init__(self, frames):
        self._frames = list(frames)
        self.sent = []

    def send(self, msg):
        self.sent.append(msg)

    def recv(self, timeout=None):
        if self._frames:
            return self._frames.pop(0)
        return None


class _Logger:
    def debug(self, *a, **k):
        pass

    def display(self, *a, **k):
        pass

    def success(self, *a, **k):
        pass

    def fail(self, *a, **k):
        pass


class _Harness(UDSMixin, ISOTPMixin):
    def __init__(self):
        self.logger = _Logger()
        self.extended = False
        self.args = {}


def _sf(arb_id, payload):
    """ISO-TP single frame carrying a de-framed UDS payload."""
    return _FakeMessage(
        arb_id, bytes([len(payload)] + list(payload) + [0x00] * (8 - 1 - len(payload)))
    )


class TestResponsePendingHandling(unittest.TestCase):
    def test_pending_then_positive_reports_success(self):
        """7F 11 78 then 51 11 -> uds_ecu_reset must return True."""
        h = _Harness()
        # Response ECU for request 0x7E0 is 0x7E8.
        frames = [
            _sf(0x7E8, [0x7F, 0x11, 0x78]),  # pending
            _sf(0x7E8, [0x11 + UDS_POSITIVE_RESPONSE_OFFSET, 0x01]),  # 51 11
        ]
        bus = _FakeBus(frames)
        self.assertTrue(h.uds_ecu_reset(bus, 0x7E0, reset_type=0x01))

    def test_pending_then_real_rejection_reports_failure(self):
        """7F 11 78 then 7F 11 33 -> still a genuine rejection."""
        h = _Harness()
        frames = [
            _sf(0x7E8, [0x7F, 0x11, 0x78]),  # pending
            _sf(0x7E8, [0x7F, 0x11, 0x33]),  # securityAccessDenied
        ]
        bus = _FakeBus(frames)
        self.assertFalse(h.uds_ecu_reset(bus, 0x7E0, reset_type=0x01))

    def test_endless_pending_terminates(self):
        """An ECU that only ever sends 0x78 must not hang the scanner.

        The pending cap makes _recv_uds_response give up and return None; the
        caller (uds_ecu_reset) maps None to "no response (ECU may have reset)"
        -> True, which is its documented pre-existing contract for silence.
        The regression property under test is TERMINATION within a bounded
        time, not the return value.
        """
        h = _Harness()
        # Enough pendings to exceed the cap; the bus never yields a final frame.
        endless = [
            _sf(0x7E8, [UDS_NEGATIVE_RESPONSE, 0x11, 0x78])
            for _ in range(UDS_MAX_PENDING_RESPONSES + 5)
        ]
        bus = _FakeBus(endless)
        start = time.monotonic()
        result = h.uds_ecu_reset(bus, 0x7E0, reset_type=0x01)
        elapsed = time.monotonic() - start
        # Must terminate, and quickly: each pending extends the deadline by
        # UDS_P2_STAR_TIMEOUT only until the cap is hit, and the fake bus
        # drains instantly, so wall time stays near zero.
        self.assertLess(elapsed, UDS_P2_STAR_TIMEOUT * 2)
        self.assertIn(result, (True, False))

    def test_plain_positive_response_unchanged(self):
        """No 0x78 involved: single positive response still works."""
        h = _Harness()
        frames = [_sf(0x7E8, [0x11 + UDS_POSITIVE_RESPONSE_OFFSET, 0x01])]
        bus = _FakeBus(frames)
        self.assertTrue(h.uds_ecu_reset(bus, 0x7E0, reset_type=0x01))

    def test_no_response_still_treated_as_possible_success(self):
        """Timeout with no frames keeps the pre-existing 'may have reset' True."""
        h = _Harness()
        bus = _FakeBus([])
        self.assertTrue(h.uds_ecu_reset(bus, 0x7E0, reset_type=0x01))

    def test_constants_are_sane(self):
        """P2* and the pending cap stay bounded."""
        self.assertGreater(UDS_P2_STAR_TIMEOUT, 0)
        self.assertLess(UDS_P2_STAR_TIMEOUT, 60)
        self.assertLess(UDS_MAX_PENDING_RESPONSES, 50)


if __name__ == "__main__":
    unittest.main()
