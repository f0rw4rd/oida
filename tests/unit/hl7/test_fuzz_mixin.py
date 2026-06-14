"""Unit tests for the HL7 FuzzMixin (mixins/fuzz.py).

_fuzz_messages runs a confirm-gated two-phase fuzz: (1) a fixed list of
protocol-specific malformed payloads, (2) mutation fuzzing over every message
type. We drive it with a fake conn that ACKs everything and a tiny iteration
count, and assert the gate + the aggregated fuzz_results structure.
"""

import types
import unittest
from unittest.mock import Mock, patch

from oida.protocols.hl7.utils import MLLP_END, MLLP_START
from tests.unit.hl7.conftest import _make_hl7_instance


def _args(**kw):
    base = dict(
        hl7_version="2.5",
        sending_app="OIDA",
        sending_facility="SECURITY",
        confirm=False,
        fuzz_iterations=2,
        fuzz_segment=None,
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


def _ack():
    body = "MSH|^~\\&|S|F|OIDA|SEC|20240101||ACK|1|P|2.5\rMSA|AA|1"
    return MLLP_START + body.encode() + MLLP_END


class _AlwaysAckConn:
    """Returns a fresh ACK for every message sent."""

    def __init__(self):
        self.sent = []
        self._pending = b""

    def sendall(self, data):
        self.sent.append(data)
        self._pending = _ack()

    def recv(self, _n):
        if self._pending:
            out, self._pending = self._pending, b""
            return out
        return b""


def _scanner(args, conn=None):
    s = _make_hl7_instance(args, None, "10.0.0.8")
    s.logger = Mock()
    s.conn = conn if conn is not None else _AlwaysAckConn()
    return s


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestFuzzMessages(unittest.TestCase):
    def test_requires_confirm(self):
        conn = _AlwaysAckConn()
        s = _scanner(_args(confirm=False), conn=conn)
        s._fuzz_messages()
        self.assertEqual(conn.sent, [])
        s.logger.fail.assert_called_with("Fuzzing requires --confirm flag")
        self.assertNotIn("fuzz_results", s.results["data"])

    def test_runs_test_cases_and_mutations(self):
        s = _scanner(_args(confirm=True, fuzz_iterations=2))
        s._fuzz_messages()
        results = s.results["data"]["fuzz_results"]
        # The 7 fixed protocol test cases must each be represented.
        named = {r["test"] for r in results if "test" in r}
        self.assertIn("Empty message", named)
        self.assertIn("SQL injection", named)
        self.assertIn("Oversized field", named)
        # Plus mutation-result entries (carry a "type"/"tests" shape).
        mutation_entries = [r for r in results if "type" in r and "tests" in r]
        self.assertTrue(mutation_entries)
        # With an ACKing conn, every mutation that was sent got a response.
        any_with_resp = any(r["responses"] >= 1 for r in mutation_entries)
        self.assertTrue(any_with_resp)

    def test_segment_injection_path(self):
        # fuzz_segment routes each base message through _inject_fuzz_segment;
        # we just need it to run without error and still produce results.
        s = _scanner(_args(confirm=True, fuzz_iterations=1, fuzz_segment="PID"))
        s._fuzz_messages()
        self.assertIn("fuzz_results", s.results["data"])

    def test_mutation_counts_aggregate(self):
        s = _scanner(_args(confirm=True, fuzz_iterations=3))
        s._fuzz_messages()
        mutation_entries = [r for r in s.results["data"]["fuzz_results"] if "tests" in r]
        # Each mutation entry's tests == responses + (errors counted separately);
        # tests should be > 0 for at least one message type.
        self.assertTrue(any(r["tests"] > 0 for r in mutation_entries))


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestInjectFuzzSegment(unittest.TestCase):
    def test_replaces_existing_segment(self):
        s = _scanner(_args())
        msg = "MSH|^~\\&|A\rPID|1||ORIGINALMRN\rPV1|1|I"
        out = s._inject_fuzz_segment(msg, "PID")
        # The original PID payload is gone, replaced by an oversized one.
        self.assertNotIn("ORIGINALMRN", out)
        self.assertIn("MSH|^~\\&|A", out)
        self.assertIn("PV1|1|I", out)
        # Oversized marker from the fuzz_content table.
        self.assertIn("X" * 100, out)
        # MSH/PV1 untouched, PID replaced -> still 3 segments.
        self.assertEqual(out.count("\r"), 2)

    def test_appends_when_segment_absent(self):
        s = _scanner(_args())
        msg = "MSH|^~\\&|A"
        out = s._inject_fuzz_segment(msg, "OBX")
        self.assertTrue(out.startswith("MSH|^~\\&|A"))
        self.assertIn("OBX|1|ST|", out)

    def test_unknown_segment_returns_unchanged(self):
        s = _scanner(_args())
        msg = "MSH|^~\\&|A\rZZZ|1"
        out = s._inject_fuzz_segment(msg, "ZZZ")
        self.assertEqual(out, msg)


if __name__ == "__main__":
    unittest.main()
