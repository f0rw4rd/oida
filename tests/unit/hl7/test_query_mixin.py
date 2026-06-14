"""Unit tests for the HL7 QueryMixin (mixins/query.py).

Covers:
- QRY/QBP/OSQ message *builders* (real hl7apy ER7 output, wildcard logic).
- The send-and-extract dispatch methods: they call _send_mllp_message (mocked
  via a scripted conn), then parse the response and emit findings.

Builders are exercised with hl7apy actually installed so we assert on the
emitted ER7 text. The send dispatchers are driven through a fake conn that
returns a canned MLLP response so we can assert the result/finding side
effects without a socket.
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
        enum_patients=False,
        patient_id=None,
        obx_id=None,
        order_id=None,
        extract_response=False,
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


def _mllp(body: str) -> bytes:
    return MLLP_START + body.encode() + MLLP_END


class _ReplayConn:
    """conn stub returning one MLLP message split across recv() calls."""

    def __init__(self, response_bytes):
        self._buf = response_bytes
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, _n):
        if self._buf:
            out, self._buf = self._buf, b""
            return out
        return b""


def _scanner(args):
    s = _make_hl7_instance(args, None, "10.0.0.5")
    s.logger = Mock()
    return s


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestQueryBuilders(unittest.TestCase):
    def test_qry_default_uses_wildcard_when_no_patient_id(self):
        s = _scanner(_args(patient_id=None))
        er7 = s._create_qry_message()
        self.assertIsNotNone(er7)
        self.assertIn("QRY^Q01", er7)
        self.assertIn("QRD", er7)
        self.assertIn("*", er7)  # wildcard who-subject

    def test_qry_enum_patients_forces_wildcard(self):
        s = _scanner(_args(enum_patients=True, patient_id="MRN5"))
        er7 = s._create_qry_message()
        # Even with a specific patient_id, enum mode queries '*'
        self.assertIn("*", er7)
        self.assertNotIn("MRN5", er7)

    def test_qry_uses_specific_patient_id(self):
        s = _scanner(_args(patient_id="MRN777"))
        er7 = s._create_qry_message()
        self.assertIn("MRN777", er7)

    def test_qry_r02_builds_obs_query_with_qrf(self):
        s = _scanner(_args(patient_id="P1", obx_id="GLU"))
        er7 = s._create_qry_r02_message()
        self.assertIn("QRY^R02", er7)
        self.assertIn("QRF", er7)
        self.assertIn("OBX", er7)
        self.assertIn("GLU", er7)

    def test_qbp_q31_builds_pharmacy_query(self):
        s = _scanner(_args(patient_id="PHARM1"))
        er7 = s._create_qbp_q31_message()
        self.assertIn("QPD", er7)
        self.assertIn("Q31", er7)
        self.assertIn("RCP", er7)
        self.assertIn("PHARM1", er7)

    def test_osq_q06_uses_order_id_over_patient_id(self):
        s = _scanner(_args(order_id="ORD42", patient_id="PAT1"))
        er7 = s._create_osq_q06_message()
        self.assertIn("OSQ^Q06", er7)
        self.assertIn("ORD42", er7)
        self.assertIn("QRF", er7)

    def test_legacy_pharmacy_query_builds_qry_q28(self):
        s = _scanner(_args(patient_id="LEG1"))
        er7 = s._create_legacy_pharmacy_query()
        self.assertIn("QRY^Q28", er7)
        self.assertIn("QRD", er7)
        self.assertIn("LEG1", er7)

    def test_builder_falls_back_to_test_message_on_error(self):
        s = _scanner(_args())
        # Force the hl7apy Message ctor to blow up inside _create_qry_message.
        with patch("oida.protocols.hl7.mixins.query.Message", side_effect=RuntimeError("boom")):
            er7 = s._create_qry_message()
        # Falls back to _create_test_message("QRY", "Q01") which still yields ER7.
        self.assertIsNotNone(er7)
        self.assertIn("QRY", er7)
        s.logger.debug.assert_called()


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestQuerySendDispatch(unittest.TestCase):
    def _patient_response(self):
        body = (
            "MSH|^~\\&|EPIC|HOSP|OIDA|SEC|20240101||ADT^A01|1|P|2.5\r"
            "PID|1||MRN9^^^HOSP^MR||SMITH^JANE||19900202|F\r"
            "MSA|AA|1"
        )
        return _mllp(body)

    def test_send_qry_extracts_patients_and_emits_finding(self):
        s = _scanner(_args())
        s.conn = _ReplayConn(self._patient_response())
        s._send_qry_message()
        # Query results stored and an unrestricted-access finding emitted.
        self.assertIn("query_results", s.results["data"])
        self.assertEqual(s.results["data"]["query_results"]["count"], 1)
        findings = s.results["data"].get("security_findings", [])
        issues = [f["issue"] for f in findings]
        self.assertIn("Unrestricted Query Access", issues)

    def test_send_qry_wildcard_adds_enumeration_finding(self):
        s = _scanner(_args(enum_patients=True))
        s.conn = _ReplayConn(self._patient_response())
        s._send_qry_message()
        issues = [f["issue"] for f in s.results["data"].get("security_findings", [])]
        self.assertIn("Wildcard Query Accepted", issues)

    def test_send_qry_no_response_warns_and_no_results(self):
        s = _scanner(_args())
        s.conn = _ReplayConn(b"")  # no data
        s._send_qry_message()
        self.assertNotIn("query_results", s.results["data"])
        s.logger.warning.assert_called()

    def test_send_qry_obs_extracts_observations_and_finding(self):
        s = _scanner(_args())
        body = (
            "MSH|^~\\&|EPIC|HOSP|OIDA|SEC|20240101||ADT^A01|1|P|2.5\r"
            "PID|1||MRN1^^^HOSP^MR||DOE^JOHN\r"
            "OBX|1|NM|1234-5^WBC^LN||7.5|K/uL|||||F\r"
            "MSA|AA|1"
        )
        s.conn = _ReplayConn(_mllp(body))
        s._send_qry_obs_message()
        self.assertIn("observation_results", s.results["data"])
        self.assertEqual(s.results["data"]["observation_results"]["count"], 1)
        issues = [f["issue"] for f in s.results["data"].get("security_findings", [])]
        self.assertIn("Observation Results Accessible", issues)

    def test_send_qry_orders_no_orders_records_nothing(self):
        # Standard message structures nest ORC/OBR into groups, so an
        # ADT-wrapped response surfaces no top-level orders; the extractor
        # must handle that without writing a results key.
        s = _scanner(_args())
        body = (
            "MSH|^~\\&|EPIC|HOSP|OIDA|SEC|20240101||ADT^A01|1|P|2.5\r"
            "PID|1||MRN1^^^HOSP^MR||DOE^JOHN\r"
            "MSA|AA|1"
        )
        s.conn = _ReplayConn(_mllp(body))
        s._send_qry_orders_message()
        self.assertNotIn("order_status_results", s.results["data"])
        # Server info was still parsed from the response.
        self.assertEqual(s.results["data"]["server_info"]["sending_app"], "EPIC")


if __name__ == "__main__":
    unittest.main()
