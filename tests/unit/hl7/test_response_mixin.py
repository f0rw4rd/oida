"""Unit tests for the HL7 ResponseMixin (mixins/response.py) and the shared
_display_results_table helper.

_extract_detailed_response only runs when --extract-response is set; it parses
the response and pulls either operator-requested fields (--extract-fields
"SEG-N,...") or a default common-field set, appending to self.all_responses.
"""

import types
import unittest
from unittest.mock import Mock, patch

from tests.unit.hl7.conftest import _make_hl7_instance


def _args(**kw):
    base = dict(
        hl7_version="2.5",
        extract_response=False,
        extract_fields="",
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


def _scanner(args):
    s = _make_hl7_instance(args, None, "10.0.0.6")
    s.logger = Mock()
    return s


def _adt_response():
    return (
        "MSH|^~\\&|EPIC|HOSP|OIDA|SEC|20240101||ADT^A01|1|P|2.5\r"
        "PID|1||MRN42^^^HOSP^MR||DOE^JOHN^Q||19800101|M\r"
        "PV1|1|I|ICU^101^A|||||||||||||||V9999"
    ).encode()


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestExtractDetailedResponse(unittest.TestCase):
    def test_disabled_when_flag_off(self):
        s = _scanner(_args(extract_response=False))
        s._extract_detailed_response(_adt_response(), "ADT^A01")
        self.assertEqual(s.all_responses, [])

    def test_default_common_fields_extracted(self):
        s = _scanner(_args(extract_response=True))
        s._extract_detailed_response(_adt_response(), "ADT^A01")
        self.assertEqual(len(s.all_responses), 1)
        entry = s.all_responses[0]
        self.assertEqual(entry["message_type"], "ADT^A01")
        # PID-3 / PID-5 captured.
        self.assertIn("MRN42", entry["segments"]["PID-3"])
        self.assertIn("DOE", entry["segments"]["PID-5"])

    def test_explicit_field_spec_extracted(self):
        s = _scanner(_args(extract_response=True, extract_fields="PID-3, MSH-9"))
        s._extract_detailed_response(_adt_response(), "ADT^A01")
        seg = s.all_responses[0]["segments"]
        self.assertIn("PID-3", seg)
        self.assertIn("MSH-9", seg)
        self.assertIn("MRN42", seg["PID-3"])
        self.assertIn("ADT", seg["MSH-9"])

    def test_malformed_response_handled_gracefully(self):
        s = _scanner(_args(extract_response=True))
        # Not a valid HL7 message; should be swallowed, no entry appended.
        s._extract_detailed_response(b"\x00\x01garbage", "ADT^A01")
        self.assertEqual(s.all_responses, [])
        s.logger.debug.assert_called()


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestDisplayResultsTable(unittest.TestCase):
    def test_empty_items_no_store_no_finding(self):
        s = _scanner(_args())
        s._display_results_table(
            items=[],
            column_defs=[("ID", "ID")],
            result_key="query_results",
            result_label="patient(s)",
            security_finding={"issue": "X"},
        )
        self.assertNotIn("query_results", s.results["data"])
        self.assertNotIn("security_findings", s.results["data"])

    def test_stores_items_and_finding(self):
        s = _scanner(_args())
        items = [{"ID": "1", "Name": "A"}, {"ID": "2", "Name": "B"}]
        s._display_results_table(
            items=items,
            column_defs=[("ID", "ID"), ("Name", "Name")],
            result_key="query_results",
            result_label="patient(s)",
            security_finding={"issue": "Unrestricted Query Access"},
        )
        stored = s.results["data"]["query_results"]
        self.assertEqual(stored["count"], 2)
        # result_label "patient(s)" -> item key "patient"
        self.assertEqual(stored["patient"], items)
        issues = [f["issue"] for f in s.results["data"]["security_findings"]]
        self.assertIn("Unrestricted Query Access", issues)

    def test_only_nonempty_columns_kept(self):
        # The 'Empty' column has no values across items -> dropped from table.
        s = _scanner(_args())
        items = [{"ID": "1", "Empty": ""}, {"ID": "2", "Empty": ""}]
        with patch("oida.utils.export_utils.print_table") as pt:
            s._display_results_table(
                items=items,
                column_defs=[("ID", "ID"), ("Empty", "Empty")],
                result_key="r",
                result_label="row(s)",
            )
        # print_table called with headers excluding the all-empty column.
        _, kwargs = pt.call_args
        args = pt.call_args.args
        headers = args[1]
        self.assertIn("ID", headers)
        self.assertNotIn("Empty", headers)


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestObservationAndPharmacyNoData(unittest.TestCase):
    def test_observation_extraction_no_obx_records_nothing(self):
        s = _scanner(_args())
        resp = b"MSH|^~\\&|S|F|O|S|20240101||ADT^A01|1|P|2.5\rPID|1||M^^^H"
        s._extract_observation_results(resp)
        self.assertNotIn("observation_results", s.results["data"])

    def test_pharmacy_extraction_no_meds_records_nothing(self):
        s = _scanner(_args())
        resp = b"MSH|^~\\&|S|F|O|S|20240101||ADT^A01|1|P|2.5\rPID|1||M^^^H"
        s._extract_pharmacy_results(resp)
        self.assertNotIn("pharmacy_results", s.results["data"])


if __name__ == "__main__":
    unittest.main()
