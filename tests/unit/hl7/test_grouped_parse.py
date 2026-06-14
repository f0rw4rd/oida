"""Regression: parse_message must descend into hl7apy message Groups.

For standard structures (e.g. ORU^R01) hl7apy nests PID/OBR/OBX/etc. inside
Group children, so the old `for child in msg.children` walk saw only MSH + the
group container and returned zero patients/observations. _iter_segments flattens
the tree so nested clinical segments surface.
"""

import unittest

from oida.protocols.hl7.segments import HL7SegmentParser

# ORU^R01 with PID/OBR/OBX nested under the PATIENT_RESULT group.
ORU_R01 = (
    "MSH|^~\\&|SEND|FAC|RECV|FAC|20240101000000||ORU^R01|MSG1|P|2.5\r"
    "PID|1||12345^^^HOSP||DOE^JANE\r"
    "OBR|1|||CBC^Complete Blood Count\r"
    "OBX|1|NM|GLU^Glucose||99|mg/dL\r"
    "OBX|2|NM|NA^Sodium||140|mmol/L\r"
)


class TestGroupedParse(unittest.TestCase):
    def test_nested_patient_surfaces(self):
        r = HL7SegmentParser.parse_message(ORU_R01)
        self.assertEqual(len(r["patients"]), 1)
        self.assertEqual(r["patients"][0]["PatientName"], "DOE JANE")
        self.assertEqual(r["patients"][0]["PatientID"], "12345")

    def test_nested_observations_surface(self):
        r = HL7SegmentParser.parse_message(ORU_R01)
        # Both OBX rows (nested in groups) must be found.
        self.assertEqual(len(r["observations"]), 2)
        # And they are correlated to the in-group patient.
        self.assertTrue(all(o.get("PatientID") == "12345" for o in r["observations"]))

    def test_nested_order_surfaces(self):
        r = HL7SegmentParser.parse_message(ORU_R01)
        self.assertEqual(len(r["orders"]), 1)

    def test_iter_segments_flattens_groups(self):
        from hl7apy.parser import parse_message as _pm

        msg = _pm(ORU_R01)
        names = [s.name for s in HL7SegmentParser._iter_segments(msg)]
        # Top-level walk would yield ['MSH', 'ORU_R01_PATIENT_RESULT'];
        # flattened must include the nested clinical segments.
        self.assertIn("PID", names)
        self.assertIn("OBR", names)
        self.assertEqual(names.count("OBX"), 2)


if __name__ == "__main__":
    unittest.main()
