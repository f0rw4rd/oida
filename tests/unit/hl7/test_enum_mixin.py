"""Unit tests for the HL7 EnumMixin (mixins/enum.py).

Covers provider, application/facility and location enumeration. These methods
parse stored / fresh HL7 responses and populate self.results["data"] with the
enumerated topology. We drive the QRY round-trip via a fake conn and also feed
stored responses via self.all_responses.
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
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


def _mllp(body: str) -> bytes:
    return MLLP_START + body.encode() + MLLP_END


class _ReplayConn:
    def __init__(self, response_bytes=b""):
        self._buf = response_bytes
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, _n):
        if self._buf:
            out, self._buf = self._buf, b""
            return out
        return b""


def _scanner(args, conn=None):
    s = _make_hl7_instance(args, None, "10.0.0.9")
    s.logger = Mock()
    s.conn = conn if conn is not None else _ReplayConn(b"")
    return s


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestEnumProviders(unittest.TestCase):
    def test_extracts_providers_into_results(self):
        # PV1 with a doctor name surfaces a provider; ADT keeps PV1 flat.
        resp = _mllp(
            "MSH|^~\\&|EPIC|HOSP|OIDA|SEC|20240101||ADT^A01|1|P|2.5\r"
            "PID|1||MRN1^^^HOSP^MR||DOE^JOHN\r"
            "PV1|1|I|ICU^101^A|A|B|C|1234^WELBY^MARCUS|5678^JONES^B"
        )
        s = _scanner(_args(), conn=_ReplayConn(resp))
        s._enum_providers()
        providers = s.results["data"].get("providers")
        self.assertIsNotNone(providers)
        # At least one physician category was populated from PV1.
        all_docs = (
            providers["attending_physicians"]
            + providers["referring_physicians"]
            + providers["consulting_physicians"]
            + providers["admitting_physicians"]
        )
        self.assertTrue(any("WELBY" in d for d in all_docs))

    def test_no_providers_warns_and_stores_nothing(self):
        # Response with no PV1/OBR/ORC -> nothing to enumerate.
        resp = _mllp("MSH|^~\\&|S|F\rMSA|AA|1")
        s = _scanner(_args(), conn=_ReplayConn(resp))
        s._enum_providers()
        self.assertNotIn("providers", s.results["data"])
        s.logger.warning.assert_called()

    def test_pulls_providers_from_stored_responses(self):
        s = _scanner(_args(), conn=_ReplayConn(b""))  # QRY returns nothing
        stored = (
            "MSH|^~\\&|EPIC|HOSP|OIDA|SEC|20240101||ADT^A01|1|P|2.5\r"
            "PID|1||MRN2^^^HOSP^MR||SMITH^ANN\r"
            "PV1|1|I|WARD^5^B|A|B|C|999^HOUSE^GREG"
        )
        s.all_responses = [{"raw": stored.encode()}]
        s._enum_providers()
        self.assertIn("providers", s.results["data"])


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestEnumApps(unittest.TestCase):
    def test_extracts_apps_and_facilities_from_responses(self):
        s = _scanner(_args())
        stored = "MSH|^~\\&|MIRTH|GENERAL_HOSP|OIDA|SEC|20240101||ADT^A01|1|P|2.5"
        s.all_responses = [{"raw": stored.encode()}]
        s._enum_apps()
        topo = s.results["data"].get("interface_topology")
        self.assertIsNotNone(topo)
        self.assertIn("MIRTH", topo["applications"])
        # Vendor identification ran on MSH-3.
        self.assertEqual(topo["applications"]["MIRTH"]["vendor"], "NextGen")
        self.assertIn("GENERAL_HOSP", topo["facilities"])

    def test_seeds_from_existing_server_info(self):
        s = _scanner(_args())
        s.results["data"]["server_info"] = {
            "sending_app": "CERNER",
            "sending_facility": "CLINIC_A",
            "vendor": "Cerner Corporation",
            "product_type": "EMR",
        }
        s._enum_apps()
        topo = s.results["data"]["interface_topology"]
        self.assertIn("CERNER", topo["applications"])
        self.assertIn("CLINIC_A", topo["facilities"])

    def test_no_apps_warns(self):
        s = _scanner(_args())
        s.all_responses = []
        s._enum_apps()
        self.assertNotIn("interface_topology", s.results["data"])
        s.logger.warning.assert_called()


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestEnumLocations(unittest.TestCase):
    def test_extracts_location_components(self):
        # PV1-3 = Point of Care^Room^Bed^Facility -> units/rooms/beds split.
        resp = _mllp(
            "MSH|^~\\&|EPIC|HOSP|OIDA|SEC|20240101||ADT^A01|1|P|2.5\r"
            "PID|1||MRN1^^^HOSP^MR||DOE^JOHN\r"
            "PV1|1|I|WARD5^201^B^HOSP"
        )
        s = _scanner(_args(), conn=_ReplayConn(resp))
        s._enum_locations()
        locs = s.results["data"].get("locations")
        self.assertIsNotNone(locs)
        self.assertIn("WARD5", locs["nursing_units"])
        self.assertIn("201", locs["rooms"])
        self.assertIn("B", locs["beds"])
        self.assertTrue(any("WARD5" in fl for fl in locs["full_locations"]))

    def test_no_locations_warns(self):
        resp = _mllp("MSH|^~\\&|S|F\rMSA|AA|1")
        s = _scanner(_args(), conn=_ReplayConn(resp))
        s._enum_locations()
        self.assertNotIn("locations", s.results["data"])
        s.logger.warning.assert_called()


if __name__ == "__main__":
    unittest.main()
