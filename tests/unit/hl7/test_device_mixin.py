"""Unit tests for the HL7 DeviceMixin (mixins/device.py) - IHE PCD messages.

PCD-01 (device observation), PCD-03 (infusion order) and PCD alarm are all
write/dangerous operations gated behind --confirm. We assert:
- the --confirm gate refuses to send and emits no message;
- the message *builders* produce valid ER7 with the expected MDC-coded OBX /
  RXG / OBR segments and respect the device/infusion CLI args;
- on an AA ack the correct security finding is emitted.
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
        device_type="lvp",
        device_id="DEV1",
        patient_id=None,
        patient_name=None,
        location="ICU^101^A",
        flow_rate=None,
        vtbi=None,
        volume_delivered=None,
        drug_concentration=None,
        dose_rate=None,
        drug_name=None,
        rx_drug="Morphine",
        rx_dose="10",
        rx_units="mg",
        alarm_type="generic",
        extract_response=False,
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


def _ack(code="AA"):
    body = f"MSH|^~\\&|PUMP|ICU|OIDA|SEC|20240101||ACK|1|P|2.5\rMSA|{code}|1"
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
    s = _make_hl7_instance(args, None, "10.0.0.7")
    s.logger = Mock()
    s.conn = conn if conn is not None else _ReplayConn(b"")
    return s


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestPcdConfirmGate(unittest.TestCase):
    def test_pcd01_refuses_without_confirm(self):
        conn = _ReplayConn(_ack())
        s = _scanner(_args(confirm=False), conn=conn)
        s._send_pcd01_message()
        self.assertEqual(conn.sent, [])  # nothing sent
        s.logger.fail.assert_called()

    def test_pcd03_refuses_without_confirm(self):
        conn = _ReplayConn(_ack())
        s = _scanner(_args(confirm=False), conn=conn)
        s._send_pcd03_message()
        self.assertEqual(conn.sent, [])
        s.logger.fail.assert_called()

    def test_pcd_alarm_refuses_without_confirm(self):
        conn = _ReplayConn(_ack())
        s = _scanner(_args(confirm=False), conn=conn)
        s._send_pcd_alarm_message()
        self.assertEqual(conn.sent, [])
        s.logger.fail.assert_called()


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestPcd01Builder(unittest.TestCase):
    def test_default_observation_is_flow_rate(self):
        s = _scanner(_args())
        er7 = s._create_pcd01_message()
        self.assertIn("ORU^R01", er7)
        self.assertIn("OBR", er7)
        self.assertIn("OBX", er7)
        self.assertIn("MDC", er7)  # MDC-coded observation
        # Default flow rate of 125 with no explicit metric args.
        self.assertIn("125", er7)

    def test_explicit_metrics_added_as_obx(self):
        s = _scanner(_args(flow_rate="50", vtbi="250", dose_rate="3"))
        er7 = s._create_pcd01_message()
        self.assertIn("50", er7)
        self.assertIn("250", er7)
        self.assertIn("3", er7)
        # Multiple OBX segments for the multiple metrics.
        self.assertGreaterEqual(er7.count("OBX"), 3)

    def test_device_type_sets_sending_app(self):
        s = _scanner(_args(device_type="monitor", device_id="MON7"))
        er7 = s._create_pcd01_message()
        self.assertIn("BEDSIDE_MONITOR", er7)
        self.assertIn("MON7", er7)


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestPcd03Builder(unittest.TestCase):
    def test_infusion_order_includes_rxg_and_tq1(self):
        s = _scanner(_args(drug_name="Heparin", flow_rate="20", rx_units="units"))
        er7 = s._create_pcd03_message()
        self.assertIn("RGV^O15", er7)
        self.assertIn("ORC", er7)
        self.assertIn("RXG", er7)
        self.assertIn("TQ1", er7)
        self.assertIn("Heparin", er7)

    def test_concentration_adds_strength_fields(self):
        s = _scanner(_args(drug_name="Insulin", drug_concentration="100"))
        er7 = s._create_pcd03_message()
        self.assertIn("Insulin", er7)
        self.assertIn("100", er7)
        self.assertIn("mg/mL", er7)


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestPcdAlarmBuilder(unittest.TestCase):
    def test_occlusion_alarm_is_high_priority(self):
        s = _scanner(_args(alarm_type="occlusion"))
        er7 = s._create_pcd_alarm_message()
        self.assertIn("ORU^R42", er7)
        self.assertIn("Line Occluded", er7)
        self.assertIn("HIGH", er7)

    def test_generic_alarm_is_medium_priority(self):
        s = _scanner(_args(alarm_type="generic"))
        er7 = s._create_pcd_alarm_message()
        self.assertIn("MEDIUM", er7)

    def test_alarm_includes_pid_when_patient_id_given(self):
        s = _scanner(_args(alarm_type="battery", patient_id="P55"))
        er7 = s._create_pcd_alarm_message()
        self.assertIn("PID", er7)
        self.assertIn("P55", er7)
        self.assertIn("Low Battery", er7)


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestPcdSendFindings(unittest.TestCase):
    def test_pcd01_accepted_emits_finding(self):
        s = _scanner(_args(confirm=True, device_type="syringe"), conn=_ReplayConn(_ack("AA")))
        s._send_pcd01_message()
        findings = s.results["data"].get("security_findings", [])
        issues = [f["issue"] for f in findings]
        self.assertIn("Device Observation Accepted", issues)

    def test_pcd03_accepted_emits_finding(self):
        s = _scanner(_args(confirm=True, drug_name="Morphine"), conn=_ReplayConn(_ack("AA")))
        s._send_pcd03_message()
        issues = [f["issue"] for f in s.results["data"].get("security_findings", [])]
        self.assertIn("Infusion Order Accepted", issues)

    def test_pcd_alarm_accepted_emits_finding(self):
        s = _scanner(_args(confirm=True, alarm_type="air"), conn=_ReplayConn(_ack("AA")))
        s._send_pcd_alarm_message()
        issues = [f["issue"] for f in s.results["data"].get("security_findings", [])]
        self.assertIn("Device Alarm Accepted", issues)

    def test_pcd01_rejected_emits_no_finding(self):
        s = _scanner(_args(confirm=True), conn=_ReplayConn(_ack("AR")))
        s._send_pcd01_message()
        # Rejected -> no acceptance finding.
        issues = [f["issue"] for f in s.results["data"].get("security_findings", [])]
        self.assertNotIn("Device Observation Accepted", issues)


if __name__ == "__main__":
    unittest.main()
