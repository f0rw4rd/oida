"""Unit tests for the HL7 PharmacyMixin send-dispatch flow (mixins/pharmacy.py).

Focuses on the confirm-gate, build-failure handling, no-response handling and
AA-finding emission of the pharmacy send methods (RDE/RAS/RGV/RDS). The message
builders themselves are covered by test_pharmacy_messages.py, so here we mock
the builders and drive only the dispatch logic.
"""

import types
import unittest
from unittest.mock import Mock, patch

from oida.protocols.hl7.utils import MLLP_END, MLLP_START
from tests.unit.hl7.conftest import _make_hl7_instance


def _args(**kw):
    base = dict(
        hl7_version="2.5",
        confirm=False,
        rx_drug="Warfarin",
        extract_response=False,
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


def _scanner(args):
    s = _make_hl7_instance(args, None, "10.0.0.3")
    s.logger = Mock()
    return s


def _ack(code="AA"):
    body = f"MSH|^~\\&|PHARM|RX|OIDA|SEC|20240101||ACK|1|P|2.5\rMSA|{code}|1"
    return MLLP_START + body.encode() + MLLP_END


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestRdeSend(unittest.TestCase):
    def test_refuses_without_confirm(self):
        s = _scanner(_args(confirm=False))
        with patch.object(s, "_send_mllp_message") as send:
            s._send_rx_message()
        send.assert_not_called()
        s.logger.fail.assert_called()

    def test_accepted_emits_prescription_finding(self):
        s = _scanner(_args(confirm=True, rx_drug="Heparin"))
        with (
            patch.object(s, "_create_rx_message", return_value="MSH|...RDE"),
            patch.object(s, "_send_mllp_message", return_value=_ack("AA")),
        ):
            s._send_rx_message()
        findings = s.results["data"].get("security_findings", [])
        self.assertTrue(any(f["issue"] == "Prescription Order Accepted" for f in findings))
        self.assertTrue(any("Heparin" in f["description"] for f in findings))

    def test_no_response_warns_no_finding(self):
        s = _scanner(_args(confirm=True))
        with (
            patch.object(s, "_create_rx_message", return_value="MSH|...RDE"),
            patch.object(s, "_send_mllp_message", return_value=None),
        ):
            s._send_rx_message()
        self.assertNotIn("security_findings", s.results["data"])
        s.logger.warning.assert_called()

    def test_rejected_ack_emits_no_finding(self):
        s = _scanner(_args(confirm=True))
        with (
            patch.object(s, "_create_rx_message", return_value="MSH|...RDE"),
            patch.object(s, "_send_mllp_message", return_value=_ack("AR")),
        ):
            s._send_rx_message()
        self.assertNotIn("security_findings", s.results["data"])


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestSharedPharmacyConfirmed(unittest.TestCase):
    def test_ras_refuses_without_confirm(self):
        s = _scanner(_args(confirm=False))
        with (
            patch.object(s, "_send_mllp_message") as send,
            patch.object(s, "_create_ras_message") as create,
        ):
            s._send_ras_message()
        send.assert_not_called()
        create.assert_not_called()
        s.logger.fail.assert_called()

    def test_rgv_build_failure_fails_cleanly(self):
        s = _scanner(_args(confirm=True))
        with (
            patch.object(s, "_create_rgv_message", return_value=None),
            patch.object(s, "_send_mllp_message") as send,
        ):
            s._send_rgv_message()
        send.assert_not_called()
        # logger.fail called with the "<MSG> message creation failed" message.
        self.assertTrue(any("creation failed" in str(c.args) for c in s.logger.fail.call_args_list))

    def test_rds_accepted_emits_dispense_finding(self):
        s = _scanner(_args(confirm=True))
        with (
            patch.object(s, "_create_rds_message", return_value="MSH|...RDS"),
            patch.object(s, "_send_mllp_message", return_value=_ack("AA")),
        ):
            s._send_rds_message()
        issues = [f["issue"] for f in s.results["data"].get("security_findings", [])]
        self.assertIn("Pharmacy Dispense Accepted", issues)

    def test_ras_no_response_warns(self):
        s = _scanner(_args(confirm=True))
        with (
            patch.object(s, "_create_ras_message", return_value="MSH|...RAS"),
            patch.object(s, "_send_mllp_message", return_value=None),
        ):
            s._send_ras_message()
        s.logger.warning.assert_called()
        self.assertNotIn("security_findings", s.results["data"])


if __name__ == "__main__":
    unittest.main()
