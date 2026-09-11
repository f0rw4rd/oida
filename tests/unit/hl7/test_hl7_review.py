"""Regression tests for the four HL7 review bugs.

BUG 1 (query.py:_send_qry_message): the "Wildcard Query Accepted" security
finding must only fire when the server actually accepted (MSA|AA or MSA|CA),
not merely because a response was received.

BUG 2 (_helpers.py:populate_msh): -R/--receiving-app and
--receiving-facility must reach MSH-5/MSH-6, overriding the mixin's
contextual default when the operator supplies a non-empty value.

BUG 3 (~10 sites across mixins/*.py): acceptance checks must treat MSA|CA
(enhanced-mode Commit Accept) the same as MSA|AA (Application Accept), via
the shared ``ack_accepted`` helper.

BUG 4 (master_file.py:_create_mfn_message): STF-11 (department) was always
"" because no --department CLI flag existed. A flag was added to
proto_args.py; this asserts it flows through to the STF segment.
"""

import types
import unittest
from unittest.mock import Mock, patch

from hl7apy.core import Message

from oida.protocols.hl7.mixins._helpers import ack_accepted, populate_msh
from oida.protocols.hl7.utils import MLLP_END, MLLP_START
from tests.unit.hl7.conftest import _make_hl7_instance


def _mllp(body: str) -> bytes:
    return MLLP_START + body.encode() + MLLP_END


class _ReplayConn:
    """conn stub returning one MLLP message split across recv() calls."""

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


def _args(**kw):
    base = dict(
        hl7_version="2.5",
        sending_app="OIDA",
        sending_facility="SECURITY",
        receiving_app="",
        receiving_facility="",
        confirm=False,
        enum_patients=False,
        patient_id=None,
        extract_response=False,
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


def _scanner(args, conn=None):
    s = _make_hl7_instance(args, None, "10.0.0.9")
    s.logger = Mock()
    s.conn = conn if conn is not None else _ReplayConn(b"")
    return s


# ---------------------------------------------------------------------------
# BUG 1 — wildcard query finding gated on acceptance
# ---------------------------------------------------------------------------


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestWildcardQueryFindingGatedOnAck(unittest.TestCase):
    def _response(self, ack_code: str) -> bytes:
        body = (
            "MSH|^~\\&|EPIC|HOSP|OIDA|SEC|20240101||ADT^A01|1|P|2.5\r"
            "PID|1||MRN9^^^HOSP^MR||SMITH^JANE||19900202|F\r"
            f"MSA|{ack_code}|1"
        )
        return _mllp(body)

    def test_wildcard_finding_emitted_on_aa_accept(self):
        s = _scanner(_args(enum_patients=True))
        s.conn = _ReplayConn(self._response("AA"))
        s._send_qry_message()
        issues = [f["issue"] for f in s.results["data"].get("security_findings", [])]
        self.assertIn("Wildcard Query Accepted", issues)

    def test_wildcard_finding_not_emitted_on_ar_reject(self):
        """A server that REJECTS the wildcard query (MSA|AR) must not be
        reported as allowing wildcard patient enumeration — this is the
        exact fabricated-finding bug: before the fix, `if response:` alone
        triggered the finding regardless of the ack code."""
        s = _scanner(_args(enum_patients=True))
        s.conn = _ReplayConn(self._response("AR"))
        s._send_qry_message()
        issues = [f["issue"] for f in s.results["data"].get("security_findings", [])]
        self.assertNotIn("Wildcard Query Accepted", issues)


# ---------------------------------------------------------------------------
# BUG 2 — -R/--receiving-app and --receiving-facility must reach MSH-5/6
# ---------------------------------------------------------------------------


class TestPopulateMshReceivingArgsOverride(unittest.TestCase):
    def _msg(self, version="2.5"):
        return Message("QRY_Q01", version=version)

    def test_explicit_receiving_app_and_facility_win_over_default(self):
        msg = self._msg()
        args = _args(receiving_app="TARGET_EMR", receiving_facility="REMOTE_HOSPITAL")
        populate_msh(
            msg,
            args,
            version="2.5",
            msg_type="QRY^Q01",
            control_prefix="QRY",
            receiving_app="LAB",
            receiving_facility="MAIN_LAB",
        )
        self.assertEqual(msg.msh.msh_5.to_er7(), "TARGET_EMR")
        self.assertEqual(msg.msh.msh_6.to_er7(), "REMOTE_HOSPITAL")

    def test_empty_receiving_args_fall_back_to_contextual_default(self):
        """When the operator supplies nothing (argparse default ""), the
        mixin's contextual literal (e.g. 'PHARMACY', 'LAB') must still
        apply — this must not regress to a hardcoded value ignoring both."""
        msg = self._msg()
        args = _args(receiving_app="", receiving_facility="")
        populate_msh(
            msg,
            args,
            version="2.5",
            msg_type="QRY^Q01",
            control_prefix="QRY",
            receiving_app="LAB",
            receiving_facility="MAIN_LAB",
        )
        self.assertEqual(msg.msh.msh_5.to_er7(), "LAB")
        self.assertEqual(msg.msh.msh_6.to_er7(), "MAIN_LAB")

    def test_missing_receiving_attrs_fall_back_to_contextual_default(self):
        """args objects without receiving_app/receiving_facility at all
        (e.g. Mock() in unrelated tests) must not raise and must keep the
        contextual default."""
        msg = self._msg()
        args = types.SimpleNamespace(sending_app="OIDA", sending_facility="SECURITY")
        populate_msh(
            msg,
            args,
            version="2.5",
            msg_type="QRY^Q01",
            control_prefix="QRY",
            receiving_app="LAB",
            receiving_facility="MAIN_LAB",
        )
        self.assertEqual(msg.msh.msh_5.to_er7(), "LAB")
        self.assertEqual(msg.msh.msh_6.to_er7(), "MAIN_LAB")


# ---------------------------------------------------------------------------
# BUG 3 — enhanced-mode "CA" acks must be treated as acceptance
# ---------------------------------------------------------------------------


class TestAckAcceptedHelper(unittest.TestCase):
    def test_aa_and_ca_are_accepted(self):
        self.assertTrue(ack_accepted("AA"))
        self.assertTrue(ack_accepted("CA"))

    def test_ar_ae_and_none_are_not_accepted(self):
        self.assertFalse(ack_accepted("AR"))
        self.assertFalse(ack_accepted("AE"))
        self.assertFalse(ack_accepted(None))
        self.assertFalse(ack_accepted(""))


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestEnhancedModeAckTreatedAsAccept(unittest.TestCase):
    """Representative sites: financial.py (BAR^P01) and master_file.py
    (MFN^M02), both previously compared `ack == "AA"` only."""

    def _ack(self, code: str) -> bytes:
        body = f"MSH|^~\\&|BILL|HOSP|OIDA|SEC|20240101||ACK|1|P|2.5\rMSA|{code}|1"
        return _mllp(body)

    def test_bar_finding_emitted_on_ca_commit_accept(self):
        s = _scanner(_args(confirm=True))
        s.conn = _ReplayConn(self._ack("CA"))
        s._send_bar_message()
        issues = [f["issue"] for f in s.results["data"].get("security_findings", [])]
        self.assertIn("Billing Account Creation Accepted", issues)

    def test_mfn_finding_emitted_on_ca_commit_accept(self):
        s = _scanner(_args(confirm=True, mfn_type="M01"))
        s.conn = _ReplayConn(self._ack("CA"))
        s._send_mfn_message()
        issues = [f["issue"] for f in s.results["data"].get("security_findings", [])]
        self.assertIn("Master File Modification Accepted (General Master File)", issues)


# ---------------------------------------------------------------------------
# BUG 4 — --department flag flows into STF-11
# ---------------------------------------------------------------------------


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestMfnDepartmentFlag(unittest.TestCase):
    def test_department_flag_registered_in_proto_args(self):
        """--department must exist in proto_args.py (added as the fix) so
        that argparse actually populates args.department for real CLI runs."""
        from argparse import ArgumentParser

        from oida.protocols.hl7.proto_args import proto_args

        parent_parser = ArgumentParser(add_help=False)
        main_parser = ArgumentParser()
        subparsers = main_parser.add_subparsers(dest="protocol")
        proto_args(subparsers, [parent_parser])
        ns = main_parser.parse_args(
            ["hl7", "--department", "CARDIOLOGY", "--mfn-type", "M02", "target"]
        )
        self.assertEqual(ns.department, "CARDIOLOGY")

    def test_department_reaches_stf11_segment(self):
        s = _scanner(_args(confirm=True, mfn_type="M02", staff_id="STF9", department="ONCOLOGY"))
        er7 = s._create_mfn_message("M02")
        self.assertIsNotNone(er7)
        stf_line = next(line for line in er7.splitlines() if line.startswith("STF|"))
        fields = stf_line.split("|")
        # STF-11 is index 11 (STF is index 0).
        self.assertEqual(fields[11], "ONCOLOGY")

    def test_department_defaults_to_empty_when_not_supplied(self):
        s = _scanner(_args(confirm=True, mfn_type="M02", staff_id="STF9"))
        er7 = s._create_mfn_message("M02")
        self.assertIsNotNone(er7)
        stf_line = next(line for line in er7.splitlines() if line.startswith("STF|"))
        fields = stf_line.split("|")
        self.assertEqual(fields[11] if len(fields) > 11 else "", "")


if __name__ == "__main__":
    unittest.main()


class TestPrintHostInfoEnhancedAck(unittest.TestCase):
    """BUG 5 (display): print_host_info only knew the original-mode "Ax"
    acknowledgement codes, so an enhanced-mode MSA|CA (Commit Accept) fell
    through to the generic ``logger.display`` branch and was rendered
    identically to an unparsable value -- an operator could not tell a
    successful commit ack from garbage. HL7 table 0008 defines CA/CE/CR
    alongside AA/AE/AR.
    """

    def _render(self, ack_code):
        scanner = _make_hl7_instance()
        scanner.results["data"]["ack_code"] = ack_code
        scanner.print_host_info()
        return scanner.logger

    def test_commit_accept_reported_as_success(self):
        logger = self._render("CA")
        logger.success.assert_called()
        joined = " ".join(str(c.args) for c in logger.success.call_args_list)
        self.assertIn("CA", joined)
        self.assertIn("Commit Accept", joined)

    def test_commit_reject_reported_as_failure(self):
        logger = self._render("CR")
        logger.fail.assert_called()
        self.assertIn(
            "Commit Reject",
            " ".join(str(c.args) for c in logger.fail.call_args_list),
        )

    def test_commit_error_reported_as_warning(self):
        logger = self._render("CE")
        logger.warning.assert_called()
        self.assertIn(
            "Commit Error",
            " ".join(str(c.args) for c in logger.warning.call_args_list),
        )

    def test_original_mode_codes_still_routed(self):
        self._render("AA").success.assert_called()
        self._render("AR").fail.assert_called()
        self._render("AE").warning.assert_called()

    def test_unknown_code_still_falls_through_to_display(self):
        logger = self._render("ZZ")
        logger.success.assert_not_called()
        logger.fail.assert_not_called()
        self.assertIn(
            "ZZ",
            " ".join(str(c.args) for c in logger.display.call_args_list),
        )
