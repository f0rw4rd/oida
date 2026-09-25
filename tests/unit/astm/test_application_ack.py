"""
Regression tests for the ASTM "link-level ACK != application acceptance" fix.

A frame-level ACK (the single ACK byte _send_frame waits on) only confirms
data-link receipt + checksum per ASTM E1381 - it says nothing about whether
the LIS application accepted/persisted the record. These tests verify that the
HIGH/CRITICAL injection/PHI findings are only raised when the LIS returns an
application-level acknowledgement; otherwise the finding is downgraded to LOW
and reworded to "link level (application acceptance unverified)".
"""

from argparse import Namespace
from unittest.mock import MagicMock

from oida.protocols.astm.mixins import FramingMixin, RecordsMixin, EnumerationMixin
from oida.protocols.astm.records import ASTMRecordBuilder, ACK, ENQ, STX, ETX, CR, LF


class _Scanner(FramingMixin, RecordsMixin, EnumerationMixin):
    """Minimal composition exercising the real framing + record/enum logic."""


class _ScriptedConn:
    """Mock socket whose recv() returns bytes from a scripted queue.

    _send_enq / _send_frame each do recv(1) expecting an ACK. After EOT,
    _read_application_ack does recv(1) (expects ENQ) then recv(1024).
    Anything not explicitly scripted defaults to ACK so framing succeeds.
    """

    def __init__(self, app_reply: bytes | None):
        # Always ACK every ENQ/frame so the link-level path succeeds.
        # app_reply controls what _read_application_ack sees on its first recv:
        #   None  -> raise TimeoutError (no server transmission)
        #   bytes -> ENQ then a record frame (application reply)
        self._app_reply = app_reply
        self._after_eot = False
        self.sent: list[bytes] = []

    def settimeout(self, t):
        pass

    def gettimeout(self):
        return 10

    def sendall(self, data):
        self.sent.append(data)
        from oida.protocols.astm.records import EOT

        if data == EOT:
            self._after_eot = True

    def recv(self, bufsize, flags=0):
        if not self._after_eot:
            # Link-level handshake: ACK everything.
            return ACK
        # Application-ack probe after EOT.
        if self._app_reply is None:
            raise TimeoutError("no application response")
        if bufsize == 1:
            # First probe recv expects ENQ.
            return ENQ
        # Second recv: the server's data frame.
        return self._app_reply


def _make_scanner(conn):
    s = _Scanner()
    s.conn = conn
    s.logger = MagicMock()
    s.frame_number = 1
    s.record_builder = ASTMRecordBuilder(version="E1394")
    s.results = {"data": {}}
    s.args = Namespace(
        sender_name="OIDA",
        patient_id="",
        patient_name="",
        order_id="",
        test_id="",
        sample_id="",
        priority="R",
        action_code="N",
        cancel_order=False,
        result_status="F",
        correct_result=False,
        delete_result=False,
        result_units="",
        reference_range="",
        abnormal_flag="",
        result_value="",
    )
    return s


def _findings(scanner):
    return scanner.results["data"].get("security_findings", [])


def _record_frame(text: str) -> bytes:
    """A plausible server data frame (STX + record + CR + ETX + checksum + CR LF).

    Computes a real modulo-256 checksum over frame_num + text + CR + ETX so this
    fixture reflects a well-formed ASTM E1381 frame instead of a bogus "00".
    """
    checksum_data = b"1" + text.encode() + CR + ETX
    checksum = f"{sum(checksum_data) % 256:02X}".encode()
    return STX + checksum_data + checksum + CR + LF


# --- Patient -----------------------------------------------------------------


def test_patient_link_level_only_is_low_not_high():
    """Frame ACK but no application reply -> LOW, not HIGH injection finding."""
    scanner = _make_scanner(_ScriptedConn(app_reply=None))
    scanner._send_patient_record()

    findings = _findings(scanner)
    assert len(findings) == 1
    f = findings[0]
    assert "Patient Injection Possible" != f["issue"]
    assert "application acceptance unverified" in f["description"]
    assert scanner.results["data"]["patient_app_accepted"] is False


def test_patient_application_reply_is_high():
    """Frame ACK + application reply -> HIGH 'Patient Injection Possible'."""
    scanner = _make_scanner(_ScriptedConn(app_reply=_record_frame("C|1|Accepted")))
    scanner._send_patient_record()

    findings = _findings(scanner)
    assert len(findings) == 1
    f = findings[0]
    assert f["issue"] == "Patient Injection Possible"
    assert scanner.results["data"]["patient_app_accepted"] is True


# --- Order -------------------------------------------------------------------


def test_order_link_level_only_is_low_not_critical():
    scanner = _make_scanner(_ScriptedConn(app_reply=None))
    scanner._send_order_record()

    findings = _findings(scanner)
    assert len(findings) == 1
    assert "application acceptance unverified" in findings[0]["description"]


def test_order_application_reply_is_critical():
    scanner = _make_scanner(_ScriptedConn(app_reply=_record_frame("C|1|Order accepted")))
    scanner._send_order_record()

    findings = _findings(scanner)
    assert len(findings) == 1
    assert findings[0]["issue"] == "Order Injection Possible"


# --- Result ------------------------------------------------------------------


def test_result_link_level_only_is_low_not_critical():
    scanner = _make_scanner(_ScriptedConn(app_reply=None))
    scanner._send_result_record()

    findings = _findings(scanner)
    assert len(findings) == 1
    assert "application acceptance unverified" in findings[0]["description"]


def test_result_application_reply_is_critical():
    scanner = _make_scanner(_ScriptedConn(app_reply=_record_frame("C|1|Result accepted")))
    scanner._send_result_record()

    findings = _findings(scanner)
    assert len(findings) == 1
    assert findings[0]["issue"] == "Result Injection Possible"


# --- Patient enumeration (PHI) -----------------------------------------------


def test_patient_enum_link_level_only_is_low_not_high():
    scanner = _make_scanner(_ScriptedConn(app_reply=None))
    scanner._enum_patients()

    findings = _findings(scanner)
    assert len(findings) == 1
    assert findings[0]["issue"] != "Patient Data Exposure"
    assert "application acceptance unverified" in findings[0]["description"]


def test_patient_enum_application_reply_is_high():
    scanner = _make_scanner(_ScriptedConn(app_reply=_record_frame("P|1|PID^Doe^John")))
    scanner._enum_patients()

    findings = _findings(scanner)
    assert len(findings) == 1
    assert findings[0]["issue"] == "Patient Data Exposure"
