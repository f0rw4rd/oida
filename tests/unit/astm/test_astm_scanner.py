"""
Unit tests for ASTM/LIS Scanner class (__init__.py)

Tests all scanner methods with mocked socket connections to achieve
coverage of the NXC-style scanner class. Existing tests in test_scanner.py
cover records.py, constants, and proto_args; these tests cover the scanner
methods that had 5% coverage.

Categories:
- Connection: create_conn_obj, _disconnect
- Framing: _send_enq, _send_eot, _send_frame, _calculate_checksum
- Extraction: _extract_analyzer_info, _identify_server, _receive_server_response
- Operations: _send_query_record, _send_patient_record, _send_order_record, _send_result_record
- Enumeration: _enum_tests, _enum_instruments, _enum_patients
- Probing: _probe_operations, _test_*_record
- Security: _analyze_security, _fuzz_records
- Export: _export_results
- Workflow: proto_flow, enum_host_info, print_host_info
"""

import json
import os
import socket
import tempfile
from argparse import Namespace
from unittest.mock import MagicMock, patch


from oida.protocols.astm.records import (
    ACK,
    CR,
    ENQ,
    EOT,
    ETX,
    LF,
    NAK,
    STX,
    ASTMRecordBuilder,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_args(**overrides):
    """Build a minimal Namespace for the ASTM scanner."""
    defaults = dict(
        port=1394,
        timeout=5,
        tls=False,
        tls_cert=None,
        tls_key=None,
        sender_name="OIDA",
        sender_id="",
        receiver_name="",
        receiver_id="",
        astm_version="E1394",
        probe_ops=False,
        send_query=False,
        send_patient=False,
        send_order=False,
        send_result=False,
        fuzz=False,
        fuzz_iterations=10,
        fuzz_record=None,
        fuzz_frame=False,
        enum_tests=False,
        enum_instruments=False,
        enum_patients=False,
        confirm=False,
        output=None,
        format="json",
        verbose=0,
        debug=False,
        patient_id="",
        patient_name="",
        sample_id="",
        order_id="",
        test_id="",
        result_value="",
        result_units="",
        reference_range="",
        abnormal_flag="",
        action_code="N",
        result_status="F",
        priority="R",
        cancel_order=False,
        correct_result=False,
        delete_result=False,
    )
    defaults.update(overrides)
    return Namespace(**defaults)


def _make_mock_socket(recv_values=None):
    """Create a mock socket with configurable recv responses."""
    sock = MagicMock(spec=socket.socket)
    if recv_values is not None:
        sock.recv.side_effect = list(recv_values)
    else:
        sock.recv.return_value = ACK
    return sock


class _AppAcceptingSocket:
    """Socket stub that ACKs every link-level frame, then returns a server
    application-level reply after EOT.

    Record/enum operations only raise their HIGH/CRITICAL findings when the LIS
    returns an application-level acknowledgement (server-initiated ENQ followed
    by an STX-framed record) - a bare frame ACK is link-level only. This stub
    ACKs the ENQ/header/record/terminator frames, then, once EOT has been sent,
    answers _read_application_ack's probe with ENQ + an STX record so the
    "accepted" path under test is exercised. See test_application_ack.py for the
    link-level-only (no reply) counterpart.
    """

    def __init__(self, app_reply=None):
        self._app_reply = (
            app_reply
            if app_reply is not None
            else (STX + b"1C|1|Accepted" + CR + ETX + b"C6" + CR + LF)
        )
        self._after_eot = False
        self.sent = []

    def settimeout(self, _t):
        pass

    def gettimeout(self):
        return 5

    def sendall(self, data):
        self.sent.append(data)
        if data == EOT:
            self._after_eot = True

    def recv(self, bufsize, flags=0):
        if not self._after_eot:
            return ACK
        if bufsize == 1:
            return ENQ
        return self._app_reply

    def close(self):
        pass


def _instantiate_scanner(args, mock_sock=None):
    """Instantiate the ASTM scanner with proto_flow patched out, then set conn."""
    with patch("oida.protocols.astm.proto_flow", create=True):
        with patch.object(
            __import__("oida.protocols.astm", fromlist=["astm"]).astm,
            "proto_flow",
        ):
            from oida.protocols.astm import astm as ASTMClass

            # Patch proto_flow so __init__ doesn't trigger it
            with patch.object(ASTMClass, "proto_flow"):
                scanner = ASTMClass(args, None, "127.0.0.1")

    # Manually set up the record builder and connection
    scanner.record_builder = ASTMRecordBuilder(version="E1394")
    if mock_sock is not None:
        scanner.conn = mock_sock
    return scanner


# ---------------------------------------------------------------------------
# Connection Tests
# ---------------------------------------------------------------------------


class TestCreateConnObj:
    """Test create_conn_obj()"""

    def test_successful_connection(self):
        args = _make_args()
        scanner = _instantiate_scanner(args)

        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            result = scanner.create_conn_obj()

        assert result is True
        assert scanner.conn is mock_sock
        assert scanner.results["data"]["connected"] is True
        mock_sock.connect.assert_called_once_with(("127.0.0.1", 1394))

    def test_connection_refused(self):
        args = _make_args()
        scanner = _instantiate_scanner(args)

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        with patch("socket.socket", return_value=mock_sock):
            result = scanner.create_conn_obj()

        assert result is False
        assert scanner.results["data"]["connected"] is False

    def test_connection_timeout(self):
        args = _make_args()
        scanner = _instantiate_scanner(args)

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout()
        with patch("socket.socket", return_value=mock_sock):
            result = scanner.create_conn_obj()

        assert result is False

    def test_connection_generic_error(self):
        args = _make_args()
        scanner = _instantiate_scanner(args)

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Network unreachable")
        with patch("socket.socket", return_value=mock_sock):
            result = scanner.create_conn_obj()

        assert result is False

    def test_custom_port(self):
        args = _make_args(port=1395)
        scanner = _instantiate_scanner(args)

        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            scanner.create_conn_obj()

        mock_sock.connect.assert_called_once_with(("127.0.0.1", 1395))


class TestDisconnect:
    """Test _disconnect()"""

    def test_disconnect_closes_socket(self):
        scanner = _instantiate_scanner(_make_args())
        mock_sock = MagicMock()
        scanner.conn = mock_sock

        scanner._disconnect()

        mock_sock.close.assert_called_once()
        assert scanner.conn is None

    def test_disconnect_handles_error(self):
        scanner = _instantiate_scanner(_make_args())
        mock_sock = MagicMock()
        mock_sock.close.side_effect = OSError("already closed")
        scanner.conn = mock_sock

        scanner._disconnect()  # Should not raise
        assert scanner.conn is None

    def test_disconnect_no_conn(self):
        scanner = _instantiate_scanner(_make_args())
        scanner.conn = None
        scanner.logger = MagicMock()

        scanner._disconnect()

        assert scanner.conn is None
        scanner.logger.debug.assert_not_called()  # Should not raise


# ---------------------------------------------------------------------------
# Framing Tests
# ---------------------------------------------------------------------------


class TestCalculateChecksum:
    """Test _calculate_checksum()"""

    def test_basic_checksum(self):
        scanner = _instantiate_scanner(_make_args())
        result = scanner._calculate_checksum(b"1H|\\^&")
        assert len(result) == 2
        assert result.decode().isalnum()

    def test_checksum_modulus_256(self):
        scanner = _instantiate_scanner(_make_args())
        data = bytes([255, 255, 255])  # 765 % 256 = 253 = 0xFD
        assert scanner._calculate_checksum(data) == b"FD"

    def test_checksum_zero(self):
        scanner = _instantiate_scanner(_make_args())
        data = bytes([0])
        assert scanner._calculate_checksum(data) == b"00"

    def test_checksum_exactly_256(self):
        scanner = _instantiate_scanner(_make_args())
        data = bytes([128, 128])  # 256 % 256 = 0
        assert scanner._calculate_checksum(data) == b"00"


class TestSendEnq:
    """Test _send_enq()"""

    def test_enq_ack(self):
        mock_sock = _make_mock_socket([ACK])
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        assert scanner._send_enq() is True
        mock_sock.sendall.assert_called_once_with(ENQ)

    def test_enq_nak(self):
        mock_sock = _make_mock_socket([NAK])
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        assert scanner._send_enq() is False

    def test_enq_unexpected_response(self):
        mock_sock = _make_mock_socket([b"\x00"])
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        assert scanner._send_enq() is False

    def test_enq_timeout(self):
        mock_sock = MagicMock()
        mock_sock.sendall.return_value = None
        mock_sock.recv.side_effect = socket.timeout()
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        assert scanner._send_enq() is False

    def test_enq_no_connection(self):
        scanner = _instantiate_scanner(_make_args())
        scanner.conn = None

        assert scanner._send_enq() is False

    def test_enq_send_error(self):
        mock_sock = MagicMock()
        mock_sock.sendall.side_effect = BrokenPipeError()
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        assert scanner._send_enq() is False


class TestSendEot:
    """Test _send_eot()"""

    def test_eot_success(self):
        mock_sock = MagicMock()
        scanner = _instantiate_scanner(_make_args(), mock_sock)
        scanner.frame_number = 5

        assert scanner._send_eot() is True
        mock_sock.sendall.assert_called_once_with(EOT)
        assert scanner.frame_number == 1  # Reset

    def test_eot_no_connection(self):
        scanner = _instantiate_scanner(_make_args())
        scanner.conn = None

        assert scanner._send_eot() is False

    def test_eot_error(self):
        mock_sock = MagicMock()
        mock_sock.sendall.side_effect = BrokenPipeError()
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        assert scanner._send_eot() is False


class TestSendFrame:
    """Test _send_frame()"""

    def test_frame_accepted(self):
        mock_sock = _make_mock_socket([ACK])
        scanner = _instantiate_scanner(_make_args(), mock_sock)
        scanner.frame_number = 1

        result = scanner._send_frame("H|\\^&|||OIDA")

        assert result is True
        assert scanner.frame_number == 2

        # Verify frame structure
        sent_data = mock_sock.sendall.call_args[0][0]
        assert sent_data.startswith(STX)
        assert sent_data.endswith(CR + LF)
        assert ETX in sent_data
        # ASTM E1394 record text is CR-terminated; that CR must land inside
        # the checksummed span, immediately before the frame's ETX.
        etx_idx = sent_data.index(ETX)
        assert sent_data[etx_idx - 1 : etx_idx] == CR

    def test_frame_rejected(self):
        mock_sock = _make_mock_socket([NAK])
        scanner = _instantiate_scanner(_make_args(), mock_sock)
        scanner.frame_number = 1

        result = scanner._send_frame("H|\\^&|||OIDA")

        assert result is False
        assert scanner.frame_number == 1  # Not incremented

    def test_frame_timeout(self):
        mock_sock = MagicMock()
        mock_sock.sendall.return_value = None
        mock_sock.recv.side_effect = socket.timeout()
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        assert scanner._send_frame("data") is False

    def test_frame_no_connection(self):
        scanner = _instantiate_scanner(_make_args())
        scanner.conn = None

        assert scanner._send_frame("data") is False

    def test_frame_number_wraps(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        scanner = _instantiate_scanner(_make_args(), mock_sock)
        scanner.frame_number = 8

        result = scanner._send_frame("data")

        sent_data = mock_sock.sendall.call_args[0][0]
        # Frame number 8 % 8 = 0
        assert sent_data[1:2] == b"0"
        assert result is True
        # _send_frame advances frame_number by one fragment sent (real
        # counter state, not the wrapped on-wire digit checked above).
        assert scanner.frame_number == 9


# ---------------------------------------------------------------------------
# Extraction Tests
# ---------------------------------------------------------------------------


class TestExtractAnalyzerInfo:
    """Test _extract_analyzer_info()"""

    def test_extract_from_header(self):
        scanner = _instantiate_scanner(_make_args())

        data = b"\x021H|\\^&|||COBAS_8000^Roche^8.1.2||||||||||E1394\x0300\x0d\x0a"
        scanner._extract_analyzer_info(data)

        info = scanner.results["data"].get("analyzer_info")
        assert info is not None
        assert info["name"] == "COBAS_8000"
        assert info["vendor"] == "Roche"
        assert info["version"] == "8.1.2"
        assert scanner.detected_analyzer == "COBAS_8000"

    def test_extract_vendor_lookup(self):
        scanner = _instantiate_scanner(_make_args())

        # Sender name without explicit vendor -> vendor lookup
        data = b"H|\\^&|||SYSMEX_XN||||||||\x03"
        scanner._extract_analyzer_info(data)

        info = scanner.results["data"].get("analyzer_info")
        assert info is not None
        assert info["name"] == "SYSMEX_XN"
        assert info["vendor"] == "Sysmex"

    def test_extract_no_header(self):
        scanner = _instantiate_scanner(_make_args())

        data = b"R|1|GLU|100|mg/dL\x03"
        scanner._extract_analyzer_info(data)

        assert "analyzer_info" not in scanner.results["data"]

    def test_extract_empty_sender(self):
        scanner = _instantiate_scanner(_make_args())

        # Header with empty field 5
        data = b"H|\\^&|||\x03"
        scanner._extract_analyzer_info(data)

        # analyzer_info should be empty dict, not stored
        assert "analyzer_info" not in scanner.results["data"]

    def test_extract_version_from_field14(self):
        scanner = _instantiate_scanner(_make_args())

        # Header with version in field 13 (index 12) - per LIS02-A2, H-13 is
        # the Processing ID / Version Number field; H-14 (index 13) is the
        # date/time of message, not a version.
        fields = [
            "H",
            "\\^&",
            "",
            "",
            "TestAnalyzer",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "E1394-2.5.1",
        ]
        data = ("|".join(fields) + "\x03").encode()
        scanner._extract_analyzer_info(data)

        info = scanner.results["data"].get("analyzer_info")
        assert info is not None
        assert info["version"] == "2.5.1"

    def test_extract_analyzer_type_field12(self):
        scanner = _instantiate_scanner(_make_args())

        # H-12 (index 11) is the Processing ID field per LIS02-A2, not an
        # analyzer "type" - the code stores it as processing_id and does not
        # set a "type" key.
        fields = ["H", "\\^&", "", "", "MyAnalyzer", "", "", "", "", "", "", "Chemistry", "", ""]
        data = ("|".join(fields) + "\x03").encode()
        scanner._extract_analyzer_info(data)

        info = scanner.results["data"].get("analyzer_info")
        assert info is not None
        assert info["processing_id"] == "Chemistry"

    def test_extract_handles_malformed_data(self):
        scanner = _instantiate_scanner(_make_args())

        # Should not raise
        scanner._extract_analyzer_info(b"\xff\xfe\xfd")
        assert "analyzer_info" not in scanner.results["data"]


class TestReceiveServerResponse:
    """Test _receive_server_response()"""

    def test_receive_eot(self):
        scanner = _instantiate_scanner(_make_args())
        mock_sock = MagicMock()
        mock_sock.settimeout.return_value = None
        mock_sock.recv.return_value = EOT
        scanner.conn = mock_sock

        scanner._receive_server_response()

        # No frame was ever parsed, so nothing gets ACKed/NAKed and no
        # analyzer info is recorded.
        mock_sock.sendall.assert_not_called()
        assert "analyzer_info" not in scanner.results["data"]

    def test_receive_frame_then_eot(self):
        scanner = _instantiate_scanner(_make_args())
        mock_sock = MagicMock()
        mock_sock.settimeout.return_value = None
        # First recv returns a frame with STX, second returns EOT. Checksum
        # E1 is the correct modulo-256 checksum over "1H|\^&|||TestLIS" + CR + ETX.
        frame = STX + b"1H|\\^&|||TestLIS" + CR + ETX + b"E1" + CR + LF
        mock_sock.recv.side_effect = [frame, EOT]
        scanner.conn = mock_sock

        scanner._receive_server_response()
        # Should have sent ACK for the frame
        mock_sock.sendall.assert_called_with(ACK)

    def test_receive_timeout(self):
        scanner = _instantiate_scanner(_make_args())
        mock_sock = MagicMock()
        mock_sock.settimeout.return_value = None
        mock_sock.recv.side_effect = socket.timeout()
        scanner.conn = mock_sock

        scanner._receive_server_response()

        # Timed out before any frame arrived: no ACK/NAK, no analyzer info.
        mock_sock.sendall.assert_not_called()
        assert "analyzer_info" not in scanner.results["data"]

    def test_receive_empty_data(self):
        scanner = _instantiate_scanner(_make_args())
        mock_sock = MagicMock()
        mock_sock.settimeout.return_value = None
        mock_sock.recv.return_value = b""
        scanner.conn = mock_sock

        scanner._receive_server_response()

        # Empty recv() means the peer closed the connection: read loop
        # bails out with no frame parsed, no ACK/NAK, no analyzer info.
        mock_sock.sendall.assert_not_called()
        assert "analyzer_info" not in scanner.results["data"]


# ---------------------------------------------------------------------------
# Record Operation Tests
# ---------------------------------------------------------------------------


class TestSendQueryRecord:
    """Test _send_query_record()"""

    def test_query_accepted(self):
        mock_sock = _AppAcceptingSocket()
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        scanner._send_query_record()

        assert scanner.results["data"].get("query_accepted") is True
        findings = scanner.results["data"].get("security_findings", [])
        assert any(f["issue"] == "Query Access Available" for f in findings)

    def test_query_enq_fails(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = NAK
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        scanner._send_query_record()

        assert "query_accepted" not in scanner.results["data"]


class TestSendPatientRecord:
    """Test _send_patient_record()"""

    def test_patient_accepted(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        scanner._send_patient_record()

        assert scanner.results["data"].get("patient_accepted") is True

    def test_patient_header_rejected(self):
        mock_sock = MagicMock()
        # First recv (ENQ->ACK), second recv (header->NAK)
        mock_sock.recv.side_effect = [ACK, NAK]
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        scanner._send_patient_record()

        assert "patient_accepted" not in scanner.results["data"]


class TestSendOrderRecord:
    """Test _send_order_record()"""

    def test_order_new_accepted(self):
        mock_sock = _AppAcceptingSocket()
        scanner = _instantiate_scanner(_make_args(action_code="N"), mock_sock)

        scanner._send_order_record()

        assert scanner.results["data"].get("order_accepted") is True
        findings = scanner.results["data"].get("security_findings", [])
        assert any("Order Injection" in f.get("issue", "") for f in findings)

    def test_order_cancel_accepted(self):
        mock_sock = _AppAcceptingSocket()
        scanner = _instantiate_scanner(_make_args(cancel_order=True), mock_sock)

        scanner._send_order_record()

        assert scanner.results["data"]["order_action"] == "C"
        findings = scanner.results["data"].get("security_findings", [])
        assert any("Order Cancellation" in f.get("issue", "") for f in findings)

    def test_order_delete_accepted(self):
        mock_sock = _AppAcceptingSocket()
        scanner = _instantiate_scanner(_make_args(action_code="X"), mock_sock)

        scanner._send_order_record()

        findings = scanner.results["data"].get("security_findings", [])
        assert any("Order Deletion" in f.get("issue", "") for f in findings)


class TestSendResultRecord:
    """Test _send_result_record()"""

    def test_result_final_accepted(self):
        mock_sock = _AppAcceptingSocket()
        scanner = _instantiate_scanner(_make_args(result_status="F"), mock_sock)

        scanner._send_result_record()

        assert scanner.results["data"].get("result_accepted") is True
        findings = scanner.results["data"].get("security_findings", [])
        assert any("Result Injection" in f.get("issue", "") for f in findings)

    def test_result_corrected(self):
        mock_sock = _AppAcceptingSocket()
        scanner = _instantiate_scanner(_make_args(correct_result=True), mock_sock)

        scanner._send_result_record()

        findings = scanner.results["data"].get("security_findings", [])
        assert any("Result Correction" in f.get("issue", "") for f in findings)

    def test_result_deleted(self):
        mock_sock = _AppAcceptingSocket()
        scanner = _instantiate_scanner(_make_args(delete_result=True), mock_sock)

        scanner._send_result_record()

        findings = scanner.results["data"].get("security_findings", [])
        assert any("Result Deletion" in f.get("issue", "") for f in findings)


# ---------------------------------------------------------------------------
# Enumeration Tests
# ---------------------------------------------------------------------------


class TestEnumTests:
    """Test _enum_tests()"""

    def test_enum_tests_accepted(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        scanner._enum_tests()

        assert scanner.results["data"].get("tests_enumerated") is True

    def test_enum_tests_enq_fails(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = NAK
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        scanner._enum_tests()

        assert "tests_enumerated" not in scanner.results["data"]


class TestEnumInstruments:
    """Test _enum_instruments()"""

    def test_enum_instruments(self):
        scanner = _instantiate_scanner(_make_args())

        scanner._enum_instruments()

        assert scanner.results["data"].get("instruments_enumerated") is True


class TestEnumPatients:
    """Test _enum_patients()"""

    def test_enum_patients_accepted(self):
        mock_sock = _AppAcceptingSocket()
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        scanner._enum_patients()

        assert scanner.results["data"].get("patient_enum_accepted") is True
        findings = scanner.results["data"].get("security_findings", [])
        assert any("Patient Data Exposure" in f.get("issue", "") for f in findings)


# ---------------------------------------------------------------------------
# Probing Tests
# ---------------------------------------------------------------------------


class TestProbeOperations:
    """Test _probe_operations() and _test_*_record()"""

    def test_probe_all_accepted(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        scanner = _instantiate_scanner(_make_args(confirm=True), mock_sock)

        scanner._probe_operations()

        probe = scanner.results["data"].get("probe_results")
        assert probe is not None
        assert len(probe["supported"]) == 6  # H, Q, C + P, O, R (with --confirm)
        assert len(probe["rejected"]) == 0

    def test_probe_without_confirm_skips_write_records(self):
        """Without --confirm only the read-only H/Q/C records are probed;
        the write-capable P/O/R records are never transmitted to the LIS."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        scanner = _instantiate_scanner(_make_args(confirm=False), mock_sock)

        scanner._probe_operations()

        probe = scanner.results["data"]["probe_results"]
        probed = {rt for rt, _ in probe["supported"] + probe["rejected"] + probe["timeout"]}
        assert probed == {"H", "Q", "C"}
        assert not probed & {"P", "O", "R"}

    def test_probe_all_rejected(self):
        mock_sock = MagicMock()

        # ENQ -> ACK, any data frame -> NAK (every retry attempt, for every
        # record type). Keyed off the last sendall() payload rather than a
        # fixed-length list, since a NAKed frame is now retried per ASTM
        # E1381 before being reported as rejected.
        def _recv_side_effect(*_args, **_kwargs):
            sent = mock_sock.sendall.call_args[0][0]
            return ACK if sent == ENQ else NAK

        mock_sock.recv.side_effect = _recv_side_effect
        scanner = _instantiate_scanner(_make_args(confirm=True), mock_sock)

        scanner._probe_operations()

        probe = scanner.results["data"]["probe_results"]
        # Header accepted (first ACK), but record rejected (NAK)
        # Actually: ENQ=ACK, header=NAK -> rejected for all
        assert len(probe["rejected"]) > 0

    def test_probe_enq_timeout(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout()
        scanner = _instantiate_scanner(_make_args(confirm=True), mock_sock)

        scanner._probe_operations()

        probe = scanner.results["data"]["probe_results"]
        assert len(probe["timeout"]) == 6


class TestTestRecordHelpers:
    """Test individual _test_*_record() methods."""

    def test_test_header_record_accepted(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        assert scanner._test_header_record() == "accepted"

    def test_test_query_record_enq_fail(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = NAK
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        # ENQ gets NAK
        assert scanner._test_query_record() == "timeout"

    def test_test_comment_record_accepted(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        assert scanner._test_comment_record() == "accepted"


# ---------------------------------------------------------------------------
# Security Tests
# ---------------------------------------------------------------------------


class TestAnalyzeSecurity:
    """Test _analyze_security()"""

    def test_no_auth_finding(self):
        scanner = _instantiate_scanner(_make_args())
        scanner._analyze_security()

        findings = scanner.results["data"]["security_findings"]
        assert any(f["issue"] == "No Authentication" for f in findings)

    def test_unencrypted_finding(self):
        scanner = _instantiate_scanner(_make_args(tls=False))
        scanner._analyze_security()

        findings = scanner.results["data"]["security_findings"]
        assert any(f["issue"] == "Unencrypted Communication" for f in findings)

    def test_tls_no_unencrypted_finding(self):
        scanner = _instantiate_scanner(_make_args(tls=True))
        scanner._analyze_security()

        findings = scanner.results["data"]["security_findings"]
        assert not any(f["issue"] == "Unencrypted Communication" for f in findings)

    def test_no_duplicate_findings(self):
        scanner = _instantiate_scanner(_make_args())

        # Call twice
        scanner._analyze_security()
        scanner._analyze_security()

        findings = scanner.results["data"]["security_findings"]
        no_auth_count = sum(1 for f in findings if f["issue"] == "No Authentication")
        assert no_auth_count == 1  # Not duplicated


# ---------------------------------------------------------------------------
# Fuzzing Tests
# ---------------------------------------------------------------------------


class TestFuzzRecords:
    """Test _fuzz_records()"""

    def test_fuzz_record_level(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        scanner = _instantiate_scanner(_make_args(fuzz_iterations=5, fuzz_record="H"), mock_sock)

        scanner._fuzz_records()

        fuzz = scanner.results["data"]["fuzz_results"]
        assert fuzz["tests"] == 5
        assert fuzz["errors"] == 0

    def test_fuzz_frame_level(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        scanner = _instantiate_scanner(_make_args(fuzz_iterations=3, fuzz_frame=True), mock_sock)

        scanner._fuzz_records()

        fuzz = scanner.results["data"]["fuzz_results"]
        # fuzz_iterations is a floor, not a cap: with fuzz_frame=True the full
        # case list (8 frame + 30 record = 38) always runs.
        assert fuzz["tests"] >= 3
        assert fuzz["errors"] == 0

    def test_fuzz_crash_detection(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        mock_sock.sendall.side_effect = BrokenPipeError()
        scanner = _instantiate_scanner(_make_args(fuzz_iterations=2, fuzz_frame=True), mock_sock)

        # Reconnect will also fail, stopping the loop
        with patch.object(scanner, "create_conn_obj", return_value=False):
            scanner._fuzz_records()

        fuzz = scanner.results["data"]["fuzz_results"]
        assert fuzz["crashes"] >= 1

    def test_fuzz_connection_reset(self):
        """Test ConnectionResetError is caught (not just BrokenPipeError)."""
        mock_sock = MagicMock()
        mock_sock.sendall.side_effect = ConnectionResetError()
        scanner = _instantiate_scanner(_make_args(fuzz_iterations=1, fuzz_frame=True), mock_sock)

        with patch.object(scanner, "create_conn_obj", return_value=False):
            scanner._fuzz_records()

        fuzz = scanner.results["data"]["fuzz_results"]
        assert fuzz["crashes"] >= 1


# ---------------------------------------------------------------------------
# Export Tests
# ---------------------------------------------------------------------------


class TestExportResults:
    """Test _export_results()"""

    def test_export_no_output(self):
        scanner = _instantiate_scanner(_make_args(output=None))

        with patch("oida.utils.export_utils.export_json") as mock_export:
            scanner._export_results()

        # No --output was requested, so export must be skipped entirely.
        mock_export.assert_not_called()

    def test_export_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _instantiate_scanner(_make_args(output=tmpdir))
            scanner.results["data"]["test"] = "value"

            scanner._export_results()

            output_path = os.path.join(tmpdir, "astm_results.json")
            assert os.path.exists(output_path)

            with open(output_path) as f:
                data = json.load(f)
            assert data["data"]["test"] == "value"

    def test_export_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "nested", "output")
            scanner = _instantiate_scanner(_make_args(output=output_dir))

            scanner._export_results()

            assert os.path.exists(os.path.join(output_dir, "astm_results.json"))


# ---------------------------------------------------------------------------
# Workflow Tests
# ---------------------------------------------------------------------------


class TestProtoFlow:
    """Test proto_flow() orchestration."""

    def test_proto_flow_basic(self):
        """Test proto_flow with connection success."""
        scanner = _instantiate_scanner(_make_args())

        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK

        with patch.object(scanner, "create_conn_obj", return_value=True):
            scanner.conn = mock_sock
            scanner.proto_flow()

        # enum_host_info() ran the ENQ/ACK + header exchange to completion,
        # and _disconnect() at the end of the flow cleared the connection.
        assert scanner.results["data"]["header_accepted"] is True
        assert scanner.results.get("success") is not False
        assert scanner.conn is None

    def test_proto_flow_connection_fails(self):
        """Test proto_flow returns early on connection failure."""
        scanner = _instantiate_scanner(_make_args())

        def _fail():
            # The real create_conn_obj stamps the contract on failure (GH
            # issue #59); reproduce that so proto_flow's early-return branch
            # is tested as it runs in production.
            scanner.record_connect_failure("refused")
            return False

        with patch.object(scanner, "create_conn_obj", side_effect=_fail):
            scanner.proto_flow()

        # Bails out before any data is populated and marks the scan failed.
        assert scanner.results["success"] is False
        assert scanner.results["data"] == {}

    def test_proto_flow_probe_ops(self):
        """Test proto_flow with --probe-ops."""
        scanner = _instantiate_scanner(_make_args(probe_ops=True))

        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK

        with patch.object(scanner, "create_conn_obj", return_value=True):
            scanner.conn = mock_sock
            scanner.proto_flow()

        assert "probe_results" in scanner.results["data"]

    def test_proto_flow_send_query(self):
        """Test proto_flow with --send-query."""
        scanner = _instantiate_scanner(_make_args(send_query=True))

        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        mock_sock.settimeout.return_value = None

        with patch.object(scanner, "create_conn_obj", return_value=True):
            scanner.conn = mock_sock
            scanner.proto_flow()

        # Frame-level ACK accepted the query, but the peer never opened its
        # own transmission afterwards, so there's no application-level reply.
        assert scanner.results["data"]["query_accepted"] is True
        assert scanner.results["data"]["query_app_accepted"] is False

    def test_proto_flow_fuzz_no_confirm(self):
        """Test fuzzing without --confirm is rejected."""
        scanner = _instantiate_scanner(_make_args(fuzz=True, confirm=False))

        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        mock_sock.settimeout.return_value = None

        with patch.object(scanner, "create_conn_obj", return_value=True):
            scanner.conn = mock_sock
            scanner.proto_flow()

        # Fuzz should not have run
        assert "fuzz_results" not in scanner.results["data"]

    def test_proto_flow_order_no_confirm(self):
        """Test order without --confirm is rejected."""
        scanner = _instantiate_scanner(_make_args(send_order=True, confirm=False))

        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        mock_sock.settimeout.return_value = None

        with patch.object(scanner, "create_conn_obj", return_value=True):
            scanner.conn = mock_sock
            scanner.proto_flow()

        assert "order_accepted" not in scanner.results["data"]


class TestEnumHostInfo:
    """Test enum_host_info()"""

    def test_enum_host_info_success(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = ACK
        mock_sock.settimeout.return_value = None
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        scanner.enum_host_info()

        assert scanner.results["data"].get("header_accepted") is True

    def test_enum_host_info_enq_fails(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = NAK
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        scanner.enum_host_info()

        assert "header_accepted" not in scanner.results["data"]


class TestPrintHostInfo:
    """Test print_host_info()"""

    def test_print_connected(self):
        scanner = _instantiate_scanner(_make_args())
        scanner.results["data"]["connected"] = True
        scanner.results["data"]["header_accepted"] = True
        scanner.logger = MagicMock()

        scanner.print_host_info()

        scanner.logger.display.assert_any_call("  ASTM Protocol: Header exchange successful")
        # No TLS was reported, so the plaintext finding must fire.
        scanner.logger.security_finding.assert_called_once_with(
            "No encryption", detail="ASTM communication is unencrypted (plaintext)"
        )

    def test_print_with_analyzer(self):
        scanner = _instantiate_scanner(_make_args())
        scanner.results["data"]["connected"] = True
        scanner.results["data"]["analyzer_info"] = {
            "name": "COBAS_8000",
            "vendor": "Roche",
            "version": "8.1.2",
            "product": "cobas 8000",
            "type": "Chemistry",
        }
        scanner.logger = MagicMock()

        scanner.print_host_info()

        scanner.logger.display.assert_any_call("  Analyzer: COBAS_8000 v8.1.2")
        scanner.logger.display.assert_any_call("  Vendor: Roche (cobas 8000) [Chemistry]")

    def test_print_tls_enabled(self):
        scanner = _instantiate_scanner(_make_args())
        scanner.results["data"]["connected"] = True
        scanner.results["data"]["tls_enabled"] = True
        scanner.logger = MagicMock()

        scanner.print_host_info()

        scanner.logger.display.assert_any_call("  Encryption: TLS enabled")
        scanner.logger.security_finding.assert_not_called()

    def test_print_no_connection(self):
        scanner = _instantiate_scanner(_make_args())
        scanner.results["data"]["connected"] = False
        scanner.logger = MagicMock()

        scanner.print_host_info()

        # Not connected: no header status is printed, but the missing-TLS
        # finding still fires since tls_enabled was never set.
        scanner.logger.display.assert_not_called()
        scanner.logger.warning.assert_not_called()
        scanner.logger.security_finding.assert_called_once_with(
            "No encryption", detail="ASTM communication is unencrypted (plaintext)"
        )


# ---------------------------------------------------------------------------
# Escape Order Test (records.py fix verification)
# ---------------------------------------------------------------------------


class TestEscapeOrder:
    """Verify escape order fix in records.py"""

    def test_backslash_escaped_before_component(self):
        builder = ASTMRecordBuilder()
        # A backslash should become &R& and not interfere with ^ escaping
        result = builder._escape_field("a\\b^c")
        assert "&R&" in result
        assert "&S&" in result
        # The & in &R& should NOT be double-escaped
        assert "&E&&R&E&" not in result

    def test_ampersand_first(self):
        builder = ASTMRecordBuilder()
        result = builder._escape_field("a&b")
        assert result == "a&E&b"

    def test_all_delimiters(self):
        builder = ASTMRecordBuilder()
        result = builder._escape_field("&|^\\")
        assert result == "&E&&F&&S&&R&"
