"""
Regression tests for three confirmed ASTM E1394/E1381 bugs:

BUG 1 (records.py build_header): receiver value landed in the H-11
      (Comment/Special Instructions) field instead of H-10 (Receiver ID).
BUG 2 (cli_runner.py _extract_analyzer_info): read H-12 (Processing ID)
      and H-14 (Date/Time) instead of H-9 (Sender characteristics) and
      H-13 (Version Number).
BUG 3 (cli_runner.py _receive_server_response): never verified the
      modulo-256 checksum of received frames, ACKing corrupted frames.

Field numbering (1-based H-n = python list index n-1):
  H-1 record type | H-2 delimiters | H-3 message control id | H-4 access
  password | H-5 sender | H-6 sender address | H-7 reserved | H-8 sender
  phone | H-9 sender characteristics | H-10 receiver id | H-11 comment |
  H-12 processing id | H-13 version | H-14 date/time
"""

from argparse import Namespace
from unittest.mock import patch

from oida.protocols.astm.records import ACK, CR, EOT, ETX, LF, NAK, STX, ASTMRecordBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_args(**overrides):
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
    )
    defaults.update(overrides)
    return Namespace(**defaults)


def _instantiate_scanner(args, mock_sock=None):
    """Instantiate the ASTM scanner with proto_flow patched out, then set conn.

    Mirrors tests/unit/astm/test_astm_scanner.py::_instantiate_scanner so this
    file calls the exact same real code path.
    """
    with patch("oida.protocols.astm.proto_flow", create=True):
        with patch.object(
            __import__("oida.protocols.astm", fromlist=["astm"]).astm,
            "proto_flow",
        ):
            from oida.protocols.astm import astm as ASTMClass

            with patch.object(ASTMClass, "proto_flow"):
                scanner = ASTMClass(args, None, "127.0.0.1")

    scanner.record_builder = ASTMRecordBuilder(version="E1394")
    if mock_sock is not None:
        scanner.conn = mock_sock
    return scanner


class _FakeSocket:
    """Minimal fake socket: recv() drains a queue of pre-baked chunks,
    sendall() records everything sent back to us (ACK/NAK bytes)."""

    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.sent = []

    def settimeout(self, _t):
        pass

    def recv(self, _n=1024):
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    def sendall(self, data):
        self.sent.append(data)


def _make_frame(body: str) -> bytes:
    """Build a real, correctly-checksummed ASTM frame: STX + body + ETX +
    checksum + CR + LF, using the real checksum implementation under test."""
    builder = ASTMRecordBuilder()
    data_bytes = body.encode("utf-8")
    checksum_data = data_bytes + ETX
    checksum = builder._calculate_checksum(checksum_data)
    return STX + checksum_data + checksum + CR + LF


# ---------------------------------------------------------------------------
# BUG 1: build_header() writes receiver into the wrong field
# ---------------------------------------------------------------------------


class TestBuildHeaderReceiverField:
    def test_receiver_lands_in_h10_not_h11_comment(self):
        builder = ASTMRecordBuilder(version="E1394")
        header = builder.build_header(
            sender_name="OIDA",
            sender_id="",
            receiver_name="LIS",
            receiver_id="001",
        )
        fields = header.split("|")

        # H-10 = index 9 must carry the receiver value.
        assert fields[9] == "LIS^001", fields

        # H-11 = index 10 (Comment/Special Instructions) must be empty.
        assert fields[10] == "", fields

    def test_receiver_name_only_no_id(self):
        builder = ASTMRecordBuilder(version="E1394")
        header = builder.build_header(receiver_name="ANALYZER_X")
        fields = header.split("|")

        assert fields[9] == "ANALYZER_X"
        assert fields[10] == ""


# ---------------------------------------------------------------------------
# BUG 2: _extract_analyzer_info() reads the wrong H fields
# ---------------------------------------------------------------------------


class TestExtractAnalyzerInfoFieldMapping:
    def test_version_read_from_h13_not_h14(self):
        scanner = _instantiate_scanner(_make_args())

        # H-13 (index 12) carries the version-number string; H-14 (index 13)
        # is the date/time of message and must NOT be treated as a version.
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
            "20260101120000",
        ]
        data = ("|".join(fields) + "\x03").encode()
        scanner._extract_analyzer_info(data)

        info = scanner.results["data"].get("analyzer_info")
        assert info is not None
        assert info["version"] == "2.5.1"

    def test_characteristics_read_from_h9(self):
        scanner = _instantiate_scanner(_make_args())

        # H-9 (index 8) is "Sender characteristics".
        fields = [
            "H",
            "\\^&",
            "",
            "",
            "TestAnalyzer",
            "",
            "",
            "",
            "SomeCharacteristic",
            "",
            "",
            "",
            "",
            "",
        ]
        data = ("|".join(fields) + "\x03").encode()
        scanner._extract_analyzer_info(data)

        info = scanner.results["data"].get("analyzer_info")
        assert info is not None
        assert info.get("characteristics") == "SomeCharacteristic"

    def test_h12_processing_id_not_mislabeled_as_type(self):
        scanner = _instantiate_scanner(_make_args())

        # H-12 (index 11) is Processing ID (P/D/T) -- it must never be
        # surfaced as an analyzer "type".
        fields = ["H", "\\^&", "", "", "MyAnalyzer", "", "", "", "", "", "", "P", "", ""]
        data = ("|".join(fields) + "\x03").encode()
        scanner._extract_analyzer_info(data)

        info = scanner.results["data"].get("analyzer_info") or {}
        assert info.get("type") != "P"
        assert "type" not in info


# ---------------------------------------------------------------------------
# BUG 3: _receive_server_response() never verifies checksums
# ---------------------------------------------------------------------------


class TestReceiveServerResponseChecksumVerification:
    def test_valid_checksum_frame_is_acked_and_extracted(self):
        scanner = _instantiate_scanner(_make_args())
        body = "1H|\\^&|||TestLIS"
        frame = _make_frame(body)
        sock = _FakeSocket([frame, EOT])
        scanner.conn = sock

        scanner._receive_server_response()

        assert ACK in sock.sent
        assert NAK not in sock.sent
        info = scanner.results["data"].get("analyzer_info")
        assert info is not None
        assert info.get("name") == "TestLIS"

    def test_corrupted_checksum_frame_is_nacked_and_not_extracted(self):
        scanner = _instantiate_scanner(_make_args())
        body = "1H|\\^&|||TestLIS"
        good_frame = _make_frame(body)

        # Corrupt the two checksum hex bytes (right before CR LF) so the
        # embedded checksum no longer matches the frame's actual content.
        # good_frame layout: STX + body + ETX + CC + CR + LF
        etx_idx = good_frame.index(ETX)
        corrupt_checksum = b"00" if good_frame[etx_idx + 1 : etx_idx + 3] != b"00" else b"FF"
        bad_frame = good_frame[: etx_idx + 1] + corrupt_checksum + CR + LF

        sock = _FakeSocket([bad_frame, EOT])
        scanner.conn = sock

        scanner._receive_server_response()

        assert NAK in sock.sent
        assert ACK not in sock.sent
        assert "analyzer_info" not in scanner.results["data"]
