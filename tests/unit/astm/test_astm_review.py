"""Regression tests for wire-protocol bugs found in a senior-dev review of the
ASTM scanner's framing layer (mixins/framing.py, cli_runner.py).

Each test targets one confirmed bug:
    A-1  missing CR before ETX (and the resulting wrong checksum span)
    H1   stale frame number surviving an aborted transmission
    H2a  coalesced frames in one recv() silently dropping records
    H2b  leftover application-ack bytes corrupting the next ENQ handshake
    M1   case-sensitive checksum comparison rejecting valid lowercase hex
    M3   no retransmission on NAK/timeout
    M4   no ETB splitting for records over 240 characters
"""

import socket
from argparse import Namespace
from unittest.mock import MagicMock, patch

from oida.protocols.astm.records import (
    ACK,
    CR,
    ENQ,
    EOT,
    ETB,
    ETX,
    LF,
    NAK,
    STX,
    ASTMRecordBuilder,
)


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
    sock = MagicMock(spec=socket.socket)
    if recv_values is not None:
        sock.recv.side_effect = list(recv_values)
    else:
        sock.recv.return_value = ACK
    return sock


def _instantiate_scanner(args, mock_sock=None):
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


def _checksum(data: bytes) -> bytes:
    return f"{sum(data) % 256:02X}".encode()


# ---------------------------------------------------------------------------
# A-1: frame must include CR before ETX/ETB, checksum must cover it
# ---------------------------------------------------------------------------


class TestBugA1FrameChecksumSpan:
    def test_send_frame_includes_cr_before_etx_with_matching_checksum(self):
        mock_sock = _make_mock_socket([ACK])
        scanner = _instantiate_scanner(_make_args(), mock_sock)
        scanner.frame_number = 1

        result = scanner._send_frame("H|\\^&|||OIDA|||||||P|E1394|20260911211936")
        assert result is True

        sent = mock_sock.sendall.call_args[0][0]
        assert sent.startswith(STX)
        assert sent.endswith(CR + LF)

        etx_idx = sent.index(ETX)
        # The record-terminating CR must sit immediately before ETX, inside
        # the checksummed span - not missing (bug A-1).
        assert sent[etx_idx - 1 : etx_idx] == CR

        checksum_data = sent[1 : etx_idx + 1]  # frame_num + text + CR + ETX
        received_checksum = sent[etx_idx + 1 : etx_idx + 3]
        assert received_checksum == _checksum(checksum_data)


# ---------------------------------------------------------------------------
# H1: frame number must reset at the start of a new transmission even if the
# previous transmission aborted mid-stream (never reached a successful EOT).
# ---------------------------------------------------------------------------


class TestBugH1FrameNumberResetsAfterAbort:
    def test_new_enq_resets_frame_number_after_aborted_transmission(self):
        mock_sock = _make_mock_socket()
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        # Simulate an aborted transmission: frames 1-2 were ACKed (frame_number
        # advanced to 3), then frame 3's sendall raised so both the frame send
        # and the follow-up EOT failed - frame_number is left stuck at 3.
        scanner.frame_number = 3

        # A fresh connection begins a new transmission: ENQ -> ACK must reset
        # frame numbering to 1 regardless of the previous transmission's fate.
        mock_sock.recv.side_effect = [ACK]
        assert scanner._send_enq() is True
        assert scanner.frame_number == 1

        # And the first data frame of the new transmission must carry "1".
        mock_sock.recv.side_effect = [ACK]
        assert scanner._send_frame("H|1") is True
        sent = mock_sock.sendall.call_args[0][0]
        assert sent[1:2] == b"1"


# ---------------------------------------------------------------------------
# H2a: frames coalesced into a single recv() must all be parsed and ACKed.
# ---------------------------------------------------------------------------


class TestBugH2aCoalescedFrames:
    def test_three_coalesced_frames_all_acked_and_extracted(self):
        mock_sock = _make_mock_socket()
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        def _frame(num: str, text: bytes, terminator: bytes = ETX) -> bytes:
            checksum_data = num.encode() + text + CR + terminator
            return STX + checksum_data + _checksum(checksum_data) + CR + LF

        f1 = _frame("1", b"H|\\^&|||TestLIS")
        f2 = _frame("2", b"R|1|^^^Glucose|95|mg/dL")
        f3 = _frame("3", b"L|1|N")

        # All three frames arrive in a single recv(); the follow-up recv()
        # yields EOT.
        mock_sock.recv.side_effect = [f1 + f2 + f3, EOT]

        scanner._receive_server_response()

        ack_calls = [c for c in mock_sock.sendall.call_args_list if c[0][0] == ACK]
        assert len(ack_calls) == 3

        info = scanner.results["data"].get("analyzer_info")
        assert info is not None
        assert info.get("name") == "TestLIS"


# ---------------------------------------------------------------------------
# H2b: bytes left over after draining an application-ack reply must not leak
# into (and corrupt) the next ENQ handshake read.
# ---------------------------------------------------------------------------


class TestBugH2bLeftoverBytesDontCorruptNextHandshake:
    def test_read_frames_until_eot_leaves_no_leftover_after_eot(self):
        mock_sock = _make_mock_socket()
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        checksum_data = b"1C|1|Accepted" + CR + ETX
        frame = STX + checksum_data + _checksum(checksum_data) + CR + LF

        # Everything - the frame AND the EOT that follows it - coalesced into
        # one recv() call, the way a real TCP peer could deliver it.
        mock_sock.recv.side_effect = [frame + EOT]

        frames = scanner._read_frames_until_eot(timeout=1)
        assert len(frames) == 1
        # No trailing bytes must remain buffered/lost; the next protocol read
        # must hit the real socket, not stale data.
        assert scanner._rx_buffer == b""

    def test_next_enq_after_app_ack_gets_real_ack_not_leftover_byte(self):
        mock_sock = _make_mock_socket()
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        checksum_data = b"1C|1|Accepted" + CR + ETX
        frame = STX + checksum_data + _checksum(checksum_data) + CR + LF

        # The application-ack probe: ENQ, our ACK is sent, then the server's
        # reply frame + EOT arrive coalesced in one chunk. A fresh connection
        # then starts a new transmission with a real ACK to our ENQ.
        mock_sock.recv.side_effect = [ENQ, frame + EOT, ACK]

        assert scanner._read_application_ack(timeout=1) is True
        # The real ACK for the *next* transmission's ENQ must still be seen -
        # it must not have been silently consumed/mis-attributed already.
        assert scanner._send_enq() is True


# ---------------------------------------------------------------------------
# M1: checksum comparison must be case-insensitive on the receive side.
# ---------------------------------------------------------------------------


class TestBugM1CaseInsensitiveChecksum:
    def test_lowercase_hex_checksum_is_accepted(self):
        mock_sock = _make_mock_socket()
        scanner = _instantiate_scanner(_make_args(), mock_sock)

        checksum_data = b"1H|\\^&|||TestLIS" + CR + ETX
        checksum = _checksum(checksum_data)
        assert any(c.isalpha() for c in checksum.decode()), (
            "test fixture must exercise a checksum containing a hex letter"
        )
        lower_checksum = checksum.lower()

        frame = STX + checksum_data + lower_checksum + CR + LF
        mock_sock.recv.side_effect = [frame, EOT]

        frames = scanner._read_frames_until_eot(timeout=1)
        assert len(frames) == 1
        assert mock_sock.sendall.call_args_list[0][0][0] == ACK


# ---------------------------------------------------------------------------
# M3: a NAKed (or timed-out) frame must be retransmitted, same frame number.
# ---------------------------------------------------------------------------


class TestBugM3RetransmitOnNak:
    def test_two_naks_then_ack_succeeds_with_same_frame_number(self):
        mock_sock = _make_mock_socket([NAK, NAK, ACK])
        scanner = _instantiate_scanner(_make_args(), mock_sock)
        scanner.frame_number = 4

        assert scanner._send_frame("H|1") is True
        assert mock_sock.sendall.call_count == 3

        frame_nums = {call[0][0][1:2] for call in mock_sock.sendall.call_args_list}
        assert frame_nums == {b"4"}


# ---------------------------------------------------------------------------
# M4: records over 240 characters must be split into ETB-terminated frames.
# ---------------------------------------------------------------------------


class TestBugM4FrameSplitting:
    def test_oversized_record_splits_with_incrementing_frame_numbers(self):
        mock_sock = _make_mock_socket()
        mock_sock.recv.return_value = ACK
        scanner = _instantiate_scanner(_make_args(), mock_sock)
        scanner.frame_number = 1

        long_text = "R|1|^^^Glucose|" + ("9" * 300) + "|mg/dL"
        assert len(long_text) > 240

        assert scanner._send_frame(long_text) is True

        sent_frames = [c[0][0] for c in mock_sock.sendall.call_args_list]
        assert len(sent_frames) >= 2

        for i, frame in enumerate(sent_frames):
            assert frame.startswith(STX)
            assert frame.endswith(CR + LF)
            is_last = i == len(sent_frames) - 1
            terminator = ETX if is_last else ETB
            term_idx = frame.index(terminator)
            checksum_data = frame[1:term_idx]
            received_checksum = frame[term_idx + 1 : term_idx + 3]
            assert received_checksum == _checksum(checksum_data + terminator)

        # Frame numbers increment per fragment, mod 8, starting at 1.
        seen_nums = [f[1:2] for f in sent_frames]
        expected_nums = [str((1 + i) % 8).encode() for i in range(len(sent_frames))]
        assert seen_nums == expected_nums

        # Only the final fragment's terminator is ETX; all others are ETB.
        assert all(ETB in f for f in sent_frames[:-1])
        assert all(ETB not in f[: f.index(ETX)] for f in sent_frames[-1:])


# ---------------------------------------------------------------------------
# H3: vendor fingerprinting used a bare substring test (`pattern in name_upper`),
# so a short vendor code like "STA" matched accidentally inside an unrelated
# token, e.g. "MY-STAT-ANALYZER" -> falsely reported as Diagnostica Stago.
# ---------------------------------------------------------------------------


class TestBugH3VendorFingerprintBoundary:
    def test_short_pattern_does_not_match_inside_unrelated_token(self):
        from oida.protocols.astm.records import identify_vendor_from_name

        assert identify_vendor_from_name("MY-STAT-ANALYZER") is None

    def test_short_pattern_still_matches_genuine_analyzer_name(self):
        from oida.protocols.astm.records import identify_vendor_from_name

        vendor, _product = identify_vendor_from_name("STA-R EVOLUTION")
        assert vendor == "Diagnostica Stago"

    def test_pattern_matches_when_run_into_model_number(self):
        # Real ASTM analyzers often run a vendor code straight into a model
        # number with no separator (e.g. Radiometer "ABL800").
        from oida.protocols.astm.records import identify_vendor_from_name

        vendor, _product = identify_vendor_from_name("ABL800 FLEX")
        assert vendor == "Radiometer"

    def test_long_pattern_still_matches(self):
        from oida.protocols.astm.records import identify_vendor_from_name

        vendor, _product = identify_vendor_from_name("ARCHITECT_C16000")
        assert vendor == "Abbott"

    def test_extract_analyzer_info_end_to_end_no_false_positive(self):
        scanner = _instantiate_scanner(_make_args(), _make_mock_socket())

        scanner._extract_analyzer_info(b"H|\\^&|||MY-STAT-ANALYZER||||||||\x03")

        info = scanner.results["data"].get("analyzer_info")
        assert info is not None
        assert "vendor" not in info


# ---------------------------------------------------------------------------
# M2: build_patient/build_order/build_result/build_query interpolated
# operator-supplied values RAW into the pipe-delimited field list. An
# embedded "|" shifted every later field. Only comment_text was escaped.
# ---------------------------------------------------------------------------


class TestBugM2FieldDelimiterEscaping:
    def test_patient_name_pipe_does_not_shift_field_count(self):
        from oida.protocols.astm.records import ASTMRecordBuilder

        builder = ASTMRecordBuilder()
        clean = builder.build_patient(sequence=1, patient_id="1", patient_name="DOE^JOHN")
        injected = builder.build_patient(sequence=1, patient_id="1", patient_name="DOE^JOHN|EVIL")
        assert len(injected.split("|")) == len(clean.split("|"))

    def test_patient_name_component_structure_preserved(self):
        from oida.protocols.astm.records import ASTMRecordBuilder

        builder = ASTMRecordBuilder()
        rec = builder.build_patient(sequence=1, patient_id="1", patient_name="DOE^JOHN^A")
        fields = rec.split("|")
        assert fields[5] == "DOE^JOHN^A"

    def test_scalar_field_delimiter_is_escaped(self):
        from oida.protocols.astm.records import ASTMRecordBuilder

        builder = ASTMRecordBuilder()
        clean = builder.build_patient(sequence=1, patient_id="1", patient_name="DOE^JOHN")
        rec = builder.build_patient(sequence=1, patient_id="1|EVIL", patient_name="DOE^JOHN")
        assert len(rec.split("|")) == len(clean.split("|"))
        assert "&F&" in rec

    def test_order_test_id_composite_preserved_but_pipe_escaped(self):
        from oida.protocols.astm.records import ASTMRecordBuilder

        builder = ASTMRecordBuilder()
        clean = builder.build_order(sequence=1, sample_id="S1", test_id="GLU^1")
        injected = builder.build_order(sequence=1, sample_id="S1|EVIL", test_id="GLU^1")
        assert len(injected.split("|")) == len(clean.split("|"))
        fields = clean.split("|")
        assert fields[4] == "GLU^1"


# ---------------------------------------------------------------------------
# M5: on BrokenPipeError/ConnectionResetError, _fuzz_records() reconnected via
# create_conn_obj() without closing the old (broken) socket first - a file
# descriptor leak on every drop.
# ---------------------------------------------------------------------------



class TestBugM6DeadDiscoveryFlagsRemoved:
    def test_flags_removed_from_parser(self):
        import argparse

        import pytest

        from oida.protocols.astm.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        proto_args(subparsers, [parent])
        for flag in ("--discover", "--quick", "--full", "--deep-scan"):
            with pytest.raises(SystemExit):
                main_parser.parse_args(["astm", "192.168.1.100", flag])

    def test_epilog_does_not_advertise_quick_flag(self):
        import argparse

        from oida.protocols.astm.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        astm_parser = proto_args(subparsers, [parent])
        assert "--quick" not in (astm_parser.epilog or "")


# ---------------------------------------------------------------------------
# M5: the fuzz loop must close the stale socket before reconnecting
# ---------------------------------------------------------------------------
class TestBugM5StaleSocketClosedOnReconnect:
    """create_conn_obj() overwrites self.conn with a fresh socket. Without an
    explicit close of the previous one, every BrokenPipeError/ConnectionReset
    during --fuzz leaks a file descriptor -- one per drop, per host, on a CIDR
    sweep against a peer that keeps dropping.

    Bounded by construction: the very first fuzz case raises BrokenPipeError,
    and create_conn_obj is stubbed to return False so the loop sets aborted
    and breaks after exactly one iteration. Nothing blocks on a socket.
    """

    def test_stale_socket_closed_before_reconnect(self):
        args = _make_args(fuzz=True, fuzz_frame=True, fuzz_iterations=1, confirm=True)
        stale = MagicMock(spec=socket.socket)
        stale.sendall.side_effect = BrokenPipeError("peer went away")
        scanner = _instantiate_scanner(args, stale)
        scanner.logger = MagicMock()

        with patch.object(type(scanner), "create_conn_obj", return_value=False) as reconnect:
            scanner._fuzz_records()

        reconnect.assert_called_once()
        stale.close.assert_called_once()

    def test_close_failure_does_not_break_the_fuzz_loop(self):
        """A socket that is already torn down raises on close(); that must not
        escape and abort the scan."""
        args = _make_args(fuzz=True, fuzz_frame=True, fuzz_iterations=1, confirm=True)
        stale = MagicMock(spec=socket.socket)
        stale.sendall.side_effect = ConnectionResetError("reset")
        stale.close.side_effect = OSError("already closed")
        scanner = _instantiate_scanner(args, stale)
        scanner.logger = MagicMock()

        with patch.object(type(scanner), "create_conn_obj", return_value=False):
            scanner._fuzz_records()

        stale.close.assert_called_once()
