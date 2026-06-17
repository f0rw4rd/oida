"""Unit tests for oida.protocols.hl7.utils — the pure helper functions.

These functions are transport/parse helpers shared by the scanner and the
fuzzer: MLLP framing, ACK parsing, test-message construction and the
``send_probe`` / ``probe_server_capabilities`` socket helpers. They are pure
(no class state) so we exercise them directly, mocking only the socket layer
(``ConnectionHelper.create_tcp_socket``) used by ``send_probe``.
"""

import unittest
from unittest.mock import patch

from oida.protocols.hl7 import utils
from oida.protocols.hl7.utils import (
    MLLP_END,
    MLLP_START,
    create_test_message,
    extract_ack_code,
    parse_ack_response,
    probe_server_capabilities,
    send_probe,
    strip_mllp,
    wrap_mllp,
)


def _mllp(body: str) -> bytes:
    return MLLP_START + body.encode() + MLLP_END


class TestMllpFraming(unittest.TestCase):
    def test_wrap_mllp_adds_vt_and_fs_cr(self):
        out = wrap_mllp("MSH|^~\\&|A")
        self.assertTrue(out.startswith(MLLP_START))
        self.assertTrue(out.endswith(MLLP_END))
        self.assertIn(b"MSH", out)

    def test_strip_mllp_removes_framing(self):
        framed = _mllp("MSH|^~\\&|A\rMSA|AA|1")
        self.assertEqual(strip_mllp(framed), b"MSH|^~\\&|A\rMSA|AA|1")

    def test_strip_mllp_keeps_unframed_body(self):
        # No leading VT, no trailing FS+CR -> returned unchanged.
        raw = b"MSH|^~\\&|A"
        self.assertEqual(strip_mllp(raw), raw)

    def test_strip_mllp_truncates_trailing_garbage_after_end(self):
        framed = MLLP_START + b"BODY" + MLLP_END + b"JUNKAFTER"
        self.assertEqual(strip_mllp(framed), b"BODY")

    def test_wrap_then_strip_roundtrip(self):
        body = "MSH|^~\\&|SENDER\rMSA|AA|MSG1"
        self.assertEqual(strip_mllp(wrap_mllp(body)).decode(), body)


class TestExtractAckCode(unittest.TestCase):
    def test_extracts_aa(self):
        resp = _mllp("MSH|^~\\&|A|B|C|D|T||ACK|1|P|2.5\rMSA|AA|1")
        self.assertEqual(extract_ack_code(resp), "AA")

    def test_extracts_ar_reject(self):
        resp = _mllp("MSH|^~\\&|A\rMSA|AR|1|rejected")
        self.assertEqual(extract_ack_code(resp), "AR")

    def test_no_msa_returns_none(self):
        resp = _mllp("MSH|^~\\&|A|B\rPID|1||X")
        self.assertIsNone(extract_ack_code(resp))

    def test_works_on_unframed_bytes(self):
        # strip_mllp is a no-op for unframed input, so this must still parse.
        self.assertEqual(extract_ack_code(b"MSH|^~\\&|A\rMSA|CE|1"), "CE")


class TestParseAckResponse(unittest.TestCase):
    def test_parses_server_info_and_ack(self):
        resp = _mllp("MSH|^~\\&|EPIC|HOSPITAL|OIDA|SEC|20240101||ACK|99|P|2.7\rMSA|AA|99|All good")
        info = parse_ack_response(resp)
        self.assertEqual(info["server_app"], "EPIC")
        self.assertEqual(info["server_facility"], "HOSPITAL")
        self.assertEqual(info["version"], "2.7")
        self.assertEqual(info["ack_code"], "AA")
        self.assertEqual(info["ack_text"], "All good")

    def test_version_strips_component_suffix(self):
        resp = _mllp("MSH|^~\\&|A|B|C|D|T||ACK|1|P|2.5^extra\rMSA|AE|1")
        info = parse_ack_response(resp)
        self.assertEqual(info["version"], "2.5")
        self.assertEqual(info["ack_code"], "AE")

    def test_missing_fields_yield_none_defaults(self):
        info = parse_ack_response(b"MSH|^~\\&\rMSA|AR|1")
        self.assertEqual(info["ack_code"], "AR")
        # MSH had no app/facility/version fields populated.
        self.assertIsNone(info["server_app"])
        self.assertIsNone(info["version"])


class TestCreateTestMessage(unittest.TestCase):
    def test_adt_contains_evn_pid_pv1(self):
        msg = create_test_message("ADT", "A01")
        self.assertIn("MSH", msg)
        self.assertIn("ADT^A01", msg)
        self.assertIn("EVN", msg)
        self.assertIn("PID", msg)
        self.assertIn("PV1", msg)

    def test_oru_contains_obr_obx(self):
        msg = create_test_message("ORU", "R01")
        self.assertIn("ORU^R01", msg)
        self.assertIn("OBR", msg)
        self.assertIn("OBX", msg)

    def test_orm_contains_orc(self):
        msg = create_test_message("ORM", "O01")
        self.assertIn("ORM^O01", msg)
        self.assertIn("ORC", msg)

    def test_qry_contains_qrd_wildcard(self):
        msg = create_test_message("QRY", "A19")
        self.assertIn("QRD", msg)
        # who-subject probe value
        self.assertIn("PROBE", msg)

    def test_ack_falls_back_to_raw_msh_pid(self):
        # hl7apy has no ACK_<trigger> structure, so create_test_message's
        # hl7apy branch raises and the raw fallback (MSH + generic PID) runs.
        msg = create_test_message("ACK", "A01")
        self.assertIn("MSH", msg)
        self.assertIn("ACK^A01", msg)
        self.assertIn("PID|1||PROBE", msg)

    def test_custom_sender_propagates_to_msh(self):
        msg = create_test_message("ADT", "A04", sending_app="MYAPP", sending_facility="MYFAC")
        self.assertIn("MYAPP", msg)
        self.assertIn("MYFAC", msg)

    def test_unsupported_type_uses_raw_fallback(self):
        # QBP is not in the hl7apy-handled branch list above, but the raw
        # fallback builds a QPD+RCP message.
        with patch.object(utils, "Message", None):
            msg = create_test_message("QBP", "Q11")
        self.assertIn("QPD", msg)
        self.assertIn("RCP", msg)
        self.assertIn("QBP^Q11", msg)

    def test_raw_fallback_adt_has_evn_pid_pv1(self):
        with patch.object(utils, "Message", None):
            msg = create_test_message("ADT", "A01")
        # CR-joined raw segments
        self.assertEqual(msg.count("\r"), 3)  # MSH, EVN, PID, PV1 -> 3 separators
        self.assertIn("EVN|A01", msg)
        self.assertIn("PV1|1|I|PROBE^101^A", msg)

    def test_raw_fallback_generic_has_pid_only(self):
        with patch.object(utils, "Message", None):
            msg = create_test_message("ZZZ", "Z01")
        self.assertIn("ZZZ^Z01", msg)
        self.assertIn("PID|1||PROBE", msg)
        self.assertNotIn("EVN", msg)


class _FakeSocket:
    """Minimal socket: records sends, replays a scripted recv sequence."""

    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.sent = []
        self.closed = False

    def send(self, data):
        self.sent.append(data)

    def recv(self, _bufsize):
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    def close(self):
        self.closed = True


class TestSendProbe(unittest.TestCase):
    def test_send_probe_frames_and_returns_ack(self):
        fake = _FakeSocket([_mllp("MSH|^~\\&|SRV\rMSA|AA|1")])
        with patch(
            "oida.protocols.hl7.utils.ConnectionHelper.create_tcp_socket",
            return_value=fake,
        ):
            resp, ack = send_probe("1.2.3.4", 2575, "ACK", "")
        self.assertEqual(ack, "AA")
        self.assertIn(b"MSH", resp)
        # The probe was MLLP-framed before sending.
        self.assertTrue(fake.sent[0].startswith(MLLP_START))
        self.assertTrue(fake.closed)

    def test_send_probe_reassembles_chunks_until_mllp_end(self):
        body = "MSH|^~\\&|SRV\rMSA|AE|1"
        framed = _mllp(body)
        # Split mid-message into 3 chunks.
        chunks = [framed[:5], framed[5:12], framed[12:]]
        fake = _FakeSocket(chunks)
        with patch(
            "oida.protocols.hl7.utils.ConnectionHelper.create_tcp_socket",
            return_value=fake,
        ):
            resp, ack = send_probe("1.2.3.4", 2575, "QRY", "A19")
        self.assertEqual(ack, "AE")
        self.assertIn(b"MSA|AE", resp)

    def test_send_probe_no_response_returns_none(self):
        fake = _FakeSocket([b""])  # peer closes immediately
        with patch(
            "oida.protocols.hl7.utils.ConnectionHelper.create_tcp_socket",
            return_value=fake,
        ):
            resp, ack = send_probe("1.2.3.4", 2575, "ACK", "")
        self.assertIsNone(resp)
        self.assertIsNone(ack)
        self.assertTrue(fake.closed)

    def test_send_probe_returns_none_when_message_build_fails(self):
        with patch("oida.protocols.hl7.utils.create_test_message", return_value=None):
            resp, ack = send_probe("1.2.3.4", 2575, "ACK", "")
        self.assertEqual((resp, ack), (None, None))


class TestProbeServerCapabilities(unittest.TestCase):
    def test_aa_marks_type_supported_and_mllp(self):
        # Every probe gets AA -> all 4 probe types supported.
        with patch(
            "oida.protocols.hl7.utils.send_probe",
            return_value=(_mllp("MSH|^~\\&|VENDORX|FAC|||T||ACK|1|P|2.6\r"), "AA"),
        ):
            caps = probe_server_capabilities("1.2.3.4")
        self.assertTrue(caps["mllp_supported"])
        self.assertIn("ACK", caps["message_types"])
        self.assertIn("QBP", caps["message_types"])
        self.assertEqual(caps["server_app"], "VENDORX")
        self.assertEqual(caps["detected_version"], "2.6")
        self.assertEqual(caps["rejected_types"], set())

    def test_ar_marks_type_rejected(self):
        with patch(
            "oida.protocols.hl7.utils.send_probe",
            return_value=(_mllp("MSH|^~\\&|S\rMSA|AR|1"), "AR"),
        ):
            caps = probe_server_capabilities("1.2.3.4")
        # All probed types were rejected.
        self.assertIn("ACK", caps["rejected_types"])
        self.assertEqual(caps["message_types"], set())
        self.assertTrue(caps["mllp_supported"])

    def test_no_response_assumes_supported_but_not_mllp(self):
        with patch("oida.protocols.hl7.utils.send_probe", return_value=(None, None)):
            caps = probe_server_capabilities("1.2.3.4")
        # No response -> still added to supported (may be one-way), but
        # mllp_supported stays False since nothing came back.
        self.assertFalse(caps["mllp_supported"])
        self.assertIn("QRY", caps["message_types"])


if __name__ == "__main__":
    unittest.main()
