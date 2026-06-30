"""Behavioral parse tests for the DICOM passive listener.

``DICOMPassiveListener`` dispatches on the DICOM PDU type and extracts AE
titles, SOP classes, DIMSE commands, reject/abort reasons, PHI tags and
implementation fingerprints from the pyshark ``dicom`` layer.

These tests build fake pyshark packets/layers and drive ``process_packet()``
(the real dispatcher) plus ``harvest()`` / ``get_write_operations()`` /
``get_sessions_summary()``. No pyshark, tshark, or .pcap is required. Every
assertion checks parsed output against the exact mock field values, the PDU
dispatch table, and the constant lookup tables in the module.
"""

from oida.pcap.dicom import DICOMPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer (attribute access only)."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    """A fake DICOM-over-TCP packet."""

    def __init__(
        self,
        src_ip,
        dst_ip,
        dicom_fields,
        *,
        src_port=11112,
        dst_port=104,
        src_mac="aa:bb:cc:00:00:01",
        dst_mac="aa:bb:cc:00:00:02",
    ):
        self.eth = _Layer(src=src_mac, dst=dst_mac)
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.tcp = _Layer(srcport=str(src_port), dstport=str(dst_port), stream="0")
        self.dicom = _Layer(**dicom_fields)


SCU_IP = "10.30.0.10"  # client / calling AE (modality)
SCP_IP = "10.30.0.20"  # server / called AE (PACS)
CT_SOP = "1.2.840.10008.5.1.4.1.1.2"  # -> "CT Image"


def _make_listener():
    return DICOMPassiveListener(interface="lo", timeout=1)


# ---------------------------------------------------------------------------
# Dispatch gating
# ---------------------------------------------------------------------------


def test_packet_without_dicom_layer_ignored():
    listener = _make_listener()

    class _NoDicom:
        pass

    listener.process_packet(_NoDicom())
    assert listener.interactions == []


def test_packet_without_pdu_type_ignored():
    """A dicom layer with no pdu.type field yields no interaction."""
    listener = _make_listener()
    listener.process_packet(_FakePacket(SCU_IP, SCP_IP, {"foo": "bar"}))
    assert listener.interactions == []


def test_unknown_pdu_type_falls_through():
    """A PDU type outside the dispatch table (e.g. 0x08) records nothing but
    must not raise."""
    listener = _make_listener()
    listener.process_packet(_FakePacket(SCU_IP, SCP_IP, {"pdu_type": "0x08"}))
    assert listener.interactions == []


# ---------------------------------------------------------------------------
# A-ASSOCIATE-RQ (0x01)
# ---------------------------------------------------------------------------


def test_associate_rq_extracts_ae_titles_and_sop_class():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            SCU_IP,
            SCP_IP,
            {
                "pdu_type": "0x01",
                "assoc_ae_calling": "MODALITY_CT ",
                "assoc_ae_called": " PACS_MAIN",
                "assoc_version": "1",
                "pctx_abss_syntax": CT_SOP,
                "pctx_xfer_syntax": "1.2.840.10008.1.2.1",
                "userinfo_uid": "1.2.276.0.7230010.3.0.3.6.4",
                "userinfo_version": "OFFIS_DCMTK_364",
                "max_pdu_len": "16384",
            },
        )
    )
    ix = listener.interactions[-1]
    assert ix.operation == "A-ASSOCIATE-RQ"
    assert ix.direction == "request"
    d = ix.details
    assert d["calling_ae"] == "MODALITY_CT"  # stripped
    assert d["called_ae"] == "PACS_MAIN"  # stripped
    assert d["version"] == 1
    assert d["abstract_syntax"] == CT_SOP
    assert d["sop_class_name"] == "CT Image"
    assert d["transfer_syntax"] == "1.2.840.10008.1.2.1"
    assert d["impl_version"] == "OFFIS_DCMTK_364"
    assert d["max_pdu_length"] == 16384
    assert "MODALITY_CT -> PACS_MAIN" in ix.summary
    assert "[CT Image]" in ix.summary

    # Association tracked + device entries created
    assoc = listener.associations[(SCU_IP, SCP_IP)]
    assert assoc.calling_ae == "MODALITY_CT"
    assert assoc.called_ae == "PACS_MAIN"
    assert "CT Image" in assoc.sop_classes
    assert "dicom-server:" + SCP_IP in listener.discovered_devices
    assert "dicom-client:" + SCU_IP in listener.discovered_devices
    srv = listener.discovered_devices["dicom-server:" + SCP_IP]
    assert srv.dicom_passive_data["ae_title"] == "PACS_MAIN"
    assert srv.dicom_passive_data["role"] == "server"


def test_associate_rq_dotted_field_fallback():
    """When the underscore field names are absent the dotted XML-mode names
    (``assoc.ae.calling``) are used as a fallback."""
    listener = _make_listener()
    fields = {"pdu_type": "0x01"}
    fields["assoc.ae.calling"] = "CALL_AE"
    fields["assoc.ae.called"] = "CALLED_AE"
    listener.process_packet(_FakePacket(SCU_IP, SCP_IP, fields))
    d = listener.interactions[-1].details
    assert d["calling_ae"] == "CALL_AE"
    assert d["called_ae"] == "CALLED_AE"


# ---------------------------------------------------------------------------
# A-ASSOCIATE-AC (0x02)
# ---------------------------------------------------------------------------


def test_associate_ac_marks_association_accepted():
    listener = _make_listener()
    # First the request so the association exists.
    listener.process_packet(
        _FakePacket(
            SCU_IP,
            SCP_IP,
            {"pdu_type": "0x01", "assoc_ae_calling": "CT1", "assoc_ae_called": "PACS"},
        )
    )
    # Accept comes from server (SCP) back to client (SCU).
    listener.process_packet(
        _FakePacket(
            SCP_IP,
            SCU_IP,
            {
                "pdu_type": "0x02",
                "assoc_ae_calling": "CT1",
                "assoc_ae_called": "PACS",
                "userinfo_version": "DCMTK_365",
                "pctx_abss_syntax": CT_SOP,
            },
        )
    )
    ix = listener.interactions[-1]
    assert ix.operation == "A-ASSOCIATE-AC"
    assert ix.direction == "response"
    assert ix.details["impl_version"] == "DCMTK_365"
    assert ix.details["sop_class_name"] == "CT Image"
    assert "[DCMTK_365]" in ix.summary

    assoc = listener.associations[(SCU_IP, SCP_IP)]
    assert assoc.accepted is True
    assert assoc.impl_version == "DCMTK_365"


# ---------------------------------------------------------------------------
# A-ASSOCIATE-RJ (0x03)
# ---------------------------------------------------------------------------


def test_associate_rj_user_source_reason():
    """Source=1 (service user) -> reason resolved from the USER reason table."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            SCP_IP,
            SCU_IP,
            {
                "pdu_type": "0x03",
                "assoc_reject_result": "1",
                "assoc_reject_source": "1",
                "assoc_reject_reason": "7",
            },
        )
    )
    d = listener.interactions[-1].details
    assert d["reject_result_name"] == "Rejected (Permanent)"
    assert d["reject_source_name"] == "DICOM UL Service User"
    assert d["reject_reason_name"] == "Called AE title not recognized"
    assert "Called AE title not recognized" in listener.interactions[-1].summary


def test_associate_rj_acse_source_reason():
    """Source=2 (ACSE provider) -> reason resolved from the ACSE reason table."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            SCP_IP,
            SCU_IP,
            {
                "pdu_type": "0x03",
                "assoc_reject_result": "2",
                "assoc_reject_source": "2",
                "assoc_reject_reason": "2",
            },
        )
    )
    d = listener.interactions[-1].details
    assert d["reject_result_name"] == "Rejected (Transient)"
    assert d["reject_source_name"] == "DICOM UL Service Provider (ACSE)"
    assert d["reject_reason_name"] == "Protocol version not supported"


def test_associate_rj_unknown_source_reason_passthrough():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            SCP_IP,
            SCU_IP,
            {"pdu_type": "0x03", "assoc_reject_source": "3", "assoc_reject_reason": "9"},
        )
    )
    d = listener.interactions[-1].details
    assert d["reject_source_name"] == "DICOM UL Service Provider (Presentation)"
    assert d["reject_reason_name"] == "reason=9"


# ---------------------------------------------------------------------------
# P-DATA-TF (0x04): DIMSE commands + PHI
# ---------------------------------------------------------------------------


def test_data_identifies_dimse_command_from_command_field():
    """tag_value_16u carrying 0x0001 -> C-STORE-RQ."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            SCU_IP,
            SCP_IP,
            {
                "pdu_type": "0x04",
                "pdv_ctx": "1",
                "pdv_flags": "0x00",  # command, bit0=0 -> request
                "tag_value_16u": "1",  # 0x0001 C-STORE-RQ
            },
        )
    )
    ix = listener.interactions[-1]
    assert ix.details["dimse_command"] == "C-STORE-RQ"
    assert ix.details["command_field"] == 1
    assert ix.direction == "request"
    assert ix.details["pdv_context"] == 1


def test_data_response_direction_from_pdv_flags():
    """pdv_flags bit0=1 -> data fragment -> response direction."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            SCP_IP,
            SCU_IP,
            {
                "pdu_type": "0x04",
                "pdv_flags": "0x01",
                "tag_value_16u": "32816",
            },  # 0x8030 C-ECHO-RSP
        )
    )
    ix = listener.interactions[-1]
    assert ix.direction == "response"
    assert ix.details["dimse_command"] == "C-ECHO-RSP"


def test_data_phi_tag_sets_exposure_and_marks_association():
    listener = _make_listener()
    # Establish an association so PHI can be marked on it.
    listener.process_packet(
        _FakePacket(
            SCU_IP,
            SCP_IP,
            {"pdu_type": "0x01", "assoc_ae_calling": "CT", "assoc_ae_called": "PACS"},
        )
    )
    # PatientName tag 0x00100010 with a value present.
    listener.process_packet(
        _FakePacket(
            SCU_IP,
            SCP_IP,
            {"pdu_type": "0x04", "tag": "0x00100010", "tag_value_str": "DOE^JANE"},
        )
    )
    ix = listener.interactions[-1]
    assert ix.details["phi_tag"] == "PatientName"
    assert ix.details["phi_exposed"] is True
    assert ix.details["phi_value_present"] is True
    assert "[PHI: PatientName]" in ix.summary
    assert listener.associations[(SCU_IP, SCP_IP)].phi_exposed is True


def test_data_non_phi_tag_not_flagged():
    listener = _make_listener()
    listener.process_packet(_FakePacket(SCU_IP, SCP_IP, {"pdu_type": "0x04", "tag": "0x00080018"}))
    assert "phi_exposed" not in listener.interactions[-1].details


# ---------------------------------------------------------------------------
# A-RELEASE-RQ/RP (0x05/0x06)
# ---------------------------------------------------------------------------


def test_release_rq_is_request():
    listener = _make_listener()
    listener.process_packet(_FakePacket(SCU_IP, SCP_IP, {"pdu_type": "0x05"}))
    ix = listener.interactions[-1]
    assert ix.operation == "A-RELEASE-RQ"
    assert ix.direction == "request"


def test_release_rp_is_response():
    listener = _make_listener()
    listener.process_packet(_FakePacket(SCP_IP, SCU_IP, {"pdu_type": "0x06"}))
    ix = listener.interactions[-1]
    assert ix.operation == "A-RELEASE-RP"
    assert ix.direction == "response"


# ---------------------------------------------------------------------------
# A-ABORT (0x07)
# ---------------------------------------------------------------------------


def test_abort_resolves_source_and_reason():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            SCP_IP,
            SCU_IP,
            {"pdu_type": "0x07", "assoc_abort_source": "2", "assoc_abort_reason": "1"},
        )
    )
    d = listener.interactions[-1].details
    assert d["abort_source_name"] == "DICOM UL Service Provider"
    assert d["abort_reason_name"] == "Unrecognized PDU"
    assert "Unrecognized PDU" in listener.interactions[-1].summary


# ---------------------------------------------------------------------------
# Column formatting
# ---------------------------------------------------------------------------


def test_format_protocol_columns_for_data_with_phi():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            SCU_IP,
            SCP_IP,
            {"pdu_type": "0x04", "tag": "0x00100020", "tag_value_16u": "1"},  # PatientID + C-STORE
        )
    )
    cols = listener._format_protocol_columns(listener.interactions[-1])
    pdu_type, calling, called, sop, detail = cols
    assert pdu_type == "P-DATA-TF"
    assert "C-STORE-RQ" in detail
    assert "[PHI:PatientID]" in detail


def test_format_protocol_columns_for_reject():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(SCP_IP, SCU_IP, {"pdu_type": "0x03", "assoc_reject_result": "1"})
    )
    cols = listener._format_protocol_columns(listener.interactions[-1])
    assert "Rejected (Permanent)" in cols[4]


# ---------------------------------------------------------------------------
# harvest() / write ops / session summary
# ---------------------------------------------------------------------------


def test_harvest_phi_and_cleartext_alerts():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            SCU_IP,
            SCP_IP,
            {"pdu_type": "0x01", "assoc_ae_calling": "CT", "assoc_ae_called": "PACS"},
        )
    )
    listener.process_packet(
        _FakePacket(SCU_IP, SCP_IP, {"pdu_type": "0x04", "tag": "0x00100010", "tag_value_str": "X"})
    )
    result = listener.harvest()
    cats = {a["category"] for a in result["alerts"]}
    assert "phi_exposure" in cats
    assert "cleartext" in cats
    phi_msg = next(a["message"] for a in result["alerts"] if a["category"] == "phi_exposure")
    assert "cleartext" in phi_msg.lower()
    assert SCU_IP in phi_msg


def test_get_write_operations_counts_store_command():
    listener = _make_listener()
    # C-STORE-RQ (0x0001) is a write command; tag_value_16u sets command_field.
    listener.process_packet(
        _FakePacket(SCU_IP, SCP_IP, {"pdu_type": "0x04", "pdv_flags": "0x00", "tag_value_16u": "1"})
    )
    writes = listener.get_write_operations()
    assert len(writes) == 1
    assert writes[0]["client"] == SCU_IP
    assert writes[0]["server"] == SCP_IP
    assert writes[0]["write_count"] == 1


def test_get_write_operations_ignores_read_command():
    listener = _make_listener()
    # C-FIND-RQ (0x0020) is NOT in DICOM_WRITE_COMMANDS.
    listener.process_packet(
        _FakePacket(
            SCU_IP, SCP_IP, {"pdu_type": "0x04", "pdv_flags": "0x00", "tag_value_16u": "32"}
        )
    )
    assert listener.get_write_operations() == []


def test_get_sessions_summary_reports_association():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            SCU_IP,
            SCP_IP,
            {
                "pdu_type": "0x01",
                "assoc_ae_calling": "CT1",
                "assoc_ae_called": "PACS",
                "pctx_abss_syntax": CT_SOP,
            },
        )
    )
    sessions = listener.get_sessions_summary()
    assert len(sessions) == 1
    s = sessions[0]
    assert s["calling_ae"] == "CT1"
    assert s["called_ae"] == "PACS"
    assert s["client"] == SCU_IP
    assert s["server"] == SCP_IP
    assert s["accepted"] is False
    assert "CT Image" in s["sop_classes"]
