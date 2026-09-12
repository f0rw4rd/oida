"""Regression: FF-HSE service-ID tables must match the real tshark registry.

``ff_hse.py``'s six service-ID tables were largely invented. The critical
consequence: FMS confirmed service id 2 is real-world **Read** and id 3 is
**Write** (per the ``ff.hdr_srv.fms.service_id.confirm`` value_string), but
the old table mapped 1->Read and 2->Write. Since ``process_packet()`` does
``if svc_name in FF_WRITE_SERVICES: session.write_count += 1``, write
detection fired on READ traffic and never on real writes. The old
``FF_WRITE_SERVICES`` also listed ``FDA_Write``/``FDA_WriteWithSubindex``,
which do not exist in the FDA registry (FDA confirm only registers 1=Open
Session and 3=Idle; there is no FDA unconfirmed table at all).

Authority: ``tshark -G values | grep -P '^V\\tff\\.hdr_srv\\.'`` (tshark
4.4.15). Trust that live output over any transcription, including this one.
"""

from oida.pcap.ff_hse import (
    FDA_CONFIRMED_SERVICES,
    FDA_UNCONFIRMED_SERVICES,
    FF_WRITE_SERVICES,
    FMS_CONFIRMED_SERVICES,
    FMS_UNCONFIRMED_SERVICES,
    LAN_SERVICES,
    LAN_UNCONFIRMED_SERVICES,
    SM_CONFIRMED_SERVICES,
    SM_UNCONFIRMED_SERVICES,
    FFHSEPassiveListener,
)

# Verbatim from `tshark -G values | grep -P '^V\tff\.hdr_srv\.'` (tshark 4.4.15)

TSHARK_FDA_CONFIRMED = {
    1: "FDA_OpenSession",
    3: "FDA_Idle",
}

TSHARK_SM_CONFIRMED = {
    3: "SM_Identify",
    12: "SM_ClearAddress",
    14: "SM_SetAssignmentInfo",
    15: "SM_ClearAssignmentInfo",
}

TSHARK_SM_UNCONFIRMED = {
    1: "SM_FindTagQuery",
    2: "SM_FindTagReply",
    16: "SM_DeviceAnnunciation",
}

TSHARK_FMS_CONFIRMED = {
    0: "FMS_Status",
    1: "FMS_Identify",
    2: "FMS_Read",
    3: "FMS_Write",
    4: "FMS_GetOD",
    7: "FMS_DefineVariableList",
    8: "FMS_DeleteVariableList",
    9: "FMS_InitiateDownloadSequence",
    10: "FMS_DownloadSegment",
    11: "FMS_TerminateDownloadSequence",
    12: "FMS_InitiateUploadSequence",
    13: "FMS_UploadSegment",
    14: "FMS_TerminateUploadSequence",
    15: "FMS_RequestDomainDownload",
    16: "FMS_RequestDomainUpload",
    17: "FMS_CreateProgramInvocation",
    18: "FMS_DeleteProgramInvocation",
    19: "FMS_Start",
    20: "FMS_Stop",
    21: "FMS_Resume",
    22: "FMS_Reset",
    23: "FMS_Kill",
    24: "FMS_AlterEventConditionMonitoring",
    25: "FMS_AcknowledgeEventNotification",
    28: "FMS_InitiatePutOD",
    29: "FMS_PutOD",
    30: "FMS_TerminatePutOD",
    31: "FMS_GenericInitiateDownloadSequence",
    32: "FMS_GenericDownloadSegment",
    33: "FMS_GenericTerminateDownloadSequence",
    82: "FMS_ReadWithSubindex",
    83: "FMS_WriteWithSubindex",
    96: "FMS_Initiate",
}

TSHARK_FMS_UNCONFIRMED = {
    0: "FMS_InformationReport",
    1: "FMS_UnsolicitedStatus",
    2: "FMS_EventNotification",
    16: "FMS_InformationReportWithSubindex",
    17: "FMS_InformationReportOnChange",
    18: "FMS_InformationReportOnChangeWithSubindex",
    112: "FMS_Abort",
}

TSHARK_LAN_CONFIRMED = {
    1: "LR_GetInfo",
    2: "LR_PutInfo",
    3: "LR_GetStatistics",
}

TSHARK_LAN_UNCONFIRMED = {
    1: "LR_DiagnosticMsg",
}


def test_fda_confirmed_matches_registry():
    assert FDA_CONFIRMED_SERVICES == TSHARK_FDA_CONFIRMED


def test_fda_unconfirmed_is_empty():
    """tshark registers no ff.hdr_srv.fda.service_id.unconfirm table at all."""
    assert FDA_UNCONFIRMED_SERVICES == {}


def test_sm_confirmed_matches_registry():
    assert SM_CONFIRMED_SERVICES == TSHARK_SM_CONFIRMED


def test_sm_unconfirmed_matches_registry():
    assert SM_UNCONFIRMED_SERVICES == TSHARK_SM_UNCONFIRMED


def test_fms_confirmed_matches_registry():
    assert FMS_CONFIRMED_SERVICES == TSHARK_FMS_CONFIRMED


def test_fms_unconfirmed_matches_registry():
    assert FMS_UNCONFIRMED_SERVICES == TSHARK_FMS_UNCONFIRMED


def test_lan_confirmed_matches_registry():
    assert LAN_SERVICES == TSHARK_LAN_CONFIRMED


def test_lan_unconfirmed_matches_registry():
    assert LAN_UNCONFIRMED_SERVICES == TSHARK_LAN_UNCONFIRMED


def test_fms_id_2_is_read_and_id_3_is_write():
    assert FMS_CONFIRMED_SERVICES[2] == "FMS_Read"
    assert FMS_CONFIRMED_SERVICES[3] == "FMS_Write"


def test_lan_confirmed_1_is_get_information_not_put():
    """The old (wrong) table had 1 -> LR_PutInfo; the real value is Get Info."""
    assert LAN_SERVICES[1] == "LR_GetInfo"


def test_no_fabricated_fda_write_service():
    assert "FDA_Write" not in FF_WRITE_SERVICES
    assert "FDA_WriteWithSubindex" not in FF_WRITE_SERVICES
    assert "FDA_Write" not in FDA_CONFIRMED_SERVICES.values()


def test_write_services_are_real_state_changing_verbs():
    expected = {
        "FMS_Write",
        "FMS_WriteWithSubindex",
        "FMS_PutOD",
        "FMS_InitiatePutOD",
        "FMS_TerminatePutOD",
        "FMS_InitiateDownloadSequence",
        "FMS_DownloadSegment",
        "FMS_TerminateDownloadSequence",
        "FMS_GenericInitiateDownloadSequence",
        "FMS_GenericDownloadSegment",
        "FMS_GenericTerminateDownloadSequence",
        "FMS_RequestDomainDownload",
        "FMS_Start",
        "FMS_Stop",
        "FMS_Resume",
        "FMS_Reset",
        "FMS_Kill",
        "FMS_CreateProgramInvocation",
        "FMS_DeleteProgramInvocation",
        "SM_ClearAddress",
        "SM_SetAssignmentInfo",
        "SM_ClearAssignmentInfo",
        "LR_PutInfo",
    }
    assert FF_WRITE_SERVICES == expected


# --- Behavioural: process_packet() must count writes/reads correctly ---


class _Layer:
    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _Packet:
    def __init__(self, ff):
        self.ff = ff
        self.ip = _Layer(src="10.0.0.5", dst="10.0.0.10")
        self.udp = _Layer(srcport="1090", dstport="1090", stream="0")
        self.eth = _Layer(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")
        self.transport_layer = "UDP"
        self.highest_layer = "FF"

    def __contains__(self, item):
        return hasattr(self, str(item).lower())


def _fms_packet(service_id: int):
    """Build a fake FF packet carrying an FMS confirmed-service request."""
    return _Packet(
        _Layer(
            hdr_srv_fms_service_id_confirm=str(service_id),
            hdr_confirm_msg_type="0",  # 0 = Request
        )
    )


def test_fms_write_service_increments_write_count_only():
    listener = FFHSEPassiveListener(interface="lo", timeout=1)
    listener.process_packet(_fms_packet(3))  # FMS_Write
    assert len(listener.sessions) == 1
    session = next(iter(listener.sessions.values()))
    assert session.write_count == 1
    assert session.read_count == 0
    assert "FMS_Write" in session.services_seen


def test_fms_read_service_increments_read_count_only():
    listener = FFHSEPassiveListener(interface="lo", timeout=1)
    listener.process_packet(_fms_packet(2))  # FMS_Read
    assert len(listener.sessions) == 1
    session = next(iter(listener.sessions.values()))
    assert session.write_count == 0
    assert session.read_count == 1
    assert "FMS_Read" in session.services_seen


def test_lan_unconfirmed_service_is_decoded():
    """LAN unconfirmed frames were never decoded (LAN wired with an empty
    unconfirm map in _identify_service); LR_DiagnosticMsg must now resolve.
    """
    listener = FFHSEPassiveListener(interface="lo", timeout=1)
    packet = _Packet(
        _Layer(
            hdr_srv_lan_service_id_unconfirm="1",
            hdr_confirm_msg_type="0",
        )
    )
    listener.process_packet(packet)
    assert len(listener.interactions) == 1
    assert listener.interactions[0].details["service"] == "LR_DiagnosticMsg"
