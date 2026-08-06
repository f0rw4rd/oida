"""Regression test: DICOM PHI tag detection across pyshark EK and XML modes.

CODE_REVIEW finding (``src/oida/pcap/dicom.py``): the PHI tag was parsed with
``self._parse_int(tag_raw, None, base=16)``. In pyshark EK mode the base class
``get_field()`` normalises the integer FT_UINT32 ``dicom.tag`` to its DECIMAL
string (tag 0x00100010 -> "1048592"); ``_parse_int(..., base=16)`` then parsed
that decimal string as hex (int("1048592", 16) = 19293650), which never matches
the ``PHI_TAGS`` integer keys. PHI-exposure detection silently failed for every
EK-mode capture: ``phi_exposed`` was never set and the harvest() PHI-EXPOSURE
alert -- the core security value of this listener -- was never emitted.

The fix parses the tag with the default base 10 so EK-mode decimal strings
resolve correctly while ``_parse_int``'s ``0x``-prefix auto-detection still
handles XML-mode hex.

These tests drive _process_data() with a lightweight fake layer (no pyshark /
tshark / .pcap fixture needed).
"""

from oida.pcap.dicom import DICOMPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only.

    Only the fields explicitly passed exist; absent fields fall through to
    getattr's default, exactly like a dissector that did not emit them.
    """

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


PATIENT_NAME_TAG = 0x00100010  # PHI_TAGS key -> decimal 1048592


def _make_listener():
    return DICOMPassiveListener(interface="lo", timeout=1)


def _run(dicom_layer):
    listener = _make_listener()
    listener._process_data(
        dicom_layer,
        pdu_name="P-DATA-TF",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        flow_id="f1",
        src_port=11112,
        dst_port=104,
        stream_id="0",
        now="2026-01-01T00:00:00",
    )
    return listener.interactions[-1]


def test_phi_exposed_in_ek_mode_integer_tag():
    """EK mode: dicom.tag arrives as a native int (0x00100010). get_field
    normalises it to the decimal string "1048592"; PHI detection must still
    fire. The base=16 regression parsed it as 19293650 and missed it."""
    # An int attribute models the EK-mode FT_UINT32 normalisation path.
    ix = _run(_Layer(tag=PATIENT_NAME_TAG, tag_value_str="DOE^JOHN"))

    assert ix.details.get("phi_exposed") is True, (
        "EK-mode PHI tag (integer 0x00100010) not detected -- base=16 regression"
    )
    assert ix.details.get("phi_tag") == "PatientName"
    assert ix.details.get("phi_value_present") is True


def test_phi_exposed_in_xml_mode_hex_string_tag():
    """XML mode: tshark emits the tag as a 0x-prefixed hex string. The 0x
    auto-detection in _parse_int must keep this working under base 10."""
    ix = _run(_Layer(tag="0x00100010", tag_value_str="DOE^JOHN"))

    assert ix.details.get("phi_exposed") is True
    assert ix.details.get("phi_tag") == "PatientName"


def test_non_phi_tag_not_flagged():
    """A non-PHI tag (e.g. 0x00000100 command field) must NOT set phi_exposed."""
    ix = _run(_Layer(tag=0x00000100))

    assert "phi_exposed" not in ix.details
    assert "phi_tag" not in ix.details


# --- multi-tag P-DATA-TF (dicom.py:604 finding) --------------------------------

SOP_INSTANCE_UID_TAG = 0x00080018  # decimal 524312 -- non-PHI leading element


def test_phi_detected_when_not_the_first_tag():
    """A P-DATA-TF PDV carries many elements; get_field() comma-joins them in
    EK mode. PHI on a trailing tag (not the leading metadata tag) must still be
    detected -- the pre-fix code inspected only the first occurrence."""
    ix = _run(
        _Layer(
            tag=f"{SOP_INSTANCE_UID_TAG},{PATIENT_NAME_TAG}",
            tag_value_str="1.2.3,DOE^JOHN",
        )
    )

    assert ix.details.get("phi_exposed") is True
    assert ix.details.get("phi_tag") == "PatientName"


# --- DIMSE command qualification (dicom.py:650 finding) ------------------------


def test_command_field_identifies_c_store_rq():
    """When the command-field tag (0000,0100) is present, its US value names
    the DIMSE command and drives direction via the 0x8000 RSP bit."""
    ix = _run(_Layer(tag=0x00000100, tag_value_16u=0x0001))

    assert ix.details.get("dimse_command") == "C-STORE-RQ"
    assert ix.details.get("command_field") == 0x0001
    assert ix.direction == "request"


def test_command_field_rsp_bit_sets_response_direction():
    ix = _run(_Layer(tag=0x00000100, tag_value_16u=0x8001))

    assert ix.details.get("dimse_command") == "C-STORE-RSP"
    assert ix.direction == "response"


def test_unqualified_16u_value_is_not_a_command():
    """A data PDV with no command-field tag but a US value that collides with a
    command code (0x0020 == C-FIND-RQ, e.g. a Message ID / count) must NOT be
    labelled a command, and direction must fall back to the flow heuristic --
    not flip to a spurious request/response from the bare 16u value."""
    ix = _run(_Layer(tag=SOP_INSTANCE_UID_TAG, tag_value_16u=0x0020))

    assert "dimse_command" not in ix.details
    assert "command_field" not in ix.details
    # No command field -> no spurious "DICOM WRITE" fodder in get_write_operations.
    assert ix.details.get("command_field") is None
