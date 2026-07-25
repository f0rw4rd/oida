"""Offline gating + render tests for the DICOM Upper Layer fuzzer.

Mirrors tests/unit/fuzz/test_ipv6_request_gating.py: the boofuzz session is
built offline via MockConnectionFactory and session.nodes is inspected to prove
that every advertised request is individually enable/disable-selectable and that
advertised == connected under default flags (strict 1:1 gating).

Also renders the two crown-jewel requests to assert the malformation bytes
actually reach the wire:
  - DICOM_CStore_UID_Traversal   -> "../" path-traversal payload present
  - DICOM_PresContext_Overflow   -> oversized abstract-syntax UID present
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections.base import MockConnectionFactory
from oida.fuzz.protocols.dicom import DICOMFuzzer

pytestmark = pytest.mark.core

ADVERTISED = {
    "DICOM_Baseline",
    "DICOM_PresContext_Overflow",
    "DICOM_PDU_Length_Lie",
    "DICOM_SubItem_Length_Overflow",
    "DICOM_DIMSE_Malformed",
    "DICOM_CStore_UID_Traversal",
    "DICOM_PDU_Type_Boundary",
    "DICOM_AETitle_Overflow",
}

EXPECTED_CATEGORIES = {
    "DICOM_Baseline": "baseline",
    "DICOM_PresContext_Overflow": "overflow",
    "DICOM_PDU_Length_Lie": "boundary",
    "DICOM_SubItem_Length_Overflow": "overflow",
    "DICOM_DIMSE_Malformed": "malformed",
    "DICOM_CStore_UID_Traversal": "malformed",
    "DICOM_PDU_Type_Boundary": "boundary",
    "DICOM_AETitle_Overflow": "overflow",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=104,
        protocol_type=ProtocolType.TCP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _build(config):
    return DICOMFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in DICOMFuzzer.get_request_definitions()}


def _render(fuzzer, name) -> bytes:
    """Render a single request's default value to raw bytes."""
    session = fuzzer.session
    for node in session.nodes.values():
        if node.name == name:
            return node.render()
    raise AssertionError(f"request {name} not connected")


# ---------------------------------------------------------------------------
# advertising / gating
# ---------------------------------------------------------------------------
def test_eight_requests_advertised():
    assert _advertised() == ADVERTISED
    assert len(DICOMFuzzer.get_request_definitions()) == 8


def test_request_categories():
    got = {d.name: d.category for d in DICOMFuzzer.get_request_definitions()}
    assert got == EXPECTED_CATEGORIES


def test_default_run_advertised_equals_connected():
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected <= _advertised()


@pytest.mark.parametrize("name", sorted(ADVERTISED))
def test_each_request_is_selectable(name):
    """--enable <name> connects exactly that one request (strict 1:1 gating)."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(ADVERTISED))
def test_each_request_is_disableable(name):
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert "DICOM_Baseline" in connected or name == "DICOM_Baseline"


# ---------------------------------------------------------------------------
# render assertions on the malformation payloads
# ---------------------------------------------------------------------------
def test_cstore_uid_traversal_render_contains_path_traversal():
    fuzzer = _build(_make_config(enabled_requests=["DICOM_CStore_UID_Traversal"]))
    data = _render(fuzzer, "DICOM_CStore_UID_Traversal")
    assert b"../" in data
    assert b"etc/passwd" in data
    assert data[0] == 0x04  # P-DATA-TF PDU type


def test_prescontext_overflow_render_contains_oversized_uid():
    fuzzer = _build(_make_config(enabled_requests=["DICOM_PresContext_Overflow"]))
    data = _render(fuzzer, "DICOM_PresContext_Overflow")
    assert b"9" * 512 in data  # oversized abstract-syntax UID reached the wire
    assert data[0] == 0x01  # A-ASSOCIATE-RQ PDU type


def test_baseline_render_is_valid_associate_rq():
    fuzzer = _build(_make_config(enabled_requests=["DICOM_Baseline"]))
    data = _render(fuzzer, "DICOM_Baseline")
    assert data[0] == 0x01  # A-ASSOCIATE-RQ
    assert data[1] == 0x00  # reserved
    assert b"1.2.840.10008.1.1" in data  # Verification SOP Class
    assert b"1.2.840.10008.1.2" in data  # Implicit VR LE transfer syntax


def test_default_monitors_socket_5():
    assert DICOMFuzzer.DEFAULT_MONITORS == "socket:5"
