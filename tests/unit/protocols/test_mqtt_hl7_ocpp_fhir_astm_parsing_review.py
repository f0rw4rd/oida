#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hostile-peer parsing review for MQTT / HL7 / OCPP / FHIR / ASTM.

Every test here feeds a *malformed, truncated or hostile* peer response to a
real parse/handler routine and asserts the scanner degrades gracefully instead
of letting an unexpected exception type escape the local handler.

Each test was written fail-first: it reproduced a concrete defect against the
code as it stood, and only then was the minimal fix applied.

Note on impact: ``NetworkConnection.run()`` has a broad ``except Exception``
safety net, so these defects do not kill the interpreter -- they abort the
*entire remaining scan of that host* (every later probe, enumeration step and
listen mode is skipped) and mark the run failed. The local handlers here all
declare their own graceful-degradation path; these inputs route around it.
"""

from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _RecordingLogger:
    """Minimal stand-in for the NXC-style logger used by the scanners."""

    def __init__(self) -> None:
        self.messages: List[str] = []

    def _record(self, msg, *args, **kwargs):
        self.messages.append(str(msg) % args if args else str(msg))

    display = info = debug = success = fail = warning = highlight = _record

    @property
    def text(self) -> str:
        return "\n".join(self.messages)


class _ScriptedScanner:
    """Returns a canned raw frame for every _send_and_receive() call."""

    def __init__(self, response: Optional[str]) -> None:
        self.response = response
        self.sent: List[str] = []

    def _send_and_receive(self, _conn, message, *args, **kwargs):
        self.sent.append(message)
        return self.response


def _make_ocpp(response: str, **args_kwargs: Any):
    """Build an `ocpp` connection instance without running a real scan.

    The NXC-style class auto-executes proto_flow() in __init__, so the object
    is constructed via __new__ and only the attributes the handlers under test
    actually touch are populated.
    """
    from oida.protocols.ocpp import ocpp

    conn = object.__new__(ocpp)
    conn.logger = _RecordingLogger()
    conn.scanner = _ScriptedScanner(response)
    conn.conn = object()  # truthy sentinel; never used by the scripted scanner
    conn.results: Dict[str, Any] = {"data": {}, "success": True}
    defaults = {"auth_id": None, "trigger": None, "connector_id": 0}
    defaults.update(args_kwargs)
    conn.args = SimpleNamespace(**defaults)
    return conn


# ---------------------------------------------------------------------------
# OCPP -- a CALLRESULT payload is whatever JSON the server put in element 2.
# _parse_message() returns data[2] verbatim with no type check, so a server
# answering with a scalar/list instead of an object turns the handlers'
# ``payload.get(...)`` into an AttributeError. The handlers catch only
# ValueError, so it escapes their "Unparseable response" degradation path.
#
# src/oida/protocols/ocpp/__init__.py  _handle_authorize_test / _handle_trigger_message
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload_json",
    [
        '"pwned"',  # scalar string CALLRESULT payload
        "42",  # scalar int
        "[1, 2]",  # list instead of object
        "null",
        '{"idTagInfo": "not-an-object"}',  # right key, wrong nesting
    ],
    ids=["str", "int", "list", "null", "nested-scalar"],
)
def test_ocpp_authorize_survives_non_object_callresult(payload_json):
    """Authorize CALLRESULT with a non-object payload must not abort the scan."""
    conn = _make_ocpp(f'[3, "abc123", {payload_json}]', auth_id="DEADBEEF")

    conn._handle_authorize_test()  # must not raise

    assert "Authorize" in conn.logger.text


@pytest.mark.parametrize(
    "payload_json",
    ['"boom"', "0", "[]", "null"],
    ids=["str", "int", "list", "null"],
)
def test_ocpp_trigger_survives_non_object_callresult(payload_json):
    """TriggerMessage CALLRESULT with a non-object payload must not abort."""
    conn = _make_ocpp(f'[3, "abc123", {payload_json}]', trigger="StatusNotification")

    conn._handle_trigger_message()  # must not raise

    assert "TriggerMessage" in conn.logger.text


def test_ocpp_callerror_details_non_object_is_survivable():
    """A CALLERROR whose element 2/3 are non-strings must not abort either."""
    conn = _make_ocpp('[4, "abc123", 500, ["x"], "ignored"]', auth_id="TAG")

    conn._handle_authorize_test()

    assert "Authorize" in conn.logger.text


# --- control: well-formed input must keep working, byte for byte -------------


def test_ocpp_authorize_wellformed_unchanged():
    conn = _make_ocpp('[3, "abc123", {"idTagInfo": {"status": "Accepted"}}]', auth_id="TAG1")

    conn._handle_authorize_test()

    assert conn.results["data"]["authorize"] == {"id_tag": "TAG1", "status": "Accepted"}
    assert "[Authorize] TAG1: Accepted" in conn.logger.text


def test_ocpp_authorize_wellformed_missing_status_defaults_to_unknown():
    conn = _make_ocpp('[3, "abc123", {}]', auth_id="TAG1")

    conn._handle_authorize_test()

    assert conn.results["data"]["authorize"] == {"id_tag": "TAG1", "status": "Unknown"}


def test_ocpp_trigger_wellformed_unchanged():
    conn = _make_ocpp('[3, "abc123", {"status": "Accepted"}]', trigger="BootNotification")

    conn._handle_trigger_message()

    assert "[TriggerMessage] BootNotification: Accepted" in conn.logger.text


# ---------------------------------------------------------------------------
# HL7 -- continuation reassembly parses every collected fragment with hl7apy.
# _check_continuation() finds a DSC pointer by plain string match (no full
# parse), so a server can hand out a pointer and then answer the QCN request
# with a frame hl7apy refuses to parse. _reassemble_fragments() has no
# try/except, so hl7apy's ParserError escapes the whole query path.
#
# src/oida/protocols/hl7/mixins/continuation.py  _reassemble_fragments
# ---------------------------------------------------------------------------


def _make_hl7_continuation():
    from oida.protocols.hl7.mixins.continuation import ContinuationMixin

    obj = object.__new__(type("_Cont", (ContinuationMixin,), {}))
    obj.logger = _RecordingLogger()
    return obj


_GOOD_FRAME = (
    b"MSH|^~\\&|SRV|FAC|OIDA|SEC|20240101000000||RSP^K21|1|P|2.5\r"
    b"MSA|AA|1\r"
    b"PID|1||12345^^^MRN||DOE^JOHN\r"
    b"DSC|1|I\r"
)


@pytest.mark.parametrize(
    "hostile",
    [
        b"GARBAGE",  # no MSH at all
        b"",  # empty continuation frame
        b"MSH|",  # truncated header
        b"\x00\x01\x02\x03",  # binary noise
        b"MSH|^~\\&|\rPID|1",  # header with no encoding chars/type
    ],
    ids=["no-msh", "empty", "truncated-msh", "binary", "headerless"],
)
def test_hl7_reassemble_survives_unparseable_fragment(hostile):
    """A hostile continuation fragment must not abort the query path."""
    cont = _make_hl7_continuation()

    result = cont._reassemble_fragments([_GOOD_FRAME, hostile])  # must not raise

    assert isinstance(result, bytes)
    # The good fragment's data survives; the hostile one is dropped.
    assert b"DOE^JOHN" in result


def test_hl7_reassemble_all_fragments_unparseable_falls_back_to_first_frame():
    """If nothing parses, degrade to what a single-shot send would have returned."""
    cont = _make_hl7_continuation()

    result = cont._reassemble_fragments([b"GARBAGE", b"MORE GARBAGE"])

    assert result == b"GARBAGE"


# --- control: well-formed multi-fragment reassembly is unchanged -------------


def test_hl7_reassemble_wellformed_unchanged():
    second = (
        b"MSH|^~\\&|SRV|FAC|OIDA|SEC|20240101000000||RSP^K21|2|P|2.5\r"
        b"MSA|AA|2\r"
        b"PID|2||67890^^^MRN||ROE^JANE\r"
    )
    cont = _make_hl7_continuation()

    result = cont._reassemble_fragments([_GOOD_FRAME, second])
    text = result.decode()

    # MSH/MSA kept from the first fragment only, DSC dropped, both PIDs kept.
    assert text.count("MSH|") == 1
    assert text.count("MSA|") == 1
    assert "DSC|" not in text
    assert "DOE^JOHN" in text
    assert "ROE^JANE" in text


def test_hl7_reassemble_single_fragment_is_passthrough():
    cont = _make_hl7_continuation()

    assert cont._reassemble_fragments([_GOOD_FRAME]) is _GOOD_FRAME
    assert cont._reassemble_fragments([]) == b""
