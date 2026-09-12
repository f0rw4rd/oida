#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hostile-peer parsing review for the SNMP / CoAP / DICOM modules.

Every test here feeds a *malformed, truncated or hostile* response to a real
parse routine and asserts the scanner degrades gracefully instead of crashing
(IndexError/struct.error/ValueError/RecursionError), hanging, or over-allocating.

Each test was written fail-first: it reproduced a concrete defect against the
code as it stood, and only then was the minimal fix applied.
"""

import pytest

from tests.service_gate import require_import

pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# CoAP -- parse_payload()/_parse_json_payload() run json.loads() on the raw
# response body of an untrusted server. json.loads() raises RecursionError
# (NOT JSONDecodeError) on deeply nested input, and ~1000 nested brackets fit
# in a single CoAP datagram, so a hostile server can abort the scan.
# ---------------------------------------------------------------------------


DEEP_JSON = b"[" * 20000


def test_parse_payload_survives_deeply_nested_json_heuristic():
    """No content-format: the JSON heuristic must not blow the stack."""
    from oida.protocols.coap.helpers import parse_payload

    result = parse_payload(DEEP_JSON)
    assert result["raw_size"] == len(DEEP_JSON)
    # Degrades to a non-JSON classification rather than raising.
    assert result["type"] in ("text", "binary")


def test_parse_payload_survives_deeply_nested_json_content_format():
    """Explicit application/json (cf=50) takes the _parse_json_payload path."""
    from oida.protocols.coap.helpers import parse_payload

    for content_format in (50, 11543, 110):
        result = parse_payload(DEEP_JSON, content_format=content_format)
        assert result["type"] == "binary"
        assert result["value"] == DEEP_JSON.hex()


def test_parse_payload_well_formed_json_unchanged():
    """Control: valid payloads keep their existing classification/value."""
    from oida.protocols.coap.helpers import parse_payload

    assert parse_payload(b'{"a": 1}') == {
        "raw_size": 8,
        "value": {"a": 1},
        "type": "json",
    }
    assert parse_payload(b'{"a": 1}', content_format=50)["type"] == "json"
    assert parse_payload(b"hello", content_format=0) == {
        "raw_size": 5,
        "value": "hello",
        "type": "text",
    }
    assert parse_payload(b"\xff\xfe", content_format=0)["type"] == "binary"
    assert parse_payload(b"")["type"] == "empty"


# ---------------------------------------------------------------------------
# DICOM -- a C-FIND response stream is an endless sequence of "Pending"
# (0xFF00) identifiers entirely under the SCP's control. Loops that collect
# those identifiers without a cap never terminate and grow a list until the
# process OOMs. Both spots below were uncapped.
#
# The fake SCP raises _TooManyResponses (a BaseException, so the production
# `except Exception` handlers cannot swallow it) once the scanner has pulled
# far more responses than any cap should allow -- that is the hang tripwire.
# ---------------------------------------------------------------------------

pynetdicom = require_import("pynetdicom", reason="pip install -e .[dicom]")
from pydicom.dataset import Dataset  # noqa: E402
from unittest.mock import Mock  # noqa: E402

from tests.unit.dicom.test_scanner import _make_dicom_instance  # noqa: E402

TRIPWIRE = 20000


class _TooManyResponses(BaseException):
    """Raised by the hostile fake SCP: the scanner failed to stop pulling."""


def _pending(**fields):
    """(status, identifier) pair mimicking a Pending C-FIND response."""
    status = Mock()
    status.Status = 0xFF00
    ds = Dataset()
    for key, value in fields.items():
        setattr(ds, key, value)
    return status, ds


def _endless(**fields):
    """Infinite Pending stream that trips once the scanner over-reads."""
    count = 0
    while True:
        count += 1
        if count > TRIPWIRE:
            raise _TooManyResponses(f"scanner consumed {count} responses uncapped")
        yield _pending(**fields)


class _HostileArgs:
    max_patients = 1
    max_studies = 1
    verbose = False
    debug = False


def test_bulk_export_series_loop_is_capped(tmp_path):
    """operations.py step 3: endless SERIES Pending stream must not hang/OOM."""
    from oida.protocols.dicom.mixins.operations import OperationsMixin

    args = _HostileArgs()
    args.output_dir = str(tmp_path)
    scanner = _make_dicom_instance(args)

    def send_c_find(dataset, model):
        level = str(dataset.QueryRetrieveLevel)
        if level == "PATIENT":
            return iter([_pending(PatientID="P1", PatientName="X")])
        if level == "STUDY":
            return iter([_pending(StudyInstanceUID="1.2.3", StudyDate="20200101")])
        return _endless(SeriesInstanceUID="1.2.3.4", Modality="CT")

    assoc = Mock()
    assoc.is_established = True
    assoc.send_c_find = send_c_find
    assoc.send_c_get = Mock(return_value=iter([]))
    scanner.assoc = assoc

    OperationsMixin._recursive_bulk_export(scanner)

    # Must have stopped well before the tripwire (no _TooManyResponses escape).
    assert scanner.results["data"]["bulk_export"]["series"] < TRIPWIRE


def test_enum_devices_study_fallback_is_capped():
    """enumeration.py: endless STUDY Pending stream in the fallback path."""
    from oida.protocols.dicom.mixins.enumeration import EnumerationMixin

    scanner = _make_dicom_instance(_HostileArgs())

    def send_c_find(dataset, model):
        level = str(dataset.QueryRetrieveLevel)
        if level == "SERIES":
            # Return nothing so the study-by-study fallback is taken.
            return iter([])
        return _endless(StudyInstanceUID="1.2.3")

    assoc = Mock()
    assoc.is_established = True
    assoc.send_c_find = send_c_find
    scanner.assoc = assoc

    # Completes (bounded) instead of collecting study UIDs forever.
    EnumerationMixin._enum_devices(scanner)


def test_dicom_bounded_streams_unchanged_for_well_formed_scp(tmp_path):
    """Control: a normal, finite SCP still yields every response it sends."""
    from oida.protocols.dicom.mixins.operations import OperationsMixin

    args = _HostileArgs()
    args.output_dir = str(tmp_path)
    scanner = _make_dicom_instance(args)

    def send_c_find(dataset, model):
        level = str(dataset.QueryRetrieveLevel)
        if level == "PATIENT":
            return iter([_pending(PatientID="P1", PatientName="X")])
        if level == "STUDY":
            return iter([_pending(StudyInstanceUID="1.2.3", StudyDate="20200101")])
        return iter(
            [
                _pending(SeriesInstanceUID="1.2.3.4", Modality="CT"),
                _pending(SeriesInstanceUID="1.2.3.5", Modality="MR"),
            ]
        )

    assoc = Mock()
    assoc.is_established = True
    assoc.send_c_find = send_c_find
    assoc.send_c_get = Mock(return_value=iter([]))
    scanner.assoc = assoc

    OperationsMixin._recursive_bulk_export(scanner)

    stats = scanner.results["data"]["bulk_export"]
    assert stats["patients"] == 1
    assert stats["studies"] == 1
    assert stats["series"] == 2
