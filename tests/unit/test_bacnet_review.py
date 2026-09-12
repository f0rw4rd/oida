"""
Regression tests for three review findings in the BACnet files/state mixins.

B11 (HIGH)   src/oida/protocols/bacnet/mixins/files.py
             A device Error/Abort/Reject response is a real, raisable object
             that bacpypes3's Application.confirmation() rejects the request
             future with via ``future.set_exception(apdu)``. In bacpypes3
             0.0.106, ErrorPDU/AbortPDU/RejectPDU/Error all derive from
             ``ErrorRejectAbortNack(BaseException)`` -- NOT from ``Exception``
             -- so a bare ``except Exception`` around ``app.request()`` does
             not catch them and they propagate out of the whole scan.

B12 (MEDIUM) src/oida/protocols/bacnet/mixins/state.py ``_handle_diff``
             Only computed ``new_objs`` (current - baseline); objects removed
             since the baseline was taken were never reported, and the
             trailing "No significant changes detected" message was gated
             only on device-level add/remove, so it could contradict
             object-level changes reported just above it.

B13 (MEDIUM) src/oida/protocols/bacnet/mixins/files.py ``_bacpypes3_read_file``
             AtomicReadFile recordAccess addresses records by RECORD COUNT
             (ASHRAE 135), but the byte offset accumulator was reused as
             ``fileStartRecord``, so the second record-access request asks
             for a record number far past EOF.
"""

import asyncio
import json
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch


from tests.service_gate import require_import

require_import("bacpypes3")

from bacpypes3.apdu import AbortPDU, Error, ErrorPDU, RejectPDU  # noqa: E402
from bacpypes3.basetypes import ErrorClass, ErrorCode  # noqa: E402

from oida.protocols.bacnet import bacnet  # noqa: E402
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger  # noqa: E402


def _create_instance(**kwargs):
    """Create a bacnet instance bypassing __init__ (same pattern as
    tests/unit/bacnet/test_files_mixin.py)."""
    instance = object.__new__(bacnet)
    instance.args = create_mock_args(**kwargs)
    instance.logger = create_mock_logger()
    instance.results = {"data": {}}
    instance.host = "192.168.1.100"
    instance.devices = {}
    instance.objects = {}
    return instance


def _make_error_pdu():
    """A real bacpypes3 ErrorPDU, exactly what Application.confirmation()
    rejects an application-layer request's future with."""
    e = ErrorPDU()
    e.errorClass = ErrorClass.object
    e.errorCode = ErrorCode.unknownObject
    return e


def _dummy_types(extra=None):
    """bacpypes3 type dict using REAL PDU classes (so the mixin's
    ``except (AbortPDU, ErrorPDU, RejectPDU, Error)`` clauses -- which close
    over whatever ``_load_bacpypes3()`` returns -- actually match what we
    raise) and Mocks for everything only used to build request objects."""
    types = {
        "ReadPropertyRequest": Mock(return_value=Mock()),
        "ObjectIdentifier": Mock(return_value=Mock()),
        "PropertyIdentifier": Mock(return_value=Mock()),
        "CharacterString": Mock(),
        "Unsigned": Mock(),
        "AtomicReadFileRequest": Mock(return_value=Mock()),
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "RejectPDU": RejectPDU,
        "Error": Error,
    }
    if extra:
        types.update(extra)
    return types


# ---------------------------------------------------------------------------
# B11 -- ErrorPDU must not crash the scan
# ---------------------------------------------------------------------------


class TestB11ErrorPDUDoesNotCrashScan(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.files._load_bacpypes3")
    def test_read_file_survives_error_pdu(self, mock_load):
        """A device answering fileSize AND AtomicReadFile with Error must not
        blow up _bacpypes3_read_file -- it must warn and return cleanly."""
        mock_load.return_value = _dummy_types()

        scanner = _create_instance(read_file=1, file_chunk_size=1024)

        async def raise_error_pdu(_req):
            raise _make_error_pdu()

        app = AsyncMock()
        app.request = AsyncMock(side_effect=raise_error_pdu)

        # Must complete without the ErrorPDU escaping asyncio.run().
        asyncio.run(scanner._bacpypes3_read_file(app, Mock(), 1, 5.0))

        warn_msgs = " ".join(str(c) for c in scanner.logger.warning.call_args_list)
        self.assertTrue(warn_msgs, "expected a warning to be logged for the Error response")

    @patch("oida.protocols.bacnet.mixins.files._load_bacpypes3")
    def test_enumerate_files_survives_error_pdu(self, mock_load):
        """A device answering every file-property ReadProperty with Error
        must not blow up _bacpypes3_enumerate_files."""
        mock_load.return_value = _dummy_types()

        scanner = _create_instance()
        scanner.objects = {1: {"file": [1]}}

        async def raise_error_pdu(_req):
            raise _make_error_pdu()

        app = AsyncMock()
        app.request = AsyncMock(side_effect=raise_error_pdu)

        asyncio.run(scanner._bacpypes3_enumerate_files(app, Mock(), 1, 5.0))

        warn_msgs = " ".join(str(c) for c in scanner.logger.warning.call_args_list)
        self.assertTrue(warn_msgs, "expected a warning to be logged for the Error response")


# ---------------------------------------------------------------------------
# B12 -- _handle_diff must report removed objects and not contradict itself
# ---------------------------------------------------------------------------


class TestB12DiffReportsRemovedObjects(unittest.TestCase):
    def test_removed_object_is_reported_and_summary_is_consistent(self):
        baseline = {
            "devices": {
                "10": {
                    "objects": {
                        "analogInput": [1, 2, 3],
                    }
                }
            }
        }

        with __import__("tempfile").TemporaryDirectory() as tmp:
            baseline_path = Path(tmp) / "baseline.json"
            baseline_path.write_text(json.dumps(baseline))

            scanner = _create_instance(diff=str(baseline_path))
            scanner.devices = {10: {}}
            # Instance 3 is gone since the baseline was captured.
            scanner.objects = {10: {"analogInput": [1, 2]}}

            scanner._handle_diff()

        displayed = " ".join(str(c) for c in scanner.logger.display.call_args_list)

        self.assertIn("Removed analogInput", displayed)
        self.assertIn("3", displayed)
        # The object-level change above must not be contradicted by a
        # trailing "no changes" summary.
        self.assertNotIn("No significant changes detected", displayed)


# ---------------------------------------------------------------------------
# B13 -- recordAccess must use a record count for fileStartRecord, not bytes
# ---------------------------------------------------------------------------


def _make_record_response(records, eof=False):
    ra = Mock()
    ra.fileRecordData = records
    am = Mock(spec=["recordAccess"])
    am.recordAccess = ra
    resp = Mock()
    resp.endOfFile = eof
    resp.accessMethod = am
    return resp


class TestB13RecordAccessUsesRecordCount(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.files._load_bacpypes3")
    def test_second_record_request_uses_record_count_not_byte_offset(self, mock_load):
        atomic_request_mock = Mock(return_value=Mock())
        types = _dummy_types({"AtomicReadFileRequest": atomic_request_mock})
        mock_load.return_value = types

        scanner = _create_instance(read_file=1, file_access_method="record", file_chunk_size=1024)

        # First AtomicReadFile response: 2 records totalling 8 bytes.
        first_resp = _make_record_response([b"AAAA", b"BBBB"], eof=False)
        # Second response ends the loop.
        second_resp = _make_record_response([b"CCCC"], eof=True)

        call_count = {"n": 0}

        async def request_side_effect(_req):
            n = call_count["n"]
            call_count["n"] += 1
            if n == 0:
                return Mock()  # fileSize ReadProperty response
            if n == 1:
                return first_resp
            return second_resp

        app = AsyncMock()
        app.request = AsyncMock(side_effect=request_side_effect)

        asyncio.run(scanner._bacpypes3_read_file(app, Mock(), 1, 5.0))

        # AtomicReadFileRequest is called once per AtomicReadFile read (not
        # for the fileSize ReadPropertyRequest, which is a different mock).
        self.assertGreaterEqual(atomic_request_mock.call_count, 2)

        second_call_kwargs = atomic_request_mock.call_args_list[1].kwargs
        second_start_record = second_call_kwargs["accessMethod"]["recordAccess"]["fileStartRecord"]

        # Must be the RECORD COUNT read so far (2 records from the first
        # response), never the byte offset (8 bytes from "AAAA"+"BBBB").
        self.assertEqual(second_start_record, 2)
        self.assertNotEqual(second_start_record, 8)


if __name__ == "__main__":
    unittest.main()
