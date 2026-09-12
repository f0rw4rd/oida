"""
Unit tests for BACnet FilesMixin AtomicReadFile size capping.

Regression for CODE_REVIEW finding files.py:123-235 — an attacker-controlled
fileSize must not drive unbounded in-memory accumulation.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from oida.protocols.bacnet import bacnet
from oida.protocols.bacnet.mixins.files import MAX_FILE_BYTES
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _create_instance(**kwargs):
    """Create bacnet instance bypassing __init__."""
    instance = object.__new__(bacnet)
    instance.args = create_mock_args(**kwargs)
    instance.logger = create_mock_logger()
    instance.results = {"data": {}}
    instance.host = "192.168.1.100"
    instance.devices = {}
    instance.objects = {}
    return instance


def _get_mock_types(chunk_bytes, file_size):
    """Mock bacpypes3 types for the file-read path.

    The fileSize property read returns ``file_size``; every AtomicReadFile
    response yields a fixed-size stream chunk with endOfFile=False, so the
    only thing that can stop the loop is the size/iteration cap.
    """
    AbortPDU = type("AbortPDU", (), {})
    ErrorPDU = type("ErrorPDU", (), {})
    RejectPDU = type("RejectPDU", (), {})
    Error = type("Error", (), {})

    Unsigned = Mock(name="Unsigned")

    def read_prop_request(**kwargs):
        return Mock()

    def atomic_request(**kwargs):
        return Mock()

    return {
        "ReadPropertyRequest": Mock(side_effect=read_prop_request),
        "ObjectIdentifier": Mock(return_value=Mock()),
        "PropertyIdentifier": Mock(return_value=Mock()),
        "Unsigned": Unsigned,
        "AtomicReadFileRequest": Mock(side_effect=atomic_request),
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "RejectPDU": RejectPDU,
        "Error": Error,
    }


def _make_stream_response(chunk_bytes):
    """Build an AtomicReadFile stream response that never sets endOfFile."""
    sa = Mock()
    sa.fileData = chunk_bytes
    am = Mock(spec=["streamAccess"])
    am.streamAccess = sa
    resp = Mock()
    resp.endOfFile = False
    resp.accessMethod = am
    return resp


class TestAtomicReadFileCap(unittest.TestCase):
    """The accumulation must be bounded regardless of reported fileSize."""

    @patch("oida.protocols.bacnet.mixins.files._load_bacpypes3")
    def test_oversized_filesize_is_capped(self, mock_load):
        # Device claims a 4 GB file; chunks of 64 KB stream forever.
        chunk_size = 64 * 1024
        huge_size = 4 * 1024 * 1024 * 1024
        chunk = b"A" * chunk_size

        types = _get_mock_types(chunk, huge_size)
        mock_load.return_value = types

        scanner = _create_instance(read_file=1, file_chunk_size=chunk_size)

        # propertyValue.cast_out -> huge fileSize
        size_response = Mock()
        size_response.propertyValue = Mock()
        size_response.propertyValue.cast_out = Mock(return_value=huge_size)

        stream_response = _make_stream_response(chunk)

        # Count how many AtomicReadFile reads happen and assert the buffer
        # never exceeds the ceiling.
        call_count = {"n": 0}

        async def request_side_effect(req):
            # First request is the fileSize ReadProperty.
            if call_count["n"] == 0:
                call_count["n"] += 1
                return size_response
            call_count["n"] += 1
            return stream_response

        app = AsyncMock()
        app.request = AsyncMock(side_effect=request_side_effect)

        asyncio.run(scanner._bacpypes3_read_file(app, Mock(), 1, 5.0))

        # The cap warning must have fired.
        warn_msgs = " ".join(str(c) for c in scanner.logger.warning.call_args_list)
        self.assertIn("capped", warn_msgs.lower())

        # Number of AtomicReadFile reads must be bounded: ceiling / chunk + a
        # little slack, NOT huge_size / chunk (which would be ~65000).
        expected_max_reads = (MAX_FILE_BYTES // chunk_size) + 5
        atomic_reads = call_count["n"] - 1  # minus the size read
        self.assertLessEqual(atomic_reads, expected_max_reads)

    @patch("oida.protocols.bacnet.mixins.files._load_bacpypes3")
    def test_small_file_reads_to_completion(self, mock_load):
        """A small, well-behaved file is read fully without hitting the cap."""
        chunk_size = 1024
        types = _get_mock_types(b"", 1024)
        mock_load.return_value = types

        scanner = _create_instance(read_file=1, file_chunk_size=chunk_size)

        size_response = Mock()
        size_response.propertyValue = Mock()
        size_response.propertyValue.cast_out = Mock(return_value=1024)

        # One full chunk then endOfFile.
        resp = _make_stream_response(b"B" * 1024)
        resp.endOfFile = True

        call_count = {"n": 0}

        async def request_side_effect(req):
            if call_count["n"] == 0:
                call_count["n"] += 1
                return size_response
            call_count["n"] += 1
            return resp

        app = AsyncMock()
        app.request = AsyncMock(side_effect=request_side_effect)

        asyncio.run(scanner._bacpypes3_read_file(app, Mock(), 1, 5.0))

        # No cap warning for a legitimate small file.
        warn_msgs = " ".join(str(c) for c in scanner.logger.warning.call_args_list)
        self.assertNotIn("capped", warn_msgs.lower())
        scanner.logger.success.assert_called()


if __name__ == "__main__":
    unittest.main()
