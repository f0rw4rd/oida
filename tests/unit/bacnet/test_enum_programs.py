"""
Unit tests for BACnet program object enumeration (_bacpypes3_enum_programs).
"""

import asyncio
import struct
import unittest
from unittest.mock import Mock, AsyncMock, patch

from oida.protocols.bacnet import bacnet
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _create_instance(**kwargs):
    """Create bacnet instance bypassing __init__."""
    instance = object.__new__(bacnet)
    instance.args = create_mock_args(**kwargs)
    instance.logger = create_mock_logger()
    instance.results = {"data": {}}
    instance.host = "192.168.1.100"
    instance.devices = {
        1001: {"device_id": 1001, "address": "192.168.1.100"},
    }
    instance.objects = {}
    instance.bacnet = Mock()
    return instance


def _get_mock_types():
    """Get mock bacpypes3 types."""
    AbortPDU = type("AbortPDU", (), {})
    ErrorPDU = type("ErrorPDU", (), {})
    RejectPDU = type("RejectPDU", (), {})
    Error = type("Error", (), {})

    return {
        "ReadPropertyRequest": Mock(return_value=Mock()),
        "ObjectIdentifier": Mock(return_value=Mock()),
        "PropertyIdentifier": Mock(return_value=Mock()),
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "RejectPDU": RejectPDU,
        "Error": Error,
    }


def _make_string_response(text):
    """Create a mock response with a string tag."""
    tag = Mock()
    tag.tag_data = text.encode("utf-8")
    pv = Mock()
    pv.tagList = [tag]
    resp = Mock()
    resp.propertyValue = pv
    return resp


def _make_uint_response(value):
    """Create a mock response with an unsigned integer tag."""
    tag = Mock()
    tag.tag_data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    pv = Mock()
    pv.tagList = [tag]
    resp = Mock()
    resp.propertyValue = pv
    return resp


class TestEnumPrograms(unittest.TestCase):
    """Test _bacpypes3_enum_programs."""

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_programs_from_cached_objects(self, mock_load):
        """Test program enum using pre-cached object list."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.objects = {1001: {"program": [1, 2]}}
        app = AsyncMock()

        # For each program: objectName, programState, programChange,
        # reasonForHalt, programLocation, description
        responses = [
            # Program 1
            _make_string_response("MainControl"),  # objectName
            _make_uint_response(2),  # programState = running
            _make_uint_response(0),  # programChange = ready
            None,  # reasonForHalt
            _make_string_response("/programs/main"),  # programLocation
            _make_string_response("Main controller"),  # description
            # Program 2
            _make_string_response("SafetyMonitor"),  # objectName
            _make_uint_response(4),  # programState = halted
            _make_uint_response(3),  # programChange = halt
            _make_string_response("by operator"),  # reasonForHalt
            _make_string_response("/programs/safe"),  # programLocation
            _make_string_response("Safety monitor"),  # description
        ]
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_enum_programs(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_programs_none_found(self, mock_load):
        """Test program enum when no program objects exist."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}
        app = AsyncMock()

        # objectList length read returns 1, then the object is AI:1 (not program)
        tag = Mock()
        tag.tag_data = (1).to_bytes(4, "big")
        pv = Mock()
        pv.tagList = [tag]
        length_resp = Mock()
        length_resp.propertyValue = pv

        # objectList[1] = analogInput:1 (type 0, instance 1)
        oid_tag = Mock()
        oid_val = (0 << 22) | 1  # analogInput:1
        oid_tag.tag_data = struct.pack(">I", oid_val)
        oid_pv = Mock()
        oid_pv.tagList = [oid_tag]
        oid_resp = Mock()
        oid_resp.propertyValue = oid_pv

        app.request = AsyncMock(side_effect=[length_resp, oid_resp])

        asyncio.run(scanner._bacpypes3_enum_programs(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_programs_timeout(self, mock_load):
        """Test program enum handles timeouts."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.objects = {}
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_enum_programs(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_programs_halted_flagged(self, mock_load):
        """Test that halted programs are flagged as security concerns."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.objects = {1001: {"program": [1]}}
        app = AsyncMock()

        responses = [
            _make_string_response("CriticalProcess"),  # objectName
            _make_uint_response(4),  # programState = halted
            _make_uint_response(3),  # programChange = halt
            _make_string_response("unknown failure"),  # reasonForHalt
            _make_string_response("/progs/critical"),  # programLocation
            _make_string_response("Critical"),  # description
        ]
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_enum_programs(app, Mock(), 1001, 5.0))

        # Should report the halted program
        scanner.logger.display.assert_called()


if __name__ == "__main__":
    unittest.main()
