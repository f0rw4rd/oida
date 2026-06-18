"""
Unit tests for BACnet loop/PID controller enumeration (_bacpypes3_enum_loops).
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
    instance.host_info = {}
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


def _make_float_response(value):
    """Create a mock response with a float (real) tag."""
    tag = Mock()
    tag.tag_data = struct.pack(">f", value)
    pv = Mock()
    pv.tagList = [tag]
    resp = Mock()
    resp.propertyValue = pv
    return resp


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


class TestEnumLoops(unittest.TestCase):
    """Test _bacpypes3_enum_loops."""

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_loops_from_cached_objects(self, mock_load):
        """Test loop enum using pre-cached object list."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.objects = {1001: {"loop": [1]}}
        app = AsyncMock()

        # Properties read per loop (17 total):
        # objectName, presentValue, manipulatedVariableReference,
        # controlledVariableReference, setpoint, setpointReference,
        # action, proportionalConstant, integralConstant, derivativeConstant,
        # bias, maximumOutput, minimumOutput, outputUnits, updateInterval,
        # priorityForWriting, covIncrement
        responses = [
            _make_string_response("Zone Temp PID"),  # objectName
            _make_float_response(72.5),  # presentValue
            _make_string_response("AO:1"),  # manipulatedVariableRef
            _make_string_response("AI:1"),  # controlledVariableRef
            _make_float_response(72.0),  # setpoint
            None,  # setpointReference
            _make_uint_response(0),  # action = direct
            _make_float_response(10.0),  # proportionalConstant
            _make_float_response(0.5),  # integralConstant
            _make_float_response(0.1),  # derivativeConstant
            _make_float_response(50.0),  # bias
            _make_float_response(100.0),  # maximumOutput
            _make_float_response(0.0),  # minimumOutput
            _make_uint_response(64),  # outputUnits
            _make_uint_response(100),  # updateInterval (centiseconds)
            _make_uint_response(8),  # priorityForWriting
            _make_float_response(0.5),  # covIncrement
        ]
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_enum_loops(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_loops_no_cached_probes_range(self, mock_load):
        """Test loop enum probes instances 1-20 when no cache."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.objects = {}
        app = AsyncMock()

        # All reads timeout - no loops found
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_enum_loops(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_loops_empty_list(self, mock_load):
        """Test loop enum with explicitly empty loop list."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.objects = {1001: {"loop": []}}
        app = AsyncMock()

        asyncio.run(scanner._bacpypes3_enum_loops(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_loops_high_p_gain_flagged(self, mock_load):
        """Test that high proportional gain triggers security concern."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.objects = {1001: {"loop": [1]}}
        app = AsyncMock()

        # High P gain (100.0 > 50.0 threshold)
        responses = [
            _make_string_response("Pressure PID"),  # objectName
            _make_float_response(50.0),  # presentValue
            None,
            None,  # refs
            _make_float_response(48.0),  # setpoint
            None,  # setpointRef
            _make_uint_response(0),  # action
            _make_float_response(100.0),  # proportionalConstant (HIGH)
            _make_float_response(0.5),  # integralConstant
            _make_float_response(0.1),  # derivativeConstant
            None,
            None,
            None,
            None,
            None,  # bias, limits, etc.
            _make_uint_response(8),  # priorityForWriting
            None,  # covIncrement
        ]
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_enum_loops(app, Mock(), 1001, 5.0))

        # High P gain should be flagged
        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_loops_no_response(self, mock_load):
        """Test loop enum when device returns no responses."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.objects = {1001: {"loop": [1, 2]}}
        app = AsyncMock()
        app.request = AsyncMock(return_value=None)

        asyncio.run(scanner._bacpypes3_enum_loops(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()


if __name__ == "__main__":
    unittest.main()
