"""
Unit tests for BACnet deep device walk (_bacpypes3_deep_enum).
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
    """Get mock bacpypes3 types for deep enum operations."""
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


def _make_response_with_uint(value):
    """Create a mock response with an unsigned integer tag."""
    tag = Mock()
    tag.tag_data = value.to_bytes(4, "big")
    tag_str = "data_tag"
    tag.__str__ = lambda self: tag_str
    pv = Mock()
    pv.tagList = [tag]
    resp = Mock()
    resp.propertyValue = pv
    return resp


def _make_response_with_object_id(obj_type, obj_instance):
    """Create a mock response with a BACnet object identifier tag."""
    val = (obj_type << 22) | obj_instance
    tag = Mock()
    tag.tag_data = struct.pack(">I", val)
    tag_str = "oid_tag"
    tag.__str__ = lambda self: tag_str
    pv = Mock()
    pv.tagList = [tag]
    resp = Mock()
    resp.propertyValue = pv
    return resp


def _make_response_with_string(text):
    """Create a mock response with a string tag."""
    tag = Mock()
    tag.tag_data = text.encode("utf-8")
    tag_str = "string_tag"
    tag.__str__ = lambda self: tag_str
    pv = Mock()
    pv.tagList = [tag]
    resp = Mock()
    resp.propertyValue = pv
    return resp


class TestDeepEnum(unittest.TestCase):
    """Test _bacpypes3_deep_enum."""

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_deep_enum_with_indexed_object_list(self, mock_load):
        """Test deep enum using chunked/indexed objectList reads."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()

        # First call: objectList length = 2
        # Then: objectList[1] = analogInput:1, objectList[2] = binaryOutput:5
        # Then: property reads for each object (objectName, presentValue, etc.)
        responses = [
            _make_response_with_uint(2),  # objectList length
            _make_response_with_object_id(0, 1),  # objectList[1] = AI:1
            _make_response_with_object_id(4, 5),  # objectList[2] = BO:5
            # Property reads for AI:1
            _make_response_with_string("Zone Temp"),  # objectName
            None,
            None,
            None,
            None,
            None,  # other props
            None,
            None,
            None,
            None,  # cross-ref props
            # Property reads for BO:5
            _make_response_with_string("Fan Output"),  # objectName
            None,
            None,
            None,
            None,
            None,  # other props
            None,
            None,
            None,
            None,  # cross-ref props
        ]
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_deep_enum(app, Mock(), 1001, 5.0))

        scanner.logger.success.assert_called()
        # Verify objects were stored
        self.assertIn(1001, scanner.objects)

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_deep_enum_empty_object_list(self, mock_load):
        """Test deep enum when objectList is empty."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()

        # objectList length = 0, bulk read also returns nothing
        app.request = AsyncMock(return_value=None)

        asyncio.run(scanner._bacpypes3_deep_enum(app, Mock(), 1001, 5.0))

        scanner.logger.warning.assert_called()

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_deep_enum_timeout(self, mock_load):
        """Test deep enum handles timeouts gracefully."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_deep_enum(app, Mock(), 1001, 5.0))

        # Should warn about empty list
        scanner.logger.warning.assert_called()

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_deep_enum_max_objects_limit(self, mock_load):
        """Test deep enum respects max_objects limit."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance(max_objects=1)
        app = AsyncMock()

        # objectList length = 5 but max_objects = 1
        responses = [
            _make_response_with_uint(5),  # objectList length
            _make_response_with_object_id(0, 1),  # objectList[1]
            # Property reads for AI:1
            _make_response_with_string("Zone Temp"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ]
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_deep_enum(app, Mock(), 1001, 5.0))

        scanner.logger.warning.assert_called()

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_deep_enum_error_response(self, mock_load):
        """Test deep enum handles error responses."""
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()

        # Return an ErrorPDU for the objectList length read
        error = mock_types["ErrorPDU"]()
        app.request = AsyncMock(return_value=error)

        asyncio.run(scanner._bacpypes3_deep_enum(app, Mock(), 1001, 5.0))

        scanner.logger.warning.assert_called()


if __name__ == "__main__":
    unittest.main()
