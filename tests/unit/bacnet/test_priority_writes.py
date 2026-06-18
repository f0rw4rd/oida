"""
Unit tests for priority write testing feature.
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
    instance.objects = {
        1001: {
            "analogOutput": [1, 2],
            "analogValue": [1],
            "binaryOutput": [1],
            "analogInput": [1, 2, 3],
        },
    }
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
        "WritePropertyRequest": Mock(return_value=Mock()),
        "ReadPropertyRequest": Mock(return_value=Mock()),
        "ObjectIdentifier": Mock(return_value=Mock()),
        "PropertyIdentifier": Mock(return_value=Mock()),
        "Real": Mock(return_value=Mock()),
        "Unsigned": Mock(return_value=Mock()),
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "RejectPDU": RejectPDU,
        "Error": Error,
        "AnyAtomic": Mock(return_value=Mock()),
    }


class TestPriorityWritesNoObjects(unittest.TestCase):
    """Test priority write testing with no commandable objects."""

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_no_commandable_objects(self, mock_load):
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1, 2]}}  # Not commandable

        app = AsyncMock()
        target_addr = Mock()

        asyncio.run(scanner._bacpypes3_test_priority_writes(app, target_addr, 1001, 5.0))
        scanner.logger.display.assert_called()


class TestPriorityWritesWithObjects(unittest.TestCase):
    """Test priority write testing with commandable objects."""

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_all_priorities_rejected(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()
        target_addr = Mock()

        # First call reads current value - return a tag with float data
        read_response = Mock()
        tag = Mock()
        tag.tag_data = struct.pack(">f", 42.0)
        read_response.propertyValue = Mock()
        read_response.propertyValue.tagList = [tag]
        # Subsequent calls are writes - return ErrorPDU
        error_response = mock_types["ErrorPDU"]()
        app.request = AsyncMock(side_effect=[read_response] + [error_response] * 16)

        asyncio.run(scanner._bacpypes3_test_priority_writes(app, target_addr, 1001, 5.0))
        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_some_priorities_writable(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()
        target_addr = Mock()

        # Read current value
        read_response = Mock()
        tag = Mock()
        tag.tag_data = struct.pack(">f", 42.0)
        read_response.propertyValue = Mock()
        read_response.propertyValue.tagList = [tag]

        # Priorities 1-8 rejected, 9-16 accepted (None = success)
        error_response = mock_types["ErrorPDU"]()
        responses = [read_response] + [error_response] * 8 + [None] * 8
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_test_priority_writes(app, target_addr, 1001, 5.0))
        scanner.logger.warning.assert_called()

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_cannot_read_current_value(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()
        target_addr = Mock()

        # Return error on read
        error_response = mock_types["ErrorPDU"]()
        app.request = AsyncMock(return_value=error_response)

        asyncio.run(scanner._bacpypes3_test_priority_writes(app, target_addr, 1001, 5.0))
        scanner.logger.warning.assert_called()


class TestPriorityLevelConstants(unittest.TestCase):
    """Test priority level constant mapping."""

    def test_all_16_levels_defined(self):
        from oida.protocols.bacnet.constants import BACNET_PRIORITY_LEVELS

        for i in range(1, 17):
            self.assertIn(i, BACNET_PRIORITY_LEVELS)

    def test_life_safety_is_priority_1(self):
        from oida.protocols.bacnet.constants import BACNET_PRIORITY_LEVELS

        self.assertIn("Life Safety", BACNET_PRIORITY_LEVELS[1])

    def test_operator_is_priority_8(self):
        from oida.protocols.bacnet.constants import BACNET_PRIORITY_LEVELS

        self.assertIn("Operator", BACNET_PRIORITY_LEVELS[8])


if __name__ == "__main__":
    unittest.main()
