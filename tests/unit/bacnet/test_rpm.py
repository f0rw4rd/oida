"""
Unit tests for ReadPropertyMultiple (RPM) feature.
"""

import asyncio
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
            "analogInput": [1, 2, 3],
            "analogOutput": [1],
            "binaryOutput": [1],
        },
    }
    instance.bacnet = Mock()
    return instance


class TestRPMNoObjects(unittest.TestCase):
    """Test RPM with no objects enumerated."""

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_rpm_no_objects_for_device(self, mock_load):
        mock_types = self._get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        scanner.objects = {}

        app = AsyncMock()
        target_addr = Mock()

        asyncio.run(scanner._bacpypes3_read_property_multiple(app, target_addr, 1001, 5.0))
        scanner.logger.warning.assert_called()

    def _get_mock_types(self):
        return {
            "ReadPropertyMultipleRequest": Mock,
            "ReadAccessSpecification": Mock,
            "PropertyReference": Mock,
            "ObjectIdentifier": Mock,
            "PropertyIdentifier": Mock,
            "AbortPDU": type("AbortPDU", (), {}),
            "ErrorPDU": type("ErrorPDU", (), {}),
            "RejectPDU": type("RejectPDU", (), {}),
            "Error": type("Error", (), {}),
            "CharacterString": Mock,
            "Real": Mock,
            "Unsigned": Mock,
        }


class TestRPMWithObjects(unittest.TestCase):
    """Test RPM with objects present."""

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_rpm_success_response(self, mock_load):
        mock_types = {
            "ReadPropertyMultipleRequest": Mock(return_value=Mock()),
            "ReadAccessSpecification": Mock(return_value=Mock()),
            "PropertyReference": Mock(return_value=Mock()),
            "ObjectIdentifier": Mock(return_value=Mock()),
            "PropertyIdentifier": Mock(return_value=Mock()),
            "AbortPDU": type("AbortPDU", (), {}),
            "ErrorPDU": type("ErrorPDU", (), {}),
            "RejectPDU": type("RejectPDU", (), {}),
            "Error": type("Error", (), {}),
            "CharacterString": Mock,
            "Real": Mock,
            "Unsigned": Mock,
        }
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()

        # Mock a successful response
        mock_response = Mock()
        mock_response.listOfReadAccessResults = []
        app.request = AsyncMock(return_value=mock_response)

        target_addr = Mock()

        asyncio.run(scanner._bacpypes3_read_property_multiple(app, target_addr, 1001, 5.0))
        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_rpm_timeout_fallback(self, mock_load):
        mock_types = {
            "ReadPropertyMultipleRequest": Mock(return_value=Mock()),
            "ReadAccessSpecification": Mock(return_value=Mock()),
            "PropertyReference": Mock(return_value=Mock()),
            "ObjectIdentifier": Mock(return_value=Mock()),
            "PropertyIdentifier": Mock(return_value=Mock()),
            "AbortPDU": type("AbortPDU", (), {}),
            "ErrorPDU": type("ErrorPDU", (), {}),
            "RejectPDU": type("RejectPDU", (), {}),
            "Error": type("Error", (), {}),
            "CharacterString": Mock,
            "Real": Mock,
            "Unsigned": Mock,
        }
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        target_addr = Mock()

        asyncio.run(scanner._bacpypes3_read_property_multiple(app, target_addr, 1001, 5.0))
        # Should report failures
        scanner.logger.display.assert_called()


if __name__ == "__main__":
    unittest.main()
