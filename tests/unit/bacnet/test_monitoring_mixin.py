"""
Unit tests for BACnet MonitoringMixin including COV and ReadRange.
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
            "schedule": [1, 2],
            "calendar": [1],
            "notificationClass": [1, 2],
            "trendLog": [1, 2],
            "lifeSafetyPoint": [1],
        },
    }
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
        "SubscribeCOVRequest": Mock(return_value=Mock()),
        "ObjectIdentifier": Mock(return_value=Mock()),
        "PropertyIdentifier": Mock(return_value=Mock()),
        "Unsigned": Mock(return_value=Mock()),
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "RejectPDU": RejectPDU,
        "Error": Error,
    }


class TestCheckSchedules(unittest.TestCase):
    """Test _bacpypes3_check_schedules."""

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_schedules_accessible(self, mock_load):
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()
        response = Mock()
        app.request = AsyncMock(return_value=response)

        asyncio.run(scanner._bacpypes3_check_schedules(app, Mock(), 1001, 5.0))
        scanner.logger.warning.assert_called()

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_schedules_not_accessible(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_check_schedules(app, Mock(), 1001, 5.0))
        scanner.logger.display.assert_called()


class TestCheckTrendlogs(unittest.TestCase):
    """Test _bacpypes3_check_trendlogs."""

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_trendlogs_with_records(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()

        response = Mock()
        response.propertyValue = Mock()
        tag = Mock()
        tag.tag_data = (100).to_bytes(4, "big")
        response.propertyValue.tagList = [tag]
        app.request = AsyncMock(return_value=response)

        asyncio.run(scanner._bacpypes3_check_trendlogs(app, Mock(), 1001, 5.0))
        scanner.logger.warning.assert_called()


class TestCheckPriority(unittest.TestCase):
    """Test _bacpypes3_check_priority."""

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_priority_array_accessible(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=Mock())

        asyncio.run(scanner._bacpypes3_check_priority(app, Mock(), 1001, 5.0))
        scanner.logger.warning.assert_called()

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_priority_no_commandable_objects(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}  # Not commandable
        app = AsyncMock()

        asyncio.run(scanner._bacpypes3_check_priority(app, Mock(), 1001, 5.0))
        scanner.logger.display.assert_called()


class TestCOVSubscription(unittest.TestCase):
    """Test _bacpypes3_subscribe_cov."""

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_cov_no_objects(self, mock_load):
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.objects = {1001: {"device": [1001]}}  # No control points
        app = AsyncMock()

        asyncio.run(scanner._bacpypes3_subscribe_cov(app, Mock(), 1001, 5.0))
        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_cov_subscription_accepted(self, mock_load):
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        scanner.args.cov_duration = 1  # Short duration for test
        app = AsyncMock()
        app.request = AsyncMock(return_value=None)  # None = success

        asyncio.run(scanner._bacpypes3_subscribe_cov(app, Mock(), 1001, 5.0))
        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_cov_subscription_rejected(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=mock_types["ErrorPDU"]())

        asyncio.run(scanner._bacpypes3_subscribe_cov(app, Mock(), 1001, 5.0))
        scanner.logger.display.assert_called()


class TestReadRange(unittest.TestCase):
    """Test _bacpypes3_read_range."""

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_read_range_no_trendlogs(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}  # No trend logs
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_read_range(app, Mock(), 1001, 5.0))
        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_read_range_with_records(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        scanner.args.read_range_count = 5
        app = AsyncMock()

        # Metadata reads return record counts
        meta_response = Mock()
        meta_response.propertyValue = Mock()
        tag = Mock()
        tag.tag_data = (10).to_bytes(4, "big")
        meta_response.propertyValue.tagList = [tag]

        # Record reads succeed
        record_response = Mock()
        record_response.propertyValue = Mock(spec=["__str__"])
        record_response.propertyValue.__str__ = Mock(return_value="record_data")

        app.request = AsyncMock(return_value=meta_response)

        asyncio.run(scanner._bacpypes3_read_range(app, Mock(), 1001, 5.0))
        scanner.logger.display.assert_called()


class TestEnumLifeSafety(unittest.TestCase):
    """Test _bacpypes3_enum_life_safety."""

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_life_safety_found(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()

        response = Mock()
        response.propertyValue = Mock()
        tag = Mock()
        tag.tag_data = b"Fire Alarm Zone 1"
        response.propertyValue.tagList = [tag]
        app.request = AsyncMock(return_value=response)

        asyncio.run(scanner._bacpypes3_enum_life_safety(app, Mock(), 1001, 5.0))
        scanner.logger.security_finding.assert_called()


if __name__ == "__main__":
    unittest.main()
