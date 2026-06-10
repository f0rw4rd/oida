"""
Unit tests for BACnet NetworkMixin including BBMD injection testing.
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
        1001: {"analogInput": [1, 2]},
    }
    instance.bacnet = Mock()
    instance.host_info = {}
    instance.remote_networks = []
    return instance


def _get_mock_types():
    """Get mock bacpypes3 types for network operations."""
    AbortPDU = type("AbortPDU", (), {})
    ErrorPDU = type("ErrorPDU", (), {})
    RejectPDU = type("RejectPDU", (), {})
    Error = type("Error", (), {})

    return {
        "WhoHasRequest": Mock(return_value=Mock()),
        "WhoHasObject": Mock(return_value=Mock()),
        "ReadBroadcastDistributionTable": Mock(return_value=Mock()),
        "ReadForeignDeviceTable": Mock(return_value=Mock()),
        "WriteBroadcastDistributionTable": Mock(return_value=Mock()),
        "RegisterForeignDevice": Mock(return_value=Mock()),
        "WhoIsRouterToNetwork": Mock(return_value=Mock()),
        "WhoIsRequest": Mock(return_value=Mock()),
        "ReadPropertyRequest": Mock(return_value=Mock()),
        "ObjectIdentifier": Mock(return_value=Mock()),
        "PropertyIdentifier": Mock(return_value=Mock()),
        "CharacterString": Mock(return_value=Mock()),
        "GlobalBroadcast": Mock(return_value=Mock()),
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "RejectPDU": RejectPDU,
        "Error": Error,
    }


class TestWhoHas(unittest.TestCase):
    """Test _bacpypes3_who_has."""

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_who_has_found(self, mock_load):
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()
        response = Mock()
        response.deviceIdentifier = 1001
        response.objectIdentifier = ("analogInput", 1)
        app.request = AsyncMock(return_value=response)

        asyncio.run(scanner._bacpypes3_who_has(app, Mock(), "TestObject", 5.0))
        scanner.logger.success.assert_called()

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_who_has_timeout(self, mock_load):
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_who_has(app, Mock(), "TestObject", 5.0))
        scanner.logger.display.assert_called()


class TestEnumBBMD(unittest.TestCase):
    """Test _bacpypes3_enum_bbmd."""

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_bbmd_found(self, mock_load):
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=Mock())

        asyncio.run(scanner._bacpypes3_enum_bbmd(app, Mock(), 5.0))
        scanner.logger.success.assert_called()

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_bbmd_not_found(self, mock_load):
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=None)

        asyncio.run(scanner._bacpypes3_enum_bbmd(app, Mock(), 5.0))
        scanner.logger.display.assert_called()


class TestBBMDInjection(unittest.TestCase):
    """Test _bacpypes3_test_bbmd_injection."""

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_bbmd_injection_all_rejected(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()
        # All requests rejected
        app.request = AsyncMock(return_value=None)

        asyncio.run(scanner._bacpypes3_test_bbmd_injection(app, Mock(), 5.0))
        # Should report findings
        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_bbmd_injection_fd_accepted(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()

        # BDT read returns response, FD registration returns None (accepted)
        responses = [Mock(), None, None]
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_test_bbmd_injection(app, Mock(), 5.0))
        scanner.logger.warning.assert_called()

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_bbmd_injection_timeout(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_test_bbmd_injection(app, Mock(), 5.0))
        scanner.logger.display.assert_called()


class TestScanAllNetworks(unittest.TestCase):
    """Test _bacpypes3_scan_all_networks."""

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_scan_all_no_networks(self, mock_load):
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        scanner.remote_networks = []
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_scan_all_networks(app, Mock(), 5.0))
        scanner.logger.display.assert_called()


if __name__ == "__main__":
    unittest.main()
