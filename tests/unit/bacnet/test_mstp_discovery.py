"""
Unit tests for BACnet MS/TP device discovery (_bacpypes3_discover_mstp).
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
    instance.objects = {}
    instance.bacnet = Mock()
    instance.host_info = {}
    return instance


def _get_mock_types():
    """Get mock bacpypes3 types for MS/TP discovery."""
    AbortPDU = type("AbortPDU", (), {})
    ErrorPDU = type("ErrorPDU", (), {})
    RejectPDU = type("RejectPDU", (), {})
    Error = type("Error", (), {})

    return {
        "ReadPropertyRequest": Mock(return_value=Mock()),
        "ObjectIdentifier": Mock(return_value=Mock()),
        "PropertyIdentifier": Mock(return_value=Mock()),
        "WhoIsRequest": Mock(return_value=Mock()),
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "RejectPDU": RejectPDU,
        "Error": Error,
        "Address": Mock(return_value=Mock()),
    }


def _make_uint_tag(value):
    """Create a mock tag with unsigned integer data."""
    tag = Mock()
    tag.tag_data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return tag


def _make_string_tag(text):
    """Create a mock tag with string data."""
    tag = Mock()
    tag.tag_data = text.encode("utf-8")
    return tag


def _make_bytes_tag(data):
    """Create a mock tag with raw bytes."""
    tag = Mock()
    tag.tag_data = data
    return tag


class TestMSTPDiscovery(unittest.TestCase):
    """Test _bacpypes3_discover_mstp."""

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_mstp_no_network_ports(self, mock_load):
        """Test MS/TP discovery when no network ports found."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()

        # numberOfNetworkPorts = None, and all port probes return None
        app.request = AsyncMock(return_value=None)

        asyncio.run(scanner._bacpypes3_discover_mstp(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_mstp_only_ip_ports(self, mock_load):
        """Test MS/TP discovery when only BACnet/IP ports exist (no MS/TP)."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()

        call_count = [0]

        async def mock_request(req):
            call_count[0] += 1
            # numberOfNetworkPorts = 1
            if call_count[0] == 1:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(1)]))
            # Port 1 objectName
            if call_count[0] == 2:
                return Mock(propertyValue=Mock(tagList=[_make_string_tag("BACnet/IP")]))
            # Port 1 networkType = 5 (BACnet/IP, not MS/TP)
            if call_count[0] == 3:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(5)]))
            # Port 1 networkNumber = 1
            if call_count[0] == 4:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(1)]))
            # Port 1 macAddress
            if call_count[0] == 5:
                return Mock(propertyValue=Mock(tagList=[_make_bytes_tag(b"\xc0\xa8\x01\x64")]))
            # Port 2+ objectName = None (no more ports)
            return None

        app.request = AsyncMock(side_effect=mock_request)

        asyncio.run(scanner._bacpypes3_discover_mstp(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_mstp_timeout(self, mock_load):
        """Test MS/TP discovery handles all timeouts."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_discover_mstp(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_mstp_port_found_no_network_number(self, mock_load):
        """Test MS/TP discovery when MS/TP port has no network number."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()

        call_count = [0]

        async def mock_request(req):
            call_count[0] += 1
            # numberOfNetworkPorts = 1
            if call_count[0] == 1:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(1)]))
            # Port 1 objectName
            if call_count[0] == 2:
                return Mock(propertyValue=Mock(tagList=[_make_string_tag("MS/TP Port")]))
            # Port 1 networkType = 2 (MS/TP)
            if call_count[0] == 3:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(2)]))
            # Port 1 networkNumber = None
            if call_count[0] == 4:
                return None
            # Port 1 macAddress
            if call_count[0] == 5:
                return Mock(propertyValue=Mock(tagList=[_make_bytes_tag(b"\x01")]))
            # MS/TP properties: maxMaster, maxInfoFrames, slaveProxy, etc.
            if call_count[0] in (6, 7, 8, 9, 10, 11):
                return None
            # Port 2+ objectName = None (no more ports)
            return None

        app.request = AsyncMock(side_effect=mock_request)

        asyncio.run(scanner._bacpypes3_discover_mstp(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_mstp_with_mstp_port(self, mock_load):
        """Test MS/TP discovery finds an MS/TP port and attempts segment scan."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()

        call_count = [0]

        async def mock_request(req):
            call_count[0] += 1
            # numberOfNetworkPorts
            if call_count[0] == 1:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(2)]))
            # Port 1 objectName
            if call_count[0] == 2:
                return Mock(propertyValue=Mock(tagList=[_make_string_tag("BACnet/IP")]))
            # Port 1 networkType = 5 (BACnet/IP)
            if call_count[0] == 3:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(5)]))
            # Port 1 networkNumber = 1
            if call_count[0] == 4:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(1)]))
            # Port 1 macAddress
            if call_count[0] == 5:
                return None
            # Port 2 objectName
            if call_count[0] == 6:
                return Mock(propertyValue=Mock(tagList=[_make_string_tag("MS/TP Trunk")]))
            # Port 2 networkType = 2 (MS/TP)
            if call_count[0] == 7:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(2)]))
            # Port 2 networkNumber = 100
            if call_count[0] == 8:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(100)]))
            # Port 2 macAddress = 0x01 (MS/TP MAC)
            if call_count[0] == 9:
                return Mock(propertyValue=Mock(tagList=[_make_bytes_tag(b"\x01")]))
            # MS/TP config: maxMaster=127
            if call_count[0] == 10:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(127)]))
            # maxInfoFrames
            if call_count[0] == 11:
                return Mock(propertyValue=Mock(tagList=[_make_uint_tag(1)]))
            # slaveProxyEnable, manualSlaveAddressBinding, autoSlaveDiscovery, slavePollTimeout
            if call_count[0] in (12, 13, 14, 15):
                return None
            # Port 3+ = None
            if call_count[0] == 16:
                return None
            # Port 4+ = None
            if call_count[0] == 17:
                return None
            # Who-Is on MS/TP segment and subsequent reads all timeout
            raise asyncio.TimeoutError()

        app.request = AsyncMock(side_effect=mock_request)

        asyncio.run(scanner._bacpypes3_discover_mstp(app, Mock(), 1001, 5.0))

        scanner.logger.success.assert_called()


if __name__ == "__main__":
    unittest.main()
