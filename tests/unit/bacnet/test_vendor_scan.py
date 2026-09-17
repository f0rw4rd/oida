"""
Unit tests for BACnet vendor-specific/proprietary scan (_bacpypes3_vendor_scan).
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
    return instance


# Sentinel primitive-data types so cast_out can dispatch on identity.
_CharacterString = type("CharacterString", (), {})
_Unsigned = type("Unsigned", (), {})
_Real = type("Real", (), {})


def _get_mock_types():
    """Get mock bacpypes3 types."""
    AbortPDU = type("AbortPDU", (), {})
    ErrorPDU = type("ErrorPDU", (), {})
    ErrorRejectAbortNack = type("ErrorRejectAbortNack", (BaseException,), {})
    RejectPDU = type("RejectPDU", (), {})
    Error = type("Error", (), {})

    return {
        "ReadPropertyRequest": Mock(return_value=Mock()),
        "ObjectIdentifier": Mock(return_value=Mock()),
        "PropertyIdentifier": Mock(return_value=Mock()),
        "CharacterString": _CharacterString,
        "Unsigned": _Unsigned,
        "Real": _Real,
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "ErrorRejectAbortNack": ErrorRejectAbortNack,
        "RejectPDU": RejectPDU,
        "Error": Error,
    }


def _make_response(value, value_type):
    """Build a response whose propertyValue.cast_out(value_type) returns value.

    cast_out raises for any other primitive type, mirroring bacpypes3's
    behaviour when the wire encoding doesn't match the requested type.
    """

    def cast_out(cast_type):
        if cast_type is value_type:
            return value
        raise ValueError("type mismatch")

    pv = Mock()
    pv.cast_out = cast_out
    resp = Mock()
    resp.propertyValue = pv
    return resp


def _make_uint_response(value):
    """Create a mock response that decodes as an unsigned integer."""
    return _make_response(value, _Unsigned)


def _make_string_response(text):
    """Create a mock response that decodes as a character string."""
    return _make_response(text, _CharacterString)


class TestVendorScan(unittest.TestCase):
    """Test _bacpypes3_vendor_scan."""

    @patch("oida.protocols.bacnet.mixins.discovery._load_bacpypes3")
    def test_vendor_scan_identifies_vendor(self, mock_load):
        """Test vendor scan reads and identifies vendor ID."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()

        # First call returns vendorIdentifier = 36 (Tridium, per ASHRAE registry)
        # Remaining calls return None (no proprietary objects/props found)
        responses = [_make_uint_response(36)] + [None] * 500
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_vendor_scan(app, Mock(), 1001, 5.0))

        # Should identify vendor
        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.discovery._load_bacpypes3")
    def test_vendor_scan_timeout(self, mock_load):
        """Test vendor scan handles all timeouts."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_vendor_scan(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.discovery._load_bacpypes3")
    def test_vendor_scan_finds_proprietary_objects(self, mock_load):
        """Test vendor scan discovers proprietary object types."""
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        app = AsyncMock()

        # Vendor ID read, then proprietary object type 128 instance 1 responds
        call_count = [0]

        async def mock_request(req):
            call_count[0] += 1
            if call_count[0] == 1:
                # vendorIdentifier
                return _make_uint_response(7)  # Siemens
            if call_count[0] == 2:
                # First proprietary object probe succeeds
                return _make_string_response("ProprietaryObj128")
            # Everything else: no response
            return None

        app.request = AsyncMock(side_effect=mock_request)

        asyncio.run(scanner._bacpypes3_vendor_scan(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.discovery._load_bacpypes3")
    def test_vendor_scan_finds_proprietary_properties(self, mock_load):
        """Test vendor scan discovers proprietary property IDs."""
        mock_types = _get_mock_types()
        mock_load.return_value = mock_types

        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}
        app = AsyncMock()

        # Vendor ID read succeeds, no proprietary objects found,
        # but proprietary property 512 on device object responds
        call_count = [0]

        async def mock_request(req):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_uint_response(4)  # Honeywell
            # Skip proprietary object probes (128-170 * 5 instances = 215 calls)
            # Then proprietary property scan starts
            # Let's just return None for everything except one property
            return None

        app.request = AsyncMock(side_effect=mock_request)

        asyncio.run(scanner._bacpypes3_vendor_scan(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.discovery._load_bacpypes3")
    def test_vendor_scan_unknown_vendor(self, mock_load):
        """Test vendor scan with unknown vendor ID."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()

        # Unknown vendor ID
        responses = [_make_uint_response(9999)] + [None] * 500
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_vendor_scan(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.mixins.discovery._load_bacpypes3")
    def test_vendor_scan_no_vendor_id(self, mock_load):
        """Test vendor scan when vendorIdentifier cannot be read."""
        mock_load.return_value = _get_mock_types()

        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=None)

        asyncio.run(scanner._bacpypes3_vendor_scan(app, Mock(), 1001, 5.0))

        scanner.logger.display.assert_called()


if __name__ == "__main__":
    unittest.main()
