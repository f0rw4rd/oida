"""
Regression tests for the async bacpypes3 write path datatype coercion.

Bug: _bacpypes3_write_single_property parsed every numeric value with
float() and always encoded the result as Real, so an integer / enumeration
value like '1' (e.g. a binaryValue/multistateValue presentValue) was sent
as Real(1.0) and rejected by spec-compliant devices. The synchronous
_handle_write path demotes integer-valued floats to int; this async path
must agree on the wire type.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from oida.protocols.bacnet import bacnet
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _get_mock_types():
    AbortPDU = type("AbortPDU", (), {})
    ErrorPDU = type("ErrorPDU", (), {})
    ErrorRejectAbortNack = type("ErrorRejectAbortNack", (BaseException,), {})
    RejectPDU = type("RejectPDU", (), {})
    Error = type("Error", (), {})

    return {
        "WritePropertyRequest": Mock(return_value=Mock()),
        "ObjectIdentifier": Mock(return_value=Mock()),
        "PropertyIdentifier": Mock(return_value=Mock()),
        "Real": Mock(return_value=Mock(name="Real")),
        "Unsigned": Mock(return_value=Mock(name="Unsigned")),
        "CharacterString": Mock(return_value=Mock(name="CharacterString")),
        "AnyAtomic": Mock(return_value=Mock(name="AnyAtomic")),
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "ErrorRejectAbortNack": ErrorRejectAbortNack,
        "RejectPDU": RejectPDU,
        "Error": Error,
    }


def _make_scanner(write_spec):
    scanner = object.__new__(bacnet)
    scanner.args = create_mock_args(write=write_spec, confirm=True, priority=None)
    scanner.logger = create_mock_logger()
    scanner.host = "192.168.1.100"
    scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}
    return scanner


def _run_write(scanner, types):
    app = AsyncMock()
    app.request = AsyncMock(return_value=None)  # None => success (not an error PDU)
    target_addr = Mock()
    with patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3", return_value=types):
        asyncio.run(scanner._bacpypes3_write_single_property(app, target_addr, 5.0))
    return app


class TestAsyncWriteDatatypeCoercion(unittest.TestCase):
    def test_integer_value_not_encoded_as_real(self):
        """Writing '1' to an enumeration must use Unsigned, never Real."""
        types = _get_mock_types()
        scanner = _make_scanner("binaryValue:1:presentValue:1")

        _run_write(scanner, types)

        types["Real"].assert_not_called()
        types["Unsigned"].assert_called_once_with(1)

    def test_float_value_still_encoded_as_real(self):
        """A genuine fractional value stays Real."""
        types = _get_mock_types()
        scanner = _make_scanner("analogValue:1:presentValue:1.5")

        _run_write(scanner, types)

        types["Real"].assert_called_once_with(1.5)
        types["Unsigned"].assert_not_called()

    def test_string_value_encoded_as_characterstring(self):
        """A non-numeric value stays a CharacterString."""
        types = _get_mock_types()
        scanner = _make_scanner("characterstringValue:1:presentValue:hello")

        _run_write(scanner, types)

        types["CharacterString"].assert_called_once_with("hello")
        types["Real"].assert_not_called()
        types["Unsigned"].assert_not_called()


if __name__ == "__main__":
    unittest.main()
