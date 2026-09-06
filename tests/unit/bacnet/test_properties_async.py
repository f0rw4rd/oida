"""
Unit tests for BACnet PropertiesMixin async (bacpypes3) read/write paths.

Mocks only the bacpypes3 app.request boundary and _load_bacpypes3 type
registry; drives the real property-read/decode logic with realistic
responses and asserts on logger output and returned/decoded values.
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
    instance.logger.security_finding = Mock()
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
            "device": [1001],
        },
    }
    instance.bacnet = Mock()
    return instance


def _pdu_class(name):
    return type(name, (), {})


def _get_mock_types():
    """Realistic stand-ins for the bacpypes3 type registry.

    PDU error classes are real classes so isinstance() checks behave;
    request/identifier constructors return Mocks; cast helpers default
    to CharacterString.
    """
    AbortPDU = _pdu_class("AbortPDU")
    ErrorPDU = _pdu_class("ErrorPDU")
    RejectPDU = _pdu_class("RejectPDU")
    Error = _pdu_class("Error")

    # Datatype constructors are callable Mocks so write-path calls like
    # Unsigned(42) / Real(42.5) / CharacterString("x") are recordable; each
    # carries __name__ so the read-path cast_out(cast_type).__name__ check
    # still routes correctly.
    CharacterString = Mock(name="CharacterString")
    CharacterString.__name__ = "CharacterString"
    Real = Mock(name="Real")
    Real.__name__ = "Real"
    Unsigned = Mock(name="Unsigned")
    Unsigned.__name__ = "Unsigned"

    class AnyAtomic:
        def __init__(self, value=None):
            self.value = value

    return {
        "ReadPropertyRequest": Mock(side_effect=lambda **kw: Mock(name="ReadPropertyRequest")),
        "ReadPropertyMultipleRequest": Mock(
            side_effect=lambda **kw: Mock(name="ReadPropertyMultipleRequest")
        ),
        "ReadAccessSpecification": Mock(side_effect=lambda **kw: Mock()),
        "PropertyReference": Mock(side_effect=lambda **kw: Mock()),
        "WritePropertyRequest": Mock(side_effect=lambda **kw: Mock(name="WritePropertyRequest")),
        "ObjectIdentifier": Mock(side_effect=lambda v: Mock(name="ObjectIdentifier")),
        "PropertyIdentifier": Mock(side_effect=lambda v: Mock(name="PropertyIdentifier")),
        "CharacterString": CharacterString,
        "Real": Real,
        "Unsigned": Unsigned,
        "AnyAtomic": AnyAtomic,
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "RejectPDU": RejectPDU,
        "Error": Error,
    }


def _pv_casting(value, accept_type_name="CharacterString"):
    """Build a propertyValue mock whose cast_out returns `value` only for the
    given cast type name and raises otherwise (mimics datatype mismatch)."""
    pv = Mock()

    def cast_out(cast_type):
        if cast_type.__name__ == accept_type_name:
            return value
        raise ValueError("datatype mismatch")

    pv.cast_out = Mock(side_effect=cast_out)
    return pv


# ---------------------------------------------------------------------------
# _bacpypes3_read_single_property
# ---------------------------------------------------------------------------


class TestReadSingleProperty(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_single_success_charstring(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(read="analogInput:1:objectName")

        response = Mock()
        response.propertyValue = _pv_casting("AHU-1 Supply Temp", "CharacterString")
        app = AsyncMock()
        app.request = AsyncMock(return_value=response)

        asyncio.run(scanner._bacpypes3_read_single_property(app, "192.168.1.100", 5.0))

        scanner.logger.success.assert_called_once()
        msg = scanner.logger.success.call_args[0][0]
        self.assertIn("AHU-1 Supply Temp", msg)
        self.assertIn("analogInput:1:objectName", msg)

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_single_device_type_uses_named_branch(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance(read="device:1001:objectName")

        response = Mock()
        response.propertyValue = _pv_casting("Controller", "CharacterString")
        app = AsyncMock()
        app.request = AsyncMock(return_value=response)

        asyncio.run(scanner._bacpypes3_read_single_property(app, "192.168.1.100", 5.0))

        scanner.logger.success.assert_called_once()
        # "device" is a known lowercase name -> first ObjectIdentifier branch.
        types["ObjectIdentifier"].assert_any_call(("device", 1001))

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_single_str_fallback_when_cast_fails(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(read="analogInput:1:presentValue")

        pv = Mock()
        pv.cast_out = Mock(side_effect=ValueError("nope"))
        pv.__str__ = Mock(return_value="72.5")
        response = Mock()
        response.propertyValue = pv
        app = AsyncMock()
        app.request = AsyncMock(return_value=response)

        asyncio.run(scanner._bacpypes3_read_single_property(app, "192.168.1.100", 5.0))

        scanner.logger.success.assert_called_once()
        self.assertIn("72.5", scanner.logger.success.call_args[0][0])

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_single_error_pdu_warns(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance(read="analogInput:1:presentValue")

        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())

        asyncio.run(scanner._bacpypes3_read_single_property(app, "192.168.1.100", 5.0))

        scanner.logger.warning.assert_called_once()
        self.assertIn("Could not read", scanner.logger.warning.call_args[0][0])

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_single_timeout(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(read="analogInput:1:presentValue")

        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_read_single_property(app, "192.168.1.100", 5.0))

        scanner.logger.fail.assert_called_once()
        self.assertIn("Timeout", scanner.logger.fail.call_args[0][0])

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_single_generic_error(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(read="analogInput:1:presentValue")

        app = AsyncMock()
        app.request = AsyncMock(side_effect=RuntimeError("segmentation refused"))

        asyncio.run(scanner._bacpypes3_read_single_property(app, "192.168.1.100", 5.0))

        scanner.logger.fail.assert_called_once()
        self.assertIn("Error reading", scanner.logger.fail.call_args[0][0])

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_single_numeric_object_type_resolves(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        # "0" is not a named type -> int-parse branch -> OBJECT_TYPES[0].
        scanner = _create_instance(read="0:1:presentValue")

        response = Mock()
        response.propertyValue = _pv_casting("ok", "CharacterString")
        app = AsyncMock()
        app.request = AsyncMock(return_value=response)

        asyncio.run(scanner._bacpypes3_read_single_property(app, "192.168.1.100", 5.0))

        # numeric type id 0 maps to analogInput.
        types["ObjectIdentifier"].assert_any_call(("analogInput", 1))
        scanner.logger.success.assert_called_once()

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_single_invalid_spec_returns_early(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(read="garbage")

        app = AsyncMock()
        app.request = AsyncMock()

        asyncio.run(scanner._bacpypes3_read_single_property(app, "192.168.1.100", 5.0))

        app.request.assert_not_called()
        scanner.logger.fail.assert_called()


# ---------------------------------------------------------------------------
# _bacpypes3_read_present_values
# ---------------------------------------------------------------------------


class TestReadPresentValues(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_present_values_no_objects_for_device(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}

        app = AsyncMock()
        asyncio.run(scanner._bacpypes3_read_present_values(app, "192.168.1.100", 9999, 5.0))

        scanner.logger.warning.assert_called_once()
        self.assertIn("No objects enumerated", scanner.logger.warning.call_args[0][0])

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_present_values_real_value_displayed(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}

        response = Mock()
        response.propertyValue = _pv_casting(72.5, "Real")
        app = AsyncMock()
        app.request = AsyncMock(return_value=response)

        asyncio.run(scanner._bacpypes3_read_present_values(app, "192.168.1.100", 1001, 5.0))

        joined = " ".join(c.args[0] for c in scanner.logger.display.call_args_list)
        self.assertIn("analogInput:1 = 72.5", joined)

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_present_values_skips_non_control_points(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        # "schedule" is not a control point and not "device" -> skipped.
        scanner.objects = {1001: {"schedule": [1, 2]}}

        app = AsyncMock()
        app.request = AsyncMock(return_value=Mock())

        asyncio.run(scanner._bacpypes3_read_present_values(app, "192.168.1.100", 1001, 5.0))

        app.request.assert_not_called()

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_present_values_timeout_continues(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1, 2]}}

        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_read_present_values(app, "192.168.1.100", 1001, 5.0))

        # Header still displayed, no crash.
        scanner.logger.display.assert_called()


# ---------------------------------------------------------------------------
# _render_bacnet_value (pure decode logic, real bacpypes3 types)
# ---------------------------------------------------------------------------


class TestRenderBacnetValue(unittest.TestCase):
    def test_render_none(self):
        scanner = _create_instance()
        self.assertIsNone(scanner._render_bacnet_value(None))

    def test_render_enumerated_symbolic(self):
        from bacpypes3.basetypes import BinaryPV

        scanner = _create_instance()
        rendered = scanner._render_bacnet_value(BinaryPV("active"))
        self.assertEqual(rendered, "active")

    def test_render_status_flags_named(self):
        from bacpypes3.basetypes import StatusFlags

        scanner = _create_instance()
        # in-alarm + fault set.
        rendered = scanner._render_bacnet_value(StatusFlags([1, 1, 0, 0]))
        self.assertIn("in-alarm", rendered)
        self.assertIn("fault", rendered)

    def test_render_status_flags_normal(self):
        from bacpypes3.basetypes import StatusFlags

        scanner = _create_instance()
        rendered = scanner._render_bacnet_value(StatusFlags([0, 0, 0, 0]))
        self.assertEqual(rendered, "normal")

    def test_render_sentinel_dropped(self):
        scanner = _create_instance()
        self.assertIsNone(scanner._render_bacnet_value("-no object class-"))
        self.assertIsNone(scanner._render_bacnet_value("   "))

    def test_render_plain_string(self):
        scanner = _create_instance()
        self.assertEqual(scanner._render_bacnet_value("AHU-1"), "AHU-1")

    def test_render_numeric_native(self):
        scanner = _create_instance()
        self.assertEqual(scanner._render_bacnet_value(42), 42)
        self.assertEqual(scanner._render_bacnet_value(3.5), 3.5)
        self.assertEqual(scanner._render_bacnet_value(True), True)

    def test_render_any_atomic_dropped(self):
        scanner = _create_instance()
        any_atomic = type("AnyAtomic", (), {})()
        self.assertIsNone(scanner._render_bacnet_value(any_atomic))

    def test_render_constructed_to_json(self):
        from bacpypes3.basetypes import DateRange
        from bacpypes3.primitivedata import Date

        scanner = _create_instance()
        dr = DateRange(startDate=Date("2024-01-01"), endDate=Date("2024-12-31"))
        rendered = scanner._render_bacnet_value(dr)
        # sequence_to_json yields a dict.
        self.assertIsInstance(rendered, dict)

    def test_render_unresolvable_object_to_str(self):
        scanner = _create_instance()

        class Weird:
            def __str__(self):
                return "weird-repr"

        rendered = scanner._render_bacnet_value(Weird())
        self.assertEqual(rendered, "weird-repr")


# ---------------------------------------------------------------------------
# _bacpypes3_read_one (two-tier: app.read_property -> raw fallback)
# ---------------------------------------------------------------------------


class TestReadOne(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_one_tier1_decoded(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()

        app = Mock()
        app.read_property = AsyncMock(return_value="AHU-1")
        result = asyncio.run(
            scanner._bacpypes3_read_one(app, "addr", "analogInput", 1, "objectName", 5.0)
        )
        self.assertEqual(result, "AHU-1")

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_one_timeout_returns_none(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()

        app = Mock()
        app.read_property = AsyncMock(side_effect=asyncio.TimeoutError())
        result = asyncio.run(
            scanner._bacpypes3_read_one(app, "addr", "analogInput", 1, "presentValue", 5.0)
        )
        self.assertIsNone(result)

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_one_falls_back_to_raw(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()

        # tier 1 raises (proprietary type) -> raw read path with a Real value.
        app = Mock()
        app.read_property = AsyncMock(side_effect=RuntimeError("no object class"))
        raw_response = Mock()
        raw_response.propertyValue = _pv_casting(3.14, "Real")
        app.request = AsyncMock(return_value=raw_response)

        result = asyncio.run(
            scanner._bacpypes3_read_one(app, "addr", "proprietary", 1, "vendorProp", 5.0)
        )
        self.assertEqual(result, 3.14)

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_read_one_tier1_sentinel_then_raw(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()

        # tier 1 returns sentinel (render -> None) -> fall through to raw.
        app = Mock()
        app.read_property = AsyncMock(return_value="-no object class-")
        raw_response = Mock()
        raw_response.propertyValue = _pv_casting(99, "Unsigned")
        app.request = AsyncMock(return_value=raw_response)

        result = asyncio.run(
            scanner._bacpypes3_read_one(app, "addr", "proprietary", 5, "vendorProp", 5.0)
        )
        self.assertEqual(result, 99)


# ---------------------------------------------------------------------------
# _bacpypes3_read_raw
# ---------------------------------------------------------------------------


class TestReadRaw(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_raw_error_pdu_returns_none(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()

        app = AsyncMock()
        app.request = AsyncMock(return_value=types["AbortPDU"]())
        result = asyncio.run(
            scanner._bacpypes3_read_raw(app, "addr", "analogInput", 1, "presentValue", 5.0)
        )
        self.assertIsNone(result)

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_raw_timeout_returns_none(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()

        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())
        result = asyncio.run(
            scanner._bacpypes3_read_raw(app, "addr", "analogInput", 1, "presentValue", 5.0)
        )
        self.assertIsNone(result)

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_raw_no_propertyvalue_returns_none(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()

        response = Mock(spec=[])  # no propertyValue attr
        app = AsyncMock()
        app.request = AsyncMock(return_value=response)
        result = asyncio.run(
            scanner._bacpypes3_read_raw(app, "addr", "analogInput", 1, "presentValue", 5.0)
        )
        self.assertIsNone(result)

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_raw_primary_cast_real(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()

        response = Mock()
        response.propertyValue = _pv_casting(1.5, "Real")
        app = AsyncMock()
        app.request = AsyncMock(return_value=response)
        result = asyncio.run(
            scanner._bacpypes3_read_raw(app, "addr", "analogInput", 1, "presentValue", 5.0)
        )
        self.assertEqual(result, 1.5)

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_raw_broad_octetstring_hex(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()

        # primary casts (Real/Unsigned/CharacterString) all fail; broad
        # OctetString cast yields bytes -> hex string.
        pv = Mock()
        from bacpypes3.primitivedata import OctetString

        def cast_out(cast_type):
            if cast_type is OctetString:
                return b"\xde\xad\xbe\xef"
            raise ValueError("mismatch")

        pv.cast_out = Mock(side_effect=cast_out)
        response = Mock()
        response.propertyValue = pv
        app = AsyncMock()
        app.request = AsyncMock(return_value=response)

        result = asyncio.run(
            scanner._bacpypes3_read_raw(app, "addr", "proprietary", 1, "vendorProp", 5.0)
        )
        self.assertEqual(result, "deadbeef")

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_raw_all_casts_fail_returns_none(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()

        pv = Mock()
        pv.cast_out = Mock(side_effect=ValueError("undecodable"))
        response = Mock()
        response.propertyValue = pv
        app = AsyncMock()
        app.request = AsyncMock(return_value=response)

        result = asyncio.run(
            scanner._bacpypes3_read_raw(app, "addr", "proprietary", 1, "vendorProp", 5.0)
        )
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# _bacpypes3_write_single_property
# ---------------------------------------------------------------------------


class TestWriteSingleProperty(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_write_requires_confirm(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(write="analogValue:1:presentValue:42", confirm=False)

        app = AsyncMock()
        asyncio.run(scanner._bacpypes3_write_single_property(app, "addr", 5.0))

        scanner.logger.fail.assert_called_once()
        self.assertIn("--confirm", scanner.logger.fail.call_args[0][0])
        app.request.assert_not_called()

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_write_int_success(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance(write="analogValue:1:presentValue:42", confirm=True)

        app = AsyncMock()
        app.request = AsyncMock(return_value=None)  # no error PDU -> success
        asyncio.run(scanner._bacpypes3_write_single_property(app, "addr", 5.0))

        scanner.logger.success.assert_called_once()
        self.assertIn("Wrote 42", scanner.logger.success.call_args[0][0])
        # int value -> AnyAtomic(Unsigned(...))
        types["Unsigned"].assert_called_with(42)

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_write_float_uses_real(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance(write="analogValue:1:presentValue:42.5", confirm=True)

        app = AsyncMock()
        app.request = AsyncMock(return_value=None)
        asyncio.run(scanner._bacpypes3_write_single_property(app, "addr", 5.0))

        types["Real"].assert_called_with(42.5)
        scanner.logger.success.assert_called_once()

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_write_string_uses_charstring(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance(write="characterstringValue:1:presentValue:hello", confirm=True)

        app = AsyncMock()
        app.request = AsyncMock(return_value=None)
        asyncio.run(scanner._bacpypes3_write_single_property(app, "addr", 5.0))

        types["CharacterString"].assert_called_with("hello")
        scanner.logger.success.assert_called_once()

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_write_with_priority(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance(write="analogOutput:1:presentValue:50", confirm=True, priority=8)

        app = AsyncMock()
        app.request = AsyncMock(return_value=None)
        asyncio.run(scanner._bacpypes3_write_single_property(app, "addr", 5.0))

        # priority routed into the WritePropertyRequest kwargs as Unsigned(8).
        types["Unsigned"].assert_any_call(8)
        scanner.logger.success.assert_called_once()

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_write_rejected_by_error_pdu(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance(write="analogValue:1:presentValue:42", confirm=True)

        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())
        asyncio.run(scanner._bacpypes3_write_single_property(app, "addr", 5.0))

        scanner.logger.fail.assert_called_once()
        self.assertIn("rejected", scanner.logger.fail.call_args[0][0])

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_write_timeout_warns(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(write="analogValue:1:presentValue:42", confirm=True)

        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())
        asyncio.run(scanner._bacpypes3_write_single_property(app, "addr", 5.0))

        scanner.logger.warning.assert_called_once()
        self.assertIn("timeout", scanner.logger.warning.call_args[0][0].lower())

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_write_invalid_spec_returns_early(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(write="bad:spec", confirm=True)

        app = AsyncMock()
        asyncio.run(scanner._bacpypes3_write_single_property(app, "addr", 5.0))
        app.request.assert_not_called()


# ---------------------------------------------------------------------------
# _bacpypes3_read_property_multiple (RPM)
# ---------------------------------------------------------------------------


class TestReadPropertyMultiple(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_rpm_no_objects_for_device(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()

        app = AsyncMock()
        asyncio.run(scanner._bacpypes3_read_property_multiple(app, "addr", 9999, 5.0))
        scanner.logger.warning.assert_called_once()

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_rpm_decodes_results(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}

        # Build a nested RPM response: one access result, two prop results.
        rr_name = Mock()
        rr_name.propertyValue = _pv_casting("AHU-1", "CharacterString")
        pr_name = Mock()
        pr_name.propertyIdentifier = "objectName"
        pr_name.readResult = rr_name

        rr_err = Mock(spec=["propertyAccessError"])
        rr_err.propertyAccessError = "unknown-property"
        pr_err = Mock(spec=["propertyIdentifier", "readResult"])
        pr_err.propertyIdentifier = "description"
        pr_err.readResult = rr_err

        access_result = Mock()
        access_result.listOfResults = [pr_name, pr_err]

        response = Mock()
        response.listOfReadAccessResults = [access_result]

        app = AsyncMock()
        app.request = AsyncMock(return_value=response)

        asyncio.run(scanner._bacpypes3_read_property_multiple(app, "addr", 1001, 5.0))

        joined = " ".join(c.args[0] for c in scanner.logger.display.call_args_list)
        self.assertIn("AHU-1", joined)
        self.assertIn("objectName=", joined)
        self.assertIn("RPM Summary: 1 objects read", joined)

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_rpm_abort_breaks_with_tip(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1, 2]}}

        app = AsyncMock()
        app.request = AsyncMock(return_value=types["AbortPDU"]())

        asyncio.run(scanner._bacpypes3_read_property_multiple(app, "addr", 1001, 5.0))

        joined = " ".join(c.args[0] for c in scanner.logger.display.call_args_list)
        self.assertIn("RPM Summary", joined)
        self.assertIn("don't support RPM", joined)

    @patch("oida.protocols.bacnet.mixins.properties._load_bacpypes3")
    def test_rpm_timeout_counts_failure(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}

        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_read_property_multiple(app, "addr", 1001, 5.0))

        joined = " ".join(c.args[0] for c in scanner.logger.display.call_args_list)
        self.assertIn("0 objects read, 1 failed", joined)


if __name__ == "__main__":
    unittest.main()
