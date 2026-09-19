"""
Unit tests for BACnet MonitoringMixin async (bacpypes3) security checks.

Mocks only the bacpypes3 app.request boundary and _load_bacpypes3 type
registry; drives the real schedule/calendar/alarm/trendlog/priority/loop
logic with realistic responses and asserts findings + security_finding
Category enum values (Category.ACCESS_CONTROL).
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
    instance.logger.security_finding = Mock()
    instance.results = {"data": {}}
    instance.host = "192.168.1.100"
    instance.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}
    instance.objects = {
        1001: {
            "analogInput": [1, 2, 3],
            "analogOutput": [1, 2],
            "binaryOutput": [1],
            "analogValue": [1],
            "schedule": [1, 2],
            "calendar": [1],
            "notificationClass": [1, 2],
            "trendLog": [1, 2],
            "lifeSafetyPoint": [1],
            "loop": [1],
        },
    }
    instance.bacnet = Mock()
    return instance


def _pdu_class(name):
    return type(name, (), {})


def _get_mock_types():
    AbortPDU = _pdu_class("AbortPDU")
    ErrorPDU = _pdu_class("ErrorPDU")
    RejectPDU = _pdu_class("RejectPDU")
    Error = _pdu_class("Error")

    return {
        "ReadPropertyRequest": Mock(side_effect=lambda **kw: Mock()),
        "SubscribeCOVRequest": Mock(side_effect=lambda **kw: Mock()),
        "ObjectIdentifier": Mock(side_effect=lambda v: Mock()),
        "PropertyIdentifier": Mock(side_effect=lambda v: Mock()),
        "Unsigned": Mock(side_effect=lambda v: Mock()),
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "ErrorRejectAbortNack": type("ErrorRejectAbortNack", (BaseException,), {}),
        "RejectPDU": RejectPDU,
        "Error": Error,
    }


def _tag_response(tag_data):
    """Build a ReadProperty response carrying a single wire tag with tag_data."""
    response = Mock()
    response.propertyValue = Mock()
    tag = Mock()
    tag.tag_data = tag_data
    response.propertyValue.tagList = [tag]
    return response


def _displayed(logger):
    return " ".join(c.args[0] for c in logger.display.call_args_list)


def _warned(logger):
    return " ".join(c.args[0] for c in logger.warning.call_args_list)


# ---------------------------------------------------------------------------
# _bacpypes3_check_schedules
# ---------------------------------------------------------------------------


class TestCheckSchedules(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_schedule_findings_reported(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=Mock())

        asyncio.run(scanner._bacpypes3_check_schedules(app, "addr", 1001, 5.0))

        warned = _warned(scanner.logger)
        self.assertIn("schedule object(s) accessible", warned)
        self.assertIn("HVAC/lighting timing", warned)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_schedule_default_instances_when_none_enumerated(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}  # no schedule key
        app = AsyncMock()
        app.request = AsyncMock(return_value=Mock())

        asyncio.run(scanner._bacpypes3_check_schedules(app, "addr", 1001, 5.0))

        # Default probe instances are [1,2,3].
        types["ObjectIdentifier"].assert_any_call(("schedule", 1))
        types["ObjectIdentifier"].assert_any_call(("schedule", 3))

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_schedule_none_accessible_on_error_pdu(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())

        asyncio.run(scanner._bacpypes3_check_schedules(app, "addr", 1001, 5.0))

        self.assertIn("No accessible schedule objects", _displayed(scanner.logger))
        scanner.logger.warning.assert_not_called()


# ---------------------------------------------------------------------------
# _bacpypes3_check_calendars
# ---------------------------------------------------------------------------


class TestCheckCalendars(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_calendar_readable(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=Mock())

        asyncio.run(scanner._bacpypes3_check_calendars(app, "addr", 1001, 5.0))

        warned = _warned(scanner.logger)
        self.assertIn("calendar object(s) accessible", warned)
        self.assertIn("exception scheduling", warned)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_calendar_timeout_none_found(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}  # default instances
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_check_calendars(app, "addr", 1001, 5.0))

        self.assertIn("No accessible calendar objects", _displayed(scanner.logger))


# ---------------------------------------------------------------------------
# _bacpypes3_check_alarms
# ---------------------------------------------------------------------------


class TestCheckAlarms(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_notification_class_accessible(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=Mock())

        asyncio.run(scanner._bacpypes3_check_alarms(app, "addr", 1001, 5.0))

        warned = _warned(scanner.logger)
        self.assertIn("notification class(es) accessible", warned)
        self.assertIn("false alarms", warned)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_alarms_none_accessible(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["RejectPDU"]())

        asyncio.run(scanner._bacpypes3_check_alarms(app, "addr", 1001, 5.0))

        self.assertIn("No accessible notification class objects", _displayed(scanner.logger))


# ---------------------------------------------------------------------------
# _bacpypes3_check_trendlogs
# ---------------------------------------------------------------------------


class TestCheckTrendlogs(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_trendlog_records_summed(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"trendLog": [1, 2]}}
        app = AsyncMock()
        # Each trend log reports 100 records.
        app.request = AsyncMock(return_value=_tag_response((100).to_bytes(4, "big")))

        asyncio.run(scanner._bacpypes3_check_trendlogs(app, "addr", 1001, 5.0))

        warned = _warned(scanner.logger)
        self.assertIn("trend log(s) accessible", warned)
        self.assertIn("200 historical records", warned)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_trendlog_none_found(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"trendLog": [1]}}
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_check_trendlogs(app, "addr", 1001, 5.0))

        self.assertIn("No accessible trend log objects", _displayed(scanner.logger))


# ---------------------------------------------------------------------------
# _bacpypes3_check_priority
# ---------------------------------------------------------------------------


class TestCheckPriority(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_priority_array_and_relinquish_readable(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"analogOutput": [1]}}
        app = AsyncMock()
        app.request = AsyncMock(return_value=Mock())

        asyncio.run(scanner._bacpypes3_check_priority(app, "addr", 1001, 5.0))

        warned = _warned(scanner.logger)
        self.assertIn("Priority array accessible", warned)
        self.assertIn("override safety controls", warned)
        displayed = _displayed(scanner.logger)
        self.assertIn("Priority array readable", displayed)
        self.assertIn("Relinquish default readable", displayed)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_priority_no_commandable_objects(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}
        app = AsyncMock()

        asyncio.run(scanner._bacpypes3_check_priority(app, "addr", 1001, 5.0))

        self.assertIn("No commandable objects", _displayed(scanner.logger))
        app.request.assert_not_called()

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_priority_not_accessible(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()
        scanner.objects = {1001: {"analogOutput": [1]}}
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())

        asyncio.run(scanner._bacpypes3_check_priority(app, "addr", 1001, 5.0))

        self.assertIn("Priority arrays not accessible", _displayed(scanner.logger))


# ---------------------------------------------------------------------------
# _bacpypes3_enum_life_safety
# ---------------------------------------------------------------------------


class TestEnumLifeSafety(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_life_safety_finding_category(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"lifeSafetyPoint": [1]}}
        app = AsyncMock()
        app.request = AsyncMock(return_value=_tag_response(b"Fire Alarm Zone 1"))

        asyncio.run(scanner._bacpypes3_enum_life_safety(app, "addr", 1001, 5.0))

        scanner.logger.security_finding.assert_called_once()
        args, kwargs = scanner.logger.security_finding.call_args
        self.assertEqual(args[0], "Insecure configuration")
        self.assertIn("life safety object", kwargs["detail"])
        # The decoded object name appears in the displayed findings.
        self.assertIn("Fire Alarm Zone 1", _displayed(scanner.logger))

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_life_safety_none_found(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}  # default probe instances
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())

        asyncio.run(scanner._bacpypes3_enum_life_safety(app, "addr", 1001, 5.0))

        self.assertIn("No life safety objects found", _displayed(scanner.logger))
        scanner.logger.security_finding.assert_not_called()


# ---------------------------------------------------------------------------
# _bacpypes3_check_life_safety
# ---------------------------------------------------------------------------


class TestCheckLifeSafety(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_life_safety_modes_accessible_finding(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"lifeSafetyPoint": [1]}}
        app = AsyncMock()
        app.request = AsyncMock(return_value=Mock())

        asyncio.run(scanner._bacpypes3_check_life_safety(app, "addr", 1001, 5.0))

        scanner.logger.security_finding.assert_called_once()
        args, kwargs = scanner.logger.security_finding.call_args
        self.assertEqual(args[0], "Insecure configuration")
        self.assertIn("fire/security alarms", kwargs["detail"])

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_life_safety_modes_none_accessible(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()
        scanner.objects = {1001: {"analogInput": [1]}}  # default probe [1,2]
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["AbortPDU"]())

        asyncio.run(scanner._bacpypes3_check_life_safety(app, "addr", 1001, 5.0))

        self.assertIn("No life safety mode properties accessible", _displayed(scanner.logger))
        scanner.logger.security_finding.assert_not_called()


# ---------------------------------------------------------------------------
# _bacpypes3_subscribe_cov
# ---------------------------------------------------------------------------


class TestSubscribeCOV(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_cov_subscribed_then_cancelled(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(cov_duration=1)
        scanner.objects = {1001: {"analogInput": [1]}}
        app = AsyncMock()
        app.request = AsyncMock(return_value=None)  # success + cancel both ok

        asyncio.run(scanner._bacpypes3_subscribe_cov(app, "addr", 1001, 5.0))

        displayed = _displayed(scanner.logger)
        self.assertIn("Subscribed to analogInput:1", displayed)
        self.assertIn("1 subscribed", displayed)
        self.assertIn("COV listening complete", displayed)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_cov_all_rejected_returns_early(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance(cov_duration=1)
        scanner.objects = {1001: {"analogInput": [1]}}
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())

        asyncio.run(scanner._bacpypes3_subscribe_cov(app, "addr", 1001, 5.0))

        displayed = _displayed(scanner.logger)
        self.assertIn("0 subscribed, 1 failed", displayed)
        self.assertIn("may not support COV", displayed)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_cov_keyboard_interrupt_stops_monitoring(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(cov_duration=5)
        scanner.objects = {1001: {"analogInput": [1]}}

        sleeps = {"n": 0}

        async def fake_sleep(_):
            sleeps["n"] += 1
            raise KeyboardInterrupt()

        app = AsyncMock()
        app.request = AsyncMock(return_value=None)

        with patch("asyncio.sleep", side_effect=fake_sleep):
            asyncio.run(scanner._bacpypes3_subscribe_cov(app, "addr", 1001, 5.0))

        displayed = _displayed(scanner.logger)
        self.assertIn("COV monitoring stopped", displayed)
        self.assertIn("COV listening complete", displayed)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_cov_no_control_points(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"device": [1001]}}
        app = AsyncMock()

        asyncio.run(scanner._bacpypes3_subscribe_cov(app, "addr", 1001, 5.0))

        self.assertIn("No control point objects", _displayed(scanner.logger))
        app.request.assert_not_called()

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_cov_timeout_failure(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(cov_duration=1)
        scanner.objects = {1001: {"analogInput": [1]}}
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_subscribe_cov(app, "addr", 1001, 5.0))

        self.assertIn("0 subscribed, 1 failed", _displayed(scanner.logger))


# ---------------------------------------------------------------------------
# _bacpypes3_read_range
# ---------------------------------------------------------------------------


class TestReadRange(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_read_range_reads_records(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance(read_range_count=3)
        scanner.objects = {1001: {"trendLog": [1]}}

        # objectName + totalRecordCount metadata, then record reads.
        name_resp = _tag_response(b"Boiler Temp Log")
        count_resp = _tag_response((3).to_bytes(4, "big"))
        record_resp = Mock()
        record_resp.propertyValue = "<record>"

        responses = [name_resp, count_resp]  # first two metadata props seen
        app = AsyncMock()

        def side_effect(req):
            async def _coro():
                if responses:
                    return responses.pop(0)
                return record_resp

            return _coro()

        app.request = Mock(side_effect=side_effect)

        asyncio.run(scanner._bacpypes3_read_range(app, "addr", 1001, 5.0))

        displayed = _displayed(scanner.logger)
        self.assertIn("Boiler Temp Log", displayed)
        self.assertIn("Total records: 3", displayed)
        self.assertIn("ReadRange Summary", displayed)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_read_range_zero_records_skips(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"trendLog": [1]}}

        name_resp = _tag_response(b"Empty Log")
        count_resp = _tag_response((0).to_bytes(4, "big"))
        responses = [name_resp, count_resp]
        app = AsyncMock()

        def side_effect(req):
            async def _coro():
                if responses:
                    return responses.pop(0)
                # remaining metadata props time out
                raise asyncio.TimeoutError()

            return _coro()

        app.request = Mock(side_effect=side_effect)

        asyncio.run(scanner._bacpypes3_read_range(app, "addr", 1001, 5.0))

        displayed = _displayed(scanner.logger)
        self.assertIn("Total records: 0", displayed)
        self.assertIn("ReadRange Summary: 0 total records", displayed)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_read_range_no_metadata_continues(self, mock_load):
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"trendLog": [1]}}
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_read_range(app, "addr", 1001, 5.0))

        self.assertIn("ReadRange Summary: 0 total records", _displayed(scanner.logger))


# ---------------------------------------------------------------------------
# _bacpypes3_enum_loops (PID controller analysis)
# ---------------------------------------------------------------------------


class TestEnumLoops(unittest.TestCase):
    def _loop_response_factory(self, prop_values):
        """Return an app.request side_effect that maps PropertyIdentifier
        constructor args to wire tag_data so the loop decoder produces values.

        prop_values: dict of property-name -> bytes (or None to time out).
        """
        types = _get_mock_types()

        # Track which property identifier was requested last by capturing the
        # PropertyIdentifier(name) call.
        requested = {"name": None}

        def make_pid(name):
            requested["name"] = name
            return Mock()

        types["PropertyIdentifier"] = Mock(side_effect=make_pid)

        def request_side_effect(req):
            async def _coro():
                name = requested["name"]
                data = prop_values.get(name)
                if data is None:
                    raise asyncio.TimeoutError()
                return _tag_response(data)

            return _coro()

        return types, request_side_effect

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_loops_with_security_concerns(self, mock_load):
        prop_values = {
            "objectName": b"Primary Pressure Loop",
            "presentValue": struct.pack(">f", 55.0),
            "setpoint": struct.pack(">f", 60.0),
            "proportionalConstant": struct.pack(">f", 75.0),  # >50 -> oscillation
            "integralConstant": struct.pack(">f", 1.0),
            "derivativeConstant": struct.pack(">f", 0.1),
            "bias": struct.pack(">f", 2.0),
            "minimumOutput": struct.pack(">f", 0.0),
            "maximumOutput": struct.pack(">f", 300.0),  # range>200 -> wide
            "action": (1).to_bytes(1, "big"),  # reverse
            "priorityForWriting": (5).to_bytes(1, "big"),  # 1-8 -> override
            "setpointReference": b"analogValue:7",
            "outputUnits": (98).to_bytes(1, "big"),
            "updateInterval": (100).to_bytes(2, "big"),
            "covIncrement": struct.pack(">f", 0.5),
            "manipulatedVariableReference": b"analogOutput:3",
            "controlledVariableReference": b"analogInput:2",
        }
        types, side_effect = self._loop_response_factory(prop_values)
        mock_load.return_value = types

        scanner = _create_instance()
        scanner.objects = {1001: {"loop": [1]}}
        app = AsyncMock()
        app.request = Mock(side_effect=side_effect)

        asyncio.run(scanner._bacpypes3_enum_loops(app, "addr", 1001, 5.0))

        # security_finding raised with ACCESS_CONTROL category.
        scanner.logger.security_finding.assert_called_once()
        args, kwargs = scanner.logger.security_finding.call_args
        self.assertEqual(args[0], "Insecure configuration")
        self.assertIn("PID security concern", kwargs["detail"])

        displayed = _displayed(scanner.logger)
        self.assertIn("Primary Pressure Loop", displayed)
        self.assertIn("Loop Summary: 1 loop(s) discovered", displayed)
        # Relationship map rendered for output/input/setpoint refs.
        self.assertIn("Loop Relationship Map", displayed)
        self.assertIn("analogOutput:3", displayed)
        # Reverse action decoded.
        self.assertIn("reverse", displayed)
        # Concern text for high P gain and high-priority write.
        self.assertIn("high proportional gain", displayed)
        self.assertIn("priority 5", displayed)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_loops_clean_no_concerns(self, mock_load):
        prop_values = {
            "objectName": b"Gentle Loop",
            "presentValue": struct.pack(">f", 20.0),
            "setpoint": struct.pack(">f", 21.0),
            "proportionalConstant": struct.pack(">f", 2.0),  # low
            "priorityForWriting": (12).to_bytes(1, "big"),  # >8, safe
            "minimumOutput": struct.pack(">f", 0.0),
            "maximumOutput": struct.pack(">f", 50.0),  # narrow
            "action": (0).to_bytes(1, "big"),  # direct
        }
        types, side_effect = self._loop_response_factory(prop_values)
        mock_load.return_value = types

        scanner = _create_instance()
        scanner.objects = {1001: {"loop": [1]}}
        app = AsyncMock()
        app.request = Mock(side_effect=side_effect)

        asyncio.run(scanner._bacpypes3_enum_loops(app, "addr", 1001, 5.0))

        # A clean loop is discovered but raises no security_finding.
        scanner.logger.security_finding.assert_not_called()
        displayed = _displayed(scanner.logger)
        self.assertIn("Gentle Loop", displayed)
        self.assertIn("direct", displayed)
        self.assertIn("Loop Summary: 1 loop(s) discovered", displayed)

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_loops_decode_error_skips_property(self, mock_load):
        types = _get_mock_types()
        requested = {"name": None}

        def make_pid(name):
            requested["name"] = name
            return Mock()

        types["PropertyIdentifier"] = Mock(side_effect=make_pid)
        mock_load.return_value = types

        class BadBytes:
            """tag_data truthy but .decode() raises -> inner decode except."""

            def __bool__(self):
                return True

            def decode(self, *a, **k):
                raise UnicodeDecodeError("utf-8", b"", 0, 1, "boom")

        def side_effect(req):
            async def _coro():
                name = requested["name"]
                if name == "objectName":
                    # one usable property so the loop is still recorded...
                    return _tag_response(b"Loop A")
                if name == "manipulatedVariableReference":
                    # ...but this string prop fails to decode (exercises the
                    # per-property decode except path without aborting the loop).
                    resp = Mock()
                    resp.propertyValue = Mock()
                    tag = Mock()
                    tag.tag_data = BadBytes()
                    resp.propertyValue.tagList = [tag]
                    return resp
                raise asyncio.TimeoutError()

            return _coro()

        scanner = _create_instance()
        scanner.objects = {1001: {"loop": [1]}}
        app = AsyncMock()
        app.request = Mock(side_effect=side_effect)

        asyncio.run(scanner._bacpypes3_enum_loops(app, "addr", 1001, 5.0))

        # objectName decoded fine; loop discovered despite the bad property.
        self.assertIn("Loop A", _displayed(scanner.logger))
        self.assertIn("Loop Summary: 1 loop(s) discovered", _displayed(scanner.logger))

    @patch("oida.protocols.bacnet.mixins.monitoring._load_bacpypes3")
    def test_loops_none_accessible(self, mock_load):
        types = _get_mock_types()
        mock_load.return_value = types
        scanner = _create_instance()
        scanner.objects = {1001: {"loop": [1]}}
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_enum_loops(app, "addr", 1001, 5.0))

        self.assertIn("No accessible loop objects found", _displayed(scanner.logger))
        scanner.logger.security_finding.assert_not_called()


if __name__ == "__main__":
    unittest.main()
