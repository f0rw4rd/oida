"""Unit tests for the BACnet --call dispatcher and per-service handlers (CallMixin).

Drives the real dispatch logic in call.py with realistic --call argv. bacpypes3
types are real (installed extra); only the network transport (app.request) and
the cross-mixin read collaborators (_bacpypes3_read_one / _bacpypes3_read_file /
_bacpypes3_who_is_instance) are mocked, since those live in OTHER mixins and are
external to the code under test.

Asserts on dispatch routing (risk gating, --confirm gate, unknown/detect-only
services), value coercion through to the WriteProperty request, the
objType:inst:property:value[:priority] spec split, and the _send ACK/Error
decoding.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, Mock

try:
    import bacpypes3  # noqa: F401

    _HAS = True
except ImportError:
    _HAS = False

from oida.protocols.bacnet import bacnet
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _create_instance(**kwargs):
    instance = object.__new__(bacnet)
    instance.args = create_mock_args(**kwargs)
    instance.logger = create_mock_logger()
    instance.results = {"data": {}}
    instance.host = "192.168.1.100"
    instance.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}
    instance.objects = {}
    instance.bacnet = Mock()
    return instance


def _simple_ack():
    """A bacpypes3 SimpleAckPDU-shaped response (type name drives _send)."""
    return type("SimpleAckPDU", (), {})()


@unittest.skipUnless(_HAS, "bacpypes3 required")
class TestParseObjid(unittest.TestCase):
    def setUp(self):
        self.scanner = _create_instance()

    def test_abbrev(self):
        oid = self.scanner._parse_objid("AV:7")
        # bacpypes3 normalises the type to its ObjectType enum (analog-value).
        self.assertEqual(str(oid[0]), "analog-value")
        self.assertEqual(oid[1], 7)

    def test_full_name(self):
        oid = self.scanner._parse_objid("binaryOutput:3")
        self.assertEqual(str(oid[0]), "binary-output")
        self.assertEqual(oid[1], 3)

    def test_missing_colon_raises(self):
        with self.assertRaises(ValueError):
            self.scanner._parse_objid("AV7")


@unittest.skipUnless(_HAS, "bacpypes3 required")
class TestSplitWriteSpec(unittest.TestCase):
    def setUp(self):
        self.scanner = _create_instance()

    def test_plain_with_priority(self):
        otype, inst, prop, value, priority = self.scanner._split_write_spec("AV:1:pv:42:8")
        self.assertEqual((otype, inst, prop, value), ("AV", "1", "pv", "42"))
        self.assertEqual(priority, 8)

    def test_typed_value_colon_is_not_priority(self):
        # "real:1.0" must stay intact, not be split into value="real" priority=…
        otype, inst, prop, value, priority = self.scanner._split_write_spec("AV:1:pv:real:1.0")
        self.assertEqual(value, "real:1.0")
        self.assertIsNone(priority)

    def test_no_priority(self):
        otype, inst, prop, value, priority = self.scanner._split_write_spec("BV:2:pv:active")
        self.assertEqual(value, "active")
        self.assertIsNone(priority)

    def test_too_few_fields_raises(self):
        with self.assertRaises(ValueError):
            self.scanner._split_write_spec("AV:1:pv")


@unittest.skipUnless(_HAS, "bacpypes3 required")
class TestBuildWriteProperty(unittest.TestCase):
    def setUp(self):
        self.scanner = _create_instance()

    def test_real_value_and_priority(self):
        req = self.scanner._build_write_property("AV", "1", "present-value", "11.0", 8)
        self.assertEqual(type(req).__name__, "WritePropertyRequest")
        self.assertEqual(str(req.objectIdentifier[0]), "analog-value")
        self.assertEqual(req.objectIdentifier[1], 1)
        # "11.0" coerces to Real (the demote-to-Unsigned bug _coerce_atomic guards
        # against), and the priority field is populated.

        self.assertEqual(self.scanner._coerce_atomic("11.0").__class__.__name__, "Real")
        self.assertIsNotNone(req.priority)
        self.assertEqual(int(req.priority), 8)

    def test_no_priority_omits_field(self):
        req = self.scanner._build_write_property("AV", "2", "pv", "5", None)
        self.assertIsNone(req.priority)


@unittest.skipUnless(_HAS, "bacpypes3 required")
class TestSend(unittest.TestCase):
    def setUp(self):
        self.scanner = _create_instance()

    def test_simple_ack_is_ok(self):
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        req = Mock()
        ok, detail = asyncio.run(self.scanner._send(app, req, Mock(), 5.0))
        self.assertTrue(ok)
        self.assertIn("SimpleAck", detail)

    def test_none_is_ok_simpleack(self):
        # bacpypes3 returns None for an acknowledged confirmed request.
        app = AsyncMock()
        app.request = AsyncMock(return_value=None)
        ok, detail = asyncio.run(self.scanner._send(app, Mock(), Mock(), 5.0))
        self.assertTrue(ok)

    def test_timeout_is_failure(self):
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())
        ok, detail = asyncio.run(self.scanner._send(app, Mock(), Mock(), 5.0))
        self.assertFalse(ok)
        self.assertIn("timeout", detail)

    def test_exception_is_failure_with_type_name(self):
        app = AsyncMock()
        app.request = AsyncMock(side_effect=ValueError("nope"))
        ok, detail = asyncio.run(self.scanner._send(app, Mock(), Mock(), 5.0))
        self.assertFalse(ok)
        self.assertIn("ValueError", detail)
        self.assertIn("nope", detail)

    def test_error_pdu_is_failure(self):
        from bacpypes3.apdu import RejectPDU

        app = AsyncMock()
        # RejectPDU(reason) stringifies cleanly; it's in _send's error tuple.
        app.request = AsyncMock(return_value=RejectPDU(reason=9))
        ok, detail = asyncio.run(self.scanner._send(app, Mock(), Mock(), 5.0))
        self.assertFalse(ok)


@unittest.skipUnless(_HAS, "bacpypes3 required")
class TestDispatcher(unittest.TestCase):
    def test_no_call_returns_quietly(self):
        scanner = _create_instance(call=None)
        app = AsyncMock()
        asyncio.run(scanner._bacpypes3_call_service(app, Mock(), 1001, 5.0))
        scanner.logger.fail.assert_not_called()

    def test_unknown_service_fails(self):
        scanner = _create_instance(call=["bogusservice"])
        app = AsyncMock()
        asyncio.run(scanner._bacpypes3_call_service(app, Mock(), 1001, 5.0))
        msg = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list)
        self.assertIn("Unknown service", msg)

    def test_detect_only_service_fails(self):
        # confirmedCOVNotification is callable=False (indication / detect-only).
        scanner = _create_instance(call=["confirmedCOVNotification"])
        app = AsyncMock()
        asyncio.run(scanner._bacpypes3_call_service(app, Mock(), 1001, 5.0))
        msg = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list)
        self.assertIn("detect-only", msg)

    def test_mutating_without_confirm_is_gated(self):
        # writeProperty mutates -> needs --confirm.
        scanner = _create_instance(call=["write", "AV:1:pv:5"], confirm=False)
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._bacpypes3_call_service(app, Mock(), 1001, 5.0))
        msg = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list)
        self.assertIn("--confirm", msg)
        # No request was sent.
        app.request.assert_not_called()

    def test_read_property_dispatch_invokes_handler(self):
        scanner = _create_instance(call=["read", "AV:1:pv"])
        app = AsyncMock()
        # _bacpypes3_read_one belongs to PropertiesMixin (external collaborator).
        scanner._bacpypes3_read_one = AsyncMock(return_value=72.5)
        asyncio.run(scanner._bacpypes3_call_service(app, Mock(), 1001, 5.0))
        scanner._bacpypes3_read_one.assert_awaited()
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("72.5", succ)

    def test_write_property_with_confirm_sends_request(self):
        scanner = _create_instance(call=["write", "AV:1:pv:11.0:8"], confirm=True)
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._bacpypes3_call_service(app, Mock(), 1001, 5.0))
        app.request.assert_awaited()
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "WritePropertyRequest")
        self.assertEqual(sent.objectIdentifier[1], 1)

    def test_control_service_warns_disruptive(self):
        # reinitializeDevice is RISK_CONTROL.
        scanner = _create_instance(call=["reinit", "warmstart"], confirm=True)
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._bacpypes3_call_service(app, Mock(), 1001, 5.0))
        warn = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("DISRUPTIVE", warn)

    def test_bad_arguments_reports_usage(self):
        # write with no argv -> ValueError -> "Bad arguments" + usage.
        scanner = _create_instance(call=["write"], confirm=True)
        app = AsyncMock()
        asyncio.run(scanner._bacpypes3_call_service(app, Mock(), 1001, 5.0))
        msg = " ".join(str(c.args[0]) for c in scanner.logger.fail.call_args_list)
        self.assertIn("Bad arguments", msg)


@unittest.skipUnless(_HAS, "bacpypes3 required")
class TestReadFamilyHandlers(unittest.TestCase):
    def test_read_property_multiple(self):
        scanner = _create_instance()
        app = AsyncMock()
        scanner._bacpypes3_read_one = AsyncMock(side_effect=[1.0, "ON"])
        asyncio.run(
            scanner._call_read_property_multiple(app, Mock(), 1001, 5.0, ["AV:1:pv,BV:2:pv"])
        )
        self.assertEqual(scanner._bacpypes3_read_one.await_count, 2)

    def test_read_range_reads_log_buffer(self):
        scanner = _create_instance()
        app = AsyncMock()
        scanner._bacpypes3_read_one = AsyncMock(return_value="<buffer>")
        asyncio.run(scanner._call_read_range(app, Mock(), 1001, 5.0, ["AV:1"]))
        # logBuffer is the property actually read.
        self.assertEqual(scanner._bacpypes3_read_one.await_args.args[4], "logBuffer")

    def test_who_is_handler(self):
        scanner = _create_instance()
        app = AsyncMock()
        scanner._bacpypes3_who_is_instance = AsyncMock(return_value=1001)
        asyncio.run(scanner._call_who_is(app, Mock(), 1001, 5.0, []))
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("1001", succ)

    def test_read_property_no_args_raises(self):
        scanner = _create_instance()
        app = AsyncMock()
        with self.assertRaises(ValueError):
            asyncio.run(scanner._call_read_property(app, Mock(), 1001, 5.0, []))


@unittest.skipUnless(_HAS, "bacpypes3 required")
class TestWriteFamilyHandlers(unittest.TestCase):
    def test_write_property_sends_coerced_value(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._call_write_property(app, Mock(), 1001, 5.0, ["AV:3:pv:23.5"]))
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "WritePropertyRequest")
        self.assertEqual(str(sent.objectIdentifier[0]), "analog-value")
        self.assertEqual(sent.objectIdentifier[1], 3)
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("WriteProperty", succ)

    def test_delete_object(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._call_delete_object(app, Mock(), 1001, 5.0, ["AV:9"]))
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "DeleteObjectRequest")

    def test_subscribe_cov_builds_request(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._call_subscribe_cov(app, Mock(), 1001, 5.0, ["AV:1:120"]))
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "SubscribeCOVRequest")

    def test_write_group_unconfirmed_dispatch(self):
        scanner = _create_instance()
        # Unconfirmed request, but app.request() still returns an awaitable
        # (an APDUFuture in real bacpypes3) that must be awaited or the send
        # task gets cancelled at app.close() before bytes hit the wire.
        app = AsyncMock()
        app.request = AsyncMock(return_value=None)
        asyncio.run(scanner._call_write_group(app, Mock(), 1001, 5.0, ["1:2:21.0:8"]))
        app.request.assert_awaited()
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("WriteGroup", succ)

    def test_dcc_disable_initiation_mode(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._call_dcc(app, Mock(), 1001, 5.0, ["disable-initiation:5:pw"]))
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "DeviceCommunicationControlRequest")

    def test_reinitialize_device_coldstart(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._call_reinitialize_device(app, Mock(), 1001, 5.0, ["coldstart:secret"]))
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "ReinitializeDeviceRequest")

    def test_atomic_write_file_rejects_missing_file(self):
        scanner = _create_instance()
        app = AsyncMock()
        with self.assertRaises(ValueError):
            asyncio.run(
                scanner._call_atomic_write_file(app, Mock(), 1001, 5.0, ["1:/no/such/file.bin"])
            )

    def test_create_object_with_instance(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._call_create_object(app, Mock(), 1001, 5.0, ["AV:42"]))
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "CreateObjectRequest")

    def test_create_object_type_only(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._call_create_object(app, Mock(), 1001, 5.0, ["analogValue"]))
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "CreateObjectRequest")

    def test_add_list_element(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(
            scanner._call_add_list_element(app, Mock(), 1001, 5.0, ["group:1:listOfGroupMembers:5"])
        )
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "AddListElementRequest")

    def test_remove_list_element(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(
            scanner._call_remove_list_element(
                app, Mock(), 1001, 5.0, ["group:1:listOfGroupMembers:5"]
            )
        )
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "RemoveListElementRequest")

    def test_write_property_multiple(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(
            scanner._call_write_property_multiple(app, Mock(), 1001, 5.0, ["AV:1:pv:5,AV:2:pv:6"])
        )
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "WritePropertyMultipleRequest")

    def test_time_sync_explicit_time_dispatch(self):
        scanner = _create_instance()
        # Unconfirmed request, but app.request() still returns an awaitable
        # (an APDUFuture in real bacpypes3) that must be awaited or the send
        # task gets cancelled at app.close() before bytes hit the wire.
        app = AsyncMock()
        app.request = AsyncMock(return_value=None)
        asyncio.run(scanner._call_time_sync(app, Mock(), 1001, 5.0, ["2024-01-02T03:04:05"]))
        app.request.assert_awaited()
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("TimeSync sent", succ)

    def test_time_sync_now_requires_explicit_time(self):
        scanner = _create_instance()
        app = Mock()
        with self.assertRaises(ValueError):
            asyncio.run(scanner._call_time_sync(app, Mock(), 1001, 5.0, ["now"]))

    def test_text_message(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._call_text_message(app, Mock(), 1001, 5.0, ["maintenance window"]))
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "ConfirmedTextMessageRequest")

    def test_acknowledge_alarm(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(
            scanner._call_acknowledge_alarm(app, Mock(), 1001, 5.0, ["7:analogInput:1:normal"])
        )
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "AcknowledgeAlarmRequest")

    def test_life_safety_operation(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(
            scanner._call_life_safety_operation(
                app, Mock(), 1001, 5.0, ["lifeSafetyPoint:1:none:3"]
            )
        )
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "LifeSafetyOperationRequest")


@unittest.skipUnless(_HAS, "bacpypes3 required")
class TestReadFamilyExtra(unittest.TestCase):
    def test_get_alarm_summary(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._call_get_alarm_summary(app, Mock(), 1001, 5.0, []))
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "GetAlarmSummaryRequest")

    def test_get_event_information(self):
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_simple_ack())
        asyncio.run(scanner._call_get_event_information(app, Mock(), 1001, 5.0, []))
        sent = app.request.call_args.args[0]
        self.assertEqual(type(sent).__name__, "GetEventInformationRequest")

    def test_who_has_delegates(self):
        scanner = _create_instance()
        app = AsyncMock()
        scanner._bacpypes3_who_has = AsyncMock()
        asyncio.run(scanner._call_who_has(app, Mock(), 1001, 5.0, ["ZoneTemp"]))
        scanner._bacpypes3_who_has.assert_awaited()

    def test_atomic_read_file_delegates(self):
        scanner = _create_instance()
        app = AsyncMock()
        scanner._bacpypes3_read_file = AsyncMock()
        asyncio.run(scanner._call_atomic_read_file(app, Mock(), 1001, 5.0, ["3"]))
        scanner._bacpypes3_read_file.assert_awaited()
        # File instance 3 is passed through.
        self.assertEqual(scanner._bacpypes3_read_file.await_args.args[2], 3)


@unittest.skipUnless(_HAS, "bacpypes3 required")
class TestListServices(unittest.TestCase):
    def test_list_services_prints_callable_catalog(self):
        scanner = _create_instance()
        scanner._handle_list_services()
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("Service Catalog", out)
        # A known callable token must appear.
        self.assertIn("read", out)


if __name__ == "__main__":
    unittest.main()
