"""Unit tests for ObjectsMixin enumeration paths.

Covers the parts of objects.py the existing test_deep_enum.py /
test_enum_programs.py skip: the synchronous _handle_enumerate_objects and
_handle_services, the async _bacpypes3_enumerate_objects /
_bacpypes3_enumerate_services bitstring decode, and the program-enumeration
security findings (Insecure configuration + Writable access, both
Category.ACCESS_CONTROL).

External I/O only is mocked: the bacpypes3 type catalog, app.request, and the
cross-mixin _read_property collaborator. The real parsing/branching/finding
emission runs.
"""

import asyncio
import struct
import unittest
from unittest.mock import AsyncMock, Mock, patch

from oida.protocols.bacnet import bacnet
from oida.utils.common_types import Category
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


def _error_classes():
    return {
        "AbortPDU": type("AbortPDU", (), {}),
        "ErrorPDU": type("ErrorPDU", (), {}),
        "RejectPDU": type("RejectPDU", (), {}),
        "Error": type("Error", (), {}),
    }


def _obj_types():
    t = _error_classes()
    for name in ("ReadPropertyRequest", "ObjectIdentifier", "PropertyIdentifier"):
        t[name] = Mock(return_value=Mock())
    return t


def _bitstring_response(data_bytes):
    """A ReadProperty response carrying a bitString tag (services / obj-types)."""
    tag = Mock()
    tag.tag_data = data_bytes
    tag.__str__ = lambda self: "bitString"
    pv = Mock()
    pv.tagList = [tag]
    resp = Mock(spec=["propertyValue"])
    resp.propertyValue = pv
    return resp


def _objectlist_response(oids):
    """A ReadProperty response carrying objectIdentifier tags for a list read."""
    tags = []
    for obj_type, obj_instance in oids:
        val = (obj_type << 22) | obj_instance
        tag = Mock()
        tag.tag_data = struct.pack(">I", val)
        tag.__str__ = lambda self: "objectIdentifier"
        tags.append(tag)
    pv = Mock()
    pv.tagList = tags
    resp = Mock(spec=["propertyValue"])
    resp.propertyValue = pv
    return resp


def _uint_response(value):
    tag = Mock()
    tag.tag_data = value.to_bytes(2, "big")
    pv = Mock()
    pv.tagList = [tag]
    resp = Mock(spec=["propertyValue"])
    resp.propertyValue = pv
    return resp


def _string_response(text):
    tag = Mock()
    tag.tag_data = text.encode("utf-8")
    pv = Mock()
    pv.tagList = [tag]
    resp = Mock(spec=["propertyValue"])
    resp.propertyValue = pv
    return resp


# ---------------------------------------------------------------------------
# Synchronous _handle_enumerate_objects
# ---------------------------------------------------------------------------
class TestHandleEnumerateObjects(unittest.TestCase):
    def test_categorises_and_stores_objects(self):
        scanner = _create_instance()
        # objectList: AI:1, AI:2, BO:5  (types 0,0,4)
        scanner._read_property = Mock(return_value=[(0, 1), (0, 2), (4, 5)])
        scanner._handle_enumerate_objects()

        self.assertIn(1001, scanner.objects)
        self.assertEqual(sorted(scanner.objects[1001]["analogInput"]), [1, 2])
        self.assertEqual(scanner.objects[1001]["binaryOutput"], [5])
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("Found 3 objects", succ)

    def test_object_type_filter(self):
        scanner = _create_instance(object_type="binaryOutput")
        scanner._read_property = Mock(return_value=[(0, 1), (4, 5)])
        scanner._handle_enumerate_objects()
        # Only binaryOutput survives the filter.
        self.assertEqual(list(scanner.objects[1001].keys()), ["binaryOutput"])

    def test_max_objects_limit(self):
        scanner = _create_instance(max_objects=1)
        scanner._read_property = Mock(return_value=[(0, 1), (0, 2), (4, 5)])
        scanner._handle_enumerate_objects()
        warn = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("max objects limit", warn)

    def test_no_devices_warns(self):
        scanner = _create_instance()
        scanner.devices = {}
        scanner._handle_enumerate_objects()
        scanner.logger.warning.assert_called()

    def test_empty_object_list_warns(self):
        scanner = _create_instance()
        scanner._read_property = Mock(return_value=None)
        scanner._handle_enumerate_objects()
        warn = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("Could not read object list", warn)


# ---------------------------------------------------------------------------
# Synchronous _handle_services
# ---------------------------------------------------------------------------
class TestHandleServices(unittest.TestCase):
    def test_stores_services_and_object_types(self):
        scanner = _create_instance()
        scanner._read_property = Mock(side_effect=["SVCBITS", "OBJBITS"])
        scanner._handle_services()
        self.assertEqual(scanner.devices[1001]["services"], "SVCBITS")
        self.assertEqual(scanner.devices[1001]["object_types"], "OBJBITS")

    def test_no_devices_warns(self):
        scanner = _create_instance()
        scanner.devices = {}
        scanner._handle_services()
        scanner.logger.warning.assert_called()


# ---------------------------------------------------------------------------
# Async _bacpypes3_enumerate_objects
# ---------------------------------------------------------------------------
class TestBacpypesEnumerateObjects(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_parses_object_list_and_stores(self, mock_load):
        mock_load.return_value = _obj_types()
        scanner = _create_instance()
        app = AsyncMock()
        # objectList with AI:1, AI:2, BO:5
        app.request = AsyncMock(return_value=_objectlist_response([(0, 1), (0, 2), (4, 5)]))

        asyncio.run(scanner._bacpypes3_enumerate_objects(app, Mock(), 1001, 5.0))

        self.assertIn(1001, scanner.objects)
        self.assertEqual(sorted(scanner.objects[1001]["analogInput"]), [1, 2])
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("Found 3 objects", succ)

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_timeout_warns(self, mock_load):
        mock_load.return_value = _obj_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())
        asyncio.run(scanner._bacpypes3_enumerate_objects(app, Mock(), 1001, 5.0))
        warn = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("timed out", warn)

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_error_response_no_store(self, mock_load):
        types = _obj_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())
        asyncio.run(scanner._bacpypes3_enumerate_objects(app, Mock(), 1001, 5.0))
        self.assertEqual(scanner.objects, {})


# ---------------------------------------------------------------------------
# Async _bacpypes3_enumerate_services
# ---------------------------------------------------------------------------
class TestBacpypesEnumerateServices(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_decodes_service_bitstring(self, mock_load):
        mock_load.return_value = _obj_types()
        scanner = _create_instance()
        app = AsyncMock()
        # bitString: leading unused-bits byte (0x00) + a byte with bit 7..set.
        # byte=0b10010000 -> bits 0 and 3 set in the (7-bit) MSB-first scheme,
        # i.e. service indices 0 (acknowledgeAlarm) and 3 (getAlarmSummary).
        svc_data = bytes([0x00, 0b10010000])
        objtypes_data = bytes([0x00, 0b11000000])  # object types 0 and 1
        app.request = AsyncMock(
            side_effect=[_bitstring_response(svc_data), _bitstring_response(objtypes_data)]
        )

        asyncio.run(scanner._bacpypes3_enumerate_services(app, Mock(), 1001, 5.0))

        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("Supported services", succ)
        self.assertIn("Supported object types", succ)
        # Catalog cross-reference annotation appears for callable services.
        disp = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("acknowledgeAlarm", disp)

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_error_response_quiet(self, mock_load):
        types = _obj_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())
        asyncio.run(scanner._bacpypes3_enumerate_services(app, Mock(), 1001, 5.0))
        # No "Supported services" success on an error response.
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertNotIn("Supported services", succ)


# ---------------------------------------------------------------------------
# _bacpypes3_enum_programs — security findings
# ---------------------------------------------------------------------------
class TestEnumProgramsFindings(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_loading_program_emits_insecure_and_writable_findings(self, mock_load):
        mock_load.return_value = _obj_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"program": [1]}}
        app = AsyncMock()
        # Per-program reads in order:
        # objectName, programState(1=loading), programChange(1=load),
        # reasonForHalt, descriptionOfHalt, programLocation, instanceOf, description
        responses = [
            _string_response("LoaderProg"),  # objectName
            _uint_response(1),  # programState = loading
            _uint_response(1),  # programChange = load (!= ready)
            None,  # reasonForHalt
            None,  # descriptionOfHalt
            _string_response("/ctrl/loader.bin"),  # programLocation
            None,  # instanceOf
            None,  # description
        ]
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_enum_programs(app, Mock(), 1001, 5.0))

        findings = scanner.logger.security_finding.call_args_list
        titles = [c.args[0] for c in findings]
        cats = [c.kwargs["category"] for c in findings]
        self.assertIn("Insecure configuration", titles)
        self.assertIn("Writable access", titles)
        # Both are canonical ACCESS_CONTROL.
        self.assertTrue(all(cat == Category.ACCESS_CONTROL for cat in cats))
        # The concern detail lists the active-load + pending-change + location.
        concerns = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("ACTIVE LOAD", concerns)
        self.assertIn("LOCATION EXPOSED", concerns)

    @patch("oida.protocols.bacnet.mixins.objects._load_bacpypes3")
    def test_idle_program_no_security_finding(self, mock_load):
        mock_load.return_value = _obj_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"program": [2]}}
        app = AsyncMock()
        responses = [
            _string_response("SteadyProg"),  # objectName
            _uint_response(0),  # programState = idle
            _uint_response(0),  # programChange = ready
            None,
            None,
            None,  # no programLocation
            None,
            None,
        ]
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_enum_programs(app, Mock(), 1001, 5.0))

        scanner.logger.security_finding.assert_not_called()
        disp = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("No security concerns identified", disp)


if __name__ == "__main__":
    unittest.main()
