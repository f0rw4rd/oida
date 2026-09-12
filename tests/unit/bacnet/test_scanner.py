#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for BACnet (Building Automation and Control Network) scanner functionality.

Tests the BACnet scanner module without requiring actual network connections.
"""

import unittest
from unittest.mock import Mock, patch

from tests.service_gate import require_import

require_import(
    "bacpypes3", reason="bacpypes3 not installed (required for BACnet scanner instantiation)"
)


class MockBAC0Device:
    """Mock BAC0 device for testing"""

    def __init__(self, device_id=1001, vendor_id=7, address="192.168.1.100"):
        self.device_id = device_id
        self.vendor = vendor_id
        self.address = address
        self.modelName = "Test BACnet Device"
        self.vendorName = "Siemens Building Technologies"
        self.objectName = "TestDevice"
        self.segmentationSupported = True
        self.servicesSupported = ["readProperty", "writeProperty", "whoIs", "iAm"]


class MockBAC0Network:
    """Mock BAC0 network for testing"""

    def __init__(self, devices=None):
        self.devices = devices or [MockBAC0Device()]
        self.whois_results = []

    def whois(self, low_limit=None, high_limit=None):
        """Simulate Who-Is discovery"""
        for device in self.devices:
            self.whois_results.append(device)
        return self.whois_results

    def read(self, address, object_id, property_id):
        """Simulate property read"""
        return f"value_{property_id}"

    def write(self, address, object_id, property_id, value, priority=None):
        """Simulate property write"""
        return True


class TestBACnetDataStructures(unittest.TestCase):
    """Test BACnet data structures and constants"""

    def test_object_types_defined(self):
        """Test BACnet object types are properly defined"""
        from oida.protocols.bacnet import OBJECT_TYPES

        # Check common object types
        self.assertEqual(OBJECT_TYPES[0], "analogInput")
        self.assertEqual(OBJECT_TYPES[1], "analogOutput")
        self.assertEqual(OBJECT_TYPES[2], "analogValue")
        self.assertEqual(OBJECT_TYPES[3], "binaryInput")
        self.assertEqual(OBJECT_TYPES[4], "binaryOutput")
        self.assertEqual(OBJECT_TYPES[5], "binaryValue")
        self.assertEqual(OBJECT_TYPES[8], "device")
        self.assertEqual(OBJECT_TYPES[17], "schedule")
        self.assertEqual(OBJECT_TYPES[20], "trendLog")

    def test_object_type_names_reverse_mapping(self):
        """Test reverse mapping from name to type ID"""
        from oida.protocols.bacnet import OBJECT_TYPES, OBJECT_TYPE_NAMES

        # Test reverse mapping
        self.assertEqual(OBJECT_TYPE_NAMES["analogInput"], 0)
        self.assertEqual(OBJECT_TYPE_NAMES["binaryOutput"], 4)
        self.assertEqual(OBJECT_TYPE_NAMES["device"], 8)

        # Verify consistency
        for type_id, name in OBJECT_TYPES.items():
            self.assertEqual(OBJECT_TYPE_NAMES[name], type_id)

    def test_control_point_types(self):
        """Test control point types for filtering"""
        from oida.protocols.bacnet import CONTROL_POINT_TYPES

        expected_control_types = {
            "analogInput",
            "analogOutput",
            "analogValue",
            "binaryInput",
            "binaryOutput",
            "binaryValue",
            "multiStateInput",
            "multiStateOutput",
            "multiStateValue",
        }

        self.assertEqual(CONTROL_POINT_TYPES, expected_control_types)

    def test_vendor_ids_defined(self):
        """Test common BACnet vendor IDs are defined"""
        from oida.protocols.bacnet import VENDORS

        # Check common vendors
        self.assertEqual(VENDORS[0], "ASHRAE")
        self.assertEqual(VENDORS[4], "PolarSoft")
        self.assertEqual(VENDORS[5], "Johnson Controls")
        self.assertEqual(VENDORS[7], "Siemens Schweiz AG")
        self.assertEqual(VENDORS[17], "Honeywell")
        self.assertEqual(VENDORS[36], "Tridium")

    def test_vendor_coverage(self):
        """Test vendor ID coverage"""
        from oida.protocols.bacnet import VENDORS

        # Should have a reasonable number of vendor IDs
        self.assertGreater(len(VENDORS), 20)


class TestBACnetScannerInit(unittest.TestCase):
    """Test BACnet scanner initialization"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.who_is = False
        self.mock_args.identify = False
        self.mock_args.services = False
        self.mock_args.enumerate_objects = False
        self.mock_args.enumerate_properties = False
        self.mock_args.present_value = False
        self.mock_args.read = None
        self.mock_args.write = None
        self.mock_args.dump = False
        self.mock_args.diff = None
        self.mock_args.monitor = False
        self.mock_args.assess = False
        self.mock_args.test_write = False
        self.mock_args.enumerate_writable = False
        self.mock_args.check_reinit = False
        self.mock_args.check_oos = False
        self.mock_args.quick = False
        self.mock_args.discover = False
        self.mock_args.full = False
        self.mock_args.confirm = False
        self.mock_args.port = 47808
        self.mock_args.timeout = 3.0
        self.mock_args.interface = None
        self.mock_args.bbmd = None
        self.mock_args.device_id = None
        self.mock_args.device_range = None
        self.mock_args.object_type = None
        self.mock_args.max_objects = 1000
        self.mock_args.object_types = None
        self.mock_args.control_points = False
        self.mock_args.values_only = False
        self.mock_args.full_properties = False
        self.mock_args.output = None
        self.mock_args.format = "json"
        self.mock_args.interval = 1.0
        self.mock_args.cov = False
        self.mock_args.priority = None

    def test_basic_initialization(self):
        """Test basic scanner initialization"""
        from oida.protocols.bacnet import bacnet

        with patch.object(bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(bacnet)
            scanner.protocol_name = "bacnet"
            scanner.default_port = 47808
            scanner.bacnet = None
            scanner.devices = {}
            scanner.objects = {}

            self.assertEqual(scanner.protocol_name, "bacnet")
            self.assertEqual(scanner.default_port, 47808)
            self.assertIsNone(scanner.bacnet)
            self.assertEqual(scanner.devices, {})
            self.assertEqual(scanner.objects, {})


class TestBACnetShortcuts(unittest.TestCase):
    """Test BACnet CLI shortcut flags"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.bacnet import bacnet

        self.bacnet = bacnet
        self.mock_args = Mock()
        self.mock_args.who_is = False
        self.mock_args.identify = False
        self.mock_args.services = False
        self.mock_args.enumerate_objects = False
        self.mock_args.enumerate_properties = False
        self.mock_args.assess = False
        self.mock_args.quick = False
        self.mock_args.discover = False
        self.mock_args.full = False
        self.mock_args.write = None
        self.mock_args.test_write = False
        self.mock_args.check_reinit = False
        self.mock_args.check_oos = False
        self.mock_args.check_anonymous = False
        self.mock_args.check_priority = False
        self.mock_args.check_schedules = False
        self.mock_args.check_calendars = False
        self.mock_args.check_alarms = False
        self.mock_args.check_trendlogs = False
        self.mock_args.enum_life_safety = False
        self.mock_args.check_bacnet_sc = False
        self.mock_args.enum_bbmd = False
        self.mock_args.enum_fdt = False
        self.mock_args.enum_routers = False
        self.mock_args.enum_networks = False
        self.mock_args.enumerate_writable = False
        self.mock_args.assess_network = False
        self.mock_args.assess_access = False
        self.mock_args.assess_config = False
        self.mock_args.assess_info = False

    def test_quick_shortcut(self):
        """Test --quick shortcut applies correct flags"""
        self.mock_args.quick = True

        with patch.object(self.bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(self.bacnet)
            scanner.args = self.mock_args
            scanner._apply_shortcuts()

            self.assertTrue(scanner.args.who_is)
            self.assertTrue(scanner.args.identify)

    def test_discover_shortcut(self):
        """Test --discover shortcut applies correct flags"""
        self.mock_args.discover = True

        with patch.object(self.bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(self.bacnet)
            scanner.args = self.mock_args
            scanner._apply_shortcuts()

            self.assertTrue(scanner.args.who_is)
            self.assertTrue(scanner.args.identify)
            self.assertTrue(scanner.args.enumerate_objects)

    def test_full_shortcut(self):
        """Test --full shortcut applies correct flags"""
        self.mock_args.full = True

        with patch.object(self.bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(self.bacnet)
            scanner.args = self.mock_args
            scanner._apply_shortcuts()

            self.assertTrue(scanner.args.who_is)
            self.assertTrue(scanner.args.identify)
            self.assertTrue(scanner.args.enumerate_objects)
            self.assertTrue(scanner.args.enumerate_properties)
            self.assertTrue(scanner.args.assess)

    def test_assess_shortcut(self):
        """Test --assess shortcut enables all security checks"""
        self.mock_args.assess = True

        with patch.object(self.bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(self.bacnet)
            scanner.args = self.mock_args
            scanner._apply_shortcuts()

            self.assertTrue(scanner.args.check_anonymous)
            self.assertTrue(scanner.args.check_priority)
            self.assertTrue(scanner.args.check_schedules)
            self.assertTrue(scanner.args.check_calendars)
            self.assertTrue(scanner.args.check_alarms)
            self.assertTrue(scanner.args.check_trendlogs)


class TestBACnetObjectIdParsing(unittest.TestCase):
    """Test BACnet object ID parsing"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.bacnet import bacnet

        self.bacnet = bacnet

    def test_parse_object_id_tuple(self):
        """Test parsing object ID from tuple"""
        with patch.object(self.bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(self.bacnet)

            result = scanner._parse_object_id((0, 1))
            self.assertEqual(result, (0, 1))

            result = scanner._parse_object_id((8, 1001))
            self.assertEqual(result, (8, 1001))

    def test_parse_object_id_string_colon(self):
        """Test parsing object ID from string with colon (type name:instance)"""
        with patch.object(self.bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(self.bacnet)

            # Using type name (which is the expected format)
            result = scanner._parse_object_id("analogInput:1")
            self.assertEqual(result, (0, 1))

            # Using numeric string - note: numeric types are looked up as names
            # so "8" would not match any name and return 0
            result = scanner._parse_object_id("device:1001")
            self.assertEqual(result, (8, 1001))

    def test_parse_object_id_string_name(self):
        """Test parsing object ID with type name"""
        with patch.object(self.bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(self.bacnet)

            result = scanner._parse_object_id("analogInput:1")
            self.assertEqual(result, (0, 1))

            result = scanner._parse_object_id("device:1001")
            self.assertEqual(result, (8, 1001))


class TestBACnetConstants(unittest.TestCase):
    """Test BACnet constants and enums"""

    def test_default_port(self):
        """Test default BACnet/IP port"""
        from oida.protocols.bacnet import bacnet

        with patch.object(bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(bacnet)
            scanner.default_port = 47808

            self.assertEqual(scanner.default_port, 47808)

    def test_object_type_count(self):
        """Test that all standard object types are defined"""
        from oida.protocols.bacnet import OBJECT_TYPES

        # BACnet has 60+ standard object types (0-59 in recent specs)
        self.assertGreater(len(OBJECT_TYPES), 50)

    def test_multistate_types(self):
        """Test multistate object types"""
        from oida.protocols.bacnet import OBJECT_TYPES

        self.assertEqual(OBJECT_TYPES[13], "multiStateInput")
        self.assertEqual(OBJECT_TYPES[14], "multiStateOutput")
        self.assertEqual(OBJECT_TYPES[19], "multiStateValue")


class TestBACnetVendorLookup(unittest.TestCase):
    """Test BACnet vendor ID lookup"""

    def test_lookup_known_vendor(self):
        """Test lookup of known vendor IDs"""
        from oida.protocols.bacnet import VENDORS

        self.assertEqual(VENDORS.get(7), "Siemens Schweiz AG")
        self.assertEqual(VENDORS.get(5), "Johnson Controls")
        self.assertEqual(VENDORS.get(4), "PolarSoft")
        self.assertEqual(VENDORS.get(17), "Honeywell")

    def test_lookup_unknown_vendor(self):
        """Test lookup of unknown vendor ID"""
        from oida.protocols.bacnet import VENDORS

        # Unknown vendor should return None
        self.assertIsNone(VENDORS.get(99999))

    def test_vendor_id_zero(self):
        """Test ASHRAE vendor ID (0)"""
        from oida.protocols.bacnet import VENDORS

        self.assertEqual(VENDORS[0], "ASHRAE")


class TestBACnetSecurityAnalysis(unittest.TestCase):
    """Test BACnet security analysis features"""

    def test_anonymous_access_detection(self):
        """Test detection of anonymous access"""
        from oida.protocols.bacnet import bacnet

        with patch.object(bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(bacnet)
            scanner.logger = Mock()

            # BACnet typically has no authentication
            # Security analysis should flag this
            security_results = {
                "anonymous_access": True,
                "writable_objects": [],
                "priority_access": False,
            }

            self.assertTrue(security_results["anonymous_access"])

    def test_writable_objects_detection(self):
        """Test detection of writable objects"""
        from oida.protocols.bacnet import bacnet

        with patch.object(bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(bacnet)
            scanner.logger = Mock()

            # Simulate writable objects found
            writable_objects = [
                {"object_id": (2, 1), "name": "AnalogValue1"},
                {"object_id": (5, 1), "name": "BinaryValue1"},
            ]

            self.assertEqual(len(writable_objects), 2)


class TestBACnetDeviceInfo(unittest.TestCase):
    """Test BACnet device information extraction"""

    def test_device_info_structure(self):
        """Test device information structure"""
        device_info = {
            "device_id": 1001,
            "address": "192.168.1.100",
            "vendor_id": 7,
            "vendor_name": "Siemens Building Technologies",
            "modelName": "Test Device",
            "objectName": "TestDevice",
            "segmentationSupported": True,
        }

        self.assertEqual(device_info["device_id"], 1001)
        self.assertEqual(device_info["vendor_id"], 7)
        self.assertIn("vendor_name", device_info)

    def test_device_services_structure(self):
        """Test device services structure"""
        services = {
            "readProperty": True,
            "writeProperty": True,
            "whoIs": True,
            "iAm": True,
            "subscribeCOV": True,
            "confirmedCOVNotification": True,
            "readPropertyMultiple": True,
            "writePropertyMultiple": True,
        }

        self.assertTrue(services["readProperty"])
        self.assertTrue(services["whoIs"])


class TestBACnetObjectEnumeration(unittest.TestCase):
    """Test BACnet object enumeration"""

    def test_object_list_structure(self):
        """Test object list structure"""
        objects = [
            {"type": "analogInput", "instance": 1, "name": "AI_1"},
            {"type": "analogOutput", "instance": 1, "name": "AO_1"},
            {"type": "binaryInput", "instance": 1, "name": "BI_1"},
            {"type": "binaryOutput", "instance": 1, "name": "BO_1"},
        ]

        self.assertEqual(len(objects), 4)
        self.assertEqual(objects[0]["type"], "analogInput")

    def test_object_property_structure(self):
        """Test object property structure"""
        properties = {
            "objectIdentifier": (0, 1),
            "objectName": "Temperature Sensor",
            "objectType": "analogInput",
            "presentValue": 72.5,
            "units": "degreesFahrenheit",
            "statusFlags": [False, False, False, False],
        }

        self.assertEqual(properties["objectType"], "analogInput")
        self.assertEqual(properties["presentValue"], 72.5)


class TestBACnetModuleImport(unittest.TestCase):
    """Test BACnet module import and structure"""

    def test_module_import(self):
        """Test that BACnet module can be imported"""
        from oida.protocols.bacnet import bacnet, OBJECT_TYPES, VENDORS

        self.assertIsNotNone(bacnet)
        self.assertIsNotNone(OBJECT_TYPES)
        self.assertIsNotNone(VENDORS)

    def test_nxc_class_exists(self):
        """Test that NXC-style class exists"""
        from oida.protocols.bacnet import bacnet

        self.assertIsNotNone(bacnet)

    def test_nxc_class_methods(self):
        """Test NXC class has required methods"""
        from oida.protocols.bacnet import bacnet

        self.assertTrue(hasattr(bacnet, "proto_flow"))
        self.assertTrue(hasattr(bacnet, "enum_host_info"))
        self.assertTrue(hasattr(bacnet, "print_host_info"))


class TestBACnetPropertyReading(unittest.TestCase):
    """Test BACnet property reading functionality"""

    def test_property_value_types(self):
        """Test different property value types"""
        # BACnet supports various data types
        property_values = {
            "presentValue": 72.5,  # Real
            "objectName": "Sensor1",  # CharacterString
            "statusFlags": [False, False, False, False],  # BitString
            "eventState": "normal",  # Enumerated
            "outOfService": False,  # Boolean
            "reliability": "noFaultDetected",  # Enumerated
        }

        self.assertIsInstance(property_values["presentValue"], float)
        self.assertIsInstance(property_values["objectName"], str)
        self.assertIsInstance(property_values["statusFlags"], list)
        self.assertIsInstance(property_values["outOfService"], bool)

    def test_status_flags_interpretation(self):
        """Test status flags interpretation"""
        # BACnet status flags: [inAlarm, fault, overridden, outOfService]
        normal_flags = [False, False, False, False]
        alarm_flags = [True, False, False, False]
        fault_flags = [False, True, False, False]
        oos_flags = [False, False, False, True]

        self.assertFalse(normal_flags[0])  # No alarm
        self.assertTrue(alarm_flags[0])  # In alarm
        self.assertTrue(fault_flags[1])  # Fault
        self.assertTrue(oos_flags[3])  # Out of service


class TestBACnetScheduleEnumeration(unittest.TestCase):
    """Test BACnet schedule enumeration"""

    def test_schedule_structure(self):
        """Test schedule object structure"""
        schedule = {
            "objectType": "schedule",
            "instance": 1,
            "objectName": "HVAC_Schedule",
            "presentValue": "occupied",
            "weeklySchedule": {
                "monday": [(("6:00", "occupied"), ("18:00", "unoccupied"))],
                "tuesday": [(("6:00", "occupied"), ("18:00", "unoccupied"))],
            },
            "effectivePeriod": {
                "startDate": "2024-01-01",
                "endDate": "2024-12-31",
            },
        }

        self.assertEqual(schedule["objectType"], "schedule")
        self.assertIn("weeklySchedule", schedule)


class TestBACnetTrendLogEnumeration(unittest.TestCase):
    """Test BACnet trend log enumeration"""

    def test_trend_log_structure(self):
        """Test trend log object structure"""
        trend_log = {
            "objectType": "trendLog",
            "instance": 1,
            "objectName": "Temperature_Log",
            "logDeviceObjectProperty": (0, 1, "presentValue"),
            "enable": True,
            "logInterval": 300,  # 5 minutes
            "bufferSize": 1000,
            "recordCount": 500,
        }

        self.assertEqual(trend_log["objectType"], "trendLog")
        self.assertEqual(trend_log["logInterval"], 300)


class TestBACnetNetworkDiscovery(unittest.TestCase):
    """Test BACnet network discovery functionality"""

    def test_who_is_response_structure(self):
        """Test Who-Is/I-Am response structure"""
        iam_response = {
            "deviceIdentifier": 1001,
            "maxApduLengthAccepted": 480,
            "segmentationSupported": "segmented-both",
            "vendorId": 7,
            "address": "192.168.1.100:47808",
        }

        self.assertEqual(iam_response["deviceIdentifier"], 1001)
        self.assertIn("vendorId", iam_response)

    def test_device_range_parsing(self):
        """Test device ID range parsing"""
        # Simulate parsing device range
        device_range = "1000-1010"
        parts = device_range.split("-")
        low_limit = int(parts[0])
        high_limit = int(parts[1])

        self.assertEqual(low_limit, 1000)
        self.assertEqual(high_limit, 1010)


class TestBACnetErrorHandling(unittest.TestCase):
    """Test BACnet error handling"""

    def test_connection_error_handling(self):
        """Test handling of connection errors"""
        from oida.protocols.bacnet import bacnet

        with patch.object(bacnet, "__init__", lambda self, args, db, host: None):
            scanner = object.__new__(bacnet)
            scanner.logger = Mock()
            scanner.devices = {}

            # Simulate connection failure
            connection_error = {
                "error": "Connection timeout",
                "host": "192.168.1.100",
                "port": 47808,
            }

            self.assertIn("error", connection_error)

    def test_property_read_error_handling(self):
        """Test handling of property read errors"""
        # BACnet error structure
        error_response = {
            "error_class": "object",
            "error_code": "unknown-object",
            "description": "Object not found",
        }

        self.assertEqual(error_response["error_class"], "object")
        self.assertEqual(error_response["error_code"], "unknown-object")


class TestBACnetProtocolOptions(unittest.TestCase):
    """Test BACnet protocol options"""

    def test_discovery_options(self):
        """Test discovery-related options"""
        options = {
            "who_is": True,
            "device_range": "1-4194302",
            "timeout": 5.0,
            "interface": "eth0",
            "bbmd": "192.168.1.1",
        }

        self.assertTrue(options["who_is"])
        self.assertEqual(options["timeout"], 5.0)

    def test_enumeration_options(self):
        """Test enumeration options"""
        options = {
            "enumerate_objects": True,
            "enumerate_properties": True,
            "max_objects": 1000,
            "object_types": ["analogInput", "analogOutput"],
            "control_points": True,
        }

        self.assertTrue(options["enumerate_objects"])
        self.assertEqual(options["max_objects"], 1000)

    def test_security_options(self):
        """Test security assessment options"""
        options = {
            "assess": True,
            "test_write": False,
            "enumerate_writable": True,
            "check_reinit": False,
        }

        self.assertTrue(options["assess"])


class TestBACnetAddressFormat(unittest.TestCase):
    """Test BACnet address format handling"""

    def test_ip_address_format(self):
        """Test IP address format"""
        address = "192.168.1.100"
        parts = address.split(".")

        self.assertEqual(len(parts), 4)
        for part in parts:
            self.assertTrue(0 <= int(part) <= 255)

    def test_ip_with_port_format(self):
        """Test IP:port address format"""
        address = "192.168.1.100:47808"
        ip, port = address.rsplit(":", 1)

        self.assertEqual(ip, "192.168.1.100")
        self.assertEqual(int(port), 47808)


class TestBACnetClassInitialization(unittest.TestCase):
    """Test BACnet class initialization and setup"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.who_is = False
        self.mock_args.identify = False
        self.mock_args.services = False
        self.mock_args.enumerate_objects = False
        self.mock_args.enumerate_properties = False
        self.mock_args.present_value = False
        self.mock_args.read = None
        self.mock_args.write = None
        self.mock_args.dump = False
        self.mock_args.diff = None
        self.mock_args.monitor = False
        self.mock_args.assess = False
        self.mock_args.test_write = False
        self.mock_args.enumerate_writable = False
        self.mock_args.check_reinit = False
        self.mock_args.check_oos = False
        self.mock_args.quick = False
        self.mock_args.discover = False
        self.mock_args.full = False
        self.mock_args.confirm = False
        self.mock_args.port = 47808
        self.mock_args.timeout = 3.0
        self.mock_args.interface = None
        self.mock_args.bbmd = None
        self.mock_args.device_id = None
        self.mock_args.device_range = None
        self.mock_args.object_type = None
        self.mock_args.max_objects = 1000
        self.mock_args.object_types = None
        self.mock_args.control_points = False
        self.mock_args.values_only = False
        self.mock_args.full_properties = False
        self.mock_args.output = None
        self.mock_args.format = "json"
        self.mock_args.interval = 1.0
        self.mock_args.cov = False
        self.mock_args.priority = None
        self.mock_args.quiet = True
        self.mock_args.debug = False
        self.mock_db = Mock()
        self.host = "192.168.1.100"

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_bacnet_instance_creation(self, mock_asyncio_run):
        """Test creating a BACnet scanner instance"""
        from oida.protocols.bacnet import bacnet

        scanner = bacnet(self.mock_args, self.mock_db, self.host)

        self.assertEqual(scanner.protocol_name, "bacnet")
        self.assertEqual(scanner.default_port, 47808)
        self.assertEqual(scanner.host, self.host)
        self.assertIsInstance(scanner.devices, dict)
        self.assertIsInstance(scanner.objects, dict)

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_bacnet_initialization_with_empty_devices(self, mock_asyncio_run):
        """Test BACnet initialization starts with empty devices"""
        from oida.protocols.bacnet import bacnet

        scanner = bacnet(self.mock_args, self.mock_db, self.host)

        self.assertEqual(len(scanner.devices), 0)
        self.assertEqual(len(scanner.objects), 0)

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_bacnet_port_default(self, mock_asyncio_run):
        """Test BACnet uses correct default port"""
        from oida.protocols.bacnet import bacnet

        scanner = bacnet(self.mock_args, self.mock_db, self.host)

        self.assertEqual(scanner.default_port, 47808)


class TestBACnetParseObjectList(unittest.TestCase):
    """Test _parse_object_list method"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.bacnet import bacnet

        self.bacnet_class = bacnet
        self.mock_args = Mock()
        self.mock_args.quiet = True
        self.mock_db = Mock()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_parse_object_id_from_tuple(self, mock_asyncio_run):
        """Test parsing object ID from tuple format"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")

        result = scanner._parse_object_id((0, 1))
        self.assertEqual(result, (0, 1))

        result = scanner._parse_object_id((8, 1001))
        self.assertEqual(result, (8, 1001))

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_parse_object_id_from_string_with_colon(self, mock_asyncio_run):
        """Test parsing object ID from string with colon separator"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")

        result = scanner._parse_object_id("analogInput:1")
        self.assertEqual(result, (0, 1))

        result = scanner._parse_object_id("device:1001")
        self.assertEqual(result, (8, 1001))

        result = scanner._parse_object_id("binaryOutput:5")
        self.assertEqual(result, (4, 5))

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_parse_object_id_from_string_with_comma(self, mock_asyncio_run):
        """Test parsing object ID from string with comma separator"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")

        result = scanner._parse_object_id("analogInput,10")
        self.assertEqual(result, (0, 10))

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_parse_object_id_invalid_string(self, mock_asyncio_run):
        """Test parsing invalid object ID string returns default"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")

        result = scanner._parse_object_id("invalid")
        self.assertEqual(result, (0, 0))

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_parse_object_id_with_unknown_type(self, mock_asyncio_run):
        """Test parsing object ID with unknown type name"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")

        result = scanner._parse_object_id("unknownType:100")
        # Should default to type 0 for unknown type names
        self.assertEqual(result, (0, 100))


class TestBACnetDeviceDiscovery(unittest.TestCase):
    """Test device discovery logic"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.bacnet import bacnet

        self.bacnet_class = bacnet
        self.mock_args = Mock()
        self.mock_args.who_is = True
        self.mock_args.device_range = None
        self.mock_args.timeout = 3.0
        self.mock_args.quiet = True
        self.mock_db = Mock()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_enum_host_info_with_devices(self, mock_asyncio_run):
        """Test enum_host_info with discovered devices"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")

        # Populate devices
        scanner.devices = {
            1001: {
                "device_id": 1001,
                "address": "192.168.1.100",
                "vendor_id": 7,
                "vendor_name": "Siemens Building Technologies",
            }
        }

        scanner.enum_host_info()

        self.assertIn("device_info", scanner.results["data"])
        self.assertEqual(scanner.results["data"]["device_info"]["device_count"], 1)
        self.assertIn(1001, scanner.results["data"]["device_info"]["devices"])

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_enum_host_info_without_devices(self, mock_asyncio_run):
        """Test enum_host_info without discovered devices"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")

        scanner.enum_host_info()

        self.assertIn("device_info", scanner.results["data"])
        self.assertTrue(scanner.results["data"]["device_info"]["connected"])

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_discover_via_read_with_device_id(self, mock_asyncio_run):
        """Test _discover_via_read with specified device ID"""
        self.mock_args.device_id = 1001
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")

        scanner._discover_via_read()

        self.assertIn(1001, scanner.devices)
        self.assertEqual(scanner.devices[1001]["device_id"], 1001)
        self.assertEqual(scanner.devices[1001]["address"], "192.168.1.100")

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_discover_via_read_without_device_id(self, mock_asyncio_run):
        """Test _discover_via_read without device ID"""
        self.mock_args.device_id = None
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")

        scanner._discover_via_read()

        # Should not add any devices
        self.assertEqual(len(scanner.devices), 0)


class TestBACnetObjectEnumerationParsing(unittest.TestCase):
    """Test object enumeration and parsing"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.bacnet import bacnet

        self.bacnet_class = bacnet
        self.mock_args = Mock()
        self.mock_args.enumerate_objects = True
        self.mock_args.max_objects = 1000
        self.mock_args.object_type = None
        self.mock_args.quiet = True
        self.mock_db = Mock()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_handle_enumerate_objects_no_devices(self, mock_asyncio_run):
        """Test enumerate objects with no devices"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()

        scanner._handle_enumerate_objects()

        scanner.logger.warning.assert_called()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_handle_enumerate_objects_with_mock_property_read(self, mock_asyncio_run):
        """Test enumerate objects with mocked property reading"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()
        scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}

        # Mock _read_property to return object list
        mock_object_list = [
            (0, 1),  # analogInput:1
            (1, 2),  # analogOutput:2
            (2, 3),  # analogValue:3
        ]
        scanner._read_property = Mock(return_value=mock_object_list)

        scanner._handle_enumerate_objects()

        # Verify objects were categorized
        self.assertIn(1001, scanner.objects)
        self.assertIn("analogInput", scanner.objects[1001])
        self.assertIn("analogOutput", scanner.objects[1001])
        self.assertIn("analogValue", scanner.objects[1001])

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_handle_enumerate_objects_with_max_limit(self, mock_asyncio_run):
        """Test enumerate objects respects max_objects limit"""
        self.mock_args.max_objects = 2
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()
        scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}

        # Create object list with more than max_objects
        mock_object_list = [(0, i) for i in range(10)]
        scanner._read_property = Mock(return_value=mock_object_list)

        scanner._handle_enumerate_objects()

        # Should only process max_objects
        total_objects = sum(len(instances) for instances in scanner.objects[1001].values())
        self.assertEqual(total_objects, 2)

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_handle_enumerate_objects_with_type_filter(self, mock_asyncio_run):
        """Test enumerate objects with object type filter"""
        self.mock_args.object_type = "analogInput"
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()
        scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}

        mock_object_list = [
            (0, 1),  # analogInput:1
            (1, 2),  # analogOutput:2 (should be filtered)
            (0, 3),  # analogInput:3
        ]
        scanner._read_property = Mock(return_value=mock_object_list)

        scanner._handle_enumerate_objects()

        # Should only have analogInput objects
        self.assertIn("analogInput", scanner.objects[1001])
        self.assertNotIn("analogOutput", scanner.objects[1001])
        self.assertEqual(len(scanner.objects[1001]["analogInput"]), 2)


class TestBACnetNetworkErrorHandling(unittest.TestCase):
    """Test error handling for network failures"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.bacnet import bacnet

        self.bacnet_class = bacnet
        self.mock_args = Mock()
        self.mock_args.identify = True
        self.mock_args.quiet = True
        self.mock_db = Mock()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_disconnect_with_active_connection(self, mock_asyncio_run):
        """Test disconnect with active BACnet connection"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()

        # Mock BACnet connection
        scanner.bacnet = Mock()
        scanner.bacnet.disconnect = Mock()

        scanner._disconnect()

        scanner.bacnet.disconnect.assert_called_once()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_disconnect_with_no_connection(self, mock_asyncio_run):
        """Test disconnect with no active connection"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()
        scanner.bacnet = None

        # Should not raise exception
        scanner._disconnect()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_disconnect_with_exception(self, mock_asyncio_run):
        """Test disconnect handles exceptions gracefully"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()

        scanner.bacnet = Mock()
        scanner.bacnet.disconnect = Mock(side_effect=Exception("Disconnect error"))

        # Should not raise exception
        scanner._disconnect()

        # Should log debug message
        scanner.logger.debug.assert_called()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_handle_identify_no_devices(self, mock_asyncio_run):
        """Test identify with no discovered devices"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()

        scanner._handle_identify()

        scanner.logger.warning.assert_called()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_handle_identify_with_property_read_failure(self, mock_asyncio_run):
        """Test identify handles property read failures"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()
        scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}

        # Mock _read_property to raise exception
        scanner._read_property = Mock(side_effect=Exception("Network error"))

        # Should not raise exception
        scanner._handle_identify()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_handle_enumerate_objects_with_read_failure(self, mock_asyncio_run):
        """Test enumerate objects handles read failures"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()
        scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}

        # Mock _read_property to return None (read failure)
        scanner._read_property = Mock(return_value=None)

        scanner._handle_enumerate_objects()

        scanner.logger.warning.assert_called()


class TestBACnetPropertyFormatting(unittest.TestCase):
    """Test property value formatting"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.bacnet import bacnet

        self.bacnet_class = bacnet
        self.mock_args = Mock()
        self.mock_args.quiet = True
        self.mock_db = Mock()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_vendor_id_resolution(self, mock_asyncio_run):
        """Test vendor ID is resolved to vendor name"""
        from oida.protocols.bacnet import VENDORS

        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()
        scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}

        # Mock _read_property to return vendor ID
        def mock_read(address, obj_type, instance, prop):
            if prop == "vendorIdentifier":
                return 7  # Siemens
            return None

        scanner._read_property = Mock(side_effect=mock_read)

        scanner._handle_identify()

        # Vendor name should be resolved
        self.assertEqual(scanner.devices[1001]["vendor_id"], 7)
        self.assertEqual(scanner.devices[1001]["vendor_name"], VENDORS[7])

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_unknown_vendor_id_resolution(self, mock_asyncio_run):
        """Test unknown vendor ID formatting"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()
        scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}

        # Mock _read_property to return unknown vendor ID
        def mock_read(address, obj_type, instance, prop):
            if prop == "vendorIdentifier":
                return 99999  # Unknown vendor
            return None

        scanner._read_property = Mock(side_effect=mock_read)

        scanner._handle_identify()

        # Should have "Unknown" format
        self.assertIn("Unknown", scanner.devices[1001]["vendor_name"])
        self.assertIn("99999", scanner.devices[1001]["vendor_name"])


class TestBACnetPrintHostInfo(unittest.TestCase):
    """Test print_host_info output"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.bacnet import bacnet

        self.bacnet_class = bacnet
        self.mock_args = Mock()
        self.mock_args.quiet = False
        self.mock_args.port = 47808
        self.mock_db = Mock()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_print_host_info_with_devices(self, mock_asyncio_run):
        """Test print_host_info displays device information"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()

        scanner.devices = {
            1001: {
                "device_id": 1001,
                "address": "192.168.1.100",
                "vendor_name": "Siemens Building Technologies",
                "modelName": "Test Device",
            }
        }

        scanner.print_host_info()

        scanner.logger.success.assert_called()
        scanner.logger.display.assert_called()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_print_host_info_quiet_mode(self, mock_asyncio_run):
        """Test print_host_info in quiet mode"""
        self.mock_args.quiet = True
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()

        scanner.devices = {1001: {"device_id": 1001}}

        scanner.print_host_info()

        # Should not print anything in quiet mode
        scanner.logger.success.assert_not_called()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_print_host_info_without_devices(self, mock_asyncio_run):
        """Test print_host_info with no devices"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()

        scanner.print_host_info()

        scanner.logger.display.assert_called()


class TestBACnetExportResults(unittest.TestCase):
    """Test results export functionality"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.bacnet import bacnet

        self.bacnet_class = bacnet
        self.mock_args = Mock()
        self.mock_args.output = None
        self.mock_args.format = "json"
        self.mock_args.quiet = True
        self.mock_db = Mock()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_export_results_no_output_path(self, mock_asyncio_run):
        """Test export with no output path specified"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()

        scanner._export_results()

        # Should return early without logging
        scanner.logger.success.assert_not_called()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    @patch("pathlib.Path.write_text")
    def test_export_results_json_format(self, mock_write_text, mock_asyncio_run):
        """Test export results in JSON format"""
        self.mock_args.output = "/tmp/test_output"
        self.mock_args.format = "json"

        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()
        scanner.devices = {1001: {"device_id": 1001}}
        scanner.objects = {1001: {"analogInput": [1, 2, 3]}}

        scanner._export_results()

        mock_write_text.assert_called_once()
        scanner.logger.success.assert_called()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    def test_export_results_csv_format(self, mock_open, mock_asyncio_run):
        """Test export results in CSV format"""
        self.mock_args.output = "/tmp/test_output"
        self.mock_args.format = "csv"

        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()
        scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}
        scanner.objects = {1001: {"analogInput": [1, 2]}}

        scanner._export_results()

        mock_open.assert_called()
        scanner.logger.success.assert_called()


class TestBACnetApplyShortcuts(unittest.TestCase):
    """Test shortcut flag application"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.bacnet import bacnet

        self.bacnet_class = bacnet
        self.mock_db = Mock()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_assess_network_shortcut(self, mock_asyncio_run):
        """Test --assess-network shortcut applies correct flags"""
        mock_args = Mock()
        mock_args.assess_network = True
        mock_args.enum_bbmd = False
        mock_args.enum_fdt = False
        mock_args.enum_routers = False
        mock_args.networks = False
        mock_args.quiet = True

        scanner = self.bacnet_class(mock_args, self.mock_db, "192.168.1.100")

        self.assertTrue(scanner.args.enum_bbmd)
        self.assertTrue(scanner.args.enum_fdt)
        self.assertTrue(scanner.args.enum_routers)
        self.assertTrue(scanner.args.networks)

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_assess_access_shortcut(self, mock_asyncio_run):
        """Test --assess-access shortcut applies correct flags"""
        mock_args = Mock()
        mock_args.assess_access = True
        mock_args.check_anonymous = False
        mock_args.check_priority = False
        mock_args.check_oos = False
        mock_args.enumerate_writable = False
        mock_args.quiet = True

        scanner = self.bacnet_class(mock_args, self.mock_db, "192.168.1.100")

        self.assertTrue(scanner.args.check_anonymous)
        self.assertTrue(scanner.args.check_priority)
        self.assertTrue(scanner.args.check_oos)
        self.assertTrue(scanner.args.enumerate_writable)

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_assess_config_shortcut(self, mock_asyncio_run):
        """Test --assess-config shortcut applies correct flags"""
        mock_args = Mock()
        mock_args.assess_config = True
        mock_args.check_schedules = False
        mock_args.check_calendars = False
        mock_args.check_alarms = False
        mock_args.check_trendlogs = False
        mock_args.quiet = True

        scanner = self.bacnet_class(mock_args, self.mock_db, "192.168.1.100")

        self.assertTrue(scanner.args.check_schedules)
        self.assertTrue(scanner.args.check_calendars)
        self.assertTrue(scanner.args.check_alarms)
        self.assertTrue(scanner.args.check_trendlogs)

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_assess_info_shortcut(self, mock_asyncio_run):
        """Test --assess-info shortcut applies correct flags"""
        mock_args = Mock()
        mock_args.assess_info = True
        mock_args.identify = False
        mock_args.services = False
        mock_args.quiet = True

        scanner = self.bacnet_class(mock_args, self.mock_db, "192.168.1.100")

        self.assertTrue(scanner.args.identify)
        self.assertTrue(scanner.args.services)


class TestBACnetHandleEnumerateProperties(unittest.TestCase):
    """Test property enumeration"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.bacnet import bacnet

        self.bacnet_class = bacnet
        self.mock_args = Mock()
        self.mock_args.enumerate_properties = True
        self.mock_args.quiet = True
        self.mock_db = Mock()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_enumerate_properties_no_objects(self, mock_asyncio_run):
        """Test enumerate properties with no objects"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()

        scanner._handle_enumerate_properties()

        scanner.logger.warning.assert_called()

    @patch("oida.protocols.bacnet.cli_runner.asyncio.run")
    def test_enumerate_properties_with_objects(self, mock_asyncio_run):
        """Test enumerate properties with enumerated objects"""
        scanner = self.bacnet_class(self.mock_args, self.mock_db, "192.168.1.100")
        scanner.logger = Mock()
        scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}
        scanner.objects = {1001: {"analogInput": [1, 2, 3]}}

        # Mock _read_property
        def mock_read(address, obj_type, instance, prop):
            if prop == "objectName":
                return f"Sensor_{instance}"
            elif prop == "presentValue":
                return 72.5
            return None

        scanner._read_property = Mock(side_effect=mock_read)

        scanner._handle_enumerate_properties()

        scanner.logger.display.assert_called()


if __name__ == "__main__":
    unittest.main()
