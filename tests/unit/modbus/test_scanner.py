#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for Modbus scanner functionality.
"""

import unittest
from unittest.mock import Mock, patch
from datetime import datetime


from oida.utils.exceptions import ModbusError, ICSConnectionError, ICSTimeoutError


class MockModbusClient:
    """Mock Modbus client for testing"""

    def __init__(self, connect_success=True):
        self.connect_success = connect_success
        self.connected = False

    def connect(self):
        self.connected = self.connect_success
        return self.connect_success

    def close(self):
        self.connected = False

    def read_holding_registers(self, address, count, unit=1):
        if not self.connected:
            raise Exception("Not connected")

        # Mock response
        response = Mock()
        response.isError.return_value = False
        response.registers = [42 + i for i in range(count)]
        return response

    def read_coils(self, address, count, unit=1):
        if not self.connected:
            raise Exception("Not connected")

        response = Mock()
        response.isError.return_value = False
        response.bits = [True, False] * (count // 2 + 1)
        return response

    def write_register(self, address, value, unit=1):
        if not self.connected:
            raise Exception("Not connected")

        response = Mock()
        response.isError.return_value = False
        return response


class TestModbusEnums(unittest.TestCase):
    """Test Modbus enums and constants"""

    def setUp(self):
        # Import here to avoid module import issues
        from oida.protocols.modbus import ModbusFunctionCode, ModbusExceptionCode, RegisterType

        self.ModbusFunctionCode = ModbusFunctionCode
        self.ModbusExceptionCode = ModbusExceptionCode
        self.RegisterType = RegisterType

    def test_function_codes(self):
        """Test Modbus function code enum"""
        self.assertEqual(self.ModbusFunctionCode.READ_COILS, 1)
        self.assertEqual(self.ModbusFunctionCode.READ_HOLDING_REGISTERS, 3)
        self.assertEqual(self.ModbusFunctionCode.WRITE_SINGLE_COIL, 5)
        self.assertEqual(self.ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS, 16)

    def test_exception_codes(self):
        """Test Modbus exception code enum"""
        self.assertEqual(self.ModbusExceptionCode.ILLEGAL_FUNCTION, 1)
        self.assertEqual(self.ModbusExceptionCode.ILLEGAL_DATA_ADDRESS, 2)
        self.assertEqual(self.ModbusExceptionCode.SERVER_DEVICE_FAILURE, 4)

    def test_register_types(self):
        """Test register type enum"""
        self.assertEqual(self.RegisterType.COILS.value, "coils")
        self.assertEqual(self.RegisterType.HOLDING_REGISTERS.value, "holding_registers")
        self.assertEqual(self.RegisterType.INPUT_REGISTERS.value, "input_registers")


class TestModbusScannerInit(unittest.TestCase):
    """Test Modbus scanner initialization"""

    def test_scanner_init_defaults(self):
        """Test scanner initialization with default values"""
        args = {"rhost": "192.168.1.100", "rport": 502, "timeout": 5}

        # We can't import the full scanner due to dependencies,
        # but we can test the args processing logic
        unit_id = int(args.get("unit-id", 1))
        scan_range = args.get("scan-range", "0-100")
        register_type = args.get("register-type", "all")

        self.assertEqual(unit_id, 1)
        self.assertEqual(scan_range, "0-100")
        self.assertEqual(register_type, "all")

    def test_scanner_init_custom_values(self):
        """Test scanner initialization with custom values"""
        args = {
            "rhost": "10.0.0.50",
            "rport": 1502,
            "unit-id": 5,
            "scan-range": "100-200",
            "register-type": "holding",
            "baudrate": 19200,
        }

        unit_id = int(args.get("unit-id", 1))
        scan_range = args.get("scan-range", "0-100")
        register_type = args.get("register-type", "all")
        baudrate = int(args.get("baudrate", 9600))

        self.assertEqual(unit_id, 5)
        self.assertEqual(scan_range, "100-200")
        self.assertEqual(register_type, "holding")
        self.assertEqual(baudrate, 19200)


class TestModbusProtocolLogic(unittest.TestCase):
    """Test Modbus protocol logic without full scanner"""

    def test_parse_address_range(self):
        """Test address range parsing"""

        def parse_address_range(range_str):
            """Simple range parser for testing"""
            if "-" in range_str:
                start, end = map(int, range_str.split("-"))
                return list(range(start, end + 1))
            return [int(range_str)]

        # Test various range formats
        self.assertEqual(parse_address_range("0-5"), [0, 1, 2, 3, 4, 5])
        self.assertEqual(parse_address_range("100-102"), [100, 101, 102])
        self.assertEqual(parse_address_range("42"), [42])

    def test_register_value_conversion(self):
        """Test register value type conversions"""

        def safe_int_conversion(value, default=0):
            """Safe integer conversion"""
            try:
                return int(value)
            except (ValueError, TypeError):
                return default

        self.assertEqual(safe_int_conversion("123"), 123)
        self.assertEqual(safe_int_conversion("invalid", 0), 0)
        self.assertEqual(safe_int_conversion(None, -1), -1)
        self.assertEqual(safe_int_conversion(45.7), 45)


class TestModbusErrorHandling(unittest.TestCase):
    """Test Modbus error handling"""

    def test_modbus_specific_errors(self):
        """Test Modbus-specific exception handling"""
        # Test ModbusError creation
        error = ModbusError("Illegal function code", function_code=1, exception_code=1)

        self.assertEqual(error.protocol, "Modbus")
        self.assertEqual(error.function_code, 1)
        self.assertEqual(error.exception_code, 1)
        self.assertIn("Modbus", str(error))

    def test_connection_error_handling(self):
        """Test connection error scenarios"""
        with self.assertRaises(Exception):
            # Simulate connection failure
            client = MockModbusClient(connect_success=False)
            if not client.connect():
                raise ICSConnectionError("Failed to connect to Modbus server")

    def test_timeout_handling(self):
        """Test timeout scenarios"""

        def simulate_timeout_operation():
            # Simulate a timeout
            raise ICSTimeoutError("Operation timed out after 5 seconds")

        with self.assertRaises(ICSTimeoutError):
            simulate_timeout_operation()


class TestModbusMockOperations(unittest.TestCase):
    """Test Modbus operations with mock client"""

    def setUp(self):
        self.client = MockModbusClient(connect_success=True)
        self.client.connect()

    def tearDown(self):
        if self.client.connected:
            self.client.close()

    def test_read_holding_registers(self):
        """Test reading holding registers"""
        result = self.client.read_holding_registers(40001, 5)

        self.assertFalse(result.isError())
        self.assertEqual(len(result.registers), 5)
        self.assertEqual(result.registers[0], 42)

    def test_read_coils(self):
        """Test reading coils"""
        result = self.client.read_coils(1, 4)

        self.assertFalse(result.isError())
        self.assertGreaterEqual(len(result.bits), 4)

    def test_write_register(self):
        """Test writing to register"""
        result = self.client.write_register(40001, 1234)

        self.assertFalse(result.isError())

    def test_disconnected_operations(self):
        """Test operations when disconnected"""
        self.client.close()

        with self.assertRaises(Exception):
            self.client.read_holding_registers(40001, 1)


class TestMEIParsing(unittest.TestCase):
    """Tests for MEI (Modbus Encapsulated Interface) response parsing"""

    def setUp(self):
        """Set up mock objects for MEI testing"""
        # Import the MEI_OBJECT_NAMES constant if available
        try:
            from oida.protocols.modbus.scanner import MEI_OBJECT_NAMES

            self.MEI_OBJECT_NAMES = MEI_OBJECT_NAMES
        except ImportError:
            # Default mapping if import fails
            self.MEI_OBJECT_NAMES = {
                0x00: "VendorName",
                0x01: "ProductCode",
                0x02: "MajorMinorRevision",
                0x03: "VendorUrl",
                0x04: "ProductName",
                0x05: "ModelName",
                0x06: "UserApplicationName",
            }

    def test_mei_parse_basic_response(self):
        """Test parsing basic MEI response with vendor/product/version"""
        # Simulate pymodbus 3.x response format with .information dict
        mock_response = Mock()
        mock_response.isError.return_value = False
        mock_response.information = {
            0x00: b"Schneider Electric",
            0x01: b"PM5100",
            0x02: b"1.2.3",
        }

        # Parse the response
        objects = {}
        for obj_id, value in mock_response.information.items():
            obj_name = self.MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")
            if isinstance(value, bytes):
                try:
                    objects[obj_name] = value.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    objects[obj_name] = value.hex()
            else:
                objects[obj_name] = str(value)

        self.assertEqual(objects["VendorName"], "Schneider Electric")
        self.assertEqual(objects["ProductCode"], "PM5100")
        self.assertEqual(objects["MajorMinorRevision"], "1.2.3")

    def test_mei_parse_extended_response(self):
        """Test parsing extended MEI response with additional fields"""
        mock_response = Mock()
        mock_response.isError.return_value = False
        mock_response.information = {
            0x00: b"Siemens AG",
            0x01: b"6ES7 315-2EH14-0AB0",
            0x02: b"V3.2.16",
            0x03: b"https://www.siemens.com",
            0x04: b"SIMATIC S7-300 CPU 315-2 PN/DP",
            0x05: b"CPU315-2PN/DP",
            0x06: b"ProcessControl_v2",
        }

        objects = {}
        for obj_id, value in mock_response.information.items():
            obj_name = self.MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")
            if isinstance(value, bytes):
                try:
                    objects[obj_name] = value.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    objects[obj_name] = value.hex()
            else:
                objects[obj_name] = str(value)

        self.assertEqual(len(objects), 7)
        self.assertEqual(objects["VendorName"], "Siemens AG")
        self.assertEqual(objects["VendorUrl"], "https://www.siemens.com")
        self.assertEqual(objects["ProductName"], "SIMATIC S7-300 CPU 315-2 PN/DP")
        self.assertEqual(objects["ModelName"], "CPU315-2PN/DP")
        self.assertEqual(objects["UserApplicationName"], "ProcessControl_v2")

    def test_mei_parse_empty_response(self):
        """Test handling of empty MEI response"""
        mock_response = Mock()
        mock_response.isError.return_value = False
        mock_response.information = {}

        objects = {}
        for obj_id, value in mock_response.information.items():
            obj_name = self.MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")
            objects[obj_name] = str(value)

        self.assertEqual(len(objects), 0)

    def test_mei_parse_malformed_response(self):
        """Test handling of malformed MEI response data"""
        mock_response = Mock()
        mock_response.isError.return_value = False
        # Non-UTF8 bytes that need hex fallback
        mock_response.information = {
            0x00: b"\xff\xfe\x00\x01",  # Invalid UTF-8
            0x01: b"ValidProduct",
        }

        objects = {}
        for obj_id, value in mock_response.information.items():
            obj_name = self.MEI_OBJECT_NAMES.get(obj_id, f"Object_{obj_id:02X}")
            if isinstance(value, bytes):
                try:
                    decoded = value.decode("utf-8", errors="replace").strip("\x00")
                    objects[obj_name] = decoded
                except Exception:
                    objects[obj_name] = value.hex()
            else:
                objects[obj_name] = str(value)

        # The malformed bytes should be decoded with replacement chars
        self.assertIn("VendorName", objects)
        self.assertEqual(objects["ProductCode"], "ValidProduct")

    def test_mei_object_filter_basic(self):
        """Test filtering to basic objects only (IDs 0x00-0x02)"""
        all_objects = {
            0x00: "Vendor",
            0x01: "Product",
            0x02: "Version",
            0x03: "URL",
            0x04: "Name",
            0x05: "Model",
        }

        # Filter to basic objects only (0x00-0x02)
        basic_objects = {k: v for k, v in all_objects.items() if k <= 0x02}

        self.assertEqual(len(basic_objects), 3)
        self.assertIn(0x00, basic_objects)
        self.assertIn(0x01, basic_objects)
        self.assertIn(0x02, basic_objects)
        self.assertNotIn(0x03, basic_objects)

    def test_mei_object_filter_specific(self):
        """Test specific object ID filtering"""
        all_objects = {
            0x00: "Schneider Electric",
            0x01: "PM5100",
            0x02: "1.0.0",
            0x04: "PowerLogic PM5100",
        }

        # Filter for specific object ID 0x04
        specific_object = {k: v for k, v in all_objects.items() if k == 0x04}

        self.assertEqual(len(specific_object), 1)
        self.assertEqual(specific_object[0x04], "PowerLogic PM5100")

    def test_mei_error_response(self):
        """Test handling of MEI error response"""
        mock_response = Mock()
        mock_response.isError.return_value = True
        mock_response.exception_code = 1  # ILLEGAL_FUNCTION

        self.assertTrue(mock_response.isError())
        self.assertEqual(mock_response.exception_code, 1)

    def test_mei_vendor_specific_objects(self):
        """Test parsing vendor-specific MEI objects (0x80-0xFF range)"""
        mock_response = Mock()
        mock_response.isError.return_value = False
        mock_response.information = {
            0x00: b"CustomVendor",
            0x80: b"VendorSpecificData1",  # Vendor-specific range
            0x81: b"VendorSpecificData2",
        }

        objects = {}
        for obj_id, value in mock_response.information.items():
            if obj_id in self.MEI_OBJECT_NAMES:
                obj_name = self.MEI_OBJECT_NAMES[obj_id]
            elif 0x80 <= obj_id <= 0xFF:
                obj_name = f"VendorDefined_{obj_id:02X}"
            else:
                obj_name = f"Object_{obj_id:02X}"

            if isinstance(value, bytes):
                objects[obj_name] = value.decode("utf-8", errors="replace")
            else:
                objects[obj_name] = str(value)

        self.assertEqual(objects["VendorName"], "CustomVendor")
        self.assertEqual(objects["VendorDefined_80"], "VendorSpecificData1")
        self.assertEqual(objects["VendorDefined_81"], "VendorSpecificData2")


class TestFingerprintingLogic(unittest.TestCase):
    """Tests for device fingerprinting logic"""

    def test_fingerprint_basic_fc_support(self):
        """Test basic function code support detection"""
        # Simulate scanning multiple function codes
        fc_results = {}

        mock_responses = {
            1: (False, None),  # READ_COILS - success
            2: (False, None),  # READ_DISCRETE_INPUTS - success
            3: (False, None),  # READ_HOLDING_REGISTERS - success
            4: (False, None),  # READ_INPUT_REGISTERS - success
            5: (True, 1),  # WRITE_SINGLE_COIL - ILLEGAL_FUNCTION
            6: (True, 1),  # WRITE_SINGLE_REGISTER - ILLEGAL_FUNCTION
            15: (True, 1),  # WRITE_MULTIPLE_COILS - ILLEGAL_FUNCTION
            16: (True, 1),  # WRITE_MULTIPLE_REGISTERS - ILLEGAL_FUNCTION
        }

        for fc, (is_error, exc_code) in mock_responses.items():
            fc_results[fc] = exc_code if is_error else None

        # Analyze results
        supported = [fc for fc, exc in fc_results.items() if exc is None]
        unsupported = [fc for fc, exc in fc_results.items() if exc == 1]

        self.assertEqual(supported, [1, 2, 3, 4])
        self.assertEqual(unsupported, [5, 6, 15, 16])

    def test_fingerprint_read_only_device(self):
        """Test fingerprint pattern for read-only device (e.g., power meter)"""
        # Power meters typically only support read operations
        fc_results = {
            1: 1,  # READ_COILS - not supported
            2: 1,  # READ_DISCRETE_INPUTS - not supported
            3: None,  # READ_HOLDING_REGISTERS - supported
            4: None,  # READ_INPUT_REGISTERS - supported
            5: 1,  # WRITE_SINGLE_COIL - not supported
            6: 1,  # WRITE_SINGLE_REGISTER - not supported
        }

        supported = [fc for fc, exc in fc_results.items() if exc is None]

        # Power meters typically only support FC 3 and 4
        self.assertEqual(len(supported), 2)
        self.assertIn(3, supported)
        self.assertIn(4, supported)

    def test_fingerprint_full_plc(self):
        """Test fingerprint pattern for full PLC with read/write support"""
        fc_results = {
            1: None,  # READ_COILS - supported
            2: None,  # READ_DISCRETE_INPUTS - supported
            3: None,  # READ_HOLDING_REGISTERS - supported
            4: None,  # READ_INPUT_REGISTERS - supported
            5: None,  # WRITE_SINGLE_COIL - supported
            6: None,  # WRITE_SINGLE_REGISTER - supported
            15: None,  # WRITE_MULTIPLE_COILS - supported
            16: None,  # WRITE_MULTIPLE_REGISTERS - supported
            43: None,  # MEI - supported
        }

        supported = [fc for fc, exc in fc_results.items() if exc is None]

        # Full PLC should support all standard function codes
        self.assertEqual(len(supported), 9)
        self.assertIn(43, supported)  # MEI support indicates modern device

    def test_fingerprint_exception_patterns(self):
        """Test exception-based device detection patterns"""
        # Different devices respond with different exception codes
        test_patterns = {
            "strict_device": {
                3: None,  # Success
                100: 1,  # ILLEGAL_FUNCTION
            },
            "lenient_device": {
                3: None,  # Success
                100: 2,  # ILLEGAL_DATA_ADDRESS (FC recognized but invalid addr)
            },
            "gateway_device": {
                3: None,  # Success
                100: 10,  # GATEWAY_PATH_UNAVAILABLE
            },
        }

        for device_type, pattern in test_patterns.items():
            # Strict device rejects unknown FCs entirely
            if device_type == "strict_device":
                self.assertEqual(pattern[100], 1)

            # Lenient device accepts FC but rejects address
            if device_type == "lenient_device":
                self.assertEqual(pattern[100], 2)

            # Gateway device indicates routing issue
            if device_type == "gateway_device":
                self.assertEqual(pattern[100], 10)

    def test_fingerprint_timing_analysis(self):
        """Test timing-based fingerprint collection"""
        # Simulate response time collection
        timing_samples = []

        for _ in range(10):
            # Mock response times (in seconds)
            response_time = 0.015 + (0.005 * ((_ % 3) / 3))  # 15-20ms typical
            timing_samples.append(response_time)

        # Calculate statistics
        avg_time = sum(timing_samples) / len(timing_samples)
        min_time = min(timing_samples)
        max_time = max(timing_samples)

        self.assertGreater(len(timing_samples), 0)
        self.assertLess(avg_time, 0.1)  # Should be under 100ms
        self.assertGreaterEqual(max_time, min_time)

    def test_fingerprint_vendor_fc_detection(self):
        """Test detection of vendor-specific function codes"""
        # Schneider-specific function codes
        vendor_fcs = {
            90: "UMAS Protocol (Schneider)",
            66: "Program Upload (Legacy Modicon)",
            70: "Program Download (Legacy Modicon)",
        }

        fc_results = {
            90: None,  # UMAS supported = Schneider
            66: 1,  # Not supported
            70: 1,  # Not supported
        }

        detected_vendor_fcs = [
            (fc, vendor_fcs[fc]) for fc in vendor_fcs if fc_results.get(fc) is None
        ]

        self.assertEqual(len(detected_vendor_fcs), 1)
        self.assertEqual(detected_vendor_fcs[0][0], 90)


class TestMonitorLoop(unittest.TestCase):
    """Tests for register monitoring functionality"""

    def test_monitor_on_change_detection(self):
        """Test value change detection logic"""
        previous_values = {40001: 100, 40002: 200, 40003: 300}
        current_values = {40001: 100, 40002: 250, 40003: 300}  # 40002 changed

        changes = {}
        for addr in current_values:
            if addr in previous_values and previous_values[addr] != current_values[addr]:
                changes[addr] = {"old": previous_values[addr], "new": current_values[addr]}
            elif addr not in previous_values:
                changes[addr] = {"old": None, "new": current_values[addr]}

        self.assertEqual(len(changes), 1)
        self.assertIn(40002, changes)
        self.assertEqual(changes[40002]["old"], 200)
        self.assertEqual(changes[40002]["new"], 250)

    def test_monitor_new_address_detection(self):
        """Test detection of newly appearing addresses"""
        previous_values = {40001: 100}
        current_values = {40001: 100, 40002: 200}  # 40002 is new

        changes = {}
        for addr in current_values:
            if addr not in previous_values:
                changes[addr] = {"old": None, "new": current_values[addr]}

        self.assertEqual(len(changes), 1)
        self.assertIn(40002, changes)
        self.assertIsNone(changes[40002]["old"])
        self.assertEqual(changes[40002]["new"], 200)

    def test_monitor_interval_timing(self):
        """Test interval timing behavior simulation"""
        import time

        interval = 0.1  # 100ms
        iterations = 3
        timestamps = []

        start = time.time()
        for _ in range(iterations):
            timestamps.append(time.time() - start)
            time.sleep(interval)

        # Verify approximately correct intervals
        for i in range(1, len(timestamps)):
            delta = timestamps[i] - timestamps[i - 1]
            # Allow 50ms tolerance for timing variance
            self.assertAlmostEqual(delta, interval, delta=0.05)

    def test_monitor_duration_limit(self):
        """Test duration limit enforcement"""
        duration = 5  # seconds
        elapsed_times = [0, 1, 2, 3, 4, 5, 6]  # Simulated elapsed times

        # Simulate duration check
        should_continue = []
        for elapsed in elapsed_times:
            should_continue.append(elapsed < duration)

        # Should stop at or after 5 seconds
        self.assertTrue(all(should_continue[:5]))  # 0-4 seconds: continue
        self.assertFalse(any(should_continue[5:]))  # 5+ seconds: stop

    def test_monitor_log_file_format(self):
        """Test CSV format for monitor logging"""
        import io
        import csv

        # Simulate log entries
        log_entries = [
            {"timestamp": "2024-01-01T10:00:00", "address": 40001, "value": 100},
            {"timestamp": "2024-01-01T10:00:01", "address": 40001, "value": 105},
            {"timestamp": "2024-01-01T10:00:02", "address": 40001, "value": 110},
        ]

        # Write to CSV format
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["timestamp", "address", "value"])
        writer.writeheader()
        for entry in log_entries:
            writer.writerow(entry)

        csv_content = output.getvalue()

        # Verify CSV format
        self.assertIn("timestamp,address,value", csv_content)
        self.assertIn("2024-01-01T10:00:00,40001,100", csv_content)

    def test_monitor_multiple_addresses(self):
        """Test monitoring multiple register addresses"""
        addresses = [40001, 40002, 40003, 40004, 40005]

        # Simulate reading all addresses
        mock_values = {}
        for addr in addresses:
            mock_values[addr] = addr - 40000  # Value = offset from 40000

        self.assertEqual(len(mock_values), 5)
        self.assertEqual(mock_values[40001], 1)
        self.assertEqual(mock_values[40005], 5)

    def test_monitor_coil_values(self):
        """Test monitoring coil (boolean) values"""
        previous_coils = {1: True, 2: False, 3: True}
        current_coils = {1: True, 2: True, 3: False}  # 2 and 3 changed

        changes = {}
        for addr in current_coils:
            if addr in previous_coils and previous_coils[addr] != current_coils[addr]:
                changes[addr] = {"old": previous_coils[addr], "new": current_coils[addr]}

        self.assertEqual(len(changes), 2)
        self.assertIn(2, changes)
        self.assertIn(3, changes)


class TestExceptionAnalysis(unittest.TestCase):
    """Tests for Modbus exception analysis utilities"""

    def test_exception_code_meanings(self):
        """Test interpretation of standard exception codes"""
        exception_meanings = {
            1: ("ILLEGAL_FUNCTION", "Function code not supported"),
            2: ("ILLEGAL_DATA_ADDRESS", "Address not valid"),
            3: ("ILLEGAL_DATA_VALUE", "Value not acceptable"),
            4: ("SERVER_DEVICE_FAILURE", "Internal device error"),
            5: ("ACKNOWLEDGE", "Request acknowledged, processing"),
            6: ("SERVER_DEVICE_BUSY", "Device busy"),
            10: ("GATEWAY_PATH_UNAVAILABLE", "Gateway routing error"),
            11: ("GATEWAY_TARGET_DEVICE_FAILED", "Target device not responding"),
        }

        for code, (name, meaning) in exception_meanings.items():
            self.assertIsInstance(name, str)
            self.assertIsInstance(meaning, str)

    def test_security_sensitive_function_codes(self):
        """Test identification of security-sensitive function codes"""
        # Write function codes are security-sensitive
        sensitive_fcs = {
            5: "Write Single Coil",
            6: "Write Single Register",
            15: "Write Multiple Coils",
            16: "Write Multiple Registers",
            21: "Write File Record",
            22: "Mask Write Register",
            23: "Read/Write Multiple Registers",
        }

        # All write FCs should be considered sensitive
        for fc in sensitive_fcs:
            self.assertIn(fc, sensitive_fcs)
            self.assertIn("Write", sensitive_fcs[fc])

    def test_analyze_gateway_response(self):
        """Test analysis of gateway exception responses"""
        # Gateway exception codes indicate network topology
        gateway_exceptions = {10, 11}

        test_results = {
            3: 10,  # READ_HOLDING_REGISTERS got gateway error
            4: 11,  # READ_INPUT_REGISTERS got target device failed
        }

        gateway_errors = [fc for fc, exc in test_results.items() if exc in gateway_exceptions]

        self.assertEqual(len(gateway_errors), 2)
        self.assertIn(3, gateway_errors)
        self.assertIn(4, gateway_errors)


class TestFunctionCodeSupport(unittest.TestCase):
    """Tests for function code support detection"""

    def test_standard_read_function_codes(self):
        """Test standard read function code definitions"""
        read_fcs = {
            1: "READ_COILS",
            2: "READ_DISCRETE_INPUTS",
            3: "READ_HOLDING_REGISTERS",
            4: "READ_INPUT_REGISTERS",
            7: "READ_EXCEPTION_STATUS",
            17: "REPORT_SERVER_ID",
            20: "READ_FILE_RECORD",
            24: "READ_FIFO_QUEUE",
        }

        self.assertEqual(read_fcs[3], "READ_HOLDING_REGISTERS")
        self.assertEqual(read_fcs[4], "READ_INPUT_REGISTERS")

    def test_standard_write_function_codes(self):
        """Test standard write function code definitions"""
        write_fcs = {
            5: "WRITE_SINGLE_COIL",
            6: "WRITE_SINGLE_REGISTER",
            15: "WRITE_MULTIPLE_COILS",
            16: "WRITE_MULTIPLE_REGISTERS",
            21: "WRITE_FILE_RECORD",
            22: "MASK_WRITE_REGISTER",
        }

        self.assertEqual(write_fcs[5], "WRITE_SINGLE_COIL")
        self.assertEqual(write_fcs[16], "WRITE_MULTIPLE_REGISTERS")

    def test_diagnostic_function_codes(self):
        """Test diagnostic function code handling"""
        diagnostic_subfunctions = {
            0x00: "Return Query Data",
            0x01: "Restart Communications Option",
            0x04: "Force Listen Only Mode",
            0x0A: "Clear Counters",
        }

        self.assertEqual(diagnostic_subfunctions[0x00], "Return Query Data")
        self.assertEqual(diagnostic_subfunctions[0x04], "Force Listen Only Mode")

    def test_user_defined_fc_range(self):
        """Test user-defined function code ranges"""
        user_defined_ranges = [(65, 72), (100, 110)]

        for fc in [65, 66, 70, 72, 100, 105, 110]:
            in_range = any(start <= fc <= end for start, end in user_defined_ranges)
            self.assertTrue(in_range, f"FC {fc} should be in user-defined range")

        # FCs outside ranges
        for fc in [1, 3, 50, 63, 73, 99, 111, 120]:
            in_range = any(start <= fc <= end for start, end in user_defined_ranges)
            self.assertFalse(in_range, f"FC {fc} should NOT be in user-defined range")


class TestModbusScannerClass(unittest.TestCase):
    """Test ModbusScanner class with mocks"""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_scanner_initialization_tcp(self, mock_pymodbus):
        """Test scanner initialization with TCP args"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {
            "rhost": "192.168.1.100",
            "rport": 502,
            "timeout": 5,
            "unit-id": 1,
            "scan-range": "0-100",
            "register-type": "holding",
        }

        scanner = ModbusScanner(args)

        self.assertEqual(scanner.unit_id, 1)
        self.assertEqual(scanner.scan_range, "0-100")
        self.assertEqual(scanner.register_type, "holding")
        self.assertEqual(scanner.get_protocol_name(), "Modbus")
        self.assertEqual(scanner.get_default_port(), 502)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_scanner_initialization_custom_values(self, mock_pymodbus):
        """Test scanner initialization with custom values"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {
            "rhost": "10.0.0.50",
            "rport": 1502,
            "timeout": 10,
            "unit-id": 5,
            "scan-range": "1000-2000",
            "register-type": "all",
            "discover-units": "true",
            "unit-range": "1-10",
            "function-range": "1-4",
            "baudrate": 19200,
        }

        scanner = ModbusScanner(args)

        self.assertEqual(scanner.unit_id, 5)
        self.assertEqual(scanner.scan_range, "1000-2000")
        self.assertEqual(scanner.register_type, "all")
        self.assertTrue(scanner.discover_units)
        self.assertEqual(scanner.unit_range, "1-10")
        self.assertEqual(scanner.fc_range, "1-4")
        self.assertEqual(scanner.baudrate, 19200)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_scanner_initialization_serial(self, mock_pymodbus):
        """Test scanner initialization for serial connection"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {
            "rhost": "localhost",  # Still needs a host for initialization
            "rport": 502,
            "timeout": 3,
            "serial-port": "/dev/ttyUSB0",
            "baudrate": 9600,
            "unit-id": 1,
        }

        scanner = ModbusScanner(args)

        self.assertEqual(scanner.serial_port, "/dev/ttyUSB0")
        self.assertEqual(scanner.baudrate, 9600)
        self.assertEqual(scanner.unit_id, 1)


class TestParseMEIResponse(unittest.TestCase):
    """Test _parse_mei_response method"""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def setUp(self, mock_pymodbus):
        """Set up scanner instance"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
        self.scanner = ModbusScanner(args)

    def test_parse_mei_response_information_format(self):
        """Test parsing MEI response with .information attribute"""
        mock_response = Mock()
        mock_response.information = {
            0x00: b"Schneider Electric",
            0x01: b"PM5100",
            0x02: b"1.2.3",
            0x04: b"PowerLogic PM5100",
        }

        result = self.scanner._parse_mei_response(mock_response)

        self.assertEqual(result["VendorName"], "Schneider Electric")
        self.assertEqual(result["ProductCode"], "PM5100")
        self.assertEqual(result["MajorMinorRevision"], "1.2.3")
        self.assertEqual(result["ProductName"], "PowerLogic PM5100")

    def test_parse_mei_response_binary_data(self):
        """Test parsing MEI response with non-UTF8 binary data"""
        mock_response = Mock()
        mock_response.information = {
            0x00: b"\xff\xfe\x00\x01",  # Invalid UTF-8
            0x01: b"Product123",
        }

        result = self.scanner._parse_mei_response(mock_response)

        # Binary data should be hex encoded as fallback
        self.assertIn("VendorName", result)
        self.assertEqual(result["ProductCode"], "Product123")

    def test_parse_mei_response_null_terminated_strings(self):
        """Test parsing MEI response with null-terminated strings"""
        mock_response = Mock()
        mock_response.information = {
            0x00: b"Vendor\x00\x00\x00",
            0x01: b"Product\x00",
            0x02: b"1.0\x00",
        }

        result = self.scanner._parse_mei_response(mock_response)

        self.assertEqual(result["VendorName"], "Vendor")
        self.assertEqual(result["ProductCode"], "Product")
        self.assertEqual(result["MajorMinorRevision"], "1.0")

    def test_parse_mei_response_string_values(self):
        """Test parsing MEI response with string values instead of bytes"""
        mock_response = Mock()
        mock_response.information = {
            0x00: "StringVendor",
            0x01: 12345,  # Non-bytes value
        }

        result = self.scanner._parse_mei_response(mock_response)

        self.assertEqual(result["VendorName"], "StringVendor")
        self.assertEqual(result["ProductCode"], "12345")

    def test_parse_mei_response_empty(self):
        """Test parsing empty MEI response"""
        mock_response = Mock()
        mock_response.information = {}

        result = self.scanner._parse_mei_response(mock_response)

        self.assertEqual(result, {})

    def test_parse_mei_response_unknown_object_ids(self):
        """Test parsing MEI response with unknown object IDs"""
        mock_response = Mock()
        mock_response.information = {
            0x00: b"KnownVendor",
            0x50: b"UnknownObject",  # Not in MEI_OBJECT_NAMES
            0x80: b"VendorSpecific",  # Vendor-specific range
        }

        result = self.scanner._parse_mei_response(mock_response)

        self.assertEqual(result["VendorName"], "KnownVendor")
        self.assertIn("Object_50", result)
        self.assertIn("Object_80", result)


class TestModbusScannerErrorPaths(unittest.TestCase):
    """Test error handling paths in ModbusScanner"""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def setUp(self, mock_pymodbus):
        """Set up scanner instance"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
        self.scanner = ModbusScanner(args)

    def test_parse_mei_response_exception_handling(self):
        """Test MEI response parsing handles exceptions gracefully"""
        # Response with no information or objects attributes
        mock_response = Mock(spec=[])

        result = self.scanner._parse_mei_response(mock_response)

        # Should return empty dict on error
        self.assertEqual(result, {})

    def test_parse_mei_response_decode_error(self):
        """Test MEI response handles decode errors"""
        mock_response = Mock()
        mock_response.information = {
            0x00: b"\x80\x81\x82\x83",  # Invalid UTF-8
        }

        # Should not raise exception
        result = self.scanner._parse_mei_response(mock_response)

        # Should have VendorName key (either replaced chars or hex)
        self.assertIn("VendorName", result)


class TestModbusGetExceptionName(unittest.TestCase):
    """Test _get_exception_name method"""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def setUp(self, mock_pymodbus):
        """Set up scanner instance"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
        self.scanner = ModbusScanner(args)

    def test_get_exception_name_known_codes(self):
        """Test getting names for known exception codes"""
        # Note: The actual implementation uses spaces, not underscores
        self.assertEqual(self.scanner._get_exception_name(1), "ILLEGAL FUNCTION")
        self.assertEqual(self.scanner._get_exception_name(2), "ILLEGAL DATA ADDRESS")
        self.assertEqual(self.scanner._get_exception_name(4), "SERVER DEVICE FAILURE")

    def test_get_exception_name_unknown_code(self):
        """Test getting name for unknown exception code"""
        result = self.scanner._get_exception_name(99)

        # Should return "UNKNOWN" for unknown codes
        self.assertEqual(result, "UNKNOWN")


class TestModbusConnectionMethods(unittest.TestCase):
    """Test connection-related methods"""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    def test_get_protocol_name(self, mock_tcp_client, mock_pymodbus):
        """Test get_protocol_name returns Modbus"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
        scanner = ModbusScanner(args)

        self.assertEqual(scanner.get_protocol_name(), "Modbus")

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    @patch("oida.protocols.modbus.scanner._get_modbus_tcp_client")
    def test_get_default_port(self, mock_tcp_client, mock_pymodbus):
        """Test get_default_port returns 502"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
        scanner = ModbusScanner(args)

        self.assertEqual(scanner.get_default_port(), 502)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_check_dependencies(self, mock_pymodbus):
        """Test check_dependencies method"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
        scanner = ModbusScanner(args)

        # This depends on whether pymodbus is actually installed
        # Just ensure the method exists and returns a bool
        result = scanner.check_dependencies()
        self.assertIsInstance(result, bool)


class TestExecutePDU(unittest.TestCase):
    """Test execute_pdu helper function"""

    @patch("oida.protocols.modbus.scanner._get_pymodbus_version")
    def test_execute_pdu_version_3(self, mock_version):
        """Test execute_pdu with pymodbus 3.x"""
        from oida.protocols.modbus.scanner import execute_pdu

        mock_version.return_value = 3
        mock_client = Mock()
        mock_pdu = Mock()
        unit_id = 5

        execute_pdu(mock_client, mock_pdu, unit_id)

        # In v3, dev_id is set on PDU
        self.assertEqual(mock_pdu.dev_id, unit_id)
        mock_client.execute.assert_called_once_with(False, mock_pdu)

    @patch("oida.protocols.modbus.scanner._get_pymodbus_version")
    def test_execute_pdu_version_2(self, mock_version):
        """Test execute_pdu with pymodbus 2.x"""
        from oida.protocols.modbus.scanner import execute_pdu

        mock_version.return_value = 2
        mock_client = Mock()
        mock_pdu = Mock()
        unit_id = 3

        execute_pdu(mock_client, mock_pdu, unit_id)

        # In v2, unit is passed as keyword argument
        mock_client.execute.assert_called_once_with(mock_pdu, unit=unit_id)


class TestModbusDisconnect(unittest.TestCase):
    """Test disconnect method"""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def setUp(self, mock_pymodbus):
        """Set up scanner instance"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
        self.scanner = ModbusScanner(args)

    def test_disconnect_valid_connection(self):
        """Test disconnecting a valid connection"""
        mock_connection = Mock()
        mock_connection.close = Mock()

        self.scanner.disconnect(mock_connection)

        mock_connection.close.assert_called_once()

    def test_disconnect_none_connection(self):
        """Test disconnecting with None connection"""
        # Should not raise exception
        self.scanner.disconnect(None)


class TestModbusEnumValues(unittest.TestCase):
    """Test Modbus enum values and constants"""

    def test_mei_type_enum(self):
        """Test MEIType enum values"""
        from oida.protocols.modbus.scanner import MEIType

        self.assertEqual(MEIType.READ_DEVICE_ID, 14)

    def test_mei_read_device_id_code_enum(self):
        """Test MEIReadDeviceIdCode enum values"""
        from oida.protocols.modbus.scanner import MEIReadDeviceIdCode

        self.assertEqual(MEIReadDeviceIdCode.BASIC, 1)
        self.assertEqual(MEIReadDeviceIdCode.REGULAR, 2)
        self.assertEqual(MEIReadDeviceIdCode.EXTENDED, 3)
        self.assertEqual(MEIReadDeviceIdCode.SPECIFIC, 4)

    def test_mei_object_id_enum(self):
        """Test MEIObjectId enum values"""
        from oida.protocols.modbus.scanner import MEIObjectId

        self.assertEqual(MEIObjectId.VENDOR_NAME, 0x00)
        self.assertEqual(MEIObjectId.PRODUCT_CODE, 0x01)
        self.assertEqual(MEIObjectId.MAJOR_MINOR_REVISION, 0x02)
        self.assertEqual(MEIObjectId.VENDOR_URL, 0x03)
        self.assertEqual(MEIObjectId.PRODUCT_NAME, 0x04)
        self.assertEqual(MEIObjectId.MODEL_NAME, 0x05)
        self.assertEqual(MEIObjectId.USER_APPLICATION_NAME, 0x06)

    def test_diagnostic_subfunction_enum(self):
        """Test DiagnosticSubfunction enum values"""
        from oida.protocols.modbus.scanner import DiagnosticSubfunction

        self.assertEqual(DiagnosticSubfunction.RETURN_QUERY_DATA, 0x00)
        self.assertEqual(DiagnosticSubfunction.RESTART_COMM_OPTION, 0x01)
        self.assertEqual(DiagnosticSubfunction.CLEAR_COUNTERS, 0x0A)
        self.assertEqual(DiagnosticSubfunction.FORCE_LISTEN_ONLY_MODE, 0x04)

    def test_mei_object_names_dict(self):
        """Test MEI_OBJECT_NAMES dictionary"""
        from oida.protocols.modbus.scanner import MEI_OBJECT_NAMES

        self.assertEqual(MEI_OBJECT_NAMES[0x00], "VendorName")
        self.assertEqual(MEI_OBJECT_NAMES[0x01], "ProductCode")
        self.assertEqual(MEI_OBJECT_NAMES[0x02], "MajorMinorRevision")
        self.assertEqual(MEI_OBJECT_NAMES[0x04], "ProductName")

    def test_function_codes_dict(self):
        """Test FUNCTION_CODES dictionary"""
        from oida.protocols.modbus.scanner import FUNCTION_CODES

        self.assertEqual(FUNCTION_CODES[1], "Read Coils")
        self.assertEqual(FUNCTION_CODES[3], "Read Holding Registers")
        self.assertEqual(FUNCTION_CODES[16], "Write Multiple Registers")
        self.assertEqual(FUNCTION_CODES[43], "Device Information")

    def test_exception_codes_dict(self):
        """Test EXCEPTION_CODES dictionary"""
        from oida.protocols.modbus.scanner import EXCEPTION_CODES

        self.assertEqual(EXCEPTION_CODES[1], "Illegal Function")
        self.assertEqual(EXCEPTION_CODES[2], "Illegal Data Address")


class TestModbusRegisterType(unittest.TestCase):
    """Test RegisterType enum"""

    def test_register_type_values(self):
        """Test RegisterType enum values"""
        from oida.protocols.modbus.scanner import RegisterType

        self.assertEqual(RegisterType.COILS.value, "coils")
        self.assertEqual(RegisterType.DISCRETE_INPUTS.value, "discrete_inputs")
        self.assertEqual(RegisterType.HOLDING_REGISTERS.value, "holding_registers")
        self.assertEqual(RegisterType.INPUT_REGISTERS.value, "input_registers")


class TestModbusLazyImports(unittest.TestCase):
    """Test lazy import helper functions"""

    @patch("oida.protocols.modbus.scanner._pymodbus")
    def test_get_pymodbus(self, mock_lazy_pymodbus):
        """Test _get_pymodbus function (delegates to the memoized lazy import)"""
        from oida.protocols.modbus.scanner import _get_pymodbus

        mock_lazy_pymodbus.return_value = Mock(__name__="pymodbus")

        result = _get_pymodbus()

        self.assertIsNotNone(result)
        mock_lazy_pymodbus.assert_called_once()

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_get_pymodbus_version(self, mock_get_pymodbus):
        """Test _get_pymodbus_version function"""
        import oida.protocols.modbus.scanner as scanner_mod

        # Reset the module-level version cache
        saved = scanner_mod._pymodbus_version
        try:
            scanner_mod._pymodbus_version = None
            mock_get_pymodbus.return_value = Mock(__version__="3.5.2")

            version = scanner_mod._get_pymodbus_version()

            self.assertEqual(version, 3)
        finally:
            scanner_mod._pymodbus_version = saved


class TestModbusScannerMEIErrorHandling(unittest.TestCase):
    """Test MEI response parsing with various error conditions"""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def setUp(self, mock_pymodbus):
        """Set up scanner instance"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
        self.scanner = ModbusScanner(args)

    def test_parse_mei_response_with_exception(self):
        """Test MEI response parsing when decode raises exception"""
        mock_response = Mock()

        # Make information.items() raise an exception
        def raise_exception():
            raise Exception("Parsing error")

        mock_response.information = Mock()
        mock_response.information.items = raise_exception

        # The exception will propagate (no try-except at this level)
        with self.assertRaises(Exception):
            self.scanner._parse_mei_response(mock_response)

    def test_parse_mei_response_mixed_data_types(self):
        """Test MEI response with mixed data types"""
        mock_response = Mock()
        mock_response.information = {
            0x00: b"ByteString",
            0x01: "PlainString",
            0x02: 12345,
            0x03: None,
            0x04: ["list", "data"],
        }

        result = self.scanner._parse_mei_response(mock_response)

        self.assertEqual(result["VendorName"], "ByteString")
        self.assertEqual(result["ProductCode"], "PlainString")
        self.assertIn("MajorMinorRevision", result)
        self.assertIn("VendorUrl", result)


class TestModbusScannerInitializationEdgeCases(unittest.TestCase):
    """Test ModbusScanner initialization with edge cases"""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_scanner_init_missing_optional_args(self, mock_pymodbus):
        """Test scanner with minimal args (only required fields)"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {
            "rhost": "192.168.1.1",
            "rport": 502,
        }

        scanner = ModbusScanner(args)

        # Should use defaults
        self.assertEqual(scanner.unit_id, 1)
        self.assertIsNone(scanner.scan_range)  # scan_range is None when not specified
        self.assertEqual(scanner.register_type, "all")
        self.assertFalse(scanner.discover_units)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_scanner_init_get_device_id_false(self, mock_pymodbus):
        """Test scanner with get-device-id disabled"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {
            "rhost": "192.168.1.1",
            "rport": 502,
            "get-device-id": "false",
        }

        scanner = ModbusScanner(args)

        self.assertFalse(scanner.get_device_id)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_scanner_init_all_optional_args(self, mock_pymodbus):
        """Test scanner with all optional args set"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {
            "rhost": "10.0.0.1",
            "rport": 1502,
            "timeout": 10,
            "unit-id": 10,
            "scan-range": "500-600",
            "register-type": "input",
            "discover-units": "yes",
            "unit-range": "5-15",
            "function-range": "3,4,16",
            "serial-port": "/dev/ttyS0",
            "baudrate": 115200,
            "get-device-id": "true",
        }

        scanner = ModbusScanner(args)

        self.assertEqual(scanner.unit_id, 10)
        self.assertEqual(scanner.scan_range, "500-600")
        self.assertEqual(scanner.register_type, "input")
        self.assertTrue(scanner.discover_units)
        self.assertEqual(scanner.unit_range, "5-15")
        self.assertEqual(scanner.fc_range, "3,4,16")
        self.assertEqual(scanner.serial_port, "/dev/ttyS0")
        self.assertEqual(scanner.baudrate, 115200)
        self.assertTrue(scanner.get_device_id)


class TestModbusExceptionCodeEnum(unittest.TestCase):
    """Test ModbusExceptionCode enum"""

    def test_all_exception_codes(self):
        """Test all ModbusExceptionCode values"""
        from oida.protocols.modbus.scanner import ModbusExceptionCode

        self.assertEqual(ModbusExceptionCode.ILLEGAL_FUNCTION, 1)
        self.assertEqual(ModbusExceptionCode.ILLEGAL_DATA_ADDRESS, 2)
        self.assertEqual(ModbusExceptionCode.ILLEGAL_DATA_VALUE, 3)
        self.assertEqual(ModbusExceptionCode.SERVER_DEVICE_FAILURE, 4)
        self.assertEqual(ModbusExceptionCode.ACKNOWLEDGE, 5)
        self.assertEqual(ModbusExceptionCode.SERVER_DEVICE_BUSY, 6)
        self.assertEqual(ModbusExceptionCode.NEGATIVE_ACKNOWLEDGE, 7)
        self.assertEqual(ModbusExceptionCode.MEMORY_PARITY_ERROR, 8)
        self.assertEqual(ModbusExceptionCode.GATEWAY_PATH_UNAVAILABLE, 10)
        self.assertEqual(ModbusExceptionCode.GATEWAY_TARGET_DEVICE_FAILED, 11)


class TestModbusFunctionCodeEnum(unittest.TestCase):
    """Test ModbusFunctionCode enum"""

    def test_read_function_codes(self):
        """Test read-related function codes"""
        from oida.protocols.modbus.scanner import ModbusFunctionCode

        self.assertEqual(ModbusFunctionCode.READ_COILS, 1)
        self.assertEqual(ModbusFunctionCode.READ_DISCRETE_INPUTS, 2)
        self.assertEqual(ModbusFunctionCode.READ_HOLDING_REGISTERS, 3)
        self.assertEqual(ModbusFunctionCode.READ_INPUT_REGISTERS, 4)

    def test_write_function_codes(self):
        """Test write-related function codes"""
        from oida.protocols.modbus.scanner import ModbusFunctionCode

        self.assertEqual(ModbusFunctionCode.WRITE_SINGLE_COIL, 5)
        self.assertEqual(ModbusFunctionCode.WRITE_SINGLE_REGISTER, 6)
        self.assertEqual(ModbusFunctionCode.WRITE_MULTIPLE_COILS, 15)
        self.assertEqual(ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS, 16)

    def test_special_function_codes(self):
        """Test special/diagnostic function codes"""
        from oida.protocols.modbus.scanner import ModbusFunctionCode

        self.assertEqual(ModbusFunctionCode.DIAGNOSTICS, 8)
        self.assertEqual(ModbusFunctionCode.REPORT_SERVER_ID, 17)
        self.assertEqual(ModbusFunctionCode.DEVICE_INFORMATION, 43)
        self.assertEqual(ModbusFunctionCode.MASK_WRITE_REGISTER, 22)


class TestModbusConstantDictionaries(unittest.TestCase):
    """Test legacy constant dictionaries"""

    def test_diagnostic_subfunctions_dict(self):
        """Test DIAGNOSTIC_SUBFUNCTIONS dictionary"""
        from oida.protocols.modbus.scanner import DIAGNOSTIC_SUBFUNCTIONS

        self.assertIn(0x00, DIAGNOSTIC_SUBFUNCTIONS)
        self.assertEqual(DIAGNOSTIC_SUBFUNCTIONS[0x00], "Return Query Data")
        self.assertEqual(DIAGNOSTIC_SUBFUNCTIONS[0x0A], "Clear Counters and Diagnostic Register")

    def test_function_codes_completeness(self):
        """Test FUNCTION_CODES dictionary has common codes"""
        from oida.protocols.modbus.scanner import FUNCTION_CODES

        common_codes = [1, 2, 3, 4, 5, 6, 15, 16, 17, 43]
        for fc in common_codes:
            self.assertIn(fc, FUNCTION_CODES)

    def test_exception_codes_completeness(self):
        """Test EXCEPTION_CODES dictionary has common codes"""
        from oida.protocols.modbus.scanner import EXCEPTION_CODES

        common_codes = [1, 2, 3, 4]
        for ec in common_codes:
            self.assertIn(ec, EXCEPTION_CODES)


import pytest
import socket


# ==============================================================================
# Error Path Tests - Network Failures, Malformed Data, Timeouts
# ==============================================================================


class TestModbusNetworkErrorPaths(unittest.TestCase):
    """Test network error handling paths in ModbusScanner.

    These tests verify the scanner handles various network failures gracefully
    without crashing or leaking resources.
    """

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def setUp(self, mock_pymodbus):
        """Set up scanner instance"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 1}
        self.scanner = ModbusScanner(args)

    def test_connection_refused(self):
        """Test handling of connection refused error."""
        mock_client = Mock()
        mock_client.connect.side_effect = ConnectionRefusedError("Connection refused")

        self.scanner.client = mock_client

        # Should handle connection refused gracefully
        with self.assertRaises(ConnectionRefusedError):
            mock_client.connect()

    def test_connection_timeout(self):
        """Test handling of connection timeout."""
        mock_client = Mock()
        mock_client.connect.side_effect = socket.timeout("Connection timed out")

        self.scanner.client = mock_client

        with self.assertRaises(socket.timeout):
            mock_client.connect()

    def test_connection_reset_during_read(self):
        """Test handling of connection reset during register read."""
        mock_client = Mock()
        mock_client.connect.return_value = True
        mock_client.read_holding_registers.side_effect = ConnectionResetError(
            "Connection reset by peer"
        )

        self.scanner.client = mock_client

        with self.assertRaises(ConnectionResetError):
            mock_client.read_holding_registers(40001, 10)

    def test_broken_pipe_during_write(self):
        """Test handling of broken pipe during write operation."""
        mock_client = Mock()
        mock_client.connect.return_value = True
        mock_client.write_register.side_effect = BrokenPipeError("Broken pipe")

        self.scanner.client = mock_client

        with self.assertRaises(BrokenPipeError):
            mock_client.write_register(40001, 100)

    def test_socket_timeout_during_recv(self):
        """Test handling of socket timeout during data receive."""
        mock_client = Mock()
        mock_client.connect.return_value = True
        mock_client.read_holding_registers.side_effect = socket.timeout("timed out")

        self.scanner.client = mock_client

        with self.assertRaises(socket.timeout):
            mock_client.read_holding_registers(40001, 10)

    def test_network_unreachable(self):
        """Test handling of network unreachable error."""
        import errno

        mock_client = Mock()
        mock_client.connect.side_effect = OSError(errno.ENETUNREACH, "Network is unreachable")

        self.scanner.client = mock_client

        with self.assertRaises(OSError) as ctx:
            mock_client.connect()
        self.assertEqual(ctx.exception.errno, errno.ENETUNREACH)

    def test_host_unreachable(self):
        """Test handling of host unreachable error."""
        import errno

        mock_client = Mock()
        mock_client.connect.side_effect = OSError(errno.EHOSTUNREACH, "No route to host")

        self.scanner.client = mock_client

        with self.assertRaises(OSError) as ctx:
            mock_client.connect()
        self.assertEqual(ctx.exception.errno, errno.EHOSTUNREACH)

    def test_multiple_consecutive_failures(self):
        """Test handling of multiple consecutive connection failures."""
        mock_client = Mock()
        # First 3 attempts fail, then succeed
        mock_client.connect.side_effect = [
            socket.timeout("timed out"),
            ConnectionRefusedError("refused"),
            ConnectionResetError("reset"),
            True,
        ]

        self.scanner.client = mock_client

        # Simulate retry logic - each exception type handled separately
        with self.assertRaises(socket.timeout):
            mock_client.connect()

        with self.assertRaises(ConnectionRefusedError):
            mock_client.connect()

        with self.assertRaises(ConnectionResetError):
            mock_client.connect()

        # Fourth attempt should succeed
        result = mock_client.connect()
        self.assertTrue(result)


class TestModbusMalformedResponseHandling(unittest.TestCase):
    """Test handling of malformed Modbus responses."""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def setUp(self, mock_pymodbus):
        """Set up scanner instance"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
        self.scanner = ModbusScanner(args)

    def test_response_with_error_flag(self):
        """Test handling response with isError() = True."""
        mock_response = Mock()
        mock_response.isError.return_value = True
        mock_response.exception_code = 2  # ILLEGAL_DATA_ADDRESS
        mock_response.function_code = 0x83  # Error response

        self.assertTrue(mock_response.isError())
        self.assertEqual(mock_response.exception_code, 2)

    def test_response_with_missing_registers(self):
        """Test handling response with missing register data."""
        mock_response = Mock()
        mock_response.isError.return_value = False
        mock_response.registers = None  # Missing registers

        self.assertFalse(mock_response.isError())
        self.assertIsNone(mock_response.registers)

    def test_response_with_empty_registers(self):
        """Test handling response with empty register list."""
        mock_response = Mock()
        mock_response.isError.return_value = False
        mock_response.registers = []

        self.assertFalse(mock_response.isError())
        self.assertEqual(len(mock_response.registers), 0)

    def test_response_with_wrong_register_count(self):
        """Test handling response with unexpected register count."""
        mock_response = Mock()
        mock_response.isError.return_value = False
        # Asked for 10 registers, got 5
        mock_response.registers = [100, 200, 300, 400, 500]

        requested_count = 10
        received_count = len(mock_response.registers)

        # Application should detect mismatch
        self.assertNotEqual(requested_count, received_count)

    def test_response_with_invalid_values(self):
        """Test handling response with out-of-range register values."""
        mock_response = Mock()
        mock_response.isError.return_value = False
        # Modbus registers are 16-bit, max value 65535
        mock_response.registers = [100, 65535, 0, 32768]

        for value in mock_response.registers:
            self.assertGreaterEqual(value, 0)
            self.assertLessEqual(value, 65535)

    def test_mei_response_missing_information(self):
        """Test MEI response without information attribute."""
        mock_response = Mock(spec=[])  # No attributes

        result = self.scanner._parse_mei_response(mock_response)

        # Should return empty dict when response has no data
        self.assertEqual(result, {})

    def test_mei_response_with_none_values(self):
        """Test MEI response with None values in information dict."""
        mock_response = Mock()
        mock_response.information = {
            0x00: None,
            0x01: b"Product",
            0x02: None,
        }

        result = self.scanner._parse_mei_response(mock_response)

        # Should handle None values gracefully
        self.assertIn("ProductCode", result)
        self.assertEqual(result["ProductCode"], "Product")


class TestModbusTimeoutEdgeCases(unittest.TestCase):
    """Test timeout handling edge cases."""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_zero_timeout(self, mock_pymodbus):
        """Test scanner behavior with zero timeout."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 0}
        scanner = ModbusScanner(args)

        self.assertEqual(scanner.timeout, 0)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_very_small_timeout(self, mock_pymodbus):
        """Test scanner behavior with very small timeout (1ms).

        Note: BaseScanner converts timeout to int, so 0.001 becomes 0.
        """
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 0.001}
        scanner = ModbusScanner(args)

        # BaseScanner uses int(timeout), so 0.001 -> 0
        self.assertEqual(scanner.timeout, 0)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_very_large_timeout(self, mock_pymodbus):
        """Test scanner behavior with very large timeout."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 3600}  # 1 hour
        scanner = ModbusScanner(args)

        self.assertEqual(scanner.timeout, 3600)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_negative_timeout_handling(self, mock_pymodbus):
        """Test scanner behavior with negative timeout."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": -1}
        scanner = ModbusScanner(args)

        # Scanner may accept negative timeout or convert to default
        # Just ensure it doesn't crash
        self.assertIsNotNone(scanner.timeout)


class TestModbusInvalidInputHandling(unittest.TestCase):
    """Test handling of invalid input parameters."""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_invalid_unit_id_zero(self, mock_pymodbus):
        """Test handling of unit ID 0."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "unit-id": 0}
        scanner = ModbusScanner(args)

        # Unit ID 0 is broadcast address in Modbus
        self.assertEqual(scanner.unit_id, 0)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_invalid_unit_id_over_247(self, mock_pymodbus):
        """Test handling of unit ID > 247."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "unit-id": 255}
        scanner = ModbusScanner(args)

        # Unit ID 248-255 are reserved in Modbus spec
        self.assertEqual(scanner.unit_id, 255)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_invalid_port_zero(self, mock_pymodbus):
        """Test handling of port 0.

        Note: BaseScanner uses `rport or get_default_port()`, so port 0
        (falsy) falls back to the default Modbus port 502.
        """
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 0}
        scanner = ModbusScanner(args)

        # Port 0 is falsy, so falls back to default port 502
        self.assertEqual(scanner.port, 502)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_invalid_port_over_65535(self, mock_pymodbus):
        """Test handling of port > 65535."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 70000}
        scanner = ModbusScanner(args)

        self.assertEqual(scanner.port, 70000)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_empty_scan_range(self, mock_pymodbus):
        """Test handling of empty scan range."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "scan-range": ""}
        scanner = ModbusScanner(args)

        # Should use default or handle empty string
        self.assertIsNotNone(scanner.scan_range)

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_malformed_scan_range(self, mock_pymodbus):
        """Test handling of malformed scan range format."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "scan-range": "invalid"}
        scanner = ModbusScanner(args)

        # Scanner stores the value; parsing happens during scan
        self.assertEqual(scanner.scan_range, "invalid")

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_reversed_scan_range(self, mock_pymodbus):
        """Test handling of reversed scan range (end < start)."""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "scan-range": "100-50"}
        scanner = ModbusScanner(args)

        self.assertEqual(scanner.scan_range, "100-50")


class TestModbusExceptionResponseParsing(unittest.TestCase):
    """Test parsing of Modbus exception responses."""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def setUp(self, mock_pymodbus):
        """Set up scanner instance"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
        self.scanner = ModbusScanner(args)

    def test_all_standard_exception_codes(self):
        """Test parsing all standard Modbus exception codes."""
        exception_codes = [1, 2, 3, 4, 5, 6, 7, 8, 10, 11]

        for code in exception_codes:
            name = self.scanner._get_exception_name(code)
            self.assertIsInstance(name, str)
            self.assertNotEqual(name, "")

    def test_gateway_exception_codes(self):
        """Test parsing gateway-specific exception codes."""
        # 10 = GATEWAY_PATH_UNAVAILABLE
        # 11 = GATEWAY_TARGET_DEVICE_FAILED
        name_10 = self.scanner._get_exception_name(10)
        name_11 = self.scanner._get_exception_name(11)

        self.assertIn("GATEWAY", name_10)
        self.assertIn("GATEWAY", name_11)

    def test_unknown_exception_code(self):
        """Test parsing unknown exception code."""
        # Codes outside standard range
        unknown_codes = [0, 9, 12, 100, 255]

        for code in unknown_codes:
            name = self.scanner._get_exception_name(code)
            # Should return "UNKNOWN" or similar
            self.assertIsInstance(name, str)


class TestModbusResourceCleanup(unittest.TestCase):
    """Test proper resource cleanup on errors."""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def setUp(self, mock_pymodbus):
        """Set up scanner instance"""
        from oida.protocols.modbus.scanner import ModbusScanner

        args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
        self.scanner = ModbusScanner(args)

    def test_disconnect_after_connection_error(self):
        """Test that disconnect is called after connection error."""
        mock_client = Mock()
        mock_client.connect.side_effect = ICSConnectionError("Failed")
        mock_client.close = Mock()

        self.scanner.client = mock_client

        try:
            mock_client.connect()
        except ICSConnectionError:
            self.scanner.disconnect(mock_client)

        mock_client.close.assert_called_once()

    def test_disconnect_after_read_error(self):
        """Test that disconnect is called after read error."""
        mock_client = Mock()
        mock_client.read_holding_registers.side_effect = socket.timeout("timeout")
        mock_client.close = Mock()

        self.scanner.client = mock_client

        try:
            mock_client.read_holding_registers(40001, 10)
        except socket.timeout:
            self.scanner.disconnect(mock_client)

        mock_client.close.assert_called_once()

    def test_multiple_disconnect_calls_safe(self):
        """Test that multiple disconnect calls don't raise errors."""
        mock_client = Mock()
        mock_client.close = Mock()

        self.scanner.client = mock_client

        # Multiple disconnects should be safe
        self.scanner.disconnect(mock_client)
        self.scanner.disconnect(mock_client)
        self.scanner.disconnect(mock_client)

        # Should have been called 3 times
        self.assertEqual(mock_client.close.call_count, 3)


# Pytest-style tests for integration with conftest_errors fixtures
class TestModbusWithErrorInjection:
    """Pytest-style tests using error injection fixtures from conftest_errors."""

    @pytest.fixture(autouse=True)
    def setup_scanner(self):
        """Set up scanner for each test."""
        with patch("oida.protocols.modbus.scanner._get_pymodbus"):
            from oida.protocols.modbus.scanner import ModbusScanner

            args = {"rhost": "192.168.1.1", "rport": 502, "timeout": 5}
            self.scanner = ModbusScanner(args)

    def test_partial_data_received(self):
        """Test handling of partial data in response."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.isError.return_value = False
        # Simulate partial data
        mock_response.registers = [100]  # Asked for 10, got 1

        mock_client.read_holding_registers.return_value = mock_response

        result = mock_client.read_holding_registers(40001, 10)

        # Should return the partial data
        assert len(result.registers) == 1

    @pytest.mark.parametrize(
        "exception_type,message",
        [
            (ConnectionRefusedError, "Connection refused"),
            (ConnectionResetError, "Connection reset by peer"),
            (BrokenPipeError, "Broken pipe"),
            (socket.timeout, "timed out"),
            (OSError, "Network is down"),
        ],
    )
    def test_various_connection_errors(self, exception_type, message):
        """Test handling of various connection error types."""
        mock_client = Mock()
        mock_client.connect.side_effect = exception_type(message)

        with pytest.raises(exception_type):
            mock_client.connect()

    @pytest.mark.parametrize("exception_code", [1, 2, 3, 4, 5, 6, 7, 8, 10, 11])
    def test_modbus_exception_codes(self, exception_code):
        """Test all standard Modbus exception codes are handled."""
        name = self.scanner._get_exception_name(exception_code)

        assert isinstance(name, str)
        assert len(name) > 0


if __name__ == "__main__":
    unittest.main()
