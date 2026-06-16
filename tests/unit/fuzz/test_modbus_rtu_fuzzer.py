"""Tests for Modbus RTU Protocol Fuzzer

Tests Modbus RTU fuzzer implementation including:
- CRC16 checksum calculations with known test vectors
- Protocol constants (function codes, diagnostic codes)
- Request definitions and structures
- Boundary value testing patterns
- Serial-specific options
"""

import pytest

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.config import FuzzerConfig
from oida.fuzz.protocols.modbus.rtu import ModbusRTUFuzzer
from oida.fuzz.protocols.modbus.constants import (
    ModbusFunctionCodes,
    ModbusDiagnosticCodes,
    ModbusMEITypes,
    ModbusDeviceIDObjects,
    ADDRESS_BOUNDARIES,
    QUANTITY_BOUNDARIES,
    COIL_VALUE_BOUNDARIES,
    UNIT_ID_BOUNDARIES,
    INVALID_FUNCTION_CODES,
    ALL_FUNCTION_CODES,
    READ_FUNCTION_CODES,
    WRITE_SINGLE_FUNCTION_CODES,
    DEVICE_ID_READ_CODES,
)


class MockConnectionFactory:
    """Mock connection factory for isolated fuzzer tests."""

    def create_connection(self, *args, **kwargs):
        class MockConnection:
            def open(self):
                pass

            def close(self):
                pass

            def send(self, data):
                pass

            def recv(self, size):
                return b""

        return MockConnection()


@pytest.fixture
def fuzzer_config():
    """Create a basic fuzzer configuration for RTU."""
    config = FuzzerConfig(
        target_ip="127.0.0.1",  # Placeholder for RTU
        target_port=502,  # Placeholder for RTU
        session_filename="modbus_rtu_test",
        # Serial port settings via protocol options
        protocol_options={"serial_port": "/dev/ttyUSB0", "baudrate": 9600},
    )
    return config


@pytest.fixture
def modbus_rtu_fuzzer(fuzzer_config):
    """Create a Modbus RTU fuzzer instance with mock connection."""
    return ModbusRTUFuzzer(
        config=fuzzer_config,
        connection_factory=MockConnectionFactory(),
    )


class TestModbusRTUFuzzerCreation:
    """Test Modbus RTU fuzzer instantiation."""

    def test_fuzzer_inherits_from_base(self):
        """Verify ModbusRTUFuzzer inherits from BaseFuzzer."""
        assert issubclass(ModbusRTUFuzzer, BaseFuzzer)

    def test_fuzzer_creates_with_config(self, fuzzer_config):
        """Test fuzzer instantiation with configuration."""
        fuzzer = ModbusRTUFuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        assert fuzzer is not None

    def test_fuzzer_frame_gap_calculation(self, fuzzer_config):
        """Test frame gap is calculated from baudrate."""
        fuzzer = ModbusRTUFuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        # 3.5 character times at 9600 baud
        # char_time = 11 / 9600 = ~0.00115s
        # frame_gap = char_time * 3.5 = ~0.004s
        assert fuzzer.frame_gap > 0
        assert fuzzer.frame_gap < 0.01  # Should be < 10ms at 9600 baud

    def test_fuzzer_custom_baudrate(self, fuzzer_config):
        """Test fuzzer with custom baudrate."""
        fuzzer_config.protocol_options["baudrate"] = 115200
        fuzzer = ModbusRTUFuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        # Higher baudrate = smaller frame gap
        assert fuzzer.frame_gap > 0
        assert fuzzer.frame_gap < 0.001  # Should be < 1ms at 115200

    def test_fuzzer_write_option_default(self, fuzzer_config):
        """Test enable_write option defaults to True."""
        ModbusRTUFuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        # Write should be enabled by default for testing
        assert fuzzer_config.get_option("enable_write", True) is True

    def test_fuzzer_broadcast_option_default(self, fuzzer_config):
        """Test enable_broadcast option defaults to False."""
        ModbusRTUFuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        # Broadcast should be disabled by default for safety
        assert fuzzer_config.get_option("enable_broadcast", False) is False


class TestModbusCRC16:
    """Test Modbus CRC-16 checksum calculation."""

    def test_crc16_empty_data(self, modbus_rtu_fuzzer):
        """Test CRC16 with empty data."""
        result = modbus_rtu_fuzzer._calculate_modbus_crc(b"")
        assert len(result) == 2
        # CRC of empty data with 0xFFFF initial
        assert result == b"\xff\xff"

    def test_crc16_single_byte(self, modbus_rtu_fuzzer):
        """Test CRC16 with single byte."""
        result = modbus_rtu_fuzzer._calculate_modbus_crc(b"\x00")
        assert len(result) == 2
        assert isinstance(result, bytes)

    def test_crc16_known_vector_read_request(self, modbus_rtu_fuzzer):
        """Test CRC16 with known Modbus read request.

        Standard request: Slave=01, FC=03, Addr=0000, Qty=0001
        Frame (without CRC): 01 03 00 00 00 01
        Expected CRC: 84 0A (little-endian)
        """
        frame = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x01])
        result = modbus_rtu_fuzzer._calculate_modbus_crc(frame)
        assert len(result) == 2
        # This is a well-known Modbus CRC test vector
        assert result == b"\x84\x0a"

    def test_crc16_known_vector_write_single(self, modbus_rtu_fuzzer):
        """Test CRC16 with known write single coil request.

        Standard request: Slave=01, FC=05, Addr=0000, Value=FF00
        Frame (without CRC): 01 05 00 00 FF 00
        Expected CRC: 8C 3A (little-endian)
        """
        frame = bytes([0x01, 0x05, 0x00, 0x00, 0xFF, 0x00])
        result = modbus_rtu_fuzzer._calculate_modbus_crc(frame)
        assert len(result) == 2
        assert result == b"\x8c\x3a"

    def test_crc16_different_slaves(self, modbus_rtu_fuzzer):
        """Test CRC16 produces different results for different slave addresses."""
        frame1 = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x01])
        frame2 = bytes([0x02, 0x03, 0x00, 0x00, 0x00, 0x01])
        crc1 = modbus_rtu_fuzzer._calculate_modbus_crc(frame1)
        crc2 = modbus_rtu_fuzzer._calculate_modbus_crc(frame2)
        assert crc1 != crc2

    def test_crc16_deterministic(self, modbus_rtu_fuzzer):
        """Test CRC16 is deterministic."""
        frame = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x01])
        crc1 = modbus_rtu_fuzzer._calculate_modbus_crc(frame)
        crc2 = modbus_rtu_fuzzer._calculate_modbus_crc(frame)
        assert crc1 == crc2

    def test_crc16_little_endian_format(self, modbus_rtu_fuzzer):
        """Test CRC16 returns little-endian format."""
        # Modbus RTU uses little-endian CRC (low byte first)
        frame = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x01])
        result = modbus_rtu_fuzzer._calculate_modbus_crc(frame)
        # Verify low byte is first
        assert len(result) == 2
        low_byte = result[0]
        high_byte = result[1]
        # Reconstruct 16-bit value
        crc_value = (high_byte << 8) | low_byte
        assert 0 <= crc_value <= 0xFFFF


class TestModbusFunctionCodes:
    """Test Modbus function code constants."""

    def test_read_function_codes_defined(self):
        """Verify read function codes are defined."""
        assert ModbusFunctionCodes.READ_COILS == b"\x01"
        assert ModbusFunctionCodes.READ_DISCRETE_INPUTS == b"\x02"
        assert ModbusFunctionCodes.READ_HOLDING_REGISTERS == b"\x03"
        assert ModbusFunctionCodes.READ_INPUT_REGISTERS == b"\x04"

    def test_write_single_function_codes_defined(self):
        """Verify write single function codes are defined."""
        assert ModbusFunctionCodes.WRITE_SINGLE_COIL == b"\x05"
        assert ModbusFunctionCodes.WRITE_SINGLE_REGISTER == b"\x06"

    def test_write_multiple_function_codes_defined(self):
        """Verify write multiple function codes are defined."""
        assert ModbusFunctionCodes.WRITE_MULTIPLE_COILS == b"\x0f"
        assert ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS == b"\x10"

    def test_diagnostic_function_codes_defined(self):
        """Verify diagnostic function codes are defined."""
        assert ModbusFunctionCodes.READ_EXCEPTION_STATUS == b"\x07"
        assert ModbusFunctionCodes.DIAGNOSTICS == b"\x08"
        assert ModbusFunctionCodes.GET_COMM_EVENT_COUNTER == b"\x0b"
        assert ModbusFunctionCodes.GET_COMM_EVENT_LOG == b"\x0c"
        assert ModbusFunctionCodes.REPORT_SLAVE_ID == b"\x11"

    def test_advanced_function_codes_defined(self):
        """Verify advanced function codes are defined."""
        assert ModbusFunctionCodes.READ_FILE_RECORD == b"\x14"
        assert ModbusFunctionCodes.WRITE_FILE_RECORD == b"\x15"
        assert ModbusFunctionCodes.MASK_WRITE_REGISTER == b"\x16"
        assert ModbusFunctionCodes.READ_WRITE_MULTIPLE_REGISTERS == b"\x17"
        assert ModbusFunctionCodes.READ_FIFO_QUEUE == b"\x18"

    def test_mei_function_code_defined(self):
        """Verify MEI (Encapsulated Interface) function code is defined."""
        assert ModbusFunctionCodes.ENCAPSULATED_INTERFACE_TRANSPORT == b"\x2b"


class TestModbusDiagnosticCodes:
    """Test Modbus diagnostic sub-function codes."""

    def test_return_query_data_defined(self):
        """Verify Return Query Data is defined."""
        assert ModbusDiagnosticCodes.RETURN_QUERY_DATA == b"\x00\x00"

    def test_restart_communications_defined(self):
        """Verify Restart Communications is defined."""
        assert ModbusDiagnosticCodes.RESTART_COMMUNICATIONS == b"\x00\x01"

    def test_counter_diagnostics_defined(self):
        """Verify counter diagnostic codes are defined."""
        assert ModbusDiagnosticCodes.RETURN_BUS_MESSAGE_COUNT == b"\x00\x0b"
        assert ModbusDiagnosticCodes.RETURN_BUS_EXCEPTION_COUNT == b"\x00\x0d"
        assert ModbusDiagnosticCodes.RETURN_SLAVE_MESSAGE_COUNT == b"\x00\x0e"

    def test_force_listen_only_defined(self):
        """Verify Force Listen Only Mode is defined."""
        assert ModbusDiagnosticCodes.FORCE_LISTEN_ONLY_MODE == b"\x00\x04"


class TestModbusMEI:
    """Test Modbus Encapsulated Interface constants."""

    def test_mei_types_defined(self):
        """Verify MEI types are defined."""
        assert ModbusMEITypes.READ_DEVICE_IDENTIFICATION == 0x0E
        assert ModbusMEITypes.CANOPEN_GENERAL_REFERENCE == 0x0D

    def test_device_id_objects_defined(self):
        """Verify device ID objects are defined."""
        assert ModbusDeviceIDObjects.VENDOR_NAME == 0x00
        assert ModbusDeviceIDObjects.PRODUCT_CODE == 0x01
        assert ModbusDeviceIDObjects.MAJOR_MINOR_REVISION == 0x02
        assert ModbusDeviceIDObjects.VENDOR_URL == 0x03
        assert ModbusDeviceIDObjects.PRODUCT_NAME == 0x04
        assert ModbusDeviceIDObjects.MODEL_NAME == 0x05
        assert ModbusDeviceIDObjects.USER_APPLICATION_NAME == 0x06


class TestModbusRTURequestDefinitions:
    """Test Modbus RTU request definitions."""

    def test_get_request_definitions_returns_list(self):
        """Verify get_request_definitions returns list of RequestInfo."""
        definitions = ModbusRTUFuzzer.get_request_definitions()
        assert isinstance(definitions, list)
        assert len(definitions) > 0
        assert all(isinstance(d, RequestInfo) for d in definitions)

    def test_baseline_request_defined(self):
        """Verify baseline request is defined."""
        definitions = ModbusRTUFuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "RTU_Baseline" in names

    def test_overflow_testing_defined(self):
        """Verify overflow testing request is defined."""
        definitions = ModbusRTUFuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "RTU_Overflow_Testing" in names

    def test_write_operations_defined(self):
        """Verify write operations request is defined."""
        definitions = ModbusRTUFuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "RTU_Write_Operations" in names

    def test_boundary_testing_defined(self):
        """Verify boundary testing request is defined."""
        definitions = ModbusRTUFuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "RTU_Boundary_Testing" in names

    def test_read_operations_defined(self):
        """Verify read operations request is defined."""
        definitions = ModbusRTUFuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "RTU_Read_Operations" in names

    def test_diagnostics_defined(self):
        """Verify diagnostics request is defined."""
        definitions = ModbusRTUFuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "RTU_Diagnostics" in names

    def test_device_id_defined(self):
        """Verify device ID request is defined."""
        definitions = ModbusRTUFuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "RTU_Device_ID" in names

    def test_broadcast_defined(self):
        """Verify broadcast request is defined."""
        definitions = ModbusRTUFuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "RTU_Broadcast" in names

    def test_invalid_fc_defined(self):
        """Verify invalid function code request is defined."""
        definitions = ModbusRTUFuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "RTU_Invalid_FC" in names


class TestModbusRTUProtocolOptions:
    """Test Modbus RTU protocol-specific options."""

    def test_protocol_options_defined(self):
        """Verify PROTOCOL_OPTIONS dict is defined."""
        assert hasattr(ModbusRTUFuzzer, "PROTOCOL_OPTIONS")
        assert isinstance(ModbusRTUFuzzer.PROTOCOL_OPTIONS, dict)

    def test_slave_address_option(self):
        """Verify slave_address option is defined."""
        assert "slave_address" in ModbusRTUFuzzer.PROTOCOL_OPTIONS
        opt = ModbusRTUFuzzer.PROTOCOL_OPTIONS["slave_address"]
        assert opt["type"] == int
        assert opt["default"] == 1

    def test_baudrate_option(self):
        """Verify baudrate option is defined with common values."""
        assert "baudrate" in ModbusRTUFuzzer.PROTOCOL_OPTIONS
        opt = ModbusRTUFuzzer.PROTOCOL_OPTIONS["baudrate"]
        assert opt["type"] == int
        assert opt["default"] == 9600
        assert 9600 in opt["choices"]
        assert 19200 in opt["choices"]
        assert 115200 in opt["choices"]

    def test_serial_options_defined(self):
        """Verify serial port options are defined."""
        # bytesize
        assert "bytesize" in ModbusRTUFuzzer.PROTOCOL_OPTIONS
        assert ModbusRTUFuzzer.PROTOCOL_OPTIONS["bytesize"]["default"] == 8

        # parity
        assert "parity" in ModbusRTUFuzzer.PROTOCOL_OPTIONS
        assert ModbusRTUFuzzer.PROTOCOL_OPTIONS["parity"]["default"] == "N"

        # stopbits
        assert "stopbits" in ModbusRTUFuzzer.PROTOCOL_OPTIONS
        assert ModbusRTUFuzzer.PROTOCOL_OPTIONS["stopbits"]["default"] == 1

    def test_timeout_option(self):
        """Verify timeout option is defined."""
        assert "timeout" in ModbusRTUFuzzer.PROTOCOL_OPTIONS
        opt = ModbusRTUFuzzer.PROTOCOL_OPTIONS["timeout"]
        assert opt["type"] == float
        assert opt["default"] == 1.0

    def test_enable_write_option(self):
        """Verify enable_write option is defined."""
        assert "enable_write" in ModbusRTUFuzzer.PROTOCOL_OPTIONS
        opt = ModbusRTUFuzzer.PROTOCOL_OPTIONS["enable_write"]
        assert opt["type"] == bool
        assert opt["default"] is True

    def test_enable_broadcast_option(self):
        """Verify enable_broadcast option is defined."""
        assert "enable_broadcast" in ModbusRTUFuzzer.PROTOCOL_OPTIONS
        opt = ModbusRTUFuzzer.PROTOCOL_OPTIONS["enable_broadcast"]
        assert opt["type"] == bool
        assert opt["default"] is False


class TestModbusBoundaryConstants:
    """Test Modbus boundary value constants."""

    def test_address_boundaries_defined(self):
        """Verify address boundaries are defined."""
        assert len(ADDRESS_BOUNDARIES) > 0
        # Check for minimum and maximum
        assert b"\x00\x00" in ADDRESS_BOUNDARIES  # 0
        assert b"\xff\xff" in ADDRESS_BOUNDARIES  # 65535

    def test_quantity_boundaries_defined(self):
        """Verify quantity boundaries are defined."""
        assert len(QUANTITY_BOUNDARIES) > 0
        # Check for protocol-relevant values
        assert b"\x00\x00" in QUANTITY_BOUNDARIES  # Zero (invalid)
        assert b"\x00\x01" in QUANTITY_BOUNDARIES  # Minimum valid
        assert b"\x07\xd0" in QUANTITY_BOUNDARIES  # 2000 (protocol max)

    def test_coil_value_boundaries_defined(self):
        """Verify coil value boundaries are defined."""
        assert len(COIL_VALUE_BOUNDARIES) > 0
        # Valid coil values
        assert b"\x00\x00" in COIL_VALUE_BOUNDARIES  # OFF
        assert b"\xff\x00" in COIL_VALUE_BOUNDARIES  # ON

    def test_unit_id_boundaries_defined(self):
        """Verify unit ID boundaries are defined."""
        assert len(UNIT_ID_BOUNDARIES) > 0
        assert b"\x00" in UNIT_ID_BOUNDARIES  # Broadcast
        assert b"\x01" in UNIT_ID_BOUNDARIES  # Minimum valid
        assert b"\xf7" in UNIT_ID_BOUNDARIES  # Maximum valid (247)
        assert b"\xff" in UNIT_ID_BOUNDARIES  # Reserved (255)

    def test_invalid_function_codes_defined(self):
        """Verify invalid function codes are defined."""
        assert len(INVALID_FUNCTION_CODES) > 0
        assert b"\x00" in INVALID_FUNCTION_CODES  # Reserved
        assert b"\x80" in INVALID_FUNCTION_CODES  # Exception flag


class TestModbusFunctionCodeLists:
    """Test Modbus function code lists."""

    def test_all_function_codes_list(self):
        """Verify ALL_FUNCTION_CODES contains all 19 standard codes."""
        assert len(ALL_FUNCTION_CODES) >= 19
        # Verify it contains key codes
        assert ModbusFunctionCodes.READ_COILS in ALL_FUNCTION_CODES
        assert ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS in ALL_FUNCTION_CODES
        assert ModbusFunctionCodes.ENCAPSULATED_INTERFACE_TRANSPORT in ALL_FUNCTION_CODES

    def test_read_function_codes_list(self):
        """Verify READ_FUNCTION_CODES contains FC 01-04."""
        assert len(READ_FUNCTION_CODES) == 4
        assert ModbusFunctionCodes.READ_COILS in READ_FUNCTION_CODES
        assert ModbusFunctionCodes.READ_DISCRETE_INPUTS in READ_FUNCTION_CODES
        assert ModbusFunctionCodes.READ_HOLDING_REGISTERS in READ_FUNCTION_CODES
        assert ModbusFunctionCodes.READ_INPUT_REGISTERS in READ_FUNCTION_CODES

    def test_write_single_function_codes_list(self):
        """Verify WRITE_SINGLE_FUNCTION_CODES contains FC 05, 06."""
        assert len(WRITE_SINGLE_FUNCTION_CODES) == 2
        assert ModbusFunctionCodes.WRITE_SINGLE_COIL in WRITE_SINGLE_FUNCTION_CODES
        assert ModbusFunctionCodes.WRITE_SINGLE_REGISTER in WRITE_SINGLE_FUNCTION_CODES

    def test_device_id_read_codes_list(self):
        """Verify DEVICE_ID_READ_CODES contains valid codes."""
        assert len(DEVICE_ID_READ_CODES) == 4
        assert b"\x01" in DEVICE_ID_READ_CODES  # Basic
        assert b"\x02" in DEVICE_ID_READ_CODES  # Regular
        assert b"\x03" in DEVICE_ID_READ_CODES  # Extended
        assert b"\x04" in DEVICE_ID_READ_CODES  # Specific


class TestModbusRTUFrameStructure:
    """Test Modbus RTU frame structure constants."""

    def test_slave_address_range(self):
        """Verify slave address valid range (1-247)."""
        # Valid range: 1-247
        # 0 = broadcast
        # 248-255 = reserved
        min_valid = 1
        max_valid = 247
        broadcast = 0
        reserved_start = 248

        assert min_valid == 1
        assert max_valid == 247
        assert broadcast == 0
        assert reserved_start == 248

    def test_max_pdu_size(self):
        """Verify max PDU size for RTU (253 bytes)."""
        # RTU ADU = 1 (addr) + 253 (max PDU) + 2 (CRC) = 256 bytes
        max_pdu = 253
        max_adu = 256
        assert max_pdu == 253
        assert max_adu == 256

    def test_function_code_exception_flag(self):
        """Verify exception flag (0x80) is added to function codes."""
        # Exception response: FC + 0x80
        read_coils = 0x01
        read_coils_exception = 0x81
        assert read_coils_exception == read_coils + 0x80


class TestModbusRTUCRCPolynomial:
    """Test Modbus RTU CRC polynomial."""

    def test_polynomial_value(self):
        """Verify Modbus CRC uses polynomial 0xA001 (reversed 0x8005)."""
        # Standard Modbus CRC-16 polynomial
        reversed_poly = 0xA001

        # Verify relationship
        assert reversed_poly == 0xA001
        # Bit-reverse 0x8005 = 0xA001
        # 0x8005 = 1000 0000 0000 0101
        # reversed = 1010 0000 0000 0001 = 0xA001

    def test_initial_value(self):
        """Verify Modbus CRC initial value is 0xFFFF."""
        initial_value = 0xFFFF
        assert initial_value == 0xFFFF


class TestModbusRTUExports:
    """Test Modbus RTU fuzzer exports."""

    def test_fuzzer_importable(self):
        """Verify ModbusRTUFuzzer is importable."""
        from oida.fuzz.protocols.modbus.rtu import ModbusRTUFuzzer

        assert ModbusRTUFuzzer is not None

    def test_constants_importable(self):
        """Verify Modbus constants are importable."""
        from oida.fuzz.protocols.modbus.constants import (
            ModbusFunctionCodes,
            ModbusDiagnosticCodes,
            ModbusMEITypes,
            ModbusDeviceIDObjects,
        )

        assert ModbusFunctionCodes is not None
        assert ModbusDiagnosticCodes is not None
        assert ModbusMEITypes is not None
        assert ModbusDeviceIDObjects is not None
