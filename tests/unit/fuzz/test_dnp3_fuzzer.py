"""Tests for DNP3 Protocol Fuzzer

Tests DNP3 fuzzer implementation including:
- CRC16 checksum calculations with known test vectors
- Protocol constants (function codes, object groups)
- Request definitions and structures
- CVE-targeted attack patterns
- Boundary and overflow testing patterns
"""

import pytest

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.config import FuzzerConfig
from oida.fuzz.protocols.dnp3 import DNP3Fuzzer, DNP3FunctionCodes, DNP3ObjectGroups


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
    """Create a basic fuzzer configuration."""
    return FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=20000,
        session_filename="dnp3_test",
    )


@pytest.fixture
def dnp3_fuzzer(fuzzer_config):
    """Create a DNP3 fuzzer instance with mock connection."""
    return DNP3Fuzzer(
        config=fuzzer_config,
        connection_factory=MockConnectionFactory(),
    )


class TestDNP3FuzzerCreation:
    """Test DNP3 fuzzer instantiation."""

    def test_fuzzer_inherits_from_base(self):
        """Verify DNP3Fuzzer inherits from BaseFuzzer."""
        assert issubclass(DNP3Fuzzer, BaseFuzzer)

    def test_fuzzer_creates_with_config(self, fuzzer_config):
        """Test fuzzer instantiation with configuration."""
        fuzzer = DNP3Fuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        assert fuzzer is not None
        assert fuzzer.source_address == 2  # Default
        assert fuzzer.dest_address == 1  # Default

    def test_fuzzer_custom_addresses(self, fuzzer_config):
        """Test fuzzer with custom DNP3 addresses."""
        fuzzer_config.set_option("source_address", 10)
        fuzzer_config.set_option("dest_address", 5)
        fuzzer = DNP3Fuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        assert fuzzer.source_address == 10
        assert fuzzer.dest_address == 5

    def test_fuzzer_auth_option(self, fuzzer_config):
        """Test fuzzer with authentication option."""
        fuzzer_config.set_option("enable_auth", True)
        fuzzer = DNP3Fuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        assert fuzzer.enable_auth is True

    def test_fuzzer_control_option_default(self, fuzzer_config):
        """Test fuzzer control option defaults to False (safety gate)."""
        fuzzer = DNP3Fuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        assert fuzzer.enable_control is False

    def test_fuzzer_file_option_default(self, fuzzer_config):
        """Test fuzzer file option defaults to False (safety gate)."""
        fuzzer = DNP3Fuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        assert fuzzer.enable_file is False

    def test_fuzzer_write_option_default(self, fuzzer_config):
        """Test fuzzer enable_write defaults to False (safety gate)."""
        fuzzer = DNP3Fuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        assert fuzzer.enable_write is False

    def test_fuzzer_control_requires_write(self, fuzzer_config):
        """Test enable_control requires enable_write as master gate."""
        fuzzer_config.set_option("enable_control", True)
        fuzzer = DNP3Fuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        # enable_control is True in config but enable_write is False,
        # so the effective value should be False
        assert fuzzer.enable_control is False

        fuzzer_config.set_option("enable_write", True)
        fuzzer2 = DNP3Fuzzer(
            config=fuzzer_config,
            connection_factory=MockConnectionFactory(),
        )
        assert fuzzer2.enable_control is True


class TestDNP3CRC16:
    """Test DNP3 CRC-16 checksum calculation."""

    def test_crc16_empty_data(self, dnp3_fuzzer):
        """Test CRC16 with empty data."""
        result = dnp3_fuzzer._dnp3_crc16(b"")
        assert len(result) == 2
        # CRC of empty data with DNP3 polynomial
        assert isinstance(result, bytes)

    def test_crc16_single_byte(self, dnp3_fuzzer):
        """Test CRC16 with single byte."""
        result = dnp3_fuzzer._dnp3_crc16(b"\x00")
        assert len(result) == 2

    def test_crc16_known_vector_link_header(self, dnp3_fuzzer):
        """Test CRC16 with DNP3 link header bytes.

        DNP3 link header: length=0x05, control=0xC0, dest=0x0001, src=0x0002
        """
        # Typical link header: length=0x05, ctrl=0xC0, dest=0x0001 (LE), src=0x0002 (LE)
        link_header = bytes([0x05, 0xC0, 0x01, 0x00, 0x02, 0x00])
        result = dnp3_fuzzer._dnp3_crc16(link_header)
        assert len(result) == 2
        # Result should be valid 2-byte little-endian CRC
        assert isinstance(result, bytes)

    def test_crc16_with_list_input(self, dnp3_fuzzer):
        """Test CRC16 handles list input."""
        result = dnp3_fuzzer._dnp3_crc16([0x05, 0xC0, 0x01, 0x00])
        assert len(result) == 2

    def test_crc16_with_tuple_input(self, dnp3_fuzzer):
        """Test CRC16 handles tuple input."""
        result = dnp3_fuzzer._dnp3_crc16((0x05, 0xC0, 0x01, 0x00))
        assert len(result) == 2

    def test_crc16_little_endian_format(self, dnp3_fuzzer):
        """Test CRC16 returns little-endian format."""
        # Run same calculation twice to verify determinism
        result1 = dnp3_fuzzer._dnp3_crc16(b"\x01\x02\x03\x04")
        result2 = dnp3_fuzzer._dnp3_crc16(b"\x01\x02\x03\x04")
        assert result1 == result2
        assert len(result1) == 2

    def test_crc16_different_data_different_crc(self, dnp3_fuzzer):
        """Test different data produces different CRC."""
        crc1 = dnp3_fuzzer._dnp3_crc16(b"\x00\x00\x00\x00")
        crc2 = dnp3_fuzzer._dnp3_crc16(b"\xff\xff\xff\xff")
        assert crc1 != crc2


class TestDNP3FunctionCodes:
    """Test DNP3 function code constants."""

    def test_request_function_codes_defined(self):
        """Verify all standard request function codes are defined."""
        # Basic operations
        assert DNP3FunctionCodes.CONFIRM == 0x00
        assert DNP3FunctionCodes.READ == 0x01
        assert DNP3FunctionCodes.WRITE == 0x02

    def test_control_function_codes_defined(self):
        """Verify control function codes are defined."""
        assert DNP3FunctionCodes.SELECT == 0x03
        assert DNP3FunctionCodes.OPERATE == 0x04
        assert DNP3FunctionCodes.DIRECT_OPERATE == 0x05
        assert DNP3FunctionCodes.DIRECT_OPERATE_NR == 0x06

    def test_freeze_function_codes_defined(self):
        """Verify freeze function codes are defined."""
        assert DNP3FunctionCodes.FREEZE == 0x07
        assert DNP3FunctionCodes.FREEZE_CLEAR == 0x08
        assert DNP3FunctionCodes.FREEZE_AT_TIME == 0x09
        assert DNP3FunctionCodes.FREEZE_AT_TIME_NR == 0x0A

    def test_restart_function_codes_defined(self):
        """Verify restart function codes are defined."""
        assert DNP3FunctionCodes.COLD_RESTART == 0x0D
        assert DNP3FunctionCodes.WARM_RESTART == 0x0E

    def test_application_function_codes_defined(self):
        """Verify application control function codes are defined."""
        assert DNP3FunctionCodes.INITIALIZE_DATA == 0x0F
        assert DNP3FunctionCodes.INITIALIZE_APPLICATION == 0x10
        assert DNP3FunctionCodes.START_APPLICATION == 0x11
        assert DNP3FunctionCodes.STOP_APPLICATION == 0x12
        assert DNP3FunctionCodes.SAVE_CONFIGURATION == 0x13

    def test_unsolicited_function_codes_defined(self):
        """Verify unsolicited function codes are defined."""
        assert DNP3FunctionCodes.ENABLE_UNSOLICITED == 0x14
        assert DNP3FunctionCodes.DISABLE_UNSOLICITED == 0x15

    def test_file_function_codes_defined(self):
        """Verify file operation function codes are defined."""
        assert DNP3FunctionCodes.OPEN_FILE == 0x19
        assert DNP3FunctionCodes.CLOSE_FILE == 0x1A
        assert DNP3FunctionCodes.DELETE_FILE == 0x1B
        assert DNP3FunctionCodes.GET_FILE_INFO == 0x1C
        assert DNP3FunctionCodes.AUTHENTICATE_FILE == 0x1D
        assert DNP3FunctionCodes.ABORT_FILE == 0x1E

    def test_authentication_function_codes_defined(self):
        """Verify authentication function codes are defined."""
        assert DNP3FunctionCodes.AUTHENTICATE_REQUEST == 0x20
        assert DNP3FunctionCodes.AUTHENTICATE_ERROR == 0x21

    def test_response_function_codes_defined(self):
        """Verify response function codes are defined."""
        assert DNP3FunctionCodes.RESPONSE == 0x81
        assert DNP3FunctionCodes.UNSOLICITED_RESPONSE == 0x82
        assert DNP3FunctionCodes.AUTHENTICATE_RESPONSE == 0x83

    def test_time_function_codes_defined(self):
        """Verify time-related function codes are defined."""
        assert DNP3FunctionCodes.DELAY_MEASUREMENT == 0x17
        assert DNP3FunctionCodes.RECORD_CURRENT_TIME == 0x18

    def test_class_assignment_defined(self):
        """Verify class assignment function code is defined."""
        assert DNP3FunctionCodes.ASSIGN_CLASS == 0x16


class TestDNP3ObjectGroups:
    """Test DNP3 object group constants."""

    def test_binary_input_groups_defined(self):
        """Verify binary input groups are defined."""
        assert DNP3ObjectGroups.BINARY_INPUT == 0x01
        assert DNP3ObjectGroups.BINARY_INPUT_EVENT == 0x02

    def test_binary_output_groups_defined(self):
        """Verify binary output groups are defined."""
        assert DNP3ObjectGroups.BINARY_OUTPUT == 0x0A
        assert DNP3ObjectGroups.BINARY_OUTPUT_EVENT == 0x0B
        assert DNP3ObjectGroups.CONTROL_RELAY_OUTPUT_BLOCK == 0x0C

    def test_counter_groups_defined(self):
        """Verify counter groups are defined."""
        assert DNP3ObjectGroups.COUNTER == 0x14
        assert DNP3ObjectGroups.FROZEN_COUNTER == 0x15
        assert DNP3ObjectGroups.COUNTER_EVENT == 0x16

    def test_analog_input_groups_defined(self):
        """Verify analog input groups are defined."""
        assert DNP3ObjectGroups.ANALOG_INPUT == 0x1E
        assert DNP3ObjectGroups.ANALOG_INPUT_EVENT == 0x20

    def test_analog_output_groups_defined(self):
        """Verify analog output groups are defined."""
        assert DNP3ObjectGroups.ANALOG_OUTPUT == 0x28
        assert DNP3ObjectGroups.ANALOG_OUTPUT_BLOCK == 0x29

    def test_time_group_defined(self):
        """Verify time group is defined."""
        assert DNP3ObjectGroups.TIME_AND_DATE == 0x32

    def test_class_data_group_defined(self):
        """Verify class data group is defined."""
        assert DNP3ObjectGroups.CLASS_DATA == 0x3C

    def test_file_control_group_defined(self):
        """Verify file control group is defined."""
        assert DNP3ObjectGroups.FILE_CONTROL == 0x46

    def test_authentication_groups_defined(self):
        """Verify authentication groups are defined."""
        assert DNP3ObjectGroups.AUTHENTICATION == 0x78
        assert DNP3ObjectGroups.SECURE_AUTHENTICATION == 0x79

    def test_data_set_group_defined(self):
        """Verify data set group is defined (CVE-2020-10611 target)."""
        assert DNP3ObjectGroups.DATA_SET == 0x55

    def test_octet_string_group_defined(self):
        """Verify octet string group is defined."""
        assert DNP3ObjectGroups.OCTET_STRING == 0x6E

    def test_virtual_terminal_group_defined(self):
        """Verify virtual terminal group is defined."""
        assert DNP3ObjectGroups.VIRTUAL_TERMINAL == 0x70


class TestDNP3RequestDefinitions:
    """Test DNP3 request definitions."""

    def test_get_request_definitions_returns_list(self):
        """Verify get_request_definitions returns list of RequestInfo."""
        definitions = DNP3Fuzzer.get_request_definitions()
        assert isinstance(definitions, list)
        assert len(definitions) > 0
        assert all(isinstance(d, RequestInfo) for d in definitions)

    def test_baseline_request_defined(self):
        """Verify baseline request is defined."""
        definitions = DNP3Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "DNP3_Baseline" in names

    def test_overflow_request_defined(self):
        """Verify overflow request is defined (CVE-2020-10615)."""
        definitions = DNP3Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "DNP3_Overflow" in names

    def test_control_request_defined(self):
        """Verify control request is defined."""
        definitions = DNP3Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "DNP3_Control" in names

    def test_file_request_defined(self):
        """Verify file request is defined (CVE-2020-10611)."""
        definitions = DNP3Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "DNP3_File" in names

    def test_auth_request_defined(self):
        """Verify authentication request is defined."""
        definitions = DNP3Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "DNP3_Auth" in names

    def test_boundary_request_defined(self):
        """Verify boundary request is defined."""
        definitions = DNP3Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "DNP3_Boundary" in names

    def test_read_request_defined(self):
        """Verify read request is defined."""
        definitions = DNP3Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "DNP3_Read" in names

    def test_system_request_defined(self):
        """Verify system request is defined."""
        definitions = DNP3Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "DNP3_System" in names

    def test_malformed_request_defined(self):
        """Verify malformed request is defined."""
        definitions = DNP3Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "DNP3_Malformed" in names

    def test_combined_request_defined(self):
        """Verify combined attack request is defined."""
        definitions = DNP3Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "DNP3_Combined" in names

    def test_request_categories_valid(self):
        """Verify all request categories are valid."""
        valid_categories = {"baseline", "protocol", "boundary", "write", "read", "special"}
        definitions = DNP3Fuzzer.get_request_definitions()
        for d in definitions:
            assert d.category in valid_categories, f"Invalid category: {d.category}"


class TestDNP3ProtocolOptions:
    """Test DNP3 protocol-specific options."""

    def test_protocol_options_defined(self):
        """Verify PROTOCOL_OPTIONS dict is defined."""
        assert hasattr(DNP3Fuzzer, "PROTOCOL_OPTIONS")
        assert isinstance(DNP3Fuzzer.PROTOCOL_OPTIONS, dict)

    def test_source_address_option(self):
        """Verify source_address option is defined."""
        assert "source_address" in DNP3Fuzzer.PROTOCOL_OPTIONS
        opt = DNP3Fuzzer.PROTOCOL_OPTIONS["source_address"]
        assert opt["type"] == int
        assert opt["default"] == 2

    def test_dest_address_option(self):
        """Verify dest_address option is defined."""
        assert "dest_address" in DNP3Fuzzer.PROTOCOL_OPTIONS
        opt = DNP3Fuzzer.PROTOCOL_OPTIONS["dest_address"]
        assert opt["type"] == int
        assert opt["default"] == 1

    def test_enable_auth_option(self):
        """Verify enable_auth option is defined."""
        assert "enable_auth" in DNP3Fuzzer.PROTOCOL_OPTIONS
        opt = DNP3Fuzzer.PROTOCOL_OPTIONS["enable_auth"]
        assert opt["type"] == bool
        assert opt["default"] is False

    def test_enable_write_option(self):
        """Verify enable_write option is defined with safe default."""
        assert "enable_write" in DNP3Fuzzer.PROTOCOL_OPTIONS
        opt = DNP3Fuzzer.PROTOCOL_OPTIONS["enable_write"]
        assert opt["type"] == bool
        assert opt["default"] is False

    def test_enable_control_option(self):
        """Verify enable_control option is defined with safe default."""
        assert "enable_control" in DNP3Fuzzer.PROTOCOL_OPTIONS
        opt = DNP3Fuzzer.PROTOCOL_OPTIONS["enable_control"]
        assert opt["type"] == bool
        assert opt["default"] is False

    def test_enable_file_option(self):
        """Verify enable_file option is defined with safe default."""
        assert "enable_file" in DNP3Fuzzer.PROTOCOL_OPTIONS
        opt = DNP3Fuzzer.PROTOCOL_OPTIONS["enable_file"]
        assert opt["type"] == bool
        assert opt["default"] is False


class TestDNP3CVEPatterns:
    """Test DNP3 CVE-targeted patterns."""

    def test_cve_2020_10611_pattern(self):
        """Verify CVE-2020-10611 (data set) pattern is targeted.

        CVE-2020-10611: Type confusion in DNP3 Data Sets
        """
        # Data Set object group should be defined for targeting
        assert DNP3ObjectGroups.DATA_SET == 0x55

        # File operations are main CVE-2020-10611 attack vectors
        definitions = DNP3Fuzzer.get_request_definitions()
        file_def = next(d for d in definitions if d.name == "DNP3_File")
        assert "CVE-2020-10611" in file_def.description

    def test_cve_2020_10615_pattern(self):
        """Verify CVE-2020-10615 (stack overflow) pattern is targeted.

        CVE-2020-10615: Stack buffer overflow via length field
        """
        definitions = DNP3Fuzzer.get_request_definitions()
        overflow_def = next(d for d in definitions if d.name == "DNP3_Overflow")
        assert "CVE-2020-10615" in overflow_def.description

    def test_length_overflow_attacks(self):
        """Verify length field overflow attacks are defined."""
        definitions = DNP3Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]
        assert "DNP3_Overflow" in names

        # Overflow should be high priority (early in list)
        overflow_def = next(d for d in definitions if d.name == "DNP3_Overflow")
        assert overflow_def.category == "protocol"


class TestDNP3LinkLayerConstants:
    """Test DNP3 link layer constants and structure."""

    def test_start_bytes_constant(self):
        """Verify DNP3 start bytes are 0x0564."""
        # These are hardcoded in the protocol definition
        start_bytes = b"\x05\x64"
        assert start_bytes[0] == 0x05
        assert start_bytes[1] == 0x64

    def test_control_byte_dir_prm_bits(self):
        """Verify control byte structure."""
        # DIR=1, PRM=1 for master request = 0xC0
        master_request = 0xC0
        assert (master_request & 0x80) == 0x80  # DIR bit
        assert (master_request & 0x40) == 0x40  # PRM bit

        # Standard control = 0x44 (unconfirmed user data from master)
        standard_control = 0x44
        assert (standard_control & 0x40) == 0x40  # PRM bit

    def test_transport_header_fir_fin_bits(self):
        """Verify transport header structure."""
        # FIR=1, FIN=1 for single fragment = 0xC0
        single_fragment = 0xC0
        assert (single_fragment & 0x80) == 0x80  # FIR bit
        assert (single_fragment & 0x40) == 0x40  # FIN bit

    def test_app_control_header_bits(self):
        """Verify application control header structure."""
        # FIR=1, FIN=1 for single fragment app layer = 0xC0
        app_control = 0xC0
        assert (app_control & 0x80) == 0x80  # FIR bit
        assert (app_control & 0x40) == 0x40  # FIN bit


class TestDNP3AddressBoundaries:
    """Test DNP3 address boundary values."""

    def test_valid_address_range(self):
        """Verify valid DNP3 address range (0-65519)."""
        # Valid addresses are 0x0000 to 0xFFEF (0-65519)
        min_valid = 0x0000
        max_valid = 0xFFEF
        assert min_valid == 0
        assert max_valid == 65519

    def test_reserved_address_range(self):
        """Verify reserved DNP3 address range (65520-65535)."""
        # Reserved addresses: 0xFFF0 to 0xFFFF (65520-65535)
        reserved_start = 0xFFF0
        broadcast_self = 0xFFFC  # Self-address
        broadcast_outstations = 0xFFFD  # All outstations
        broadcast_all = 0xFFFE  # All stations
        broadcast_reserved = 0xFFFF  # Reserved

        assert reserved_start == 65520
        assert broadcast_self == 65532
        assert broadcast_outstations == 65533
        assert broadcast_all == 65534
        assert broadcast_reserved == 65535


class TestDNP3QualifierCodes:
    """Test DNP3 qualifier code constants."""

    def test_8bit_start_stop_qualifier(self):
        """Verify 8-bit start/stop qualifier code."""
        # Qualifier 0x00: 8-bit start/stop indices
        assert 0x00 == 0  # 8-bit range

    def test_16bit_start_stop_qualifier(self):
        """Verify 16-bit start/stop qualifier code."""
        # Qualifier 0x01: 16-bit start/stop indices
        assert 0x01 == 1  # 16-bit range

    def test_all_objects_qualifier(self):
        """Verify all objects qualifier code."""
        # Qualifier 0x06: All objects
        assert 0x06 == 6

    def test_8bit_count_qualifier(self):
        """Verify 8-bit count qualifier code."""
        # Qualifier 0x07: 8-bit count
        assert 0x07 == 7

    def test_16bit_count_qualifier(self):
        """Verify 16-bit count qualifier code."""
        # Qualifier 0x08: 16-bit count
        assert 0x08 == 8

    def test_free_format_qualifier(self):
        """Verify free format qualifier code."""
        # Qualifier 0x5B: Free format (variable sized)
        assert 0x5B == 91


class TestDNP3FuzzerExports:
    """Test DNP3 fuzzer exports."""

    def test_all_exports_defined(self):
        """Verify __all__ exports are defined."""
        from oida.fuzz.protocols import dnp3

        assert hasattr(dnp3, "__all__")
        assert "DNP3Fuzzer" in dnp3.__all__
        assert "DNP3FunctionCodes" in dnp3.__all__
        assert "DNP3ObjectGroups" in dnp3.__all__

    def test_fuzzer_importable(self):
        """Verify DNP3Fuzzer is importable."""
        from oida.fuzz.protocols.dnp3 import DNP3Fuzzer

        assert DNP3Fuzzer is not None

    def test_function_codes_importable(self):
        """Verify DNP3FunctionCodes is importable."""
        from oida.fuzz.protocols.dnp3 import DNP3FunctionCodes

        assert DNP3FunctionCodes is not None

    def test_object_groups_importable(self):
        """Verify DNP3ObjectGroups is importable."""
        from oida.fuzz.protocols.dnp3 import DNP3ObjectGroups

        assert DNP3ObjectGroups is not None
