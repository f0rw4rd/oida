"""
Tests for IEC 60870-5-104 Protocol Fuzzer.

Tests cover:
- IEC104Fuzzer: IEC 104 protocol fuzzing
- Request definitions and categories
- APCI/ASDU encoding correctness
- U-format, I-format, S-format frames
- ASDU type coverage
- Control commands
- State machine integration
- Helper functions for creating protocol structures
"""

import pytest


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def iec104_config():
    """Create a basic IEC 104 FuzzerConfig."""
    from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType

    config = FuzzerConfig(
        target_ip="192.168.1.100",
        target_port=2404,
        protocol_type=ProtocolType.TCP,
    )
    return config


@pytest.fixture
def iec104_fuzzer(iec104_config):
    """Create an IEC104Fuzzer instance with mocked connection."""
    from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer
    from src.oida.fuzz.core.connections.base import MockConnectionFactory

    factory = MockConnectionFactory()
    fuzzer = IEC104Fuzzer(iec104_config, connection_factory=factory)
    return fuzzer


# =============================================================================
# Test Protocol Constants
# =============================================================================


class TestAPCITypes:
    """Tests for APCI type constants."""

    def test_apci_types_defined(self):
        """APCI type constants are defined."""
        from src.oida.fuzz.protocols.iec104 import APCI_Types

        assert APCI_Types.I_FORMAT == 0x00
        assert APCI_Types.S_FORMAT == 0x01
        assert APCI_Types.U_FORMAT == 0x03


class TestUFormatFunctions:
    """Tests for U-format function constants."""

    def test_u_format_functions_defined(self):
        """U-format function constants are defined."""
        from src.oida.fuzz.protocols.iec104 import UFormat_Functions

        assert UFormat_Functions.STARTDT_ACT == 0x07
        assert UFormat_Functions.STARTDT_CON == 0x0B
        assert UFormat_Functions.STOPDT_ACT == 0x13
        assert UFormat_Functions.STOPDT_CON == 0x23
        assert UFormat_Functions.TESTFR_ACT == 0x43
        assert UFormat_Functions.TESTFR_CON == 0x83


class TestASDUTypes:
    """Tests for ASDU type constants."""

    def test_monitoring_asdu_types_defined(self):
        """Monitoring ASDU types are defined."""
        from src.oida.fuzz.protocols.iec104 import ASDU_Types

        # Single/double point
        assert ASDU_Types.M_SP_NA_1 == 1
        assert ASDU_Types.M_DP_NA_1 == 3
        # Measured values
        assert ASDU_Types.M_ME_NA_1 == 9
        assert ASDU_Types.M_ME_NC_1 == 13

    def test_control_asdu_types_defined(self):
        """Control ASDU types are defined."""
        from src.oida.fuzz.protocols.iec104 import ASDU_Types

        assert ASDU_Types.C_SC_NA_1 == 45
        assert ASDU_Types.C_DC_NA_1 == 46
        assert ASDU_Types.C_SE_NA_1 == 48

    def test_system_command_types_defined(self):
        """System command ASDU types are defined."""
        from src.oida.fuzz.protocols.iec104 import ASDU_Types

        assert ASDU_Types.C_IC_NA_1 == 100  # Interrogation
        assert ASDU_Types.C_CS_NA_1 == 103  # Clock sync
        assert ASDU_Types.C_TS_NA_1 == 104  # Test command


class TestCauseOfTransmission:
    """Tests for Cause of Transmission constants."""

    def test_cot_values_defined(self):
        """Cause of Transmission values are defined."""
        from src.oida.fuzz.protocols.iec104 import CauseOfTransmission

        assert CauseOfTransmission.PERIODIC == 1
        assert CauseOfTransmission.SPONTANEOUS == 3
        assert CauseOfTransmission.ACTIVATION == 6
        assert CauseOfTransmission.ACTIVATION_CON == 7


# =============================================================================
# Test IEC104StateMachine
# =============================================================================


class TestIEC104StateMachine:
    """Tests for IEC 104 state machine."""

    def test_initial_state(self):
        """Initial state is DISCONNECTED."""
        from src.oida.fuzz.protocols.iec104 import IEC104StateMachine

        sm = IEC104StateMachine()
        assert sm.state == "DISCONNECTED"

    def test_start_data_transfer(self):
        """start_data_transfer() transitions to DATA_TRANSFER."""
        from src.oida.fuzz.protocols.iec104 import IEC104StateMachine

        sm = IEC104StateMachine()
        sm.start_data_transfer()
        assert sm.state == "DATA_TRANSFER"

    def test_stop_data_transfer(self):
        """stop_data_transfer() transitions to CONNECTED."""
        from src.oida.fuzz.protocols.iec104 import IEC104StateMachine

        sm = IEC104StateMachine()
        sm.start_data_transfer()
        sm.stop_data_transfer()
        assert sm.state == "CONNECTED"

    def test_disconnect(self):
        """disconnect() transitions to DISCONNECTED."""
        from src.oida.fuzz.protocols.iec104 import IEC104StateMachine

        sm = IEC104StateMachine()
        sm.start_data_transfer()
        sm.disconnect()
        assert sm.state == "DISCONNECTED"

    def test_get_current_state_name(self):
        """get_current_state_name() returns state name."""
        from src.oida.fuzz.protocols.iec104 import IEC104StateMachine

        sm = IEC104StateMachine()
        assert sm.get_current_state_name() == "DISCONNECTED"

    def test_validate_current_state(self):
        """validate_current_state() returns True."""
        from src.oida.fuzz.protocols.iec104 import IEC104StateMachine

        sm = IEC104StateMachine()
        assert sm.validate_current_state() is True


# =============================================================================
# Test Helper Functions
# =============================================================================


class TestCreateAPCIUFormat:
    """Tests for create_apci_u_format helper."""

    def test_create_apci_u_format_returns_block(self):
        """create_apci_u_format() returns a Block."""
        from src.oida.fuzz.protocols.iec104 import create_apci_u_format, UFormat_Functions
        from boofuzz import Block

        result = create_apci_u_format("test", UFormat_Functions.TESTFR_ACT)
        assert isinstance(result, Block)

    def test_create_startdt_act(self):
        """STARTDT_ACT frame is created correctly."""
        from src.oida.fuzz.protocols.iec104 import create_apci_u_format, UFormat_Functions

        block = create_apci_u_format("startdt", UFormat_Functions.STARTDT_ACT)
        assert block is not None

    def test_create_testfr_act(self):
        """TESTFR_ACT frame is created correctly."""
        from src.oida.fuzz.protocols.iec104 import create_apci_u_format, UFormat_Functions

        block = create_apci_u_format("testfr", UFormat_Functions.TESTFR_ACT)
        assert block is not None


class TestCreateAPCIIFormat:
    """Tests for create_apci_i_format_header helper."""

    def test_create_apci_i_format_header_returns_block(self):
        """create_apci_i_format_header() returns a Block."""
        from src.oida.fuzz.protocols.iec104 import create_apci_i_format_header
        from boofuzz import Block

        result = create_apci_i_format_header()
        assert isinstance(result, Block)


class TestCreateASDUHeader:
    """Tests for create_asdu_header helper."""

    def test_create_asdu_header_returns_block(self):
        """create_asdu_header() returns a Block."""
        from src.oida.fuzz.protocols.iec104 import create_asdu_header, ASDU_Types
        from boofuzz import Block

        result = create_asdu_header(ASDU_Types.M_SP_NA_1)
        assert isinstance(result, Block)

    def test_create_asdu_header_with_cot(self):
        """ASDU header with custom COT."""
        from src.oida.fuzz.protocols.iec104 import (
            create_asdu_header,
            ASDU_Types,
            CauseOfTransmission,
        )

        result = create_asdu_header(ASDU_Types.C_SC_NA_1, cot=CauseOfTransmission.ACTIVATION)
        assert result is not None


class TestCreateCP56Time2a:
    """Tests for create_cp56time2a helper."""

    def test_create_cp56time2a_returns_block(self):
        """create_cp56time2a() returns a Block."""
        from src.oida.fuzz.protocols.iec104 import create_cp56time2a
        from boofuzz import Block

        result = create_cp56time2a()
        assert isinstance(result, Block)


# =============================================================================
# Test Information Object Helpers
# =============================================================================


class TestInfoObjectHelpers:
    """Tests for information object creation helpers."""

    def test_create_single_point_info_object(self):
        """Single point information object is created."""
        from src.oida.fuzz.protocols.iec104 import create_info_object_single_point
        from boofuzz import Block

        result = create_info_object_single_point(ioa=100, value=1)
        assert isinstance(result, Block)

    def test_create_double_point_info_object(self):
        """Double point information object is created."""
        from src.oida.fuzz.protocols.iec104 import create_info_object_double_point
        from boofuzz import Block

        result = create_info_object_double_point(ioa=100, value=2)
        assert isinstance(result, Block)

    def test_create_measured_normalized_info_object(self):
        """Measured value normalized info object is created."""
        from src.oida.fuzz.protocols.iec104 import create_info_object_measured_normalized
        from boofuzz import Block

        result = create_info_object_measured_normalized(ioa=100, value=1000, quality=0)
        assert isinstance(result, Block)

    def test_create_measured_float_info_object(self):
        """Measured value float info object is created."""
        from src.oida.fuzz.protocols.iec104 import create_info_object_measured_float
        from boofuzz import Block

        result = create_info_object_measured_float(ioa=100, value=3.14, quality=0)
        assert isinstance(result, Block)

    def test_create_single_command_info_object(self):
        """Single command info object is created."""
        from src.oida.fuzz.protocols.iec104 import create_info_object_single_command
        from boofuzz import Block

        result = create_info_object_single_command(ioa=100, sco=0x01)
        assert isinstance(result, Block)

    def test_create_double_command_info_object(self):
        """Double command info object is created."""
        from src.oida.fuzz.protocols.iec104 import create_info_object_double_command
        from boofuzz import Block

        result = create_info_object_double_command(ioa=100, dco=0x02)
        assert isinstance(result, Block)

    def test_create_setpoint_normalized_info_object(self):
        """Setpoint normalized info object is created."""
        from src.oida.fuzz.protocols.iec104 import create_info_object_setpoint_normalized
        from boofuzz import Block

        result = create_info_object_setpoint_normalized(ioa=100, value=500, ql=0, se=0)
        assert isinstance(result, Block)

    def test_create_interrogation_info_object(self):
        """Interrogation command info object is created."""
        from src.oida.fuzz.protocols.iec104 import create_info_object_interrogation
        from boofuzz import Block

        result = create_info_object_interrogation(ioa=0, qoi=20)
        assert isinstance(result, Block)

    def test_create_clock_sync_info_object(self):
        """Clock sync info object is created."""
        from src.oida.fuzz.protocols.iec104 import create_info_object_clock_sync
        from boofuzz import Block

        result = create_info_object_clock_sync(ioa=0)
        assert isinstance(result, Block)


class TestCreateCompleteASDUMessage:
    """Tests for create_complete_asdu_message helper."""

    def test_create_complete_asdu_message(self):
        """Complete ASDU message is created."""
        from src.oida.fuzz.protocols.iec104 import (
            create_complete_asdu_message,
            create_info_object_single_point,
            ASDU_Types,
        )
        from boofuzz import Request

        info_obj = create_info_object_single_point(ioa=100, value=1)
        result = create_complete_asdu_message("test_message", ASDU_Types.M_SP_NA_1, info_obj)
        assert isinstance(result, Request)


# =============================================================================
# Test IEC104Fuzzer Creation
# =============================================================================


class TestIEC104FuzzerCreation:
    """Tests for IEC104Fuzzer instantiation."""

    def test_basic_creation(self, iec104_config):
        """IEC104Fuzzer can be created."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        fuzzer = IEC104Fuzzer(iec104_config, connection_factory=MockConnectionFactory())
        assert fuzzer is not None

    def test_state_machine_initialized(self, iec104_fuzzer):
        """State machine is initialized."""
        from src.oida.fuzz.protocols.iec104 import IEC104StateMachine

        assert isinstance(iec104_fuzzer.state_machine, IEC104StateMachine)

    def test_sequence_numbers_initialized(self, iec104_fuzzer):
        """Sequence numbers are initialized to 0."""
        assert iec104_fuzzer.send_seq == 0
        assert iec104_fuzzer.recv_seq == 0


class TestIEC104FuzzerOptions:
    """Tests for IEC104Fuzzer protocol options."""

    def test_protocol_options_defined(self):
        """Protocol options are defined."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        assert "common_address" in IEC104Fuzzer.PROTOCOL_OPTIONS
        assert "enable_file_transfer" in IEC104Fuzzer.PROTOCOL_OPTIONS
        assert "attack_intensity" in IEC104Fuzzer.PROTOCOL_OPTIONS

    def test_common_address_default(self):
        """Default common address is 1."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        assert IEC104Fuzzer.PROTOCOL_OPTIONS["common_address"]["default"] == 1

    def test_file_transfer_disabled_by_default(self):
        """File transfer is disabled by default."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        assert IEC104Fuzzer.PROTOCOL_OPTIONS["enable_file_transfer"]["default"] is False

    def test_attack_intensity_choices(self):
        """Attack intensity has valid choices."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        choices = IEC104Fuzzer.PROTOCOL_OPTIONS["attack_intensity"]["choices"]
        assert "low" in choices
        assert "medium" in choices
        assert "high" in choices


# =============================================================================
# Test Request Definitions
# =============================================================================


class TestIEC104RequestDefinitions:
    """Tests for IEC 104 request definitions."""

    def test_get_request_definitions_returns_list(self):
        """get_request_definitions() returns a list."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        definitions = IEC104Fuzzer.get_request_definitions()
        assert isinstance(definitions, list)

    def test_request_definitions_not_empty(self):
        """Request definitions are not empty."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        definitions = IEC104Fuzzer.get_request_definitions()
        assert len(definitions) > 0

    def test_connection_requests_defined(self):
        """Connection establishment requests are defined."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        definitions = IEC104Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        assert "IEC104_Baseline" in names
        assert "IEC104_Connection" in names

    def test_monitoring_requests_defined(self):
        """Monitoring ASDU requests are defined."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        definitions = IEC104Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        assert "IEC104_Monitoring" in names
        assert "IEC104_Measured_Values" in names

    def test_control_requests_defined(self):
        """Control ASDU requests are defined."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        definitions = IEC104Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        assert "IEC104_Control" in names
        assert "IEC104_System" in names

    def test_attack_requests_defined(self):
        """Attack pattern requests are defined."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        definitions = IEC104Fuzzer.get_request_definitions()
        names = [d.name for d in definitions]

        assert "IEC104_Attack_Patterns" in names
        assert "IEC104_Sequence_Attacks" in names

    def test_request_categories_cover_all_types(self):
        """Request categories cover all test types."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        definitions = IEC104Fuzzer.get_request_definitions()
        categories = {d.category for d in definitions}

        # Should have baseline, core, read, write, attacks
        assert "baseline" in categories
        assert "read" in categories
        assert "write" in categories
        assert "attacks" in categories


# =============================================================================
# Test Monitor Setup
# =============================================================================


class TestIEC104MonitorSetup:
    """Tests for IEC 104 monitor setup."""

    def test_setup_custom_monitors_returns_list(self, iec104_fuzzer):
        """setup_custom_monitors() returns a list."""
        monitors = iec104_fuzzer.setup_custom_monitors()
        assert isinstance(monitors, list)
        assert len(monitors) > 0

    def test_uses_iec104_monitor(self, iec104_fuzzer):
        """Uses IEC104Monitor for protocol-level health checking."""
        from src.oida.fuzz.monitors import IEC104Monitor

        monitors = iec104_fuzzer.setup_custom_monitors()
        assert isinstance(monitors[0], IEC104Monitor)


# =============================================================================
# Test ASDU Type Coverage
# =============================================================================


class TestASDUTypeCoverage:
    """Tests for ASDU type coverage."""

    def test_all_monitoring_types_have_helpers(self):
        """All essential monitoring types have helper functions."""
        from src.oida.fuzz.protocols import iec104

        # Essential monitoring types
        assert hasattr(iec104, "create_info_object_single_point")
        assert hasattr(iec104, "create_info_object_double_point")
        assert hasattr(iec104, "create_info_object_measured_normalized")
        assert hasattr(iec104, "create_info_object_measured_scaled")
        assert hasattr(iec104, "create_info_object_measured_float")

    def test_all_control_types_have_helpers(self):
        """All essential control types have helper functions."""
        from src.oida.fuzz.protocols import iec104

        # Essential control types
        assert hasattr(iec104, "create_info_object_single_command")
        assert hasattr(iec104, "create_info_object_double_command")
        assert hasattr(iec104, "create_info_object_setpoint_normalized")

    def test_system_command_helpers_exist(self):
        """System command helper functions exist."""
        from src.oida.fuzz.protocols import iec104

        assert hasattr(iec104, "create_info_object_interrogation")
        assert hasattr(iec104, "create_info_object_clock_sync")


# =============================================================================
# Test Security-Relevant Features
# =============================================================================


class TestIEC104SecurityFeatures:
    """Tests for security-relevant IEC 104 features."""

    def test_sequence_numbers_tracked(self, iec104_fuzzer):
        """Send and receive sequence numbers are tracked."""
        assert hasattr(iec104_fuzzer, "send_seq")
        assert hasattr(iec104_fuzzer, "recv_seq")

    def test_file_transfer_option_exists(self):
        """File transfer option exists for directory traversal testing."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        assert "enable_file_transfer" in IEC104Fuzzer.PROTOCOL_OPTIONS

    def test_vendor_attacks_option_exists(self):
        """Vendor-specific attacks option exists."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        assert "enable_vendor_attacks" in IEC104Fuzzer.PROTOCOL_OPTIONS

    def test_default_monitors_use_iec104(self):
        """Default monitors use IEC104-specific monitoring."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer

        assert "iec104" in IEC104Fuzzer.DEFAULT_MONITORS


# =============================================================================
# Test Custom Configuration
# =============================================================================


class TestIEC104CustomConfiguration:
    """Tests for custom IEC 104 configuration."""

    def test_custom_common_address(self, iec104_config):
        """Custom common address is used."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        iec104_config.protocol_options = {"common_address": 65535}
        fuzzer = IEC104Fuzzer(iec104_config, connection_factory=MockConnectionFactory())
        ca = fuzzer.config.get_option("common_address", 1)
        assert ca == 65535

    def test_high_attack_intensity(self, iec104_config):
        """High attack intensity can be set."""
        from src.oida.fuzz.protocols.iec104 import IEC104Fuzzer
        from src.oida.fuzz.core.connections.base import MockConnectionFactory

        iec104_config.protocol_options = {"attack_intensity": "high"}
        fuzzer = IEC104Fuzzer(iec104_config, connection_factory=MockConnectionFactory())
        intensity = fuzzer.config.get_option("attack_intensity", "medium")
        assert intensity == "high"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
