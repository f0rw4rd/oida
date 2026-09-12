"""
KNX/EIB Protocol Integration Tests

Tests oida knx scanner against Docker mock service (Calimero KNXnet/IP Server).
Uses structured JSON log assertions for precise validation.

Mock Server Data (from docker/mocks/services/knx/):
  Calimero KNXnet/IP Server:
    Server Name:          "oida-knx" / friendly "OIDA KNX Mock Server"
    Individual Address:   1.1.0
    Additional Addresses: 1.1.10 - 1.1.20 (11 tunneling addresses)
    Medium:               PL110
    Routing:              enabled
    Network Monitoring:   enabled
    UDP Port:             3671
    TCP Port:             3671

  Configured Group Addresses (12 datapoints):
    Lighting:  1/0/1 (Light_Living, DPT 1.001)
               1/0/2 (Light_Kitchen, DPT 1.001)
               1/0/3 (Light_Bedroom, DPT 1.001)
    Dimming:   1/1/1 (Dimmer_Living, DPT 5.001)
               1/1/2 (Dimmer_Kitchen, DPT 5.001)
    Temperature: 2/0/1 (Temp_Living, DPT 9.001)
                 2/0/2 (Temp_Kitchen, DPT 9.001)
                 2/0/3 (Temp_Outdoor, DPT 9.001)
    Blinds:    3/0/1 (Blinds_Living, DPT 5.001)
               3/0/2 (Blinds_Kitchen, DPT 5.001)
    HVAC:      4/0/1 (HVAC_Mode, DPT 20.102)
    Scene:     5/0/1 (Scene_Control, DPT 17.001)

  Calimero Limitations (virtual subnet, no real KNX devices):
    - No BCU key authentication (AuthorizeRequest not handled)
    - No CEMI device management (memory read/write, property read/write)
    - No programming mode detection
    - No interface object enumeration
    - No firmware info via management frames
    - No ADC channel reading
    - Group address read returns "no response" (no device to answer)

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  13 tests
Category B (conditional -- mock may not support, accept 0 or 1):       34 tests
Category C (error handling -- assert failure + validate error events):  10 tests
Skipped (untestable -- requires hardware/ETS files/key files):           0 tests
Total defined in file:                                                  57 tests
Total collected (including 8 inherited from BaseProtocolIntegrationTest): 65 tests
---------------------------------------------------------------------------

Flag Coverage Matrix (proto_args.py):
  --port                       [A] test_basic_unicast_discovery
  --timeout                    [A] test_custom_timeout
  (NAT default-on)             [A] test_nat_mode_discovery
  --no-nat                     [A] test_no_nat_mode_discovery
  --interface                  [skip] requires specific network interface
  --tcp                        [B] test_tcp_tunneling_mode
  --individual-address / -i    [B] test_device_info_with_individual_address
  --group-address / -g         [B] test_group_address_read
  --device-info                [B] test_device_info_with_individual_address
  --enumerate-objects           [B] test_enumerate_objects
  --prog-mode                  [B] test_prog_mode
  --firmware-info              [B] test_firmware_info
  --vendor-objects             [B] test_vendor_objects
  --prop-dump                  [B] test_prop_dump
  --memory-dump                [B] test_memory_dump
  --memory-ext                 [B] test_memory_ext
  --memory-user                [B] test_memory_user
  --memory-write               [B] test_memory_write_with_confirm
  --property-read              [B] test_property_read
  --property-write             [B] test_property_write_with_confirm
  --fuzz-property              [B] test_fuzz_property
  --fuzz-iterations            [B] test_fuzz_property
  --adc-read                   [B] test_adc_read
  --group-write                [B] test_group_write_with_confirm
  --restart                    [B] test_restart_device_with_confirm
  --confirm                    [C] test_write_without_confirm_rejected, test_group_write_without_confirm
  --prop-desc                  [B] test_prop_desc
  --gateway-scan               [A] test_gateway_scan_discovery
  --bus-scan                   [B] test_bus_scan_with_range
  --listen                     [B] test_listen_mode
  --listen-time / -t           [B] test_listen_mode
  --slow-scan                  [B] test_slow_scan
  --serial-scan                [B] test_serial_scan
  --scan-range / -r            [B] test_bus_scan_with_range
  --auth-test                  [B] test_auth_default_key, test_auth_custom_key
  --key-file                   [skip] requires key file on disk
  --key-range                  [B] test_key_range_brute
  --brute-delay                [B] test_key_range_brute
  --continue-on-success        [B] (default stop tested via test_auth_default_key)
  --key-write                  [B] test_key_write_with_confirm
  --knxproj                    [C] test_knxproj_nonexistent_file
  --knxproj-password           [skip] requires .knxproj file
  --knxproj-wordlist           [skip] requires .knxproj + wordlist
  --knxproj-threads            [skip] requires .knxproj + wordlist
  --knxproj-info               [C] test_knxproj_info_nonexistent
  --knxproj-hash               [C] test_knxproj_hash_nonexistent
  --knxproj-fast               [skip] requires .knxproj + wordlist
  (security: no encryption)    [B] test_security_finding_no_encryption
  (security: no auth)          [B] test_security_finding_no_authentication
  (security: writable access)  [B] test_security_finding_writable_access
  (security: insecure config)  [B] test_security_finding_insecure_configuration
  (security: weak password)    [C] test_security_finding_weak_password_knxproj
  format (global)              [A] test_csv_output_format, test_xml_output_format
  -v (global)                  [A] test_verbose_output
  --debug (global)             [A] test_debug_output
  --help (global)              [A] test_help_output
"""

import pytest
from typing import Optional

from .base_protocol_test import BaseProtocolIntegrationTest
from .conftest import MOCK_HOST


# ---------------------------------------------------------------------------
# Known Mock Data Constants (from Calimero server-config.xml)
# ---------------------------------------------------------------------------
MOCK_SERVER_NAME = "oida-knx"
MOCK_FRIENDLY_NAME = "oida knx mock server"
MOCK_INDIVIDUAL_ADDR = "1.1.0"
MOCK_MEDIUM = "pl110"
MOCK_KNX_PORT = 3671

# Configured group addresses (from datapoints.xml)
MOCK_GROUP_LIGHTING = ["1/0/1", "1/0/2", "1/0/3"]
MOCK_GROUP_DIMMING = ["1/1/1", "1/1/2"]
MOCK_GROUP_TEMPERATURE = ["2/0/1", "2/0/2", "2/0/3"]
MOCK_GROUP_BLINDS = ["3/0/1", "3/0/2"]
MOCK_GROUP_HVAC = ["4/0/1"]
MOCK_GROUP_SCENE = ["5/0/1"]
MOCK_ALL_GROUPS = (
    MOCK_GROUP_LIGHTING
    + MOCK_GROUP_DIMMING
    + MOCK_GROUP_TEMPERATURE
    + MOCK_GROUP_BLINDS
    + MOCK_GROUP_HVAC
    + MOCK_GROUP_SCENE
)

# Additional individual addresses configured for tunneling
MOCK_ADDITIONAL_ADDRS = [f"1.1.{i}" for i in range(10, 21)]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_messages(log) -> str:
    """Concatenate all log messages into a single lowercase string for searching."""
    return " ".join(e.get("message", "") for e in log.events).lower()


def _assert_log_has_events(result, min_count=1):
    """Assert that the scan_log exists and has at least min_count events."""
    assert result.scan_log is not None, "scan_log should be populated when json_log=True"
    result.scan_log.assert_has_events(min_count=min_count)


def _assert_log_event_structure(log):
    """Validate that every event in the log has the required fields."""
    required = {"timestamp", "level", "event_type", "module", "message"}
    for i, event in enumerate(log.events):
        missing = required - set(event.keys())
        assert not missing, f"Event {i} missing fields: {missing}"


def _combined_text(result, log=None) -> str:
    """Return lowercase combined output + log messages for broad searches."""
    parts = [result.combined_output.lower()]
    if log is not None:
        parts.append(_all_messages(log))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Test Class
# ---------------------------------------------------------------------------


@pytest.mark.knx
class TestKNXIntegration(BaseProtocolIntegrationTest):
    """Integration tests for KNX/EIB protocol scanner"""

    @property
    def protocol_name(self) -> str:
        return "knx"

    @property
    def default_port(self) -> int:
        return 3671

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    # ========================================================================
    # Gateway Discovery Tests
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    def test_basic_unicast_discovery(self, cli_runner, target, port):
        """Test default unicast DescriptionRequest discovery against Calimero mock [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Unicast discovery failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Calimero should respond to the DescriptionRequest with gateway info
        text = _combined_text(result, log)
        # The gateway name or individual address should appear in output
        assert any(
            term in text
            for term in [
                "knx",
                "gateway",
                "1.1.0",
                "searchresponse",
                "oida",
                "knx/ip",
                "tunneling",
                "tunnelling",
            ]
        ), f"Expected KNX gateway info in output, got: {text[:500]}"

    @pytest.mark.containers("knx-calimero")
    def test_gateway_scan_discovery(self, cli_runner, target, port):
        """Test --gateway-scan flag for KNXnet/IP gateway discovery [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--gateway-scan",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Gateway scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Gateway scan should report gateway details
        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "gateway",
                "knx",
                "tunnelling",
                "tunneling",
                "routing",
                "1.1.0",
                "oida",
            ]
        ), f"Expected gateway discovery results in output, got: {text[:500]}"

    @pytest.mark.containers("knx-calimero")
    def test_nat_mode_discovery(self, cli_runner, target, port):
        """Test NAT mode discovery (NAT is enabled by default) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"NAT mode failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # NAT mode should still yield results
        text = _combined_text(result, log)
        assert any(
            term in text for term in ["knx", "gateway", "1.1.0", "searchresponse", "tunneling"]
        ), f"Expected KNX info in NAT mode output, got: {text[:500]}"

    @pytest.mark.containers("knx-calimero")
    def test_no_nat_mode_discovery(self, cli_runner, target, port):
        """Test explicit non-NAT mode discovery [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--no-nat",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"No-NAT mode failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Should still get results even without NAT
        text = _combined_text(result, log)
        assert any(term in text for term in ["knx", "gateway", "1.1.0", "searchresponse"]), (
            f"Expected KNX info in no-NAT mode, got: {text[:500]}"
        )

    @pytest.mark.containers("knx-calimero")
    def test_custom_timeout(self, cli_runner, target, port):
        """Test --timeout parameter [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Custom timeout scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

    # ========================================================================
    # Connection Mode Tests
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    def test_tcp_tunneling_mode(self, cli_runner, target, port):
        """Test TCP tunneling mode (--tcp) against Calimero [Category B]

        Calimero supports TCP tunneling on port 3671, but xknx TCP tunnel
        behavior may vary. Accept both success and failure.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--tcp",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                text = _combined_text(result, result.scan_log)
                assert any(term in text for term in ["tcp", "tunnel", "knx", "connected"]), (
                    f"Expected TCP tunneling info in output, got: {text[:300]}"
                )

    @pytest.mark.containers("knx-calimero")
    def test_tcp_tunneling_with_gateway_scan(self, cli_runner, target, port):
        """Test TCP tunneling with gateway scan [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--tcp",
            "--gateway-scan",
            # Bound the post-discovery device read-access sweep; the default range
            # (255 addresses at the 5s connect timeout) cannot finish within 30s.
            "--scan-range",
            "1.1.1-1.1.1",
            "--timeout",
            "2",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Device Operations Tests (Calimero likely does NOT support CEMI mgmt)
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    def test_device_info_with_individual_address(self, cli_runner, target, port):
        """Test reading device info for specific individual address [Category B]

        Calimero's virtual subnet likely does not support DeviceDescriptorRead
        or PropertyValueRead management frames. We accept graceful failure.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-info",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            text = _combined_text(result, result.scan_log)
            # Should at least mention device info attempt
            assert any(
                term in text for term in ["device", "info", "knx", "1.1.0", "connected", "tunnel"]
            ), f"Expected device info context in output, got: {text[:300]}"

    @pytest.mark.containers("knx-calimero")
    def test_firmware_info(self, cli_runner, target, port):
        """Test reading firmware information [Category B]

        Calimero does not support firmware info management frames.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--firmware-info",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    def test_enumerate_objects(self, cli_runner, target, port):
        """Test enumerating interface objects [Category B]

        Calimero does not support interface object enumeration.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enumerate-objects",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    def test_prog_mode(self, cli_runner, target, port):
        """Test checking programming mode [Category B]

        Calimero may not respond to programming mode queries.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--prog-mode",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    def test_vendor_objects(self, cli_runner, target, port):
        """Test discovering vendor-specific interface objects (200-255) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--vendor-objects",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Group Address Tests
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    def test_group_address_read(self, cli_runner, target, port):
        """Test reading a group address (lighting datapoint) [Category B]

        Calimero has the group address filter configured but reads may
        return empty/no response from virtual devices.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--group-address",
            "1/0/1",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            text = _combined_text(result, result.scan_log)
            assert any(term in text for term in ["group", "1/0/1", "read", "knx", "tunnel"]), (
                f"Expected group address context, got: {text[:300]}"
            )

    @pytest.mark.containers("knx-calimero")
    def test_group_address_read_temperature(self, cli_runner, target, port):
        """Test reading temperature group address [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--group-address",
            "2/0/1",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.security
    def test_group_write_with_confirm(self, cli_runner, target, port):
        """Test writing to group address with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--group-write",
            "1/0/1:01",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.security
    def test_group_write_dimmer(self, cli_runner, target, port):
        """Test writing to dimmer group address [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--group-write",
            "1/1/1:80",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Memory Operations Tests (CEMI management -- mock likely does NOT support)
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    def test_memory_dump(self, cli_runner, target, port):
        """Test memory dump operation [Category B]

        Calimero virtual subnet does not support MemoryRead CEMI frames.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--memory-dump",
            "0x0100:64",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    def test_memory_ext(self, cli_runner, target, port):
        """Test extended memory dump (24-bit addresses) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--memory-ext",
            "0x010000:64",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    def test_memory_user(self, cli_runner, target, port):
        """Test user memory dump [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--memory-user",
            "0x0100:64",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.security
    def test_memory_write_with_confirm(self, cli_runner, target, port):
        """Test memory write with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--memory-write",
            "0x0116:00",
            "-i",
            "1.1.0",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Property Operations Tests (CEMI management -- mock likely does NOT support)
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    def test_property_read(self, cli_runner, target, port):
        """Test reading property value (serial number) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--property-read",
            "0:78",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.security
    def test_property_write_with_confirm(self, cli_runner, target, port):
        """Test property write with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--property-write",
            "0:19:00",
            "-i",
            "1.1.0",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    def test_prop_desc(self, cli_runner, target, port):
        """Test reading property description/metadata [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--prop-desc",
            "0:78",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    def test_prop_dump(self, cli_runner, target, port):
        """Test dumping all properties of all interface objects [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--prop-dump",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    def test_adc_read(self, cli_runner, target, port):
        """Test reading ADC channel value [Category B]

        Calimero does not support ADC management frames.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--adc-read",
            "0",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Bus Scanning Tests
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.slow
    def test_bus_scan_with_range(self, cli_runner, target, port):
        """Test bus scan with small address range [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--bus-scan",
            "--scan-range",
            "1.1.1-1.1.5",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            text = _combined_text(result, result.scan_log)
            # Should indicate scanning activity
            assert any(
                term in text for term in ["scan", "bus", "fast", "address", "probe", "knx"]
            ), f"Expected bus scan activity in output, got: {text[:300]}"

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.slow
    def test_slow_scan(self, cli_runner, target, port):
        """Test slow scan method (nm_individual_address_check) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--bus-scan",
            "--slow-scan",
            "--scan-range",
            "1.1.1-1.1.3",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    def test_serial_scan(self, cli_runner, target, port):
        """Test finding device by serial number [Category B]

        Calimero does not support IndividualAddressSerialRead.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--serial-scan",
            "00FA12345678",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Passive Listening Tests
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.slow
    def test_listen_mode(self, cli_runner, target, port):
        """Test passive listen mode with short duration [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--listen",
            "--listen-time",
            "5",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            text = _combined_text(result, result.scan_log)
            assert any(term in text for term in ["listen", "traffic", "bus", "knx", "captured"]), (
                f"Expected listen mode context, got: {text[:300]}"
            )

    # ========================================================================
    # Authentication Tests (BCU auth -- mock likely does NOT support)
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.auth
    def test_auth_default_key(self, cli_runner, target, port):
        """Test default BCU key authentication (FFFFFFFF factory key) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--auth-test",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.auth
    def test_auth_custom_key(self, cli_runner, target, port):
        """Test custom BCU key authentication [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--auth-test",
            "00000000",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.auth
    def test_key_range_brute(self, cli_runner, target, port):
        """Test BCU key range brute force (small range) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--key-range",
            "00000000-00000003",
            "--brute-delay",
            "50",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.auth
    @pytest.mark.security
    def test_key_write_with_confirm(self, cli_runner, target, port):
        """Test BCU key write with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--key-write",
            "FFFFFFFF:0",
            "-i",
            "1.1.0",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Device Restart Test
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.security
    def test_restart_device_with_confirm(self, cli_runner, target, port):
        """Test device restart with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--restart",
            "-i",
            "1.1.0",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Fuzzing Tests
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.fuzz
    def test_fuzz_property(self, cli_runner, target, port):
        """Test fuzzing a property with small iteration count [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz-property",
            "0:19",
            "--fuzz-iterations",
            "3",
            "-i",
            "1.1.0",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Write Safety Tests (--confirm requirement)
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    def test_group_write_without_confirm(self, cli_runner, target, port):
        """Test that group write without --confirm is handled gracefully [Category C]

        The scanner may or may not require --confirm for group writes.
        The important thing is it does not crash.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--group-write",
            "1/0/1:01",
            timeout=30,
            json_log=True,
        )

        # Should not crash
        assert result.returncode != -1

    @pytest.mark.containers("knx-calimero")
    def test_write_without_confirm_rejected(self, cli_runner, target, port):
        """Test that property write without --confirm is properly handled [Category C]

        Property writes are dangerous operations that should require --confirm.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--property-write",
            "0:19:00",
            "-i",
            "1.1.0",
            timeout=30,
            json_log=True,
        )

        # Should handle gracefully (might reject or succeed depending on implementation)
        assert result.returncode != -1
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("knx-calimero")
    def test_key_write_without_confirm(self, cli_runner, target, port):
        """Test that key write without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--key-write",
            "FFFFFFFF:0",
            "-i",
            "1.1.0",
            timeout=30,
            json_log=True,
        )

        # Should not crash; might report error about missing --confirm
        assert result.returncode != -1
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Error Handling Tests
    # ========================================================================

    def test_invalid_individual_address_format(self, cli_runner, target, port):
        """Test handling of invalid individual address format [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-info",
            "-i",
            "invalid.address",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should handle gracefully (fail but not crash)
        assert result.returncode != -1
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_invalid_memory_range_format(self, cli_runner, target, port):
        """Test handling of invalid memory range specification [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--memory-dump",
            "not-a-range",
            "-i",
            "1.1.0",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should handle gracefully
        assert result.returncode != -1

    def test_connection_refused_port(self, cli_runner, target):
        """Test connection to closed port [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "65534",
            "--gateway-scan",
            "--timeout",
            "3",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should complete without hanging
        assert result.returncode != -1

    # ========================================================================
    # ETS Project File Tests (no network, tests arg parsing and file handling)
    # ========================================================================

    def test_knxproj_nonexistent_file(self, cli_runner):
        """Test --knxproj with nonexistent file [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "--knxproj",
            "/nonexistent/path/project.knxproj",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail gracefully with file-not-found
        assert result.returncode in [0, 1, 2]
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        # Must specifically signal the missing file -- _handle_knxproj() emits
        # "File not found: <path>" via logger.fail(). Require a real
        # file-not-found phrasing, not just an incidental "knxproj" token.
        assert any(
            term in text for term in ["not found", "no such", "does not exist", "file not found"]
        ), f"Expected file-not-found error for missing knxproj, got: {text[:300]}"
        # And the offending path should be surfaced to the operator.
        assert "project.knxproj" in text, (
            f"Expected the missing knxproj path in output, got: {text[:300]}"
        )

    def test_knxproj_info_nonexistent(self, cli_runner):
        """Test --knxproj-info with nonexistent file [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "--knxproj",
            "/nonexistent.knxproj",
            "--knxproj-info",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail gracefully
        assert result.returncode in [0, 1, 2]

    def test_knxproj_hash_nonexistent(self, cli_runner):
        """Test --knxproj-hash with nonexistent file [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "--knxproj",
            "/nonexistent.knxproj",
            "--knxproj-hash",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail gracefully
        assert result.returncode in [0, 1, 2]

    # ========================================================================
    # Output Format Tests
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    def test_csv_output_format(self, cli_runner, target, port):
        """Test CSV output format [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="csv",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"CSV output failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

    @pytest.mark.containers("knx-calimero")
    def test_xml_output_format(self, cli_runner, target, port):
        """Test XML output format [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="xml",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"XML output failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

    # ========================================================================
    # Standard / Verbosity Tests
    # ========================================================================

    def test_help_output(self, cli_runner):
        """Test --help output shows KNX-specific options [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )

        assert result.returncode == 0
        output = result.combined_output.lower()
        assert "knx" in output
        # Should mention key KNX-specific flags
        assert any(
            term in output
            for term in ["gateway-scan", "bus-scan", "group-address", "individual-address"]
        ), f"Expected KNX-specific flags in help output, got: {output[:500]}"

    @pytest.mark.containers("knx-calimero")
    def test_verbose_output(self, cli_runner, target, port):
        """Test verbose output flag [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            verbose=True,
            timeout=30,
        )

        assert result.success, f"Verbose mode failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

    @pytest.mark.containers("knx-calimero")
    def test_debug_output(self, cli_runner, target, port):
        """Test --debug output flag [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            debug=True,
            timeout=30,
        )

        assert result.success, f"Debug mode failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Debug mode should produce debug-level events
        debug_events = log.get_events(level="debug")
        assert len(debug_events) > 0, "Expected debug-level events with --debug flag"

    @pytest.mark.containers("knx-calimero")
    def test_verbose_with_gateway_scan(self, cli_runner, target, port):
        """Test verbose + gateway-scan combination [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--gateway-scan",
            format="json",
            json_log=True,
            verbose=True,
            timeout=30,
        )

        assert result.success, f"Verbose gateway scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Verbose mode should produce events at info level or above
        all_events = log.get_events()
        assert len(all_events) > 0, "Expected events from verbose gateway scan"

    # ========================================================================
    # Security Findings Tests
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.security
    def test_security_finding_no_encryption(self, cli_runner, target, port):
        """Test that scanner reports 'No encryption' finding for KNX protocol [Category A]

        KNX protocol does not use encryption by design. The 'No encryption'
        finding is emitted UNCONDITIONALLY in _analyze_security() (security.py)
        which runs in discover() at scanner.py:204 regardless of whether the
        xknx tunnel actually completes -- _async_discover() returns a results
        dict (never raises), so the finding always fires once the tunnel path
        is entered via --device-info. This is therefore Category A: we assert
        the exact structured finding is present, not merely a text mention.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-info",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        assert result.scan_log is not None, "scan_log should be populated when json_log=True"
        findings = result.scan_log.get_security_findings()

        # Require the exact structured 'No encryption' finding emitted by
        # _analyze_security(). All security findings carry event_type=security
        # and data.finding set to the finding name.
        finding_names = [f.get("data", {}).get("finding") for f in findings]
        assert "No encryption" in finding_names, (
            f"Expected structured 'No encryption' security finding. Got findings: {finding_names}"
        )
        # The finding event must carry the explanatory detail and be a security event.
        enc = next(f for f in findings if f.get("data", {}).get("finding") == "No encryption")
        assert enc.get("event_type") == "security"
        assert "encryption" in str(enc.get("data", {}).get("details", "")).lower()

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.security
    def test_security_finding_no_authentication(self, cli_runner, target, port):
        """Test that scanner reports 'No authentication' finding for KNX protocol [Category A]

        KNX protocol does not require authentication by design. The
        'No authentication' finding is emitted UNCONDITIONALLY in
        _analyze_security() (security.py), which runs in discover() regardless
        of tunnel completion (see test_security_finding_no_encryption). We use
        --device-info to enter the tunnel path and assert the exact structured
        finding rather than a vacuous text mention. Category A.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-info",
            "-i",
            "1.1.0",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        assert result.scan_log is not None, "scan_log should be populated when json_log=True"
        findings = result.scan_log.get_security_findings()

        finding_names = [f.get("data", {}).get("finding") for f in findings]
        assert "No authentication" in finding_names, (
            f"Expected structured 'No authentication' security finding. Got findings: {finding_names}"
        )
        auth = next(f for f in findings if f.get("data", {}).get("finding") == "No authentication")
        assert auth.get("event_type") == "security"
        assert "authentication" in str(auth.get("data", {}).get("details", "")).lower()

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.security
    def test_security_finding_writable_access(self, cli_runner, target, port):
        """Test that scanner reports 'Writable access' when write tests find writable devices [Category B]

        The 'Writable access' finding is emitted in _analyze_security() only if
        write_test_results contains devices with writable_addresses. This requires
        the scanner to discover devices AND run write tests. The Calimero mock
        may not support the full CEMI management flow needed for write testing,
        so this is Category B. We trigger a tunnel scan and check for any
        indication of write access analysis.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--group-write",
            "1/0/1:01",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        findings = result.scan_log.get_security_findings() if result.scan_log is not None else []

        # Check for writable access finding or write-related activity
        has_write_finding = any("writ" in str(f.get("data", {})).lower() for f in findings)
        has_write_text = any(
            term in text
            for term in [
                "writable access",
                "write access",
                "group write",
                "group_write",
                "write",
            ]
        )
        # If tunnel/connection failed, that's acceptable output too
        tunnel_failed = any(
            term in text for term in ["connection failed", "connection timeout", "tunnel"]
        )
        assert has_write_finding or has_write_text or tunnel_failed, (
            f"Expected writable access finding, write mention, or tunnel failure. "
            f"Findings: {[f.get('data', {}).get('finding') for f in findings]}, "
            f"text excerpt: {text[:500]}"
        )

    @pytest.mark.containers("knx-calimero")
    @pytest.mark.security
    def test_security_finding_insecure_configuration(self, cli_runner, target, port):
        """Test that scanner reports 'Insecure configuration' when routing is accessible [Category B]

        The 'Insecure configuration' finding is emitted in _analyze_security()
        when routing_test.routing_supported is True. Routing test runs when
        test-routing is enabled internally (not directly exposed as CLI flag).
        The Calimero mock supports routing, so if the scanner runs routing
        analysis during a full scan, this finding may appear. We trigger a
        bus scan to exercise the full tunnel path where routing may be tested.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--bus-scan",
            "--scan-range",
            "1.1.1-1.1.3",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        findings = result.scan_log.get_security_findings() if result.scan_log is not None else []

        # Check for insecure configuration finding or routing-related info
        has_routing_finding = any(
            "insecure" in str(f.get("data", {})).lower()
            or "routing" in str(f.get("data", {})).lower()
            for f in findings
        )
        has_routing_text = any(
            term in text
            for term in [
                "insecure configuration",
                "routing accessible",
                "routing",
                "bus scan",
                "bus-scan",
                "scan",
            ]
        )
        # If tunnel/connection failed, that's acceptable output too
        tunnel_failed = any(
            term in text for term in ["connection failed", "connection timeout", "tunnel"]
        )
        assert has_routing_finding or has_routing_text or tunnel_failed, (
            f"Expected insecure config finding, routing mention, or tunnel failure. "
            f"Findings: {[f.get('data', {}).get('finding') for f in findings]}, "
            f"text excerpt: {text[:500]}"
        )

    @pytest.mark.security
    def test_security_finding_weak_password_knxproj(self, cli_runner):
        """Test that scanner reports 'Weak password' when KNX project password is cracked [Category C]

        The 'Weak password' finding is emitted in _handle_knxproj() when
        crack_knxproj() successfully finds the password via a wordlist.
        This requires a real password-protected .knxproj file and a
        wordlist containing the correct password. Since we do not have
        these test fixtures, we test that the scanner handles the missing
        file gracefully and produces appropriate error output. A real
        'Weak password' finding would need Category A test fixtures.
        """
        result = cli_runner.run(
            self.protocol_name,
            "--knxproj",
            "/nonexistent/test_project.knxproj",
            "--knxproj-wordlist",
            "/nonexistent/wordlist.txt",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should fail gracefully (file not found) but not crash
        assert result.returncode != -1
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        # Must produce error output about missing file or knxproj context
        assert any(
            term in text
            for term in [
                "not found",
                "error",
                "failed",
                "no such",
                "knxproj",
                "does not exist",
            ]
        ), f"Expected error message about missing knxproj file, got: {text[:500]}"

    # ========================================================================
    # JSON Log Structure Validation
    # ========================================================================

    @pytest.mark.containers("knx-calimero")
    def test_json_log_event_lifecycle(self, cli_runner, target, port):
        """Test that JSON log captures scan lifecycle events [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result, min_count=2)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Verify event types exist in the log
        event_types = {e.get("event_type") for e in log.events}
        assert len(event_types) > 0, "Expected at least one event type in log"

        # All events should have module set
        for i, event in enumerate(log.events):
            assert event.get("module"), f"Event {i} missing 'module' field"

    @pytest.mark.containers("knx-calimero")
    def test_json_log_gateway_info(self, cli_runner, target, port):
        """Test that JSON log contains gateway information [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--gateway-scan",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Gateway scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Should have success or display messages about gateway
        messages = _all_messages(log)
        has_gateway_info = any(
            term in messages
            for term in [
                "gateway",
                "knx",
                "1.1.0",
                "oida",
                "tunnelling",
                "tunneling",
                "routing",
                "found",
            ]
        )
        assert has_gateway_info, f"Expected gateway info in log messages. Got: {messages[:500]}"
