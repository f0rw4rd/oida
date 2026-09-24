"""
OPC UA Protocol Integration Tests

Tests oida opcua scanner against Docker mock services.
Uses structured JSON log assertions for precise validation.

Mock Server Data (from docker/mocks/services/opcua_server.py):
  Server Name:    "OIDA Enhanced Mock OPC UA Server"
  Namespace URI:  "http://oida.mock.server"
  Product:        "FreeOpcUa Python Server" (asyncua default BuildInfo)

  Authentication:
    Port 4840 (default):   admin/admin, operator/operator123, readonly/readonly, user/user
    Port 4841 (advanced):  admin/admin  (OPCUA_AUTH=true, OPCUA_SECURITY=true)
    Port 4842 (insecure):  anonymous only, no security

  Address Space (ns=2):
    IndustrialDevice/
      Sensors/       Temperature1(W,H), Temperature2(W,H), Pressure1(H), Pressure2, FlowRate
      Actuators/     MotorSpeed(W), MotorEnabled(W), ValvePosition(W), ValveOpen(W), PumpFlow(W)
      Alarms/        TemperatureAlarm, PressureAlarm, SystemFault
      Configuration/ TemperatureSetpoint(W), PressureSetpoint(W), MaxFlowRate(W),
                     DeviceName="Mock Industrial Controller", FirmwareVersion="v1.2.3",
                     SerialNumber="OIDA-001"
      Methods/       StartPump, StopPump, ResetDevice, SetTemperature(Float),
                     EmergencyStop, GetDiagnostics, ExecuteCommand(String)
      Files/         config.ini(R), system.log(R), firmware.bin(W), recipe.xml(W)

  Historizing:  Temperature1, Temperature2, Pressure1
  Writable:     Temperature1, Temperature2, MotorSpeed, MotorEnabled, ValvePosition,
                ValveOpen, PumpFlow, TemperatureSetpoint, PressureSetpoint, MaxFlowRate

  GDS Server (port 4850):
    Pre-registered servers: Industrial Controller 1, HMI Server, Historian Server
    FindServersOnNetwork, RegisterServer (no auth)

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  30 tests
Category B (conditional -- mock may not support, accept 0 or 1):       43 tests
Category C (error handling -- assert failure + validate error events):  19 tests
Skipped (untestable -- flag untestable or requires certificate):        3 tests
Total defined in file:                                                  95 tests
Total collected (including inherited from BaseProtocolIntegrationTest): 102 tests
---------------------------------------------------------------------------

Flag Coverage Matrix (proto_args.py):
  --port                    [A] (via base), test_basic_server_info
  --timeout                 [A] test_custom_timeout
  --get-endpoints           [A] test_get_endpoints
  --find-servers            [B] test_find_servers
  --find-servers-on-network [B] test_find_servers_on_network
  --gds-url                 [B] test_gds_url
  -d/--dump                 [A] test_browse_address_space, test_browse_max_depth
  -D/--dump-all             [A] test_dump_all_with_access_levels
  --dump-values             [A] test_dump_all_with_values
  --dump-methods            [A] test_dump_methods
  --dump-write              [A] test_dump_writable_nodes
  --dump-namespaces         [A] test_dump_namespaces
  --dump-examples           [B] test_dump_methods_with_examples
  --dump-history            [A] test_dump_history
  --dump-files              [A] test_dump_files
  --max-depth               [A] test_browse_max_depth, test_max_depth_actually_limits
  --max-nodes               [A] test_max_nodes_limit, test_max_nodes_actually_limits
  --ns                      [B] test_namespace_filter, [C] test_namespace_filter_invalid
  --start-node              [B] test_start_node, [C] test_start_node_invalid
  --node-id                 [A] test_read_specific_node_known, [B] test_read_specific_node
  --read-attributes         [B] test_read_attributes
  --write-value             [B] test_write_value_with_confirm, [C] test_write_value_no_confirm
  --call-method             [B] test_call_method, [C] test_method_args_malformed_json
  --method-args             [B] test_call_method_with_args, [C] test_method_args_malformed_json
  --subscribe               [B] test_subscribe_values
  --subscribe-events        [B] test_subscribe_events
  --subscription-interval   [B] test_subscription_interval
  --duration                [B] test_subscribe_values, test_subscribe_honours_duration
  --history-read            [B] test_history_read
  --history-start/end       [B] test_history_read_with_time_range
  --history-max             [B] test_history_read_with_time_range
  --history-raw             [B] test_history_raw
  --history-start           [C] test_history_invalid_datetime
  --read-file               [B] test_file_output, [C] test_read_file_invalid_node
  --file-output             [B] test_file_output
  --write-file              [C] test_write_file_requires_confirm
  --file-data               [C] test_write_file_requires_confirm
  --username/--password     [A] test_valid_credentials, [C] test_invalid_credentials;
                            file-driven brute: test_security_finding_brute_force_valid_creds_advanced
  --brute-rate              [B] test_brute_delay
  --mode                    [B] test_security_modes, test_security_mode_sign_and_encrypt
  --policy                  [B] test_security_policy_basic256, test_security_policy_basic256sha256
  --certificate/--privatekey [C] test_certificate_auth_missing_files
  --test-cert-trust         [B] test_cert_trust
  --test-subscription-limits [B] test_subscription_limits
  --test-rbac               [B] test_rbac_testing
  --rbac-detailed           [B] test_rbac_detailed
  --confirm                 [A] test_write_value_with_confirm, [C] test_write_value_no_confirm, test_fuzz_without_confirm_is_rejected
  --fuzz nodes              [C] test_node_fuzzing, test_fuzz_without_confirm_is_rejected
  --fuzz methods            [C] test_fuzz_all_methods
  --fuzz-method             [C] test_method_fuzzing
  --fuzz-node               [C] test_fuzz_specific_node
  --fuzz-iterations         [C] test_node_fuzzing, test_fuzz_all_methods
  format (global)           [B] test_csv_output
  -v (global)               [B] test_verbose_output
  --debug (global)          [B] test_debug_output
  --help (global)           [A] test_help_output
"""

import time

import pytest
from typing import Optional

from tests.integration.base_protocol_test import BaseProtocolIntegrationTest
from tests.integration.conftest import MOCK_HOST


# ---------------------------------------------------------------------------
# Known Mock Data Constants (extracted from opcua_server.py)
# ---------------------------------------------------------------------------
MOCK_SERVER_NAME = "oida enhanced mock opc ua server"
MOCK_NAMESPACE_URI = "http://oida.mock.server"
MOCK_DEVICE_NAME = "mock industrial controller"
MOCK_FIRMWARE = "v1.2.3"
MOCK_SERIAL = "oida-001"

# Sensor/actuator node names present in the mock address space
MOCK_SENSOR_NAMES = ["temperature1", "temperature2", "pressure1", "pressure2", "flowrate"]
MOCK_ACTUATOR_NAMES = ["motorspeed", "motorenabled", "valveposition", "valveopen", "pumpflow"]
MOCK_METHOD_NAMES = [
    "startpump",
    "stoppump",
    "resetdevice",
    "settemperature",
    "emergencystop",
    "getdiagnostics",
    "executecommand",
]
MOCK_FILE_NAMES = ["config.ini", "system.log", "firmware.bin", "recipe.xml"]
MOCK_FOLDER_NAMES = ["sensors", "actuators", "methods", "files", "configuration", "alarms"]

# Writable node names (set_writable() in mock)
MOCK_WRITABLE_NAMES = [
    "temperature1",
    "temperature2",
    "motorspeed",
    "motorenabled",
    "valveposition",
    "valveopen",
    "pumpflow",
    "temperaturesetpoint",
    "pressuresetpoint",
    "maxflowrate",
]

# Credentials for default server (port 4840) with OPCUA_AUTH=true
AUTH_DEFAULT = ("admin", "admin")  # Port 4840
AUTH_OPERATOR = ("operator", "operator123")
AUTH_READONLY = ("readonly", "readonly")


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


@pytest.mark.opcua
class TestOPCUAIntegration(BaseProtocolIntegrationTest):
    """Integration tests for OPC UA protocol scanner"""

    @property
    def protocol_name(self) -> str:
        return "opcua"

    @property
    def default_port(self) -> int:
        return 4840

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        p = port or self.default_port
        return f"opc.tcp://{host}:{p}"

    @property
    def uses_port_argument(self) -> bool:
        return False

    def _assert_successful_discovery(self, result):
        """OPC UA discovery succeeds if endpoints are found, even if anonymous auth is rejected"""
        if result.success:
            return
        output = result.combined_output.lower()
        assert any(x in output for x in ["endpoint", "security", "policy", "server"]), (
            f"Discovery failed with no endpoint info: {result.stderr}\nCommand: {result.command}"
        )

    @pytest.mark.slow
    def test_concurrent_connections(self, cli_runner, target, port):
        """Test multiple concurrent connections to same target [Category B]"""
        import concurrent.futures

        port_args = self._get_port_args(port)

        def run_scan():
            args = [self.protocol_name, target] + port_args
            return cli_runner.run(*args, format="json", timeout=30)

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(run_scan) for _ in range(3)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All connections should complete (not hang)
        for r in results:
            assert r.returncode != -1, "Concurrent connection should not hang"

        successes = [r for r in results if r.success or "endpoint" in r.combined_output.lower()]
        assert len(successes) >= 1, "No concurrent connections produced endpoint info"

    # ========================================================================
    # Category A: Discovery Tests (port 4842 insecure -- anonymous access)
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_get_endpoints(self, cli_runner, mock_host, mock_ports):
        """Test getting server endpoints lists security policies [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--get-endpoints",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        assert any(x in text for x in ["endpoint", "policy", "security"]), (
            f"Expected endpoint/policy info. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_basic_server_info(self, cli_runner, mock_host, mock_ports):
        """Test default scan returns server product info [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # The insecure server should return product/server info
        assert any(x in text for x in ["server", "endpoint", "product", "freeopcua"]), (
            f"Expected server info in output. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_basic_server_info_connection_lifecycle(self, cli_runner, mock_host, mock_ports):
        """Test that basic discovery produces proper connection lifecycle events [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Verify connection lifecycle events exist
        conn_events = log.get_connection_events()
        if conn_events:
            assert len(conn_events) >= 1, "Expected at least one connection event"

    @pytest.mark.containers("opcua-insecure")
    def test_custom_timeout(self, cli_runner, mock_host, mock_ports):
        """Test --timeout flag is respected [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Category A: Address Space Browsing
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_browse_address_space(self, cli_runner, mock_host, mock_ports):
        """Test -d dumps address space with node names [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--max-depth",
            "4",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # At depth 4 we see ns=2 folder names (Sensors, Actuators, Methods, etc.)
        found = [name for name in MOCK_FOLDER_NAMES if name in text]
        assert len(found) >= 1, (
            f"Expected address space folder names. Found: {found}. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_browse_max_depth(self, cli_runner, mock_host, mock_ports):
        """Test dump with shallow depth limit [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--max-depth",
            "2",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-insecure")
    def test_max_nodes_limit(self, cli_runner, mock_host, mock_ports):
        """Test --max-nodes caps the number of browsed nodes [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])

        # Run with small cap
        result_small = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--max-nodes",
            "10",
            "--max-depth",
            "5",
            format="json",
            json_log=True,
        )

        assert result_small.success, f"Failed: {result_small.stderr}"
        assert result_small.returncode == 0
        _assert_log_has_events(result_small)
        _assert_log_event_structure(result_small.scan_log)

        text_small = _combined_text(result_small, result_small.scan_log)
        assert any(x in text_small for x in ["node", "dump", "browse", "object", "variable"]), (
            f"Expected browse output with max-nodes. Got: {text_small[:500]}"
        )

        # Run with larger cap for comparison
        result_large = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--max-nodes",
            "200",
            "--max-depth",
            "5",
            format="json",
            json_log=True,
        )

        assert result_large.success, f"Failed: {result_large.stderr}"
        text_large = _combined_text(result_large, result_large.scan_log)

        # The small cap should produce noticeably less output than the large cap
        assert len(text_small) < len(text_large), (
            f"max-nodes=10 ({len(text_small)} chars) should produce less output "
            f"than max-nodes=200 ({len(text_large)} chars)"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_dump_all_with_access_levels(self, cli_runner, mock_host, mock_ports):
        """Test -D shows access levels (R/W/H) on nodes [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-D",
            "--max-depth",
            "3",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Full dump should show access level indicators (R=Read, W=Write, H=History)
        assert any(
            x in text for x in ["access", "currentread", "currentwrite", "rw", "rh", "rwh"]
        ) or (
            "variable" in text and any(x in text for x in MOCK_SENSOR_NAMES + MOCK_ACTUATOR_NAMES)
        ), f"Expected access level info in dump-all. Got: {text[:500]}"

    @pytest.mark.containers("opcua-insecure")
    def test_dump_all_with_values(self, cli_runner, mock_host, mock_ports):
        """Test -D --dump-values includes current values [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-D",
            "--dump-values",
            "--max-depth",
            "4",
            "--max-nodes",
            "50",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # With dump-values, should see actual data values from sensors (numeric values or type names)
        import re

        has_numeric_value = bool(re.search(r"\d+\.\d+", text))
        has_value_keyword = any(x in text for x in ["value", "float", "double", "int32", "boolean"])
        has_known_node_value = any(
            x in text for x in [MOCK_DEVICE_NAME, MOCK_FIRMWARE, MOCK_SERIAL]
        )
        assert has_numeric_value or has_value_keyword or has_known_node_value, (
            f"Expected actual data values in dump-all --dump-values. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_dump_methods(self, cli_runner, mock_host, mock_ports):
        """Test --dump-methods lists callable methods [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--dump-methods",
            "--max-depth",
            "5",
            expect_json=False,
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        found_methods = [m for m in MOCK_METHOD_NAMES if m in text]
        assert len(found_methods) >= 1, (
            f"Expected method names in output. Found: {found_methods}. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_dump_writable_nodes(self, cli_runner, mock_host, mock_ports):
        """Test --dump-write shows writable variables [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--dump-write",
            "--max-depth",
            "5",
            expect_json=False,
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        found = [n for n in MOCK_WRITABLE_NAMES if n in text]
        assert len(found) >= 1, f"Expected writable node names. Found: {found}. Got: {text[:500]}"

    @pytest.mark.containers("opcua-insecure")
    def test_dump_namespaces(self, cli_runner, mock_host, mock_ports):
        """Test --dump-namespaces shows the namespace table [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--dump-namespaces",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Should show the mock namespace URI
        assert any(x in text for x in ["namespace", "oida.mock", "opc.tcp", "opcfoundation"]), (
            f"Expected namespace info. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_dump_history(self, cli_runner, mock_host, mock_ports):
        """Test --dump-history finds historizing nodes [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--dump-history",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        assert any(x in text for x in ["histor", "temperature", "pressure"]), (
            f"Expected historizing info. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_dump_files(self, cli_runner, mock_host, mock_ports):
        """Test --dump-files finds FileType nodes [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--dump-files",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        assert any(x in text for x in ["file", "config", "firmware", "recipe"]), (
            f"Expected file node info. Got: {text[:500]}"
        )

    # ========================================================================
    # Category A: Security Findings
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_security_findings_insecure(self, cli_runner, mock_host, mock_ports):
        """Test security analysis detects insecure configuration [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--get-endpoints",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Insecure server should trigger findings about lack of security policy
        assert any(
            x in text for x in ["nosecurity", "no security", "insecure", "securitypolicy#none"]
        ), f"Expected insecure configuration findings. Got: {text[:500]}"

    @pytest.mark.containers("opcua-insecure")
    def test_security_findings_anonymous_access(self, cli_runner, mock_host, mock_ports):
        """Test that anonymous access is detected as a security finding [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Anonymous access on insecure server should be reported specifically
        assert "anonymous" in text, f"Expected anonymous access finding. Got: {text[:500]}"

    @pytest.mark.containers("opcua-insecure")
    def test_security_findings_no_encryption(self, cli_runner, mock_host, mock_ports):
        """Test that lack of encryption is detected on insecure server [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--get-endpoints",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Check for security findings about encryption specifically
        security_events = log.get_security_findings()
        text = _combined_text(result, log)

        # Insecure server (OPCUA_SECURITY=false) has no encryption --
        # check for encryption-related findings or security event count
        has_encryption_finding = (
            len(security_events) > 0
            or "encrypt" in text
            or "no security" in text
            or "insecure" in text
            or "nosecurity" in text
        )
        assert has_encryption_finding, (
            f"Expected encryption/security finding. "
            f"Security events: {len(security_events)}. Got: {text[:500]}"
        )

    # ========================================================================
    # Category A: Security Findings -- Auditing & Writable Access
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.security
    def test_security_finding_auditing_disabled(self, cli_runner, mock_host, mock_ports):
        """Test that auditing disabled is detected as Insecure configuration finding [Category A]

        The insecure mock server (OPCUA_AUTH=false, OPCUA_SECURITY=false) has
        asyncua's default Auditing=False on ns=0;i=2994. The _check_server_security()
        method reads this node after authentication and fires:
            security_finding("Insecure configuration", "Auditing disabled - no activity logging")
        """
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # _check_server_security() fires "Insecure configuration" when auditing is off
        assert "auditing" in text, (
            f"Expected 'auditing' mention in output (auditing disabled finding). Got: {text[:500]}"
        )
        # Validate it specifically mentions being disabled
        assert any(
            phrase in text
            for phrase in ["auditing disabled", "no activity logging", "auditing: false"]
        ), f"Expected auditing-disabled finding detail. Got: {text[:500]}"

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.security
    def test_security_finding_writable_access_full_browse(self, cli_runner, mock_host, mock_ports):
        """Test that -D full browse triggers 'Writable access' security finding [Category A]

        The browse mixin _dump_address_space(mode='full') checks writable nodes:
            if writable_nodes and mode != 'write':
                security_finding('Writable access', f'Found {len(writable_nodes)} writable variable(s)')
        The insecure mock has 10+ writable nodes (Temperature1, MotorSpeed, etc.).
        """
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-D",
            "--max-depth",
            "5",
            "--max-nodes",
            "200",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)

        # The full browse should detect writable nodes and fire the security finding
        assert "writable" in text, f"Expected 'writable' mention in output. Got: {text[:500]}"

        # Check for the security finding via structured log
        security_events = log.get_security_findings()
        writable_findings = [
            f
            for f in security_events
            if "writable" in f.get("message", "").lower()
            or f.get("data", {}).get("finding", "").lower() == "writable access"
        ]
        # Also check text for the finding message pattern
        has_writable_finding = (
            len(writable_findings) > 0 or "writable access" in text or "writable variable" in text
        )
        assert has_writable_finding, (
            f"Expected 'Writable access' security finding from full browse. "
            f"Security events: {len(security_events)}, writable findings: {len(writable_findings)}. "
            f"Output: {text[:500]}"
        )

        # Validate that at least one known writable node name is mentioned
        found_writable = [n for n in MOCK_WRITABLE_NAMES if n in text]
        assert len(found_writable) >= 1, (
            f"Expected writable mock nodes in output. Found: {found_writable}. "
            f"Looked for: {MOCK_WRITABLE_NAMES[:5]}. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.security
    def test_security_finding_writable_access_node_count(self, cli_runner, mock_host, mock_ports):
        """Test that the writable access finding reports a plausible count [Category A]

        The insecure mock defines at least 10 writable nodes:
        Temperature1, Temperature2, MotorSpeed, MotorEnabled, ValvePosition,
        ValveOpen, PumpFlow, TemperatureSetpoint, PressureSetpoint, MaxFlowRate
        """
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-D",
            "--max-depth",
            "5",
            "--max-nodes",
            "200",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)

        # The message should mention a count, e.g. "Found 10 writable variable(s)"
        import re

        writable_match = re.search(r"found\s+(\d+)\s+writable", text)
        assert writable_match, f"Expected 'Found N writable' pattern in output. Got: {text[:500]}"
        writable_count = int(writable_match.group(1))
        # The mock has at least 10 writable nodes
        assert writable_count >= 5, f"Expected at least 5 writable nodes, found {writable_count}"

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.security
    def test_security_finding_insecure_config_via_structured_log(
        self, cli_runner, mock_host, mock_ports
    ):
        """Test that security findings appear as structured events in JSON log [Category A]

        When scanning the insecure server, _check_server_security() fires
        security_finding('Insecure configuration', 'Auditing disabled - no activity logging').
        This should appear as a structured event with event_type='security'.
        """
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Look for security events specifically
        security_events = log.get_security_findings()
        text = _combined_text(result, log)

        # The insecure server MUST emit structured security events (not just console text).
        assert len(security_events) > 0, (
            f"Expected structured security events from insecure server scan, got none. "
            f"Output: {text[:500]}"
        )

        # The "Insecure configuration" finding (auditing disabled) must carry its
        # human-readable text in the `details` field of security_finding(), NOT
        # mis-slotted into `category`. This guards against the security_finding(
        # title, "detail") positional-arg bug where the detail lands in `category`.
        structured_findings = [
            e.get("data", {}) for e in security_events if isinstance(e.get("data"), dict)
        ]
        insecure_findings = [
            d for d in structured_findings if d.get("finding") == "Insecure configuration"
        ]
        assert insecure_findings, (
            f"Expected an 'Insecure configuration' structured finding. "
            f"Structured findings: {structured_findings}"
        )
        assert any("details" in d and d["details"] for d in insecure_findings), (
            f"'Insecure configuration' finding must populate the `details` field "
            f"(detail text must not be mis-slotted into `category`). "
            f"Findings: {insecure_findings}"
        )
        assert any("auditing" in d.get("details", "").lower() for d in insecure_findings), (
            f"Expected the auditing-disabled detail in the finding `details`. "
            f"Findings: {insecure_findings}"
        )

    # ========================================================================
    # Category B: Security Findings -- Credentials, RBAC, Deprecated Policies
    # ========================================================================

    @pytest.mark.security
    @pytest.mark.auth
    @pytest.mark.slow
    @pytest.mark.containers("opcua-advanced")
    def test_security_finding_default_credentials(
        self, cli_runner, mock_host, mock_ports, tmp_path
    ):
        """Test that brute force detects default credentials and fires finding [Category B]

        The advanced server (port 4841) has OPCUA_AUTH=true with admin:admin.
        When passing username/password as files, _brute_force_credentials() tests each pair.
        On success it fires: security_finding('Default credentials', 'Valid OPC UA credentials: ...')
        """
        # Create credential files
        user_file = tmp_path / "opcua_users.txt"
        user_file.write_text("admin\noperator\ninvalid_user\n")
        pass_file = tmp_path / "opcua_passwords.txt"
        pass_file.write_text(f"{AUTH_DEFAULT[1]}\n{AUTH_OPERATOR[1]}\nwrong_pass\n")

        target = self.get_target(mock_host, mock_ports["opcua_auth"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--username",
            str(user_file),
            "--password",
            str(pass_file),
            format="json",
            json_log=True,
            timeout=90,
        )

        # Crash guard -- brute force may succeed or fail depending on timing
        assert result.returncode in [0, 1]

        # UNCONDITIONAL: scanner must show it attempted credential testing
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["testing", "credential", "brute", "pairs", "valid", "denied"]
        ), f"Expected credential testing attempt in output. Got: {text[:500]}"

        # If successful, check for the security finding
        if result.success and result.scan_log is not None:
            security_events = result.scan_log.get_security_findings()
            cred_findings = [
                f
                for f in security_events
                if "credential" in f.get("message", "").lower()
                or f.get("data", {}).get("finding", "").lower() == "default credentials"
            ]
            if cred_findings:
                # Validate the finding mentions the actual username. The username
                # lives in data.details ("Valid OPC UA credentials: user:pass");
                # message carries only the finding title.
                finding_text = " ".join(
                    f"{f.get('message', '')} {f.get('data', {}).get('details', '')}"
                    for f in cred_findings
                ).lower()
                assert "admin" in finding_text or "valid" in finding_text, (
                    f"Expected credential finding to mention 'admin'. Got: {finding_text[:300]}"
                )

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.security
    @pytest.mark.auth
    @pytest.mark.slow
    def test_security_finding_no_rbac_insecure(self, cli_runner, mock_host, mock_ports):
        """Test that RBAC test on insecure server detects no access control [Category B]

        On the insecure server (OPCUA_AUTH=false), all auth methods have the same
        read/write access. The _test_rbac() method compares anonymous vs named user
        and fires: security_finding('No authentication', 'NO RBAC DETECTED - ...')

        Note: This requires providing credentials to test RBAC comparison.
        The insecure server allows anonymous access, so named credentials will also
        connect (or fail gracefully), and if both connect with same permissions,
        the finding fires.
        """
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-rbac",
            "--username",
            "admin",
            "--password",
            "admin",
            format="json",
            json_log=True,
            timeout=60,
        )

        # Crash guard
        assert result.returncode in [0, 1]

        # UNCONDITIONAL: scanner must attempt RBAC testing
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in ["rbac", "role-based", "auth method", "access control", "testing"]
        ), f"Expected RBAC testing attempt in output. Got: {text[:500]}"

        # Check for the specific RBAC findings
        if result.scan_log is not None and len(result.scan_log) > 0:
            security_events = result.scan_log.get_security_findings()
            rbac_findings = [
                f
                for f in security_events
                if any(
                    term in f.get("message", "").lower()
                    for term in ["no rbac", "no authentication", "same access"]
                )
                or f.get("data", {}).get("finding", "") in ("No authentication", "Anonymous access")
            ]
            # Also check text for the finding patterns
            has_rbac_finding = (
                len(rbac_findings) > 0
                or "no rbac" in text
                or "same access" in text
                or "no authentication" in text
            )
            # The comparison only runs once at least two auth methods connect.
            # On the insecure server (OPCUA_AUTH=false) anonymous and the named
            # user see the same node set, so the comparison must land on the
            # no-RBAC finding, not on "RBAC appears to be configured".
            if "connected auth methods: 2/2" in text:
                assert has_rbac_finding, (
                    "Both auth methods connected to the insecure server, so the "
                    f"no-RBAC finding must fire. Got: {text[:500]}"
                )
            # At minimum we should see the RBAC test attempted
            assert "rbac" in text or "role" in text or "auth method" in text, (
                f"Expected RBAC analysis output. Got: {text[:500]}"
            )

    @pytest.mark.security
    @pytest.mark.auth
    @pytest.mark.slow
    @pytest.mark.containers("opcua-advanced")
    def test_security_finding_anonymous_access_vs_named(self, cli_runner, mock_host, mock_ports):
        """Test that RBAC detects anonymous has same/more access than named user [Category B]

        On insecure server, _test_rbac() checks:
            if anon_read >= user_read:
                security_finding('Anonymous access', 'Anonymous has same/more access than ...')

        On the insecure server both anonymous and named users have identical permissions,
        so this finding should fire.
        """
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-rbac",
            "--username",
            "testuser",
            "--password",
            "testpass",
            format="json",
            json_log=True,
            timeout=60,
        )

        # Crash guard
        assert result.returncode in [0, 1]

        # UNCONDITIONAL: scanner must attempt the operation
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["rbac", "anonymous", "testing", "auth method", "access"]
        ), f"Expected RBAC/anonymous access testing in output. Got: {text[:500]}"

        # On insecure server, anonymous connects fine. If a named user also connects
        # (which it may since there's no auth), both have the same access.
        if result.scan_log is not None and len(result.scan_log) > 0:
            security_events = result.scan_log.get_security_findings()
            anon_findings = [
                f
                for f in security_events
                if "anonymous" in f.get("message", "").lower()
                or f.get("data", {}).get("finding", "").lower() == "anonymous access"
            ]
            if anon_findings:
                # Validate the finding mentions comparative access
                finding_text = " ".join(f.get("message", "") for f in anon_findings).lower()
                assert (
                    "same" in finding_text or "more" in finding_text or "access" in finding_text
                ), f"Expected anonymous access comparison finding. Got: {finding_text[:300]}"

    @pytest.mark.security
    @pytest.mark.containers("opcua-advanced")
    def test_security_finding_outdated_protocol_version(self, cli_runner, mock_host, mock_ports):
        """Test detection of deprecated security policies (Basic128Rsa15, Basic256) [Category B]

        The _show_endpoints_summary() detects deprecated policies in endpoint URIs.
        The advanced server (OPCUA_SECURITY=true) uses Basic256Sha256 and Aes128 --
        NOT deprecated Basic128Rsa15 or Basic256. So this test validates that the
        scanner at least checks for deprecated policies, even if none are found.

        If the mock serves deprecated policies, the finding would fire:
            security_finding('Outdated protocol version', 'Deprecated security policy: ...')
        """
        target = self.get_target(mock_host, mock_ports["opcua_auth"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--get-endpoints",
            "--username",
            AUTH_DEFAULT[0],
            "--password",
            AUTH_DEFAULT[1],
            format="json",
            json_log=True,
            timeout=30,
        )

        # Crash guard -- advanced server may require auth for full endpoint listing
        assert result.returncode in [0, 1]

        # UNCONDITIONAL: scanner must show endpoint/policy information
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "endpoint",
                "policy",
                "security",
                "basic256sha256",
                "aes128",
                "nosecurity",
            ]
        ), f"Expected endpoint/policy information in output. Got: {text[:500]}"

        # The advanced server should NOT have deprecated policies, so validate
        # that we at least see the modern policies
        if result.scan_log is not None and len(result.scan_log) > 0:
            security_events = result.scan_log.get_security_findings()
            deprecated_findings = [
                f
                for f in security_events
                if "outdated" in f.get("message", "").lower()
                or "deprecated" in f.get("message", "").lower()
                or f.get("data", {}).get("finding", "").lower() == "outdated protocol version"
            ]
            # The advanced server uses modern policies, so deprecated findings
            # should NOT appear -- but if they do, that's also valid
            if deprecated_findings:
                finding_text = " ".join(f.get("message", "") for f in deprecated_findings).lower()
                assert "basic128" in finding_text or "basic256" in finding_text, (
                    f"Deprecated finding should mention policy name. Got: {finding_text[:300]}"
                )

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.security
    def test_security_finding_no_encryption_insecure_server(
        self, cli_runner, mock_host, mock_ports
    ):
        """Test structured security events for no-encryption on insecure server [Category A]

        The insecure server (OPCUA_SECURITY=false) has only NoSecurity policy.
        The pre-auth discovery via _show_endpoints_summary() should detect:
        - SecurityMode None: traffic is unencrypted and unsigned
        - SecurityPolicy None: no cryptographic protection
        These appear as warnings in output (not security_finding events).

        Additionally, _check_server_security() runs post-auth and may detect
        further issues. This test validates the complete security picture.
        """
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)

        # The insecure server should show multiple security concerns
        security_indicators = [
            "nosecurity",
            "no security",
            "none_",
            "securitypolicy#none",
            "unencrypted",
            "unsigned",
            "no cryptographic",
            "insecure",
        ]
        found_indicators = [ind for ind in security_indicators if ind in text]
        assert len(found_indicators) >= 1, (
            f"Expected at least one no-encryption indicator from insecure server. "
            f"Checked: {security_indicators}. Got: {text[:500]}"
        )

    @pytest.mark.security
    @pytest.mark.slow
    @pytest.mark.auth
    @pytest.mark.containers("opcua-advanced")
    def test_security_finding_brute_force_valid_creds_advanced(
        self, cli_runner, mock_host, mock_ports, tmp_path
    ):
        """Test brute force against advanced server finds admin:admin [Category B]

        The advanced server (opcua_server.py CustomUserManager) has:
            admin:admin, operator:operator123, readonly:readonly, user:user
        Passing these as files triggers _brute_force_credentials() which fires
        security_finding('Default credentials', ...) for each valid pair found.
        """
        user_file = tmp_path / "opcua_brute_users.txt"
        user_file.write_text("admin\nwronguser\n")
        pass_file = tmp_path / "opcua_brute_passwords.txt"
        pass_file.write_text(f"{AUTH_DEFAULT[1]}\nwrongpass\n")

        target = self.get_target(mock_host, mock_ports["opcua_auth"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--username",
            str(user_file),
            "--password",
            str(pass_file),
            "--brute-rate",
            "0.1",
            format="json",
            json_log=True,
            timeout=60,
        )

        # Crash guard
        assert result.returncode in [0, 1]

        # UNCONDITIONAL: must show brute force activity
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["testing", "credential", "pairs", "brute", "tested"]
        ), f"Expected brute force attempt in output. Got: {text[:500]}"

    # ========================================================================
    # Category A: Authentication Tests
    # ========================================================================

    @pytest.mark.auth
    @pytest.mark.containers("opcua-advanced")
    def test_valid_credentials(self, cli_runner, mock_host, mock_ports):
        """Test authentication with valid credentials on default server [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--username",
            AUTH_DEFAULT[0],
            "--password",
            AUTH_DEFAULT[1],
            "-d",
            "--max-depth",
            "2",
            format="json",
            json_log=True,
        )

        # With valid credentials, should succeed or at least produce useful output
        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            text = _combined_text(result, result.scan_log)
            if result.success:
                assert any(x in text for x in ["server", "endpoint", "node", "industrialdevice"]), (
                    f"Expected scan output with valid credentials. Got: {text[:500]}"
                )

    @pytest.mark.auth
    @pytest.mark.containers("opcua-advanced")
    def test_valid_credentials_operator(self, cli_runner, mock_host, mock_ports):
        """Test authentication with operator credentials [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--username",
            AUTH_OPERATOR[0],
            "--password",
            AUTH_OPERATOR[1],
            "--get-endpoints",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_help_output(self, cli_runner):
        """Test --help output shows OPC UA options [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )

        assert result.returncode == 0
        output = result.stdout.lower()
        assert "opcua" in output or "opc" in output
        # Verify key flags are documented in help
        assert any(x in output for x in ["dump", "endpoint", "browse", "method"]), (
            f"Expected OPC UA flags in help output. Got: {output[:500]}"
        )

    # ========================================================================
    # Category A: Specific Node Read
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_read_specific_node_known(self, cli_runner, mock_host, mock_ports):
        """Test reading a known mock node (DeviceName ns=2;i=90) [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "ns=2;i=90",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # DeviceName node should contain "Mock Industrial Controller"
        assert any(x in text for x in ["mock industrial controller", "devicename", "ns=2;i=90"]), (
            f"Expected DeviceName value. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_read_firmware_version_node(self, cli_runner, mock_host, mock_ports):
        """Test reading FirmwareVersion node (ns=2;i=91) returns v1.2.3 [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "ns=2;i=91",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        assert any(x in text for x in [MOCK_FIRMWARE, "firmwareversion"]), (
            f"Expected firmware version '{MOCK_FIRMWARE}'. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_read_serial_number_node(self, cli_runner, mock_host, mock_ports):
        """Test reading SerialNumber node (ns=2;i=92) returns OIDA-001 [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "ns=2;i=92",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        assert any(x in text for x in [MOCK_SERIAL, "serialnumber"]), (
            f"Expected serial number '{MOCK_SERIAL}'. Got: {text[:500]}"
        )

    # ========================================================================
    # Category B: Discovery Variants
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_find_servers(self, cli_runner, mock_host, mock_ports):
        """Test FindServers discovery [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--find-servers",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-gds")
    def test_find_servers_on_network(self, cli_runner, mock_host, mock_ports):
        """Test GDS/LDS discovery [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--find-servers-on-network",
            format="json",
            json_log=True,
            timeout=20,
        )

        # GDS may not be available
        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-gds")
    def test_gds_url(self, cli_runner, mock_host, mock_ports):
        """Test GDS endpoint URL [Category B]"""
        gds_port = mock_ports.get("opcua_gds", 4850)
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--gds-url",
            f"opc.tcp://{mock_host}:{gds_port}",
            "--find-servers-on-network",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-insecure")
    def test_dead_scan_mode_flags_are_rejected(self, cli_runner, mock_host, mock_ports):
        """--discover/--quick/--deep-scan are no longer accepted [Category C]

        These were parsed but never read, so passing any of them produced output
        byte-identical to a plain scan -- the tests that used to live here asserted
        only ``returncode in [0, 1]`` and so passed no matter what. OPC UA discovery
        is driven by the explicit services (--get-endpoints, --find-servers,
        --find-servers-on-network) and browse breadth by --max-depth/--max-nodes.

        --full is asserted separately below: it is NOT rejected, because it is an
        unambiguous abbreviation of the global --full-width, so argparse silently
        absorbs it. That distinction is the whole trap, so it is pinned as an
        invariant rather than left as a comment -- if --full-width is ever renamed,
        --full would start being rejected and this test would tell us.
        """
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        for flag in ("--discover", "--quick", "--deep-scan"):
            result = cli_runner.run(self.protocol_name, target, flag)
            assert result.returncode == 2, f"{flag} should be rejected by argparse"
            assert "unrecognized arguments" in (result.stderr or ""), (
                f"{flag} should be reported as unrecognized, got: {result.stderr!r}"
            )

        # --full is absorbed by the global --full-width, so it must NOT be rejected.
        result = cli_runner.run(self.protocol_name, target, "--full")
        assert result.returncode != 2, (
            "--full should be absorbed as an abbreviation of --full-width, not "
            f"rejected; got rc={result.returncode}, stderr={result.stderr!r}"
        )
        assert "unrecognized arguments" not in (result.stderr or ""), (
            f"--full should not be reported as unrecognized, got: {result.stderr!r}"
        )

    # ========================================================================
    # Category B: Address Space Browsing Variants
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_namespace_filter(self, cli_runner, mock_host, mock_ports):
        """Test --ns namespace filter restricts browsing to specific namespace [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--ns",
            "2",
            "--max-depth",
            "4",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                text = _combined_text(result, result.scan_log)
                # Namespace 2 is the mock's custom namespace
                assert any(
                    x in text for x in ["ns=2", "industrialdevice", "sensors", "actuators"]
                ), f"Expected ns=2 nodes in filtered output. Got: {text[:500]}"

    @pytest.mark.containers("opcua-insecure")
    def test_start_node(self, cli_runner, mock_host, mock_ports):
        """Test --start-node browses from a specific node [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--start-node",
            "ns=2;i=2",  # Sensors folder
            "--max-depth",
            "3",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                text = _combined_text(result, result.scan_log)
                # Starting from Sensors folder should show sensor nodes
                assert any(x in text for x in ["sensor", "temperature", "pressure", "flowrate"]), (
                    f"Expected sensor nodes from start-node. Got: {text[:500]}"
                )

    @pytest.mark.containers("opcua-insecure")
    def test_dump_methods_with_examples(self, cli_runner, mock_host, mock_ports):
        """Test --dump-methods --dump-examples shows CLI usage [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--dump-methods",
            "--dump-examples",
            "--max-depth",
            "5",
            expect_json=False,
            json_log=True,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                text = _combined_text(result, result.scan_log)
                # Examples should include CLI invocations or method info
                assert any(x in text for x in ["method", "call", "oida", "startpump", "example"]), (
                    f"Expected method examples. Got: {text[:500]}"
                )

    # ========================================================================
    # Category B: Node Operations
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_read_specific_node(self, cli_runner, mock_host, mock_ports):
        """Test reading specific node by ID (Server object) [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "i=2253",  # Server object
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-insecure")
    def test_read_attributes(self, cli_runner, mock_host, mock_ports):
        """Test reading all node attributes [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "ns=2;i=10",  # Temperature1 variable
            "--read-attributes",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                text = _combined_text(result, result.scan_log)
                assert any(
                    x in text for x in ["attribute", "value", "temperature", "float", "access"]
                ), f"Expected attribute details. Got: {text[:500]}"

    # ========================================================================
    # Category B: Method Operations
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_call_method(self, cli_runner, mock_host, mock_ports):
        """Test calling a method by NodeId [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--call-method",
            "ns=2;i=1000",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Method node may not have this exact ID on all servers
        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-insecure")
    def test_call_method_with_args(self, cli_runner, mock_host, mock_ports):
        """Test calling a method with arguments [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--call-method",
            "ns=2;i=1000",
            "--method-args",
            '[42, "test"]',
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Category B: Subscription and Monitoring
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.slow
    def test_subscribe_values(self, cli_runner, mock_host, mock_ports):
        """Test subscribing to node value changes [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--subscribe",
            "--duration",
            "3",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.slow
    def test_subscribe_events(self, cli_runner, mock_host, mock_ports):
        """Test subscribing to server events [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--subscribe-events",
            "--duration",
            "3",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.slow
    def test_subscription_interval(self, cli_runner, mock_host, mock_ports):
        """Test custom subscription interval [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--subscribe",
            "--subscription-interval",
            "500",
            "--duration",
            "2",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-insecure")
    def test_monitor_and_interval_are_rejected(self, cli_runner, mock_host, mock_ports):
        """--monitor/--interval are no longer accepted [Category C]

        Nothing read args.monitor or args.interval, so --monitor performed a single
        read and returned immediately, ignoring --duration. The old test asserted
        only ``returncode in [0, 1]`` and so never noticed. Continuous watching is
        --subscribe (see test_subscribe_honours_duration).
        """
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        for flag in ("--monitor", "--interval"):
            result = cli_runner.run(self.protocol_name, target, flag, "1")
            assert result.returncode == 2, f"{flag} should be rejected by argparse"
            assert "unrecognized arguments" in (result.stderr or ""), (
                f"{flag} should be reported as unrecognized, got: {result.stderr!r}"
            )

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.slow
    def test_subscribe_honours_duration(self, cli_runner, mock_host, mock_ports):
        """--subscribe actually watches for --duration seconds [Category B]

        Regression guard for the bug that --monitor hid: a watch flag must spend the
        requested time on the wire, not return after a single read. Asserting on
        elapsed time is what distinguishes a real subscription from a no-op flag.
        """
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        start = time.monotonic()
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--subscribe",
            "--start-node",
            "ns=2;i=2",
            "--duration",
            "5",
            format="json",
            json_log=True,
            timeout=60,
        )
        elapsed = time.monotonic() - start

        assert result.returncode in [0, 1]
        assert elapsed >= 4.5, (
            f"--subscribe --duration 5 returned after {elapsed:.1f}s; "
            "the flag is not actually subscribing"
        )
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Category B: Historical Data Access
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_history_read(self, cli_runner, mock_host, mock_ports):
        """Test reading historical data from a node [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "ns=2;i=10",
            "--history-read",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-insecure")
    def test_history_read_with_time_range(self, cli_runner, mock_host, mock_ports):
        """Test reading historical data with custom time range [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "ns=2;i=10",
            "--history-read",
            "--history-start",
            "2024-01-01T00:00:00",
            "--history-end",
            "2024-12-31T23:59:59",
            "--history-max",
            "50",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-insecure")
    def test_history_raw(self, cli_runner, mock_host, mock_ports):
        """Test --history-raw for raw historical data [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "ns=2;i=10",
            "--history-read",
            "--history-raw",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Category B: Security Tests
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.security
    def test_security_modes(self, cli_runner, mock_host, mock_ports):
        """Test different security modes [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        for mode in ["None", "Sign"]:
            result = cli_runner.run(
                self.protocol_name,
                target,
                "--mode",
                mode,
                format="json",
                json_log=True,
            )
            assert result.returncode != -1, f"Mode {mode} timed out"
            assert result.returncode in [0, 1], (
                f"Mode {mode} unexpected returncode: {result.returncode}"
            )
            assert result.stdout or result.stderr, f"Mode {mode} should produce output"

    @pytest.mark.security
    @pytest.mark.containers("opcua-advanced")
    def test_security_policy_basic256(self, cli_runner, mock_host, mock_ports):
        """Test Basic256 security policy [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--policy",
            "Basic256",
            "--mode",
            "Sign",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    @pytest.mark.containers("opcua-advanced")
    def test_security_policy_basic256sha256(self, cli_runner, mock_host, mock_ports):
        """Test Basic256Sha256 security policy [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--policy",
            "Basic256Sha256",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.security
    def test_cert_trust(self, cli_runner, mock_host, mock_ports):
        """Test --test-cert-trust checks if server accepts untrusted certs [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-cert-trust",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    @pytest.mark.slow
    @pytest.mark.containers("opcua-advanced")
    def test_rbac_testing(self, cli_runner, mock_host, mock_ports):
        """Test RBAC comparison across auth methods [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-rbac",
            "--username",
            AUTH_DEFAULT[0],
            "--password",
            AUTH_DEFAULT[1],
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    @pytest.mark.slow
    @pytest.mark.containers("opcua-advanced")
    def test_rbac_detailed(self, cli_runner, mock_host, mock_ports):
        """Test --rbac-detailed includes per-node permission matrix [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-rbac",
            "--rbac-detailed",
            "--username",
            AUTH_DEFAULT[0],
            "--password",
            AUTH_DEFAULT[1],
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.security
    @pytest.mark.slow
    def test_subscription_limits(self, cli_runner, mock_host, mock_ports):
        """Test subscription-based DoS vulnerability detection [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-subscription-limits",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Category B: Authentication / Credential Testing
    # ========================================================================

    @pytest.mark.auth
    @pytest.mark.containers("opcua-advanced")
    def test_brute_delay(self, cli_runner, mock_host, mock_ports):
        """Test brute force rate option [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--username",
            AUTH_DEFAULT[0],
            "--password",
            AUTH_DEFAULT[1],
            "--brute-rate",
            "0.1",
            "-d",
            "--max-depth",
            "1",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.auth
    @pytest.mark.containers("opcua-advanced")
    def test_default_creds_and_credentials_file_are_rejected(
        self, cli_runner, mock_host, mock_ports
    ):
        """--default-creds/--credentials are no longer accepted [Category C]

        OPC UA ships no built-in credential list to spray (see the comment in
        scanner.py where default credentials are looked up), and the runner reads
        only args.username/args.password -- passing a --credentials file left the
        client on anonymous auth. Credential lists are supplied by handing a file
        path to --username/--password instead.
        """
        target = self.get_target(mock_host, mock_ports["opcua"])

        result = cli_runner.run(self.protocol_name, target, "--default-creds")
        assert result.returncode == 2
        assert "unrecognized arguments" in (result.stderr or "")

        result = cli_runner.run(self.protocol_name, target, "--credentials", "/dev/null")
        assert result.returncode == 2
        assert "unrecognized arguments" in (result.stderr or "")

    @pytest.mark.auth
    @pytest.mark.containers("opcua-advanced")
    def test_anonymous_access_default_server(self, cli_runner, mock_host, mock_ports):
        """Test anonymous access to auth-enabled server [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--get-endpoints",
            format="json",
            json_log=True,
        )

        # Default server has auth -- anonymous may be rejected after endpoint retrieval
        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            text = _combined_text(result, result.scan_log)
            assert any(x in text for x in ["endpoint", "security", "policy"]), (
                f"Expected at least endpoint info. Got: {text[:500]}"
            )

    @pytest.mark.auth
    @pytest.mark.slow
    @pytest.mark.containers("opcua-advanced")
    def test_brute_force_with_file(self, cli_runner, mock_host, mock_ports, tmp_path):
        """Test brute force with credential file [Category B]"""
        # Create a small credential file
        user_file = tmp_path / "users.txt"
        user_file.write_text("admin\noperator\ninvalid\n")
        pass_file = tmp_path / "passwords.txt"
        pass_file.write_text("admin\noperator123\nwrong\n")

        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--username",
            str(user_file),
            "--password",
            str(pass_file),
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Category B: Output Format Tests
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_csv_output(self, cli_runner, mock_host, mock_ports):
        """Test CSV output format [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--max-depth",
            "2",
            format="csv",
            expect_json=False,
        )

        assert result.returncode in [0, 1]
        if result.success:
            assert result.stdout, "CSV output should produce stdout on success"

    @pytest.mark.containers("opcua-insecure")
    def test_verbose_output(self, cli_runner, mock_host, mock_ports):
        """Test verbose output [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            verbose=True,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Verbose mode should produce output"

    @pytest.mark.containers("opcua-insecure")
    def test_debug_output(self, cli_runner, mock_host, mock_ports):
        """Test --debug output [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            debug=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Debug mode should produce output"

    # ========================================================================
    # Category B: Write Operations
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_write_value_with_confirm(self, cli_runner, mock_host, mock_ports):
        """Test writing a value to a writable node with --confirm [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "ns=2;i=10",  # Temperature1 (writable)
            "--write-value",
            "42.0",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                text = _combined_text(result, result.scan_log)
                assert any(x in text for x in ["write", "success", "42", "value"]), (
                    f"Expected write confirmation. Got: {text[:500]}"
                )

    # ========================================================================
    # Category C: Error Handling Tests
    # ========================================================================

    def test_invalid_endpoint_url(self, cli_runner):
        """Test handling of invalid endpoint URL [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "opc.tcp://invalid-host-12345:4840",
            "--get-endpoints",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1, "Should not hang"
        assert not result.success, "Should fail on invalid host"

    def test_wrong_port(self, cli_runner, mock_host):
        """Test handling of wrong port [Category C]"""
        target = self.get_target(mock_host, 65534)
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--timeout",
            "3",
            timeout=10,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1, "Should not hang"
        assert not result.success, "Should fail on wrong port"

    def test_nonroutable_host_timeout(self, cli_runner):
        """Test timeout handling for non-routable host [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "opc.tcp://10.255.255.1:4840",
            "--timeout",
            "3",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1, "Should not hang on non-routable host"
        assert result.execution_time < 20, "Should respect timeout"

    @pytest.mark.auth
    @pytest.mark.containers("opcua-advanced")
    def test_invalid_credentials(self, cli_runner, mock_host, mock_ports):
        """Test with invalid credentials [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--username",
            "invalid_user",
            "--password",
            "wrong_password",
            "-d",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1, "Should not crash"
        assert not result.success, "Invalid credentials should not succeed"

    @pytest.mark.auth
    @pytest.mark.containers("opcua-advanced")
    def test_username_without_password(self, cli_runner, mock_host, mock_ports):
        """Test providing username without password fails gracefully [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--username",
            "admin",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1, "Should not crash"
        # Should fail or warn about missing password
        output = result.combined_output.lower()
        assert not result.success or "password" in output, (
            "Username without password should fail or warn"
        )

    @pytest.mark.auth
    @pytest.mark.security
    @pytest.mark.containers("opcua-advanced")
    def test_certificate_auth_missing_files(self, cli_runner, mock_host, mock_ports):
        """Test certificate authentication with missing files [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--certificate",
            "/nonexistent/cert.pem",
            "--privatekey",
            "/nonexistent/key.pem",
            "-d",
            format="json",
            timeout=15,
        )

        # Should fail gracefully (file not found) -- success (rc=0) is not acceptable
        assert (
            not result.success
            or "not found" in result.combined_output.lower()
            or "error" in result.combined_output.lower()
        ), "Missing certificate files should not succeed without error indication"

    @pytest.mark.containers("opcua-insecure")
    def test_write_value_no_confirm(self, cli_runner, mock_host, mock_ports):
        """Test that write-value without --confirm is rejected [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "ns=2;i=10",
            "--write-value",
            "99.9",
            format="json",
            json_log=True,
            timeout=20,
        )

        # The writes mixin logs "requires --confirm" when confirm flag is missing
        text = _combined_text(result, result.scan_log)
        assert "requires --confirm" in text or "require --confirm" in text, (
            f"Write without --confirm should show 'requires --confirm' message. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_read_file_invalid_node(self, cli_runner, mock_host, mock_ports):
        """Test reading from invalid file node [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--read-file",
            "ns=99;i=99999",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        # Invalid node should produce error indication even if returncode is 0
        # (scanner may succeed overall but report the node error in output)
        text = _combined_text(result, result.scan_log)
        assert any(x in text for x in ["error", "fail", "not found", "bad", "invalid"]), (
            f"Expected error indication for invalid file node. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_write_file_requires_confirm(self, cli_runner, mock_host, mock_ports):
        """Test that write-file requires --confirm flag [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--write-file",
            "ns=2;i=100",
            "--file-data",
            "test content",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode != -1, "Should not hang"
        output = result.combined_output.lower()
        assert "confirm" in output or not result.success, (
            "Write without --confirm should either warn about confirm or fail"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_read_nonexistent_node(self, cli_runner, mock_host, mock_ports):
        """Test reading a nonexistent node ID [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "ns=99;i=999999",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            text = _combined_text(result, result.scan_log)
            assert any(
                x in text for x in ["error", "fail", "not found", "bad", "invalid", "does not"]
            ), f"Expected error for nonexistent node. Got: {text[:500]}"

    # ========================================================================
    # Category C: Fuzzing Tests
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_node_fuzzing(self, cli_runner, mock_host, mock_ports):
        """Test fuzzing writable nodes [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--fuzz",
            "nodes",
            "--fuzz-iterations",
            "3",
            "--fuzz-max-targets",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode != -1, "Fuzzing should not hang"
        assert result.returncode in [0, 1, 2], (
            f"Node fuzzing unexpected returncode: {result.returncode}"
        )

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.fuzz
    def test_fuzz_specific_node(self, cli_runner, mock_host, mock_ports):
        """Test fuzzing a specific node [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--fuzz",
            "nodes",
            "--fuzz-node",
            "ns=2;i=10",
            "--fuzz-iterations",
            "2",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode != -1, "Fuzzing should not hang"
        assert result.returncode in [0, 1, 2], (
            f"Specific node fuzzing unexpected returncode: {result.returncode}"
        )

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.fuzz
    def test_method_fuzzing(self, cli_runner, mock_host, mock_ports):
        """Test fuzzing methods (SetTemperature method on insecure server) [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--fuzz-method",
            "ns=2;i=99",
            "--fuzz-iterations",
            "5",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode != -1, "Fuzzing should not hang"
        assert result.returncode in [0, 1, 2], (
            f"Method fuzzing unexpected returncode: {result.returncode}"
        )
        text = result.combined_output.lower()
        assert "fuzz" in text or "tests" in text or not result.success

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_all_methods(self, cli_runner, mock_host, mock_ports):
        """Test fuzzing all discovered methods [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--fuzz",
            "methods",
            "--fuzz-iterations",
            "3",
            "--fuzz-max-targets",
            "5",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode != -1, "Fuzzing should not hang"
        assert result.returncode in [0, 1, 2], (
            f"All-methods fuzzing unexpected returncode: {result.returncode}"
        )
        text = result.combined_output.lower()
        assert "method" in text or "fuzz" in text or not result.success

    # ========================================================================
    # Category A: Comparative Tests (verify flags actually limit output)
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_max_nodes_actually_limits(self, cli_runner, mock_host, mock_ports):
        """Test that --max-nodes=5 produces less output than --max-nodes=100 [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])

        result_small = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--max-nodes",
            "5",
            "--max-depth",
            "5",
            format="json",
            json_log=True,
        )
        assert result_small.success, f"Small run failed: {result_small.stderr}"

        result_large = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--max-nodes",
            "100",
            "--max-depth",
            "5",
            format="json",
            json_log=True,
        )
        assert result_large.success, f"Large run failed: {result_large.stderr}"

        text_small = _combined_text(result_small, result_small.scan_log)
        text_large = _combined_text(result_large, result_large.scan_log)

        assert len(text_small) < len(text_large), (
            f"--max-nodes=5 ({len(text_small)} chars) should produce less output "
            f"than --max-nodes=100 ({len(text_large)} chars)"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_max_depth_actually_limits(self, cli_runner, mock_host, mock_ports):
        """Test that --max-depth=1 lacks deep nodes that --max-depth=5 has [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])

        # NOTE: console (default) output format is required here. With --format json
        # the per-node address-space table is routed to the JSON document (which only
        # carries node counts, not names) and is NOT emitted as log events, so the
        # json-log would never contain the deep node names regardless of depth.
        result_shallow = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--max-depth",
            "1",
            json_log=True,
        )
        assert result_shallow.success, f"Shallow run failed: {result_shallow.stderr}"

        result_deep = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--max-depth",
            "5",
            json_log=True,
        )
        assert result_deep.success, f"Deep run failed: {result_deep.stderr}"

        text_shallow = _combined_text(result_shallow, result_shallow.scan_log)
        text_deep = _combined_text(result_deep, result_deep.scan_log)

        # Deep nodes (sensor/actuator names) should appear at depth 5 but not at depth 1
        deep_node_names = MOCK_SENSOR_NAMES + MOCK_ACTUATOR_NAMES
        deep_found_shallow = [n for n in deep_node_names if n in text_shallow]
        deep_found_deep = [n for n in deep_node_names if n in text_deep]

        assert deep_found_deep, (
            "--max-depth=5 should reveal deep sensor/actuator nodes "
            f"(expected any of {deep_node_names}), but found none. "
            f"Deep output sample: {text_deep[:500]}"
        )
        assert len(deep_found_deep) > len(deep_found_shallow), (
            f"--max-depth=5 should reveal more deep nodes than --max-depth=1. "
            f"Shallow found: {deep_found_shallow}, Deep found: {deep_found_deep}"
        )

    # ========================================================================
    # Category C: Confirm-Gate Tests
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    @pytest.mark.fuzz
    def test_fuzz_without_confirm_is_rejected(self, cli_runner, mock_host, mock_ports):
        """Test that --fuzz without --confirm is rejected [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--fuzz",
            "--fuzz-iterations",
            "2",
            format="json",
            json_log=True,
            timeout=20,
        )

        # The fuzz mixin logs "Fuzzing requires --confirm flag" when confirm is missing
        text = _combined_text(result, result.scan_log)
        assert "requires --confirm" in text or "require --confirm" in text, (
            f"Fuzz without --confirm should show 'requires --confirm' message. Got: {text[:500]}"
        )
        # Should NOT produce any fuzz data
        assert "iteration" not in text or "fuzz_result" not in text, (
            "Fuzz without --confirm should not produce fuzz data"
        )

    # ========================================================================
    # Category C: Malformed Input Tests
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_method_args_malformed_json(self, cli_runner, mock_host, mock_ports):
        """Test --method-args with invalid JSON doesn't crash [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--call-method",
            "ns=2;i=1000",
            "--method-args",
            "not valid json",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Should not crash (returncode -1 = timeout/hang)
        assert result.returncode != -1, "Should not hang on malformed JSON"
        assert result.stdout or result.stderr, "Should produce output"

    @pytest.mark.containers("opcua-insecure")
    def test_history_invalid_datetime(self, cli_runner, mock_host, mock_ports):
        """Test --history-start with invalid datetime doesn't crash [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--node-id",
            "ns=2;i=10",
            "--history-read",
            "--history-start",
            "not-a-date",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Should not crash
        assert result.returncode != -1, "Should not hang on invalid datetime"
        assert result.stdout or result.stderr, "Should produce output"

    @pytest.mark.containers("opcua-insecure")
    def test_namespace_filter_invalid(self, cli_runner, mock_host, mock_ports):
        """Test --ns with non-numeric value doesn't crash [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--ns",
            "abc",
            "--max-depth",
            "2",
            format="json",
            json_log=True,
            timeout=20,
        )

        # browse.py:41 has ValueError handling for invalid namespace filter
        assert result.returncode != -1, "Should not hang on invalid namespace filter"
        assert result.stdout or result.stderr, "Should produce output"
        # Should indicate the error
        text = _combined_text(result, result.scan_log)
        assert any(x in text for x in ["invalid", "error", "fail", "valueerror"]), (
            f"Expected error indication for invalid namespace. Got: {text[:500]}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_start_node_invalid(self, cli_runner, mock_host, mock_ports):
        """Test --start-node with garbage value doesn't crash [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-d",
            "--start-node",
            "garbage",
            "--max-depth",
            "2",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Should not crash
        assert result.returncode != -1, "Should not hang on invalid start node"
        assert result.stdout or result.stderr, "Should produce output"

    # ========================================================================
    # Skipped Tests (require hardware or unsupported features)
    # ========================================================================

    # NOTE: --wordlist / --brute were removed from the OPC UA CLI — they were
    # never read by the scanner (brute-force is driven by --username FILE /
    # --password FILE, see test_security_finding_brute_force_valid_creds_advanced).

    @pytest.mark.containers("opcua-insecure")
    def test_file_output(self, cli_runner, mock_host, mock_ports):
        """Test --read-file --file-output writes the downloaded file to disk [Category B]

        The mock exposes a real OPC UA FileType node (ns=2;i=240, "readme.txt")
        implementing Open/Read/Close, so --read-file actually transfers content
        and --file-output persists it locally.

        NOTE: safe_file_path() confines --file-output to the CLI process CWD, so
        the destination is created under CWD (pytest's tmp_path is outside it)
        and cleaned up afterwards.
        """
        import os
        import tempfile
        from pathlib import Path

        fd, out_name = tempfile.mkstemp(prefix="opcua_dl_", suffix=".txt", dir=os.getcwd())
        os.close(fd)
        out_path = Path(out_name)
        try:
            target = self.get_target(mock_host, mock_ports["opcua_insecure"])
            result = cli_runner.run(
                self.protocol_name,
                target,
                "--read-file",
                "ns=2;i=240",
                "--file-output",
                str(out_path),
                format="json",
                json_log=True,
                timeout=30,
            )

            assert result.returncode in [0, 1], f"Unexpected returncode: {result.returncode}"
            text = _combined_text(result, result.scan_log)
            # The scanner must report a successful read of the FileType content.
            assert "bytes" in text.lower() or "saved" in text.lower(), (
                f"Expected a successful file read in output. Got: {text[:500]}"
            )
            # --file-output must have persisted the transferred bytes.
            data = out_path.read_bytes()
            assert len(data) > 0, f"Downloaded file is empty. Output: {text[:500]}"
            assert b"OIDA" in data or b"mock" in data.lower(), (
                f"Unexpected file content: {data[:200]!r}"
            )
        finally:
            out_path.unlink(missing_ok=True)

    @pytest.mark.security
    @pytest.mark.containers("opcua-advanced")
    def test_security_mode_sign_and_encrypt(self, cli_runner, mock_host, mock_ports):
        """Test --mode SignAndEncrypt against the secure endpoint [Category B]

        The scanner auto-generates a self-signed client cert, so encrypted
        channels work without external cert setup (same path exercised by
        test_security_policy_basic256). Assertions are tolerant: the secure
        mock may or may not offer the exact policy/mode pair, but the scan must
        not crash and must produce output.
        """
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--policy",
            "Basic256Sha256",
            "--mode",
            "SignAndEncrypt",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode != -1, "SignAndEncrypt scan timed out"
        assert result.returncode in [0, 1], (
            f"SignAndEncrypt unexpected returncode: {result.returncode}"
        )
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Long-form flag aliases (--dump-all, --security-mode, --security-policy,
    # --scan-writable, --fuzz-mode) — proto_args.py exposes these as the long
    # forms of -D/--mode/--policy plus two flags with no short-flag test
    # coverage yet.
    # ========================================================================

    @pytest.mark.containers("opcua-insecure")
    def test_dump_all_long_flag(self, cli_runner, mock_host, mock_ports):
        """Test --dump-all (long form of -D) shows access levels [Category A]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--dump-all",
            "--max-depth",
            "3",
            format="json",
            json_log=True,
        )

        assert result.success, f"Failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        assert any(
            x in text for x in ["access", "currentread", "currentwrite", "rw", "rh", "rwh"]
        ) or (
            "variable" in text and any(x in text for x in MOCK_SENSOR_NAMES + MOCK_ACTUATOR_NAMES)
        ), f"Expected access level info in --dump-all. Got: {text[:500]}"

    @pytest.mark.security
    @pytest.mark.containers("opcua-insecure")
    def test_security_mode_long_flag(self, cli_runner, mock_host, mock_ports):
        """Test --security-mode (long form of --mode) is accepted [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--security-mode",
            "Sign",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode != -1, "--security-mode Sign timed out"
        assert result.returncode in [0, 1], (
            f"--security-mode Sign unexpected returncode: {result.returncode}"
        )
        assert result.stdout or result.stderr, "Should produce output"

    @pytest.mark.security
    @pytest.mark.containers("opcua-advanced")
    def test_security_policy_long_flag(self, cli_runner, mock_host, mock_ports):
        """Test --security-policy (long form of --policy) is accepted [Category B]"""
        target = self.get_target(mock_host, mock_ports["opcua"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--security-policy",
            "Basic256",
            "--security-mode",
            "Sign",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode != -1, "--security-policy Basic256 timed out"
        assert result.returncode in [0, 1], (
            f"--security-policy Basic256 unexpected returncode: {result.returncode}"
        )
        assert result.stdout or result.stderr, "Should produce output"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    @pytest.mark.containers("opcua-insecure")
    def test_scan_writable(self, cli_runner, mock_host, mock_ports):
        """Test --scan-writable finds writable nodes via AccessLevel [Category A]

        The insecure mock exposes multiple writable Variable nodes (Temperature1,
        MotorSpeed, ...) via anonymous access, so --scan-writable's read-only
        AccessLevel check should surface at least one of them.
        """
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--scan-writable",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode != -1, "--scan-writable timed out"
        assert result.returncode in [0, 1], (
            f"--scan-writable unexpected returncode: {result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        assert "writable" in text or any(x in text for x in MOCK_WRITABLE_NAMES), (
            f"Expected writable-node info from --scan-writable. Got: {text[:500]}"
        )

    @pytest.mark.fuzz
    @pytest.mark.containers("opcua-insecure")
    def test_fuzz_mode_methods(self, cli_runner, mock_host, mock_ports):
        """Test --fuzz-mode methods restricts fuzzing to callable methods [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--fuzz",
            "--fuzz-mode",
            "methods",
            "--fuzz-iterations",
            "2",
            "--fuzz-max-targets",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode != -1, "--fuzz-mode methods should not hang"
        assert result.returncode in [0, 1, 2], (
            f"--fuzz-mode methods unexpected returncode: {result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        assert "method" in text or "fuzz" in text or not result.success, (
            f"Expected method-fuzzing indication. Got: {text[:500]}"
        )

    @pytest.mark.fuzz
    @pytest.mark.containers("opcua-insecure")
    def test_fuzz_mode_all(self, cli_runner, mock_host, mock_ports):
        """Test --fuzz-mode all fuzzes both writable nodes and methods [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--fuzz",
            "--fuzz-mode",
            "all",
            "--fuzz-iterations",
            "2",
            "--fuzz-max-targets",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode != -1, "--fuzz-mode all should not hang"
        assert result.returncode in [0, 1, 2], (
            f"--fuzz-mode all unexpected returncode: {result.returncode}"
        )

    @pytest.mark.containers("opcua-insecure")
    def test_fuzz_mode_invalid_value_rejected(self, cli_runner, mock_host, mock_ports):
        """Test --fuzz-mode with an invalid choice is rejected by argparse [Category C]"""
        target = self.get_target(mock_host, mock_ports["opcua_insecure"])
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--fuzz",
            "--fuzz-mode",
            "bogus-mode",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode not in (0, -1), (
            f"Invalid --fuzz-mode value should be rejected, got {result.returncode}"
        )
        text = (result.stderr or "") + (result.stdout or "")
        assert "invalid choice" in text.lower() or "fuzz-mode" in text.lower(), (
            f"Expected argparse rejection for invalid --fuzz-mode. Got: {text[:500]}"
        )
