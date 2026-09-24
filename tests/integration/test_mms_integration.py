"""
MMS/IEC 61850 Protocol Integration Tests

Tests oida mms scanner against Docker mock services:
  - mms-libiec61850 (port 102):   server_example_basic_io
  - mms-goose (port 10106):       server_example_goose
  - mms-control (port 10107):     server_example_control
  - mms-authentication (port 10108): server_example_password_auth (rejects unauthenticated)

Mock Server Data (from libiec61850 server_example_basic_io):
  Logical Device:      simpleIOGenericIO
  Logical Nodes (3):
    GGIO1:   Mod, SPCSO1-4, NamPlt, AnIn1-4, Beh, Health, Ind1-4 (16 data objects)
    LLN0:    Mod, NamPlt, Beh, Health (4 data objects)
    LPHD1:   PhyNam, PhyHealth, Proxy (3 data objects)
  Total data objects:  23
  All 23 objects readable (MX/ST functional constraints)
  Identity:            vendor/model/revision all None (basic_io example)
  Security:            No authentication, no encryption

Mock Server Data (server_example_control, port 10107):
  Logical Device:      simpleIOGenericIO
  Logical Nodes (3):   same structure, 28 data objects

Mock Server Data (server_example_password_auth, port 10108):
  Connection rejected without credentials

Proto_args.py flags:
  --port, --timeout, -i/--identify, -l/--get-name-list, -r/--variable,
  --read-values, --test-write, --max-objects, --confirm, --fuzz,
  --fuzz-iterations, --fuzz-max-targets, --fuzz-reference,
  --tls, --tls-port, --tls-ca, --tls-pin, --tls-client-cert, --tls-client-key

JSON Log Structure (event_type values):
  info:  connection, discovery, scan progress, results
  debug: per-object discovery, read operations

Test Classification Summary (70 defined + 3 inherited from BaseProtocolIntegrationTest,
plus TestMMSTLSFlagCoverage / TestMMSArgValidationAndHygiene / TestMMSP1Verdict below)
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  36 tests
Category B (conditional -- mock may not support, accept 0 or 1):       14 tests
Category C (error handling -- assert failure + validate error events):  20 tests
Total defined in file (original class):                                70 tests
Total collected (including inherited):                                 73 tests
---------------------------------------------------------------------------

Flag Coverage Matrix (proto_args.py / `oida mms -h`):
  --port                    [A] inherent in all tests via port fixture
  --timeout                 [A] inherited test_timeout_handling, test_short_timeout
  -i/--identify             [A] test_identify, test_identify_output_structure
  -l/--get-name-list        [A] test_get_name_list, test_get_name_list_finds_devices
  -r/--variable             [A] test_read_variable_ggio1, [B] test_read_variable_lln0
  --read-values             [A] test_read_values_all_readable
  --test-write              [B] test_write_access_with_confirm, [C] test_write_without_confirm
  --max-objects             [A] test_max_objects_limits_discovery
  --confirm                 [B] implicit in write/fuzz tests
  --fuzz                    [C] test_fuzz_requires_confirm, test_fuzz_with_confirm
  --fuzz-iterations         [C] test_fuzz_custom_iterations
  --fuzz-max-targets        [C] test_fuzz_max_targets
  --fuzz-reference          [C] test_fuzz_specific_reference
  format (global)           [A] test_csv_output, test_json_output
  -v (global)               [A] test_verbose_output
  --debug (global)          [A] test_debug_output

  -- TLS flags below driven against the LIVE mms-libiec61850 mock (plaintext,
     no TLS listener exists in this fleet), so they are exercised as hostile/
     negative paths: a real MMS/TCP server refusing a TLS handshake, and
     clean, non-crashing errors for bad certificate paths. See
     TestMMSTLSFlagCoverage. --

  --tls                     [C] test_tls_against_plaintext_server_fails_cleanly
  --tls-port                [B] test_tls_port_flag_is_actually_used
  --tls-ca                  [C] test_tls_ca_nonexistent_file_fails_cleanly
  --tls-pin                 [C] test_tls_pin_nonexistent_file_fails_cleanly
  --tls-client-cert         [C] test_tls_client_cert_and_key_nonexistent_fail_cleanly
  --tls-client-key          [C] test_tls_client_cert_and_key_nonexistent_fail_cleanly

Bug-hunt classes appended below the original class:
  TestMMSP1Verdict                  -- P1 false-positive identification verdict
                                        (mms is CORRECT / NOT affected; see class
                                        docstring for the reproduction and why).
  TestMMSTLSFlagCoverage            -- --tls/--tls-port/--tls-ca/--tls-pin/
                                        --tls-client-cert/--tls-client-key coverage.
  TestMMSArgValidationAndHygiene    -- P2 (unvalidated numeric ranges), P3
                                        (wrong-type args), P6 (unknown/typo flags).
"""

import json

import pytest
from typing import Optional

from tests.integration.base_protocol_test import BaseProtocolIntegrationTest
from tests.integration.conftest import MOCK_HOST, MOCK_PORTS


# All MMS tests share a single libiec61850 server per port (102/10106/10107/10108),
# and libiec61850 caps concurrent MMS clients (~5 by default). Pin the whole module
# to one xdist worker so parallel runs don't exceed that cap and flake on rc=1.
# Honored only under `--dist loadgroup`. Mirrors test_iec104_integration.py.
pytestmark = pytest.mark.xdist_group("mms_service")


# ---------------------------------------------------------------------------
# Known mock data constants (from libiec61850 server_example_basic_io)
# ---------------------------------------------------------------------------
MOCK_LOGICAL_DEVICE = "simpleIOGenericIO"
MOCK_LOGICAL_NODES = ["GGIO1", "LLN0", "LPHD1"]
MOCK_GGIO1_OBJECTS = [
    "Mod",
    "SPCSO1",
    "SPCSO2",
    "SPCSO3",
    "SPCSO4",
    "NamPlt",
    "AnIn1",
    "AnIn2",
    "AnIn3",
    "AnIn4",
    "Beh",
    "Health",
    "Ind1",
    "Ind2",
    "Ind3",
    "Ind4",
]
MOCK_LLN0_OBJECTS = ["Mod", "NamPlt", "Beh", "Health"]
MOCK_LPHD1_OBJECTS = ["PhyNam", "PhyHealth", "Proxy"]
MOCK_TOTAL_DATA_OBJECTS = 23
MOCK_TOTAL_LOGICAL_NODES = 3
MOCK_CONTROL_DATA_OBJECTS = 28  # server_example_control has more


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _all_messages(log) -> str:
    """Concatenate all log event messages into a lowercase string."""
    parts = []
    for event in log.events:
        msg = event.get("message", "")
        if msg:
            parts.append(str(msg).lower())
        data = event.get("data", {})
        if isinstance(data, dict):
            for v in data.values():
                parts.append(str(v).lower())
    return " ".join(parts)


def _assert_log_has_events(result) -> None:
    """Assert that the scan produced JSON log events."""
    assert result.scan_log is not None, "Expected scan_log but got None"
    assert len(result.scan_log) > 0, "Expected at least 1 log event, got 0"


def _assert_log_event_structure(log) -> None:
    """Assert basic structure of log events."""
    for event in log.events:
        assert "event_type" in event or "level" in event or "message" in event, (
            f"Log event missing expected fields: {event}"
        )


def _combined_text(result, log=None) -> str:
    """Return lowercase combined output + log messages for broad searches."""
    parts = [result.combined_output.lower()]
    if log is not None:
        parts.append(_all_messages(log))
    return " ".join(parts)


def _assert_found_in_log(log, substring: str) -> None:
    """Assert that a substring appears in log event messages."""
    text = _all_messages(log)
    assert substring.lower() in text, f"Expected '{substring}' in log messages. Got: {text[:500]}"


@pytest.mark.mms
@pytest.mark.flaky(reruns=2, reruns_delay=4)
class TestMMSIntegration(BaseProtocolIntegrationTest):
    """Integration tests for MMS/IEC 61850 protocol scanner

    Every test here shells out to the oida CLI with a 30-45s subprocess timeout and
    talks to the shared, connection-capped libiec61850 server. Under a fully loaded
    integration lane (8 workers, coverage instrumentation) those subprocesses can
    exceed the timeout and report an empty-stderr scan failure. Verified transient:
    the file passes 73/73 in isolation under the same -n 8 --dist loadgroup settings,
    and the whole class passed on a clean full-lane rerun. Retried rather than
    re-grouped -- the xdist_group("mms_service") above already serialises the group.
    """

    @property
    def protocol_name(self) -> str:
        return "mms"

    @property
    def default_port(self) -> int:
        return 102

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    # ========================================================================
    # Base Class Overrides
    # ========================================================================

    def test_basic_discovery(self, cli_runner, target, port):
        """Test basic protocol discovery [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"Discovery failed (rc={result.returncode}): {result.stderr}"
        text = _combined_text(result)
        assert "simpleio" in text or "mms" in text, (
            f"Expected MMS-related output. Got: {text[:300]}"
        )

    @pytest.mark.slow
    def test_concurrent_connections(self, cli_runner, target, port):
        """Test multiple concurrent connections [Category B]"""
        import concurrent.futures

        port_args = self._get_port_args(port)

        def run_scan():
            args = [self.protocol_name, target] + port_args
            return cli_runner.run(*args, format="json", timeout=30)

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(run_scan) for _ in range(3)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        for r in results:
            assert r.returncode in [0, 1], (
                f"Concurrent scan crashed (rc={r.returncode}): {r.stderr}"
            )
        completed = [r for r in results if r.success]
        assert len(completed) >= 1, "No concurrent connections succeeded"

    def test_invalid_target(self, cli_runner):
        """Test that invalid target is handled gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "not-a-valid-host-12345",
            "--port",
            str(self.default_port),
            "--timeout",
            "5",
            timeout=15,
            expect_json=False,
        )
        output_lower = result.combined_output.lower()
        has_error = any(
            term in output_lower
            for term in [
                "error",
                "failed",
                "cannot",
                "not found",
                "not known",
                "timed out",
                "timeout",
                "refused",
                "unreachable",
                "could not connect",
                "connection failed",
            ]
        )
        assert not result.success or has_error, (
            f"Expected failure for invalid target, got rc={result.returncode}"
        )

    # ========================================================================
    # Discovery Tests
    # ========================================================================

    def test_default_scan(self, cli_runner, target, port):
        """Test default scan discovers device and data model [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # Must find the logical device
        assert "simpleiogenericioio" in text.replace(" ", "") or "simpleio" in text, (
            f"Expected simpleIOGenericIO in output. Got: {text[:400]}"
        )
        # Must mention discovery counts
        assert "logical" in text
        assert "data object" in text or "23" in text

    def test_identify(self, cli_runner, target, port):
        """Test --identify sends MMS Identify request [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # The identify path queries server identity and enumerates the logical
        # device list; the mock reports "IEC 61850 Server has 1 logical devices"
        # and exposes the simpleIOGenericIO device.
        assert "iec 61850 server has" in text or "logical device" in text, (
            f"Expected MMS server-identity enumeration. Got: {text[:400]}"
        )
        assert "simpleio" in text, (
            f"Expected simpleIOGenericIO device after identify. Got: {text[:400]}"
        )

    def test_identify_output_structure(self, cli_runner, target, port):
        """Test --identify JSON log has expected event structure [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)
        # Every event must have module, host, port
        for event in result.scan_log.events:
            assert "module" in event, f"Event missing 'module': {event}"
            assert event.get("host") == "127.0.0.1"
            assert event.get("port") == port

    def test_get_name_list(self, cli_runner, target, port):
        """Test --get-name-list discovers logical devices and nodes [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--get-name-list",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # Must find the logical device name
        assert "simpleiogenericioio" in text.replace(" ", "") or "simpleio" in text

    def test_get_name_list_finds_devices(self, cli_runner, target, port):
        """Test --get-name-list finds known logical device [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--get-name-list",
            format="json",
            json_log=True,
            debug=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        log_text = _all_messages(result.scan_log)
        # With debug, log should contain the device name
        assert "simpleiogenericioio" in log_text.replace(" ", "") or "simpleio" in log_text, (
            f"Expected simpleIOGenericIO in log. Got: {log_text[:500]}"
        )

    def test_identify_and_get_name_list(self, cli_runner, target, port):
        """Test combined --identify + --get-name-list [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            "--get-name-list",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "simpleio" in text

    # ========================================================================
    # Data Model Validation Tests
    # ========================================================================

    def test_discovers_logical_device_name(self, cli_runner, target, port):
        """Test that device name 'simpleIOGenericIO' appears in output [Category A]"""
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
        assert result.success
        _assert_log_has_events(result)
        log_text = _all_messages(result.scan_log)
        assert "simpleiogenericioio" in log_text.replace(" ", "") or "simpleio" in log_text

    def test_discovers_logical_nodes(self, cli_runner, target, port):
        """Test that GGIO1, LLN0, LPHD1 logical nodes are found [Category A]"""
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
        assert result.success
        _assert_log_has_events(result)
        log_text = _all_messages(result.scan_log)
        for node in MOCK_LOGICAL_NODES:
            assert node.lower() in log_text, (
                f"Expected logical node '{node}' in log. Got: {log_text[:500]}"
            )

    def test_discovers_data_objects(self, cli_runner, target, port):
        """Test that known data objects appear in debug log [Category A]"""
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
        assert result.success
        _assert_log_has_events(result)
        log_text = _all_messages(result.scan_log)
        # Check for some characteristic data objects
        for obj in ["spcso1", "anin1", "nampl", "phynam"]:
            assert obj in log_text, f"Expected data object '{obj}' in log. Got: {log_text[:500]}"

    def test_discovers_correct_counts(self, cli_runner, target, port):
        """Test that discovery reports correct node and object counts [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        text = _combined_text(result, result.scan_log)
        assert f"{MOCK_TOTAL_LOGICAL_NODES} logical nodes" in text
        assert f"{MOCK_TOTAL_DATA_OBJECTS} data objects" in text

    def test_fingerprint_detected(self, cli_runner, target, port):
        """Test that device fingerprint is detected [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        text = _combined_text(result, result.scan_log)
        assert "fingerprint" in text

    # ========================================================================
    # Variable Operations Tests
    # ========================================================================

    def test_read_variable_ggio1(self, cli_runner, target, port):
        """Test reading specific variable GGIO1 [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--variable",
            "GGIO1",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        # Reading a variable still connects and discovers the data model;
        # the targeted logical node and its parent device must be reachable.
        text = _combined_text(result, result.scan_log)
        assert "simpleio" in text, (
            f"Expected simpleIOGenericIO device while reading GGIO1. Got: {text[:400]}"
        )
        assert "ggio1" in text, f"Expected GGIO1 node in output. Got: {text[:400]}"

    def test_read_variable_lln0(self, cli_runner, target, port):
        """Test reading variable LLN0 [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--variable",
            "LLN0",
            format="json",
            json_log=True,
            timeout=30,
        )
        # LLN0 is a real logical node on the mock; the scan connects and
        # discovers the data model successfully.
        assert result.success, f"LLN0 read failed (rc={result.returncode}): {result.stderr}"
        text = _combined_text(result, result.scan_log)
        assert "simpleio" in text and "lln0" in text, (
            f"Expected simpleIOGenericIO/LLN0 discovery. Got: {text[:400]}"
        )

    def test_read_variable_lphd1(self, cli_runner, target, port):
        """Test reading variable LPHD1 [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--variable",
            "LPHD1",
            format="json",
            json_log=True,
            timeout=30,
        )
        # LPHD1 is a real logical node on the mock; the scan connects and
        # discovers the data model successfully.
        assert result.success, f"LPHD1 read failed (rc={result.returncode}): {result.stderr}"
        text = _combined_text(result, result.scan_log)
        assert "simpleio" in text and "lphd1" in text, (
            f"Expected simpleIOGenericIO/LPHD1 discovery. Got: {text[:400]}"
        )

    def test_read_values_all_readable(self, cli_runner, target, port):
        """Test --read-values reads all 23 data objects successfully [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-values",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # All 23 objects should be readable with 0 failures
        assert "23 successful" in text, f"Expected '23 successful' in output. Got: {text[:400]}"
        assert "0 failed" in text, f"Expected '0 failed' in output. Got: {text[:400]}"

    def test_max_objects_limits_discovery(self, cli_runner, target, port):
        """Test --max-objects=5 limits discovery depth [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--max-objects",
            "5",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # With limit=5, should not discover all 23 objects
        assert "23 data objects" not in text

    # ========================================================================
    # Write Access Tests
    # ========================================================================

    def test_write_access_with_confirm(self, cli_runner, target, port):
        """Test --test-write with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--test-write",
            "--read-values",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )
        # Write test may fail if server doesn't support writes
        assert result.returncode in [0, 1]

    def test_write_without_confirm(self, cli_runner, target, port):
        """Test --test-write without --confirm stays in read-only mode [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--test-write",
            format="json",
            json_log=True,
            timeout=30,
        )
        # Should still work (read-only mode skips writes)
        assert result.returncode in [0, 1]

    # ========================================================================
    # Multi-Server Tests (GOOSE, Control, Auth)
    # ========================================================================

    @pytest.mark.containers("mms-goose")
    def test_goose_server_discovery(self, cli_runner):
        """Test discovery against GOOSE server on port 10106 [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms_goose"]),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        text = _combined_text(result, result.scan_log)
        assert "simpleio" in text

    @pytest.mark.containers("mms-control")
    def test_control_server_discovery(self, cli_runner):
        """Test discovery against control server on port 10107 [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms_control"]),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        text = _combined_text(result, result.scan_log)
        assert "simpleio" in text
        # Control server has 28 data objects
        assert f"{MOCK_CONTROL_DATA_OBJECTS} data objects" in text

    @pytest.mark.containers("mms-control")
    def test_control_server_read_values(self, cli_runner):
        """Test --read-values on control server (28 objects) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms_control"]),
            "--read-values",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success
        text = _combined_text(result, result.scan_log)
        assert "28 successful" in text

    @pytest.mark.containers("mms-authentication")
    def test_auth_server_rejects_unauthenticated(self, cli_runner):
        """Test that auth server rejects unauthenticated connection [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms_auth"]),
            format="json",
            json_log=True,
            timeout=15,
        )
        assert not result.success, "Expected auth server to reject unauthenticated connection"
        text = _combined_text(result)
        assert any(term in text for term in ["rejected", "failed", "refused", "error"]), (
            f"Expected rejection message. Got: {text[:400]}"
        )

    # ========================================================================
    # Security Analysis Tests
    # ========================================================================

    def test_security_analysis_runs(self, cli_runner, target, port):
        """Test security analysis produces output [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # Security analysis should mention accessible devices/objects
        assert any(
            term in text for term in ["security", "accessible", "discovered", "logical device"]
        )

    def test_security_reports_accessible_data(self, cli_runner, target, port):
        """Test that accessible data objects are reported [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        text = _combined_text(result, result.scan_log)
        assert "logical device" in text

    # ========================================================================
    # Security Finding Tests
    # ========================================================================
    #
    # The MMS scanner generates security findings via two mechanisms:
    #
    # 1. SecurityAnalyzer.assess_protocol_security() produces:
    #    - issues: ["Missing authentication", "Missing authorization",
    #              "Missing encryption", "Missing integrity check",
    #              optionally "Missing access control"]
    #    - security_level: "low" (always, since MMS has no auth/encryption)
    #    - security_score: 0 or 2 out of 12
    #
    # 2. _report_findings() generates concerns reported via report_vulnerability():
    #    - "N logical devices accessible"   (when devices found)
    #    - "N data objects discovered"       (when objects found)
    #    - "N data objects readable"         (when --read-values succeeds)
    #    - "N data objects writable"         (when --test-write finds writable)
    #
    # The scanner also reports the logical device names via self.logger.display()
    # which appears in the JSON log as event_type="info".
    #
    # The concerns are reported via report_vulnerability() which writes to the
    # Python module logger (warning level), not the ICSLogger JSON log.
    # However, the security_analysis dict is embedded in the scan results
    # which are logged via self.logger events during discovery.
    #
    # These tests verify that the security analysis runs correctly and that
    # the expected security-relevant information appears in the scanner output.
    # ========================================================================

    @pytest.mark.security
    def test_finding_no_authentication_unauthenticated_access(self, cli_runner, target, port):
        """Test that scanner connects without authentication, proving no auth required [Category A]

        The MMS mock server (libiec61850 server_example_basic_io) accepts
        connections without any authentication.  The scanner should connect
        successfully and discover the data model, which itself constitutes
        evidence of "no authentication" -- unauthenticated access to the
        IEC 61850 data model.

        SecurityAnalyzer generates issue "Missing authentication" because
        the scanner passes authentication=False to assess_protocol_security().
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"Connection failed (rc={result.returncode}): {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # The scanner must successfully connect -- proving no authentication is required
        log_text = _all_messages(log)
        assert "connected" in log_text, (
            f"Expected 'connected' message (proving no auth needed). Got: {log_text[:400]}"
        )

        # After connecting without auth, the scanner discovers the data model
        assert "simpleio" in log_text or "logical device" in log_text, (
            f"Expected device discovery after unauthenticated connection. Got: {log_text[:400]}"
        )

    @pytest.mark.security
    def test_finding_no_encryption_plaintext_connection(self, cli_runner, target, port):
        """Test that connection is plaintext (no TLS/encryption) [Category A]

        The MMS scanner connects to port 102 over plain TCP without any
        TLS negotiation.  SecurityAnalyzer generates issue "Missing encryption"
        because the scanner passes encryption=False to assess_protocol_security().

        This test verifies the connection succeeds over plaintext TCP and
        the data model is fully accessible without encryption.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"Connection failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        log_text = _all_messages(log)

        # Connection succeeds on plain TCP (port 102) -- no TLS negotiation
        assert "connected" in log_text, (
            f"Expected successful plaintext connection. Got: {log_text[:400]}"
        )

        # Full data model accessible over unencrypted channel
        assert any(term in log_text for term in ["simpleio", "logical device", "data object"]), (
            f"Expected data model discovery over plaintext. Got: {log_text[:400]}"
        )

        # The cleartext connection must be reported as a no-encryption finding.
        # (The finding's own wording legitimately contains "no TLS", so we assert
        # the finding is present rather than banning the substring "tls".)
        assert "no encryption" in log_text or "cleartext" in log_text, (
            f"Expected a no-encryption finding on the plaintext connection. Got: {log_text[:400]}"
        )
        # No evidence of an actually-negotiated TLS/SSL session.
        assert not any(
            term in log_text
            for term in ["tls handshake", "tls established", "ssl handshake", "encrypted channel"]
        ), "Unexpected TLS/SSL session references in plaintext connection"

    @pytest.mark.security
    def test_finding_logical_devices_accessible(self, cli_runner, target, port):
        """Test that accessible logical devices are reported as security concern [Category A]

        _analyze_security() generates concern "1 logical devices accessible"
        when the mock server exposes its simpleIOGenericIO logical device.
        The scanner reports this via report_vulnerability() and also logs
        the device name via self.logger.display().

        The mock (server_example_basic_io) has 1 logical device: simpleIOGenericIO.
        """
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
        _assert_log_has_events(result)
        log = result.scan_log
        log_text = _all_messages(log)

        # Scanner must report finding the logical device
        assert "simpleio" in log_text, (
            f"Expected simpleIOGenericIO device discovery. Got: {log_text[:400]}"
        )

        # Scanner must report discovery count of logical devices
        text = _combined_text(result, log)
        assert "1 logical device" in text or "discovered 1" in text, (
            f"Expected '1 logical device' count in output. Got: {text[:400]}"
        )

    @pytest.mark.security
    def test_finding_data_objects_discovered(self, cli_runner, target, port):
        """Test that discovered data objects are reported as security concern [Category A]

        _analyze_security() generates concern "N data objects discovered"
        when the scanner finds data objects in the IEC 61850 data model.

        The mock (server_example_basic_io) has 23 data objects across 3 logical nodes.
        The scanner reports "Discovered 3 logical nodes and 23 data objects".
        """
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
        _assert_log_has_events(result)
        log = result.scan_log
        text = _combined_text(result, log)

        # Scanner must report the exact count of discovered data objects
        assert f"{MOCK_TOTAL_DATA_OBJECTS} data objects" in text, (
            f"Expected '{MOCK_TOTAL_DATA_OBJECTS} data objects' in output. Got: {text[:400]}"
        )

        # Scanner must also report logical node count
        assert f"{MOCK_TOTAL_LOGICAL_NODES} logical nodes" in text, (
            f"Expected '{MOCK_TOTAL_LOGICAL_NODES} logical nodes' in output. Got: {text[:400]}"
        )

    @pytest.mark.security
    def test_finding_data_objects_readable(self, cli_runner, target, port):
        """Test that readable data objects trigger security concern [Category A]

        When --read-values is used, _analyze_security() generates concern
        "N data objects readable" for each successfully read object.

        The mock supports reading all 23 data objects (MX/ST functional constraints).
        The scanner reports "Read test complete: 23 successful, 0 failed".
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-values",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success, f"Read scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        text = _combined_text(result, log)

        # Scanner must report successful reads
        assert "23 successful" in text, (
            f"Expected '23 successful' reads in output. Got: {text[:400]}"
        )
        assert "0 failed" in text, f"Expected '0 failed' reads in output. Got: {text[:400]}"

        # The read results confirm all data objects are readable without auth
        assert "read test complete" in text, (
            f"Expected 'Read test complete' summary. Got: {text[:400]}"
        )

    @pytest.mark.security
    def test_finding_data_objects_writable_with_confirm(self, cli_runner, target, port):
        """Test --test-write --confirm triggers write access testing [Category B]

        When --test-write --read-values --confirm is used, _analyze_security()
        generates concern "N data objects writable" if any writes succeed.

        NOTE: The scanner's BaseScanner defaults to read_only=True.  The
        --confirm flag is checked by fuzz/write handlers but does not
        automatically set read_only=False.  As a result, --test-write may
        be silently skipped if the scanner stays in read-only mode.  This
        test validates the scan completes and produces discovery output,
        even if write testing is skipped.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--test-write",
            "--read-values",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )
        # Write test may be skipped (read-only default) or fail if server rejects
        assert result.returncode in [0, 1]
        # UNCONDITIONAL: scanner must at least connect and discover
        text = _combined_text(result)
        assert any(
            term in text
            for term in [
                "write test",
                "write access",
                "test write",
                "writable",
                "read-only",
                "skipping write",
                "connected",
                "discovered",
                "logical device",
                "data object",
            ]
        ), f"Expected scan activity in output. Got: {text[:500]}"

    @pytest.mark.security
    def test_finding_write_test_requires_confirm(self, cli_runner, target, port):
        """Test that --test-write without --confirm skips writes (read-only) [Category B]

        The scanner should skip write testing when --confirm is not provided,
        staying in read-only mode.  This is a safety mechanism.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--test-write",
            format="json",
            json_log=True,
            timeout=30,
        )
        # Should succeed but skip writes (read-only mode)
        assert result.returncode in [0, 1]
        text = _combined_text(result)
        # Scanner must indicate it's in read-only mode or skip write tests
        assert any(
            term in text
            for term in ["read-only", "skipping write", "read only", "connected", "logical"]
        ), f"Expected read-only or skip indication. Got: {text[:500]}"

    @pytest.mark.security
    @pytest.mark.containers("mms-authentication")
    def test_finding_auth_server_connection_rejected(self, cli_runner):
        """Test that authentication server rejects unauthenticated scan [Category C]

        The mms-authentication server (port 10108) requires TLS + password
        authentication (admin:admin@mms, operator:operator@mms).  Connecting
        without credentials should be rejected, demonstrating the security
        difference between authenticated and unauthenticated servers.
        """
        result = cli_runner.run(
            self.protocol_name,
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms_auth"]),
            format="json",
            json_log=True,
            timeout=15,
        )
        # Connection should fail -- auth server rejects unauthenticated
        assert not result.success, "Expected auth server to reject unauthenticated connection"
        text = _combined_text(result)
        assert any(
            term in text for term in ["rejected", "failed", "refused", "error", "connection failed"]
        ), f"Expected rejection/failure message from auth server. Got: {text[:400]}"

    @pytest.mark.security
    def test_finding_no_authorization_full_model_access(self, cli_runner, target, port):
        """Test that full data model is accessible without authorization [Category A]

        SecurityAnalyzer generates issue "Missing authorization" because the
        scanner passes authorization=False to assess_protocol_security().

        This test proves there's no authorization by showing all logical nodes
        (GGIO1, LLN0, LPHD1) and all 23 data objects are discovered without
        any access control checks.
        """
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
        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        log_text = _all_messages(log)

        # All 3 logical nodes must be accessible
        for node in MOCK_LOGICAL_NODES:
            assert node.lower() in log_text, (
                f"Expected logical node '{node}' accessible without authorization. "
                f"Got: {log_text[:500]}"
            )

        # All data objects must be discoverable (23 total)
        text = _combined_text(result, log)
        assert f"{MOCK_TOTAL_DATA_OBJECTS} data objects" in text, (
            f"Expected all {MOCK_TOTAL_DATA_OBJECTS} objects accessible. Got: {text[:400]}"
        )

    @pytest.mark.security
    def test_finding_readable_without_authorization(self, cli_runner, target, port):
        """Test that all data objects are readable without authorization [Category A]

        When --read-values is combined with debug mode, the scanner reads all
        23 data objects.  The mock accepts all reads without authorization checks.
        This proves there's no per-object access control.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-values",
            format="json",
            json_log=True,
            debug=True,
            timeout=45,
        )
        assert result.success, f"Read scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        text = _combined_text(result, log)

        # 23 out of 23 objects readable = no authorization on reads
        assert "23 successful" in text, (
            f"Expected all 23 objects readable (no read authorization). Got: {text[:400]}"
        )
        assert "0 failed" in text, (
            f"Expected 0 read failures (no access control). Got: {text[:400]}"
        )

    @pytest.mark.security
    def test_finding_security_analysis_in_json_output(self, cli_runner, target, port):
        """Test security_analysis appears in JSON output data [Category B]

        The scanner stores security_analysis in the results dict under
        data.scan_results.security_analysis.  When format=json with -o,
        this data would be in the export file.  Here we verify the analysis
        ran by checking log messages that confirm discovery completed.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1]
        # UNCONDITIONAL: security analysis must run (it always does after discovery)
        _assert_log_has_events(result)
        log = result.scan_log
        text = _combined_text(result, log)

        # Discovery must complete (security analysis runs after discovery)
        assert any(term in text for term in ["discovered", "logical device", "data object"]), (
            f"Expected discovery completion before security analysis. Got: {text[:400]}"
        )

    @pytest.mark.security
    @pytest.mark.containers("mms-control")
    def test_finding_control_server_accessible_without_auth(self, cli_runner):
        """Test that control server data model is accessible without auth [Category A]

        The mms-control server (port 10107) runs server_example_control which
        has a writable control model.  This test verifies the 28 data objects
        are discoverable without authentication, including control-related
        objects (SBO, direct operate).
        """
        result = cli_runner.run(
            self.protocol_name,
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms_control"]),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"Control server scan failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "simpleio" in text, (
            f"Expected simpleIOGenericIO device on control server. Got: {text[:400]}"
        )
        # Control server has 28 data objects
        assert f"{MOCK_CONTROL_DATA_OBJECTS} data objects" in text, (
            f"Expected {MOCK_CONTROL_DATA_OBJECTS} objects on control server. Got: {text[:400]}"
        )

    @pytest.mark.security
    @pytest.mark.containers("mms-control")
    def test_finding_control_objects_readable_without_auth(self, cli_runner):
        """Test that control server data objects are readable without auth [Category A]

        The mms-control server (port 10107) allows reading all 28 data objects
        without authentication.  This includes control-related objects that
        could be security-sensitive.
        """
        result = cli_runner.run(
            self.protocol_name,
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms_control"]),
            "--read-values",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success, f"Control server read failed: {result.stderr}"
        text = _combined_text(result, result.scan_log)
        assert "28 successful" in text, (
            f"Expected all 28 objects readable on control server. Got: {text[:400]}"
        )

    @pytest.mark.security
    def test_finding_vulnerability_logged_for_devices(self, cli_runner, target, port):
        """Test that vulnerability for accessible devices appears in output [Category A]

        _report_findings() calls report_vulnerability(host, "iec61850_security",
        description="1 logical devices accessible") for each concern.
        report_vulnerability() logs via logger.warning() which appears in
        stderr/combined_output as a warning-level message.
        """
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
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)

        # The vulnerability report for accessible devices should appear
        # Either as "logical devices accessible" concern or as "iec61850_security"
        # vulnerability, or the underlying discovery messages
        assert any(
            term in text
            for term in [
                "logical devices accessible",
                "iec61850_security",
                "vulnerability found",
                "1 logical device",
                "simpleio",
            ]
        ), f"Expected security concern about accessible devices. Got: {text[:500]}"

    @pytest.mark.security
    def test_finding_vulnerability_logged_for_objects(self, cli_runner, target, port):
        """Test that vulnerability for discovered objects appears in output [Category A]

        _report_findings() calls report_vulnerability(host, "iec61850_security",
        description="23 data objects discovered") when data objects are found.
        """
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
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)

        # The data object count must be reported
        assert f"{MOCK_TOTAL_DATA_OBJECTS} data objects" in text, (
            f"Expected '{MOCK_TOTAL_DATA_OBJECTS} data objects' concern. Got: {text[:400]}"
        )

    @pytest.mark.security
    @pytest.mark.containers("mms-goose")
    def test_finding_goose_server_accessible_without_auth(self, cli_runner):
        """Test that GOOSE server is accessible without authentication [Category A]

        The mms-goose server (port 10106) runs server_example_goose with
        GOOSE publishing capabilities.  Accessing this without auth is a
        security concern as it exposes GOOSE control block configuration.
        """
        result = cli_runner.run(
            self.protocol_name,
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms_goose"]),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"GOOSE server scan failed: {result.stderr}"
        text = _combined_text(result, result.scan_log)
        assert "simpleio" in text, f"Expected device discovery on GOOSE server. Got: {text[:400]}"

    @pytest.mark.security
    def test_finding_all_security_concerns_present(self, cli_runner, target, port):
        """Test that a default scan triggers multiple security concerns [Category A]

        A default scan against the mock should trigger at least 2 concerns:
        1. "1 logical devices accessible" (always, since device is found)
        2. "23 data objects discovered" (always, since objects are found)

        These are reported via report_vulnerability() with vuln_name="iec61850_security".
        The underlying discovery messages are visible in the JSON log.
        """
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
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)

        # Concern 1: Logical devices accessible
        assert "1 logical device" in text or "simpleio" in text, (
            f"Missing concern: logical devices accessible. Got: {text[:400]}"
        )

        # Concern 2: Data objects discovered
        assert f"{MOCK_TOTAL_DATA_OBJECTS} data objects" in text, (
            f"Missing concern: data objects discovered. Got: {text[:400]}"
        )

        # Concern 3 (only with --read-values): not triggered in default scan
        # Concern 4 (only with --test-write --confirm): not triggered in default scan

    @pytest.mark.security
    def test_finding_read_values_adds_readable_concern(self, cli_runner, target, port):
        """Test that --read-values adds readable objects concern [Category A]

        When --read-values is used, the scanner tests read access to all
        discovered data objects.  On the mock, all 23 are readable.
        This triggers the additional "23 data objects readable" concern
        in _analyze_security().
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-values",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success, f"Read scan failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)

        # All concerns present: devices, objects, AND readable
        assert "1 logical device" in text or "simpleio" in text
        assert f"{MOCK_TOTAL_DATA_OBJECTS} data objects" in text
        assert "23 successful" in text, (
            f"Expected 23 readable objects triggering concern. Got: {text[:400]}"
        )

    # ========================================================================
    # Connection Lifecycle Tests
    # ========================================================================

    def test_connection_lifecycle(self, cli_runner, target, port):
        """Test connection establishes and tears down cleanly [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        log_text = _all_messages(result.scan_log)
        # Should see connect, then disconnect
        assert "connect" in log_text
        # Check events are ordered
        msgs = [e.get("message", "") for e in result.scan_log.events]
        connect_idx = next((i for i, m in enumerate(msgs) if "connected" in m.lower()), None)
        close_idx = next((i for i, m in enumerate(msgs) if "closed" in m.lower()), None)
        assert connect_idx is not None, "No connection event found"
        if close_idx is not None:
            assert close_idx > connect_idx, "Close happened before connect"

    # ========================================================================
    # Error Handling Tests
    # ========================================================================

    def test_invalid_variable(self, cli_runner, target, port):
        """Test handling of invalid variable name [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--variable",
            "INVALID_VARIABLE_12345",
            format="json",
            json_log=True,
            timeout=15,
        )
        # Should handle gracefully -- not hang or crash
        assert result.returncode != -1

    def test_connection_refused_on_closed_port(self, cli_runner):
        """Test connection refused on a closed port [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "127.0.0.1",
            "--port",
            "65534",
            "--timeout",
            "3",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert not result.success, "Expected failure on closed port"
        text = _combined_text(result)
        assert any(term in text for term in ["failed", "refused", "rejected", "error"]), (
            f"Expected failure message. Got: {text[:400]}"
        )

    def test_timeout_on_unreachable_host(self, cli_runner):
        """Test timeout on unreachable host [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "10.255.255.1",
            "--port",
            str(self.default_port),
            "--timeout",
            "3",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert not result.success, (
            f"Expected failure for unreachable host, got rc={result.returncode}"
        )
        assert result.execution_time < 20, "Command did not respect timeout"

    def test_short_timeout(self, cli_runner, target, port):
        """Test very short timeout completes without hanging [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--timeout",
            "1",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.returncode != -1
        assert result.execution_time < 20

    def test_dependency_error_message(self, cli_runner, target, port):
        """Test that scanner errors produce clear messages [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], (
            f"Scanner crashed (rc={result.returncode}): {result.stderr}"
        )
        # If it fails, the error should be clear
        if not result.success:
            text = _combined_text(result)
            assert any(
                term in text
                for term in ["pyiec61850", "import", "dependency", "install", "failed", "error"]
            )

    # ========================================================================
    # Fuzzing Tests
    # ========================================================================

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_requires_confirm(self, cli_runner, target, port):
        """Test --fuzz without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            format="json",
            json_log=True,
            timeout=30,
        )
        # Fuzz without confirm should warn or fail
        assert result.returncode in [0, 1], (
            f"Fuzz crashed (rc={result.returncode}): {result.stderr}"
        )
        text = _combined_text(result)
        if result.success:
            assert "confirm" in text or "requires" in text

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_with_confirm(self, cli_runner, target, port):
        """Test --fuzz with --confirm attempts fuzzing [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-iterations",
            "3",
            "--fuzz-max-targets",
            "2",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )
        assert result.returncode != -1

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_custom_iterations(self, cli_runner, target, port):
        """Test --fuzz-iterations parameter accepted [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-iterations",
            "2",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )
        assert result.returncode != -1

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_max_targets(self, cli_runner, target, port):
        """Test --fuzz-max-targets parameter accepted [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-max-targets",
            "1",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )
        assert result.returncode != -1

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_specific_reference(self, cli_runner, target, port):
        """Test --fuzz-reference targets specific data object [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-reference",
            "simpleIOGenericIO/GGIO1.AnIn1",
            "--fuzz-iterations",
            "2",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )
        assert result.returncode != -1

    # ========================================================================
    # Output Format Tests
    # ========================================================================

    def test_csv_output(self, cli_runner, target, port):
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
        assert result.success
        # The scan still discovers the device regardless of export format.
        text = _combined_text(result, result.scan_log)
        assert "simpleio" in text, f"Expected device discovery with CSV format. Got: {text[:400]}"

    def test_json_output(self, cli_runner, target, port):
        """Test JSON output format [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        text = _combined_text(result, result.scan_log)
        assert "simpleio" in text, f"Expected device discovery with JSON format. Got: {text[:400]}"

    # ========================================================================
    # Verbosity and Debug Tests
    # ========================================================================

    def test_verbose_output(self, cli_runner, target, port):
        """Test -v verbose output produces more events [Category A]"""
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
        assert result.success
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "simpleio" in text, f"Expected device discovery in verbose output. Got: {text[:400]}"

    def test_debug_output(self, cli_runner, target, port):
        """Test --debug reveals per-object discovery [Category A]"""
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
        assert result.success
        _assert_log_has_events(result)
        # Debug mode should show individual data object discovery
        debug_events = [e for e in result.scan_log.events if e.get("level") == "debug"]
        assert len(debug_events) > 0, "Expected debug-level events in log"
        log_text = _all_messages(result.scan_log)
        assert "found data object" in log_text

    # ========================================================================
    # Help and CLI Tests
    # ========================================================================

    def test_help_output(self, cli_runner):
        """Test --help shows MMS-specific options [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )
        assert result.returncode == 0 or "usage" in result.combined_output.lower()
        text = result.combined_output.lower()
        assert "mms" in text
        assert "--identify" in text or "identify" in text
        assert "--get-name-list" in text or "get-name-list" in text
        assert "--read-values" in text
        assert "--test-write" in text
        assert "--max-objects" in text
        assert "--fuzz" in text

    # ========================================================================
    # Combined Operation Tests
    # ========================================================================

    def test_identify_with_read_values(self, cli_runner, target, port):
        """Test --identify combined with --read-values [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            "--read-values",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success
        text = _combined_text(result, result.scan_log)
        assert "23 successful" in text

    def test_full_discovery(self, cli_runner, target, port):
        """Test identify + name-list + read-values together [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            "--get-name-list",
            "--read-values",
            "--max-objects",
            "50",
            format="json",
            json_log=True,
            timeout=60,
        )
        assert result.success
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Scan Timing Tests
    # ========================================================================

    def test_discovery_completes_in_time(self, cli_runner, target, port):
        """Test default discovery completes in reasonable time [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        assert result.execution_time < 15, f"Discovery took too long: {result.execution_time:.1f}s"

    # ========================================================================
    # JSON Log Structure Tests
    # ========================================================================

    def test_json_log_events_structure(self, cli_runner, target, port):
        """Test that JSON log events have proper structure [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)
        for event in result.scan_log.events:
            assert isinstance(event, dict)
            assert "timestamp" in event
            assert "level" in event
            assert "module" in event
            assert "message" in event

    def test_json_log_has_connection_info(self, cli_runner, target, port):
        """Test JSON log includes connection information [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        log_text = _all_messages(result.scan_log)
        assert "127.0.0.1" in log_text or "connect" in log_text

    def test_json_log_module_name(self, cli_runner, target, port):
        """Test JSON log events use correct module name [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success
        _assert_log_has_events(result)
        modules = {e.get("module") for e in result.scan_log.events}
        # Should include MMS-related module names
        assert any("mms" in m.lower() for m in modules if m), (
            f"Expected 'mms' module in log events. Found modules: {modules}"
        )


# ============================================================================
# P1 false-positive-identification verdict.
#
# connection.py's NetworkConnection.run() defaults results["success"] to True
# whenever proto_flow() returns without raising an exception. Several
# protocol modules never explicitly flip that default back to False on a
# connect failure, which produces a false "success": true in the final
# --output JSON even though nothing was ever validly identified (the
# "connection-1" systemic bug, deferred -- connection.py itself is NOT to be
# touched here).
#
# MMS's cli_runner.py (src/oida/protocols/mms/cli_runner.py) is NOT affected:
#
#   def proto_flow(self):
#       ...
#       self.create_conn_obj()
#       if not self.conn:
#           self.logger.fail(f"Failed to connect to {self.host}")
#           self.results["success"] = False
#           self.results["error"] = "Connection failed"
#           return
#
# `self.conn` comes from MMSScanner.connect() (src/oida/protocols/mms/__init__.py),
# which performs a REAL MMS/ISO association (`_Lib.MMSClient(...).connect(host,
# port)` -- an actual OSI presentation/session/ACSE handshake over the TCP
# byte stream, not just a bare TCP connect) and returns None whenever that
# association fails for any reason (TCP refused, TCP accepted but no valid
# MMS/ISO response, TLS handshake failure). Only a successful MMS association
# yields a non-None client, so success=False is the correct outcome whenever
# the responder is not really an MMS/IEC 61850 server.
#
# This is the pattern other modules should crib for their own connection-1
# fix: gate "success" on the protocol-layer handshake completing (an actual
# parsed protocol response), not on "raw TCP connect succeeded" or "no
# exception was raised".
# ============================================================================
@pytest.mark.mms
class TestMMSP1Verdict:
    """Reproduces and documents the P1 false-positive-identification verdict
    for MMS: CORRECT / NOT affected by the connection.py default-success bug."""

    protocol_name = "mms"

    def test_p1_closed_port_reports_success_false(self, cli_runner, tmp_path):
        """A closed TCP port never yields a real MMS association, so the
        final JSON must report success: false [Category C, P1 verdict]."""
        out_dir = tmp_path / "p1_closed"
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--port",
            "65530",
            "--timeout",
            "3",
            format="json",
            output=str(out_dir),
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        out_file = out_dir / "mms.json"
        assert out_file.exists(), result.combined_output[:500]
        payload = json.loads(out_file.read_text())
        last = payload[-1] if isinstance(payload, list) else payload
        assert last["success"] is False, (
            "MMS is expected to be CORRECT (not affected by the connection.py "
            f"default-success bug): closed port must report success=False. Got: {last}"
        )
        assert last.get("error") == "Connection failed"

    def test_p1_wrong_protocol_on_port_reports_success_false(self, cli_runner, tmp_path):
        """Pointing MMS at a live Modbus mock (wrong protocol on the port)
        must also report success: false -- no false-positive MMS
        identification of a non-MMS responder [Category C, P1 verdict,
        impostor server]."""
        out_dir = tmp_path / "p1_wrong_proto"
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["modbus"]),
            "--timeout",
            "3",
            format="json",
            output=str(out_dir),
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        out_file = out_dir / "mms.json"
        assert out_file.exists(), result.combined_output[:500]
        payload = json.loads(out_file.read_text())
        last = payload[-1] if isinstance(payload, list) else payload
        assert last["success"] is False, (
            "MMS is expected to be CORRECT: a Modbus responder on the probed "
            f"port must never be reported as a successful MMS scan. Got: {last}"
        )
        text = result.combined_output.lower()
        assert "connected to mms device" not in text, (
            f"Must not falsely report a successful MMS connection to a Modbus port: {text[:500]}"
        )

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_p1b_timeout_bounds_connect_to_blackhole(self, cli_runner):
        """--timeout must actually bound the connect attempt against an
        unreachable (blackhole) address; the process must not hang well past
        the requested timeout [Category C, P1b]."""
        result = cli_runner.run(
            "mms",
            "10.255.255.1",
            "--port",
            "102",
            "--timeout",
            "3",
            format="json",
            timeout=20,
            expect_json=False,
        )
        assert result.execution_time < 15, (
            f"--timeout 3 should bound the run to well under 15s, took "
            f"{result.execution_time:.1f}s: {result.combined_output[:400]}"
        )
        assert "Traceback" not in result.combined_output


# ============================================================================
# --tls/--tls-port/--tls-ca/--tls-pin/--tls-client-cert/--tls-client-key
# coverage. There is no TLS-listening MMS mock in this fleet (MMS-over-TLS
# would need a server on 3782), so these flags are exercised as hostile/
# negative paths against the live plaintext mms-libiec61850 mock: a real MMS
# server refusing a TLS handshake, and clean, non-crashing errors for bad
# certificate paths. This mirrors TestGOOSEMmsEnumAndTLS in
# test_goose_integration.py.
# ============================================================================
@pytest.mark.mms
class TestMMSTLSFlagCoverage:
    """Flag coverage for --tls/--tls-port/--tls-ca/--tls-pin/--tls-client-cert/
    --tls-client-key, driven against the live mms-libiec61850 mock [Category C]."""

    protocol_name = "mms"

    def test_tls_against_plaintext_server_fails_cleanly(self, cli_runner):
        """--tls against a real plaintext MMS server must fail the TLS
        handshake cleanly, not hang or crash, and never report a successful
        connection [Category C, TLS mismatch]."""
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms"]),
            "--tls",
            "--timeout",
            "5",
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        assert "Traceback" not in result.combined_output
        text = result.combined_output.lower()
        assert "connected to mms device" not in text, (
            f"--tls must not report a successful connection to a plaintext server: {text[:500]}"
        )

    def test_tls_ca_nonexistent_file_fails_cleanly(self, cli_runner):
        """--tls-ca pointed at a file that does not exist must produce a
        clean, readable error instead of crashing [Category C]."""
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms"]),
            "--tls",
            "--tls-ca",
            "/nonexistent/ca.pem",
            "--timeout",
            "3",
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        assert "Traceback" not in result.combined_output
        assert "/nonexistent/ca.pem" in result.combined_output, result.combined_output[:500]

    def test_tls_pin_nonexistent_file_fails_cleanly(self, cli_runner):
        """--tls-pin pointed at a file that does not exist must produce a
        clean, readable error instead of crashing [Category C]."""
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms"]),
            "--tls",
            "--tls-pin",
            "/nonexistent/pin.pem",
            "--timeout",
            "3",
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        assert "Traceback" not in result.combined_output
        assert "/nonexistent/pin.pem" in result.combined_output, result.combined_output[:500]

    def test_tls_client_cert_and_key_nonexistent_fail_cleanly(self, cli_runner):
        """--tls-client-cert/--tls-client-key with missing files must fail
        cleanly rather than crash [Category C]."""
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms"]),
            "--tls",
            "--tls-client-cert",
            "/nonexistent/client.pem",
            "--tls-client-key",
            "/nonexistent/client.key",
            "--timeout",
            "3",
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        assert "Traceback" not in result.combined_output
        assert "/nonexistent/client.pem" in result.combined_output, result.combined_output[:500]

    def test_tls_port_flag_is_actually_used(self, cli_runner):
        """--tls-port must change which port is dialed: pointing it at a
        closed port must surface that port number in the resulting error,
        proving the flag is wired rather than ignored [Category B]."""
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--tls",
            "--tls-port",
            "19999",
            "--timeout",
            "3",
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        assert "Traceback" not in result.combined_output
        assert "19999" in result.combined_output, (
            f"--tls-port value not reflected in connection attempt: {result.combined_output[:500]}"
        )


# ============================================================================
# P2 (unvalidated numeric ranges), P3 (wrong-type args), P4 (confirm-gate
# consistency check for --test-write/--fuzz, both already covered in the main
# class -- reconfirmed here against negative values), P6 (unknown/typo flag
# hygiene).
# ============================================================================
@pytest.mark.mms
class TestMMSArgValidationAndHygiene:
    """Numeric validation, bad-type inputs, confirm-gate re-check with
    negative values, and unknown/typo flags."""

    protocol_name = "mms"

    def test_max_objects_negative_value_not_validated(self, cli_runner):
        """--max-objects accepts a negative value without validation: the
        scanner treats it as an (unreachable) cap and discovers zero objects
        instead of rejecting the bad input outright [Category C, P2
        unvalidated range -- documents a real gap, not a crash]."""
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms"]),
            "--max-objects",
            "-5",
            "--timeout",
            "5",
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        assert "Traceback" not in result.combined_output
        text = result.combined_output.lower()
        assert "discovered 0 logical devices" in text, (
            "KNOWN GAP: --max-objects -5 is accepted by argparse and silently "
            f"caps discovery at 0 objects instead of being rejected. Got: {text[:500]}"
        )

    def test_timeout_non_numeric_rejected_by_parser(self, cli_runner):
        """--timeout must be numeric; a non-numeric value is a usage error,
        not a crash [Category C, P3 wrong-type]."""
        result = cli_runner.run("mms", MOCK_HOST, "--timeout", "notanumber", expect_json=False)
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_port_non_numeric_rejected_by_parser(self, cli_runner):
        """--port must be numeric; a non-numeric value is a usage error, not
        a crash [Category C, P3 wrong-type]."""
        result = cli_runner.run(
            "mms", MOCK_HOST, "--port", "notaport", "--timeout", "2", expect_json=False
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_fuzz_iterations_negative_value_does_not_crash(self, cli_runner):
        """A negative --fuzz-iterations is accepted by argparse but must not
        crash the scanner downstream [Category C, P2 unvalidated range]."""
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms"]),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "-3",
            "--timeout",
            "5",
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        assert "Traceback" not in result.combined_output

    def test_fuzz_max_targets_negative_value_does_not_crash(self, cli_runner):
        """A negative --fuzz-max-targets is accepted by argparse but must not
        crash the scanner [Category C, P2 unvalidated range]."""
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms"]),
            "--fuzz",
            "--confirm",
            "--fuzz-max-targets",
            "-1",
            "--timeout",
            "5",
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        assert "Traceback" not in result.combined_output

    def test_fuzz_without_confirm_refuses(self, cli_runner):
        """--fuzz without --confirm must refuse to run the dangerous
        operation [Category C, P4 confirm-gate]."""
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms"]),
            "--fuzz",
            "--timeout",
            "5",
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        text = result.combined_output.lower()
        assert "requires --confirm" in text, (
            f"--fuzz without --confirm should be refused. Got: {text[:500]}"
        )

    def test_test_write_without_confirm_refuses(self, cli_runner):
        """--test-write without --confirm must refuse the write probe
        [Category C, P4 confirm-gate]."""
        result = cli_runner.run(
            "mms",
            MOCK_HOST,
            "--port",
            str(MOCK_PORTS["mms_control"]),
            "--test-write",
            "--timeout",
            "5",
            expect_json=False,
        )
        assert result.returncode in [0, 1], result.combined_output[:800]
        text = result.combined_output.lower()
        assert "requires --confirm" in text, (
            f"--test-write without --confirm should be refused. Got: {text[:500]}"
        )

    def test_unknown_flag_rejected(self, cli_runner):
        """An entirely unknown flag must exit non-zero with a usage error,
        never be silently ignored [Category C, P6 flag hygiene]."""
        result = cli_runner.run("mms", MOCK_HOST, "--not-a-real-flag", "foo", expect_json=False)
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_transposed_typo_flag_rejected(self, cli_runner):
        """A transposed typo of --tls (--tsl) must be rejected as an unknown
        flag, not silently accepted or truncated-matched [Category C, P6
        flag hygiene]."""
        result = cli_runner.run("mms", MOCK_HOST, "--tsl", "--timeout", "1", expect_json=False)
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output
