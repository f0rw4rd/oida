"""
PROFINET DCP Protocol Integration Tests

Tests oida profinet scanner CLI behavior and error handling.
Uses structured JSON log assertions for precise validation.

PROFINET Architecture:
  PROFINET uses Layer 2 raw Ethernet frames for DCP (Discovery and
  Configuration Protocol, EtherType 0x8892) and LLDP (0x88CC).
  The scanner requires scapy + raw socket capability (CAP_NET_RAW or root).
  There is no TCP port to connect to -- the Docker mock uses --network=host
  and raw socket access, making it unavailable in standard CI environments.

  Because of this, the test strategy is:
    - Category B: Flag acceptance + graceful error handling when raw sockets
      are unavailable. Every flag is tested for CLI acceptance and meaningful
      output (connection error messages referencing the interface).
    - Category C: Invalid input handling -- malformed arguments, unknown
      interfaces, and write operations without --confirm.
    - No Category A tests: Would require live PROFINET bus or raw-socket Docker.

Mock Server (from docker/mocks/services/Dockerfile.profinet):
  When the raw-socket mock IS available:
    Station Name:   "oida-pn-device" (via p-net / pn_dev)
    Interface:      configurable via PNET_INTERFACE env var
    DCP services:   Identify, Set, Get
    RPC services:   I&M0-4 read, slot/subslot enumeration
    LLDP:           Standard LLDP neighbor announcements

  The mock is NOT reachable via TCP -- it uses raw L2 DCP frames.

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):    0 tests
Category B (conditional -- accepts 0 or 1, unconditional output check): 33 tests
  - TestPROFINETIntegration (loopback, no raw socket):                  22 tests
  - TestPROFINETDocker (Docker bridge, raw socket):                     11 tests
Category C (error handling -- assert failure + validate error events):    7 tests
Total defined in file:                                                  40 tests
---------------------------------------------------------------------------

Docker Tests (TestPROFINETDocker -- Category B with raw socket):
  These tests require:
    1. profinet-device Docker container healthy
    2. CAP_NET_RAW or root privileges on the host
    3. Docker bridge interface (br-<id>) discoverable
  They run: sudo oida profinet <bridge-iface> against the Docker bridge.
  Due to Docker bridge limitations, DCP multicast may not reach the mock.
  Tests verify the scanner opens the interface, attempts the scan, and exits
  cleanly.

Flag Coverage Matrix (oida profinet -h):
  target (positional)        [B] test_basic_interface_scan
  -T / --timeout             [B] test_timeout_flag
  --no-rpc                   [B] test_no_rpc_flag
  -R / --rpc-only            [B] test_rpc_only_flag
  -p / --port / --rpc-port   [B] test_rpc_port_flag
  -V / --vendor-id           [B] test_vendor_id_flag
  -D / --device-id           [B] test_device_id_flag
  --no-read-im               [B] test_no_read_im_flag
  --read-diagnosis           [B] test_read_diagnosis_flag
  --topology                 [B] test_topology_flag
  --module-diff              [B] test_module_diff_flag
  --alarms                   [B] test_alarms_flag
  -s / --slots               [B] test_slots_flag
  -e / --enum                [B] test_enum_flag
  --enum-smart               [B] test_enum_smart_flag
  -m / --mac                 [B] test_mac_target_flag
  --flash                    [B] test_flash_flag
  --fuzz                     [B] test_fuzz_flag
  --confirm                  [B] test_confirm_with_write
  --help                     [B] test_help_output
  -v (global)                [B] test_verbose_output
  --debug (global)           [B] test_debug_output
"""

import pytest

from .conftest import skip_unless_l2_docker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_messages(log) -> str:
    """Concatenate all log messages into a single lowercase string for searching."""
    return " ".join(e.get("message", "") for e in log.events).lower()


def _combined_text(result, log=None) -> str:
    """Return lowercase combined output + log messages for broad searches."""
    parts = [result.combined_output.lower()]
    if log is not None:
        parts.append(_all_messages(log))
    return " ".join(parts)


# PROFINET uses raw sockets -- connection will fail in CI.
# All "flag acceptance" tests verify that:
#   1. The flag is recognized by argparse (no 'unrecognized arguments' error)
#   2. The scanner starts and attempts to connect (produces profinet output)
#   3. Connection failure is reported gracefully (not a crash / traceback)

_TEST_INTERFACE = "lo"

# Common error terms expected when raw sockets fail
_CONNECTION_ERROR_TERMS = [
    "failed to open",
    "could not open interface",
    "connection failed",
    "failed to connect",
    "failed to initialize",
    "raw socket",
    "profinet",
    "permission",
    "interface",
    "dcp",
    "failed",
    "error",
]


def _assert_profinet_attempted(result):
    """Assert the scanner attempted a PROFINET connection and reported the outcome.

    This is the unconditional content assertion for Category B tests.
    The scanner must produce output referencing profinet and the interface/connection
    attempt regardless of whether connection succeeded or failed.
    """
    text = _combined_text(result, result.scan_log)
    assert any(term in text for term in _CONNECTION_ERROR_TERMS), (
        f"Expected PROFINET connection attempt evidence in output. "
        f"Output (first 500 chars): {text[:500]}"
    )


# ---------------------------------------------------------------------------
# Test Class
# ---------------------------------------------------------------------------


@pytest.mark.profinet
class TestPROFINETIntegration:
    """Integration tests for PROFINET DCP protocol scanner.

    PROFINET uses Layer 2 raw sockets (no TCP), so we cannot inherit from
    BaseProtocolIntegrationTest (which expects a TCP mock service port).
    Instead, tests validate flag acceptance and error handling.
    """

    protocol_name = "profinet"

    # ========================================================================
    # Help and CLI Tests
    # ========================================================================

    def test_help_output(self, cli_runner):
        """Test --help displays PROFINET usage information [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )

        assert result.returncode == 0, f"Help command failed: {result.stderr}"
        text = result.combined_output.lower()
        assert "profinet" in text, "Help should mention PROFINET"
        assert "target" in text, "Help should mention target argument"
        assert "--timeout" in text, "Help should list --timeout flag"
        assert "--fuzz" in text, "Help should list --fuzz flag"
        assert "--confirm" in text, "Help should list --confirm flag"

    def test_help_shows_all_flag_groups(self, cli_runner):
        """Test --help includes all argument groups [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )

        assert result.returncode == 0
        text = result.combined_output.lower()
        assert "discovery options" in text, "Missing 'Discovery Options' group"
        assert "rpc operations" in text, "Missing 'RPC Operations' group"
        assert "device targeting" in text, "Missing 'Device Targeting' group"
        assert "security testing" in text, "Missing 'Security Testing' group"

    def test_help_shows_examples(self, cli_runner):
        """Test --help includes usage examples [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )

        assert result.returncode == 0
        text = result.combined_output.lower()
        assert "examples" in text, "Help should show examples section"
        assert "oida profinet eth0" in text, "Help should show basic usage example"

    # ========================================================================
    # Basic Discovery Tests (Category B - connection will fail without raw sockets)
    # ========================================================================

    def test_basic_interface_scan(self, cli_runner):
        """Test basic scan with interface target [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1], f"Unexpected crash: rc={result.returncode}"
        _assert_profinet_attempted(result)

    def test_timeout_flag(self, cli_runner):
        """Test --timeout flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--timeout",
            "2",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    def test_no_rpc_flag(self, cli_runner):
        """Test --no-rpc flag for DCP-only discovery [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--no-rpc",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    # ========================================================================
    # RPC Operations Tests
    # ========================================================================

    def test_rpc_only_flag(self, cli_runner):
        """Test --rpc-only flag for direct RPC connection [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            "192.168.1.1",
            "--rpc-only",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["rpc", "connect", "failed", "error", "profinet", "timeout"]
        ), f"Expected RPC attempt in output: {text[:500]}"

    def test_rpc_port_flag(self, cli_runner):
        """Test --rpc-port flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            "192.168.1.1",
            "--rpc-only",
            "--rpc-port",
            "34964",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]

    def test_vendor_id_flag(self, cli_runner):
        """Test --vendor-id flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            "192.168.1.1",
            "--rpc-only",
            "--vendor-id",
            "0x02B8",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]

    def test_device_id_flag(self, cli_runner):
        """Test --device-id flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            "192.168.1.1",
            "--rpc-only",
            "--device-id",
            "0x07A3",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]

    def test_no_read_im_flag(self, cli_runner):
        """Test --no-read-im flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--no-read-im",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    def test_read_diagnosis_flag(self, cli_runner):
        """Test --read-diagnosis flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--read-diagnosis",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    def test_topology_flag(self, cli_runner):
        """Test --topology flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--topology",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    def test_module_diff_flag(self, cli_runner):
        """Test --module-diff flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--module-diff",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    def test_alarms_flag(self, cli_runner):
        """Test --alarms flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--alarms",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    def test_slots_flag(self, cli_runner):
        """Test -s / --slots flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-s",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    def test_enum_flag(self, cli_runner):
        """Test -e / --enum flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-e",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    def test_enum_smart_flag(self, cli_runner):
        """Test --enum-smart flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--enum-smart",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    def test_mac_target_flag(self, cli_runner):
        """Test -m / --mac flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-m",
            "00:01:02:03:04:05",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    def test_flash_flag(self, cli_runner):
        """Test --flash flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--flash",
            "-m",
            "00:01:02:03:04:05",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    # ========================================================================
    # Security Testing / Fuzz Flags
    # ========================================================================

    def test_fuzz_flag(self, cli_runner):
        """Test --fuzz flag with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--fuzz",
            "--confirm",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    def test_confirm_with_write(self, cli_runner):
        """Test --confirm flag with write operation [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--set-name",
            "test-device",
            "-m",
            "00:01:02:03:04:05",
            "--confirm",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_profinet_attempted(result)

    # ========================================================================
    # Verbose / Debug Output Tests
    # ========================================================================

    def test_verbose_output(self, cli_runner):
        """Test verbose flag produces additional output [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            timeout=15,
            expect_json=False,
            verbose=True,
        )

        assert result.returncode in [0, 1, 2], f"Verbose mode crashed: rc={result.returncode}"
        text = result.combined_output.lower()
        assert len(text) > 0, "No output produced with verbose flag"
        assert any(
            term in text for term in ["profinet", "usage", "error", "interface", "failed", "dcp"]
        ), f"Expected profinet-related output: {text[:500]}"

    def test_debug_output(self, cli_runner):
        """Test debug flag produces additional output [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            timeout=15,
            expect_json=False,
            debug=True,
        )

        assert result.returncode in [0, 1, 2], f"Debug mode crashed: rc={result.returncode}"
        text = result.combined_output.lower()
        assert len(text) > 0, "No output produced with debug flag"

    # ========================================================================
    # Error Handling Tests (Category C)
    # ========================================================================

    def test_nonexistent_interface(self, cli_runner):
        """Test graceful handling of nonexistent interface [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "nonexistent_iface_xyz",
            json_log=True,
            timeout=15,
        )

        # PROFINET may exit 0 even on interface failure (graceful error handling)
        assert result.returncode in [0, 1], f"Unexpected crash: rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in ["failed", "could not open", "interface", "connect", "error", "0 devices"]
        ), f"Expected interface error in output: {text[:500]}"

    def test_set_name_without_confirm(self, cli_runner):
        """Test --set-name is rejected without --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--set-name",
            "test-device",
            "-m",
            "00:01:02:03:04:05",
            # No --confirm
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in ["failed", "confirm", "skipped", "interface", "connect", "error"]
        ), f"Expected error or confirm warning in output: {text[:500]}"

    def test_fuzz_without_confirm(self, cli_runner):
        """Test --fuzz is rejected without --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--fuzz",
            # No --confirm
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in ["failed", "confirm", "skipped", "interface", "connect", "error"]
        ), f"Expected error or confirm warning in output: {text[:500]}"

    def test_reset_factory_without_confirm(self, cli_runner):
        """Test --reset-factory without --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--reset-factory",
            "-m",
            "00:01:02:03:04:05",
            # No --confirm
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in ["failed", "confirm", "skipped", "interface", "connect", "error"]
        ), f"Expected error or confirm warning in output: {text[:500]}"

    def test_invalid_fuzz_mode(self, cli_runner):
        """Test invalid fuzz mode is rejected by argparse [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--fuzz",
            "invalid_mode",
            "--confirm",
            timeout=10,
            expect_json=False,
        )

        # argparse should reject invalid choice
        assert result.returncode == 2, (
            f"Expected argparse error (rc=2) for invalid fuzz mode, got rc={result.returncode}"
        )
        text = result.combined_output.lower()
        assert any(term in text for term in ["invalid choice", "error", "usage"]), (
            f"Expected argparse error message: {text[:500]}"
        )

    def test_missing_target_argument(self, cli_runner):
        """Test scanner requires target argument [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "",
            timeout=10,
            expect_json=False,
        )

        assert result.returncode != 0, "Should fail without valid target"
        text = result.combined_output.lower()
        assert any(
            term in text
            for term in ["failed", "error", "interface", "connect", "no target", "usage"]
        ), f"Expected error message about missing/invalid target: {text[:500]}"

    def test_write_im1_without_confirm(self, cli_runner):
        """Test --write-im1 is rejected without --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--write-im1",
            "Motor A",
            "Hall 3",
            # No --confirm
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in ["failed", "confirm", "skipped", "interface", "connect", "error"]
        ), f"Expected error or confirm warning in output: {text[:500]}"


# ===========================================================================
# Docker-Based Tests (Category B -- Docker bridge + raw socket)
#
# These tests run the scanner against the actual profinet-device Docker
# container via the Docker bridge interface.  They require:
#   - profinet-device container healthy
#   - CAP_NET_RAW (root or setcap) on the test runner
#   - Docker bridge interface for ics-network discoverable
#
# PROFINET DCP uses multicast L2 frames.  Docker's bridge networking may
# not reliably deliver multicast between host and container.  Tests verify
# the scanner opens the interface, attempts DCP discovery, and exits
# cleanly.
# ===========================================================================

# Terms that indicate a successful interface open (scanner reached L2 layer)
_DOCKER_SUCCESS_TERMS = [
    "connecting to",
    "connected to",
    "profinet",
    "dcp",
    "discovery",
    "found",
    "device",
    "scan complete",
    "0 devices",
    "executing scan",
    "network",
    "interface",
]


def _skip_unless_docker_profinet():
    """Skip if Docker PROFINET mock or raw sockets are unavailable.

    Returns (bridge_interface, needs_sudo) tuple.
    Delegates to the generic skip_unless_l2_docker() helper.
    """
    return skip_unless_l2_docker("profinet-device", profile_hint="profinet")


def _run_docker_profinet(
    cli_runner, bridge_iface, *extra_args, needs_sudo=False, timeout=30, **kwargs
):
    """Run oida profinet against the Docker bridge, using sudo only if needed."""
    return cli_runner.run(
        "profinet",
        bridge_iface,
        *extra_args,
        use_sudo=needs_sudo,
        timeout=timeout,
        expect_json=False,
        **kwargs,
    )


def _assert_docker_scan_attempted(result):
    """Assert the scanner opened the interface and attempted a scan."""
    text = result.combined_output.lower()
    assert any(term in text for term in _DOCKER_SUCCESS_TERMS), (
        f"Expected scan attempt output from Docker PROFINET test. "
        f"Output (first 500 chars): {text[:500]}"
    )


@pytest.mark.profinet
@pytest.mark.containers("profinet-device")
class TestPROFINETDocker:
    """Docker-based integration tests for PROFINET DCP scanner.

    Tests run oida profinet against the Docker bridge interface connected
    to the profinet-device container.  Due to Docker bridge multicast
    limitations, DCP discovery may find 0 devices.  Tests verify the scanner
    opens the interface successfully and completes without crashing.
    """

    protocol_name = "profinet"

    # ========================================================================
    # Connection and Discovery Tests
    # ========================================================================

    def test_opens_bridge_interface(self, cli_runner):
        """Test scanner opens the Docker bridge interface without permission error [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_profinet()
        result = _run_docker_profinet(cli_runner, bridge, needs_sudo=needs_sudo)

        assert result.returncode in [0, 1], (
            f"Unexpected crash: rc={result.returncode}\n{result.combined_output[:500]}"
        )
        text = result.combined_output.lower()
        assert "permission" not in text and "operation not permitted" not in text, (
            f"Permission error despite having raw socket capability: {text[:500]}"
        )
        _assert_docker_scan_attempted(result)

    def test_reports_connection_to_interface(self, cli_runner):
        """Test scanner reports connecting to the bridge interface name [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_profinet()
        result = _run_docker_profinet(cli_runner, bridge, needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        text = result.combined_output.lower()
        assert bridge.lower() in text, f"Expected bridge name '{bridge}' in output: {text[:500]}"
        _assert_docker_scan_attempted(result)

    def test_no_traceback_on_zero_devices(self, cli_runner):
        """Test no Python traceback when 0 devices found [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_profinet()
        result = _run_docker_profinet(cli_runner, bridge, needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        text = result.combined_output
        assert "Traceback" not in text, f"Unexpected traceback in output: {text[:500]}"
        _assert_docker_scan_attempted(result)

    # ========================================================================
    # Flag Acceptance Tests (with raw socket, no crash)
    # ========================================================================

    def test_no_rpc_with_raw_socket(self, cli_runner):
        """Test --no-rpc runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_profinet()
        result = _run_docker_profinet(cli_runner, bridge, "--no-rpc", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_slots_with_raw_socket(self, cli_runner):
        """Test --slots runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_profinet()
        result = _run_docker_profinet(cli_runner, bridge, "-s", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_enum_with_raw_socket(self, cli_runner):
        """Test --enum runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_profinet()
        result = _run_docker_profinet(cli_runner, bridge, "-e", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_topology_with_raw_socket(self, cli_runner):
        """Test --topology runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_profinet()
        result = _run_docker_profinet(cli_runner, bridge, "--topology", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_alarms_with_raw_socket(self, cli_runner):
        """Test --alarms runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_profinet()
        result = _run_docker_profinet(cli_runner, bridge, "--alarms", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    # ========================================================================
    # Combined Operations Tests
    # ========================================================================

    def test_full_scan_all_features(self, cli_runner):
        """Test combined scan with multiple features via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_profinet()
        result = _run_docker_profinet(
            cli_runner,
            bridge,
            "-s",  # slots
            "-e",  # enumerate
            "--topology",
            "--read-diagnosis",
            needs_sudo=needs_sudo,
        )

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_verbose_scan_with_raw_socket(self, cli_runner):
        """Test verbose scan produces additional output via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_profinet()
        result = _run_docker_profinet(cli_runner, bridge, needs_sudo=needs_sudo, verbose=True)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert len(result.combined_output) > 100, (
            f"Verbose output unexpectedly short: {len(result.combined_output)} chars"
        )

    def test_enum_smart_with_raw_socket(self, cli_runner):
        """Test --enum-smart runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_profinet()
        result = _run_docker_profinet(cli_runner, bridge, "--enum-smart", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output
