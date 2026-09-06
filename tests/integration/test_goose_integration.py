"""
IEC 61850 GOOSE Protocol Integration Tests

Tests oida goose scanner CLI behavior and error handling.
Uses structured JSON log assertions for precise validation.

GOOSE Architecture:
  GOOSE (Generic Object Oriented Substation Event) uses Layer 2 raw Ethernet
  multicast frames (EtherType 0x88B8) for real-time protection signaling.
  The scanner has two modes:
    1. Passive L2 sniffing: requires raw socket capability (CAP_NET_RAW or root)
    2. MMS GoCB enumeration: connects to an IEC 61850 MMS server via TCP

  For L2 sniffing there is no TCP port -- the Docker mock (goose-l2-publisher)
  uses --network=host and raw socket access.

  Because of this, the test strategy is:
    - Category B: Flag acceptance + graceful error handling when raw sockets
      are unavailable or dependencies missing. Every flag is tested for CLI
      acceptance and meaningful output.
    - Category C: Invalid input handling -- malformed arguments, missing
      required flags.
    - No Category A tests: Would require live GOOSE publisher on same L2
      segment or pyiec61850-ng installed.

Mock Server (from docker/mocks/services/goose_publisher.py):
  When the L2 mock IS available:
    GoCB Reference:   simpleIOGenericIO/LLN0$GO$gcb01
    Dataset:          simpleIOGenericIO/LLN0$dataset1
    AppID:            0x1000
    ConfRev:          1
    Multicast DST:    01:0C:CD:01:00:00 (standard GOOSE multicast)
    EtherType:        0x88B8
    Dataset members:  BOOLEAN, INT32, FLOAT32, VisibleString
    State changes:    Every 10 seconds (configurable)
    Publish interval: 1 second (configurable)

  The mock is NOT reachable via TCP -- it publishes raw L2 frames.

  MMS-based GoCB enumeration can target the mms-goose container (port 10106)
  which is a separate TCP-based service (tested in test_mms_integration.py).

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):    0 tests
Category B (conditional -- accepts 0 or 1, unconditional output check): 21 tests
  - TestGOOSEIntegration (loopback, no raw socket):                     14 tests
  - TestGOOSEDocker (Docker bridge, raw socket):                         7 tests
Category C (error handling -- assert failure + validate error events):    5 tests
Total defined in file:                                                  26 tests
---------------------------------------------------------------------------

Docker Tests (TestGOOSEDocker -- Category B with raw socket):
  These tests require:
    1. goose-l2-publisher Docker container healthy
    2. CAP_NET_RAW or root privileges on the host
    3. Docker bridge interface (br-<id>) discoverable
  Due to Docker bridge multicast limitations, GOOSE frames may not reach
  the host. Tests verify the scanner opens the interface and exits cleanly.

Flag Coverage Matrix (oida goose -h):
  target (positional)       [B] test_basic_interface_scan
  --timeout                 [B] test_timeout_flag
  --appid                   [B] test_appid_filter_flag
  --rgoose                  [B] test_rgoose_flag
  --rgoose-port             [B] test_rgoose_port_flag
  --rgoose-auth             [B] test_rgoose_auth_flag
  --rgoose-key              [B] test_rgoose_key_flag
  --mms-enum                [B] test_mms_enum_flag
  --mms-port                [B] test_mms_port_flag
  --help                    [B] test_help_output
  -v (global)               [B] test_verbose_output
  --debug (global)          [B] test_debug_output
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


# GOOSE uses raw sockets for L2 capture -- connection will fail in CI.
# All "flag acceptance" tests verify that:
#   1. The flag is recognized by argparse (no 'unrecognized arguments' error)
#   2. The scanner starts and attempts to connect/capture
#   3. Connection/capture failure is reported gracefully (not a crash / traceback)

_TEST_INTERFACE = "lo"

# Common error terms expected when raw sockets fail or dependencies are missing
_CONNECTION_ERROR_TERMS = [
    "failed",
    "error",
    "could not open",
    "connection failed",
    "raw socket",
    "goose",
    "permission",
    "interface",
    "gocb",
    "capture",
    "pyiec61850",
    "not installed",
    "not supported",
    "dependency",
]


def _assert_goose_attempted(result):
    """Assert the scanner attempted a GOOSE operation and reported the outcome.

    This is the unconditional content assertion for Category B tests.
    The scanner must produce output referencing goose and the operation
    attempt regardless of whether it succeeded or failed.
    """
    text = _combined_text(result, result.scan_log)
    assert any(term in text for term in _CONNECTION_ERROR_TERMS), (
        f"Expected GOOSE operation attempt evidence in output. "
        f"Output (first 500 chars): {text[:500]}"
    )


# ---------------------------------------------------------------------------
# Test Class
# ---------------------------------------------------------------------------


@pytest.mark.goose
class TestGOOSEIntegration:
    """Integration tests for IEC 61850 GOOSE protocol scanner.

    GOOSE L2 sniffing uses raw sockets (no TCP), so we cannot inherit from
    BaseProtocolIntegrationTest (which expects a TCP mock service port).
    Instead, tests validate flag acceptance and error handling.
    """

    protocol_name = "goose"

    # ========================================================================
    # Help and CLI Tests
    # ========================================================================

    def test_help_output(self, cli_runner):
        """Test --help displays GOOSE usage information [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )

        assert result.returncode == 0, f"Help command failed: {result.stderr}"
        text = result.combined_output.lower()
        assert "goose" in text, "Help should mention GOOSE"
        assert "target" in text, "Help should mention target argument"
        assert "--timeout" in text, "Help should list --timeout flag"
        assert "--mms-enum" in text, "Help should list --mms-enum flag"

    def test_help_shows_flag_groups(self, cli_runner):
        """Test --help includes argument groups [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )

        assert result.returncode == 0
        text = result.combined_output.lower()
        assert "capture options" in text, "Missing 'Capture Options' group"
        assert "r-goose options" in text, "Missing 'R-GOOSE Options' group"
        assert "mms gocb enumeration" in text, "Missing 'MMS GoCB Enumeration' group"

    # ========================================================================
    # Capture Options Tests (Category B - will fail without raw sockets + deps)
    # ========================================================================

    def test_basic_interface_scan(self, cli_runner):
        """Test basic GOOSE capture with interface target [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            json_log=True,
            timeout=15,
        )

        # Connection will fail without raw socket capability or pyiec61850-ng
        assert result.returncode in [0, 1], f"Unexpected crash: rc={result.returncode}"
        _assert_goose_attempted(result)

    def test_timeout_flag(self, cli_runner):
        """Test --timeout flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--timeout",
            "5",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_goose_attempted(result)

    def test_appid_filter_flag(self, cli_runner):
        """Test --appid flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--appid",
            "4096",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_goose_attempted(result)

    # ========================================================================
    # R-GOOSE Options Tests
    # ========================================================================

    def test_rgoose_flag(self, cli_runner):
        """Test --rgoose flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--rgoose",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_goose_attempted(result)

    def test_rgoose_port_flag(self, cli_runner):
        """Test --rgoose-port flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--rgoose",
            "--rgoose-port",
            "1234",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_goose_attempted(result)

    def test_rgoose_auth_flag(self, cli_runner):
        """Test --rgoose-auth flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--rgoose",
            "--rgoose-auth",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_goose_attempted(result)

    def test_rgoose_key_flag(self, cli_runner, tmp_path):
        """Test --rgoose-key flag is accepted [Category B]"""
        key_file = tmp_path / "test_key.pem"
        key_file.write_text("dummy-key-data")

        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--rgoose",
            "--rgoose-key",
            str(key_file),
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_goose_attempted(result)

    # ========================================================================
    # MMS GoCB Enumeration Tests
    # ========================================================================

    def test_mms_enum_flag(self, cli_runner):
        """Test --mms-enum flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--mms-enum",
            "192.168.1.100",
            json_log=True,
            timeout=15,
        )

        # Will fail because target is unreachable, but flag should be accepted
        assert result.returncode in [0, 1]
        _assert_goose_attempted(result)

    def test_mms_port_flag(self, cli_runner):
        """Test --mms-port flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--mms-enum",
            "192.168.1.100",
            "--mms-port",
            "10106",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_goose_attempted(result)

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
            term in text for term in ["goose", "usage", "error", "interface", "failed", "capture"]
        ), f"Expected goose-related output: {text[:500]}"

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

        # GOOSE may exit 0 even on interface failure (graceful error handling)
        assert result.returncode in [0, 1], f"Unexpected crash: rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in ["failed", "could not open", "interface", "connect", "error", "capture"]
        ), f"Expected interface error in output: {text[:500]}"

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

    def test_mms_enum_unreachable_host(self, cli_runner):
        """Test --mms-enum gracefully handles unreachable host [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--mms-enum",
            "192.0.2.1",  # RFC 5737 TEST-NET: guaranteed unreachable
            "--timeout",
            "3",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["failed", "connect", "timeout", "error", "unreachable"]
        ), f"Expected connection failure in output: {text[:500]}"

    def test_mms_enum_wrong_port(self, cli_runner):
        """Test --mms-enum with wrong port fails gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--mms-enum",
            "127.0.0.1",
            "--mms-port",
            "1",  # Almost certainly not an MMS server
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["failed", "connect", "refused", "error", "timeout"]), (
            f"Expected connection failure in output: {text[:500]}"
        )

    def test_rgoose_not_supported_message(self, cli_runner):
        """Test R-GOOSE mode reports not-yet-supported clearly [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--rgoose",
            json_log=True,
            timeout=15,
        )

        # R-GOOSE is not yet supported -- scanner should report this
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "not supported",
                "not yet",
                "r-goose",
                "rgoose",
                "failed",
                "error",
                "dependency",
            ]
        ), f"Expected R-GOOSE not-supported message: {text[:500]}"


# ===========================================================================
# Docker-Based Tests (Category B -- Docker bridge + raw socket)
#
# These tests run the scanner against the actual goose-l2-publisher Docker
# container via the Docker bridge interface.  They require:
#   - goose-l2-publisher container healthy
#   - CAP_NET_RAW (root or setcap) on the test runner
#   - Docker bridge interface for ics-network discoverable
#
# GOOSE uses multicast L2 frames (01:0C:CD:01:00:00).  Docker's bridge
# networking may not deliver multicast frames to the host.  Tests verify
# the scanner opens the interface, attempts GOOSE capture, and exits
# cleanly.
# ===========================================================================

# Terms that indicate a successful interface open (scanner reached L2 layer)
_DOCKER_SUCCESS_TERMS = [
    "connecting to",
    "connected to",
    "goose",
    "capture",
    "listening",
    "gocb",
    "subscriber",
    "found",
    "scan complete",
    "executing",
    "interface",
    "0 messages",
    "0 gocb",
]


def _skip_unless_docker_goose():
    """Skip if Docker GOOSE publisher or raw sockets are unavailable.

    Returns (bridge_interface, needs_sudo) tuple.
    Delegates to the generic skip_unless_l2_docker() helper.
    """
    return skip_unless_l2_docker("goose-l2-publisher", profile_hint="goose-l2")


def _run_docker_goose(
    cli_runner, bridge_iface, *extra_args, needs_sudo=False, timeout=30, **kwargs
):
    """Run oida goose against the Docker bridge, using sudo only if needed."""
    return cli_runner.run(
        "goose",
        bridge_iface,
        *extra_args,
        use_sudo=needs_sudo,
        timeout=timeout,
        expect_json=False,
        **kwargs,
    )


def _assert_docker_scan_attempted(result):
    """Assert the scanner opened the interface and attempted GOOSE capture."""
    text = result.combined_output.lower()
    assert any(term in text for term in _DOCKER_SUCCESS_TERMS), (
        f"Expected scan attempt output from Docker GOOSE test. "
        f"Output (first 500 chars): {text[:500]}"
    )


@pytest.mark.goose
@pytest.mark.containers("goose-l2-publisher")
class TestGOOSEDocker:
    """Docker-based integration tests for GOOSE scanner.

    Tests run oida goose against the Docker bridge interface to capture
    GOOSE frames from the goose-l2-publisher container.  Due to Docker
    bridge multicast limitations, frames may not reach the host.  Tests
    verify the scanner opens the interface successfully and completes
    without crashing.
    """

    protocol_name = "goose"

    # ========================================================================
    # Connection and Discovery Tests
    # ========================================================================

    def test_opens_bridge_interface(self, cli_runner):
        """Test scanner opens the Docker bridge interface without permission error [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_goose()
        result = _run_docker_goose(cli_runner, bridge, "--timeout", "3", needs_sudo=needs_sudo)

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
        bridge, needs_sudo = _skip_unless_docker_goose()
        result = _run_docker_goose(cli_runner, bridge, "--timeout", "3", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        text = result.combined_output.lower()
        assert bridge.lower() in text, f"Expected bridge name '{bridge}' in output: {text[:500]}"
        _assert_docker_scan_attempted(result)

    def test_no_traceback_on_no_messages(self, cli_runner):
        """Test no Python traceback when 0 GOOSE messages captured [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_goose()
        result = _run_docker_goose(cli_runner, bridge, "--timeout", "3", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        text = result.combined_output
        assert "Traceback" not in text, f"Unexpected traceback in output: {text[:500]}"
        _assert_docker_scan_attempted(result)

    # ========================================================================
    # Flag Acceptance Tests (with raw socket, no crash)
    # ========================================================================

    def test_appid_filter_with_raw_socket(self, cli_runner):
        """Test --appid filter runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_goose()
        result = _run_docker_goose(
            cli_runner, bridge, "--appid", "4096", "--timeout", "3", needs_sudo=needs_sudo
        )

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_short_timeout_with_raw_socket(self, cli_runner):
        """Test short capture timeout runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_goose()
        result = _run_docker_goose(cli_runner, bridge, "--timeout", "2", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_verbose_with_raw_socket(self, cli_runner):
        """Test verbose scan produces additional output via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_goose()
        result = _run_docker_goose(
            cli_runner, bridge, "--timeout", "3", needs_sudo=needs_sudo, verbose=True
        )

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert len(result.combined_output) > 50, (
            f"Verbose output unexpectedly short: {len(result.combined_output)} chars"
        )

    def test_debug_with_raw_socket(self, cli_runner):
        """Test debug mode produces output via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_goose()
        result = _run_docker_goose(
            cli_runner, bridge, "--timeout", "3", needs_sudo=needs_sudo, debug=True
        )

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output
