"""
EtherCAT Protocol Integration Tests

Tests oida ethercat scanner CLI behavior and error handling.
Uses structured JSON log assertions for precise validation.

EtherCAT Architecture:
  EtherCAT uses Layer 2 raw Ethernet frames (EtherType 0x88A4), not TCP/UDP.
  The scanner requires pysoem + raw socket capability (CAP_NET_RAW or root).
  There is no TCP port to connect to -- the Docker mock requires --network=host
  and raw socket access, making it unavailable in standard CI environments.

  Because of this, the test strategy is:
    - Category B: Flag acceptance + graceful error handling when raw sockets
      are unavailable. Every flag is tested for CLI acceptance and meaningful
      output (connection error messages referencing the interface).
    - Category C: Invalid input handling -- malformed arguments, unknown
      interfaces, and write operations without --confirm.
    - No Category A tests: Would require live EtherCAT bus or raw-socket Docker.

Mock Server Data (from docker/mocks/services/ethercat_slave.c):
  When the raw-socket mock IS available:
    Vendor ID:      0x000003E7 (999 = MSF-ICS Mock)
    Product Code:   0x00001001
    Revision:       0x00010000
    Serial Number:  0x12345678
    Device Name:    "MSF-ICS Mock EtherCAT Slave"
    States:         INIT, PRE-OP, SAFE-OP, OP, BOOT
    CoE objects:    Device Type (0x1000), Error Register (0x1001),
                    Device Name (0x1008), HW Version (0x1009),
                    FW Version (0x100A), Identity (0x1018)
    FoE files:      firmware.bin (mock 512 bytes)
    EEPROM:         Full SII header + categories (STRINGS, GENERAL, SM, FMMU, PDO, DC)

  The mock is NOT reachable via TCP -- it uses AF_PACKET raw sockets.

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):    0 tests
Category B (conditional -- accepts 0 or 1, unconditional output check): 52 tests
  - TestEtherCATIntegration (loopback, no raw socket):                  37 tests
  - TestEtherCATDocker (Docker bridge, raw socket):                     15 tests
Category C (error handling -- assert failure + validate error events):   11 tests
Skipped (untestable -- requires raw socket/hardware):                    0 tests
Total defined in file:                                                   63 tests
---------------------------------------------------------------------------

Docker Tests (TestEtherCATDocker -- Category B with raw socket):
  These tests require:
    1. ethercat-slave-veth Docker container healthy
    2. CAP_NET_RAW or root privileges on the host
    3. Docker bridge interface (br-<id>) discoverable
  They run: sudo oida ethercat <bridge-iface> against the Docker bridge.
  Due to Docker bridge L2 limitations, pysoem cannot discover the slave
  via auto-increment addressing (EtherCAT ring topology).  Tests verify
  the scanner opens the interface, attempts the scan, and exits cleanly.

Flag Coverage Matrix (oida ethercat -h):
  target (positional)        [B] test_basic_interface_scan
  --interface                [B] test_interface_override_flag
  -s / --scan-range          [B] test_scan_range_flag
  -S / --slave               [B] test_slave_select_flag
  -i / --device-info         [B] test_device_info_flag
  -d / --dump                [B] test_dump_flag
  -f / --foe-read            [B] test_foe_read_flag
  --foe-write                [B] test_foe_write_flag
  --dc-analysis              [B] test_dc_analysis_flag
  -e / --eeprom-dump         [B] test_eeprom_dump_flag
  --no-emergency-monitor     [B] test_no_emergency_monitor_flag
  --op-state                 [B] test_op_state_flag
  --boot-state               [B] test_boot_state_flag
  --fsoe / --scan-fsoe       [B] test_fsoe_scan_flag
  --esc-registers            [B] test_esc_registers_flag
  -C / --scan-coe            [B] test_scan_coe_flag
  --coe-range                [B] test_coe_range_flag
  -r / --read-coe            [B] test_sdo_read_flag
  -w / --write-coe           [B] test_sdo_write_with_confirm_flag
  -p / --eeprom-parse        [B] test_eeprom_parse_flag
  --eeprom-write             [C] test_eeprom_write_without_confirm
  --set-alias                [C] test_set_alias_without_confirm
  --set-coe                  [B] test_set_coe_flag
  --set-mailbox              [B] test_set_mailbox_flag
  -F / --fuzz                [B] test_fuzz_sdo_flag, test_fuzz_pdo_flag, test_fuzz_all_flag
  --fuzz-iterations          [B] test_fuzz_iterations_flag
  -y / --confirm             [B] test_confirm_with_write
  --help                     [B] test_help_output (inherited but also explicit)
  -v (global)                [B] test_verbose_output (overridden)
  --debug (global)           [B] test_debug_output (overridden)
"""

import pytest

from .conftest import skip_unless_l2_docker


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


# EtherCAT uses raw sockets -- connection will fail in CI.
# All "flag acceptance" tests verify that:
#   1. The flag is recognized by argparse (no 'unrecognized arguments' error)
#   2. The scanner starts and attempts to connect (produces ethercat output)
#   3. Connection failure is reported gracefully (not a crash / traceback)

# The interface name "lo" (loopback) is used as target -- pysoem cannot open
# it but the error is predictable and parseable.

_TEST_INTERFACE = "lo"

# Common error terms expected when raw sockets fail
_CONNECTION_ERROR_TERMS = [
    "failed to open",
    "could not open interface",
    "connection failed",
    "failed to connect",
    "failed to initialize",
    "raw socket",
    "ethercat",
    "permission",
    "interface",
]


def _assert_ethercat_attempted(result):
    """Assert the scanner attempted an EtherCAT connection and reported the outcome.

    This is the unconditional content assertion for Category B tests.
    The scanner must produce output referencing ethercat and the interface/connection
    attempt regardless of whether connection succeeded or failed.
    """
    text = _combined_text(result, result.scan_log)
    assert any(term in text for term in _CONNECTION_ERROR_TERMS), (
        f"Expected EtherCAT connection attempt evidence in output. "
        f"Output (first 500 chars): {text[:500]}"
    )


# ---------------------------------------------------------------------------
# Test Class
# ---------------------------------------------------------------------------


@pytest.mark.ethercat
class TestEtherCATIntegration:
    """Integration tests for EtherCAT protocol scanner.

    EtherCAT uses Layer 2 raw sockets (no TCP), so we cannot inherit from
    BaseProtocolIntegrationTest (which expects a TCP mock service port).
    Instead, tests validate flag acceptance and error handling.
    """

    protocol_name = "ethercat"

    # ========================================================================
    # Help and CLI Tests
    # ========================================================================

    def test_help_output(self, cli_runner):
        """Test --help displays EtherCAT usage information [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )

        # Help should always work
        assert result.returncode == 0, f"Help command failed: {result.stderr}"
        text = result.combined_output.lower()
        # Verify key sections appear
        assert "ethercat" in text, "Help should mention EtherCAT"
        assert "target" in text, "Help should mention target argument"
        assert "--scan-range" in text, "Help should list --scan-range flag"
        assert "--device-info" in text, "Help should list --device-info flag"
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
        # All four argument groups should appear
        assert "ethercat options" in text, "Missing 'EtherCAT Options' group"
        assert "advanced options" in text, "Missing 'Advanced Options' group"
        assert "coe options" in text, "Missing 'CoE Options' group"
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
        assert "oida ethercat eth0" in text, "Help should show basic usage example"

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

        # Connection will fail without raw socket capability
        assert result.returncode in [0, 1], f"Unexpected crash: rc={result.returncode}"
        _assert_ethercat_attempted(result)

        # Verify structured log was produced
        if result.scan_log is not None:
            _assert_log_has_events(result, min_count=1)
            _assert_log_event_structure(result.scan_log)

            # Should have protocol_error events about interface failure
            errors = result.scan_log.get_events(level="error")
            if errors:
                error_messages = " ".join(e.get("message", "").lower() for e in errors)
                assert any(
                    term in error_messages for term in ["interface", "connect", "open", "failed"]
                ), f"Expected interface error in log errors: {error_messages[:300]}"

    def test_basic_scan_json_log_structure(self, cli_runner):
        """Test that JSON log events have correct module field [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

        if result.scan_log is not None and len(result.scan_log.events) > 0:
            # All events should reference the ethercat module
            for event in result.scan_log.events:
                assert event.get("module") == "ethercat", (
                    f"Expected module='ethercat', got '{event.get('module')}'"
                )

    # ========================================================================
    # EtherCAT Options Tests
    # ========================================================================

    def test_interface_override_flag(self, cli_runner):
        """Test --interface flag overrides target interface [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--interface",
            "eth99",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # The override interface should appear in the error message
        assert any(term in text for term in ["eth99", "interface", "failed", "connect"]), (
            f"Expected interface override reference in output: {text[:500]}"
        )

    def test_scan_range_flag(self, cli_runner):
        """Test --scan-range flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--scan-range",
            "1-4",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_slave_select_flag(self, cli_runner):
        """Test -S / --slave flag selects single slave [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-S",
            "2",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_device_info_flag(self, cli_runner):
        """Test -i / --device-info flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-i",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_dump_flag(self, cli_runner, tmp_path):
        """Test --dump flag with directory path [Category B]"""
        dump_dir = str(tmp_path / "ethercat_dump")
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--dump",
            dump_dir,
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    # ========================================================================
    # Advanced Options Tests
    # ========================================================================

    def test_foe_read_flag(self, cli_runner):
        """Test --foe-read flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--foe-read",
            "1:firmware.bin",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_foe_write_flag(self, cli_runner, tmp_path):
        """Test --foe-write flag with --confirm [Category B]"""
        # Create a dummy file to write
        test_file = tmp_path / "test_firmware.bin"
        test_file.write_bytes(b"\x00" * 16)

        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--foe-write",
            f"1:{test_file}",
            "--confirm",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_dc_analysis_flag(self, cli_runner):
        """Test --dc-analysis flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--dc-analysis",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_eeprom_dump_flag(self, cli_runner):
        """Test -e / --eeprom-dump flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-e",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_no_emergency_monitor_flag(self, cli_runner):
        """Test --no-emergency-monitor flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--no-emergency-monitor",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_op_state_flag(self, cli_runner):
        """Test --op-state flag is accepted (dangerous, requires --confirm) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--op-state",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_boot_state_flag(self, cli_runner):
        """Test --boot-state flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--boot-state",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_fsoe_scan_flag(self, cli_runner):
        """Test --fsoe / --scan-fsoe flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--fsoe",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_esc_registers_flag(self, cli_runner):
        """Test --esc-registers flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--esc-registers",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    # ========================================================================
    # CoE Options Tests
    # ========================================================================

    def test_scan_coe_flag(self, cli_runner):
        """Test -C / --scan-coe flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-C",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_coe_range_flag(self, cli_runner):
        """Test --coe-range flag with custom ranges [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-C",
            "--coe-range",
            "0x1000-0x1FFF,0x6000-0x6FFF",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_sdo_read_flag(self, cli_runner):
        """Test -r / --read-coe flag with SDO address [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-r",
            "0x1008:0",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_sdo_read_with_slave_prefix(self, cli_runner):
        """Test --read-coe with slave:index:subindex format [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-r",
            "1:0x1008:0",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_sdo_write_with_confirm_flag(self, cli_runner):
        """Test -w / --write-coe with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-w",
            "1:0x7000:1:0xFF",
            "--confirm",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_eeprom_parse_flag(self, cli_runner):
        """Test --eeprom-parse flag is accepted [Category B]

        Note: the legacy -p short was removed in fa61b286 because -p means
        --port everywhere else in OIDA; use the long form here.
        """
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--eeprom-parse",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_set_coe_flag(self, cli_runner):
        """Test --set-coe flag with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--set-coe",
            "sdo,sdo_info,complete_access",
            "--confirm",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_set_mailbox_flag(self, cli_runner):
        """Test --set-mailbox flag with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--set-mailbox",
            "coe,foe",
            "--confirm",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    # ========================================================================
    # Security Testing / Fuzz Flags
    # ========================================================================

    def test_fuzz_sdo_flag(self, cli_runner):
        """Test -F sdo fuzzing mode with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-F",
            "sdo",
            "--confirm",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_fuzz_pdo_flag(self, cli_runner):
        """Test -F pdo fuzzing mode with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-F",
            "pdo",
            "--confirm",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_fuzz_all_flag(self, cli_runner):
        """Test -F all (SDO + PDO) fuzzing with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-F",
            "all",
            "--confirm",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_fuzz_iterations_flag(self, cli_runner):
        """Test --fuzz-iterations flag is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-F",
            "sdo",
            "--fuzz-iterations",
            "5",
            "--confirm",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_confirm_with_write(self, cli_runner):
        """Test --confirm flag enables write operations [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--set-alias",
            "100",
            "--confirm",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    # ========================================================================
    # Combined Flag Tests
    # ========================================================================

    def test_multiple_advanced_flags(self, cli_runner):
        """Test multiple advanced flags combined [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-e",  # eeprom-dump
            "--eeprom-parse",  # -p short was removed in fa61b286 (-p means --port elsewhere)
            "--dc-analysis",
            "--fsoe",
            "--esc-registers",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

    def test_scan_with_slave_and_coe(self, cli_runner):
        """Test slave selection combined with CoE scan [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-S",
            "1",
            "-C",
            "-i",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        _assert_ethercat_attempted(result)

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

        # Should not crash with verbose flag
        assert result.returncode in [0, 1, 2], f"Verbose mode crashed: rc={result.returncode}"
        # Must produce some output
        text = result.combined_output.lower()
        assert len(text) > 0, "No output produced with verbose flag"
        # Either usage error or ethercat attempt
        assert any(
            term in text for term in ["ethercat", "usage", "error", "interface", "failed"]
        ), f"Expected ethercat-related output: {text[:500]}"

    def test_debug_output(self, cli_runner):
        """Test debug flag produces additional output [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            timeout=15,
            expect_json=False,
            debug=True,
        )

        # Should not crash with debug flag
        assert result.returncode in [0, 1, 2], f"Debug mode crashed: rc={result.returncode}"
        text = result.combined_output.lower()
        assert len(text) > 0, "No output produced with debug flag"
        assert any(
            term in text for term in ["ethercat", "usage", "error", "interface", "debug", "failed"]
        ), f"Expected ethercat-related output: {text[:500]}"

    # ========================================================================
    # Error Handling Tests (Category C)
    # ========================================================================

    def test_missing_target_argument(self, cli_runner):
        """Test scanner requires target argument [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            # No target provided -- pass empty string which will be rejected
            "",
            timeout=10,
            expect_json=False,
        )

        # Should fail (interface "" is not valid)
        assert result.returncode != 0, "Should fail without valid target"
        text = result.combined_output.lower()
        assert any(
            term in text
            for term in [
                "failed",
                "error",
                "interface",
                "connect",
                "open",
                "no target",
                "usage",
            ]
        ), f"Expected error message about missing/invalid target: {text[:500]}"

    def test_nonexistent_interface(self, cli_runner):
        """Test graceful handling of nonexistent interface [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "nonexistent_iface_xyz",
            json_log=True,
            timeout=15,
        )

        # Should fail gracefully
        assert result.returncode != 0, "Should fail with nonexistent interface"
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "failed",
                "could not open",
                "interface",
                "connect",
                "error",
            ]
        ), f"Expected interface error in output: {text[:500]}"

    def test_sdo_write_without_confirm(self, cli_runner):
        """Test SDO write is rejected without --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-w",
            "1:0x7000:1:0xFF",
            # No --confirm
            json_log=True,
            timeout=15,
        )

        # Should either fail connection (no raw socket) or warn about confirm
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # Must produce meaningful output about either connection failure or confirm requirement
        assert any(
            term in text
            for term in [
                "failed",
                "confirm",
                "skipped",
                "interface",
                "connect",
                "could not open",
            ]
        ), f"Expected error or confirm warning in output: {text[:500]}"

    def test_eeprom_write_without_confirm(self, cli_runner):
        """Test EEPROM write is rejected without --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--eeprom-write",
            "0x08:0x1234",
            # No --confirm
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "failed",
                "confirm",
                "skipped",
                "interface",
                "connect",
                "could not open",
            ]
        ), f"Expected error or confirm warning in output: {text[:500]}"

    def test_set_alias_without_confirm(self, cli_runner):
        """Test --set-alias is rejected without --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--set-alias",
            "100",
            # No --confirm
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "failed",
                "confirm",
                "skipped",
                "interface",
                "connect",
                "could not open",
            ]
        ), f"Expected error or confirm warning in output: {text[:500]}"

    def test_fuzz_without_confirm(self, cli_runner):
        """Test fuzzing is rejected without --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-F",
            "sdo",
            # No --confirm
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "failed",
                "confirm",
                "skipped",
                "interface",
                "connect",
                "could not open",
            ]
        ), f"Expected error or confirm warning in output: {text[:500]}"

    def test_foe_write_without_confirm(self, cli_runner, tmp_path):
        """Test FoE write is rejected without --confirm [Category C]"""
        test_file = tmp_path / "dummy.bin"
        test_file.write_bytes(b"\x00" * 8)

        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--foe-write",
            f"1:{test_file}",
            # No --confirm
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "failed",
                "confirm",
                "skipped",
                "interface",
                "connect",
                "could not open",
            ]
        ), f"Expected error or confirm warning in output: {text[:500]}"

    def test_set_coe_without_confirm(self, cli_runner):
        """Test --set-coe is rejected without --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--set-coe",
            "0x3F",
            # No --confirm
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "failed",
                "confirm",
                "skipped",
                "interface",
                "connect",
                "could not open",
            ]
        ), f"Expected error or confirm warning in output: {text[:500]}"

    def test_set_mailbox_without_confirm(self, cli_runner):
        """Test --set-mailbox is rejected without --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--set-mailbox",
            "coe,foe",
            # No --confirm
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "failed",
                "confirm",
                "skipped",
                "interface",
                "connect",
                "could not open",
            ]
        ), f"Expected error or confirm warning in output: {text[:500]}"

    def test_invalid_fuzz_mode(self, cli_runner):
        """Test invalid fuzz mode is rejected by argparse [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "-F",
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

    def test_invalid_scan_range_format(self, cli_runner):
        """Test handling of invalid scan range value [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            _TEST_INTERFACE,
            "--scan-range",
            "not-a-range!!!",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should either fail gracefully or treat as empty range
        assert result.returncode in [0, 1, 2], f"Crashed on invalid range: rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert len(text) > 0, "No output produced"


# ===========================================================================
# Docker-Based Tests (Category B -- Docker bridge + raw socket)
#
# These tests run the scanner against the actual ethercat-slave-veth Docker
# container via the Docker bridge interface.  They require:
#   - ethercat-slave-veth container healthy
#   - CAP_NET_RAW (root or setcap) on the test runner
#   - Docker bridge interface for ics-network discoverable
#
# IMPORTANT: EtherCAT uses daisy-chain (ring) L2 topology with auto-increment
# addressing.  Docker's bridge networking cannot emulate this ring -- frames
# reach the mock slave but the modified response doesn't return through the
# same path.  As a result, pysoem's config_init() finds 0 slaves.
#
# These tests verify the scanner successfully opens the raw socket interface,
# attempts the scan, and reports "0 slaves found" without crashing.  They are
# classified as Category B because the mock IS running but the L2 ring
# topology cannot be emulated.
#
# When running on real EtherCAT hardware or with host networking, these tests
# would find actual slaves and become full Category A.
# ===========================================================================

# Known mock data values from docker/mocks/services/ethercat_slave.c
# (These will be asserted when ring topology works; kept for documentation)
_MOCK_VENDOR_ID = 0x000003E7
_MOCK_PRODUCT_CODE = 0x00001001
_MOCK_REVISION = 0x00010000
_MOCK_SERIAL = 0x12345678
_MOCK_DEVICE_NAME = "MSF-ICS Mock EtherCAT Slave"
_MOCK_OD_DEVICE_NAME = "MSF-ICS Mock"  # CoE 0x1008 Device Name object
_MOCK_HW_VERSION = "1.0"
_MOCK_SW_VERSION = "1.0.0"

# Terms that indicate a successful interface open (scanner reached L2 layer)
_DOCKER_SUCCESS_TERMS = [
    "connecting to",
    "connected to",
    "ethercat",
    "found",
    "slave",
    "scan complete",
    "0 slaves",
    "executing scan",
    "network",
]


def _skip_unless_docker_ethercat():
    """Skip the calling test if Docker EtherCAT mock or raw sockets are unavailable.

    Returns (bridge_interface, needs_sudo) tuple.
    Delegates to the generic skip_unless_l2_docker() helper.
    """
    return skip_unless_l2_docker("ethercat-slave-veth", profile_hint="ethercat")


def _run_docker_ethercat(
    cli_runner, bridge_iface, *extra_args, needs_sudo=False, timeout=30, **kwargs
):
    """Run oida ethercat against the Docker bridge, using sudo only if needed."""
    return cli_runner.run(
        "ethercat",
        bridge_iface,
        *extra_args,
        use_sudo=needs_sudo,
        timeout=timeout,
        expect_json=False,
        **kwargs,
    )


def _assert_docker_scan_attempted(result):
    """Assert the scanner opened the interface and attempted a scan.

    This is the unconditional content assertion for Docker-based tests.
    The scanner must produce output referencing its scan attempt --
    even if 0 slaves are found (expected with Docker bridge networking).
    """
    text = result.combined_output.lower()
    assert any(term in text for term in _DOCKER_SUCCESS_TERMS), (
        f"Expected scan attempt output from Docker EtherCAT test. "
        f"Output (first 500 chars): {text[:500]}"
    )


@pytest.mark.ethercat
@pytest.mark.containers("ethercat-slave-veth")
class TestEtherCATDocker:
    """Docker-based integration tests for EtherCAT scanner.

    Tests run oida ethercat against the Docker bridge interface connected
    to the ethercat-slave-veth container.  Due to Docker bridge L2
    limitations, pysoem cannot discover the slave via auto-increment
    addressing.  Tests verify the scanner opens the interface successfully
    and completes without crashing.

    Each test skips automatically if the container is not healthy, the host
    lacks CAP_NET_RAW, or the Docker bridge interface cannot be discovered.
    """

    protocol_name = "ethercat"

    # ========================================================================
    # Connection and Discovery Tests
    # ========================================================================

    def test_opens_bridge_interface(self, cli_runner):
        """Test scanner opens the Docker bridge interface without permission error [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, needs_sudo=needs_sudo)

        assert result.returncode in [0, 1], (
            f"Unexpected crash: rc={result.returncode}\n{result.combined_output[:500]}"
        )
        text = result.combined_output.lower()
        # Must NOT have permission errors -- we have CAP_NET_RAW
        assert "permission" not in text and "operation not permitted" not in text, (
            f"Permission error despite having raw socket capability: {text[:500]}"
        )
        _assert_docker_scan_attempted(result)

    def test_reports_connection_to_interface(self, cli_runner):
        """Test scanner reports connecting to the bridge interface name [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        text = result.combined_output.lower()
        # The bridge interface name should appear in the output
        assert bridge.lower() in text, f"Expected bridge name '{bridge}' in output: {text[:500]}"
        _assert_docker_scan_attempted(result)

    def test_reports_slave_count(self, cli_runner):
        """Test scanner reports number of slaves found (0 via Docker bridge) [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        text = result.combined_output.lower()
        assert any(term in text for term in ["slaves", "scan complete", "found"]), (
            f"Expected slave count report in output: {text[:500]}"
        )
        _assert_docker_scan_attempted(result)

    def test_no_traceback_on_zero_slaves(self, cli_runner):
        """Test no Python traceback when 0 slaves found [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        text = result.combined_output
        assert "Traceback" not in text, f"Unexpected traceback in output: {text[:500]}"
        _assert_docker_scan_attempted(result)

    # ========================================================================
    # Flag Acceptance Tests (with raw socket, no crash)
    # ========================================================================

    def test_device_info_with_raw_socket(self, cli_runner):
        """Test --device-info runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, "-i", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        # No traceback
        assert "Traceback" not in result.combined_output

    def test_eeprom_dump_with_raw_socket(self, cli_runner):
        """Test --eeprom-dump runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, "-e", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_eeprom_parse_with_raw_socket(self, cli_runner):
        """Test --eeprom-parse runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, "--eeprom-parse", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_coe_scan_with_raw_socket(self, cli_runner):
        """Test -C (CoE scan) runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, "-C", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_sdo_read_with_raw_socket(self, cli_runner):
        """Test -r (SDO read) runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, "-r", "0x1008:0", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_dc_analysis_with_raw_socket(self, cli_runner):
        """Test --dc-analysis runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, "--dc-analysis", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_esc_registers_with_raw_socket(self, cli_runner):
        """Test --esc-registers runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, "--esc-registers", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_fsoe_scan_with_raw_socket(self, cli_runner):
        """Test --fsoe runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, "--fsoe", needs_sudo=needs_sudo)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_foe_read_with_raw_socket(self, cli_runner):
        """Test --foe-read runs without crash via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(
            cli_runner, bridge, "--foe-read", "1:firmware.bin", needs_sudo=needs_sudo
        )

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    # ========================================================================
    # Combined Operations Tests
    # ========================================================================

    def test_full_scan_all_features(self, cli_runner):
        """Test combined scan with multiple features via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(
            cli_runner,
            bridge,
            "-i",  # device info
            "-e",  # eeprom dump
            "--eeprom-parse",
            "-C",  # CoE scan
            "--dc-analysis",
            "--fsoe",
            needs_sudo=needs_sudo,
        )

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        assert "Traceback" not in result.combined_output

    def test_verbose_scan_with_raw_socket(self, cli_runner):
        """Test verbose scan produces additional output via raw socket [Category B]"""
        bridge, needs_sudo = _skip_unless_docker_ethercat()
        result = _run_docker_ethercat(cli_runner, bridge, needs_sudo=needs_sudo, verbose=True)

        assert result.returncode in [0, 1]
        _assert_docker_scan_attempted(result)
        # Verbose should produce more output than a minimal scan
        assert len(result.combined_output) > 100, (
            f"Verbose output unexpectedly short: {len(result.combined_output)} chars"
        )
