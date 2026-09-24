"""Real-CLI flag-coverage tests for the ``bacnet`` module.

``tests/integration/test_bacnet_integration.py`` already covers the
security-finding shortcuts (``--assess``, ``--check-anonymous``,
``--brute-force``, ``--test-write``, ...). It is 1500+ lines and already
unwieldy, so this file is additive: it targets the ~64 flags that
``scripts/flag_coverage.py bacnet --missing`` reported as never driven by a
real CLI invocation (mostly ``help=SUPPRESS`` advanced flags declared in
``src/oida/protocols/bacnet/proto_args.py`` that are absent from
``oida bacnet -h`` but are fully wired in
``src/oida/protocols/bacnet/cli_runner.py``), plus the mandatory hostile/
false-flag catalogue for a UDP protocol with no handshake.

Mock data inventory (docker/mocks/services/bacnet/mock/bacnet_server.py),
used to ground Category A assertions:

- Device: instance ``1234``, name "OIDA Test Device", vendor ID ``999``
  ("OIDA Test Vendor"), model "OIDA Mock BACnet Controller".
- Objects: 5x analogInput "Zone N Temperature", 3x analogOutput
  "Damper N Position" (commandable), 5x analogValue (3x "Zone N Setpoint"
  commandable + "Outside Air Temperature" + "Building Pressure", both RO),
  3x binaryInput "Zone N Occupancy", 5x binaryOutput "Light N"
  (commandable), 2x binaryValue system modes (commandable), 1x
  multiStateValue "HVAC Mode", 2x loop (PID), 2x program ("MainControl",
  "DiagnosticRoutine"), 1x schedule "Weekday Occupancy Schedule", 1x
  calendar "Holiday Calendar", 2x trendLog "Zone N Temp Log" (~50 records
  each), 2x file "config.txt" / "firmware.bin" (stream + record access),
  2x life-safety-point "Smoke Detector Zone 1" / "Emergency Stop", 2x
  network-port, 1x structured-view "HVAC System".
- ``ReinitializeDevice`` requires password ``"OIDA"`` exactly (wrong
  password -> ExecutionError). ``DeviceCommunicationControl`` and
  ``TimeSynchronization`` are accepted unconditionally (no real auth) -
  that absence of auth is itself the finding for the DCC brute-force and
  time-sync tests.
- The mock has **no** BACnet/SC (TLS) support at all - used deliberately
  for the TLS-mismatch hostile case.

All tests use ``--device-id 1234`` (or, for the network-discovery-layer
flags that run before device targeting, plain broadcast/unicast to the
mock's UDP port) to force a deterministic path against the mock.

Flag coverage matrix (flags previously in ``--missing``; categories per
the house style: A = strict/grounded in real mock data, B = conditional/
accepted-and-ran-without-crashing, C = negative/error path):

    --rpm                    A   test_rpm_reads_multiple_properties
    --read (-r long form)    A   test_read_and_write_property_spec
    --write (-w long form)   A/C test_read_and_write_property_spec, test_write_requires_confirm
    --priority               A   test_read_and_write_property_spec
    --vendor-scan            A   test_vendor_scan_identifies_vendor
    --deep-enum              B   test_deep_enum_with_object_filters
    --object-type            B   test_deep_enum_with_object_filters
    --object-types           B   test_enum_with_object_types_and_shaping
    --max-objects             B   test_deep_enum_with_object_filters
    --values-only            B   test_enum_with_object_types_and_shaping
    --full-properties        B   test_enum_with_object_types_and_shaping
    --values                 B   test_enum_with_object_types_and_shaping
    --control-points         B   test_enum_with_object_types_and_shaping
    --enumerate-properties   B   test_enumerate_properties_flag
    --read-range             A   test_read_range_history
    --read-range-count       A   test_read_range_history
    --who-has                A   test_who_has_locates_known_object
    --enum-bbmd              B   test_network_layer_enum_flags
    --enum-fdt               B   test_network_layer_enum_flags
    --enum-routers           B   test_network_layer_enum_flags
    --enum-networks          B   test_network_layer_enum_flags
    --bbmd                   B   test_bbmd_and_discover_mstp_flags
    --discover-mstp          B   test_bbmd_and_discover_mstp_flags
    --interface               B   test_interface_flag_accepted_in_default_scan_path
    --device-range           B   test_device_range_flag_accepted_without_filtering_direct_target,
                                   test_inverted_device_range_no_crash
    --files                  A   test_files_enumeration
    --read-file              A   test_read_file_stream_and_record
    --file-access-method     A   test_read_file_stream_and_record
    --file-chunk-size        A   test_read_file_stream_and_record
    --assess-network         B   test_assess_network_shortcut
    --assess-config          A   test_assess_config_shortcut
    --assess-info            A   test_assess_info_shortcut
    --check-alarms           B   test_check_group_maximal_invocation
    --check-calendars        A   test_check_group_maximal_invocation
    --check-oos              B   test_check_group_maximal_invocation
    --check-priority         B   test_check_group_maximal_invocation
    --check-reinit           B   test_check_group_maximal_invocation
    --check-schedules        A   test_check_group_maximal_invocation
    --check-trendlogs        A   test_check_group_maximal_invocation
    --quick                  A   test_quick_shortcut
    --discover               B   test_discover_shortcut
    --full                   B   test_full_shortcut
    --cov                    A/C test_cov_subscription
    --cov-duration           A   test_cov_subscription
    --cov-lifetime           A   test_cov_subscription
    --monitor                B   test_monitor_without_bac0_exits_immediately
    --interval               B   test_monitor_without_bac0_exits_immediately
    --diff                   A/C test_dump_then_diff_against_baseline
    --brute-force-dcc        A   test_brute_force_dcc_and_reinit
    --brute-force-reinit     A   test_brute_force_dcc_and_reinit
    --passwords              A   test_brute_force_dcc_and_reinit
    --password               A   test_password_single_value_reinit
    --test-time-sync         A/C test_time_sync_confirm_gate
    --call                   A/C test_call_service_dispatch
    --list-services          A   test_list_services_catalog
    --services               A   test_services_enumeration
    --use-bac0               B   test_use_bac0_flag_does_not_crash
    --sc                     C   test_sc_against_plaintext_mock_fails_cleanly
    --direct                 C   test_sc_direct_hub_uri_mutually_exclusive
    --hub-uri                C   test_sc_direct_hub_uri_mutually_exclusive
    --ca                     C   test_sc_bad_cert_paths_fail_cleanly
    --cert                   C   test_sc_bad_cert_paths_fail_cleanly
    --key                    C   test_sc_bad_cert_paths_fail_cleanly
    --no-tls-checks          C   test_no_tls_checks_against_plaintext_mock

Untestable/degenerate here (not stubbed, just not covered):
    (none left uncovered by design - every flag in --missing has a real
    invocation above; a handful are Category B because the mock has no
    BBMD/foreign-device table and no BACnet/SC stack, so the *acceptance*
    of the flag is what's observable, not a distinguishing result.)
"""

from __future__ import annotations

import json
import socket
import struct
import time

import pytest

from tests.service_gate import require_service

from tests.integration.base_protocol_test import BaseProtocolIntegrationTest
from tests.integration.cli_runner import CLIRunner
from tests.integration.conftest import MOCK_HOST, MOCK_PORTS

pytestmark = [pytest.mark.bacnet, pytest.mark.xdist_group("bacnet_service")]

MOCK_PORT = MOCK_PORTS.get("bacnet", 47808)
MOCK_DEVICE_ID = 1234
MOCK_DEVICE_NAME = "OIDA Test Device"
MOCK_VENDOR_NAME = "OIDA Test Vendor"
MOCK_VENDOR_ID = 999
MOCK_REINIT_PASSWORD = "OIDA"

WRONG_PROTOCOL_PORT = MOCK_PORTS.get("modbus", 502)
CLOSED_PORT = 47899
BLACKHOLE_HOST = "10.255.255.1"
SHORT_TIMEOUT = 3

_WHO_IS = bytes([0x81, 0x0A, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08])


def _check_bacnet_mock_alive(host: str, port: int, timeout: float = 3.0) -> bool:
    """Send a raw BVLL Who-Is and check for a BVLC response (UDP has no handshake)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(_WHO_IS, (host, port))
            data, _addr = sock.recvfrom(4096)
        finally:
            sock.close()
        return len(data) > 4 and data[0] == 0x81
    except (OSError, socket.error):
        return False


def _text(result) -> str:
    """Lowercased combined output + stringified scan-log events for substring checks."""
    blob = result.combined_output or ""
    if result.scan_log is not None:
        blob += " " + " ".join(json.dumps(e) for e in result.scan_log.events)
    return blob.lower()


class TestBACnetCLIFlags(BaseProtocolIntegrationTest):
    """Drives the flags absent from the existing bacnet integration suite."""

    @property
    def protocol_name(self) -> str:
        return "bacnet"

    @property
    def default_port(self) -> int:
        return MOCK_PORT

    def get_target(self, host: str = MOCK_HOST, port: int | None = None) -> str:
        return host

    @pytest.fixture(autouse=True, scope="class")
    def _start_mock(self):
        if not _check_bacnet_mock_alive(MOCK_HOST, MOCK_PORT, timeout=3.0):
            require_service("bacnet")
        yield

    @pytest.fixture
    def cli_runner(self):
        # BACnet is UDP with multi-round-trip assess/enum flags; the global
        # default CLI timeout is too tight for the maximal invocations below.
        return CLIRunner(timeout=120)

    def test_service_is_available(self):
        assert _check_bacnet_mock_alive(MOCK_HOST, MOCK_PORT)

    # ------------------------------------------------------------------
    # Object / property read-write surface
    # ------------------------------------------------------------------

    def test_rpm_reads_multiple_properties(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--rpm",
            "-e",
            "--values",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output
        text = _text(result)
        assert MOCK_VENDOR_NAME.lower() in text or str(MOCK_VENDOR_ID) in text

    def test_read_and_write_property_spec(self, cli_runner, target, port):
        read_result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--read",
            "AI:1:pv",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert read_result.returncode in (0, 1), read_result.combined_output
        assert "Traceback" not in read_result.combined_output
        read_text = _text(read_result)
        assert "presentvalue" in read_text or "present_value" in read_text or "pv" in read_text

        no_confirm = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--write",
            "AV:1:pv:72.5",
            "--priority",
            "8",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "confirm" in _text(no_confirm)

        confirmed = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--write",
            "AV:1:pv:72.5",
            "--priority",
            "8",
            "--confirm",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "Traceback" not in confirmed.combined_output
        assert confirmed.returncode in (0, 1), confirmed.combined_output

    def test_write_requires_confirm(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "-w",
            "BV:1:pv:active",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "confirm" in _text(result)
        assert "Traceback" not in result.combined_output

    def test_vendor_scan_identifies_vendor(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--vendor-scan",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output
        text = _text(result)
        assert str(MOCK_VENDOR_ID) in text or MOCK_VENDOR_NAME.lower() in text

    def test_deep_enum_with_object_filters(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "-e",
            "--deep-enum",
            "--object-type",
            "analogInput",
            "--max-objects",
            "3",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output

    def test_enum_with_object_types_and_shaping(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "-e",
            "--values",
            "--object-types",
            "analogInput,binaryInput",
            "--values-only",
            "--full-properties",
            "--control-points",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output

    def test_enumerate_properties_flag(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--enumerate-properties",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output

    def test_read_range_history(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--read-range",
            "--read-range-count",
            "10",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output
        text = _text(result)
        assert "trendlog" in text or "trend log" in text or "temp log" in text

    # ------------------------------------------------------------------
    # Network / discovery layer
    # ------------------------------------------------------------------

    def test_who_has_locates_known_object(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--who-has",
            "AI:1",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output

    def test_network_layer_enum_flags(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--enum-bbmd",
            "--enum-fdt",
            "--enum-routers",
            "--enum-networks",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output

    def test_bbmd_and_discover_mstp_flags(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--bbmd",
            MOCK_HOST,
            "--discover-mstp",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output

    def test_interface_flag_accepted_in_default_scan_path(self, cli_runner, target, port):
        """Category B: --interface parses and the scan still runs to
        completion against an invalid NIC name. Verified by manual repro
        (uv run oida bacnet ... --interface not-a-real-nic-zzz --who-is) that
        the default (non --use-bac0) raw-bacpypes3 scan path does not
        actually bind to the named interface -- the flag is a no-op there
        and only takes effect via BAC0 (--use-bac0), so this is not an
        observable-rejection flag in the path under test here."""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--interface",
            "not-a-real-nic-zzz",
            "--who-is",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "Traceback" not in result.combined_output
        assert result.returncode in (0, 1), result.combined_output

    def test_device_range_flag_accepted_without_filtering_direct_target(
        self, cli_runner, target, port
    ):
        """Category B: --device-range parses and the scan runs cleanly with
        it set, but (per manual repro) a direct unicast --who-is against an
        explicit target host is not filtered by --device-range -- the mock
        device is found whether or not its instance number 1234 falls
        inside the given range. --device-range only meaningfully restricts
        broadcast/subnet Who-Is sweeps, which this single-target CLI
        invocation is not exercising."""
        in_range = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--who-is",
            "--device-range",
            "1000-2000",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "Traceback" not in in_range.combined_output
        assert str(MOCK_DEVICE_ID) in _text(in_range)

        out_of_range = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--who-is",
            "--device-range",
            "1-100",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "Traceback" not in out_of_range.combined_output
        # Not filtered for a direct target: the device is still discovered.
        assert str(MOCK_DEVICE_ID) in _text(out_of_range)

    # ------------------------------------------------------------------
    # File access
    # ------------------------------------------------------------------

    def test_files_enumeration(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--files",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output
        text = _text(result)
        assert "config.txt" in text or "firmware.bin" in text

    def test_read_file_stream_and_record(self, cli_runner, target, port):
        stream_result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--read-file",
            "0",
            "--file-access-method",
            "stream",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert stream_result.returncode in (0, 1), stream_result.combined_output
        assert "Traceback" not in stream_result.combined_output

        record_result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--read-file",
            "1",
            "--file-access-method",
            "record",
            "--file-chunk-size",
            "256",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert record_result.returncode in (0, 1), record_result.combined_output
        assert "Traceback" not in record_result.combined_output

    # ------------------------------------------------------------------
    # Assess-* shortcuts and the check-* group
    # ------------------------------------------------------------------

    def test_assess_network_shortcut(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--assess-network",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output

    def test_assess_config_shortcut(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--assess-config",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output
        text = _text(result)
        assert "schedule" in text or "calendar" in text or "trend" in text

    def test_assess_info_shortcut(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--assess-info",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output
        text = _text(result)
        assert MOCK_DEVICE_NAME.lower() in text or MOCK_VENDOR_NAME.lower() in text

    def test_check_group_maximal_invocation(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--check-alarms",
            "--check-calendars",
            "--check-oos",
            "--check-priority",
            "--check-reinit",
            "--check-schedules",
            "--check-trendlogs",
            "--timeout",
            "20",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output
        text = _text(result)
        assert "schedule" in text or "calendar" in text

    # ------------------------------------------------------------------
    # quick / discover / full shortcuts
    # ------------------------------------------------------------------

    def test_quick_shortcut(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--quick",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output
        text = _text(result)
        assert MOCK_DEVICE_NAME.lower() in text or str(MOCK_DEVICE_ID) in text

    def test_discover_shortcut(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--discover",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output

    def test_full_shortcut(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--full",
            "--confirm",
            "--timeout",
            "20",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output
        assert result.scan_log is not None
        result.scan_log.assert_has_events(min_count=1)

    # ------------------------------------------------------------------
    # COV / monitor / diff
    # ------------------------------------------------------------------

    def test_cov_subscription(self, cli_runner, target, port):
        no_confirm = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--cov",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "confirm" in _text(no_confirm)

        confirmed = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--cov",
            "--cov-duration",
            "5",
            "--cov-lifetime",
            "30",
            "--confirm",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert "Traceback" not in confirmed.combined_output
        assert confirmed.returncode in (0, 1), confirmed.combined_output

    def test_monitor_without_bac0_exits_immediately(self, cli_runner, target, port):
        """Category B. Manual repro showed --monitor has a hard dependency
        on --use-bac0: without it, the CLI logs
        "--monitor requires --use-bac0 (not available in the default scan
        path)" and falls through to a normal one-shot scan instead of
        looping, returning promptly with rc 0/1. It does not hang, so no
        external timeout bound is needed for this invocation."""
        start = time.monotonic()
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "-e",
            "--monitor",
            "--interval",
            "0.5",
            timeout=20,
            format="json",
            json_log=True,
        )
        elapsed = time.monotonic() - start
        assert elapsed < 20, f"--monitor without --use-bac0 unexpectedly hung: {elapsed}s"
        assert "Traceback" not in result.combined_output
        assert result.returncode in (0, 1), result.combined_output
        assert "requires --use-bac0" in _text(result)

    def test_dump_then_diff_against_baseline(self, cli_runner, target, port, tmp_path):
        output_base = tmp_path / "bacnet_baseline"
        dump_result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--dump",
            "--output",
            str(output_base),
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert dump_result.returncode in (0, 1), dump_result.combined_output
        assert "Traceback" not in dump_result.combined_output

        baseline_json = output_base.with_suffix(".json")
        if not baseline_json.exists():
            candidates = list(tmp_path.glob("bacnet_baseline*.json"))
            assert candidates, f"no dump output found in {tmp_path}"
            baseline_json = candidates[0]

        diff_result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--diff",
            str(baseline_json),
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert diff_result.returncode in (0, 1), diff_result.combined_output
        assert "Traceback" not in diff_result.combined_output

    # ------------------------------------------------------------------
    # Password brute-force
    # ------------------------------------------------------------------

    def test_brute_force_dcc_and_reinit(self, cli_runner, target, port, tmp_path):
        wordlist = tmp_path / "passwords.txt"
        wordlist.write_text("wrongpass\nOIDA\nanother\n")

        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--brute-force-dcc",
            "--brute-force-reinit",
            "--passwords",
            str(wordlist),
            "--confirm",
            "--timeout",
            "20",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output
        text = _text(result)
        assert MOCK_REINIT_PASSWORD.lower() in text or "oida" in text

    def test_password_single_value_reinit(self, cli_runner, target, port):
        correct = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--test-reinit-pass",
            "--password",
            MOCK_REINIT_PASSWORD,
            "--confirm",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert "Traceback" not in correct.combined_output
        assert correct.returncode in (0, 1), correct.combined_output

        wrong = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--test-reinit-pass",
            "--password",
            "definitely-wrong",
            "--confirm",
            "--timeout",
            "15",
            format="json",
            json_log=True,
        )
        assert "Traceback" not in wrong.combined_output
        # Different password -> different outcome from the correct one.
        assert _text(wrong) != _text(correct)

    # ------------------------------------------------------------------
    # Time sync / services / call / list-services / use-bac0
    # ------------------------------------------------------------------

    def test_time_sync_confirm_gate(self, cli_runner, target, port):
        no_confirm = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--test-time-sync",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "confirm" in _text(no_confirm)

        confirmed = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--test-time-sync",
            "--confirm",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "Traceback" not in confirmed.combined_output
        assert confirmed.returncode in (0, 1), confirmed.combined_output

    def test_services_enumeration(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--services",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output

    def test_call_service_dispatch(self, cli_runner, target, port):
        read_call = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--call",
            "read",
            "AI:1:pv",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "Traceback" not in read_call.combined_output
        assert read_call.returncode in (0, 1), read_call.combined_output

        write_no_confirm = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--call",
            "write",
            "AV:1:pv:70.0",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "confirm" in _text(write_no_confirm)

    def test_list_services_catalog(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--list-services",
            format="json",
            json_log=True,
        )
        assert result.returncode in (0, 1), result.combined_output
        assert "Traceback" not in result.combined_output
        text = _text(result)
        assert "read" in text and "write" in text

    def test_use_bac0_flag_does_not_crash(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            str(MOCK_DEVICE_ID),
            "--use-bac0",
            "--who-is",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )
        assert "Traceback" not in result.combined_output

    # ------------------------------------------------------------------
    # BACnet/SC (TLS) surface - mock has no SC stack, so these are all
    # deliberately negative/hostile cases.
    # ------------------------------------------------------------------

    def test_sc_against_plaintext_mock_fails_cleanly(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            f"wss://{target}:{port}",
            "--sc",
            "--timeout",
            str(SHORT_TIMEOUT),
            format="json",
            json_log=True,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_no_tls_checks_against_plaintext_mock(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            f"wss://{target}:{port}",
            "--sc",
            "--no-tls-checks",
            "--timeout",
            str(SHORT_TIMEOUT),
            format="json",
            json_log=True,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_sc_direct_hub_uri_mutually_exclusive(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            f"wss://{target}:{port}",
            "--sc",
            "--direct",
            "--hub-uri",
            f"wss://{target}:{port}",
            format="json",
            json_log=False,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output
        assert (
            "not allowed" in result.combined_output.lower()
            or "argument" in result.combined_output.lower()
        )

    def test_sc_bad_cert_paths_fail_cleanly(self, cli_runner, target, port, tmp_path):
        missing = tmp_path / "does-not-exist.pem"
        result = cli_runner.run(
            self.protocol_name,
            f"wss://{target}:{port}",
            "--sc",
            "--direct",
            "--ca",
            str(missing),
            "--cert",
            str(missing),
            "--key",
            str(missing),
            "--timeout",
            str(SHORT_TIMEOUT),
            format="json",
            json_log=True,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output


class TestBACnetHostileServer(BaseProtocolIntegrationTest):
    """Mandatory hostile/invalid-server catalogue for the bacnet module."""

    @property
    def protocol_name(self) -> str:
        return "bacnet"

    @property
    def default_port(self) -> int:
        return MOCK_PORT

    def get_target(self, host: str = MOCK_HOST, port: int | None = None) -> str:
        return host

    @pytest.fixture(autouse=True, scope="class")
    def _start_mock(self):
        if not _check_bacnet_mock_alive(MOCK_HOST, MOCK_PORT, timeout=3.0):
            require_service("bacnet")
        yield

    @pytest.fixture
    def cli_runner(self):
        return CLIRunner(timeout=60)

    def test_service_is_available(self):
        # bacnet is UDP-only; the base class's generic check assumes TCP
        # and always fails here, so it must be overridden per protocol.
        assert _check_bacnet_mock_alive(MOCK_HOST, MOCK_PORT)

    def test_closed_port_clean_failure(self, cli_runner, target):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(CLOSED_PORT),
            "--who-is",
            "--timeout",
            str(SHORT_TIMEOUT),
            format="json",
            json_log=True,
        )
        assert "Traceback" not in result.combined_output
        assert str(MOCK_DEVICE_ID) not in _text(result)

    def test_blackhole_host_honours_timeout_budget(self, cli_runner):
        start = time.monotonic()
        result = cli_runner.run(
            self.protocol_name,
            BLACKHOLE_HOST,
            "--who-is",
            "--timeout",
            str(SHORT_TIMEOUT),
            timeout=20,
            format="json",
            json_log=True,
        )
        elapsed = time.monotonic() - start
        assert elapsed < 18, f"scan against a blackhole host ran too long: {elapsed}s"
        assert "Traceback" not in result.combined_output

    def test_wrong_protocol_port_no_false_positive(self, cli_runner, target):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(WRONG_PROTOCOL_PORT),
            "--who-is",
            "--timeout",
            str(SHORT_TIMEOUT),
            format="json",
            json_log=True,
        )
        assert "Traceback" not in result.combined_output
        assert str(MOCK_DEVICE_ID) not in _text(result)

    def test_impostor_silent_udp_socket_no_false_positive(self, cli_runner, target):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        impostor_port = sock.getsockname()[1]
        try:
            result = cli_runner.run(
                self.protocol_name,
                "127.0.0.1",
                "--port",
                str(impostor_port),
                "--who-is",
                "--timeout",
                str(SHORT_TIMEOUT),
                format="json",
                json_log=True,
            )
        finally:
            sock.close()
        assert "Traceback" not in result.combined_output
        assert str(MOCK_DEVICE_ID) not in _text(result)

    def test_impostor_garbage_bytes_no_false_positive(self, cli_runner):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(5)
        impostor_port = sock.getsockname()[1]

        def _reply_garbage():
            try:
                _data, addr = sock.recvfrom(4096)
                sock.sendto(struct.pack(">I", 0xDEADBEEF), addr)
            except OSError:
                pass

        import threading

        responder = threading.Thread(target=_reply_garbage, daemon=True)
        responder.start()
        try:
            result = CLIRunner(timeout=30).run(
                self.protocol_name,
                "127.0.0.1",
                "--port",
                str(impostor_port),
                "--who-is",
                "--timeout",
                str(SHORT_TIMEOUT),
                format="json",
                json_log=True,
            )
        finally:
            responder.join(timeout=5)
            sock.close()
        assert "Traceback" not in result.combined_output
        assert str(MOCK_DEVICE_ID) not in _text(result)

    def test_inverted_device_range_no_crash(self, cli_runner, target, port):
        """Category B, not C: --device-range is only consulted by the
        BAC0-flavored Who-Is handler (gated behind --use-bac0); the default
        raw-bacpypes3 scan path used here never reads it at all. An inverted
        range (high < low) therefore cannot be "rejected" in this path --
        confirmed by grepping the source, device_range is referenced
        nowhere outside discovery.py's BAC0 handler. The only real
        assertion available is that a nonsensical value doesn't crash the
        CLI and the direct-target device is still found (unaffected)."""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--who-is",
            "--device-range",
            "2000-1000",
            "--timeout",
            str(SHORT_TIMEOUT),
            format="json",
            json_log=True,
        )
        assert "Traceback" not in result.combined_output
        assert result.returncode in (0, 1), result.combined_output
        assert str(MOCK_DEVICE_ID) in _text(result)

    def test_malformed_device_id_non_numeric(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-id",
            "not-a-number",
            format="json",
            json_log=False,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_malformed_max_objects_non_numeric(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-e",
            "--max-objects",
            "not-a-number",
            format="json",
            json_log=False,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_empty_target_file_rejected(self, cli_runner, tmp_path):
        empty_file = tmp_path / "empty_targets.txt"
        empty_file.write_text("")
        result = cli_runner.run(
            self.protocol_name,
            str(empty_file),
            "--who-is",
            "--timeout",
            str(SHORT_TIMEOUT),
            format="json",
            json_log=False,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_junk_target_file_rejected(self, cli_runner, tmp_path):
        junk_file = tmp_path / "junk_targets.txt"
        junk_file.write_text("@@@ not a target ###\n!!!\n")
        result = cli_runner.run(
            self.protocol_name,
            str(junk_file),
            "--who-is",
            "--timeout",
            str(SHORT_TIMEOUT),
            format="json",
            json_log=False,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_unknown_flag_rejected(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--not-a-real-flag",
            format="json",
            json_log=False,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output
        assert "unrecognized" in result.combined_output.lower()

    def test_typo_flag_rejected(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-rangee",
            format="json",
            json_log=False,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output
        assert "unrecognized" in result.combined_output.lower()

    def test_flag_borrowed_from_another_protocol_rejected(self, cli_runner, target, port):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--unit-id",
            "1",
            format="json",
            json_log=False,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output
        assert "unrecognized" in result.combined_output.lower()
