"""
TASE.2/ICCP Protocol Real-CLI Integration Tests

Drives the actual `oida tase2` CLI (via `cli_runner`, which shells out to
`python -m oida.cli`) rather than importing the scanner class in-process.
This is the file that gives `scripts/flag_coverage.py tase2` real-CLI credit;
`tests/integration/test_tase2_integration.py` does not, because it imports
`TASE2Scanner` directly and drives it in-process against hand-built
`Mock*` dataclasses.

## Baseline

Before this file, `scripts/flag_coverage.py tase2 --missing` reported 0/40
module flags with any real-CLI test coverage.

## Why this is a NEW file, not an extension of test_tase2_integration.py

`test_tase2_integration.py` is a `unittest.TestCase` suite that never touches
the CLI subprocess or a network socket -- it constructs `TASE2Scanner`
directly and feeds it `MockDomain`/`MockVariable`/`MockPointValue`/etc.
dataclasses to unit-test `_analyze_security()`. That is a fundamentally
different (and valuable) style from the `BaseProtocolIntegrationTest` /
`cli_runner` / `ScanLog` pattern used by every other
`test_<proto>_integration.py` file (see `test_modbus_integration.py`).
Splicing pytest-fixture-based real-CLI tests into a unittest.TestCase module
would fight the harness. Its header comment ("NOTE: No Docker mock service
exists for TASE.2") is also now stale -- a real mock
(`tase2-libiec61850-server`, oida group `tase2`, host port 10103) exists in
`docker/mocks/compose.yml` -- but fixing that file is out of scope here.

## BLOCKING BUG: the TASE.2 Docker mock cannot start (found while writing this file)

`python services.py up tase2` brings up `tase2-libiec61850-server`, but the
container crash-loops and never binds port 10103/tcp. Two distinct bugs
stack up in `docker/mocks/services/tase2/mock/Dockerfile`:

1. **Attempted fix (see that file).** The builder stage's "collect Python
   bindings" step searched for files named `_iec61850.so` / `iec61850.py`,
   but the SWIG build of libiec61850 actually produces `pyiec61850.py` +
   `_pyiec61850.so` (module name is `pyiec61850`, not `iec61850`). The find
   patterns never matched the compiled `.so`, so the native extension was
   silently never copied into the image at all, while
   `tase2_server_spec.py` (the file the Dockerfile actually runs as
   `/app/server.py` -- NOT the sibling `tase2_server_libiec.py`) and the
   vendored FreeTase2 library (`tase2/common/iccpcommon.py`,
   `tase2/client/client.py`) both `import iec61850` directly. Result:
   `ImportError: No module named 'iec61850'` on every container start.
   Corrected the find patterns and added a compatibility shim module
   (`iec61850.py` -> `from pyiec61850 import *`) in the shared checkout at
   `/home/f0rw4rd/pro/oida/docker/mocks/services/tase2/mock/Dockerfile`
   (this worktree may not yet reflect that edit -- see report).
2. **NOT fixed -- still blocking, needs a maintainer decision.** With bug #1
   fixed, the container gets one step further and now fails with:
   `ImportError: /usr/local/lib/python3.11/site-packages/_pyiec61850.so:
   undefined symbol: GoosePublisher_createRemote`. `GoosePublisher_createRemote`
   *is* defined in the cloned libiec61850 source
   (`src/goose/goose_publisher.c`), but is not exported by the
   `libiec61850.so` that CMake actually links in this build (confirmed via
   `nm -D libiec61850.so | grep GoosePublisher_createRemote` -> no match,
   while 94 other GOOSE symbols are present). The Dockerfile does an
   unpinned `git clone --depth 1` of both `mz-automation/libiec61850` and
   the FreeTase2 repo (no tag/commit pin), so the SWIG interface file and
   the compiled core library are generated from the same unpinned HEAD but
   are still ABI-inconsistent for this one symbol -- most likely a
   conditional-compile (R-GOOSE / mbedtls-gated) mismatch between the SWIG
   `.i` wrapper and the default CMake option set. This needs someone who
   owns the mock to either pin both clones to a known-good release tag or
   patch the CMake flags / SWIG interface; it is a native-library build
   problem, not a test problem, and out of scope for this pass.

**Net effect: the tase2 mock cannot presently serve a single TASE.2
association, so no test in this file can exercise real protocol semantics
(actual domain/point/data-set values, the `--confirm` gate, or the
"No encryption" security finding).** All 40 module flags below are
therefore tested at the **CLI/argparse/connection-failure layer only**:
every flag is proven to (a) be accepted by argparse (not dead/unwired),
(b) not crash the scanner, and (c) produce a clean, logged connection
failure. That is real, assertable behavior -- it would catch a flag being
silently dropped from dispatch, or a connection-failure path throwing an
unhandled traceback -- but it is Category C throughout; there is currently
no way to write an honest Category A test for this module against Docker.
**Once bug #2 above is fixed, this file should be revisited and upgraded to
exercise real success-path (Category A) behavior using the mock data
inventory below.**

## Mock data inventory (for the future A-level pass; not assertable today)

Source: `docker/mocks/services/tase2/mock/tase2_server_spec.py` (the file
actually deployed as `/app/server.py` per the Dockerfile).

- vendor="OIDA", model="FreeTASE2", bilateral_table_id="BLT_UTILITY_001",
  tase2_version=(2000, 8)
- Supported conformance blocks: Block 1, Block 2, Block 5. Block 4
  (Information Messages) is NOT implemented anywhere in the mock (no
  IM-store code exists in `tase2_server_spec.py`/`tase2_types.py`), so even
  once the mock is fixed, `--list-im-stores`/`--list-messages`/
  `--read-message`/`--write-message`/`--delete-message`/`--test-im` will
  stay Category B ("Block 4 may not be enabled", empty results) rather than
  Category A.
- Domains: VCC (system-wide), ICC1 ("Substation North"), ICC2
  ("Substation South")
- VCC points: System_Status, Total_Generation_MW, Total_Load_MW,
  System_Frequency_Hz, ACE_MW (value -2.5, "Area Control Error")
- ICC1 points: Bus_Voltage_kV (132.5 kV, "Bus voltage"), Feeder1_MW,
  Feeder1_MVAr, Feeder2_MW, Feeder2_MVAr, Breaker1_Status, Breaker2_Status,
  Transformer_Tap (discrete), Alarm_Count (0, "Active alarm count")
- ICC2 points: Bus_Voltage_kV (33.2 kV), Load_MW (15.8), Load_MVAr (4.2),
  Power_Factor (0.966)
- Control points (Block 5): ICC1/Breaker1_Control (COMMAND,
  tag=CLOSE_ONLY_INHIBIT, reason="Scheduled maintenance"),
  ICC1/Breaker2_Control (COMMAND, tag=NO_TAG), ICC1/Tap_Setpoint
  (SETPOINT_DISCRETE), ICC2/Capacitor_Control (COMMAND,
  tag=OPEN_AND_CLOSE_INHIBIT, reason="Equipment fault - investigation in
  progress"), ICC2/Voltage_Setpoint (SETPOINT_REAL)
- Data sets: VCC/DS_System (5 members), ICC1/DS_Voltages, ICC1/DS_Feeders,
  ICC1/DS_Status, ICC2/DS_Load
- Transfer sets: `{domain}/TS_01`..`{domain}/TS_05` for VCC/ICC1/ICC2, all
  initially DISABLED

## Classification summary

- Category A (strict): 0 tests -- blocked by the mock startup bug above.
- Category B (conditional): 0 tests -- same reason; nothing to be
  conditional about without a live handshake.
- Category C (error handling / graceful-failure / dead-flag detection):
  32 tests, covering all 40 module-specific flags plus the mandatory
  hostile-input catalogue (closed port, blackhole host, wrong-protocol
  port, malformed args).
- Total: 32 tests.

## Full flag coverage matrix (all 40 module flags)

| Flag | Test | Category | Notes |
|---|---|---|---|
| --local-ap-title | test_default_scan_maximal_flags_closed_port | C | combined w/ other scan-shaping flags |
| --remote-ap-title | test_default_scan_maximal_flags_closed_port | C | |
| --no-discover-vcc | test_default_scan_maximal_flags_closed_port | C | |
| --no-discover-icc | test_default_scan_maximal_flags_closed_port | C | |
| --no-analyze-blt | test_default_scan_maximal_flags_closed_port | C | |
| --no-enumerate-points | test_default_scan_maximal_flags_closed_port | C | |
| --max-points | test_default_scan_maximal_flags_closed_port, test_max_points_non_numeric_rejected | C | also argparse-level |
| --test-rbe | test_default_scan_maximal_flags_closed_port | C | |
| --test-control | test_default_scan_maximal_flags_closed_port | C | |
| --test-write | test_default_scan_maximal_flags_closed_port | C | |
| --list-domains | test_read_action_fails_gracefully_closed_port[list-domains] | C | |
| --list-variables | test_read_action_fails_gracefully_closed_port[list-variables] | C | |
| --list-data-sets | test_read_action_fails_gracefully_closed_port[list-data-sets*] | C | tested bare and with DOMAIN |
| --list-transfer-sets | test_read_action_fails_gracefully_closed_port[list-transfer-sets] | C | |
| --read-point | test_read_action_fails_gracefully_closed_port[read-point] | C | |
| --write-point | test_write_action_without_confirm / test_write_action_with_confirm | C | write action |
| --send-command | test_write_action_without_confirm / test_write_action_with_confirm | C | write action |
| --select-device | test_write_action_without_confirm / test_write_action_with_confirm | C | write action |
| --operate-device | test_write_action_without_confirm / test_write_action_with_confirm | C | write action |
| --enable-rbe | test_write_action_without_confirm / test_write_action_with_confirm | C | write action |
| --disable-rbe | test_write_action_without_confirm / test_write_action_with_confirm | C | write action |
| --get-blt | test_read_action_fails_gracefully_closed_port[get-blt] | C | |
| --get-server-info | test_read_action_fails_gracefully_closed_port[get-server-info], test_closed_port_connection_refused, test_blackhole_host_short_timeout, test_wrong_protocol_port | C | |
| --get-features | test_read_action_fails_gracefully_closed_port[get-features] | C | |
| --get-version | test_read_action_fails_gracefully_closed_port[get-version] | C | |
| --get-data-type | test_read_action_fails_gracefully_closed_port[get-data-type] | C | |
| --read-points | test_read_action_fails_gracefully_closed_port[read-points] | C | |
| --get-ds-members | test_read_action_fails_gracefully_closed_port[get-ds-members] | C | |
| --read-data-set | test_read_action_fails_gracefully_closed_port[read-data-set] | C | |
| --create-data-set | test_write_action_without_confirm / test_write_action_with_confirm | C | write action |
| --delete-data-set | test_write_action_without_confirm / test_write_action_with_confirm | C | write action |
| --get-tag | test_read_action_fails_gracefully_closed_port[get-tag] | C | |
| --set-tag | test_write_action_without_confirm / test_write_action_with_confirm | C | write action |
| --list-im-stores | test_read_action_fails_gracefully_closed_port[list-im-stores] | C | |
| --list-messages | test_read_action_fails_gracefully_closed_port[list-messages] | C | |
| --read-message | test_read_action_fails_gracefully_closed_port[read-message] | C | |
| --write-message | test_write_action_without_confirm / test_write_action_with_confirm | C | write action |
| --delete-message | test_write_action_without_confirm / test_write_action_with_confirm | C | write action |
| --test-im | test_read_action_fails_gracefully_closed_port[test-im] | C | |
| --confirm | test_write_action_with_confirm | C | accepted by argparse; the confirm *gate itself* lives in `cli_runner._execute_action`, which only runs after a successful connection -- unreachable until the mock is fixed (documented, not silently skipped) |

## Not testable today (explicitly, not silently)

- The `--confirm` gate's actual accept/reject behavior (both directions) --
  `_execute_action()` in `src/oida/protocols/tase2/cli_runner.py` checks
  `_needs_confirm()` only after `create_conn_obj()` succeeds, which requires
  a live TASE.2 association. Blocked by bug #2 above.
- The "No encryption" security finding
  (`src/oida/protocols/tase2/cli_runner.py::create_conn_obj`) -- fires only
  on a successful connect. Blocked by bug #2.
- Any assertion on real domain/point/data-set/tag/transfer-set values.
  Blocked by bug #2.
"""

import socket

import pytest

from .conftest import MOCK_HOST

pytestmark = [pytest.mark.tase2, pytest.mark.xdist_group("tase2_service")]

CLOSED_PORT = 19999  # deliberately unbound; verified closed by this suite
WRONG_PROTOCOL_PORT = 502  # modbus (part of the "core" mock group)
BLACKHOLE_HOST = "10.255.255.1"
SHORT_TIMEOUT = 3

# --- 18 read-only/informational actions -------------------------------------
READ_ACTIONS = [
    ("get-server-info", ["--get-server-info"]),
    ("get-version", ["--get-version"]),
    ("get-features", ["--get-features"]),
    ("get-blt", ["--get-blt"]),
    ("list-domains", ["--list-domains"]),
    ("list-variables", ["--list-variables", "VCC"]),
    ("list-data-sets-bare", ["--list-data-sets"]),
    ("list-data-sets-domain", ["--list-data-sets", "VCC"]),
    ("list-transfer-sets", ["--list-transfer-sets", "VCC"]),
    ("read-point", ["--read-point", "VCC/System_Status"]),
    ("read-points", ["--read-points", "VCC/System_Status,VCC/ACE_MW"]),
    ("get-data-type", ["--get-data-type", "VCC/System_Status"]),
    ("get-ds-members", ["--get-ds-members", "VCC/DS_System"]),
    ("read-data-set", ["--read-data-set", "VCC/DS_System"]),
    ("get-tag", ["--get-tag", "ICC1/Breaker1_Control"]),
    ("list-im-stores", ["--list-im-stores"]),
    ("list-messages", ["--list-messages", "VCC/STORE1"]),
    ("read-message", ["--read-message", "VCC/STORE1/1"]),
    ("test-im", ["--test-im"]),
]

# --- 11 write/control actions (each requires --confirm per proto_args.py) ---
WRITE_ACTIONS = [
    ("write-point", ["--write-point", "VCC/System_Status:1"]),
    ("send-command", ["--send-command", "ICC1/Breaker1_Control:1"]),
    ("select-device", ["--select-device", "ICC1/Breaker1_Control"]),
    ("operate-device", ["--operate-device", "ICC1/Breaker1_Control:1"]),
    ("enable-rbe", ["--enable-rbe", "VCC/TS_01"]),
    ("disable-rbe", ["--disable-rbe", "VCC/TS_01"]),
    ("create-data-set", ["--create-data-set", "VCC/TestSet:System_Status,ACE_MW"]),
    ("delete-data-set", ["--delete-data-set", "VCC/DS_System"]),
    ("set-tag", ["--set-tag", "ICC1/Breaker1_Control:CLOSE_ONLY"]),
    ("write-message", ["--write-message", "VCC/STORE1:hello"]),
    ("delete-message", ["--delete-message", "VCC/STORE1/1"]),
]


def _assert_flag_wired_and_graceful(result):
    """Shared assertions: the flag parsed (argparse accepted it), the
    scanner didn't crash, and the failure was logged in a recognizable way.

    This is deliberately NOT just `returncode in [0, 1]` -- it also proves
    argparse actually registered the flag (catching the "factory imported
    but never called" dead-flag class of bug) and that the failure path
    doesn't raise an unhandled exception.
    """
    text = result.combined_output
    lower = text.lower()
    assert "unrecognized arguments" not in lower, f"flag not wired into argparse: {text[:500]}"
    assert "invalid choice" not in lower, f"flag not wired into argparse: {text[:500]}"
    assert "traceback (most recent call last)" not in lower, f"scanner crashed: {text[:2000]}"
    assert result.returncode != -1, f"process hung/was killed by test timeout: {text[:500]}"
    assert any(
        term in lower for term in ("connection failed", "failed to connect", "connection-rejected")
    ), f"expected a graceful connection-failure message, got: {text[:800]}"


class TestTase2CLIIntegration:
    """Real-CLI integration tests for `oida tase2`.

    Does not inherit `BaseProtocolIntegrationTest`: that base class's
    class-scoped autouse fixture calls `ensure_mock("tase2")`, which -- given
    the mock startup bug documented in the module docstring -- would hard-fail
    (not skip) every single test in the class regardless of what it actually
    exercises. These tests are deliberately written to work whether or not
    the tase2 mock is reachable, since none of them currently depend on it.
    """

    # ------------------------------------------------------------------
    # 18 read-only/informational action flags
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        "flag_args", [args for _, args in READ_ACTIONS], ids=[name for name, _ in READ_ACTIONS]
    )
    def test_read_action_fails_gracefully_closed_port(self, cli_runner, flag_args):
        """Read/info action flags parse and fail cleanly against a closed port [Category C]"""
        result = cli_runner.run(
            "tase2",
            MOCK_HOST,
            "--port",
            str(CLOSED_PORT),
            "--timeout",
            str(SHORT_TIMEOUT),
            *flag_args,
            format="json",
            json_log=True,
        )
        assert flag_args[0] in result.command, f"runner dropped {flag_args[0]}: {result.command}"
        _assert_flag_wired_and_graceful(result)

    # ------------------------------------------------------------------
    # 11 write/control action flags, without and with --confirm
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        "flag_args", [args for _, args in WRITE_ACTIONS], ids=[name for name, _ in WRITE_ACTIONS]
    )
    def test_write_action_without_confirm(self, cli_runner, flag_args):
        """Write/control flags parse and fail cleanly without --confirm [Category C]

        Connection to a closed port fails before `_execute_action()` (and
        therefore before the `--confirm` gate) is ever reached, so this only
        proves the flag is wired and safe -- it does NOT prove the confirm
        gate refuses the operation. See module docstring "Not testable
        today".
        """
        result = cli_runner.run(
            "tase2",
            MOCK_HOST,
            "--port",
            str(CLOSED_PORT),
            "--timeout",
            str(SHORT_TIMEOUT),
            *flag_args,
            format="json",
            json_log=True,
        )
        assert flag_args[0] in result.command, f"runner dropped {flag_args[0]}: {result.command}"
        assert "--confirm" not in result.command, "this test must not pass --confirm"
        _assert_flag_wired_and_graceful(result)

    @pytest.mark.parametrize(
        "flag_args", [args for _, args in WRITE_ACTIONS], ids=[name for name, _ in WRITE_ACTIONS]
    )
    def test_write_action_with_confirm(self, cli_runner, flag_args):
        """Write/control flags plus --confirm parse and fail cleanly [Category C]

        Gives `--confirm` itself real-CLI flag coverage. Same caveat as
        above: cannot prove the confirm gate's accept path without a live
        connection.
        """
        result = cli_runner.run(
            "tase2",
            MOCK_HOST,
            "--port",
            str(CLOSED_PORT),
            "--timeout",
            str(SHORT_TIMEOUT),
            *flag_args,
            "--confirm",
            format="json",
            json_log=True,
        )
        assert "--confirm" in result.command, f"runner dropped --confirm: {result.command}"
        _assert_flag_wired_and_graceful(result)

    # ------------------------------------------------------------------
    # 10 default-scan-shaping flags, maximal combined invocation
    # ------------------------------------------------------------------

    def test_default_scan_maximal_flags_closed_port(self, cli_runner):
        """All discovery/testing-scope flags combined on the default scan path [Category C]"""
        result = cli_runner.run(
            "tase2",
            MOCK_HOST,
            "--port",
            str(CLOSED_PORT),
            "--timeout",
            str(SHORT_TIMEOUT),
            "--local-ap-title",
            "1.1.1.999",
            "--remote-ap-title",
            "1.1.1.998",
            "--no-discover-vcc",
            "--no-discover-icc",
            "--no-analyze-blt",
            "--no-enumerate-points",
            "--max-points",
            "5",
            "--test-rbe",
            "--test-control",
            "--test-write",
            format="json",
            json_log=True,
        )
        for flag in ("--no-discover-vcc", "--max-points", "--test-write", "--local-ap-title"):
            assert flag in result.command, f"runner dropped {flag}: {result.command}"
        _assert_flag_wired_and_graceful(result)

    # ------------------------------------------------------------------
    # Mandatory hostile-input catalogue
    # ------------------------------------------------------------------

    def test_closed_port_connection_refused(self, cli_runner):
        """Baseline default scan against a closed port fails cleanly, no action flags [Category C]"""
        # Sanity: confirm the "closed" port really is closed in this environment,
        # so a failure here is unambiguously about tase2's handling, not luck.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(1)
        try:
            with pytest.raises(OSError):
                probe.connect((MOCK_HOST, CLOSED_PORT))
        finally:
            probe.close()

        result = cli_runner.run(
            "tase2",
            MOCK_HOST,
            "--port",
            str(CLOSED_PORT),
            "--timeout",
            str(SHORT_TIMEOUT),
            format="json",
            json_log=True,
        )
        _assert_flag_wired_and_graceful(result)
        assert result.scan_log is not None, "expected a JSON log to be written even on failure"
        error_events = result.scan_log.get_events(event_type="protocol_error")
        assert error_events, f"expected a protocol_error event, got: {result.scan_log.events[:5]}"

    def test_blackhole_host_short_timeout(self, cli_runner):
        """Unreachable host (10.255.255.1) with a short --timeout does not hang [Category C]"""
        result = cli_runner.run(
            "tase2",
            BLACKHOLE_HOST,
            "--port",
            "102",
            "--timeout",
            str(SHORT_TIMEOUT),
            "--get-server-info",
            format="json",
            json_log=True,
            timeout=SHORT_TIMEOUT + 15,
        )
        # The point of this test: --timeout is a real budget, not decoration. A
        # blackhole address never answers, so the run must end shortly after the
        # timeout rather than hanging until the subprocess is killed.
        assert result.execution_time < SHORT_TIMEOUT + 10, (
            f"--timeout {SHORT_TIMEOUT}s not honoured against a blackhole host: "
            f"took {result.execution_time:.1f}s"
        )
        _assert_flag_wired_and_graceful(result)

    def test_wrong_protocol_port(self, cli_runner):
        """Pointing tase2 at a live but wrong protocol (modbus, port 502) fails cleanly [Category C]

        Requires the "core" mock group (`python services.py up core`) to be
        running so port 502 is actually a live Modbus responder rather than
        just another closed port -- otherwise this degenerates into the
        closed-port case and stops proving anything about protocol-mismatch
        handling.
        """
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(2)
        try:
            probe.connect((MOCK_HOST, WRONG_PROTOCOL_PORT))
        except OSError:
            pytest.fail(
                f"port {WRONG_PROTOCOL_PORT} is not open -- bring up the 'core' mock "
                "group (`python services.py up core`) before running this test"
            )
        finally:
            probe.close()

        result = cli_runner.run(
            "tase2",
            MOCK_HOST,
            "--port",
            str(WRONG_PROTOCOL_PORT),
            "--timeout",
            str(SHORT_TIMEOUT),
            "--get-server-info",
            format="json",
            json_log=True,
        )
        _assert_flag_wired_and_graceful(result)
        # Must not misreport a protocol mismatch as a successful TASE.2 scan.
        assert not result.success, "tase2 falsely reported success against a modbus endpoint"

    def test_malformed_target_unresolvable_host(self, cli_runner):
        """A target that isn't a real host/IP/file fails cleanly, not a crash [Category C]"""
        result = cli_runner.run(
            "tase2",
            "definitely-not-a-real-target-xyz.invalid",
            "--port",
            str(CLOSED_PORT),
            "--timeout",
            str(SHORT_TIMEOUT),
            "--get-server-info",
            format="json",
            json_log=True,
        )
        lower = result.combined_output.lower()
        assert "traceback (most recent call last)" not in lower, (
            f"scanner crashed on malformed target: {result.combined_output[:1500]}"
        )
        assert result.returncode != -1, "process hung on malformed target"
        assert not result.success, "malformed target should not report success"

    def test_max_points_non_numeric_rejected(self, cli_runner):
        """--max-points with a non-numeric value is rejected by argparse before any I/O [Category C]"""
        result = cli_runner.run(
            "tase2",
            MOCK_HOST,
            "--max-points",
            "not-a-number",
            format="json",
            json_log=True,
        )
        assert result.returncode == 2, (
            f"expected an argparse usage error (rc=2), got rc={result.returncode}: "
            f"{result.combined_output[:500]}"
        )
        lower = result.combined_output.lower()
        assert "traceback (most recent call last)" not in lower
        assert "invalid int value" in lower or "invalid" in lower, (
            f"expected an argparse type-validation error, got: {result.combined_output[:500]}"
        )

    def test_timeout_non_numeric_rejected(self, cli_runner):
        """--timeout with a non-numeric value is rejected by argparse before any I/O [Category C]"""
        result = cli_runner.run(
            "tase2",
            MOCK_HOST,
            "--timeout",
            "not-a-number",
            format="json",
            json_log=True,
        )
        assert result.returncode == 2, (
            f"expected an argparse usage error (rc=2), got rc={result.returncode}: "
            f"{result.combined_output[:500]}"
        )
        lower = result.combined_output.lower()
        assert "traceback (most recent call last)" not in lower
        assert "invalid" in lower, (
            f"expected an argparse type-validation error, got: {result.combined_output[:500]}"
        )
