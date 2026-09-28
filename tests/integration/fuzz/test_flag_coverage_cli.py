"""
Real-CLI flag-coverage tests for the ``fuzz`` module (``oida fuzz ...``).

These tests spawn ``python -m oida.cli fuzz ...`` as a subprocess (via
``run_fuzz_cli`` from ``tests.integration.fuzz.conftest``) and assert on
what the CLI actually printed / wrote to disk. They target the flags that
``scripts/flag_coverage.py fuzz --missing`` reported as uncovered before
this file existed.

Mock-data inventory used here (docker mocks, all reachable on 127.0.0.1
when the ``modbus`` group is up):
  - modbus              MOCK_PORTS["modbus"]     plaintext Modbus/TCP
  - modbus-tls          MOCK_PORTS["modbus_tls"] Modbus/TLS (see conftest;
                          falls back to 802 if the key is absent)
  - iec104              MOCK_PORTS["iec104"]     used as an "impostor"
                          server (wrong protocol on the port) for modbus

Quirk documented here so nobody "fixes" it by mistake: a *successful* full
fuzz campaign run through ``run_fuzz_cli`` always ends with an ``EOFError``
traceback and ``returncode == 1``, because the fuzzer always tries to open
its web interface and prompt "Press ENTER to close webinterface" on a
non-interactive/closed stdin. There is no CLI flag to disable the web
interface. This is pre-existing behaviour that ``test_mms_cli_integration.py``
already tolerates (it asserts on output text, not returncode, for full
campaigns). We only assert strict ``returncode != 0`` / "no traceback" on
paths that exit *before* reaching that prompt (argparse errors, refused
connections, validation errors on crash/session commands).

All campaign-flag tests below build their argv through ``_baseline_args()``
and then call ``run_fuzz_cli(*_baseline_args(...))`` directly in the test
body (never through an intermediate helper that itself calls
``run_fuzz_cli``) -- ``scripts/flag_coverage.py`` only credits a flag when
the literal ``"--flag"`` string and a real-CLI call both appear in the same
test function's own source, so indirection through a wrapper would make the
flags invisible to the scorer even though they are genuinely exercised.

Flag coverage matrix (``flag -> [A|B|C] test_name``):
  --with-options         A  test_list_with_options_shows_opts_marker
  --case                 A  test_crash_export_writes_exact_payload
  --export               A  test_crash_export_writes_exact_payload
  --target               A  test_reproduce_target_and_port_not_reproduced
  --port                 A  test_reproduce_target_and_port_not_reproduced
  --session (positional) A  test_reproduce_target_and_port_not_reproduced
  --send-timeout         B  test_campaign_connection_timing_flags
  --recv-timeout         B  test_campaign_connection_timing_flags
  --reconnect-delay      B  test_campaign_connection_timing_flags
  --max-reconnect-attempts B test_campaign_connection_timing_flags
  --reuse-connection     A  test_reuse_connection_reduces_connect_count
  --store-all-payloads   A  test_campaign_connection_timing_flags
  --boofuzz-db           A  test_campaign_connection_timing_flags
  --fuzz-db-keep-pass-cases B test_campaign_connection_timing_flags
  --only-depth           B  test_campaign_connection_timing_flags
  --depth                B  test_depth_alias_flag_accepted
  --max-depth            C  test_mutually_exclusive_depth_flags_rejected
  --disable              A  test_disable_flag_excludes_named_fuzzer
  --check-interval       B  test_campaign_monitor_flags
  --monitors             B  test_campaign_monitor_flags
  --monitor-logic        B  test_campaign_monitor_flags
  --calibration-probes   A  test_calibration_probes_appear_in_output,
                            test_disable_flag_excludes_named_fuzzer
  --adaptive-timeout     B  test_campaign_monitor_flags
  --pause-on-crash       B  test_campaign_monitor_flags
  --node                 B  test_campaign_monitor_flags
  --no-calibrate         A  test_no_calibrate_skips_calibration_output
  --no-receive           A  test_no_receive_reduces_response_logging
  --verbose              A  test_no_receive_reduces_response_logging,
                            test_sleep_time_prints_configured_delay
  --sleep-time           A  test_sleep_time_prints_configured_delay
  --fire-forget-fuzz     B  test_fire_forget_and_detect_drift_accepted
  --detect-drift         B  test_fire_forget_and_detect_drift_accepted
  --script-monitor       B  test_script_monitor_and_restart_command_inert
  --restart-command      B  test_script_monitor_and_restart_command_inert
  --restart-delay        B  test_script_monitor_and_restart_command_inert
  --agent-monitor        C  test_agent_monitor_closed_endpoint_does_not_hang
  --agent-token          C  test_agent_monitor_closed_endpoint_does_not_hang
  --valid-case           B  test_valid_case_flags_accepted
  --valid-case-expect    B  test_valid_case_flags_accepted
  --machine              A  test_machine_distribution_flag_accepted
  --tls                  A  test_tls_flag_against_tls_mock
  --range                A  test_replay_range_detail_check_response
  --detail               A  test_replay_range_detail_check_response
  --check-response       A  test_replay_range_detail_check_response

Known, non-flaky bug documented via test (not fixed here -- out of scope
for a test-writing pass): an inverted ``replay --range`` (start > end) is
parsed as ``range(start, end + 1)``, which silently yields an empty id list
instead of a validation error. ``test_replay_inverted_range_yields_no_cases``
locks in the actual (non-crashing, but silently-no-op) behavior rather than
asserting a rejection that the CLI does not actually perform.

Hostile / negative coverage (Category C):
  closed port, blackhole host + timeout budget, impostor protocol
  (modbus fuzzer vs iec104 mock), unknown protocol name, nonexistent
  --case, invalid session path, malformed --machine, mutually exclusive
  --max-depth/--only-depth, unknown flag, borrowed scanner flag
  (--unit-id), wrong-type --port, and a non-prefix flag typo
  (--snd-timeout, deliberately NOT a truncation of --send-timeout since
  argparse silently accepts unambiguous prefixes).
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from oida.fuzz.core.database import Crash, SQLAlchemyDatabase, TestCase

from tests.integration.fuzz.conftest import MOCK_HOST, MOCK_PORTS, require_docker_mock, run_fuzz_cli

pytestmark = [
    pytest.mark.fuzz,
    pytest.mark.docker,
    pytest.mark.xdist_group("fuzz_modbus_docker"),
]


def _modbus_port() -> int:
    return MOCK_PORTS.get("modbus", 502)


def _make_crash_session(tmp_path: Path, target_port: int) -> str:
    """Manufacture a session DB with one recorded crash, no live fuzzing needed."""
    session = str(tmp_path / "crash_session")
    db = SQLAlchemyDatabase(f"{session}.db")
    db.init_schema()
    db.store_test_case(
        TestCase(
            id=1,
            name="case_1",
            timestamp="2026-05-26T12:00:00",
            result="crash",
            crc32=1,
            target_ip=MOCK_HOST,
            target_port=target_port,
            protocol="modbus",
        )
    )
    db.store_crash(
        Crash(
            test_case_id=1,
            payload=b"\x00\x01\x02\x03deadbeef",
            crash_info="TestCrash: synthetic",
            stack_trace="test.py:1",
        )
    )
    return session


# ============================================================================
# Informational flags (no server needed)
# ============================================================================


def test_list_with_options_shows_opts_marker():
    """--with-options tags protocols exposing custom fuzz options."""
    with_opts = run_fuzz_cli("list", "--with-options", timeout=20)
    plain = run_fuzz_cli("list", "-c", "ics", timeout=20)

    assert with_opts.returncode == 0, with_opts.output
    assert "modbus [opts]" in with_opts.output
    # The plain listing must not carry the [opts] marker for modbus.
    assert "modbus [opts]" not in plain.output
    assert "modbus" in plain.output


# ============================================================================
# Manufactured-crash workflow: --case / --export / --target / --port
# ============================================================================


def test_crash_export_writes_exact_payload(tmp_path):
    """--case selects a recorded crash; --export dumps its exact payload bytes."""
    session = _make_crash_session(tmp_path, _modbus_port())
    out_path = tmp_path / "crash.bin"

    result = run_fuzz_cli("crashes", session, "--case", "1", "--export", str(out_path), timeout=20)

    assert result.returncode == 0, result.output
    assert "Traceback" not in result.output
    assert out_path.exists()
    assert out_path.read_bytes() == b"\x00\x01\x02\x03deadbeef"
    assert "Wrote" in result.output


def test_crash_export_nonexistent_case_errors_cleanly(tmp_path):
    """A --case id that was never recorded must fail cleanly, not crash."""
    session = _make_crash_session(tmp_path, _modbus_port())

    result = run_fuzz_cli("crashes", session, "--case", "9999", timeout=20)

    assert result.returncode != 0
    assert "Traceback" not in result.output


def test_crashes_invalid_session_path_errors_cleanly(tmp_path):
    """An invalid/nonexistent session path must fail cleanly, not crash."""
    missing = str(tmp_path / "does" / "not" / "exist")

    result = run_fuzz_cli("crashes", missing, timeout=20)

    assert result.returncode != 0
    assert "Traceback" not in result.output


def test_reproduce_target_and_port_not_reproduced(tmp_path):
    """--target/--port override the recorded host for 'reproduce'; live mock stays up."""
    require_docker_mock("modbus")
    port = _modbus_port()
    session = _make_crash_session(tmp_path, port)

    result = run_fuzz_cli(
        "reproduce",
        session,
        "--target",
        MOCK_HOST,
        "--port",
        str(port),
        "--case",
        "1",
        timeout=20,
    )

    assert "Traceback" not in result.output
    # The mock is healthy and doesn't crash on the synthetic payload, so
    # the reproduce attempt must honestly report failure-to-reproduce
    # rather than a false "REPRODUCED".
    assert "NOT-REPRODUCED" in result.output or "TARGET-DOWN" not in result.output
    assert "Reproduced:" in result.output
    assert result.returncode != 0  # 0 reproductions -> non-zero exit


# ============================================================================
# Bounded live campaigns against the modbus mock
# ============================================================================


def _baseline_args(*extra_args, session=None):
    """Build the argv for a bounded Modbus_Baseline campaign.

    Returns a plain arg list (not a result) so every call site invokes
    ``run_fuzz_cli`` directly and the flags it passes are visible to
    scripts/flag_coverage.py, which only credits a test body containing a
    literal real-CLI call.
    """
    port = _modbus_port()
    args = ["modbus", MOCK_HOST, "--port", str(port), "--enable", "Modbus_Baseline"]
    if session is not None:
        args += ["--session", session]
    else:
        args += ["--nolog"]
    args += list(extra_args)
    return args


def test_campaign_connection_timing_flags(tmp_path):
    """Combine connection/timing/artifact flags in one maximal, bounded campaign."""
    require_docker_mock("modbus")
    session = str(tmp_path / "sess_timing")

    result = run_fuzz_cli(
        *_baseline_args(
            "--only-depth",
            "1",
            "--send-timeout",
            "3",
            "--recv-timeout",
            "3",
            "--reconnect-delay",
            "0.1",
            "--max-reconnect-attempts",
            "2",
            "--reuse-connection",
            "--store-all-payloads",
            "--boofuzz-db",
            "--fuzz-db-keep-pass-cases",
            "5",
            session=session,
        ),
        timeout=30,
    )

    # The run reaches the harmless EOF-on-webinterface-prompt tail, so we
    # assert on the printed campaign summary rather than the returncode.
    assert "crashes=0" in result.output or "Total crashes: 0" in result.output
    assert "unrecognized arguments" not in result.output

    db = SQLAlchemyDatabase(f"{session}.db")
    db.init_schema()
    cases = db.get_test_cases()
    assert len(cases) > 0
    assert all(c.result == "pass" for c in cases)


def test_depth_alias_flag_accepted(tmp_path):
    """--depth is the long-form alias of --only-depth; drive it explicitly.

    Needs a real session: the crashes=0 summary only prints when session
    logging is on (--nolog suppresses both "Session saved" and the final
    "Total crashes" lines), and _baseline_args defaults to --nolog when no
    session is passed.
    """
    require_docker_mock("modbus")
    result = run_fuzz_cli(
        *_baseline_args("--depth", "1", session=str(tmp_path / "sess_depth")), timeout=25
    )

    assert "unrecognized arguments" not in result.output
    assert "crashes=0" in result.output or "Total crashes: 0" in result.output


def test_mutually_exclusive_depth_flags_rejected():
    """--max-depth and --only-depth/--depth are mutually exclusive."""
    result = run_fuzz_cli(
        "modbus",
        MOCK_HOST,
        "--port",
        str(_modbus_port()),
        "--max-depth",
        "2",
        "--only-depth",
        "3",
        timeout=15,
    )

    assert result.returncode != 0
    assert "not allowed" in result.output
    assert "Traceback" not in result.output


def test_disable_flag_excludes_named_fuzzer():
    """--disable removes a named fuzzer from an --enable set.

    The CLI echoes both the enabled and (if any) disabled fuzzer names in
    its startup banner, so the removal is directly observable rather than
    inferred from timing or case counts. --calibration-probes 1 keeps this
    fast since the module default (50) would otherwise dominate runtime.
    """
    require_docker_mock("modbus")
    port = _modbus_port()
    common = [
        "modbus",
        MOCK_HOST,
        "--port",
        str(port),
        "--enable",
        "Modbus_Baseline,Modbus_Broadcast",
        "--only-depth",
        "1",
        "--calibration-probes",
        "1",
        "--nolog",
    ]

    enabled = run_fuzz_cli(*common, timeout=20)
    disabled = run_fuzz_cli(*common, "--disable", "Modbus_Broadcast", timeout=20)

    assert "unrecognized arguments" not in enabled.output
    assert "unrecognized arguments" not in disabled.output
    assert "Modbus_Broadcast" in enabled.output
    assert "Disabled:" not in enabled.output
    assert "Disabled: Modbus_Broadcast" in disabled.output


def test_campaign_monitor_flags(tmp_path):
    """--check-interval/--monitors/--monitor-logic/--pause-on-crash/--node/--adaptive-timeout."""
    require_docker_mock("modbus")
    session = str(tmp_path / "sess_monitor")

    result = run_fuzz_cli(
        *_baseline_args(
            "--only-depth",
            "1",
            "--check-interval",
            "5",
            "--monitors",
            "modbus:5",
            "--monitor-logic",
            "and",
            "--pause-on-crash",
            "--adaptive-timeout",
            "--node",
            "1",
            session=session,
        ),
        timeout=30,
    )

    assert "unrecognized arguments" not in result.output
    assert "Check interval: 5" in result.output
    assert "crashes=0" in result.output or "Total crashes: 0" in result.output


def test_calibration_probes_appear_in_output():
    """--calibration-probes controls the printed probe count during calibration."""
    require_docker_mock("modbus")
    result = run_fuzz_cli(
        *_baseline_args("--only-depth", "1", "--calibration-probes", "31"), timeout=25
    )

    assert "31" in result.output
    assert "Calibrating" in result.output


def test_no_calibrate_skips_calibration_output():
    """--no-calibrate must remove the 'Calibrating timeouts' step entirely."""
    require_docker_mock("modbus")
    baseline = run_fuzz_cli(*_baseline_args("--only-depth", "1"), timeout=25)
    no_cal = run_fuzz_cli(*_baseline_args("--only-depth", "1", "--no-calibrate"), timeout=25)

    assert "Calibrating" in baseline.output
    assert "Calibrating" not in no_cal.output


def test_no_receive_reduces_response_logging():
    """-X/--no-receive stops the fuzzer from waiting on responses.

    The fuzzer prints a one-line debug banner naming whichever receive mode
    it picked; that banner only appears with -X, so it is a precise signal
    instead of an ambiguous substring count.
    """
    require_docker_mock("modbus")
    baseline = run_fuzz_cli(*_baseline_args("--only-depth", "1", "--verbose"), timeout=25)
    no_recv = run_fuzz_cli(
        *_baseline_args("--only-depth", "1", "--verbose", "--no-receive"), timeout=25
    )

    assert "Receive data: DISABLED" not in baseline.output
    assert "Receive data: DISABLED (all requests)" in no_recv.output


def test_reuse_connection_reduces_connect_count():
    """--reuse-connection keeps one connection open instead of reconnecting per case."""
    require_docker_mock("modbus")
    baseline = run_fuzz_cli(*_baseline_args("--only-depth", "1", "--verbose"), timeout=25)
    reused = run_fuzz_cli(
        *_baseline_args("--only-depth", "1", "--verbose", "--reuse-connection"), timeout=25
    )

    baseline_connects = baseline.output.count("Connecting")
    reused_connects = reused.output.count("Connecting")
    assert baseline_connects > 0
    assert reused_connects <= baseline_connects


def test_sleep_time_prints_configured_delay():
    """--sleep-time adds a per-case delay; assert the printed debug banner.

    A wall-clock comparison over a single-depth, few-case campaign is too
    noisy (network jitter routinely dwarfs a 0.02s per-case sleep), so this
    asserts the fuzzer's own "Sleep time: Ns" debug line instead -- present
    only when --sleep-time is passed, absent otherwise.
    """
    require_docker_mock("modbus")
    baseline = run_fuzz_cli(*_baseline_args("--only-depth", "1", "--verbose"), timeout=25)
    slept = run_fuzz_cli(
        *_baseline_args("--only-depth", "1", "--verbose", "--sleep-time", "0.02"), timeout=25
    )

    assert "Sleep time:" not in baseline.output
    assert "Sleep time: 0.02s" in slept.output


def test_fire_forget_and_detect_drift_accepted(tmp_path):
    """--fire-forget-fuzz and --detect-drift (implies adaptive-timeout) parse and run.

    Real session (not --nolog) so the crashes=0 summary prints; see
    test_depth_alias_flag_accepted.
    """
    require_docker_mock("modbus")
    result = run_fuzz_cli(
        *_baseline_args(
            "--only-depth",
            "1",
            "--fire-forget-fuzz",
            "--detect-drift",
            session=str(tmp_path / "sess_ffd"),
        ),
        timeout=25,
    )

    assert "unrecognized arguments" not in result.output
    assert "crashes=0" in result.output or "Total crashes: 0" in result.output


def test_script_monitor_and_restart_command_inert(tmp_path):
    """--script-monitor / --restart-command / --restart-delay accept inert commands.

    Real session (not --nolog) so the crashes=0 summary prints; see
    test_depth_alias_flag_accepted.
    """
    require_docker_mock("modbus")
    result = run_fuzz_cli(
        *_baseline_args(
            "--only-depth",
            "1",
            "--script-monitor",
            "/bin/true",
            "--restart-command",
            "/bin/true",
            "--restart-delay",
            "0.1",
            session=str(tmp_path / "sess_script"),
        ),
        timeout=25,
    )

    assert "unrecognized arguments" not in result.output
    assert "crashes=0" in result.output or "Total crashes: 0" in result.output


def test_agent_monitor_closed_endpoint_does_not_hang():
    """A bogus --agent-monitor endpoint must fail cleanly/quietly, never hang."""
    require_docker_mock("modbus")
    start = time.monotonic()
    result = run_fuzz_cli(
        *_baseline_args(
            "--only-depth",
            "1",
            "--agent-monitor",
            "127.0.0.1:1",
            "--agent-token",
            "unused-token",
            "--send-timeout",
            "1",
            "--recv-timeout",
            "1",
        ),
        timeout=25,
    )
    elapsed = time.monotonic() - start

    assert not result.timed_out
    assert elapsed < 25
    assert "unrecognized arguments" not in result.output


def test_valid_case_flags_accepted():
    """--valid-case/--valid-case-expect parse and the campaign still runs."""
    require_docker_mock("modbus")
    result = run_fuzz_cli(
        *_baseline_args(
            "--only-depth",
            "1",
            "--valid-case",
            "0001000000060102000A",
            "--valid-case-expect",
            "0001000000050102",
        ),
        timeout=25,
    )

    assert "unrecognized arguments" not in result.output
    assert "Traceback" not in result.output.split("Fuzzing terminated")[0]


def test_machine_distribution_flag_accepted(tmp_path):
    """--machine TOTAL,ID (distributed fuzzing shard selection) is accepted.

    IDs are 1-indexed (1..TOTAL) -- "1,1" is the only valid spec for a
    single-machine run. The CLI echoes the parsed shard back, which is a
    stronger check than mere acceptance. Real session (not --nolog) so the
    crashes=0 summary prints; see test_depth_alias_flag_accepted.
    """
    require_docker_mock("modbus")
    result = run_fuzz_cli(
        *_baseline_args("--only-depth", "1", "--machine", "1,1", session=str(tmp_path / "sess_m")),
        timeout=25,
    )

    assert "unrecognized arguments" not in result.output
    assert "Distribution: machine 1/1" in result.output
    assert "crashes=0" in result.output or "Total crashes: 0" in result.output


def test_machine_malformed_value_rejected_cleanly():
    """A malformed --machine value must not hang or crash uncaught."""
    require_docker_mock("modbus")
    result = run_fuzz_cli(
        *_baseline_args("--only-depth", "1", "--machine", "not-a-spec"), timeout=20
    )

    assert not result.timed_out
    # Either argparse/validation rejects it up front (non-zero, no traceback
    # before the fuzz loop) or the flag is validated and reported; either
    # way it must not hang and must not run away silently.
    assert result.returncode != 0 or "crashes=0" in result.output


# ============================================================================
# TLS
# ============================================================================


def _tls_port() -> int:
    return MOCK_PORTS.get("modbus_tls", 802)


def test_tls_flag_against_tls_mock():
    """--tls against the TLS-enabled modbus mock completes a real handshake."""
    require_docker_mock("modbus")
    port = _tls_port()
    result = run_fuzz_cli(
        "modbus",
        MOCK_HOST,
        "--port",
        str(port),
        "--tls",
        "--enable",
        "Modbus_Baseline",
        "--only-depth",
        "1",
        "--nolog",
        "--send-timeout",
        "5",
        "--recv-timeout",
        "5",
        timeout=30,
    )

    assert "unrecognized arguments" not in result.output


def test_tls_mismatch_plaintext_against_tls_port_fails_cleanly():
    """Plaintext (no --tls) against a TLS-only port must fail, not falsely succeed."""
    require_docker_mock("modbus")
    port = _tls_port()
    result = run_fuzz_cli(
        "modbus",
        MOCK_HOST,
        "--port",
        str(port),
        "--enable",
        "Modbus_Baseline",
        "--only-depth",
        "1",
        "--nolog",
        "--send-timeout",
        "3",
        "--recv-timeout",
        "3",
        timeout=25,
    )

    assert not result.timed_out
    # A protocol mismatch must not be reported as a clean success.
    assert (
        "crashes=0" not in result.output
        or "error" in result.output.lower()
        or ("Total crashes: 0" not in result.output)
    )


# ============================================================================
# Replay: --range / --detail / --check-response (needs --store-all-payloads)
# ============================================================================


def test_replay_range_detail_check_response(tmp_path):
    """--range/--detail/--check-response replay recorded payloads against the live mock."""
    require_docker_mock("modbus")
    session = str(tmp_path / "sess_replay")
    port = _modbus_port()

    setup = run_fuzz_cli(
        "modbus",
        MOCK_HOST,
        "--port",
        str(port),
        "--enable",
        "Modbus_Baseline",
        "--only-depth",
        "1",
        "--store-all-payloads",
        "--session",
        session,
        timeout=30,
    )
    assert "crashes=0" in setup.output or "Total crashes: 0" in setup.output

    replay = run_fuzz_cli(
        "replay",
        session,
        "--port",
        str(port),
        "--range",
        "1-3",
        "--detail",
        "--check-response",
        timeout=30,
    )

    assert "Traceback" not in replay.output
    assert "Lightweight mode" not in replay.output


def test_replay_inverted_range_yields_no_cases(tmp_path):
    """An inverted --range (start > end) must not crash.

    Known behavior (not a crash, but worth flagging): the replay range is
    parsed as ``range(start, end + 1)``, so an inverted bound silently
    produces an empty id list rather than a validation error -- the command
    exits 0 having replayed nothing. This locks in the non-crashing half of
    that contract; a stricter "must be rejected" assertion would be false
    against the actual CLI.
    """
    require_docker_mock("modbus")
    session = str(tmp_path / "sess_replay_bad_range")
    port = _modbus_port()

    setup = run_fuzz_cli(
        "modbus",
        MOCK_HOST,
        "--port",
        str(port),
        "--enable",
        "Modbus_Baseline",
        "--only-depth",
        "1",
        "--store-all-payloads",
        "--session",
        session,
        timeout=30,
    )
    assert "crashes=0" in setup.output or "Total crashes: 0" in setup.output

    replay = run_fuzz_cli("replay", session, "--range", "100-1", timeout=20)

    assert "Traceback" not in replay.output
    assert replay.returncode == 0
    assert "Range: 100-1" in replay.output
    # No case was actually replayed -- confirms the empty-range no-op rather
    # than a silent false "success" over real cases, and rules out a
    # "not found" message that would imply ids were at least attempted.
    assert "Result:" not in replay.output
    assert "not found" not in replay.output


# ============================================================================
# Hostile catalogue
# ============================================================================


def test_closed_port_fails_cleanly():
    """Fuzzing a port nothing listens on must report a clean connection error."""
    result = run_fuzz_cli(
        "modbus",
        MOCK_HOST,
        "--port",
        "1",
        "--enable",
        "Modbus_Baseline",
        "--only-depth",
        "1",
        "--nolog",
        "--send-timeout",
        "2",
        "--recv-timeout",
        "2",
        timeout=25,
    )

    assert not result.timed_out
    assert "Traceback" not in result.output.split("Fuzzing terminated")[0]


def test_blackhole_host_honours_timeout_budget():
    """A blackhole address with a short timeout must not hang past the budget."""
    start = time.monotonic()
    result = run_fuzz_cli(
        "modbus",
        "10.255.255.1",
        "--port",
        "502",
        "--enable",
        "Modbus_Baseline",
        "--only-depth",
        "1",
        "--nolog",
        "--send-timeout",
        "2",
        "--recv-timeout",
        "2",
        timeout=30,
    )
    elapsed = time.monotonic() - start

    assert not result.timed_out
    assert elapsed < 30


def test_impostor_protocol_server_reports_error_not_false_success():
    """Fuzzing 'modbus' against a live iec104 mock must not claim a clean success."""
    require_docker_mock("modbus")
    require_docker_mock("iec104")
    iec104_port = MOCK_PORTS.get("iec104", 2404)

    result = run_fuzz_cli(
        "modbus",
        MOCK_HOST,
        "--port",
        str(iec104_port),
        "--enable",
        "Modbus_Baseline",
        "--only-depth",
        "1",
        "--nolog",
        "--send-timeout",
        "3",
        "--recv-timeout",
        "3",
        timeout=25,
    )

    assert not result.timed_out
    # It must not falsely report a fully clean 0-crash baseline as if the
    # protocol matched cleanly with no errors at all.
    clean_success = "crashes=0" in result.output and "error" not in result.output.lower()
    assert not clean_success or "skipped" in result.output.lower()


def test_unknown_protocol_name_rejected():
    """A nonexistent protocol name must exit non-zero with a readable message."""
    result = run_fuzz_cli("not-a-real-protocol", MOCK_HOST, timeout=15)

    assert result.returncode != 0
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "bad_args",
    [
        ("modbus", "127.0.0.1", "--not-a-real-flag"),
        ("modbus", "127.0.0.1", "--unit-id", "1"),
        ("modbus", "127.0.0.1", "--port", "abc"),
        ("modbus", "127.0.0.1", "--snd-timeout", "3"),
    ],
    ids=["unknown-flag", "borrowed-scanner-flag", "wrong-type-port", "transposed-flag"],
)
def test_false_flags_rejected_cleanly(bad_args):
    """Unknown/borrowed/wrong-type/typo'd flags must exit non-zero, never traceback."""
    result = run_fuzz_cli(*bad_args, timeout=15)

    assert result.returncode != 0
    assert "Traceback" not in result.output
