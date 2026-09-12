"""Behavioral tests for oida.fuzz_cli dispatch and command handlers.

These tests drive the real argparse parser and the real handler functions.
The only thing mocked away is the actual fuzz execution boundary
(``FuzzerApplication.run_command``) — everything in ``run_fuzzing`` up to and
including the args->config wiring runs for real, so the assertions verify
routing and argument translation rather than re-stating the source.

Covers fuzz_cli.py regions that were previously untouched:
  * handle_fuzz_command routing (list / replay / show-options / fuzz / errors)
  * run_fuzzing arg-to-config wiring (seed, port resolution, options, filters,
    TLS, monitors, fire-forget/no-receive flags)
  * handle_replay_command against a real on-disk session database
  * show_protocol_usage / show_fuzz_help output content
"""

import pytest

from oida import fuzz_cli
from oida.cli import gen_cli_args

pytestmark = pytest.mark.fuzz


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_fuzz(*argv):
    """Parse a full ``oida fuzz ...`` argv with the real CLI parser."""
    parser = gen_cli_args()
    return parser.parse_args(["fuzz", *argv])


def _make_session_db(tmp_path, store_all=True, with_crash=True):
    """Create a real on-disk fuzz session DB with two test cases + one crash.

    Returns the session stem (path without the .db suffix), matching the
    ``args.session`` convention used by handle_replay_command. Pass
    ``with_crash=False`` for a session whose crashes table is empty.
    """
    from oida.utils.ics_logger import set_context
    from oida.fuzz.core.database.orm import (
        SQLAlchemyDatabase,
        TestCaseDTO,
        CrashDTO,
    )

    set_context("TEST", "x", 0)
    session = str(tmp_path / "replaysess")
    db = SQLAlchemyDatabase(f"{session}.db")
    db.init_schema(store_all_payloads=store_all)
    db.store_test_case(
        TestCaseDTO(
            id=1,
            name="modbus-read-coils",
            timestamp=0.0,
            result="pass",
            crc32=0xABCD,
            target_ip="127.0.0.1",
            target_port=502,
            protocol="modbus",
            duration_ms=1,
            monitor_status="ok",
        )
    )
    db.store_test_case(
        TestCaseDTO(
            id=2,
            name="modbus-write-regs",
            timestamp=0.0,
            result="crash",
            crc32=0x1234,
            target_ip="127.0.0.1",
            target_port=502,
            protocol="modbus",
            duration_ms=2,
            monitor_status="fail",
        )
    )
    if with_crash:
        db.store_crash(
            CrashDTO(
                test_case_id=2,
                payload=b"\x00\x01\x02\x03",
                crash_info="connection reset",
                stack_trace="",
                crash_hash="deadbeef",
            )
        )
    return session


# ---------------------------------------------------------------------------
# handle_fuzz_command routing
# ---------------------------------------------------------------------------


class TestHandleFuzzCommandRouting:
    """handle_fuzz_command must route on the first positional / flags."""

    def test_routes_to_list(self, monkeypatch):
        called = {}

        def fake_list(args):
            called["list"] = args.category
            return 0

        monkeypatch.setattr(fuzz_cli, "handle_list_command", fake_list)
        args = _parse_fuzz("list", "--category", "ics")
        assert fuzz_cli.handle_fuzz_command(args) == 0
        assert called["list"] == "ics"

    def test_routes_to_replay_and_sets_session(self, monkeypatch):
        seen = {}

        def fake_replay(args):
            seen["session"] = args.session
            return 0

        monkeypatch.setattr(fuzz_cli, "handle_replay_command", fake_replay)
        args = _parse_fuzz("replay", "mysession")
        assert fuzz_cli.handle_fuzz_command(args) == 0
        # The replay branch copies the target positional into args.session.
        assert seen["session"] == "mysession"

    def test_routes_to_show_options(self, monkeypatch):
        seen = {}

        def fake(proto):
            seen["proto"] = proto
            return 0

        monkeypatch.setattr(fuzz_cli, "show_protocol_options", fake)
        args = _parse_fuzz("modbus", "--show-options")
        assert fuzz_cli.handle_fuzz_command(args) == 0
        assert seen["proto"] == "modbus"

    def test_routes_to_list_requests(self, monkeypatch):
        seen = {}

        def fake(proto):
            seen["proto"] = proto
            return 0

        monkeypatch.setattr(fuzz_cli, "show_protocol_requests", fake)
        args = _parse_fuzz("modbus", "--list-requests")
        assert fuzz_cli.handle_fuzz_command(args) == 0
        assert seen["proto"] == "modbus"

    def test_no_protocol_shows_help_and_returns_1(self, capsys):
        args = _parse_fuzz()
        assert fuzz_cli.handle_fuzz_command(args) == 1
        out = capsys.readouterr().out
        assert "Protocol is required" in out
        # The help screen lists at least one real fuzzer category/protocol.
        assert "modbus" in out

    def test_protocol_without_target_shows_usage(self, capsys):
        args = _parse_fuzz("modbus")
        assert fuzz_cli.handle_fuzz_command(args) == 1
        out = capsys.readouterr().out
        assert "Target required" in out
        assert "MODBUS" in out

    def test_protocol_with_target_invokes_run_fuzzing(self, monkeypatch):
        captured = {}

        def fake_run(args, protocol, target):
            captured["protocol"] = protocol
            captured["target"] = target
            return 0

        monkeypatch.setattr(fuzz_cli, "run_fuzzing", fake_run)
        args = _parse_fuzz("modbus", "10.0.0.5")
        assert fuzz_cli.handle_fuzz_command(args) == 0
        assert captured == {"protocol": "modbus", "target": "10.0.0.5"}


# ---------------------------------------------------------------------------
# run_fuzzing: arg -> FuzzerConfig wiring
# ---------------------------------------------------------------------------


class TestRunFuzzingWiring:
    """run_fuzzing must translate parsed args into the wrapped config.

    Only FuzzerApplication.run_command is stubbed; everything that builds
    the config wrapper runs for real, so the captured wrapper proves the wiring.
    """

    @pytest.fixture
    def capture_wrapper(self, monkeypatch):
        """Patch FuzzerApplication.run_command to capture its config arg."""
        captured = {}

        def fake_run_command(self, wrapped):
            captured["wrapped"] = wrapped
            return 0

        # FuzzerApplication is imported lazily inside run_fuzzing; patch on the
        # class so the lazy import resolves to the patched method.
        from oida.fuzz.core.application import FuzzerApplication

        monkeypatch.setattr(FuzzerApplication, "run_command", fake_run_command)
        return captured

    def test_unknown_protocol_returns_1(self, capsys):
        args = _parse_fuzz("modbus", "10.0.0.1")  # parsed shape is fine
        assert fuzz_cli.run_fuzzing(args, "definitely_not_a_protocol", "10.0.0.1") == 1
        out = capsys.readouterr().out
        assert "Unknown protocol" in out or "available protocols" in out.lower()

    def test_default_seed_is_deterministic(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1")
        assert fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1") == 0
        # No --seed -> the documented deterministic default 0x01DA.
        assert capture_wrapper["wrapped"].seed == 0x01DA

    def test_explicit_seed_passed_through(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--seed", "777")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        assert capture_wrapper["wrapped"].seed == 777

    def test_explicit_port_wins(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--port", "1502")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        assert capture_wrapper["wrapped"].port == 1502

    def test_well_known_port_default_used(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        # modbus well-known port from WELL_KNOWN_PORTS.
        assert capture_wrapper["wrapped"].port == 502

    def test_embedded_port_used_when_no_flag(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1:1234")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1:1234")
        w = capture_wrapper["wrapped"]
        assert w.ip == "127.0.0.1"
        assert w.port == 1234

    def test_protocol_options_typed_conversion(self, capture_wrapper):
        args = _parse_fuzz(
            "modbus",
            "127.0.0.1",
            "-O",
            "unit_id=5",
            "-O",
            "enabled=true",
            "-O",
            "name=foo",
            "-O",
            "off=false",
        )
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        opts = capture_wrapper["wrapped"].protocol_options
        assert opts["unit_id"] == 5  # int
        assert opts["enabled"] is True  # bool
        assert opts["off"] is False  # bool
        assert opts["name"] == "foo"  # str fallback

    def test_enable_disable_filters_split(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--enable", "a, b ,c", "--disable", "x,y")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        w = capture_wrapper["wrapped"]
        assert w.enabled_requests == ["a", "b", "c"]
        assert w.disabled_requests == ["x", "y"]

    def test_no_receive_flag_disables_receive(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "-X")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        assert capture_wrapper["wrapped"].receive_data_after_fuzz is False

    def test_fire_forget_sets_receive_split(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "-F")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        w = capture_wrapper["wrapped"]
        # -F: don't receive after fuzz payloads, but still receive per-request.
        assert w.receive_data_after_fuzz is False
        assert w.receive_data_after_each_request is True

    def test_tls_flag_wired(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--tls")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        assert capture_wrapper["wrapped"].tls_enabled is True

    def test_no_enumerate_flag_wired(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--no-enumerate")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        assert capture_wrapper["wrapped"].enumerate is False

    def test_no_calibrate_inverts_to_calibrate_false(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--no-calibrate")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        assert capture_wrapper["wrapped"].calibrate is False

    def test_detect_drift_implies_adaptive_timeout(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--detect-drift")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        w = capture_wrapper["wrapped"]
        assert w.detect_drift is True
        assert w.adaptive_timeout is True

    def test_session_name_wired(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--session", "campaign1")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        assert capture_wrapper["wrapped"].session == "campaign1"

    def test_bad_machine_format_returns_1(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--machine", "3,2,1")
        # Malformed --machine (not TOTAL,ID) must short-circuit before run.
        assert fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1") == 1
        assert "wrapped" not in capture_wrapper

    def test_machine_id_out_of_range_returns_1(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--machine", "3,9")
        assert fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1") == 1
        assert "wrapped" not in capture_wrapper

    def test_valid_machine_distribution_wired(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--machine", "4,2")
        assert fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1") == 0
        w = capture_wrapper["wrapped"]
        assert w.distribution_total == 4
        assert w.distribution_id == 2

    def test_connection_error_returns_1(self, monkeypatch):
        from oida.fuzz.core.application import FuzzerApplication

        def boom(self, wrapped):
            raise ConnectionError("refused")

        monkeypatch.setattr(FuzzerApplication, "run_command", boom)
        args = _parse_fuzz("modbus", "127.0.0.1")
        assert fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1") == 1

    def test_nolog_flag_wired(self, capture_wrapper):
        args = _parse_fuzz("modbus", "127.0.0.1", "--nolog")
        fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1")
        assert capture_wrapper["wrapped"].nolog is True

    def test_displays_request_count_banner(self, capture_wrapper, capsys):
        # The startup banner reports the seed, session and request count drawn
        # from the real modbus fuzzer's get_request_definitions().
        args = _parse_fuzz("modbus", "127.0.0.1", "--seed", "42")
        assert fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1") == 0
        out = capsys.readouterr().out
        assert "Seed: 42" in out
        assert "Requests:" in out
        assert "Web UI" in out

    def test_existing_session_db_drives_resume_and_summary(self, monkeypatch, tmp_path, capsys):
        """A pre-existing session DB exercises both the resume-detection block
        (before run) and the final-stats summary block (after run)."""
        session = _make_session_db(tmp_path)

        from oida.fuzz.core.application import FuzzerApplication

        captured = {}

        def fake_run_command(self, wrapped):
            captured["index_start"] = wrapped.index_start
            return 0

        monkeypatch.setattr(FuzzerApplication, "run_command", fake_run_command)

        args = _parse_fuzz("modbus", "127.0.0.1", "--session", session, "--port", "502")
        assert fuzz_cli.run_fuzzing(args, "modbus", "127.0.0.1") == 0
        out = capsys.readouterr().out
        # Post-run summary reads the real DB stats.
        assert "Test cases" in out
        assert "Total crashes" in out
        assert "Fuzzing completed" in out


# ---------------------------------------------------------------------------
# handle_replay_command against a real session DB
# ---------------------------------------------------------------------------


class TestHandleReplayCommand:
    """Replay must read a real session DB, not a mock."""

    def test_missing_session_db_returns_1(self, tmp_path, capsys):
        args = _parse_fuzz("replay", "nope")
        args.session = str(tmp_path / "does_not_exist")
        assert fuzz_cli.handle_replay_command(args) == 1

    def test_no_session_name_returns_1(self, capsys):
        args = _parse_fuzz("replay")
        args.session = None
        assert fuzz_cli.handle_replay_command(args) == 1
        out = capsys.readouterr().out
        assert "replay" in out.lower()

    def test_stats_view_lists_totals_and_crashes(self, tmp_path, capsys):
        session = _make_session_db(tmp_path)
        args = _parse_fuzz("replay", session)
        args.session = session
        args.replay_range = None
        args.case = None
        assert fuzz_cli.handle_replay_command(args) == 0
        out = capsys.readouterr().out
        assert "Total test cases:" in out
        # One crash was stored -> the stats view summarises the crash count and
        # points at the dedicated `crashes` subcommand (which lists cases by
        # signature). Per-case detail is asserted in TestHandleCrashesCommand.
        assert "crash(es)" in out
        assert "oida fuzz crashes" in out

    def test_replay_single_case_shows_result(self, tmp_path, capsys):
        session = _make_session_db(tmp_path)
        args = _parse_fuzz("replay", session, "--case", "2")
        args.session = session
        args.replay_range = None
        args.case = 2
        assert fuzz_cli.handle_replay_command(args) == 0
        out = capsys.readouterr().out
        assert "Replaying:" in out
        assert "modbus-write-regs" in out
        assert "crash" in out
        # crc32 is printed as 8-hex-digit, payload byte count for the crash.
        assert "00001234" in out
        assert "Payload: 4 bytes" in out

    def test_replay_range_iterates_cases(self, tmp_path, capsys):
        session = _make_session_db(tmp_path)
        args = _parse_fuzz("replay", session, "--range", "1-2")
        args.session = session
        args.replay_range = "1-2"
        args.case = None
        assert fuzz_cli.handle_replay_command(args) == 0
        out = capsys.readouterr().out
        assert "Range: 1-2" in out
        assert "modbus-read-coils" in out
        assert "modbus-write-regs" in out

    def test_replay_nonexistent_case_reports_not_found(self, tmp_path, capsys):
        session = _make_session_db(tmp_path)
        args = _parse_fuzz("replay", session, "--case", "999")
        args.session = session
        args.replay_range = None
        args.case = 999
        assert fuzz_cli.handle_replay_command(args) == 0
        out = capsys.readouterr().out
        assert "not found" in out.lower()


class TestHandleCrashesCommand:
    """The `crashes` subcommand lists stored crashes grouped by signature.

    The per-crash detail that the replay stats view used to inline was moved
    here; these tests keep that coverage (the crashing case is named, and the
    crash count / unique-signature summary is shown).
    """

    def test_crashes_command_lists_case_by_signature(self, tmp_path, capsys):
        session = _make_session_db(tmp_path)
        args = _parse_fuzz("crashes", session)
        args.session = session
        assert fuzz_cli.handle_crashes_command(args) == 0
        out = capsys.readouterr().out
        assert "modbus-write-regs" in out
        assert "1 crash(es)" in out
        assert "unique signature" in out

    def test_crashes_command_empty_session_reports_none(self, tmp_path, capsys):
        # A session with no crashes table rows -> friendly "No crashes" message.
        session = _make_session_db(tmp_path, with_crash=False)
        args = _parse_fuzz("crashes", session)
        args.session = session
        assert fuzz_cli.handle_crashes_command(args) == 0
        out = capsys.readouterr().out
        assert "No crashes" in out


# ---------------------------------------------------------------------------
# Protocol usage / options / requests output
# ---------------------------------------------------------------------------


class TestProtocolUsageOutput:
    def test_show_protocol_usage_known(self, capsys):
        assert fuzz_cli.show_protocol_usage("modbus") == 1
        out = capsys.readouterr().out
        assert "MODBUS fuzzer" in out
        assert "oida fuzz modbus" in out

    def test_show_protocol_usage_unknown(self, capsys):
        assert fuzz_cli.show_protocol_usage("not_a_real_proto") == 1
        out = capsys.readouterr().out
        assert "Unknown protocol" in out or "list" in out.lower()

    def test_show_fuzz_help_lists_categories(self, capsys):
        assert fuzz_cli.show_fuzz_help() == 1
        out = capsys.readouterr().out
        assert "Available Protocols" in out
        assert "protocols available" in out


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------


class TestSetupFuzzLogging:
    def test_verbose_sets_debug_level(self):
        import logging

        fuzz_cli.setup_fuzz_logging(verbose=True)
        assert logging.getLogger().level == logging.DEBUG
        # Noisy third-party loggers are pinned to CRITICAL.
        assert logging.getLogger("boofuzz").level == logging.CRITICAL

    def test_non_verbose_sets_warning_level(self):
        import logging

        fuzz_cli.setup_fuzz_logging(verbose=False)
        assert logging.getLogger().level == logging.WARNING
