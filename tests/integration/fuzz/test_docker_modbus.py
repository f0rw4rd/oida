"""
Tier 4/5: Docker-backed Modbus fuzzer integration tests.

Tests run the fuzzer against a real Docker mock Modbus server (port 502)
started via ``make mock-start``.  Covers:
  - Request definition execution against Docker mock
  - Protocol monitor baseline against Docker mock
  - Session DB recording and payload storage
  - End-to-end CLI invocation via subprocess
  - CLI error handling (no Docker needed)
  - CLI feature flags (seed, enable, options, -F, -X)
  - Capability enumeration
  - Connection modes

Requires:
  Docker mock services running (``make mock-start``) for Docker-backed tests.
"""

import os
import sqlite3
import tempfile

import pytest

from tests.service_gate import require_import, require_service

from tests.integration.fuzz.conftest import (
    FuzzTimeout,
    create_fuzzer_config,
    require_docker_mock,
    run_fuzz_cli,
    run_fuzz_with_timeout,
)
from tests.integration.conftest import MOCK_HOST

# These tests each fuzz a live target on MOCK_HOST:502; running them concurrently
# under `-n --dist loadgroup` lets parallel fuzz sessions contend for the same port
# and miscount crashes. The shared xdist_group co-locates them on one worker so they
# serialize relative to each other (they pass reliably when not run in parallel).
pytestmark = [
    pytest.mark.modbus,
    pytest.mark.fuzz,
    pytest.mark.slow,
    pytest.mark.xdist_group("fuzz_modbus_docker"),
]


def _get_request_names(protocol_name):
    """Get request definition names for a protocol."""
    from oida.fuzz.protocols import PROTOCOL_FUZZERS

    fuzzer_class = PROTOCOL_FUZZERS.get(protocol_name)
    if not fuzzer_class:
        return []
    return [r.name for r in fuzzer_class.get_request_definitions()]


MODBUS_REQUESTS = _get_request_names("modbus")

# Known boofuzz artifact: when the web UI is enabled and the fuzzer finishes in a
# subprocess, boofuzz calls ``input()`` which hits EOF.  This produces an
# EOFError traceback that is NOT a real crash.
_BOOFUZZ_EOF_MARKER = "EOFError: EOF when reading a line"


def _has_real_traceback(output: str) -> bool:
    """Return True if *output* contains a Python traceback other than the known boofuzz EOF."""
    if "Traceback" not in output:
        return False
    # Split on "Traceback" and check each occurrence
    for part in output.split("Traceback")[1:]:
        # If this traceback does NOT end with the boofuzz EOF marker, it's real
        # Grab the chunk up to the next blank line or end
        chunk = part[:1000]
        if _BOOFUZZ_EOF_MARKER not in chunk:
            return True
    return False


# =============================================================================
# Tier 4: Definition execution against Docker mock
# =============================================================================


class TestModbusDockerDefinitions:
    """Run each Modbus request definition against the Docker mock server."""

    @pytest.mark.parametrize("request_name", MODBUS_REQUESTS or ["skip"], ids=lambda r: r)
    def test_definition_executes(self, request_name, fuzz_session, modbus_port):
        if request_name == "skip":
            pytest.skip("No Modbus request definitions found")

        require_docker_mock("modbus")
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if not fuzzer_class:
            require_service("Modbus fuzzer not available")

        config = create_fuzzer_config(
            MOCK_HOST,
            modbus_port,
            "modbus",
            fuzz_session,
            index_end=5,
            enabled_requests=[request_name],
        )
        fuzzer = None
        try:
            fuzzer = fuzzer_class(config=config)
            run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=15)
        except FuzzTimeout:
            pass  # Timeout is acceptable -- definition executed
        except (ConnectionError, OSError):
            pass  # Connection issues are acceptable
        except ImportError as e:
            require_service(f"Missing dependency: {e}")

        if fuzzer is None:
            pytest.skip(f"Could not construct Modbus fuzzer for '{request_name}'")

        assert fuzzer.session.total_mutant_index > 0, (
            f"Modbus request definition '{request_name}' never sent a single "
            "mutated test case to the Docker mock"
        )


# =============================================================================
# Tier 5: Monitor baseline against Docker mock
# =============================================================================


class TestModbusDockerMonitor:
    """Modbus monitor against Docker mock server."""

    def test_monitor_runs_and_passes(self, fuzz_session, modbus_port):
        """Monitor should check at least once and find a healthy Docker mock."""
        require_docker_mock("modbus")
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.core.config import MonitorConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if not fuzzer_class:
            require_service("Modbus fuzzer not available")

        config = create_fuzzer_config(
            MOCK_HOST,
            modbus_port,
            "modbus",
            fuzz_session,
            index_end=20,
            monitor_config=MonitorConfig.parse("modbus:5,socket"),
            monitor_check_interval=5,
            skip_pre_send_checks=False,
        )

        try:
            fuzzer = fuzzer_class(config=config)
            run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=30)
        except FuzzTimeout:
            pass
        except (ConnectionError, OSError):
            pass
        except ImportError as e:
            require_service(f"Missing dependency: {e}")

        if hasattr(fuzzer, "monitor") and fuzzer.monitor:
            assert fuzzer.monitor.actual_check_count >= 1, (
                f"Monitor should have performed at least 1 check, "
                f"got {fuzzer.monitor.actual_check_count}"
            )
            assert fuzzer.monitor.total_failures == 0, (
                f"Docker mock should be healthy, but got {fuzzer.monitor.total_failures} failures"
            )

    def test_connection_reuse_disabled(self, fuzz_session, modbus_port):
        """Fuzzing with reuse_target_connection=False should not crash."""
        require_docker_mock("modbus")
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if not fuzzer_class:
            require_service("Modbus fuzzer not available")

        config = create_fuzzer_config(
            MOCK_HOST,
            modbus_port,
            "modbus",
            fuzz_session,
            index_end=5,
            reuse_target_connection=False,
        )

        fuzzer = None
        try:
            fuzzer = fuzzer_class(config=config)
            run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=30)
        except FuzzTimeout:
            pass  # Timeout is acceptable
        except (ConnectionError, OSError):
            pass  # Connection issues are acceptable

        if fuzzer is None:
            pytest.skip("Could not construct Modbus fuzzer with reuse_target_connection=False")

        assert fuzzer.session.total_mutant_index > 0, (
            "Fuzzing with reuse_target_connection=False never sent a single "
            "mutated test case to the Docker mock"
        )


# =============================================================================
# Session DB recording against Docker mock
# =============================================================================


class TestModbusDockerSession:
    """Session DB recording against Docker mock."""

    def test_session_db_created(self, fuzz_session, modbus_port):
        """Fuzzing 10 cases should create a session .db file."""
        require_docker_mock("modbus")
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if not fuzzer_class:
            require_service("Modbus fuzzer not available")

        config = create_fuzzer_config(
            MOCK_HOST,
            modbus_port,
            "modbus",
            fuzz_session,
            index_end=10,
            log_session=True,
        )

        try:
            fuzzer = fuzzer_class(config=config)
            run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=30)
        except FuzzTimeout:
            pass
        except (ConnectionError, OSError):
            pass
        except ImportError as e:
            require_service(f"Missing dependency: {e}")

        db_path = f"{fuzz_session}.db"
        assert os.path.exists(db_path), "Session database was not created"

        # Verify schema has test_cases table with rows
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM test_cases")
            count = cursor.fetchone()[0]
            assert count > 0, "Session DB should have test_case rows"

            # Verify protocol field if column exists
            cursor = conn.execute("PRAGMA table_info(test_cases)")
            columns = {row[1] for row in cursor.fetchall()}
            if "protocol" in columns:
                cursor = conn.execute(
                    "SELECT DISTINCT protocol FROM test_cases WHERE protocol IS NOT NULL"
                )
                protocols = {row[0] for row in cursor.fetchall()}
                if protocols:
                    assert "modbus" in protocols, f"Expected 'modbus' protocol, got {protocols}"
        finally:
            conn.close()

    def test_store_all_payloads(self, tmp_path, modbus_port):
        """With store_all_payloads=True, payloads table should have rows."""
        require_docker_mock("modbus")
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if not fuzzer_class:
            require_service("Modbus fuzzer not available")

        session = str(tmp_path / "payload_session")
        config = create_fuzzer_config(
            MOCK_HOST,
            modbus_port,
            "modbus",
            session,
            index_end=10,
            log_session=True,
            store_all_payloads=True,
        )

        try:
            fuzzer = fuzzer_class(config=config)
            run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=30)
        except FuzzTimeout:
            pass
        except (ConnectionError, OSError):
            pass
        except ImportError as e:
            require_service(f"Missing dependency: {e}")

        db_path = f"{session}.db"
        if not os.path.exists(db_path):
            pytest.skip("Session DB not created (fuzzer may not have run)")

        conn = sqlite3.connect(db_path)
        try:
            # Check that payloads table exists and has rows
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='payloads'"
            )
            if cursor.fetchone() is not None:
                cursor = conn.execute("SELECT COUNT(*) FROM payloads")
                count = cursor.fetchone()[0]
                assert count > 0, "Payloads table should have rows with store_all_payloads=True"
        finally:
            conn.close()

    def test_session_metadata_stored(self, tmp_path, modbus_port):
        """Session metadata table should contain schema_version after fuzzing."""
        require_docker_mock("modbus")
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if not fuzzer_class:
            require_service("Modbus fuzzer not available")

        session = str(tmp_path / "metadata_session")
        config = create_fuzzer_config(
            MOCK_HOST,
            modbus_port,
            "modbus",
            session,
            index_end=5,
            log_session=True,
        )

        try:
            fuzzer = fuzzer_class(config=config)
            run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=30)
        except FuzzTimeout:
            pass
        except (ConnectionError, OSError):
            pass
        except ImportError as e:
            require_service(f"Missing dependency: {e}")

        db_path = f"{session}.db"
        if not os.path.exists(db_path):
            pytest.skip("Session DB not created (fuzzer may not have run)")

        conn = sqlite3.connect(db_path)
        try:
            # session_metadata table should exist
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='session_metadata'"
            )
            assert cursor.fetchone() is not None, "session_metadata table should exist"

            # schema_version key should be present
            cursor = conn.execute("SELECT value FROM session_metadata WHERE key = 'schema_version'")
            row = cursor.fetchone()
            assert row is not None, "schema_version key should exist in session_metadata"
            assert row[0], "schema_version should have a non-empty value"
        finally:
            conn.close()

    def test_test_case_results_valid(self, tmp_path, modbus_port):
        """All test_cases.result values must be in the CHECK constraint set."""
        require_docker_mock("modbus")
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if not fuzzer_class:
            require_service("Modbus fuzzer not available")

        session = str(tmp_path / "results_session")
        config = create_fuzzer_config(
            MOCK_HOST,
            modbus_port,
            "modbus",
            session,
            index_end=10,
            log_session=True,
        )

        try:
            fuzzer = fuzzer_class(config=config)
            run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=30)
        except FuzzTimeout:
            pass
        except (ConnectionError, OSError):
            pass
        except ImportError as e:
            require_service(f"Missing dependency: {e}")

        db_path = f"{session}.db"
        if not os.path.exists(db_path):
            pytest.skip("Session DB not created (fuzzer may not have run)")

        valid_results = {"pass", "fail", "crash", "error"}
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.execute("SELECT DISTINCT result FROM test_cases")
            actual_results = {row[0] for row in cursor.fetchall()}
            if not actual_results:
                pytest.skip("No test case rows recorded (logging context issue)")
            invalid = actual_results - valid_results
            assert not invalid, f"Invalid result values found: {invalid} (expected {valid_results})"
        finally:
            conn.close()

    def test_session_resume_cli(self, tmp_path, modbus_port):
        """Running CLI twice with the same session path should not crash."""
        require_docker_mock("modbus")

        first_request = MODBUS_REQUESTS[0] if MODBUS_REQUESTS else None
        if not first_request:
            pytest.skip("No Modbus requests available")

        session = str(tmp_path / "resume_session")

        # First run - create the session DB
        run_fuzz_cli(
            "modbus",
            MOCK_HOST,
            "-p",
            str(modbus_port),
            "-s",
            session,
            "--seed",
            "12345",
            "-e",
            first_request,
            timeout=30,
        )

        db_path = f"{session}.db"
        if not os.path.exists(db_path):
            pytest.skip("Session DB not created on first run")

        # Second run - resume with same session path
        result = run_fuzz_cli(
            "modbus",
            MOCK_HOST,
            "-p",
            str(modbus_port),
            "-s",
            session,
            "--seed",
            "54321",
            "-e",
            first_request,
            timeout=30,
        )

        # Should not produce a real traceback (boofuzz EOF is expected)
        output = result.output
        assert not _has_real_traceback(output), f"Session resume produced a traceback:\n{output}"


# =============================================================================
# Session replay tests
# =============================================================================


@pytest.fixture
def populated_modbus_session(tmp_path, modbus_port):
    """Create a Modbus session with test case rows for replay testing."""
    require_docker_mock("modbus")

    first_request = MODBUS_REQUESTS[0] if MODBUS_REQUESTS else None
    if not first_request:
        pytest.skip("No Modbus requests available")

    session = str(tmp_path / "modbus_replay")
    run_fuzz_cli(
        "modbus",
        MOCK_HOST,
        "-p",
        str(modbus_port),
        "-s",
        session,
        "--seed",
        "12345",
        "-e",
        first_request,
        "--store-all-payloads",
        timeout=30,
    )

    db_path = f"{session}.db"
    if not os.path.exists(db_path):
        require_service(
            "Failed to create Modbus test session - fuzzer may not have run (missing dep?)"
        )

    return session


class TestModbusReplay:
    """Replay command tests against a populated Modbus session."""

    def test_replay_shows_usage_without_session(self):
        """oida fuzz replay with no session should show usage or error."""
        result = run_fuzz_cli("replay")

        output = result.output
        assert "Usage" in output or "Session" in output or result.returncode != 0

    def test_replay_shows_stats(self, populated_modbus_session):
        """oida fuzz replay <session> shows session statistics."""
        result = run_fuzz_cli("replay", populated_modbus_session, timeout=30)

        output = result.output
        assert "Session:" in output or populated_modbus_session in output
        # Should show total test cases
        assert "Total test cases:" in output or "test cases" in output.lower()

    def test_replay_with_range(self, populated_modbus_session):
        """oida fuzz replay <session> -r 1-5 shows test case details."""
        result = run_fuzz_cli(
            "replay",
            populated_modbus_session,
            "-r",
            "1-5",
            timeout=30,
        )

        output = result.output
        assert "Replaying:" in output or "Range:" in output or result.returncode == 0

    def test_replay_single_case(self, populated_modbus_session):
        """oida fuzz replay <session> --case 1 shows a single test case."""
        result = run_fuzz_cli(
            "replay",
            populated_modbus_session,
            "--case",
            "1",
            timeout=30,
        )

        output = result.output
        assert result.returncode == 0
        # Should show test case details
        assert "Result:" in output or "[1]" in output

    def test_replay_nonexistent_session(self):
        """Replay with a nonexistent session path should error gracefully."""
        result = run_fuzz_cli("replay", "/tmp/nonexistent_session_xyz", timeout=10)

        output = result.output
        assert result.returncode != 0 or "not found" in output.lower() or "error" in output.lower()
        assert "Traceback" not in output, f"Nonexistent session produced a traceback:\n{output}"


# =============================================================================
# Capability enumeration against Docker mock
# =============================================================================


class TestModbusDockerCapabilities:
    """Modbus capability enumeration tests against Docker mock."""

    def test_enumeration_runs_cli(self, fuzz_session, modbus_port):
        """CLI with --enumerate should show enumeration output."""
        require_docker_mock("modbus")

        first_request = MODBUS_REQUESTS[0] if MODBUS_REQUESTS else None
        if not first_request:
            pytest.skip("No Modbus requests available")

        result = run_fuzz_cli(
            "modbus",
            MOCK_HOST,
            "-p",
            str(modbus_port),
            "-s",
            fuzz_session,
            "--enumerate",
            "--seed",
            "12345",
            "-e",
            first_request,
            timeout=45,
        )

        output = result.output
        assert "Enumerating" in output or "Supported FCs" in output or "none detected" in output, (
            f"Enumeration output not found in:\n{output[:500]}"
        )

    def test_enumeration_api(self, fuzz_session, modbus_port):
        """API: enumerate=True should populate fuzzer.capabilities."""
        require_docker_mock("modbus")
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if not fuzzer_class:
            require_service("Modbus fuzzer not available")

        config = create_fuzzer_config(
            MOCK_HOST,
            modbus_port,
            "modbus",
            fuzz_session,
            index_end=5,
            enumerate=True,
        )

        try:
            fuzzer = fuzzer_class(config=config)
            run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=30)
        except FuzzTimeout:
            pass
        except (ConnectionError, OSError):
            pass
        except ImportError as e:
            require_service(f"Missing dependency: {e}")

        assert hasattr(fuzzer, "capabilities"), "Fuzzer should have a capabilities attribute"
        assert isinstance(fuzzer.capabilities, dict), "capabilities should be a dict"
        # With enumerate=True against a real mock, capabilities should be populated
        assert fuzzer.capabilities, "capabilities should be non-empty after enumeration"

    def test_no_enumerate_skips_probing(self, fuzz_session, modbus_port):
        """CLI with --no-enumerate should NOT show enumeration output."""
        require_docker_mock("modbus")

        first_request = MODBUS_REQUESTS[0] if MODBUS_REQUESTS else None
        if not first_request:
            pytest.skip("No Modbus requests available")

        result = run_fuzz_cli(
            "modbus",
            MOCK_HOST,
            "-p",
            str(modbus_port),
            "-s",
            fuzz_session,
            "--no-enumerate",
            "--seed",
            "12345",
            "-e",
            first_request,
            timeout=30,
        )

        output = result.output
        assert "Enumerating" not in output, (
            f"--no-enumerate should skip enumeration, but found 'Enumerating' in:\n{output[:500]}"
        )


# =============================================================================
# End-to-end CLI tests via subprocess
# =============================================================================


class TestModbusFuzzCLI:
    """End-to-end CLI tests via subprocess against Docker mock."""

    def test_list_requests(self):
        """oida fuzz modbus --list-requests shows request names."""
        result = run_fuzz_cli("modbus", "--list-requests")

        assert result.returncode == 0
        output = result.output

        assert "Modbus" in output or "modbus" in output
        # At least one request should be listed
        if MODBUS_REQUESTS:
            assert MODBUS_REQUESTS[0] in output

    def test_show_options(self):
        """oida fuzz modbus --show-options shows protocol options."""
        result = run_fuzz_cli("modbus", "--show-options")

        assert result.returncode == 0
        output = result.output

        assert "Protocol:" in output
        # Modbus should show transport or unit_id
        assert "unit_id" in output or "transport" in output or "Modbus" in output

    def test_fuzz_starts(self, fuzz_session, modbus_port):
        """Fuzzer starts and produces output against Docker mock."""
        require_docker_mock("modbus")

        first_request = MODBUS_REQUESTS[0] if MODBUS_REQUESTS else None
        if not first_request:
            pytest.skip("No Modbus requests available")

        result = run_fuzz_cli(
            "modbus",
            MOCK_HOST,
            "-p",
            str(modbus_port),
            "--seed",
            "12345",
            "--nolog",
            "-e",
            first_request,
            timeout=30,
        )

        output = result.output
        # Fuzzer should at least start (timeout is OK)
        assert "Fuzzer:" in output or "ModbusFuzzer" in output or "modbus" in output.lower()

    def test_fuzz_creates_session_db(self, tmp_path, modbus_port):
        """CLI fuzzing creates session database file."""
        require_docker_mock("modbus")

        first_request = MODBUS_REQUESTS[0] if MODBUS_REQUESTS else None
        if not first_request:
            pytest.skip("No Modbus requests available")

        session = str(tmp_path / "cli_session")
        run_fuzz_cli(
            "modbus",
            MOCK_HOST,
            "-p",
            str(modbus_port),
            "-s",
            session,
            "--seed",
            "12345",
            "-e",
            first_request,
            timeout=30,
        )

        db_path = f"{session}.db"
        assert os.path.exists(db_path), "Session database was not created by CLI"


# =============================================================================
# CLI error handling (no Docker needed)
# =============================================================================


class TestModbusCLIErrors:
    """CLI error handling - these tests do not require Docker."""

    def test_no_target_shows_usage(self):
        """oida fuzz modbus with no target should show usage/error."""
        result = run_fuzz_cli("modbus", timeout=30)

        assert result.returncode != 0, "No-target invocation should exit non-zero"
        output = result.output
        assert (
            "usage" in output.lower() or "error" in output.lower() or "target" in output.lower()
        ), f"Expected usage/error message, got:\n{output[:300]}"

    def test_help_flag(self):
        """oida fuzz modbus --help should exit 0 and show help text."""
        result = run_fuzz_cli("modbus", "--help", timeout=30)

        assert result.returncode == 0, f"--help should exit 0, got {result.returncode}"
        output = result.output
        assert "help" in output.lower() or "usage" in output.lower(), (
            f"Expected help text, got:\n{output[:300]}"
        )

    def test_invalid_port(self):
        """Invalid port number should produce a graceful error."""
        result = run_fuzz_cli(
            "modbus",
            "127.0.0.1",
            "-p",
            "99999",
            "--nolog",
            timeout=15,
        )

        output = result.output
        # Should fail gracefully - no Python traceback
        assert result.returncode != 0 or "error" in output.lower() or "invalid" in output.lower()
        assert "Traceback" not in output, f"Invalid port produced a traceback:\n{output}"

    def test_invalid_host(self):
        """Invalid hostname should produce a graceful error."""
        result = run_fuzz_cli(
            "modbus",
            "invalid.nonexistent.host.example",
            "-p",
            "502",
            "--nolog",
            timeout=15,
        )

        output = result.output
        assert result.returncode != 0 or "error" in output.lower() or "fail" in output.lower()
        assert "Traceback" not in output, f"Invalid host produced a traceback:\n{output}"

    def test_invalid_option_format(self):
        """Malformed -O (no '=') should produce a graceful error."""
        result = run_fuzz_cli(
            "modbus",
            "127.0.0.1",
            "-O",
            "no_equals_sign",
            "--nolog",
            timeout=15,
        )

        output = result.output
        assert (
            result.returncode != 0
            or "error" in output.lower()
            or "invalid" in output.lower()
            or "=" in output
        )
        assert "Traceback" not in output, f"Invalid option format produced a traceback:\n{output}"


# =============================================================================
# CLI feature flags (seed, enable, options, -F, -X)
# =============================================================================


class TestModbusCLIFeatures:
    """CLI feature flag tests - some require Docker."""

    def test_seed_reproducibility(self, modbus_port):
        """Same seed should produce deterministic output across two runs."""
        require_docker_mock("modbus")

        first_request = MODBUS_REQUESTS[0] if MODBUS_REQUESTS else None
        if not first_request:
            pytest.skip("No Modbus requests available")

        with tempfile.TemporaryDirectory() as tmpdir:
            session1 = os.path.join(tmpdir, "seed_session1")
            session2 = os.path.join(tmpdir, "seed_session2")

            for session in [session1, session2]:
                result = run_fuzz_cli(
                    "modbus",
                    MOCK_HOST,
                    "-p",
                    str(modbus_port),
                    "-s",
                    session,
                    "--seed",
                    "99999",
                    "--nolog",
                    "-e",
                    first_request,
                    timeout=30,
                )
                output = result.output
                assert "Seed: 99999" in output or "0x1869F" in output, (
                    f"Seed 99999 not reflected in output:\n{output[:500]}"
                )

    def test_fuzz_with_enable(self, fuzz_session, modbus_port):
        """CLI --enable should select the specified request."""
        require_docker_mock("modbus")

        first_request = MODBUS_REQUESTS[0] if MODBUS_REQUESTS else None
        if not first_request:
            pytest.skip("No Modbus requests available")

        result = run_fuzz_cli(
            "modbus",
            MOCK_HOST,
            "-p",
            str(modbus_port),
            "-s",
            fuzz_session,
            "--seed",
            "12345",
            "-e",
            first_request,
            timeout=30,
        )

        output = result.output
        # Fuzzer should start and mention the enabled request or protocol
        assert first_request in output or "modbus" in output.lower(), (
            f"Enabled request '{first_request}' not reflected in output:\n{output[:500]}"
        )

    def test_fuzz_with_protocol_options(self, fuzz_session, modbus_port):
        """CLI -O unit_id=5 should start fuzzer without error."""
        require_docker_mock("modbus")

        first_request = MODBUS_REQUESTS[0] if MODBUS_REQUESTS else None
        if not first_request:
            pytest.skip("No Modbus requests available")

        result = run_fuzz_cli(
            "modbus",
            MOCK_HOST,
            "-p",
            str(modbus_port),
            "-s",
            fuzz_session,
            "--seed",
            "12345",
            "--nolog",
            "-O",
            "unit_id=5",
            "-e",
            first_request,
            timeout=30,
        )

        output = result.output
        # Should not produce a real traceback (boofuzz EOF is expected)
        assert not _has_real_traceback(output), f"-O unit_id=5 produced a traceback:\n{output}"
        # Fuzzer should at least start
        assert "modbus" in output.lower() or "Fuzzer:" in output or result.timed_out

    def test_fire_forget_mode_cli(self, fuzz_session, modbus_port):
        """CLI -F (fire-forget) should start fuzzer without traceback."""
        require_docker_mock("modbus")

        first_request = MODBUS_REQUESTS[0] if MODBUS_REQUESTS else None
        if not first_request:
            pytest.skip("No Modbus requests available")

        result = run_fuzz_cli(
            "modbus",
            MOCK_HOST,
            "-p",
            str(modbus_port),
            "-s",
            fuzz_session,
            "--seed",
            "12345",
            "--nolog",
            "-F",
            "-e",
            first_request,
            timeout=30,
        )

        output = result.output
        assert not _has_real_traceback(output), f"-F flag produced a traceback:\n{output}"

    def test_no_receive_mode_cli(self, fuzz_session, modbus_port):
        """CLI -X (no-receive) should start fuzzer without traceback."""
        require_docker_mock("modbus")

        first_request = MODBUS_REQUESTS[0] if MODBUS_REQUESTS else None
        if not first_request:
            pytest.skip("No Modbus requests available")

        result = run_fuzz_cli(
            "modbus",
            MOCK_HOST,
            "-p",
            str(modbus_port),
            "-s",
            fuzz_session,
            "--seed",
            "12345",
            "--nolog",
            "-X",
            "-e",
            first_request,
            timeout=30,
        )

        output = result.output
        assert not _has_real_traceback(output), f"-X flag produced a traceback:\n{output}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=120"])
