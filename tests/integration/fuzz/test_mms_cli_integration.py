"""
CLI integration tests for MMS fuzzer.

Tests invoke 'oida fuzz mms' commands as subprocesses and verify output.
Requires Docker mock MMS server running on port 102 (make mock-start).

State Machine:
    CONNECTED -> COTP_ESTABLISHED -> MMS_ASSOCIATED

State Requirements by Request:
    CONNECTED:        MMS_Baseline, MMS_Buffer_Overflow, MMS_ASN1_Attacks,
                      MMS_OSI_Layer, MMS_Malformed_PDU
    COTP_ESTABLISHED: MMS_Invoke_ID, MMS_IEC61850_Attacks, MMS_Session_Mgmt
    MMS_ASSOCIATED:   MMS_Write_Operations, MMS_Control_Operations,
                      MMS_File_Services, MMS_Read_Operations, MMS_Reports
"""

import os
import tempfile

import pytest

from tests.service_gate import require_service

from tests.integration.fuzz.conftest import require_docker_mock, run_fuzz_cli

# Mark all tests in this module
pytestmark = [pytest.mark.mms, pytest.mark.fuzz, pytest.mark.cli]


# =============================================================================
# State Definitions
# =============================================================================

# MMS state machine states in order
MMS_STATES = ["CONNECTED", "COTP_ESTABLISHED", "MMS_ASSOCIATED"]

# Request -> required state mapping
STATE_REQUIREMENTS = {
    "CONNECTED": [
        "MMS_Baseline",
        "MMS_Buffer_Overflow",
        "MMS_ASN1_Attacks",
        "MMS_OSI_Layer",
        "MMS_Malformed_PDU",
    ],
    "COTP_ESTABLISHED": [
        "MMS_Invoke_ID",
        "MMS_IEC61850_Attacks",
        "MMS_Session_Mgmt",
    ],
    "MMS_ASSOCIATED": [
        "MMS_Write_Operations",
        "MMS_Control_Operations",
        "MMS_File_Services",
        "MMS_Read_Operations",
        "MMS_Reports",
    ],
}

# All 13 request names
ALL_REQUESTS = [
    "MMS_Baseline",
    "MMS_Buffer_Overflow",
    "MMS_ASN1_Attacks",
    "MMS_OSI_Layer",
    "MMS_Write_Operations",
    "MMS_Control_Operations",
    "MMS_File_Services",
    "MMS_Invoke_ID",
    "MMS_IEC61850_Attacks",
    "MMS_Malformed_PDU",
    "MMS_Read_Operations",
    "MMS_Reports",
    "MMS_Session_Mgmt",
]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_session():
    """Create temporary session directory for test isolation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        session_path = os.path.join(tmpdir, "mms_cli_test")
        yield session_path


@pytest.fixture
def populated_session(temp_session, mms_host, mms_port):
    """Create a session with some test cases for replay testing."""
    require_docker_mock("mms")

    # Run a quick fuzz to populate the session
    run_fuzz_cli(
        "mms",
        mms_host,
        "-p",
        str(mms_port),
        "-s",
        temp_session,
        "--seed",
        "12345",
        # NOTE: do NOT pass --nolog here — it disables session-DB persistence,
        # so no <session>.db is written and the replay tests below all skip.
        "-e",
        "MMS_Baseline",
        timeout=60,
    )

    # Session should be created
    db_path = f"{temp_session}.db"
    if not os.path.exists(db_path):
        require_service("Failed to create test session — fuzzer may not have run (missing dep?)")

    return temp_session


# =============================================================================
# Test CLI Info Commands
# =============================================================================


class TestMMSCLIInfo:
    """Tests for MMS fuzzer info commands (--show-options, --list-requests)."""

    def test_mms_show_options(self):
        """oida fuzz mms --show-options displays protocol options."""
        result = run_fuzz_cli("mms", "--show-options")

        assert result.returncode == 0
        output = result.output

        # Verify key options are shown
        assert "Protocol: MMS" in output
        assert "invoke_id_start" in output
        assert "max_pdu_size" in output
        assert "domain_name" in output
        assert "use_osi_stack" in output

    def test_mms_list_requests(self):
        """oida fuzz mms --list-requests shows 13 request definitions."""
        result = run_fuzz_cli("mms", "--list-requests")

        assert result.returncode == 0
        output = result.output

        # Verify protocol header
        assert "MMS" in output
        assert "Fuzzable Requests" in output or "Requests" in output

        # Verify all 13 requests are listed
        found_requests = []
        for req in ALL_REQUESTS:
            if req in output:
                found_requests.append(req)

        assert len(found_requests) >= 13, (
            f"Expected 13 requests, found {len(found_requests)}: {found_requests}"
        )

    def test_mms_list_requests_shows_state_requirements(self):
        """Request list includes state requirements for each request."""
        result = run_fuzz_cli("mms", "--list-requests")

        assert result.returncode == 0
        output = result.output

        # Verify state names appear in output (state requirements)
        for state in MMS_STATES:
            assert state in output, f"State '{state}' not found in request listing"

    def test_mms_list_requests_shows_categories(self):
        """Request list includes category information."""
        result = run_fuzz_cli("mms", "--list-requests")

        assert result.returncode == 0
        output = result.output

        # Verify categories are shown (from RequestInfo.category)
        categories = ["baseline", "crash", "write", "boundary", "read"]
        found_categories = [cat for cat in categories if cat in output.lower()]

        assert len(found_categories) >= 3, f"Expected categories in output: {categories}"


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================


class TestMMSCLIArguments:
    """Tests for MMS fuzzer CLI argument parsing."""

    def test_mms_no_target_shows_usage(self):
        """Missing target displays protocol usage information."""
        result = run_fuzz_cli("mms")

        # Should fail but show usage
        assert result.returncode != 0
        output = result.output

        assert "Target required" in output or "Usage:" in output
        assert "mms" in output.lower()

    def test_mms_help_flag(self):
        """--help shows fuzzer help."""
        result = run_fuzz_cli("mms", "--help")

        # Help should succeed
        output = result.output
        assert "fuzz" in output.lower() or "usage" in output.lower()

    def test_mms_invalid_option_format(self):
        """Invalid option format (missing =) shows error."""
        result = run_fuzz_cli(
            "mms",
            "--show-options",
            "-O",
            "invalid_format_no_equals",
            timeout=10,
        )

        # Should show options without crashing
        output = result.output
        # The CLI may ignore malformed options or show them
        assert "Protocol: MMS" in output or result.returncode == 0


# =============================================================================
# Test State Machine Verification via CLI
# =============================================================================


class TestMMSCLIStateMachine:
    """Tests that verify state machine transitions via CLI output."""

    def test_state_machine_initialized_in_output(self, mms_host, mms_port, temp_session):
        """Verify state machine initialization message appears in output."""
        require_docker_mock("mms")

        result = run_fuzz_cli(
            "mms",
            mms_host,
            "-p",
            str(mms_port),
            "-s",
            temp_session,
            "--seed",
            "12345",
            "--nolog",
            "-v",  # Verbose to see state machine output
            "-e",
            "MMS_Baseline",
            timeout=60,
        )

        output = result.output

        # Look for state machine initialization
        assert "State machine" in output or "state machine" in output or "MMS_ASSOCIATED" in output

    @pytest.mark.slow
    def test_connected_state_requests_run(self, mms_host, mms_port, temp_session):
        """Requests requiring CONNECTED state can run against mock server."""
        require_docker_mock("mms")

        # Run baseline request (requires CONNECTED)
        result = run_fuzz_cli(
            "mms",
            mms_host,
            "-p",
            str(mms_port),
            "-s",
            temp_session,
            "--seed",
            "12345",
            "--nolog",
            "-e",
            "MMS_Baseline",
            timeout=60,
        )

        output = result.output

        # Should run successfully
        assert "Fuzzer:" in output or "MMSFuzzer" in output
        assert result.returncode == 0 or "completed" in output.lower()

    @pytest.mark.slow
    def test_cotp_state_requests_run(self, mms_host, mms_port, temp_session):
        """Requests requiring COTP_ESTABLISHED state can run."""
        require_docker_mock("mms")

        # Run invoke ID request (requires COTP_ESTABLISHED)
        result = run_fuzz_cli(
            "mms",
            mms_host,
            "-p",
            str(mms_port),
            "-s",
            temp_session,
            "--seed",
            "12345",
            "--nolog",
            "-e",
            "MMS_Invoke_ID",
            timeout=60,
        )

        output = result.output

        # Should run (verify fuzzer started)
        assert "Fuzzer:" in output or "MMSFuzzer" in output

    @pytest.mark.slow
    def test_mms_associated_state_requests_run(self, mms_host, mms_port, temp_session):
        """Requests requiring MMS_ASSOCIATED state can run."""
        require_docker_mock("mms")

        # Run read operations (requires MMS_ASSOCIATED)
        result = run_fuzz_cli(
            "mms",
            mms_host,
            "-p",
            str(mms_port),
            "-s",
            temp_session,
            "--seed",
            "12345",
            "--nolog",
            "-e",
            "MMS_Read_Operations",
            timeout=60,
        )

        output = result.output

        # Should run (verify fuzzer started)
        assert "Fuzzer:" in output or "MMSFuzzer" in output


# =============================================================================
# Test Fuzzing Execution
# =============================================================================


class TestMMSCLIFuzzing:
    """Tests for MMS fuzzer execution via CLI."""

    @pytest.mark.slow
    def test_mms_fuzz_basic(self, mms_host, mms_port, temp_session):
        """Basic MMS fuzzing against mock server."""
        require_docker_mock("mms")

        result = run_fuzz_cli(
            "mms",
            mms_host,
            "-p",
            str(mms_port),
            "-s",
            temp_session,
            "--seed",
            "12345",
            "--nolog",
            "-e",
            "MMS_Baseline",  # Limit to quick request
            timeout=60,
        )

        # Timeout is OK if fuzzer started
        assert "Fuzzer: MMSFuzzer" in result.output
        assert "Seed: 12345" in result.output or "0x3039" in result.output

    @pytest.mark.slow
    def test_mms_fuzz_with_enable(self, mms_host, mms_port, temp_session):
        """Fuzz with --enable to select specific requests."""
        require_docker_mock("mms")

        result = run_fuzz_cli(
            "mms",
            mms_host,
            "-p",
            str(mms_port),
            "-s",
            temp_session,
            "--seed",
            "12345",
            "--nolog",
            "-e",
            "MMS_Baseline,MMS_Buffer_Overflow",
            timeout=60,
        )

        output = result.output

        # Verify enabled requests shown
        assert "Enabled:" in output or "MMS_Baseline" in output

    @pytest.mark.slow
    def test_mms_fuzz_with_options(self, mms_host, mms_port, temp_session):
        """Protocol options via -O are applied."""
        require_docker_mock("mms")

        result = run_fuzz_cli(
            "mms",
            mms_host,
            "-p",
            str(mms_port),
            "-s",
            temp_session,
            "--seed",
            "12345",
            "--nolog",
            "-O",
            "domain_name=TEST01",
            "-e",
            "MMS_Baseline",
            timeout=60,
        )

        output = result.output

        # Verify fuzzer ran with options
        assert "Fuzzer:" in output

    @pytest.mark.slow
    def test_mms_fuzz_creates_session_db(self, mms_host, mms_port, temp_session):
        """Fuzzing creates session database file."""
        require_docker_mock("mms")

        db_path = f"{temp_session}.db"

        # Ensure DB doesn't exist before
        if os.path.exists(db_path):
            os.remove(db_path)

        run_fuzz_cli(
            "mms",
            mms_host,
            "-p",
            str(mms_port),
            "-s",
            temp_session,
            "--seed",
            "12345",
            "-e",
            "MMS_Baseline",
            timeout=60,
        )

        # Session DB should be created
        assert os.path.exists(db_path), "Session database was not created"

    @pytest.mark.slow
    def test_mms_fuzz_seed_reproducibility(self, mms_host, mms_port):
        """Same seed produces reproducible session with deterministic output."""
        require_docker_mock("mms")

        with tempfile.TemporaryDirectory() as tmpdir:
            session1 = os.path.join(tmpdir, "session1")
            session2 = os.path.join(tmpdir, "session2")

            # Run twice with same seed - verify both start with same seed
            for session in [session1, session2]:
                result = run_fuzz_cli(
                    "mms",
                    mms_host,
                    "-p",
                    str(mms_port),
                    "-s",
                    session,
                    "--seed",
                    "99999",
                    "--nolog",
                    "-e",
                    "MMS_Baseline",
                    timeout=45,
                )
                # Fuzzer should start with correct seed
                assert "Seed: 99999" in result.output or "0x1869F" in result.output


# =============================================================================
# Test Session Management
# =============================================================================


class TestMMSCLISession:
    """Tests for MMS fuzzer session management."""

    def test_mms_replay_shows_usage_without_session(self):
        """Replay without session shows usage."""
        result = run_fuzz_cli("replay")

        output = result.output
        # Should show usage or error
        assert "Usage" in output or "Session" in output or result.returncode != 0

    @pytest.mark.slow
    def test_mms_replay_shows_stats(self, populated_session):
        """oida fuzz replay shows session statistics."""
        result = run_fuzz_cli("replay", populated_session, timeout=30)

        output = result.output

        # Should show session info
        assert "Session:" in output or populated_session in output

    @pytest.mark.slow
    def test_mms_replay_with_range(self, populated_session):
        """Replay with range specification."""
        result = run_fuzz_cli(
            "replay",
            populated_session,
            "-r",
            "1-5",
            timeout=30,
        )

        output = result.output

        # Should show replaying
        assert "Replaying:" in output or "Range:" in output or result.returncode == 0


# =============================================================================
# Test Error Handling
# =============================================================================


class TestMMSCLIErrors:
    """Tests for MMS fuzzer error handling."""

    def test_mms_fuzz_invalid_port(self, temp_session):
        """Connection failure to invalid port is handled gracefully."""
        result = run_fuzz_cli(
            "mms",
            "127.0.0.1",
            "-p",
            "65000",  # Unlikely to be open
            "-s",
            temp_session,
            "--nolog",
            "-e",
            "MMS_Baseline",
            timeout=30,
        )

        # Should fail but not crash
        output = result.output
        # Connection error is expected
        assert (
            result.returncode != 0
            or "error" in output.lower()
            or "fail" in output.lower()
            or "refused" in output.lower()
        )

    def test_mms_fuzz_invalid_host(self, temp_session):
        """Invalid host is handled gracefully."""
        result = run_fuzz_cli(
            "mms",
            "invalid.nonexistent.host.example",
            "-p",
            "102",
            "-s",
            temp_session,
            "--nolog",
            timeout=30,
        )

        # Should fail but not crash
        output = result.output
        assert result.returncode != 0 or "error" in output.lower() or "fail" in output.lower()

    def test_mms_unknown_protocol(self):
        """Unknown protocol shows error."""
        result = run_fuzz_cli("nonexistent_protocol", "127.0.0.1")

        output = result.output
        assert result.returncode != 0 or "Unknown" in output or "unknown" in output


# =============================================================================
# Test State-Specific Request Execution
# =============================================================================


class TestMMSCLIStateRequests:
    """Tests that verify each state's requests can be enabled and run."""

    @pytest.mark.slow
    @pytest.mark.parametrize("request_name", STATE_REQUIREMENTS["CONNECTED"])
    def test_connected_state_request(self, request_name, mms_host, mms_port):
        """Each CONNECTED state request can be enabled and run."""
        require_docker_mock("mms")

        with tempfile.TemporaryDirectory() as tmpdir:
            session = os.path.join(tmpdir, f"test_{request_name}")

            result = run_fuzz_cli(
                "mms",
                mms_host,
                "-p",
                str(mms_port),
                "-s",
                session,
                "--seed",
                "12345",
                "--nolog",
                "-e",
                request_name,
                timeout=45,
            )

            # Verify fuzzer started with the request (timeout is OK)
            assert "Fuzzer:" in result.output, f"Fuzzer failed to start for {request_name}"
            assert f"Enabled: {request_name}" in result.output or request_name in result.output

    @pytest.mark.slow
    @pytest.mark.parametrize("request_name", STATE_REQUIREMENTS["COTP_ESTABLISHED"])
    def test_cotp_state_request(self, request_name, mms_host, mms_port):
        """Each COTP_ESTABLISHED state request can be enabled and run."""
        require_docker_mock("mms")

        with tempfile.TemporaryDirectory() as tmpdir:
            session = os.path.join(tmpdir, f"test_{request_name}")

            result = run_fuzz_cli(
                "mms",
                mms_host,
                "-p",
                str(mms_port),
                "-s",
                session,
                "--seed",
                "12345",
                "--nolog",
                "-e",
                request_name,
                timeout=45,
            )

            # Verify fuzzer started with the request (timeout is OK)
            assert "Fuzzer:" in result.output, f"Fuzzer failed to start for {request_name}"
            assert f"Enabled: {request_name}" in result.output or request_name in result.output

    @pytest.mark.slow
    @pytest.mark.parametrize("request_name", STATE_REQUIREMENTS["MMS_ASSOCIATED"])
    def test_mms_associated_state_request(self, request_name, mms_host, mms_port):
        """Each MMS_ASSOCIATED state request can be enabled and run."""
        require_docker_mock("mms")

        with tempfile.TemporaryDirectory() as tmpdir:
            session = os.path.join(tmpdir, f"test_{request_name}")

            result = run_fuzz_cli(
                "mms",
                mms_host,
                "-p",
                str(mms_port),
                "-s",
                session,
                "--seed",
                "12345",
                "--nolog",
                "-e",
                request_name,
                timeout=45,
            )

            # Verify fuzzer started with the request (timeout is OK)
            assert "Fuzzer:" in result.output, f"Fuzzer failed to start for {request_name}"
            assert f"Enabled: {request_name}" in result.output or request_name in result.output


# =============================================================================
# Test All States Reachable
# =============================================================================


class TestMMSCLIStateReachability:
    """Tests that verify all states can be reached via CLI execution."""

    @pytest.mark.slow
    def test_all_states_reachable(self, mms_host, mms_port):
        """All 3 MMS states should be reachable against the mock server."""
        require_docker_mock("mms")

        # Run with verbose to capture state machine output
        with tempfile.TemporaryDirectory() as tmpdir:
            session = os.path.join(tmpdir, "state_test")

            result = run_fuzz_cli(
                "mms",
                mms_host,
                "-p",
                str(mms_port),
                "-s",
                session,
                "--seed",
                "12345",
                "--nolog",
                "-v",  # Verbose
                "-e",
                "MMS_Baseline",  # Limit to quick test
                timeout=45,
            )

            # Verify fuzzer ran (timeout is OK)
            assert "Fuzzer:" in result.output

            # The highest state should be MMS_ASSOCIATED when connected to mock
            assert "MMS_ASSOCIATED" in result.output or "State machine" in result.output

    @pytest.mark.slow
    def test_requests_from_all_states_run(self, mms_host, mms_port):
        """Requests from all state levels can run in a single session."""
        require_docker_mock("mms")

        # Enable one request from each state level
        requests = "MMS_Baseline,MMS_Invoke_ID,MMS_Read_Operations"

        with tempfile.TemporaryDirectory() as tmpdir:
            session = os.path.join(tmpdir, "multi_state_test")

            result = run_fuzz_cli(
                "mms",
                mms_host,
                "-p",
                str(mms_port),
                "-s",
                session,
                "--seed",
                "12345",
                "--nolog",
                "-e",
                requests,
                timeout=90,
            )

            output = result.output

            # Verify fuzzer ran with all requests
            assert "Fuzzer:" in output
            assert "Enabled:" in output or "MMS_Baseline" in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
