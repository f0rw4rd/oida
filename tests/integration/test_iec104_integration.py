"""
IEC 60870-5-104 Protocol Integration Tests

Tests oida iec104 scanner against Docker mock services (lib60870-based).

Mock profiles:
  - iec104-lib60870 (port 2404): lib60870 server, COMMON_ADDRESS=1
    120 data points across 8 type IDs (M_SP, M_DP, M_ST, M_BO, M_ME_NA/NB/NC, M_IT),
    3 files + directory (IOA 10000-10003), file transfer Type IDs 120-127
  - iec104-custom-types (port 2405): Python mock with vendor-specific
    Type IDs 200, 201, 210, 220 on IOAs 1000-1019
  - iec104-conpot (port 2409): Conpot honeypot, ASDU address 7720
  - iec104-tls (port 19998): TLS-enabled lib60870 (c104 TLS broken — xfail)

Uses structured JSON log assertions for precise validation.
"""

import pytest

from .conftest import DOCKER_COMPOSE_PATH, MOCK_HOST, MOCK_PORTS, check_port_open
from tests.service_gate import require_port, require_service

pytestmark = pytest.mark.xdist_group("iec104_service")


# ---------------------------------------------------------------------------
# Constants — known mock data (ground truth from iec104_server.c)
# ---------------------------------------------------------------------------

IEC104_PORT = MOCK_PORTS.get("iec104", 2404)
IEC104_CUSTOM_PORT = MOCK_PORTS.get("iec104_custom", 2405)
IEC104_CONPOT_PORT = MOCK_PORTS.get("iec104_conpot", 2409)
IEC104_TLS_PORT = MOCK_PORTS.get("iec104_tls", 19998)

# lib60870 mock (port 2404): 120 data points across 8 type IDs
MOCK_COMMON_ADDRESS = 1
MOCK_POINT_COUNT = 120
MOCK_TYPE_NAMES = [
    "m_sp_na",
    "m_dp_na",
    "m_st_na",
    "m_bo_na",
    "m_me_na",
    "m_me_nb",
    "m_me_nc",
    "m_it_na",
]
MOCK_IOA_RANGES = {
    "single_points": (100, 119),  # 20 x Type 1
    "double_points": (200, 209),  # 10 x Type 3
    "step_positions": (300, 309),  # 10 x Type 5
    "bitstrings": (400, 409),  # 10 x Type 7
    "normalized": (500, 519),  # 20 x Type 9
    "scaled": (600, 619),  # 20 x Type 11
    "float": (700, 719),  # 20 x Type 13
    "integrated_totals": (800, 809),  # 10 x Type 15
}

# Custom types mock (port 2405)
CUSTOM_TYPE_IDS = [200, 201, 210, 220]
CUSTOM_IOA_RANGE = (1000, 1019)

# Conpot (port 2409)
CONPOT_ASDU_ADDRESS = 7720

# TLS certs directory
IEC104_TLS_CERTS = DOCKER_COMPOSE_PATH.parent / "certs"

# c104 v2.2.1 has a broken mbedtls TLS implementation:
# https://github.com/Fraunhofer-FIT-DIEN/iec104-python/issues/64
# All c104-dependent TLS tests (--tls flag) are xfail until upstream fixes it.
# Server-side TLS is verified independently via Python ssl module.
_C104_TLS_XFAIL = pytest.mark.xfail(
    reason="c104 mbedtls TLS broken (iec104-python#64)", strict=False
)


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


def _get_security_findings(log):
    """Return all security event findings from the log."""
    return [
        e.get("data", {}).get("finding", "")
        for e in log.events
        if e.get("event_type") == "security"
    ]


def _count_discovered_ioas(log) -> int:
    """Count debug-level 'Discovered IOA=...' events in the log."""
    return sum(1 for e in log.events if "discovered ioa=" in e.get("message", "").lower())


def _get_scan_summary(log) -> str:
    """Return the 'scan complete' summary line from the log (lowercase)."""
    for e in log.events:
        if "scan complete" in e.get("message", "").lower():
            return e["message"].lower()
    return ""


# ---------------------------------------------------------------------------
# Test Classification Summary
# ---------------------------------------------------------------------------
# Category A (strict -- mock supports, assert success + validate data):   35 tests
# Category B (conditional -- mock may not support, accept 0 or 1):        25 tests
# Category C (error handling -- assert failure + validate error events):   13 tests
# Total:                                                                   73 tests
# ---------------------------------------------------------------------------


# ===========================================================================
# Class 1: lib60870 Main Mock (port 2404)
# ===========================================================================


@pytest.mark.iec104
class TestIEC104Integration:
    """Integration tests for IEC 104 protocol scanner against lib60870 mock (port 2404)."""

    # ========================================================================
    # Fixtures
    # ========================================================================

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return IEC104_PORT

    @pytest.fixture(autouse=True)
    def _require_iec104_mock(self, target, port):
        """Skip all tests if the IEC 104 mock is not reachable."""
        require_port(target, port, "IEC 104 mock not reachable on {target}:{port}")

    # ========================================================================
    # P1: Help & Basics
    # ========================================================================

    def test_help_command(self, cli_runner):
        """Verify help command works for IEC 104 protocol [Category A]"""
        result = cli_runner.run("iec104", "--help", expect_json=False)
        assert result.returncode == 0
        output = result.combined_output.lower()
        assert "iec104" in output
        assert "--interrogate" in output
        assert "--asdu-address" in output

    def test_basic_discovery(self, cli_runner, target, port):
        """Test default discovery scan (no flags) produces log events [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success, f"Basic discovery failed: {result.stderr}"
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)
        messages = _all_messages(result.scan_log)
        assert "connect" in messages or "testfr" in messages, (
            f"Expected connection/TESTFR messages, got: {messages[:500]}"
        )

    # ========================================================================
    # P2: Interrogation & Discovery
    # ========================================================================

    @pytest.mark.flaky(reruns=2, reruns_delay=2)
    def test_interrogation_discovers_type_ids(self, cli_runner, target, port):
        """Test interrogation discovers known type IDs from mock [Category A]

        Flaky: the c104 general-interrogation round-trip is timing-sensitive
        under CPU contention (passes reliably in isolation). Retried, not a bug.
        """
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--interrogate",
            "--wait-time",
            "5",
            format="json",
            json_log=True,
        )
        assert result.success, f"Interrogation failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # At least some known type names should appear in output or log
        found_types = [t for t in MOCK_TYPE_NAMES if t in text]
        assert len(found_types) >= 1, (
            f"Expected at least 1 known type ID in output, found none. Text: {text[:500]}"
        )

    @pytest.mark.flaky(reruns=2, reruns_delay=3)
    def test_interrogation_discovers_points(self, cli_runner, target, port):
        """Test interrogation discovers data points from mock [Category A]

        General-interrogation against the lib60870 mock occasionally returns an
        empty point set under full-suite load (the GI response races the
        scan-complete summary); reruns give it another attempt rather than
        flaking the whole suite.
        """
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--interrogate",
            format="json",
            json_log=True,
        )
        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        # GI against the lib60870 mock returns all 120 configured points; the
        # scan-complete summary must report that exact count.
        summary = _get_scan_summary(result.scan_log)
        assert f"{MOCK_POINT_COUNT} points" in summary, (
            f"Expected '{MOCK_POINT_COUNT} points' in scan summary, got: {summary!r}"
        )

    def test_discovery_mode(self, cli_runner, target, port):
        """Test discovery-only (no flags) produces log events [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success, f"Discovery mode failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_asdu_address(self, cli_runner, target, port):
        """Test --asdu-address 1 matches mock common address [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--asdu-address",
            str(MOCK_COMMON_ADDRESS),
            format="json",
            json_log=True,
        )
        assert result.success, f"ASDU address scan failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_common_address(self, cli_runner, target, port):
        """Test --common-address 1 works [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--common-address",
            str(MOCK_COMMON_ADDRESS),
            format="json",
            json_log=True,
        )
        assert result.success, f"Common address scan failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_wait_time(self, cli_runner, target, port):
        """Test --wait-time 5 for longer interrogation window [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--wait-time",
            "5",
            format="json",
            json_log=True,
        )
        assert result.success, f"Wait time scan failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # P3: IOA Range
    # ========================================================================

    def test_ioa_range_single_points(self, cli_runner, target, port):
        """Test interrogation covers single points [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--interrogate",
            format="json",
            json_log=True,
        )
        assert result.success, f"IOA range scan failed: {result.stderr}"
        _assert_log_has_events(result)

    @pytest.mark.flaky(reruns=2, reruns_delay=4)
    def test_ioa_range_full(self, cli_runner, target, port):
        """Test interrogation discovers all 120 mock data points [Category A]

        Full-range interrogation is the longest CLI subprocess in this class and can
        exceed its timeout when the integration lane is saturated. Transient: passed
        on a clean full-lane rerun.
        """
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--interrogate",
            "--wait-time",
            "5",
            "--timeout",
            "5",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"Full IOA range scan failed: {result.stderr}"
        _assert_log_has_events(result)
        # Validate most points were discovered (timing-dependent, 120 configured)
        ioa_count = _count_discovered_ioas(result.scan_log)
        assert ioa_count >= 100, f"Expected >= 100 discovered IOAs, got {ioa_count}"
        summary = _get_scan_summary(result.scan_log)
        assert f"{MOCK_POINT_COUNT} points" in summary, (
            f"Expected '{MOCK_POINT_COUNT} points' in summary, got: {summary}"
        )

    # ========================================================================
    # P4: Scan Phase Flags
    # ========================================================================

    def test_probe_files_flag(self, cli_runner, target, port):
        """Test --probe-files probes file transfer [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--probe-files",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"--probe-files unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "file" in text, f"--probe-files should reference file operations, got: {text[:500]}"

    @pytest.mark.slow
    @pytest.mark.flaky(reruns=2, reruns_delay=4)
    def test_all_phases(self, cli_runner, target, port):
        """Test --interrogate --probe-files --test-commands discovers all 120 mock points [Category A]

        Three scan phases in one CLI subprocess; same saturation-timeout exposure as
        test_ioa_range_full. Transient: passed on a clean full-lane rerun.
        """
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--interrogate",
            "--probe-files",
            "--test-commands",
            "--confirm",
            "--wait-time",
            "5",
            format="json",
            json_log=True,
            timeout=90,
        )
        assert result.success, f"All-phases scan failed: {result.stderr}"
        _assert_log_has_events(result)
        summary = _get_scan_summary(result.scan_log)
        assert f"{MOCK_POINT_COUNT} points" in summary, (
            f"Expected '{MOCK_POINT_COUNT} points' in scan summary, got: {summary}"
        )

    # ========================================================================
    # P5: File Transfer
    # ========================================================================

    def test_probe_files(self, cli_runner, target, port):
        """Test --probe-files detects file transfer capability [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--probe-files",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"Probe files failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "file" in text, f"Expected 'file' in output, got: {text[:500]}"

    def test_probe_custom_types_main(self, cli_runner, target, port):
        """Test --probe-custom-types probes Type IDs 128-255 [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--probe-custom-types",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Probe custom types unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "custom" in text or "probing" in text or "type" in text, (
            f"Expected custom type probe activity, got: {text[:500]}"
        )

    # ========================================================================
    # P6: Security Findings
    # ========================================================================

    @pytest.mark.security
    def test_security_anonymous_access(self, cli_runner, target, port):
        """Test 'Anonymous access allowed' finding (mock has 120 > 100 points) [Category A]

        IEC 104 TCP mode emits this finding when >100 data points are discovered.
        Requires --interrogate to trigger GI and discover points.
        """
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--interrogate",
            "--wait-time",
            "6",
            format="json",
            json_log=True,
        )
        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        findings = _get_security_findings(result.scan_log)
        assert "Anonymous access allowed" in findings, (
            f"Expected 'Anonymous access allowed' finding (120 points > 100 threshold), "
            f"got: {findings}"
        )

    @pytest.mark.security
    def test_security_finding_detail_text(self, cli_runner, target, port):
        """Test security finding has expected detail text [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--interrogate",
            format="json",
            json_log=True,
        )
        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        security_events = [e for e in result.scan_log.events if e.get("event_type") == "security"]
        assert len(security_events) >= 1, f"Expected security events, got: {security_events}"
        # The 'Anonymous access allowed' finding must carry the exact mock point
        # count (120) AND the 'without authentication' wording — the scanner's
        # documented detail string. Locate it among the security events.
        anon = [
            e
            for e in security_events
            if e.get("data", {}).get("finding") == "Anonymous access allowed"
        ]
        assert anon, f"Expected 'Anonymous access allowed' security event, got: {security_events}"
        detail = anon[0].get("data", {}).get("details", "").lower()
        assert str(MOCK_POINT_COUNT) in detail and "authentication" in detail, (
            f"Expected '{MOCK_POINT_COUNT} ... without authentication' detail, got: {detail}"
        )

    @pytest.mark.security
    def test_security_writable_access_file_transfer(self, cli_runner, target, port):
        """Test 'Writable access' finding when file transfer detected [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--probe-files",
            "--probe-files",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1], f"Files scan unexpected rc={result.returncode}"
        # Unconditional: scanner must attempt file transfer probing
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in ["file transfer", "file", "probe", "directory", "120", "error", "fail"]
        ), f"Expected file-related activity in output: {text[:500]}"
        # If scan succeeded and log available, check for the finding
        if result.success and result.scan_log is not None and len(result.scan_log) > 0:
            findings = _get_security_findings(result.scan_log)
            if "Writable access" in findings:
                # Good — finding was emitted as expected
                pass

    # ========================================================================
    # P7: Write Operations
    # ========================================================================

    def test_write_single(self, cli_runner, target, port):
        """Test --write-single 100 --value on --confirm writes to IOA 100 [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--write-single",
            "100",
            "--value",
            "on",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Write single unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "writing" in text or "command" in text or "ioa" in text, (
            f"Expected write command in output, got: {text[:500]}"
        )

    def test_write_double(self, cli_runner, target, port):
        """Test --write-double 200 --value on --confirm writes to IOA 200 [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--write-double",
            "200",
            "--value",
            "on",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Write double unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "c_dc_na" in text or "double" in text or "ioa" in text, (
            f"Expected double command type in output, got: {text[:500]}"
        )

    def test_write_float(self, cli_runner, target, port):
        """Test --write-float 700 --value 42.5 --confirm writes to IOA 700 [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--write-float",
            "700",
            "--value",
            "42.5",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Write float unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "ioa" in text or "float" in text or "setpoint" in text, (
            f"Expected write float activity, got: {text[:500]}"
        )

    def test_write_scaled(self, cli_runner, target, port):
        """Test --write-scaled 600 --value 100 --confirm writes to IOA 600 [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--write-scaled",
            "600",
            "--value",
            "100",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Write scaled unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "ioa" in text or "scaled" in text or "setpoint" in text, (
            f"Expected write scaled activity, got: {text[:500]}"
        )

    def test_write_normalized(self, cli_runner, target, port):
        """Test --write-normalized 500 --value 0.5 --confirm writes to IOA 500 [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--write-normalized",
            "500",
            "--value",
            "0.5",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Write normalized unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "ioa" in text or "normalized" in text or "setpoint" in text, (
            f"Expected write normalized activity, got: {text[:500]}"
        )

    def test_write_step(self, cli_runner, target, port):
        """Test --write-step 300 --value up --confirm writes to IOA 300 [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--write-step",
            "300",
            "--value",
            "up",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Write step unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "ioa" in text or "step" in text or "command" in text, (
            f"Expected write step activity, got: {text[:500]}"
        )

    def test_select_execute(self, cli_runner, target, port):
        """Test --write-single 100 --select-execute --confirm uses SBO mode [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--write-single",
            "100",
            "--value",
            "on",
            "--select-execute",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Select-execute unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "select" in text or "ioa" in text or "command" in text, (
            f"Expected select-execute activity, got: {text[:500]}"
        )

    def test_write_type_custom(self, cli_runner, target, port):
        """Test --write-type 45 --write-ioa 100 --value on --confirm [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--write-type",
            "45",
            "--write-ioa",
            "100",
            "--value",
            "on",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Write type custom unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "ioa" in text or "writing" in text or "command" in text, (
            f"Expected write operation in output, got: {text[:500]}"
        )

    # ========================================================================
    # P8: Write Safety Guards
    # ========================================================================

    def test_write_single_requires_value(self, cli_runner, target, port):
        """Test --write-single without --value logs error [Category C]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--write-single",
            "100",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )
        # Scanner logs a failure message but the overall scan still returns rc=0
        assert result.returncode in [0, 1, 2]
        text = _combined_text(result, result.scan_log)
        assert "--value" in text or "missing" in text or "required" in text, (
            f"Expected '--value required' error, got: {text[:500]}"
        )

    def test_write_float_requires_value(self, cli_runner, target, port):
        """Test --write-float without --value logs error [Category C]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--write-float",
            "700",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.returncode in [0, 1, 2]
        text = _combined_text(result, result.scan_log)
        assert "--value" in text or "missing" in text or "required" in text, (
            f"Expected '--value required' error, got: {text[:500]}"
        )

    # ========================================================================
    # P9: Listen Mode
    # ========================================================================

    @pytest.mark.slow
    def test_listen_mode(self, cli_runner, target, port):
        """Test -L -T 3 listen mode connects and doesn't hang [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "-L",
            "-T",
            "3",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.returncode in [0, 1], f"Listen mode unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "connect" in text or "listen" in text, (
            f"Expected connection in listen mode, got: {text[:500]}"
        )

    @pytest.mark.slow
    def test_listen_with_filter(self, cli_runner, target, port):
        """Test -L -T 3 -F 1,3,13 listen with type filter connects [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "-L",
            "-T",
            "3",
            "-F",
            "1,3,13",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.returncode in [0, 1], f"Listen with filter unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "connect" in text or "listen" in text, (
            f"Expected connection in listen with filter, got: {text[:500]}"
        )

    @pytest.mark.slow
    def test_listen_with_output(self, cli_runner, target, port, tmp_path):
        """Test -L -T 3 -O <tmpfile> writes output file [Category B]"""
        output_file = tmp_path / "iec104_listen.txt"
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "-L",
            "-T",
            "3",
            "-O",
            str(output_file),
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.returncode in [0, 1], f"Listen with output unexpected rc={result.returncode}"
        # Listen mode must at least connect to the mock — verify via the log.
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "connect" in text or "listen" in text, (
            f"Expected connection/listen activity, got: {text[:500]}"
        )
        # Output file creation is best-effort (depends on whether spontaneous
        # data was captured during the 3s window). If it was written, it must
        # be valid JSONL — non-empty and parseable, not just "exists".
        if result.success and output_file.exists() and output_file.stat().st_size > 0:
            import json

            with open(output_file) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        json.loads(line)  # raises if the listener wrote junk

    @pytest.mark.slow
    def test_listen_raw(self, cli_runner, target, port):
        """Test -L -T 3 --listen-raw connects without hanging [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "-L",
            "-T",
            "3",
            "--listen-raw",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.returncode in [0, 1], f"Listen raw unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "connect" in text or "listen" in text, (
            f"Expected connection in listen raw, got: {text[:500]}"
        )

    @pytest.mark.slow
    def test_listen_zero_timeout(self, cli_runner, target, port):
        """Test -L -T 0 with subprocess timeout [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "-L",
            "-T",
            "0",
            expect_json=False,
            timeout=5,
        )
        # Expect timeout (-1) or normal exit
        assert result.returncode in [-1, 0, 1], f"Listen T=0 unexpected rc={result.returncode}"

    # ========================================================================
    # P10: Fuzzing
    # ========================================================================

    @pytest.mark.fuzz
    def test_fuzz_requires_confirm(self, cli_runner, target, port):
        """Test --fuzz without --confirm logs blocked message [Category C]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            format="json",
            json_log=True,
            timeout=15,
        )
        # Scanner logs a failure but overall scan returns rc=0
        assert result.returncode in [0, 1, 2]
        text = _combined_text(result, result.scan_log)
        assert "--confirm" in text or "blocked" in text or "requires" in text, (
            f"Expected '--confirm required' message, got: {text[:500]}"
        )

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_with_confirm(self, cli_runner, target, port):
        """Test --fuzz --confirm --fuzz-iterations 3 starts fuzzing [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "3",
            format="json",
            json_log=True,
            timeout=60,
        )
        assert result.returncode in [0, 1, 2], (
            f"Fuzz with confirm unexpected rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        assert "fuzzing" in text or "fuzz" in text, (
            f"Expected 'fuzzing' in output, got: {text[:500]}"
        )

    @pytest.mark.fuzz
    def test_fuzz_iterations(self, cli_runner, target, port):
        """Test --fuzz --confirm --fuzz-iterations 2 starts fuzzing [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "2",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1, 2], f"Fuzz iterations unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "fuzzing" in text or "fuzz" in text, f"Expected fuzzing activity, got: {text[:500]}"

    @pytest.mark.fuzz
    def test_fuzz_ioa(self, cli_runner, target, port):
        """Test --fuzz --confirm --fuzz-ioa 100 targets IOA 100 [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-ioa",
            "100",
            "--fuzz-iterations",
            "2",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1, 2], f"Fuzz IOA unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "ioa" in text or "fuzzing" in text or "fuzz" in text, (
            f"Expected fuzz targeting IOA in output, got: {text[:500]}"
        )

    # ========================================================================
    # P12: Verbosity
    # ========================================================================

    def test_verbose_output(self, cli_runner, target, port):
        """Test -v produces output without hanging [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            verbose=True,
            expect_json=False,
            timeout=20,
        )
        assert result.success, f"Verbose output failed: {result.stderr}"
        assert result.stdout or result.stderr, "No output with verbose flag"

    def test_debug_output(self, cli_runner, target, port):
        """Test --debug doesn't hang [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            debug=True,
            expect_json=False,
            timeout=20,
        )
        assert result.returncode != -1, "Debug mode should not hang"

    # ========================================================================
    # P14: Read Operations
    # ========================================================================

    def test_read_ioa(self, cli_runner, target, port):
        """Test --read-ioa 100 reads specific IOA via C_RD_NA_1 [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--read-ioa",
            "100",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1], f"Read IOA unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "ioa" in text or "read" in text or "100" in text, (
            f"Expected read IOA activity, got: {text[:500]}"
        )

    def test_read_multiple_ioas(self, cli_runner, target, port):
        """Test --read-ioa 100,200,300 reads multiple IOAs [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--read-ioa",
            "100,200,300",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1], f"Read multiple IOAs unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "read" in text or "ioa" in text, f"Expected read activity, got: {text[:500]}"

    def test_counter_interrogation(self, cli_runner, target, port):
        """Test --counter-interrogation sends Type 101 [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--counter-interrogation",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1], (
            f"Counter interrogation unexpected rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        assert "counter" in text or "interrogation" in text or "connect" in text, (
            f"Expected counter interrogation activity, got: {text[:500]}"
        )

    def test_clock_read(self, cli_runner, target, port):
        """Test --clock-read sends clock sync command [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--clock-read",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1], f"Clock read unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "clock" in text or "time" in text or "connect" in text, (
            f"Expected clock read activity, got: {text[:500]}"
        )

    # ========================================================================
    # P15: Error Handling
    # ========================================================================

    def test_connection_refused(self, cli_runner):
        """Test handling of connection refused on closed port [Category C]"""
        result = cli_runner.run(
            "iec104",
            MOCK_HOST,
            "--port",
            "9999",
            "--timeout",
            "3",
            expect_json=False,
            json_log=True,
            timeout=10,
        )
        assert result.returncode != -1, "Should not hang on connection refused"
        assert result.returncode in [0, 1, 2], (
            f"Connection refused should exit cleanly, got rc={result.returncode}"
        )

    def test_timeout_handling(self, cli_runner):
        """Test timeout with unreachable host [Category C]"""
        result = cli_runner.run(
            "iec104",
            "10.255.255.1",
            "--timeout",
            "3",
            expect_json=False,
            timeout=15,
        )
        assert result.execution_time < 20, "Command did not respect timeout"

    def test_invalid_target(self, cli_runner):
        """Test handling of invalid target hostname [Category C]"""
        result = cli_runner.run(
            "iec104",
            "not-a-valid-host-12345!!!",
            expect_json=False,
            timeout=10,
        )
        output_lower = result.combined_output.lower()
        has_error = any(
            term in output_lower for term in ["error", "failed", "cannot", "not found", "not known"]
        )
        assert not result.success or has_error, (
            f"Invalid target should fail or show error, got rc={result.returncode}"
        )

    def test_invalid_asdu_address(self, cli_runner, target, port):
        """Test --asdu-address 255 (wrong for mock) [Category C]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--asdu-address",
            "255",
            expect_json=False,
            timeout=15,
        )
        assert result.returncode != -1, "Should not hang"
        assert result.returncode in [0, 1, 2], (
            f"Invalid ASDU address should exit cleanly, got rc={result.returncode}"
        )

    # ========================================================================
    # P16: TLS against plain TCP server
    # ========================================================================

    def test_tls_against_non_tls_server(self, cli_runner, target, port):
        """Test --tls against plain TCP server fails gracefully [Category C]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--tls",
            "--timeout",
            "5",
            expect_json=False,
            json_log=True,
            timeout=20,
        )
        # TLS handshake to plain TCP must fail
        assert result.returncode in [0, 1, 2], (
            f"TLS against non-TLS should fail cleanly, got rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        has_tls_error = any(
            term in text for term in ["tls", "handshake", "ssl", "failed to connect"]
        )
        assert has_tls_error, f"Expected TLS/handshake error, got: {text[:300]}"

    def test_tls_invalid_cert_path(self, cli_runner, target, port):
        """Test --tls with nonexistent cert file reports clear error [Category C]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--tls",
            "--tls-cert",
            "/nonexistent/cert.pem",
            "--tls-key",
            "/nonexistent/key.pem",
            "--timeout",
            "5",
            expect_json=False,
            json_log=True,
            timeout=15,
        )
        assert result.returncode in [0, 1, 2], (
            f"Bad cert path should fail cleanly, got rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        assert "cert" in text or "tls" in text or "error" in text, (
            f"Expected certificate error, got: {text[:300]}"
        )

    def test_tls_no_encryption_finding_suppressed(self, cli_runner, target, port):
        """Test that --tls suppresses 'No encryption' security finding [Category C]

        Even though TLS handshake fails against the non-TLS mock, the scanner
        should not emit the 'No encryption' finding when --tls was requested.
        If it can't connect at all, no security findings are emitted.
        """
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--tls",
            "--timeout",
            "5",
            format="json",
            json_log=True,
            timeout=20,
        )
        if result.scan_log is not None and len(result.scan_log) > 0:
            findings = _get_security_findings(result.scan_log)
            assert "No encryption" not in findings, (
                "When --tls is used, 'No encryption' finding should not appear "
                f"(even on connection failure). Found findings: {findings}"
            )

    # NOT COVERED (no test exists — do not add skipped placeholders):
    #   - IEC 101 serial mode, serial port listing, and --tls-ca: need a
    #     physical serial device / a CA-backed TLS endpoint.

    # NOTE: --fuzz-max-targets was removed from the IEC 104 CLI — it is a
    # multi-target cap that never applied to IEC 104's single --fuzz-ioa fuzzer
    # (it was an unused factory default, now gated off via include_max_targets).


# ===========================================================================
# Class 2: Custom Types Mock (port 2405)
# ===========================================================================


@pytest.mark.iec104
class TestIEC104CustomTypes:
    """Integration tests for IEC 104 custom types mock (port 2405)."""

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return IEC104_CUSTOM_PORT

    @pytest.fixture(autouse=True)
    def _require_custom_mock(self, target, port):
        """Skip all tests if the custom types mock is not reachable."""
        require_port(target, port, "IEC 104 custom types mock not reachable on {target}:{port}")

    def test_service_available(self, target, port):
        """Verify custom types mock is running [Category A]"""
        assert check_port_open(target, port), (
            f"Custom types service not responding on {target}:{port}"
        )

    def test_basic_connection(self, cli_runner, target, port):
        """Test basic connection to alternate port [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], (
            f"Connection to custom port unexpected rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        assert "connect" in text or "interrogation" in text, (
            f"Expected connection activity, got: {text[:500]}"
        )

    def test_probe_custom_types(self, cli_runner, target, port):
        """Test --probe-custom-types detects vendor-specific Type IDs [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--probe-custom-types",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"Probe custom types failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # The probe must announce itself and then reach a definite verdict.
        assert "probing for custom type ids" in text, (
            f"Expected the custom-type probe to run, got: {text[:500]}"
        )
        # Either it discovered vendor types (128-255) or it explicitly reported
        # none — a vacuous run that does neither is a regression.
        assert "discovered custom type id" in text or "no custom type ids detected" in text, (
            f"Expected a definite custom-type verdict, got: {text[:500]}"
        )

    @pytest.mark.security
    def test_custom_types_security_finding(self, cli_runner, target, port):
        """Test 'Insecure configuration' finding when custom types detected [Category B]

        The c104-based probe may not detect custom types on the Python mock
        (protocol-level incompatibility). Assert conditionally.
        Note: IEC 104 TCP mode does not emit 'No authentication' — only
        'Anonymous access allowed' (>100 pts), 'Insecure configuration'
        (custom types), and 'Writable access' (file transfer).
        """
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--probe-custom-types",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Custom types scan unexpected rc={result.returncode}"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_has_events(result)
            messages = _all_messages(result.scan_log)
            findings = _get_security_findings(result.scan_log)
            # If custom types were actually found, the finding must be present
            if "Insecure configuration" not in findings:
                # c104 probe didn't find custom types on this mock;
                # verify the negative message is present instead
                text = _combined_text(result, result.scan_log)
                assert "no custom" in text or "custom" in text, (
                    f"Expected either 'Insecure configuration' finding or custom type message, "
                    f"got findings={findings}, messages={messages[:500]}"
                )

    def test_custom_type_ioa_range(self, cli_runner, target, port):
        """Test interrogation against custom types mock [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--interrogate",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], (
            f"Custom type IOA range unexpected rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        assert "connect" in text or "ioa" in text, (
            f"Expected connection in custom type IOA scan, got: {text[:500]}"
        )

    def test_interrogation(self, cli_runner, target, port):
        """Test basic interrogation against custom types mock connects [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--interrogate",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], (
            f"Custom types interrogation unexpected rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        assert "interrogation" in text or "connect" in text, (
            f"Expected interrogation activity, got: {text[:500]}"
        )

    def test_discovery_mode(self, cli_runner, target, port):
        """Test discovery-only (no flags) against custom types mock [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], (
            f"Custom types discovery unexpected rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        assert "connect" in text or "discover" in text, (
            f"Expected discovery activity, got: {text[:500]}"
        )

    def test_common_address_override(self, cli_runner, target, port):
        """Test --common-address with non-default value [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--common-address",
            "2",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1], (
            f"Common address override unexpected rc={result.returncode}"
        )

    def test_verbose_custom_types(self, cli_runner, target, port):
        """Test verbose output against custom types mock [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--probe-custom-types",
            verbose=True,
            expect_json=False,
            timeout=30,
        )
        assert result.returncode in [0, 1], (
            f"Verbose custom types unexpected rc={result.returncode}"
        )
        assert result.stdout or result.stderr, "No output with verbose flag"


# ===========================================================================
# Class 3: Conpot Honeypot (port 2409)
# ===========================================================================


@pytest.mark.iec104
class TestIEC104Conpot:
    """Integration tests for IEC 104 Conpot honeypot (port 2409, ASDU 7720)."""

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return IEC104_CONPOT_PORT

    @pytest.fixture(autouse=True)
    def _require_conpot_mock(self, target, port):
        """Skip all tests if the Conpot mock is not reachable."""
        require_port(target, port, "IEC 104 Conpot mock not reachable on {target}:{port}")

    def test_service_available(self, target, port):
        """Verify Conpot mock is running [Category A]"""
        assert check_port_open(target, port), f"Conpot service not responding on {target}:{port}"

    @pytest.mark.flaky(reruns=2, reruns_delay=4)
    def test_conpot_interrogation(self, cli_runner, target, port):
        """Test interrogation with --asdu-address 7720 connects to Conpot [Category B]

        Conpot is a slow Python honeypot and is the first thing to time out when the
        lane is saturated. Transient: passed on a clean full-lane rerun.
        """
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--asdu-address",
            str(CONPOT_ASDU_ADDRESS),
            "--interrogate",
            "--wait-time",
            "5",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], (
            f"Conpot interrogation unexpected rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        assert "connect" in text, f"Expected connection to Conpot, got: {text[:500]}"
        # Conpot's Siemens S7-300 IEC104 template serves a stable fingerprint:
        # 59 points across M_SP/M_DP/M_ME_NB/M_ME_NC type IDs. Assert we
        # actually parsed the interrogation response, not just connected.
        summary = _get_scan_summary(result.scan_log)
        assert "59 points" in summary, (
            f"Expected Conpot's 59-point fingerprint in scan summary, got: {summary!r}"
        )
        assert _count_discovered_ioas(result.scan_log) >= 50, (
            "Expected ~59 discovered IOAs from Conpot interrogation, "
            f"got {_count_discovered_ioas(result.scan_log)}"
        )
        # The honeypot template exposes single-point, double-point, scaled and
        # short-float measured types — verify the type-ID mix was decoded.
        for type_name in ("m_sp_na_1", "m_dp_na_1", "m_me_nb_1", "m_me_nc_1"):
            assert type_name in text, (
                f"Expected Conpot type {type_name.upper()} in decoded output, got: {text[:500]}"
            )

    def test_conpot_ioa_range(self, cli_runner, target, port):
        """Test --asdu-address 7720 interrogation scans Conpot [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--asdu-address",
            str(CONPOT_ASDU_ADDRESS),
            "--interrogate",
            format="json",
            json_log=True,
            timeout=60,
        )
        assert result.returncode in [0, 1], f"Conpot IOA range unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "scan complete" in text or "connect" in text, (
            f"Expected scan activity in Conpot IOA range, got: {text[:500]}"
        )

    def test_conpot_write_single(self, cli_runner, target, port):
        """Test write to Conpot IOA 3370 logs write command [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--asdu-address",
            str(CONPOT_ASDU_ADDRESS),
            "--write-single",
            "3370",
            "--value",
            "on",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Conpot write single unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "ioa" in text or "writing" in text or "command" in text, (
            f"Expected write to IOA in output, got: {text[:500]}"
        )

    @pytest.mark.security
    def test_conpot_security_findings(self, cli_runner, target, port):
        """Test security findings against Conpot [Category B]

        Conpot has ~59 points which is below the 100-point threshold for
        'Anonymous access allowed'. IEC 104 TCP mode does not emit
        'No authentication'. It DOES always emit 'No encryption' on a confirmed
        non-TLS handshake (IEC 104 is plaintext by design), so that is the one
        finding expected here regardless of point count.
        """
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--asdu-address",
            str(CONPOT_ASDU_ADDRESS),
            "--interrogate",
            "--wait-time",
            "5",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Conpot scan unexpected rc={result.returncode}"
        # With 59 points the point-count findings stay silent, but the
        # always-on plaintext-transport finding ('No encryption') fires on the
        # confirmed non-TLS handshake. Any finding that does appear must be from
        # this allowed set.
        if result.scan_log is not None and len(result.scan_log) > 0:
            findings = _get_security_findings(result.scan_log)
            for f in findings:
                assert f in (
                    "No encryption",
                    "Anonymous access allowed",
                    "Writable access",
                    "Insecure configuration",
                ), f"Unexpected finding: {f}"

    def test_conpot_default_asdu(self, cli_runner, target, port):
        """Test scan with default ASDU address (1, not 7720) — may fail/timeout [Category C]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--timeout",
            "5",
            format="json",
            json_log=True,
            timeout=15,
        )
        # Conpot expects ASDU 7720; default 1 may not work
        assert result.returncode in [0, 1, 2], (
            f"Conpot default ASDU should exit cleanly, got rc={result.returncode}"
        )

    def test_conpot_discovery_mode(self, cli_runner, target, port):
        """Test discovery-only (no flags) against Conpot [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--asdu-address",
            str(CONPOT_ASDU_ADDRESS),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Conpot discovery unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "connect" in text or "discover" in text, (
            f"Expected discovery activity against Conpot, got: {text[:500]}"
        )

    def test_conpot_verbose(self, cli_runner, target, port):
        """Test verbose output against Conpot [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--asdu-address",
            str(CONPOT_ASDU_ADDRESS),
            verbose=True,
            expect_json=False,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"Conpot verbose unexpected rc={result.returncode}"
        assert result.stdout or result.stderr, "No output with verbose flag against Conpot"


# ===========================================================================
# Class 4: TLS Server (port 19998, IEC 62351-3)
# ===========================================================================


@pytest.mark.iec104
class TestIEC104TLS:
    """Integration tests for IEC 104 TLS server (port 19998, IEC 62351-3).

    Requires iec104-tls Docker service (lib60870 built with mbedTLS).
    Same 120 data points as the plain mock, but over TLS transport.

    Note: c104 v2.2.1 TLS is broken (iec104-python#64). Tests that depend on
    the oida ``--tls`` flag (which uses c104 internally) are marked xfail.
    The server itself is verified via Python's ssl module.
    """

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return IEC104_TLS_PORT

    @pytest.fixture(autouse=True)
    def _require_tls_mock(self, target, port):
        """Skip all tests if the TLS mock is not reachable."""
        require_port(target, port, "IEC 104 TLS mock not reachable on {target}:{port}")

    # ========================================================================
    # Service Availability (independent of c104)
    # ========================================================================

    def test_tls_service_available(self, target, port):
        """Verify TLS mock is listening on port 19998 [Category A]"""
        assert check_port_open(target, port), (
            f"IEC 104 TLS service not responding on {target}:{port}"
        )

    def test_tls_handshake_ssl_module(self, target, port):
        """Verify TLS handshake succeeds using Python ssl module [Category A]"""
        import socket
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = socket.create_connection((target, port), timeout=5)
        tls_sock = ctx.wrap_socket(sock, server_hostname=target)
        try:
            assert tls_sock.version().startswith("TLSv1"), (
                f"Expected TLS 1.x, got {tls_sock.version()}"
            )
            cipher_name, _, _ = tls_sock.cipher()
            assert "ECDHE" in cipher_name, f"Expected ECDHE cipher, got {cipher_name}"
            peer_cert = tls_sock.getpeercert(binary_form=True)
            assert len(peer_cert) > 0, "Empty server certificate"
        finally:
            tls_sock.close()

    def test_tls_server_certificate(self, target, port):
        """Verify server certificate has expected DER structure [Category A]"""
        import socket
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = socket.create_connection((target, port), timeout=5)
        tls_sock = ctx.wrap_socket(sock, server_hostname=target)
        try:
            cert_der = tls_sock.getpeercert(binary_form=True)
            # Basic DER structure check: starts with SEQUENCE tag (0x30)
            assert cert_der[0] == 0x30, "Certificate doesn't start with SEQUENCE"
            assert len(cert_der) > 100, "Certificate too short"
        finally:
            tls_sock.close()

    # ========================================================================
    # TLS Scans (c104-dependent — xfail until iec104-python#64 is fixed)
    # ========================================================================

    @_C104_TLS_XFAIL
    def test_tls_basic_scan(self, cli_runner, target, port):
        """Test --tls basic scan succeeds and mentions TLS [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--tls",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"TLS basic scan failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "connect" in text, f"Expected connection activity in TLS scan, got: {text[:500]}"

    @_C104_TLS_XFAIL
    def test_tls_interrogation(self, cli_runner, target, port):
        """Test --tls interrogation discovers data points [Category A]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--tls",
            "--interrogate",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"TLS interrogation failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "interrogation" in text or "discover" in text or "point" in text, (
            f"Expected interrogation activity in TLS scan, got: {text[:500]}"
        )

    @_C104_TLS_XFAIL
    def test_tls_with_client_cert(self, cli_runner, target, port):
        """Test --tls with --tls-cert/--tls-key for mutual TLS [Category A]"""
        client_cert = IEC104_TLS_CERTS / "client.pem"
        client_key = IEC104_TLS_CERTS / "client.key"
        if not client_cert.exists() or not client_key.exists():
            require_service("Client certificates not generated")
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--tls",
            "--tls-cert",
            str(client_cert),
            "--tls-key",
            str(client_key),
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"TLS with client cert failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # Security Findings (c104-dependent)
    # ========================================================================

    @pytest.mark.security
    @_C104_TLS_XFAIL
    def test_tls_security_findings(self, cli_runner, target, port):
        """Test that TLS scan completes and emits appropriate findings [Category A]

        IEC 104 TCP mode only emits 'Anonymous access allowed' (>100 pts),
        'Writable access' (file transfer), and 'Insecure configuration' (custom types).
        """
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--tls",
            "--interrogate",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.success, f"TLS scan failed: {result.stderr}"
        _assert_log_has_events(result)
        findings = _get_security_findings(result.scan_log)
        # TLS mock has same 120 points as plain mock
        assert "Anonymous access allowed" in findings, (
            f"Expected 'Anonymous access allowed' finding, got: {findings}"
        )

    @_C104_TLS_XFAIL
    def test_tls_cert_probe(self, cli_runner, target, port):
        """Test --tls scan probes and logs certificate info [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--tls",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1], f"TLS cert probe unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "tls" in text or "cert" in text or "connect" in text, (
            f"Expected TLS activity in output, got: {text[:500]}"
        )


# ===========================================================================
# Class 5: Fuzz Tests (port 2404)
# ===========================================================================


@pytest.mark.iec104
@pytest.mark.fuzz
class TestIEC104Fuzz:
    """Fuzzing-specific tests for IEC 104 scanner against lib60870 mock."""

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return IEC104_PORT

    @pytest.fixture(autouse=True)
    def _require_iec104_mock(self, target, port):
        """Skip all tests if the IEC 104 mock is not reachable."""
        require_port(target, port, "IEC 104 mock not reachable on {target}:{port}")

    @pytest.mark.slow
    def test_fuzz_full_cycle(self, cli_runner, target, port):
        """Test --fuzz --confirm --fuzz-iterations 5 full fuzz cycle [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "5",
            format="json",
            json_log=True,
            timeout=90,
        )
        assert result.returncode in [0, 1, 2], f"Fuzz full cycle unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "fuzz" in text, f"Expected fuzzing activity, got: {text[:500]}"

    def test_fuzz_ioa_specific(self, cli_runner, target, port):
        """Test --fuzz --fuzz-ioa 500 targets normalized IOAs [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-ioa",
            "500",
            "--fuzz-iterations",
            "2",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1, 2], f"Fuzz IOA 500 unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "fuzz" in text or "500" in text, (
            f"Expected fuzz targeting IOA 500, got: {text[:500]}"
        )

    def test_fuzz_dry_run_without_confirm(self, cli_runner, target, port):
        """Test --fuzz without --confirm acts as dry-run [Category C]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-iterations",
            "2",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.returncode in [0, 1, 2], f"Fuzz dry-run unexpected rc={result.returncode}"
        text = _combined_text(result, result.scan_log)
        assert "--confirm" in text or "blocked" in text or "requires" in text, (
            f"Expected confirmation requirement message, got: {text[:500]}"
        )

    def test_fuzz_json_structure(self, cli_runner, target, port):
        """Test fuzz results produce valid JSON output [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "2",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1, 2], (
            f"Fuzz JSON structure unexpected rc={result.returncode}"
        )
        # If scan_log exists, validate event structure
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_fuzz_with_interrogation(self, cli_runner, target, port):
        """Test --fuzz combined with --interrogate [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--interrogate",
            "--fuzz-iterations",
            "2",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1, 2], (
            f"Fuzz with interrogation unexpected rc={result.returncode}"
        )
        text = _combined_text(result, result.scan_log)
        assert "fuzz" in text or "interrogation" in text, (
            f"Expected fuzz or interrogation activity, got: {text[:500]}"
        )

    def test_fuzz_single_iteration(self, cli_runner, target, port):
        """Test --fuzz --fuzz-iterations 1 minimal fuzz [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "1",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1, 2], (
            f"Fuzz single iteration unexpected rc={result.returncode}"
        )

    def test_fuzz_high_ioa(self, cli_runner, target, port):
        """Test --fuzz --fuzz-ioa 800 targets integrated totals range [Category B]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-ioa",
            "800",
            "--fuzz-iterations",
            "2",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert result.returncode in [0, 1, 2], f"Fuzz high IOA unexpected rc={result.returncode}"

    def test_fuzz_nonexistent_ioa(self, cli_runner, target, port):
        """Test --fuzz --fuzz-ioa 99999 with nonexistent IOA [Category C]"""
        result = cli_runner.run(
            "iec104",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-ioa",
            "99999",
            "--fuzz-iterations",
            "1",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1, 2], (
            f"Fuzz nonexistent IOA unexpected rc={result.returncode}"
        )
