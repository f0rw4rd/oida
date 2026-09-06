"""
Modbus SunSpec Security Assessment Integration Tests

Tests oida modbus --sunspec-assess against the Docker SunSpec mock server
(modbus-sunspec container on port 5502). Validates that the security
assessment correctly identifies:
  - Missing SunSpec security models (3-9)
  - Writable critical control registers (Conn, SetOp, StorCtl_Mod)
  - Active production state (MPPT + AC power > 0)
  - Battery remote control mode (loc_rem_ctl == 0)
  - Device rated capacity

Mock Server Data (from docker/mocks/services/sunspec_server.py):
  Model chain: 1 (Common) -> 103 (Inverter 3ph) -> 120 (Nameplate) ->
               123 (Controls) -> 124 (Storage) -> 160 (MPPT) ->
               802 (Battery) -> 0xFFFF sentinel

  Model 1 (Common):
    Manufacturer = "OIDA Test Devices"
    Model = "SunSpec-Mock-10kW"
    Serial = "OIDA-SS-2025-001"

  Model 103 (Inverter 3ph):
    operating_state = 4 (MPPT)
    ac_power = 9850W (W_SF=0)

  Model 120 (Nameplate):
    WRtg = 10000W (WRtg_SF=0) --> 10.0 kW

  Model 123 (Controls):
    conn = 1 (CONNECT, writable)
    w_max_lim_pct = 1000 (100.0%, SF=-1, writable)
    w_max_lim_ena = 0 (DISABLED, writable)
    out_pf_set = 1000 (1.000, SF=-3, writable)

  Model 124 (Storage):
    stor_ctl_mod = 0 (writable)
    wcha_max = 5000W (writable)

  Model 802 (Battery):
    loc_rem_ctl = 0 (REMOTE)
    set_op = 1 (CONNECT, writable)
    set_inv_state = 3 (INVERTER_STARTED, writable)
    soc = 75.0%, soh = 98.0%
    typ = 4 (LITHIUM_ION)

  Security models (3-9): NONE PRESENT --> triggers finding

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  16 tests
Category B (conditional -- mock may not support, accept 0 or 1):        3 tests
Category C (error handling -- assert failure + validate error events):   3 tests
Skipped (untestable):                                                    0 tests
Total:                                                                  22 tests
---------------------------------------------------------------------------
"""

import pytest
from typing import Optional

from .base_protocol_test import BaseProtocolIntegrationTest
from .conftest import MOCK_HOST, MOCK_PORTS, ensure_mock

# ---------------------------------------------------------------------------
# Known Mock Data Constants
# ---------------------------------------------------------------------------
SUNSPEC_PORT = MOCK_PORTS["modbus_sunspec"]  # 5502

# Model 1 (Common)
MOCK_MANUFACTURER = "oida test devices"
MOCK_MODEL = "sunspec-mock-10kw"
MOCK_SERIAL = "oida-ss-2025-001"

# Model 103 (Inverter)
MOCK_OPERATING_STATE = 4  # MPPT
MOCK_AC_POWER = 9850  # W

# Model 120 (Nameplate)
MOCK_WRTG = 10000  # W

# Model chain
MOCK_MODEL_IDS = [1, 103, 120, 123, 124, 160, 802]
MOCK_MODEL_COUNT = len(MOCK_MODEL_IDS)

# Expected security finding titles (lowercase for matching)
FINDING_NO_SECURITY_MODELS = "no sunspec security models (3-9) present"
FINDING_WRITABLE_CONTROLS = "writable control register(s) exposed"
FINDING_CONN_WRITABLE = "inverter connect/disconnect register (conn) is writable"
FINDING_SETOP_WRITABLE = "battery connect/disconnect register (setop) is writable"
FINDING_STORCTL_WRITABLE = "battery storage control mode (storctl_mod) is writable"
FINDING_ACTIVE_PRODUCTION = "inverter actively producing with writable controls exposed"
FINDING_REMOTE_CONTROL = "battery in remote control mode"


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


def _get_security_finding_titles(log) -> list:
    """Extract all security finding titles from the log as lowercase strings."""
    findings = log.get_security_findings()
    titles = []
    for f in findings:
        # The finding title is in data.finding
        title = f.get("data", {}).get("finding", "")
        if title:
            titles.append(title.lower())
        # Also capture the message field
        msg = f.get("message", "")
        if msg:
            titles.append(msg.lower())
    return titles


def _get_security_findings_by_category(log, category: str) -> list:
    """Get security findings filtered by category."""
    findings = log.get_security_findings()
    return [
        f for f in findings if f.get("data", {}).get("category", "").upper() == category.upper()
    ]


# ---------------------------------------------------------------------------
# Test Class
# ---------------------------------------------------------------------------


@pytest.mark.containers("modbus-sunspec")
class TestModbusSunSpecSecurityAssessment(BaseProtocolIntegrationTest):
    """Integration tests for the SunSpec security assessment feature (--sunspec-assess)."""

    @property
    def protocol_name(self) -> str:
        return "modbus"

    @property
    def default_port(self) -> int:
        return SUNSPEC_PORT

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    @pytest.fixture(autouse=True, scope="class")
    def _start_mock(self):
        """Check SunSpec mock (port 5502) instead of standard Modbus (port 502)."""
        ensure_mock("modbus_sunspec")

    @pytest.fixture
    def port(self):
        """Override port to use SunSpec mock port for inherited base tests."""
        return SUNSPEC_PORT

    # ========================================================================
    # SunSpec Discovery Tests
    # ========================================================================

    def test_sunspec_marker_found(self, cli_runner, target, docker_services):
        """Test that SunSpec marker is found at base address 40000 [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"SunSpec discovery failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        messages = _all_messages(log)
        assert "marker found" in messages, f"Expected 'marker found' in log, got: {messages[:500]}"
        assert "40000" in messages, f"Expected base address 40000 in log, got: {messages[:500]}"

    def test_sunspec_model_chain_walked(self, cli_runner, target, docker_services):
        """Test that all models in the chain are discovered [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"SunSpec discovery failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        messages = _all_messages(log)
        # The model walk should report the count
        assert f"{MOCK_MODEL_COUNT} model" in messages, (
            f"Expected '{MOCK_MODEL_COUNT} model' in log, got: {messages[:500]}"
        )

        # Check that key model IDs appear in the output
        text = _combined_text(result, log)
        for model_id in [1, 103, 120, 123, 124, 802]:
            model_name_fragments = {
                1: "common",
                103: "three phase inverter",
                120: "nameplate",
                123: "immediate controls",
                124: "basic storage",
                802: "battery",
            }
            expected_fragment = model_name_fragments.get(model_id, str(model_id))
            assert expected_fragment in text, (
                f"Expected '{expected_fragment}' (model {model_id}) in output, got: {text[:800]}"
            )

    def test_sunspec_common_model_data(self, cli_runner, target, docker_services):
        """Test that Common model (1) fields are decoded correctly [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"SunSpec discovery failed: {result.stderr}"
        _assert_log_has_events(result)

        text = _combined_text(result, result.scan_log)
        assert MOCK_MANUFACTURER in text, (
            f"Expected manufacturer '{MOCK_MANUFACTURER}' in output, got: {text[:500]}"
        )
        assert MOCK_MODEL in text, f"Expected model '{MOCK_MODEL}' in output, got: {text[:500]}"

    def test_sunspec_assess_implies_sunspec(self, cli_runner, target, docker_services):
        """Test that --sunspec-assess implies --sunspec (no separate -S needed) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"--sunspec-assess failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # Should discover models (implies --sunspec)
        messages = _all_messages(log)
        assert "marker found" in messages, (
            "--sunspec-assess should imply --sunspec but no marker discovery occurred"
        )
        # Should also produce security findings
        security_events = log.get_security_findings()
        assert len(security_events) > 0, "--sunspec-assess should produce security findings, got 0"

    # ========================================================================
    # Security Assessment: Missing Security Models
    # ========================================================================

    def test_no_security_models_finding(self, cli_runner, target, docker_services):
        """Test detection of missing SunSpec security models (3-9) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        finding_titles = _get_security_finding_titles(log)
        assert any(FINDING_NO_SECURITY_MODELS in t for t in finding_titles), (
            f"Expected finding about missing security models. Got findings: {finding_titles}"
        )

        # Verify the finding category is AUTHENTICATION
        auth_findings = _get_security_findings_by_category(log, "AUTHENTICATION")
        assert len(auth_findings) > 0, (
            "Expected AUTHENTICATION category finding for missing security models"
        )

    # ========================================================================
    # Security Assessment: Writable Critical Controls
    # ========================================================================

    def test_writable_controls_finding(self, cli_runner, target, docker_services):
        """Test detection of writable critical control registers [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        finding_titles = _get_security_finding_titles(log)
        assert any(FINDING_WRITABLE_CONTROLS in t for t in finding_titles), (
            f"Expected finding about writable controls. Got findings: {finding_titles}"
        )

        # Verify category is ACCESS_CONTROL
        ac_findings = _get_security_findings_by_category(log, "ACCESS_CONTROL")
        assert len(ac_findings) > 0, (
            "Expected ACCESS_CONTROL category finding for writable controls"
        )

    def test_conn_register_finding(self, cli_runner, target, docker_services):
        """Test detection of writable Conn register (Model 123) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        finding_titles = _get_security_finding_titles(log)
        assert any(FINDING_CONN_WRITABLE in t for t in finding_titles), (
            f"Expected Conn writable finding. Got findings: {finding_titles}"
        )

    def test_setop_register_finding(self, cli_runner, target, docker_services):
        """Test detection of writable SetOp register (Model 802) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        finding_titles = _get_security_finding_titles(log)
        assert any(FINDING_SETOP_WRITABLE in t for t in finding_titles), (
            f"Expected SetOp writable finding. Got findings: {finding_titles}"
        )

    def test_storctl_mod_register_finding(self, cli_runner, target, docker_services):
        """Test detection of writable StorCtl_Mod register (Model 124) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        finding_titles = _get_security_finding_titles(log)
        assert any(FINDING_STORCTL_WRITABLE in t for t in finding_titles), (
            f"Expected StorCtl_Mod writable finding. Got findings: {finding_titles}"
        )

    # ========================================================================
    # Security Assessment: Active Production State
    # ========================================================================

    def test_active_production_finding(self, cli_runner, target, docker_services):
        """Test detection of inverter actively producing with exposed controls [Category A]

        Mock has Model 103 operating_state=4 (MPPT) and ac_power=9850W.
        Combined with writable controls, this should trigger OPERATIONAL_RISK finding.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        finding_titles = _get_security_finding_titles(log)
        assert any(FINDING_ACTIVE_PRODUCTION in t for t in finding_titles), (
            f"Expected active production finding. Got findings: {finding_titles}"
        )

        # The free-text "OPERATIONAL_RISK" category was consolidated onto the
        # canonical Category enum (no OPERATIONAL_RISK member); an actively-producing
        # inverter whose controls are writable is an access-control exposure, so the
        # active-production finding now lands under ACCESS_CONTROL. Assert the
        # active-production finding specifically carries that category (still strict).
        ac_findings = _get_security_findings_by_category(log, "ACCESS_CONTROL")
        ac_titles = [f.get("data", {}).get("finding", "").lower() for f in ac_findings]
        assert any(FINDING_ACTIVE_PRODUCTION in t for t in ac_titles), (
            f"Expected the active-production finding under ACCESS_CONTROL. "
            f"ACCESS_CONTROL finding titles: {ac_titles}"
        )

        # Verify the detail mentions MPPT or power
        text = _combined_text(result, log)
        assert "mppt" in text or "9850" in text, (
            f"Expected MPPT state or power value in output, got: {text[:500]}"
        )

    # ========================================================================
    # Security Assessment: Battery Remote Control
    # ========================================================================

    def test_battery_remote_control_finding(self, cli_runner, target, docker_services):
        """Test detection of battery in REMOTE control mode [Category A]

        Mock has Model 802 loc_rem_ctl=0 (REMOTE), meaning the battery
        accepts remote Modbus commands.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        finding_titles = _get_security_finding_titles(log)
        assert any(FINDING_REMOTE_CONTROL in t for t in finding_titles), (
            f"Expected battery remote control finding. Got findings: {finding_titles}"
        )

    # ========================================================================
    # Security Assessment: Device Rated Capacity
    # ========================================================================

    def test_rated_capacity_reported(self, cli_runner, target, docker_services):
        """Test that device rated capacity is reported from Model 120 [Category A]

        Mock has WRtg=10000W with WRtg_SF=0, so capacity is 10.0 kW.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result)

        # The rated capacity should appear in output as "10.0 kW"
        text = _combined_text(result, result.scan_log)
        assert "10.0 kw" in text or "10000" in text, (
            f"Expected rated capacity '10.0 kW' or '10000' in output, got: {text[:500]}"
        )

    def test_no_high_capacity_finding(self, cli_runner, target, docker_services):
        """Test that 10kW device does NOT trigger high-capacity finding [Category A]

        The high-capacity threshold is 100,000W. Mock has 10,000W which is
        below the threshold, so no "High-capacity DER" finding should appear.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        finding_titles = _get_security_finding_titles(log)
        high_cap_findings = [t for t in finding_titles if "high-capacity" in t]
        assert len(high_cap_findings) == 0, (
            f"10kW device should NOT trigger high-capacity finding, but got: {high_cap_findings}"
        )

    # ========================================================================
    # Security Assessment: Findings Count and Summary
    # ========================================================================

    def test_findings_count(self, cli_runner, target, docker_services):
        """Test that the total findings count is reported correctly [Category A]

        Expected findings from the mock:
        1. No security models (3-9)
        2. N writable control registers exposed
        3. Conn writable
        4. SetOp writable
        5. StorCtl_Mod writable
        6. Active production with exposed controls
        7. Battery in REMOTE control mode
        Total: at least 7 findings
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        security_events = log.get_security_findings()
        # We expect at least 7 security findings from the mock data
        assert len(security_events) >= 7, (
            f"Expected at least 7 security findings, got {len(security_events)}. "
            f"Findings: {[e.get('message', '')[:60] for e in security_events]}"
        )

        # The summary line should mention the count
        text = _combined_text(result, log)
        assert "security finding" in text, (
            f"Expected 'security finding' summary in output, got: {text[:500]}"
        )

    def test_security_finding_categories(self, cli_runner, target, docker_services):
        """Test that findings have correct categories [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # Check that we have findings from each expected canonical category.
        # "OPERATIONAL_RISK" was a pre-refactor free-text category with no member in
        # the canonical Category enum; its findings (active production, writable
        # controls) were folded into ACCESS_CONTROL. The SunSpec assessment still
        # spans three distinct canonical categories: AUTHENTICATION (no security
        # models), ACCESS_CONTROL (writable controls / active production), and
        # ENCRYPTION (plaintext Modbus/TCP).
        auth_findings = _get_security_findings_by_category(log, "AUTHENTICATION")
        ac_findings = _get_security_findings_by_category(log, "ACCESS_CONTROL")
        enc_findings = _get_security_findings_by_category(log, "ENCRYPTION")

        assert len(auth_findings) >= 1, (
            f"Expected >= 1 AUTHENTICATION finding, got {len(auth_findings)}"
        )
        assert len(ac_findings) >= 1, (
            f"Expected >= 1 ACCESS_CONTROL finding, got {len(ac_findings)}"
        )
        assert len(enc_findings) >= 1, f"Expected >= 1 ENCRYPTION finding, got {len(enc_findings)}"

    # ========================================================================
    # Connection Lifecycle
    # ========================================================================

    def test_connection_lifecycle(self, cli_runner, target, docker_services):
        """Test that scan completes and logs events during SunSpec scan [Category B]

        Modbus module does not currently emit structured connection events
        (event_type=connection), so we check for any logged events instead.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Assessment failed: {result.stderr}"
        _assert_log_has_events(result, min_count=5)

    # ========================================================================
    # SunSpec Discovery without Assessment (plain -S)
    # ========================================================================

    def test_sunspec_without_assess_no_findings(self, cli_runner, target, docker_services):
        """Test that plain --sunspec does NOT produce security findings [Category B]

        When using --sunspec without --sunspec-assess, the security assessment
        should not run and no security events should appear.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        # UNCONDITIONAL: scanner must at least attempt SunSpec discovery
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["sunspec", "marker", "model"]), (
            f"Expected SunSpec discovery attempt in output: {text[:500]}"
        )

        # If successful, verify no security findings from assessment
        if result.success and result.scan_log is not None:
            security_events = result.scan_log.get_security_findings()
            # The assessment findings should NOT appear (only --sunspec, not --sunspec-assess)
            # However, the base scanner might emit generic security events,
            # so check specifically for sunspec assessment finding titles
            sunspec_findings = [
                e
                for e in security_events
                if "sunspec" in e.get("message", "").lower()
                or "writable control" in e.get("message", "").lower()
                or "battery" in e.get("message", "").lower()
            ]
            assert len(sunspec_findings) == 0, (
                f"Plain --sunspec should NOT produce SunSpec assessment findings, "
                f"but got: {[e.get('message', '')[:60] for e in sunspec_findings]}"
            )

    # ========================================================================
    # Verbose Mode
    # ========================================================================

    def test_sunspec_assess_verbose(self, cli_runner, target, docker_services):
        """Test that verbose mode shows additional register details [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            format="json",
            json_log=True,
            verbose=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        # UNCONDITIONAL: scanner must produce some output
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["sunspec", "marker", "model", "security"]), (
            f"Expected SunSpec-related output in verbose mode: {text[:500]}"
        )

    # ========================================================================
    # Error Handling
    # ========================================================================

    def test_sunspec_assess_wrong_port(self, cli_runner, target, docker_services):
        """Test --sunspec-assess against non-SunSpec Modbus device [Category C]

        The main Modbus mock (port 502) has no SunSpec registers at 40000,
        so the scanner should report marker not found and handle gracefully.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "502",
            "--sunspec-assess",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Should not crash (might fail but handle gracefully)
        assert result.returncode != -1, "Scanner should not hang"
        text = _combined_text(result, result.scan_log)
        # Should either report marker not found or produce an error
        assert any(
            term in text for term in ["no sunspec marker", "not found", "error", "fail", "no model"]
        ), f"Expected graceful handling of no SunSpec support: {text[:500]}"

    def test_sunspec_assess_unreachable_port(self, cli_runner, target, docker_services):
        """Test --sunspec-assess against unreachable port [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "65534",
            "--sunspec-assess",
            timeout=10,
            expect_json=False,
            json_log=True,
        )

        # Should fail but not crash
        assert result.returncode != -1, "Should not hang on unreachable port"
        text = result.combined_output.lower()
        assert any(term in text for term in ["error", "fail", "refused", "timeout", "connect"]), (
            f"Expected error message for unreachable port: {text[:500]}"
        )

    def test_sunspec_assess_combined_with_identify(self, cli_runner, target, docker_services):
        """Test --sunspec-assess combined with --identify [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(SUNSPEC_PORT),
            "--sunspec-assess",
            "--identify",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        # UNCONDITIONAL: both features should have attempted execution
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["sunspec", "marker", "model", "security", "identify", "mei"]
        ), f"Expected SunSpec and/or identification output: {text[:500]}"
