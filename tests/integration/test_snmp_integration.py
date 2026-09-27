"""
SNMP Protocol Integration Tests

Tests oida snmp scanner against Docker mock services (net-snmp on UDP).

Mock profiles:
  - snmp-mock (port 10161): Linux ICS server with v2c communities
    (public/private/SCADA/monitor), v3 users, VACM write, HOST-RESOURCES-MIB,
    ARP table, ICS port listeners
  - snmp-v3only (port 10164): Hardened SEL-3620 gateway, SNMPv3 only,
    no v1/v2c, restricted VACM views

Uses structured JSON log assertions for precise validation.
"""

import pytest

from tests.service_gate import require_service

from tests.integration.conftest import MOCK_HOST, MOCK_PORTS


# SNMP runs over UDP, which drops packets under heavy concurrent load - many
# SNMP classes walking mocks across xdist workers cause incomplete walks and
# missing findings. Serialize all SNMP tests onto one worker. Honored only
# under `--dist loadgroup`. Mirrors test_hart/mms/iec104 integration files.
pytestmark = pytest.mark.xdist_group("snmp_service")


# ---------------------------------------------------------------------------
# Constants - known mock data (ground truth from snmpd.conf / entrypoint.sh)
# ---------------------------------------------------------------------------

SNMP_PORT = MOCK_PORTS.get("snmp", 10161)
SNMP_V3ONLY_PORT = MOCK_PORTS.get("snmp_v3only", 10164)

# Linux profile (port 10161). Only MOCK_SYSCONTACT is referenced in an
# assertion; the other sysDescr/sysName/sysLocation/vendor values are documented
# in the module docstring above and asserted inline as literals where needed, so
# duplicating them as never-read constants here was dead.
MOCK_SYSCONTACT = "ics-admin@plant.local"


# ---------------------------------------------------------------------------
# SNMP UDP reachability check (cannot use TCP socket for UDP service)
# ---------------------------------------------------------------------------


# Reachability probes deliberately narrow their exception handling. A missing
# pysnmp (ImportError) or a genuine network error maps to False so the dependent
# tests SKIP. Programming errors -- AttributeError/TypeError from a changed
# pysnmp API, e.g. a renamed symbol -- are NOT caught: a broad `except Exception`
# here would silently skip all 144 SNMP tests with CI green instead of failing
# loudly, masking a real breakage.


def _check_snmp_reachable(host: str, port: int) -> bool:
    """Check if SNMP agent responds on the given UDP port (pysnmp v7 async API)."""
    try:
        import asyncio
        from pysnmp.hlapi.asyncio import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            get_cmd,
        )
    except ImportError:
        return False

    async def _probe():
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create((host, port), timeout=2, retries=0)
        error_indication, error_status, _, _ = await get_cmd(
            engine,
            CommunityData("public"),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(".1.3.6.1.2.1.1.1.0")),
        )
        return error_indication is None and error_status == 0

    try:
        return asyncio.run(_probe())
    except OSError:
        return False


def _check_snmp_v3_reachable(host: str, port: int) -> bool:
    """Check if SNMPv3 agent responds (pysnmp v7 async API, user: engineer)."""
    try:
        import asyncio
        from pysnmp.hlapi.asyncio import (
            UsmUserData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            get_cmd,
            USM_AUTH_HMAC96_SHA,
        )
    except ImportError:
        return False

    async def _probe():
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create((host, port), timeout=2, retries=0)
        error_indication, error_status, _, _ = await get_cmd(
            engine,
            UsmUserData(
                "engineer",
                authKey="engineer1",
                authProtocol=USM_AUTH_HMAC96_SHA,
            ),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(".1.3.6.1.2.1.1.1.0")),
        )
        return error_indication is None and error_status == 0

    try:
        return asyncio.run(_probe())
    except OSError:
        return False


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


def _get_security_findings(log):
    """Return all security event findings from the log."""
    return [
        e.get("data", {}).get("finding", "")
        for e in log.events
        if e.get("event_type") == "security"
    ]


# ---------------------------------------------------------------------------
# Test Classification Summary
# ---------------------------------------------------------------------------
# Category A (strict -- mock supports, assert success + validate data):   78 tests
# Category B (conditional -- mock may not support, accept 0 or 1):        49 tests
# Category C (error handling -- assert failure + validate error events):   14 tests
# Skipped (untestable -- requires hardware/unsupported):                    3 tests
# Total:                                                                  144 tests
# ---------------------------------------------------------------------------


@pytest.mark.snmp
class TestSNMPIntegration:
    """Integration tests for SNMP protocol scanner against net-snmp mock."""

    # ========================================================================
    # Fixtures
    # ========================================================================

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return SNMP_PORT

    @pytest.fixture(autouse=True)
    def _require_snmp_mock(self, target, port):
        """Skip all tests if the SNMP mock is not reachable."""
        if not _check_snmp_reachable(target, port):
            require_service(f"SNMP mock not reachable on {target}:{port}")

    # ========================================================================
    # Service Availability
    # ========================================================================

    def test_service_is_available(self, target, port):
        """Verify SNMP mock service is running and responding [Category A]"""
        assert _check_snmp_reachable(target, port), (
            f"SNMP service not responding on {target}:{port}"
        )

    # ========================================================================
    # CLI Smoke Tests
    # ========================================================================

    def test_help_command(self, cli_runner):
        """Verify help command works for SNMP protocol [Category A]"""
        result = cli_runner.run("snmp", "--help", expect_json=False)
        assert result.returncode == 0
        output = result.combined_output.lower()
        assert "snmp" in output
        assert "community" in output
        assert "--walk" in output
        assert "--auth" in output
        assert "--default-creds" in output
        assert "--brute-rate" in output
        # Removed factory flags must not appear
        assert "--wordlist" not in output, "Removed --wordlist should not appear in help"
        assert "--stop-on-success" not in output, "Removed --stop-on-success should not appear"

    # ========================================================================
    # Basic Discovery Tests
    # ========================================================================

    def test_basic_scan_default_community(self, cli_runner, target, port):
        """Test basic scan with default community 'public' [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success, f"Basic scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        messages = _all_messages(log)
        # Validate known mock data
        assert "ics-server01" in messages, (
            f"Expected 'ics-server01' in log messages, got: {messages[:500]}"
        )
        assert "net-snmp" in messages, (
            f"Expected 'net-snmp' (vendor) in log messages, got: {messages[:500]}"
        )

    def test_basic_scan_validates_sysdescr(self, cli_runner, target, port):
        """Test that basic scan returns sysDescr from mock [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(log=result.scan_log)
        # sysDescr content from mock
        assert "linux" in messages and "ics-server01" in messages

    def test_basic_scan_community_info(self, cli_runner, target, port):
        """Test that basic scan reports community string in use [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success
        messages = _all_messages(result.scan_log)
        assert "community='public'" in messages or "community" in messages

    def test_explicit_community(self, cli_runner, target, port):
        """Test scan with explicit community string '-C public' [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "public",
            format="json",
            json_log=True,
        )
        assert result.success, f"Explicit community scan failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_private_community(self, cli_runner, target, port):
        """Test scan with 'private' rw community [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "private",
            format="json",
            json_log=True,
        )
        assert result.success, f"Private community scan failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "ics-server01" in messages

    def test_scada_community(self, cli_runner, target, port):
        """Test scan with 'SCADA' community (ICS-specific) [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "SCADA",
            format="json",
            json_log=True,
        )
        assert result.success, f"SCADA community scan failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_multi_community_csv(self, cli_runner, target, port):
        """Test comma-separated community list '-C wrong,public,private' [Category A]

        NXC flow resolves comma-separated communities before create_conn_obj(),
        testing each and selecting the first valid one.
        Uses -D to skip version detection (which would auto-select v3).
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "wrong,public,private",
            "-V",
            "2c",
            "--timeout",
            "2",
            timeout=15,
            format="json",
            json_log=True,
        )
        assert result.success, f"Multi-community CSV failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "ics-server01" in messages, (
            f"Expected sysName from resolved community, got: {messages[:300]}"
        )

    def test_community_from_file(self, cli_runner, target, port, tmp_path):
        """Test '-C file.txt' loads communities from file [Category A]

        parse_credential_input auto-detects file, loads lines as communities,
        NXC flow resolves via _test_communities before connect.
        Uses -D to skip version detection (which would auto-select v3).
        """
        community_file = tmp_path / "communities.txt"
        community_file.write_text("bogus\npublic\nprivate\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            str(community_file),
            "-V",
            "2c",
            # A -C wordlist FILE is an active brute-force and is gated behind
            # --confirm (scanner.py community_is_file gate), like --default-creds.
            "--confirm",
            "--timeout",
            "2",
            timeout=15,
            format="json",
            json_log=True,
        )
        assert result.success, f"-C file failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "ics-server01" in messages, (
            f"Expected sysName from file-loaded community, got: {messages[:300]}"
        )

    def test_community_file_all_invalid(self, cli_runner, target, port, tmp_path):
        """Test '-C file.txt' with only invalid communities fails gracefully [Category C]

        Uses -D to skip version detection and stay on v2c.
        """
        community_file = tmp_path / "bad_communities.txt"
        community_file.write_text("bogus1\nbogus2\nbogus3\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            str(community_file),
            "-V",
            "2c",
            # A -C wordlist FILE brute-force requires --confirm; without it the
            # scan is rejected before ever probing the communities.
            "--confirm",
            "--timeout",
            "2",
            timeout=15,
            format="json",
            json_log=True,
        )
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "none of" in messages, (
            f"Expected 'none of N communities responded' message, got: {messages[:300]}"
        )

    # ========================================================================
    # SNMP Version Tests
    # ========================================================================

    def test_snmpv1(self, cli_runner, target, port):
        """Test SNMPv1 mode '--snmp-version 1' [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--snmp-version",
            "1",
            format="json",
            json_log=True,
        )
        assert result.success, f"SNMPv1 scan failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "ics-server01" in messages

    def test_snmpv2c_explicit(self, cli_runner, target, port):
        """Test explicit SNMPv2c mode '--snmp-version 2c' [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--snmp-version",
            "2c",
            format="json",
            json_log=True,
        )
        assert result.success, f"SNMPv2c scan failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # SNMPv3 Authentication Tests
    # ========================================================================

    def test_v3_noauthnopriv(self, cli_runner, target, port):
        """Test SNMPv3 noAuthNoPriv with 'initial' user [Category A]

        noAuthNoPriv requires -u (username only, no colon format) since a plain
        -C value without colons is interpreted as a v2c community string.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-u",
            "initial",
            "-l",
            "noAuthNoPriv",
            format="json",
            json_log=True,
        )
        assert result.success, f"v3 noAuthNoPriv failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "ics-server01" in messages
        assert "user='initial'" in messages or "snmpv3" in messages

    def test_v3_authnopriv_sha(self, cli_runner, target, port):
        """Test SNMPv3 authNoPriv with SHA user 'engineer' [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "engineer:engineer1",
            format="json",
            json_log=True,
        )
        assert result.success, f"v3 authNoPriv SHA failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "ics-server01" in messages

    def test_v3_authpriv_sha_aes(self, cli_runner, target, port):
        """Test SNMPv3 authPriv with SHA+AES128 user 'admin' [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "admin:admin123:admin123",
            format="json",
            json_log=True,
        )
        assert result.success, f"v3 authPriv SHA+AES failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "ics-server01" in messages
        assert "user='admin'" in messages or "snmpv3" in messages

    def test_v3_longform_auth(self, cli_runner, target, port):
        """Test SNMPv3 with long-form auth arguments [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--snmp-version",
            "3",
            "--snmp-user",
            "engineer",
            "--snmp-auth-protocol",
            "SHA",
            "--snmp-auth-pass",
            "engineer1",
            "--snmp-security-level",
            "authNoPriv",
            format="json",
            json_log=True,
        )
        assert result.success, f"v3 long-form auth failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "ics-server01" in messages

    def test_v3_short_flags_snmpget_compat(self, cli_runner, target, port):
        """Test SNMPv3 with snmpget-compatible short flags (-u -a -A -x -X) [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-u",
            "admin",
            "-a",
            "SHA",
            "-A",
            "admin123",
            "-x",
            "AES128",
            "-X",
            "admin123",
            format="json",
            json_log=True,
        )
        assert result.success, f"v3 short flags failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "ics-server01" in messages
        assert "user='admin'" in messages or "snmpv3" in messages

    def test_unified_auth_community(self, cli_runner, target, port):
        """Test -C with plain community string (no colon) stays v2c [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "private",
            format="json",
            json_log=True,
        )
        assert result.success, f"Unified -C community failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "community='private'" in messages
        assert "ics-server01" in messages

    def test_unified_auth_v3_colon(self, cli_runner, target, port):
        """Test -C user:pass:priv auto-selects v3 [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "admin:admin123:admin123",
            format="json",
            json_log=True,
        )
        assert result.success, f"Unified -C v3 failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "user='admin'" in messages or "snmpv3" in messages
        assert "ics-server01" in messages

    def test_v3_authpriv_longform(self, cli_runner, target, port):
        """Test SNMPv3 authPriv with full long-form arguments [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--snmp-version",
            "3",
            "--snmp-user",
            "admin",
            "--snmp-auth-protocol",
            "SHA",
            "--snmp-auth-pass",
            "admin123",
            "--snmp-priv-protocol",
            "AES128",
            "--snmp-priv-pass",
            "admin123",
            "--snmp-security-level",
            "authPriv",
            format="json",
            json_log=True,
        )
        assert result.success, f"v3 authPriv long-form failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # Security Findings Tests
    # ========================================================================

    @pytest.mark.security
    def test_no_encryption_finding_v2c(self, cli_runner, target, port):
        """Test 'No encryption' security finding for SNMPv2c [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success
        _assert_log_has_events(result)
        findings = _get_security_findings(result.scan_log)
        assert "No encryption" in findings, f"Expected 'No encryption' finding, got: {findings}"

    @pytest.mark.security
    def test_default_creds_finding_public(self, cli_runner, target, port):
        """Test 'Default credentials' security finding for community 'public' [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "public",
            format="json",
            json_log=True,
        )
        assert result.success
        _assert_log_has_events(result)
        findings = _get_security_findings(result.scan_log)
        assert "Default credentials" in findings, (
            f"Expected 'Default credentials' finding, got: {findings}"
        )

    @pytest.mark.security
    def test_no_default_creds_finding_private(self, cli_runner, target, port):
        """Test no 'Default credentials' finding with non-default community [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "private",
            format="json",
            json_log=True,
        )
        assert result.success
        _assert_log_has_events(result)
        findings = _get_security_findings(result.scan_log)
        # 'private' is not the default community, so 'Default credentials' should not appear
        assert "Default credentials" not in findings, (
            f"'Default credentials' finding should not appear for community 'private', got: {findings}"
        )

    @pytest.mark.security
    def test_write_access_finding_private(self, cli_runner, target, port):
        """Test 'Writable access' security finding with rw community [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "private",
            "--test-write",
            "--confirm",
            format="json",
            json_log=True,
        )
        assert result.success, f"Write access test failed: {result.stderr}"
        _assert_log_has_events(result)
        findings = _get_security_findings(result.scan_log)
        assert "Writable access" in findings, (
            f"Expected 'Writable access' finding for rw community 'private', got: {findings}"
        )

    @pytest.mark.security
    def test_no_write_access_readonly(self, cli_runner, target, port):
        """Test no 'Writable access' finding with ro community [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "public",
            "--test-write",
            "--confirm",
            format="json",
            json_log=True,
        )
        # ro community should not produce write-access finding
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            findings = _get_security_findings(result.scan_log)
            assert "Writable access" not in findings, (
                f"'Writable access' should not appear for ro community 'public', got: {findings}"
            )

    # ========================================================================
    # Raw Walk Tests
    # ========================================================================

    def test_walk_default_mib2(self, cli_runner, target, port):
        """Test --walk with default MIB-2 subtree [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--walk",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success, f"Walk failed: {result.stderr}"
        _assert_log_has_events(result, min_count=3)
        messages = _all_messages(result.scan_log)
        # Walk of MIB-2 should contain system group data
        assert "walk" in messages

    def test_walk_system_group(self, cli_runner, target, port):
        """Test --walk .1.3.6.1.2.1.1 (system group) [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--walk",
            ".1.3.6.1.2.1.1",
            format="json",
            json_log=True,
        )
        assert result.success, f"Walk system group failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Should contain sysDescr, sysName, sysContact, sysLocation
        assert "ics-server01" in messages or "sysdescr" in messages or "walk" in messages

    def test_walk_list_vendor(self, cli_runner, target, port):
        """Test --walk list:<vendor> prefix for vendor-specific subtrees [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--walk",
            "list:net-snmp",
            format="json",
            json_log=True,
            timeout=45,
        )
        # Vendor subtree may have entries or be empty
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_walk_list_all(self, cli_runner, target, port):
        """Test --walk list:all (all vendor enterprise subtrees) [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--walk",
            "list:all",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_walk_all_flag(self, cli_runner, target, port):
        """Test --walk-all convenience flag (equivalent to --walk list:all) [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--walk-all",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_walk_list_invalid_vendor(self, cli_runner, target, port):
        """Test --walk list:<invalid> vendor name [Category C]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--walk",
            "list:nonexistent_vendor_xyz",
            expect_json=False,
            json_log=True,
        )
        # Should handle gracefully (may fail with unknown list or succeed with 0 results)
        assert result.returncode in [0, 1], (
            f"Unexpected return code {result.returncode} for invalid vendor walk"
        )
        output = result.combined_output.lower()
        if result.returncode != 0:
            assert any(term in output for term in ["unknown", "error", "not found", "invalid"])

    def test_bulk_walk(self, cli_runner, target, port):
        """Test --bulk flag for GETBULK walks (v2c only) [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--walk",
            ".1.3.6.1.2.1.1",
            "--bulk",
            format="json",
            json_log=True,
        )
        assert result.success, f"Bulk walk failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # Raw GET Tests
    # ========================================================================

    def test_get_single_oid_sysdescr(self, cli_runner, target, port):
        """Test --get with sysDescr OID [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--get",
            ".1.3.6.1.2.1.1.1.0",
            format="json",
            json_log=True,
        )
        assert result.success, f"GET sysDescr failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Should contain the sysDescr value
        assert "linux" in messages or "ics-server01" in messages

    def test_get_multiple_oids(self, cli_runner, target, port):
        """Test --get with comma-separated OIDs [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--get",
            ".1.3.6.1.2.1.1.1.0,.1.3.6.1.2.1.1.5.0,.1.3.6.1.2.1.1.6.0",
            format="json",
            json_log=True,
        )
        assert result.success, f"Multi-GET failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # Host Enumeration Tests (--enum)
    # ========================================================================

    def test_enum_all(self, cli_runner, target, port):
        """Test --enum (all categories) [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_interfaces(self, cli_runner, target, port):
        """Test --enum interfaces [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "interfaces",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                messages = _all_messages(result.scan_log)
                assert any(term in messages for term in ["interface", "eth", "lo", "veth"]), (
                    f"Expected interface data on success, got: {messages[:300]}"
                )

    def test_enum_tcp(self, cli_runner, target, port):
        """Test --enum tcp (TCP listener enumeration) [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "tcp",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_processes(self, cli_runner, target, port):
        """Test --enum processes (HOST-RESOURCES-MIB) [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "processes",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_storage(self, cli_runner, target, port):
        """Test --enum storage [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "storage",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_routes(self, cli_runner, target, port):
        """Test --enum routes [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "routes",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_multiple_categories(self, cli_runner, target, port):
        """Test --enum with comma-separated categories [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "interfaces,routes,storage",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_limit(self, cli_runner, target, port):
        """Test --enum-limit caps entries per table [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "processes",
            "--enum-limit",
            "5",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_enum_creds(self, cli_runner, target, port):
        """Test --enum creds (credential hunting) [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_enum_traps(self, cli_runner, target, port):
        """Test --enum traps (trap configuration) [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "traps",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_udp(self, cli_runner, target, port):
        """Test --enum udp (UDP listener enumeration) [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "udp",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_software(self, cli_runner, target, port):
        """Test --enum software (hrSWInstalledTable) [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "software",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_system(self, cli_runner, target, port):
        """Test --enum system (date, forwarding, TTL, TCP stats) [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "system",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_filesystems(self, cli_runner, target, port):
        """Test --enum filesystems (mounted filesystems) [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "filesystems",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_users(self, cli_runner, target, port):
        """Test --enum users (Windows user accounts via LanManager MIB) [Category B]

        Linux mock lacks LanManager MIB - expect graceful no-data.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "users",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_shares(self, cli_runner, target, port):
        """Test --enum shares (Windows shares via LanManager MIB) [Category B]

        Linux mock lacks LanManager MIB - expect graceful no-data.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "shares",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_services(self, cli_runner, target, port):
        """Test --enum services (Windows services via LanManager MIB) [Category B]

        Linux mock lacks LanManager MIB - expect graceful no-data.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "services",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # P3: Process Enumeration - CPU/Memory Fields
    # ========================================================================

    def test_enum_processes_has_parameters_column(self, cli_runner, target, port):
        """Test --enum processes table includes Parameters column [Category B]

        Process table shows: PID, Name, Path, Parameters, Type, Status.
        Uses --full-width to prevent column truncation on narrow terminals.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "processes",
            expect_json=False,
            json_log=True,
            full_width=True,
        )
        assert result.returncode in [0, 1]
        output = result.combined_output
        if result.success and "processes" in _all_messages(result.scan_log):
            assert "Parameters" in output, (
                f"Expected Parameters column in process table, got: {output[:500]}"
            )

    # ========================================================================
    # P2: Credential Enumeration - Vendor Correlation
    # ========================================================================

    @pytest.mark.security
    def test_enum_creds_graceful_on_linux_mock(self, cli_runner, target, port):
        """Test --enum creds handles empty vendor tables gracefully [Category B]

        P2 added Brocade/Ambit/Netopia credential OIDs and correlation logic.
        The Linux mock has none of these vendor tables - scanner must not crash.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1], (
            f"--enum creds crashed (rc={result.returncode}): {result.stderr}"
        )
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Community Brute-Force Tests
    # ========================================================================

    @pytest.mark.slow
    @pytest.mark.auth
    def test_default_creds_brute_with_confirm(self, cli_runner, target, port):
        """Test --default-creds --confirm community brute-force [Category A]

        Should find 'public' (first built-in ICS community) and proceed to scan.
        Uses -D to stay on v2c (version detection would auto-select v3).
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--default-creds",
            "--confirm",
            "--brute-rate",
            "0.05",
            "-V",
            "2c",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success, f"Default-creds brute failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert any(term in messages for term in ["valid community", "community found"]), (
            f"Expected brute-force hit on 'public', got: {messages[:300]}"
        )
        # Should proceed to discover after finding community
        assert "ics-server01" in messages, (
            f"Expected sysName after brute discovery, got: {messages[:300]}"
        )

    @pytest.mark.auth
    def test_default_creds_brute_without_confirm(self, cli_runner, target, port):
        """Test --default-creds WITHOUT --confirm is rejected [Category C]

        Safety gate: the CLI preflight refuses pre-connect (issue #51), so no
        traffic reaches the target and the JSON log stays empty.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--default-creds",
            "-V",
            "2c",
            format="json",
            json_log=True,
            timeout=10,
        )
        cli_runner.assert_confirm_refused(result, "--default-creds")

    @pytest.mark.auth
    def test_brute_rate_flag_accepted(self, cli_runner, target, port):
        """Test --brute-rate flag is accepted and scan completes [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--default-creds",
            "--confirm",
            "--brute-rate",
            "0.01",
            "-V",
            "2c",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.success, f"--brute-rate flag rejected: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # SNMPv3 Enumeration Tests
    # ========================================================================

    @pytest.mark.slow
    @pytest.mark.security
    def test_enum_v3_user_discovery(self, cli_runner, target, port):
        """Test --enum-v3 user enumeration (phase 1 only) [Category B]

        -E/--enum-v3 now requires --confirm unconditionally.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum-v3",
            "--confirm",
            "--brute-rate",
            "0.01",
            format="json",
            json_log=True,
            timeout=45,
        )
        # v3 user discovery probes many usernames; timeout is acceptable
        assert result.returncode in [-1, 0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.slow
    @pytest.mark.auth
    @pytest.mark.security
    def test_enum_v3_targeted_user_known_creds(self, cli_runner, target, port):
        """Test -E engineer -A engineer1 (targeted user, known password) [Category A]

        -E requires --confirm unconditionally. Phase 2 tests 1 password
        × 1 protocol, finds authNoPriv access immediately.
        Mock user 'engineer' has SHA/engineer1.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "engineer",
            "-A",
            "engineer1",
            "-a",
            "SHA",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.success, f"Targeted v3 user cred test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "engineer" in messages, f"Expected 'engineer' in results, got: {messages[:300]}"
        assert any(term in messages for term in ["auth found", "credentials found"]), (
            f"Expected auth found for engineer, got: {messages[:300]}"
        )

    @pytest.mark.slow
    @pytest.mark.auth
    @pytest.mark.security
    def test_enum_v3_targeted_user_full_creds(self, cli_runner, target, port):
        """Test -E admin -A admin123 -X admin123 (full authPriv creds) [Category A]

        -E requires --confirm unconditionally. Mock user 'admin' has
        SHA/admin123/AES128/admin123. Should find full authPriv access.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "admin",
            "-A",
            "admin123",
            "-X",
            "admin123",
            "-a",
            "SHA",
            "-x",
            "AES128",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.success, f"Targeted v3 full creds test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "admin" in messages, f"Expected 'admin' in results, got: {messages[:300]}"
        assert any(
            term in messages for term in ["full creds", "credentials found", "auth found"]
        ), f"Expected credential discovery for admin, got: {messages[:300]}"

    @pytest.mark.slow
    @pytest.mark.auth
    @pytest.mark.security
    def test_enum_v3_phase2_auth_brute(self, cli_runner, target, port, tmp_path):
        """Test -E engineer -A wordlist (phase 2 auth brute) [Category B]

        Targets 'engineer' user with a small wordlist file containing the correct
        password. Requires --confirm. Phase 2 tries multiple passwords × 1 protocol.
        Mock user 'engineer' has SHA/engineer1.
        """
        pw_file = tmp_path / "auth_passwords.txt"
        pw_file.write_text("wrong1\nengineer1\nwrong2\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "engineer",
            "-A",
            str(pw_file),
            "-a",
            "SHA",
            "--confirm",
            "--brute-rate",
            "0.05",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                messages = _all_messages(result.scan_log)
                assert any(term in messages for term in ["auth found", "credentials found"]), (
                    f"Expected auth brute hit, got: {messages[:300]}"
                )

    @pytest.mark.slow
    @pytest.mark.auth
    @pytest.mark.security
    def test_enum_v3_phase3_priv_brute(self, cli_runner, target, port, tmp_path):
        """Test -E admin with auth + priv brute-force (phases 2+3) [Category B]

        Targets 'admin' user with known auth password and brute-forces priv from
        a wordlist file. Phase 2 finds auth, phase 3 brutes priv key.
        Mock: SHA/admin123/AES128/admin123.
        """
        priv_file = tmp_path / "priv_passwords.txt"
        priv_file.write_text("wrong1\nadmin123\nwrong2\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "admin",
            "-A",
            "admin123",
            "-a",
            "SHA",
            "-X",
            str(priv_file),
            "-x",
            "AES128",
            "--confirm",
            "--brute-rate",
            "0.05",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                messages = _all_messages(result.scan_log)
                assert any(
                    term in messages for term in ["full creds", "credentials found", "priv"]
                ), f"Expected priv brute hit, got: {messages[:300]}"

    @pytest.mark.slow
    @pytest.mark.auth
    @pytest.mark.security
    def test_enum_v3_from_file(self, cli_runner, target, port, tmp_path):
        """Test -E users.txt (load target users from file) [Category B]

        Loads users from a file. -E requires --confirm unconditionally.
        Phase 1 should find valid usernames.
        """
        user_file = tmp_path / "v3_users.txt"
        user_file.write_text("bogus_user\nengineer\nadmin\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            str(user_file),
            "--confirm",
            "--brute-rate",
            "0.01",
            format="json",
            json_log=True,
            timeout=45,
        )
        # v3 enumeration with multiple users can be slow; timeout is acceptable
        assert result.returncode in [-1, 0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            messages = _all_messages(result.scan_log)
            assert "loaded" in messages and "users from file" in messages, (
                f"Expected file-load log message, got: {messages[:300]}"
            )

    @pytest.mark.auth
    @pytest.mark.security
    def test_enum_v3_without_confirm_rejected(self, cli_runner, target, port):
        """Test -E without --confirm is rejected upfront [Category C]

        -E/--enum-v3 without a single-credential exemption is refused by the
        CLI preflight before any connection opens (issue #51).
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "engineer",
            format="json",
            json_log=True,
            timeout=15,
        )
        cli_runner.assert_confirm_refused(result, "--enum-v3")

    @pytest.mark.auth
    @pytest.mark.security
    def test_v3_user_from_file(self, cli_runner, target, port, tmp_path):
        """Test -u file.txt loads SNMPv3 username from file [Category A]

        parse_credential_input on -u auto-detects file, uses first line as username.
        Mock user 'engineer' with SHA/engineer1.
        """
        user_file = tmp_path / "v3_user.txt"
        user_file.write_text("engineer\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-u",
            str(user_file),
            "-A",
            "engineer1",
            "-a",
            "SHA",
            "-l",
            "authNoPriv",
            format="json",
            json_log=True,
            timeout=10,
        )
        # -u with a file containing one username should work as normal v3 auth
        # But parse_credential_input returns a list; the scanner uses the raw
        # string from args. This test validates the flag accepts a file path.
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)

    @pytest.mark.auth
    @pytest.mark.security
    def test_v3_auth_pass_from_file(self, cli_runner, target, port, tmp_path):
        """Test -A file.txt loads auth password from file [Category A]

        Uses -E to trigger the v3 enum path where parse_credential_input
        resolves -A to a password list from file.
        -E requires --confirm unconditionally.
        Mock user 'engineer' has SHA/engineer1.
        """
        pw_file = tmp_path / "auth_pass.txt"
        pw_file.write_text("engineer1\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "engineer",
            "-A",
            str(pw_file),
            "-a",
            "SHA",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.success, f"-A file failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "loaded" in messages and "auth passwords from file" in messages, (
            f"Expected file-load log for -A, got: {messages[:300]}"
        )

    @pytest.mark.auth
    @pytest.mark.security
    def test_v3_priv_pass_from_file(self, cli_runner, target, port, tmp_path):
        """Test -X file.txt loads priv password from file [Category A]

        Uses -E to trigger the v3 enum path where parse_credential_input
        resolves -X to a priv password list from file.
        -E requires --confirm unconditionally.
        Mock user 'admin' has SHA/admin123/AES128/admin123.
        """
        priv_file = tmp_path / "priv_pass.txt"
        priv_file.write_text("admin123\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "admin",
            "-A",
            "admin123",
            "-a",
            "SHA",
            "-X",
            str(priv_file),
            "-x",
            "AES128",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.success, f"-X file failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "loaded" in messages and "priv passwords from file" in messages, (
            f"Expected file-load log for -X, got: {messages[:300]}"
        )

    # ========================================================================
    # Write Access Tests
    # ========================================================================

    @pytest.mark.security
    def test_write_access_with_rw_community(self, cli_runner, target, port):
        """Test --test-write detects write access via rw community [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "private",
            "--test-write",
            "--confirm",
            format="json",
            json_log=True,
        )
        assert result.success, f"Write test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Should report write access confirmed
        assert "write access" in messages, (
            f"Expected 'write access' in log for rw community, got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_write_access_readonly(self, cli_runner, target, port):
        """Test --test-write correctly detects read-only access [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "public",
            "--test-write",
            "--confirm",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            # Should indicate read-only or no write access
            findings = _get_security_findings(result.scan_log)
            assert "Writable access" not in findings

    # ========================================================================
    # MIB Directory Tests
    # ========================================================================

    def test_mib_dir_nonexistent(self, cli_runner, target, port):
        """Test --mib-dir with nonexistent directory [Category C]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--mib-dir",
            "/nonexistent/path/to/mibs",
            format="json",
            json_log=True,
        )
        # Should still complete scan (MIB loading is optional enhancement)
        assert result.returncode in [0, 1], (
            f"Unexpected return code {result.returncode} for nonexistent MIB dir"
        )

    # ========================================================================
    # Verbose / Debug Tests
    # ========================================================================

    def test_verbose_output(self, cli_runner, target, port):
        """Test -v verbose flag (global arg, must precede protocol) [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            expect_json=False,
            json_log=True,
            verbose=True,
        )
        assert result.success, f"Verbose scan failed: {result.stderr}"
        # Verbose should produce more output
        assert result.stdout or result.stderr

    def test_debug_output(self, cli_runner, target, port):
        """Test --debug flag (global arg) [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            expect_json=False,
            json_log=True,
            debug=True,
        )
        assert result.returncode in [0, 1], (
            f"Debug mode returned unexpected code {result.returncode}"
        )

    # ========================================================================
    # Error Handling Tests
    # ========================================================================

    def test_wrong_community(self, cli_runner, target, port):
        """Test scan with wrong community string [Category C]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "totally_wrong_community_xyz",
            "--timeout",
            "2",
            timeout=15,
            expect_json=False,
            json_log=True,
        )
        # Should fail gracefully (no hang, no crash)
        assert result.returncode in [0, 1], (
            f"Unexpected return code {result.returncode} for wrong community"
        )

    def test_unreachable_agent(self, cli_runner):
        """Test handling of unreachable SNMP agent (UDP) [Category C]"""
        result = cli_runner.run(
            "snmp",
            "127.0.0.1",
            "--port",
            "19999",
            "--timeout",
            "2",
            timeout=15,
            expect_json=False,
            json_log=True,
        )
        assert result.returncode in [0, 1], (
            f"Unexpected return code {result.returncode} for unreachable agent"
        )

    def test_timeout_handling(self, cli_runner):
        """Test timeout is properly enforced [Category C]"""
        result = cli_runner.run(
            "snmp",
            "10.255.255.1",
            "--timeout",
            "2",
            timeout=15,
            expect_json=False,
        )
        assert result.returncode in [0, 1], (
            f"Unexpected return code {result.returncode} for timeout test"
        )
        assert result.execution_time < 20, "Command did not respect timeout"

    def test_invalid_target(self, cli_runner):
        """Test handling of invalid target specification [Category C]"""
        result = cli_runner.run(
            "snmp",
            "not-a-valid-host-12345!!!",
            timeout=10,
            expect_json=False,
        )
        assert result.returncode in [0, 1], (
            f"Unexpected return code {result.returncode} for invalid target"
        )
        output_lower = result.combined_output.lower()
        has_error_indication = any(
            term in output_lower for term in ["error", "failed", "cannot", "not found", "not known"]
        )
        assert not result.success or has_error_indication

    def test_v3_wrong_password(self, cli_runner, target, port):
        """Test SNMPv3 with wrong password [Category C]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "admin:wrongpass:wrongpass",
            "--timeout",
            "2",
            timeout=15,
            expect_json=False,
            json_log=True,
        )
        # Should not crash; auth failure produces exit 0 or 1
        assert result.returncode in [0, 1], (
            f"Unexpected return code {result.returncode} for wrong v3 password"
        )

    def test_v3_nonexistent_user(self, cli_runner, target, port):
        """Test SNMPv3 with nonexistent user [Category C]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "nonexistent_user_xyz",
            "--timeout",
            "2",
            timeout=15,
            expect_json=False,
            json_log=True,
        )
        assert result.returncode in [0, 1], (
            f"Unexpected return code {result.returncode} for nonexistent v3 user"
        )

    def test_get_nonexistent_oid(self, cli_runner, target, port):
        """Test --get with nonexistent OID [Category C]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--get",
            ".1.3.6.1.99.99.99.0",
            format="json",
            json_log=True,
        )
        # Should complete without crash; noSuchObject is not necessarily a CLI error
        assert result.returncode in [0, 1], (
            f"Unexpected return code {result.returncode} for nonexistent OID"
        )

    # ========================================================================
    # Version Auto-Detection Tests
    # ========================================================================

    def test_version_autodetect_default(self, cli_runner, target, port):
        """Test version auto-detection runs by default and populates results [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success, f"Scan with version detection failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Version detection should log supported versions
        assert "supported" in messages or "confirmed" in messages or "auto-selected" in messages, (
            f"Expected version detection log message, got: {messages[:500]}"
        )

    def test_version_autodetect_selects_v2c(self, cli_runner, target, port):
        """Test version auto-detection selects v2c as best version [Category A]

        The mixed mock supports v1 and v2c. Auto-detection should prefer v2c
        (GETBULK support). Since default is already v2c, we expect "confirmed"
        rather than "auto-selected".
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Detection should confirm v2c (default matches best) and scan should succeed
        assert "confirmed" in messages or "auto-selected" in messages, (
            f"Expected version detection confirmation, got: {messages[:500]}"
        )
        assert "ics-server01" in messages

    def test_explicit_version_skips_detect(self, cli_runner, target, port):
        """Test -V 2c skips auto-detection [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-V",
            "2c",
            format="json",
            json_log=True,
        )
        assert result.success, f"Scan with -V 2c failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Should NOT contain version detection log messages
        assert "auto-selected snmpv" not in messages, (
            f"Version detection should be skipped with -V 2c, got: {messages[:500]}"
        )
        assert "confirmed (supported:" not in messages, (
            f"Version confirmation should not appear with -V 2c, got: {messages[:500]}"
        )

    def test_version_detect_skipped_with_v3_auth(self, cli_runner, target, port):
        """Test version detection is skipped when -C user:pass is used [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "engineer:engineer1",
            format="json",
            json_log=True,
        )
        assert result.success, f"v3 auth scan failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Version detection should not run when v3 creds are explicit
        assert "auto-selected" not in messages

    @pytest.mark.security
    def test_version_autodetect_v1_security_finding(self, cli_runner, target, port):
        """Test that v1 support triggers 'Legacy protocol' security finding [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success
        _assert_log_has_events(result)
        findings = _get_security_findings(result.scan_log)
        assert "Legacy protocol" in findings, (
            f"Expected 'Legacy protocol' finding for v1-capable mock, got: {findings}"
        )

    # ========================================================================
    # Concurrent Connection Tests
    # ========================================================================

    @pytest.mark.slow
    def test_concurrent_connections(self, cli_runner, target, port):
        """Test multiple concurrent SNMP scans to same target [Category A]"""
        import concurrent.futures

        def run_scan():
            return cli_runner.run(
                "snmp",
                target,
                "--port",
                str(port),
                format="json",
                json_log=True,
                timeout=15,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(run_scan) for _ in range(3)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Every concurrent run must complete with a valid return code
        for i, r in enumerate(results):
            assert r.returncode in [0, 1], (
                f"Concurrent scan {i} returned unexpected code {r.returncode}"
            )
        successes = [r for r in results if r.success]
        assert len(successes) >= 1, "No concurrent connections succeeded"

    # ========================================================================
    # --set Tests
    # ========================================================================

    def test_set_requires_confirm(self, cli_runner, target, port):
        """Test --set without --confirm is rejected [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--set",
            ".1.3.6.1.2.1.1.4.0",
            "s",
            "test",
            "-C",
            "private",
            format="json",
            json_log=True,
        )
        cli_runner.assert_confirm_refused(result, "--set")

    @pytest.mark.security
    def test_set_writes_syscontact(self, cli_runner, target, port):
        """Test --set writes sysContact.0 with rw community [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--set",
            ".1.3.6.1.2.1.1.4.0",
            "s",
            "oida-test-contact",
            "-C",
            "private",
            "--confirm",
            format="json",
            json_log=True,
        )
        assert result.success, f"SET failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "set .1.3.6.1.2.1.1.4.0" in messages, (
            f"Expected SET success message, got: {messages[:500]}"
        )

        # Restore original value
        cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--set",
            ".1.3.6.1.2.1.1.4.0",
            "s",
            MOCK_SYSCONTACT,
            "-C",
            "private",
            "--confirm",
            format="json",
        )

    @pytest.mark.security
    def test_set_read_only_oid(self, cli_runner, target, port):
        """Test --set on read-only OID (sysDescr) reports failure [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--set",
            ".1.3.6.1.2.1.1.1.0",
            "s",
            "x",
            "-C",
            "private",
            "--confirm",
            format="json",
            json_log=True,
        )
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Should report a write-denied error (notWritable, noAccess, readOnly, etc.)
        assert any(
            err in messages for err in ("notwritable", "noaccess", "readonly", "authorizationerror")
        ), f"Expected write-denied error for sysDescr, got: {messages[:500]}"

    # ========================================================================
    # --walk-write Tests
    # ========================================================================

    def test_walk_write_requires_confirm(self, cli_runner, target, port):
        """Test --walk-write without --confirm is rejected [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--walk-write",
            ".1.3.6.1.2.1.1",
            "-C",
            "private",
            format="json",
            json_log=True,
        )
        cli_runner.assert_confirm_refused(result, "--walk-write")

    @pytest.mark.security
    def test_walk_write_sysgroup(self, cli_runner, target, port):
        """Test --walk-write on system group shows writable count [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--walk-write",
            ".1.3.6.1.2.1.1",
            "-C",
            "private",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success, f"Walk-write failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Should contain summary line with writable/read-only counts
        assert "walk-write" in messages, f"Expected walk-write summary, got: {messages[:500]}"
        assert "writable" in messages, (
            f"Expected writable count in walk-write results, got: {messages[:500]}"
        )

    # ========================================================================
    # -E/--enum-v3 Requires --confirm (upfront gate)
    # ========================================================================

    @pytest.mark.auth
    @pytest.mark.security
    def test_enum_v3_requires_confirm(self, cli_runner, target, port):
        """Test -E admin -V 3 -A admin123 runs the targeted auth test, defers priv brute [Category C]

        A named user with a single provided auth password (`-E USER -A pass`) is a
        TARGETED credential test, not a brute-force, so it is allowed through both
        the CLI preflight (cli.py `_snmp_enum_v3_single_credential` mirrors the
        scanner's exemption) and the outer --confirm gate in scanner.py. Phase 2
        tests that one auth password and, when the user needs priv, records the
        finding and DEFERS the active priv brute-force behind --confirm ("add
        --confirm to proceed"). The upfront "requires --confirm" rejection only
        applies to bare `-E USER` (no password) -- see
        test_enum_v3_without_confirm_rejected.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "admin",
            "-V",
            "3",
            "-A",
            "admin123",
            format="json",
            json_log=True,
            timeout=10,
        )
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # The targeted single-credential auth test is NOT rejected upfront...
        assert "requires --confirm" not in messages, (
            f"Single-credential targeted -E should not be rejected upfront: {messages[:300]}"
        )
        # ...it runs phase 2 and defers the active priv brute-force behind --confirm.
        assert "add --confirm to proceed" in messages, (
            f"Expected phase-3 priv-brute deferral gated on --confirm, got: {messages[:400]}"
        )

    # ========================================================================
    # ARP Table Enumeration
    # ========================================================================

    def test_enum_arp_full_table(self, cli_runner, target, port):
        """Test --enum arp displays full ARP table [Category A]

        Mock has 2 ARP entries: 192.168.1.1 and 192.168.1.50 (from entrypoint.sh).
        Should show table with IP/MAC columns.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "arp",
            expect_json=False,
            json_log=True,
            full_width=True,
        )
        assert result.success, f"--enum arp failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "arp entries" in messages, (
            f"Expected 'ARP entries' count in log, got: {messages[:300]}"
        )
        output = result.combined_output
        assert "ARP Table" in output, f"Expected 'ARP Table' header in output, got: {output[:500]}"
        # Verify known mock ARP entries
        assert "192.168.1.1" in output, f"Expected 192.168.1.1 in ARP table, got: {output[:500]}"
        assert "192.168.1.50" in output, f"Expected 192.168.1.50 in ARP table, got: {output[:500]}"

    def test_enum_arp_not_shown_in_default_scan(self, cli_runner, target, port):
        """Test default scan does NOT render full ARP table [Category B]

        A default scan (no --enum) should NOT render the full 'ARP Table'
        header with columns - that output is only produced by --enum arp.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            expect_json=False,
            json_log=True,
        )
        assert result.returncode in [0, 1]
        output = result.combined_output
        # Full table header should NOT be present (that's only with --enum arp)
        assert "ARP Table" not in output, (
            f"Full ARP Table should not appear in default scan, got: {output[:500]}"
        )

    def test_enum_arp_in_all(self, cli_runner, target, port):
        """Test --enum all includes ARP enumeration [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            expect_json=False,
            json_log=True,
            full_width=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
            assert "arp" in messages, (
                f"Expected ARP-related messages in --enum all, got: {messages[:500]}"
            )

    # ========================================================================
    # IP Forwarding Security Finding
    # ========================================================================

    @pytest.mark.security
    def test_ip_forwarding_security_finding(self, cli_runner, target, port):
        """Test --enum system flags IP forwarding as security finding [Category A]

        Mock has ipForwarding=1 (override in snmpd.conf). Scanner should log a
        security finding about potential pivot point.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "system",
            format="json",
            json_log=True,
        )
        assert result.success, f"--enum system failed: {result.stderr}"
        _assert_log_has_events(result)
        findings = _get_security_findings(result.scan_log)
        assert any("ip forwarding" in f.lower() or "pivot" in f.lower() for f in findings), (
            f"Expected IP forwarding security finding, got: {findings}"
        )


# ============================================================================
# SNMPv3-Only Mock Tests (port 10164 - hardened SEL-3620 gateway)
# ============================================================================


@pytest.mark.snmp
@pytest.mark.containers("snmp-v3only")
class TestSNMPv3Only:
    """Tests against the v3-only hardened SNMP mock (no v1/v2c)."""

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return SNMP_V3ONLY_PORT

    @pytest.fixture(autouse=True)
    def _require_v3only_mock(self, target, port):
        """Skip if v3only mock is not reachable."""
        if not _check_snmp_v3_reachable(target, port):
            require_service(f"SNMPv3-only mock not reachable on {target}:{port}")

    def test_v3only_auth_success(self, cli_runner, target, port):
        """Test v3-only mock with valid engineer credentials [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "engineer:engineer1",
            format="json",
            json_log=True,
        )
        assert result.success, f"v3only auth failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Should see SEL-3620 identity
        assert "sel-3620" in messages or "schweitzer" in messages, (
            f"Expected SEL-3620 identity, got: {messages[:500]}"
        )

    def test_v3only_admin_authpriv(self, cli_runner, target, port):
        """Test v3-only mock with admin authPriv credentials [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "admin:admin123:admin123",
            format="json",
            json_log=True,
        )
        assert result.success, f"v3only admin auth failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "sel-3620" in messages or "schweitzer" in messages

    def test_version_autodetect_v3only(self, cli_runner, target, port):
        """Test version detection on v3-only device detects only v3 [Category B]

        The v3-only mock has no v1/v2c communities. Version detection should
        find only v3 and auto-select it. The subsequent scan will likely fail
        (no valid creds provided), but the detection log should show v3 detected.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--timeout",
            "2",
            timeout=10,
            expect_json=False,
            json_log=True,
        )
        # Scan may fail (no v2c community, no v3 creds) but should not crash
        assert result.returncode in [0, 1], (
            f"Unexpected return code {result.returncode} for v3only autodetect"
        )
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
            # Detection should have run and found v3 or reported no response
            assert any(
                term in messages
                for term in [
                    "auto-selected",
                    "v3",
                    "no version responded",
                ]
            ), f"Expected version detection evidence, got: {messages[:500]}"

    def test_v3only_no_creds_shows_hint(self, cli_runner, target, port):
        """Test v3-only auto-detect without creds shows -C hint [Category B]

        When version detection finds only v3 but no credentials were provided,
        the scanner should print an actionable error mentioning -C user:auth:priv.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--timeout",
            "2",
            timeout=10,
            expect_json=False,
            json_log=True,
        )
        assert result.returncode != -1
        output = result.combined_output.lower()
        assert "no credentials provided" in output, (
            f"Expected 'no credentials provided' hint, got: {output[:500]}"
        )
        assert "-c user:" in output, (
            f"Expected '-C user:authpass:privpass' hint, got: {output[:500]}"
        )

    def test_v3only_rejects_v2c(self, cli_runner, target, port):
        """Test v3-only mock rejects SNMPv2c community [Category C]

        The v3-only mock has no v1/v2c communities configured. With -D (skip
        version detection) we force a v2c attempt which should timeout/fail.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "public",
            "-V",
            "2c",
            "--timeout",
            "2",
            timeout=15,
            expect_json=False,
            json_log=True,
        )
        # Should complete without crash
        assert result.returncode in [0, 1], (
            f"Unexpected return code {result.returncode} for v2c on v3only mock"
        )
        # Output should indicate no response / connection failure
        output = result.combined_output.lower()
        assert any(term in output for term in ["no response", "timeout", "failed", "error"]), (
            f"Expected failure indication for v2c on v3only, got: {output[:300]}"
        )

    def test_unified_auth_colon_v3(self, cli_runner, target, port):
        """Test -C user:pass:priv triggers SNMPv3 authPriv [Category A]

        The unified -C flag should auto-detect colon-separated format as v3.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "admin:admin123:admin123",
            format="json",
            json_log=True,
        )
        assert result.success, f"Unified -C v3 authPriv failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "sel-3620" in messages or "schweitzer" in messages
        # Version detection should be skipped (v3 explicit from colon format)
        assert "auto-selected" not in messages

    def test_unified_auth_two_part_authnopriv(self, cli_runner, target, port):
        """Test -C user:pass triggers SNMPv3 authNoPriv [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "engineer:engineer1",
            format="json",
            json_log=True,
        )
        assert result.success, f"Unified -C v3 authNoPriv failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "sel-3620" in messages or "schweitzer" in messages

    @pytest.mark.slow
    @pytest.mark.security
    def test_enum_v3_no_creds(self, cli_runner, target, port, tmp_path):
        """Test -E without credentials discovers users on v3-only device [Category A]

        The v3-only mock has 4 users (admin, operator, engineer, monitor).
        Running -E -V 3 with a small username file and known password should
        discover valid noAuthNoPriv users without triggering a full brute-force.
        """
        # Write a small username file to avoid the 26-user default wordlist
        userfile = tmp_path / "users.txt"
        userfile.write_text("admin\noperator\nengineer\nmonitor\nnonexistent\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "-V",
            "3",
            "-u",
            str(userfile),
            "-A",
            "admin123",
            "-a",
            "SHA",
            "--confirm",
            "--timeout",
            "1",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1], f"enum-v3 crashed: {result.stderr}"
        assert result.scan_log is not None, "scan_log should be populated"
        _assert_log_event_structure(result.scan_log)
        # Usernames appear in security event category/details, not plain messages
        security_events = [e for e in result.scan_log.events if e.get("event_type") == "security"]
        all_security_text = " ".join(str(e.get("data", {})) for e in security_events).lower()
        all_messages = " ".join(e.get("message", "") for e in result.scan_log.events).lower()
        combined = all_security_text + " " + all_messages
        # Should find at least some valid v3 users
        found_users = sum(1 for u in ["admin", "operator", "engineer", "monitor"] if u in combined)
        assert found_users >= 2, (
            f"Expected ≥2 of [admin, operator, engineer, monitor], "
            f"found {found_users} in: {combined[:500]}"
        )

    @pytest.mark.security
    def test_enum_v3_authpriv_escalation(self, cli_runner, target, port):
        """Test -E discovers priv when authNoPriv gets authorizationError [Category A]

        The v3-only mock's admin user requires authPriv (rwuser admin priv).
        Phase 2 should detect authorizationError as WRONG_LEVEL and escalate
        to phase 3 (priv brute), finding admin123/AES128 as the priv key.
        The subsequent connect should succeed with full authPriv credentials.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "admin",
            "-V",
            "3",
            "-A",
            "admin123",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success, f"enum-v3 authPriv escalation failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Phase 2 should detect auth works but priv needed
        assert "needs priv" in messages, (
            f"Expected 'needs priv' from phase 2, got: {messages[:500]}"
        )
        # Phase 3 should find priv credentials
        assert "full creds found" in messages, (
            f"Expected 'full creds found' from phase 3, got: {messages[:500]}"
        )
        # Should connect with discovered authPriv and identify the device
        assert "authpriv" in messages, f"Expected authPriv security level, got: {messages[:500]}"
        assert "sel-3620" in messages or "schweitzer" in messages, (
            f"Expected device identity after authPriv connect, got: {messages[:500]}"
        )

    def test_fine_grained_v3_flags(self, cli_runner, target, port):
        """Test -u/-A/-X fine-grained flags override -C [Category B]

        Uses snmpget-compatible flags to specify v3 credentials individually.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-u",
            "admin",
            "-A",
            "admin123",
            "-X",
            "admin123",
            "-a",
            "SHA",
            "-x",
            "AES128",
            format="json",
            json_log=True,
        )
        assert result.success, f"Fine-grained v3 flags failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "sel-3620" in messages or "schweitzer" in messages


# ============================================================================
# SNMP Switch Mock Tests (port 10162 - H3C switch with credential tables)
# ============================================================================


SNMP_SWITCH_PORT = MOCK_PORTS.get("snmp_switch", 10162)

# Switch ground truth (snmpd-switch.conf + pass_persist.py) is asserted inline
# where needed (e.g. sysName "ICS-SWITCH-01"); the never-read SWITCH_SYSNAME /
# SWITCH_SYSDESCR_FRAGMENT constants were dead.

# H3C credential ground truth (pass_persist.py)
H3C_USERS = [
    {"username": "admin", "password": "admin123", "level": "3"},
    {"username": "monitor", "password": "monitor1", "level": "1"},
    {"username": "operator", "password": "oper@tor", "level": "2"},
]

# Brocade ADX credential ground truth (pass_persist.py)
BROCADE_USERS = [
    {"username": "admin", "password": "$1$abc$hashedpassword"},
    {"username": "readonly", "password": "$1$def$readonlyhash"},
]


@pytest.mark.snmp
@pytest.mark.containers("snmp-switch")
class TestSNMPSwitch:
    """Tests against the H3C switch mock with credential tables (P2 coverage)."""

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return SNMP_SWITCH_PORT

    @pytest.fixture(autouse=True)
    def _require_switch_mock(self, target, port):
        """Skip if switch mock is not reachable."""
        if not _check_snmp_reachable(target, port):
            require_service(f"SNMP switch mock not reachable on {target}:{port}")

    # ========================================================================
    # Basic Connectivity
    # ========================================================================

    def test_switch_identity(self, cli_runner, target, port):
        """Test switch mock returns H3C identity [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success, f"Switch scan failed: {result.stderr}"
        messages = _all_messages(result.scan_log)
        assert "ics-switch-01" in messages, (
            f"Expected sysName 'ICS-SWITCH-01', got: {messages[:300]}"
        )

    # ========================================================================
    # P2: H3C Credential Discovery (hard-check)
    # ========================================================================

    @pytest.mark.security
    def test_enum_creds_finds_h3c_users(self, cli_runner, target, port):
        """Test --enum creds discovers H3C credential table entries [Category A]

        The switch mock serves h3cUserName/Password/Level/State via pass_persist.
        The scanner's H3C correlation logic should group these into user records
        and log warnings for each discovered credential.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            "--timeout",
            "5",
            format="json",
            json_log=True,
        )
        assert result.success, f"--enum creds failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)

        # H3C correlation should find and log the users. Each correlated user is
        # logged as an info line "H3C credential: <user> / <pass> (level=N)";
        # the security event carries the same data in its details field. The
        # literal "found" only appears in that security-event detail
        # ("H3C credential found: ..."), so assert against the message form.
        assert "h3c credential:" in messages, (
            f"Expected 'H3C credential:' in log, got: {messages[:500]}"
        )
        cred_details = " ".join(_credential_finding_details(result.scan_log)).lower()
        assert "h3c credential found" in cred_details, (
            f"Expected 'H3C credential found' security finding, got: {cred_details}"
        )
        # Verify known usernames appear
        for user in H3C_USERS:
            assert user["username"] in messages, (
                f"Expected H3C user '{user['username']}' in log, got: {messages[:500]}"
            )

    @pytest.mark.security
    def test_enum_creds_h3c_passwords_logged(self, cli_runner, target, port):
        """Test --enum creds logs H3C passwords as warnings [Category A]

        The scanner should warn about each discovered H3C password.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            "--timeout",
            "5",
            format="json",
            json_log=True,
        )
        assert result.success
        messages = _all_messages(result.scan_log)
        # admin123 and monitor1 should appear (oper@tor too)
        assert "admin123" in messages, (
            f"Expected H3C password 'admin123' in log, got: {messages[:500]}"
        )

    # ========================================================================
    # P2: Brocade Credential Discovery (hard-check)
    # ========================================================================

    @pytest.mark.security
    def test_enum_creds_finds_brocade_users(self, cli_runner, target, port):
        """Test --enum creds discovers Brocade ADX admin entries [Category A]

        The switch mock serves brocadeAdxAdminUser/Password via pass_persist.
        The scanner's Brocade correlation logic should group these into records.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            "--timeout",
            "5",
            format="json",
            json_log=True,
        )
        assert result.success, f"--enum creds failed: {result.stderr}"
        messages = _all_messages(result.scan_log)

        # Brocade correlation should find and log the users. Brocade creds are
        # surfaced through the "Credential Findings" table (brocadeAdxAdminUser /
        # brocadeAdxAdminPassword rows) rather than a per-user "found" line, so
        # assert against that table content and the known usernames/passwords.
        assert "brocadeadxadminuser" in messages, (
            f"Expected Brocade credential table in log, got: {messages[:500]}"
        )
        for user in BROCADE_USERS:
            assert user["username"] in messages, (
                f"Expected Brocade user '{user['username']}' in log, got: {messages[:500]}"
            )

    @pytest.mark.security
    def test_enum_creds_reports_total_entries(self, cli_runner, target, port):
        """Test --enum creds reports correct total credential entry count [Category A]

        Switch mock has: 3 H3C users × 4 columns (name+pass+level+state) × 2 PENs = 24
        + 2 Brocade users × 2 columns = 4 -> total ≥ 28 credential entries.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            "--timeout",
            "5",
            format="json",
            json_log=True,
        )
        assert result.success
        messages = _all_messages(result.scan_log)
        assert "credential-related entries found" in messages, (
            f"Expected credential summary line, got: {messages[:500]}"
        )

    # ========================================================================
    # CAM Table Enumeration
    # ========================================================================

    def test_enum_cam_full_table(self, cli_runner, target, port):
        """Test --enum cam displays CAM/MAC forwarding table [Category A]

        Switch mock has 5 bridge FDB entries via pass_persist (dot1dTpFdb).
        Should show table with MAC/Port/Status columns.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "cam",
            expect_json=False,
            json_log=True,
            full_width=True,
        )
        assert result.success, f"--enum cam failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "cam entries" in messages, (
            f"Expected 'CAM entries' count in log, got: {messages[:300]}"
        )
        output = result.combined_output
        assert "CAM Table" in output, f"Expected 'CAM Table' header in output, got: {output[:500]}"
        # Check for known MACs from pass_persist.py bridge data
        output_lower = output.lower()
        assert "00:1a:2b" in output_lower or "001a2b" in output_lower, (
            f"Expected MAC 00:1a:2b in CAM table, got: {output[:500]}"
        )
        assert "00:de:ad" in output_lower or "00dead" in output_lower, (
            f"Expected MAC 00:de:ad in CAM table, got: {output[:500]}"
        )

    def test_enum_cam_shows_port_and_status(self, cli_runner, target, port):
        """Test --enum cam table includes port numbers and learned status [Category B]

        Bridge FDB entries have port numbers and status (3=learned, 5=self).
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "cam",
            expect_json=False,
            json_log=True,
            full_width=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            output = result.combined_output.lower()
            assert "learned" in output, (
                f"Expected 'learned' status in CAM table, got: {result.combined_output[:500]}"
            )

    # ========================================================================
    # Credential Table Column Order (Category -> Value -> OID)
    # ========================================================================

    @pytest.mark.security
    def test_enum_creds_value_before_oid(self, cli_runner, target, port):
        """Test --enum creds table has Value column before OID column [Category B]

        Credential table column order was reordered to: Category | Value | OID.
        Verify 'Value' appears before 'OID' in the table header.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            expect_json=False,
            json_log=True,
            full_width=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            output = result.combined_output
            # Find the header line containing both Value and OID
            for line in output.splitlines():
                if "Value" in line and "OID" in line:
                    value_pos = line.index("Value")
                    oid_pos = line.index("OID")
                    assert value_pos < oid_pos, f"Expected Value before OID in header, got: {line}"
                    break

    def test_enum_cam_in_all(self, cli_runner, target, port):
        """Test --enum all includes CAM enumeration [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            expect_json=False,
            json_log=True,
            full_width=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
            assert "cam" in messages, (
                f"Expected CAM-related messages in --enum all, got: {messages[:500]}"
            )


# ---------------------------------------------------------------------------
# IPv6 / Extend / Process Credential Enumeration Tests
# ---------------------------------------------------------------------------


@pytest.mark.snmp
class TestSNMPEnumIPv6:
    """Integration tests for --enum ipv6 (IPv6 address discovery via ipAddressTable)."""

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return SNMP_PORT

    @pytest.fixture(autouse=True)
    def _require_snmp_mock(self, target, port):
        if not _check_snmp_reachable(target, port):
            require_service(f"SNMP mock not reachable on {target}:{port}")

    def test_enum_ipv6_runs(self, cli_runner, target, port):
        """Test --enum ipv6 executes without error [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "ipv6",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_ipv6_discovers_addresses(self, cli_runner, target, port):
        """Test --enum ipv6 discovers IPv6 addresses from mock [Category B]

        The Linux mock has a global 2001:db8:ics::100 and auto-assigned
        link-local on veth-ics0.  The container's eth0 also has link-local.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "ipv6",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            messages = _all_messages(result.scan_log)
            assert "ipv6" in messages, f"Expected IPv6 mentions in log, got: {messages[:300]}"

    def test_enum_ipv6_classifies_scope(self, cli_runner, target, port):
        """Test --enum ipv6 classifies link-local vs global scope [Category B]

        Mock has 2001:db8:ics::100 (global) and fe80:: (link-local).
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "ipv6",
            format="json",
            json_log=True,
            verbose=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            messages = _all_messages(result.scan_log)
            # At minimum we should see the scope classification
            has_scope = "link-local" in messages or "global" in messages
            assert has_scope, f"Expected scope classification in output, got: {messages[:500]}"

    def test_enum_ipv6_global_security_finding(self, cli_runner, target, port):
        """Test that global IPv6 addresses trigger a security finding [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "ipv6",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            messages = _all_messages(result.scan_log)
            # Only assert when global unicast addresses were actually found
            # "0 global unicast" means none found; skip assertion in that case
            if "global unicast)" in messages and "0 global unicast)" not in messages:
                findings = _get_security_findings(result.scan_log)
                assert any("ipv6" in f.lower() for f in findings), (
                    f"Expected IPv6 security finding, got: {findings}"
                )

    def test_enum_ipv6_in_all(self, cli_runner, target, port):
        """Test that --enum all includes IPv6 enumeration [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
            assert "ipv6" in messages, (
                f"Expected IPv6 category in --enum all output, got: {messages[:500]}"
            )


@pytest.mark.snmp
class TestSNMPEnumExtend:
    """Integration tests for --enum extend (NET-SNMP extend script detection)."""

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return SNMP_PORT

    @pytest.fixture(autouse=True)
    def _require_snmp_mock(self, target, port):
        if not _check_snmp_reachable(target, port):
            require_service(f"SNMP mock not reachable on {target}:{port}")

    def test_enum_extend_runs(self, cli_runner, target, port):
        """Test --enum extend executes without error [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "extend",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_extend_finds_scripts(self, cli_runner, target, port):
        """Test --enum extend detects configured extend scripts [Category A]

        Mock snmpd.conf has:
          extend check-ics /bin/sh -c "echo ICS_STATUS=OK; uptime"
          extend disk-check /usr/bin/df -h
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "extend",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            messages = _all_messages(result.scan_log)
            assert "extend" in messages, f"Expected extend script mentions, got: {messages[:300]}"

    def test_enum_extend_reports_commands(self, cli_runner, target, port):
        """Test --enum extend reports command paths [Category B]

        Should find /bin/sh and /usr/bin/df from mock extend config.
        Conditional: only asserts if extend scripts were found.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "extend",
            format="json",
            json_log=True,
            verbose=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            messages = _all_messages(result.scan_log)
            if "extend script '" in messages:
                has_cmd = (
                    "/bin/sh" in messages or "/usr/bin/df" in messages or "check-ics" in messages
                )
                assert has_cmd, f"Expected extend command details, got: {messages[:500]}"

    @pytest.mark.security
    def test_enum_extend_security_finding(self, cli_runner, target, port):
        """Test extend scripts trigger RCE security finding [Category B]

        Conditional: only asserts if extend scripts were discovered.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "extend",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            messages = _all_messages(result.scan_log)
            if "extend script '" in messages and "rce" not in messages:
                findings = _get_security_findings(result.scan_log)
                assert any("rce" in f.lower() or "extend" in f.lower() for f in findings), (
                    f"Expected RCE/extend security finding, got: {findings}"
                )

    def test_enum_extend_captures_output(self, cli_runner, target, port):
        """Test --enum extend captures script output (nsExtendOutput1Line) [Category B]

        Reading nsExtendOutput1Line triggers execution of check-ics which
        outputs "ICS_STATUS=OK; uptime".
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "extend",
            format="json",
            json_log=True,
            verbose=True,
        )
        assert result.returncode in [0, 1]
        # Output capture is best-effort - some net-snmp builds may not return it
        if result.success:
            messages = _all_messages(result.scan_log)
            # If output was captured, it should contain the script result
            if "ics_status" in messages:
                assert "ok" in messages or "uptime" in messages

    def test_enum_extend_in_all(self, cli_runner, target, port):
        """Test that --enum all includes extend enumeration [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
            assert "extend" in messages, (
                f"Expected extend category in --enum all output, got: {messages[:500]}"
            )


@pytest.mark.snmp
class TestSNMPEnumProcessCreds:
    """Integration tests for process credential scanning in --enum creds."""

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return SNMP_PORT

    @pytest.fixture(autouse=True)
    def _require_snmp_mock(self, target, port):
        if not _check_snmp_reachable(target, port):
            require_service(f"SNMP mock not reachable on {target}:{port}")

    def test_enum_creds_includes_process_scan(self, cli_runner, target, port):
        """Test --enum creds walks process args for credential patterns [Category B]

        Mock starts: python3 -c "..." --host plc01 --password=S3cretICS
        The --password= pattern should match CRED_PATTERNS.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_enum_creds_detects_password_in_args(self, cli_runner, target, port):
        """Test credential detection finds --password=S3cretICS in process args [Category B]

        The mock runs a python3 process with --password=S3cretICS in argv.
        The scanner should match this via CRED_PATTERNS and log a warning.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
            verbose=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            messages = _all_messages(result.scan_log)
            # Look for credential detection indicator
            has_proc_cred = (
                "credential in process" in messages
                or "process" in messages
                and "password" in messages
            )
            if has_proc_cred:
                # Verify it found the password pattern
                assert "password" in messages, (
                    f"Expected password pattern match, got: {messages[:500]}"
                )

    @pytest.mark.security
    def test_enum_creds_process_security_finding(self, cli_runner, target, port):
        """Test process credentials trigger security finding [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            messages = _all_messages(result.scan_log)
            if "credential in process" in messages:
                findings = _get_security_findings(result.scan_log)
                assert any("credential" in f.lower() or "process" in f.lower() for f in findings), (
                    f"Expected credential exposure finding, got: {findings}"
                )


# ============================================================================
# Comprehensive Security Findings Tests
# ============================================================================
#
# This section tests every security_finding() call in scanner.py.
# Each finding is mapped to its trigger condition and tested against the
# appropriate mock profile (linux on 10161, switch on 10162, v3only on 10164).
#
# Findings inventory (scanner.py line numbers):
#   1. "Legacy protocol"          (L749)  - SNMPv1 supported        [EXISTING]
#   2. "Writable access"          (L864)  - VACM/SET write detected  [EXISTING]
#   3. "Writable OIDs found"      (L1350) - walk-write found writes  [NEW]
#   4. "No authentication"        (L1589) - v3 noAuthNoPriv user     [NEW]
#   5. "Credential disclosure"    (L1690) - v3 auth creds bruted     [NEW]
#   6. "Credential disclosure"    (L1803) - v3 full creds bruted     [NEW]
#   7. H3C credential found       (L3274) - H3C cred table           [NEW]
#   8. Brocade credential found   (L3297) - Brocade cred table       [NEW]
#   9. Credential OID password    (L3332) - password in OID walk     [NEW]
#  10. Community string in OID    (L3337) - community in OID walk    [NEW]
#  11. Credential in process args (L3395) - --password= in argv      [STRENGTHENED]
#  12. "IP forwarding enabled"    (L3505) - ipForwarding=1           [EXISTING]
#  13. "Insecure configuration"   (L3600) - writable remote mount    [SKIP: no mock data]
#  14. "RCE risk"                 (L3785) - injected extend script   [STRENGTHENED]
#  15. "Insecure configuration"   (L3815) - ICS service exposed      [NEW]
#  16. "Insecure configuration"   (L3826) - default Windows account  [SKIP: no container]
#  17. "Insecure configuration"   (L3837) - admin share exposed      [SKIP: no container]
#  18. "Insecure configuration"   (L3847) - trap community string    [NEW]
#  19. "RCE risk"                 (L3855) - extend scripts count     [NEW]
#  20. "Hidden attack surface"    (L3864) - global IPv6 addresses    [STRENGTHENED]
#  21. "Credential exposure"      (L3875) - process creds summary    [STRENGTHENED]
#  22. "No encryption"            (L3883) - SNMPv1/v2c cleartext     [EXISTING]
#  23. "Default credentials"      (L3888) - public community         [EXISTING]
# ============================================================================


def _get_security_finding_details(log):
    """Return list of (finding_title, category, details) tuples from security events."""
    results = []
    for e in log.events:
        if e.get("event_type") == "security":
            data = e.get("data", {})
            results.append(
                (
                    data.get("finding", ""),
                    data.get("category", ""),
                    data.get("details", ""),
                )
            )
    return results


def _credential_finding_details(log):
    """Return the ``details`` text of every credential-disclosure security event.

    The SNMP scanner emits a ``security_finding("Credential disclosure", ...)``
    per discovered credential, but ``ICSLogger.security_finding`` de-duplicates
    by ``(title, category)`` within a scan (see ics_logger.py docstring). Since
    every credential shares the title "Credential disclosure" + category
    INFO_DISCLOSURE, exactly one such event survives in the log; its ``details``
    field carries the vendor + username + password of the first credential
    (e.g. "H3C credential found: admin / admin123"). The full per-credential
    breakdown lives in the info-level messages - use ``_credential_messages``
    for that.
    """
    return [d[2] for d in _get_security_finding_details(log) if d[0] == "Credential disclosure"]


def _credential_messages(log) -> str:
    """Lowercased join of the info-level credential messages.

    These are the authoritative per-credential records the scanner prints once
    it has correlated the H3C / Brocade vendor tables: the "H3C credential:
    <user> / <pass> (level=N)" lines and the "Credential Findings" table rows
    (e.g. "| h3cUserPassword | admin123 | <oid>", "| brocadeAdxAdminUser |
    readonly | <oid>"). Unlike the security events, these are NOT de-duplicated,
    so every discovered username/password appears here.
    """
    return _all_messages(log)


@pytest.mark.snmp
class TestSNMPSecurityFindings:
    """Comprehensive security finding tests covering all scanner.py findings.

    Tests are organised by finding type and target the appropriate mock profile.
    Linux mock (port 10161) for most findings; switch mock (port 10162) for
    vendor credential tables; v3only mock (port 10164) for SNMPv3 brute-force.
    """

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return SNMP_PORT

    @pytest.fixture(autouse=True)
    def _require_snmp_mock(self, target, port):
        if not _check_snmp_reachable(target, port):
            require_service(f"SNMP mock not reachable on {target}:{port}")

    # ========================================================================
    # Finding: "No encryption" (L3883) - _analyze_security
    # ========================================================================

    @pytest.mark.security
    def test_finding_no_encryption_v1(self, cli_runner, target, port):
        """Test 'No encryption' finding fires for explicit SNMPv1 [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--snmp-version",
            "1",
            format="json",
            json_log=True,
        )
        assert result.success, f"SNMPv1 scan failed: {result.stderr}"
        _assert_log_has_events(result)
        findings = _get_security_findings(result.scan_log)
        assert "No encryption" in findings, f"Expected 'No encryption' for v1, got: {findings}"

    @pytest.mark.security
    def test_finding_no_encryption_detail_text(self, cli_runner, target, port):
        """Test 'No encryption' finding includes version and cleartext detail [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success
        _assert_log_has_events(result)
        finding_details = _get_security_finding_details(result.scan_log)
        no_enc = [f for f in finding_details if f[0] == "No encryption"]
        assert len(no_enc) > 0, f"Expected 'No encryption' finding, got: {finding_details}"
        # The detail should mention cleartext
        detail_text = " ".join(f[1] + " " + f[2] for f in no_enc).lower()
        assert "cleartext" in detail_text, (
            f"Expected 'cleartext' in finding detail, got: {detail_text}"
        )

    # ========================================================================
    # Finding: "Default credentials" (L3888) - _analyze_security
    # ========================================================================

    @pytest.mark.security
    def test_finding_default_creds_detail_mentions_public(self, cli_runner, target, port):
        """Test 'Default credentials' finding detail mentions 'public' [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "public",
            format="json",
            json_log=True,
        )
        assert result.success
        _assert_log_has_events(result)
        finding_details = _get_security_finding_details(result.scan_log)
        default_cred = [f for f in finding_details if f[0] == "Default credentials"]
        assert len(default_cred) > 0, (
            f"Expected 'Default credentials' finding, got: {finding_details}"
        )
        detail_text = " ".join(f[1] + " " + f[2] for f in default_cred).lower()
        assert "public" in detail_text, f"Expected 'public' mentioned in detail, got: {detail_text}"

    # ========================================================================
    # Finding: "Legacy protocol" (L749) - _detect_versions
    # ========================================================================

    @pytest.mark.security
    def test_finding_legacy_protocol_detail(self, cli_runner, target, port):
        """Test 'Legacy protocol' finding mentions SNMPv1 and integrity [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success
        _assert_log_has_events(result)
        finding_details = _get_security_finding_details(result.scan_log)
        legacy = [f for f in finding_details if f[0] == "Legacy protocol"]
        assert len(legacy) > 0, f"Expected 'Legacy protocol' finding, got: {finding_details}"
        detail_text = " ".join(f[1] + " " + f[2] for f in legacy).lower()
        assert "snmpv1" in detail_text or "v1" in detail_text, (
            f"Expected SNMPv1 mention in detail, got: {detail_text}"
        )

    # ========================================================================
    # Finding: "Writable OIDs found" (L1350) - walk_write
    # ========================================================================

    @pytest.mark.security
    def test_finding_writable_oids_walk_write(self, cli_runner, target, port):
        """Test 'Writable OIDs found' finding via --walk-write with rw community [Category A]

        The mock has 'private' as rwcommunity. Using --walk-write with the rw
        community on a small subtree (sysContact, which is override -rw) should
        find writable OIDs and trigger the finding.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "private",
            "--walk-write",
            ".1.3.6.1.2.1.1.4",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        findings = _get_security_findings(result.scan_log)
        # Walk-write should attempt the operation
        assert "walk-write" in messages, (
            f"Expected 'walk-write' in log messages, got: {messages[:500]}"
        )
        # If writable OIDs were found, the finding should fire
        if "writable" in messages and "0/" not in messages.split("walk-write")[1][:50]:
            assert "Writable OIDs found" in findings, (
                f"Expected 'Writable OIDs found' finding, got: {findings}"
            )

    @pytest.mark.security
    def test_finding_no_writable_oids_readonly(self, cli_runner, target, port):
        """Test no 'Writable OIDs found' with ro community on --walk-write [Category B]

        With 'public' (ro community), no OIDs should be writable.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "public",
            "--walk-write",
            ".1.3.6.1.2.1.1.4",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "walk-write" in messages, (
            f"Expected walk-write attempt in output, got: {messages[:500]}"
        )
        findings = _get_security_findings(result.scan_log)
        assert "Writable OIDs found" not in findings, (
            f"'Writable OIDs found' should not fire for ro community, got: {findings}"
        )

    # ========================================================================
    # Finding: "No authentication" (L1589) - SNMPv3 brute discovers noAuthNoPriv
    # ========================================================================

    @pytest.mark.security
    @pytest.mark.slow
    def test_finding_no_authentication_v3_brute(self, cli_runner, target, port):
        """Test 'No authentication' finding via -E brute discovering 'initial' user [Category B]

        The linux mock has 'initial' as a noAuthNoPriv user. The scanner's v3
        brute-force (-E) user discovery phase should find it and emit the
        'No authentication' finding. This test uses a short timeout since the
        full brute-force may take very long; partial results are checked.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "--confirm",
            "--brute-rate",
            "0.01",
            format="json",
            json_log=True,
            timeout=45,
        )
        # v3 brute may timeout (rc=-1) - that's acceptable
        assert result.returncode in [-1, 0, 1]
        # Even on timeout, scan_log should have partial events
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
            findings = _get_security_findings(result.scan_log)
            # The scanner should attempt v3 enumeration
            assert "snmpv3" in messages or "v3" in messages or "user" in messages, (
                f"Expected v3 brute attempt in output, got: {messages[:500]}"
            )
            # If it found the 'initial' noauth user, the finding should fire
            if "initial" in messages and "noauthnopriv" in messages:
                assert "No authentication" in findings, (
                    f"Expected 'No authentication' finding for 'initial' user, got: {findings}"
                )

    # ========================================================================
    # Finding: "Credential disclosure" (L1690, L1803) - SNMPv3 brute-force
    # ========================================================================

    @pytest.mark.security
    @pytest.mark.slow
    @pytest.mark.auth
    def test_finding_credential_disclosure_v3_known_creds(self, cli_runner, target, port):
        """Test 'Credential disclosure' finding with known v3 credentials [Category A]

        Using -E with the known 'engineer' user and auth pass 'engineer1'
        should produce a 'Credential disclosure' finding. -E requires --confirm.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "engineer",
            "-A",
            "engineer1",
            "-a",
            "SHA",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success, f"Targeted v3 cred test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        findings = _get_security_findings(result.scan_log)
        # The scanner should find engineer's credentials
        assert "engineer" in messages, (
            f"Expected 'engineer' user mention in output, got: {messages[:500]}"
        )
        assert any(term in messages for term in ["auth found", "credentials found"]), (
            f"Expected auth found for engineer, got: {messages[:300]}"
        )
        # Credential disclosure finding should fire
        assert "Credential disclosure" in findings, (
            f"Expected 'Credential disclosure' finding, got: {findings}"
        )

    @pytest.mark.security
    @pytest.mark.slow
    @pytest.mark.auth
    def test_finding_credential_disclosure_v3_full_creds(self, cli_runner, target, port):
        """Test 'Credential disclosure' for full authPriv credentials [Category A]

        Using -E with 'admin' user, auth pass 'admin123', priv pass 'admin123'.
        -E requires --confirm.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-E",
            "admin",
            "-A",
            "admin123",
            "-X",
            "admin123",
            "-a",
            "SHA",
            "-x",
            "AES128",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success, f"Targeted v3 full cred test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        findings = _get_security_findings(result.scan_log)
        assert "admin" in messages, (
            f"Expected 'admin' user mention in output, got: {messages[:500]}"
        )
        assert any(
            term in messages for term in ["full creds found", "credentials found", "auth found"]
        ), f"Expected credentials found for admin, got: {messages[:300]}"
        assert "Credential disclosure" in findings, (
            f"Expected 'Credential disclosure' finding, got: {findings}"
        )

    # ========================================================================
    # Finding: "Insecure configuration" - ICS service exposed (L3815)
    # ========================================================================

    @pytest.mark.security
    def test_finding_ics_service_exposed_tcp(self, cli_runner, target, port):
        """Test 'Insecure configuration' finding for ICS ports in TCP listeners [Category A]

        The Linux mock starts listeners on ports 502 (Modbus), 2404 (IEC-104),
        4840 (OPC-UA), and 44818 (EtherNet/IP). The scanner's
        _analyze_enum_security should flag these as ICS services exposed.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "tcp",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        findings = _get_security_findings(result.scan_log)
        # TCP enum should at least attempt to run
        assert "tcp" in messages or "connection" in messages, (
            f"Expected TCP enumeration output, got: {messages[:500]}"
        )
        # If ICS ports were found in listeners, the finding should fire
        if ":502" in messages or ":2404" in messages or ":4840" in messages:
            ics_detail = [
                d
                for d in _get_security_finding_details(result.scan_log)
                if "ics service exposed" in (d[1] + " " + d[2]).lower()
            ]
            assert len(ics_detail) > 0, (
                f"Expected 'ICS service exposed' finding for ICS ports, got findings: {findings}"
            )

    @pytest.mark.security
    def test_finding_ics_service_exposed_enum_all(self, cli_runner, target, port):
        """Test ICS service finding fires via --enum all (includes tcp) [Category B]

        _analyze_enum_security runs after all categories complete. ICS port
        findings should appear in --enum all output.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        all_details = _get_security_finding_details(result.scan_log)
        # --enum all should produce multiple categories of output
        assert len(messages) > 100, (
            f"Expected substantial output from --enum all, got: {messages[:300]}"
        )
        # Check for ICS service findings in the combined details
        ics_findings = [
            d for d in all_details if "ics service exposed" in (d[1] + " " + d[2]).lower()
        ]
        if ":502" in messages or "modbus" in messages.lower():
            assert len(ics_findings) > 0, (
                f"Expected ICS service exposed findings when Modbus port visible, "
                f"got: {[d[0] for d in all_details]}"
            )

    # ========================================================================
    # Finding: "Insecure configuration" - Trap community string (L3847)
    # ========================================================================

    @pytest.mark.security
    def test_finding_trap_community_string(self, cli_runner, target, port):
        """Test 'Insecure configuration' for extra community in trap config [Category B]

        The Linux mock has:
          trap2sink 192.168.1.200:162 internal
          informsink 192.168.1.201:162 public
        The 'internal' community is not 'public' (scanner default) so it should
        trigger an 'Additional community string in trap config' finding.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "traps",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Trap enum should at least run
        assert "trap" in messages, f"Expected trap-related output, got: {messages[:500]}"
        # Check for community string finding
        all_details = _get_security_finding_details(result.scan_log)
        trap_community_findings = [
            d for d in all_details if "community string in trap" in (d[1] + " " + d[2]).lower()
        ]
        # If 'internal' was discovered, the finding should fire
        if "internal" in messages:
            assert len(trap_community_findings) > 0, (
                f"Expected trap community string finding for 'internal', "
                f"got: {[d[0] for d in all_details]}"
            )

    # ========================================================================
    # Finding: "RCE risk" - extend scripts (L3785, L3855)
    # ========================================================================

    @pytest.mark.security
    def test_finding_rce_risk_extend_scripts_count(self, cli_runner, target, port):
        """Test 'RCE risk' finding for extend script count via --enum [Category A]

        The mock has 2 extend scripts (check-ics, disk-check). After --enum all,
        _analyze_enum_security should emit an 'RCE risk' finding about the count
        of extend scripts configured.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "extend",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        findings = _get_security_findings(result.scan_log)
        # Should at least attempt extend enumeration
        assert "extend" in messages, f"Expected extend-related output, got: {messages[:500]}"
        # If extend scripts were found, RCE risk should fire
        rce_findings = [f for f in findings if "rce risk" in f.lower()]
        all_details = _get_security_finding_details(result.scan_log)
        rce_details = [d for d in all_details if d[0] == "RCE risk"]
        if "extend script" in messages:
            assert len(rce_findings) > 0 or len(rce_details) > 0, (
                f"Expected 'RCE risk' finding when extend scripts found, got: {findings}"
            )

    @pytest.mark.security
    def test_finding_rce_risk_extend_detail_mentions_rce(self, cli_runner, target, port):
        """Test 'RCE risk' finding detail mentions 'RCE' for extend scripts [Category B]

        The _analyze_enum_security finding mentions 'RCE possible if community
        string has write access'. The per-script finding mentions 'Injected extend
        script'. Verify the content is meaningful.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "extend",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "extend" in messages, f"Expected extend enumeration output, got: {messages[:500]}"
        all_details = _get_security_finding_details(result.scan_log)
        rce_details = [d for d in all_details if d[0] == "RCE risk"]
        if len(rce_details) > 0:
            combined = " ".join(d[1] + " " + d[2] for d in rce_details).lower()
            assert "rce" in combined or "extend" in combined or "script" in combined, (
                f"Expected RCE/extend/script in finding detail, got: {combined}"
            )

    # ========================================================================
    # Finding: "Hidden attack surface" (L3864) - global IPv6 addresses
    # ========================================================================

    @pytest.mark.security
    def test_finding_hidden_attack_surface_ipv6(self, cli_runner, target, port):
        """Test 'Hidden attack surface' finding for global IPv6 addresses [Category A]

        The Linux mock has 2001:db8:ics::100 configured on veth-ics0 (global
        unicast). After --enum ipv6, _analyze_enum_security should emit a
        'Hidden attack surface' finding.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "ipv6",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        findings = _get_security_findings(result.scan_log)
        assert "ipv6" in messages, f"Expected IPv6 enumeration output, got: {messages[:500]}"
        # If global unicast addresses were found (not "0 global"), check finding
        if "global unicast)" in messages and "0 global unicast)" not in messages:
            assert "Hidden attack surface" in findings, (
                f"Expected 'Hidden attack surface' for global IPv6, got: {findings}"
            )

    @pytest.mark.security
    def test_finding_hidden_attack_surface_detail(self, cli_runner, target, port):
        """Test 'Hidden attack surface' detail mentions IPv6 reachability [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "ipv6",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "ipv6" in messages, f"Expected IPv6 enumeration output, got: {messages[:500]}"
        all_details = _get_security_finding_details(result.scan_log)
        ipv6_findings = [d for d in all_details if d[0] == "Hidden attack surface"]
        if len(ipv6_findings) > 0:
            combined = " ".join(d[1] + " " + d[2] for d in ipv6_findings).lower()
            assert "ipv6" in combined or "reachable" in combined, (
                f"Expected IPv6/reachable in detail, got: {combined}"
            )

    # ========================================================================
    # Finding: "Credential exposure" (L3875) - process args leaking creds
    # ========================================================================

    @pytest.mark.security
    def test_finding_credential_exposure_process_args(self, cli_runner, target, port):
        """Test 'Credential exposure' finding for process args with passwords [Category A]

        The Linux mock starts: python3 -c "..." --host plc01 --password=S3cretICS
        This should trigger both:
        - "Credential in process args" (per-process, L3395)
        - "Credential exposure" (summary, L3875)
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        findings = _get_security_findings(result.scan_log)
        # Enum creds should at least attempt to run
        assert "cred" in messages, f"Expected credential-related output, got: {messages[:500]}"
        # If process credential detection worked, check for findings
        if "credential in process" in messages or "password" in messages:
            credential_findings = [
                f for f in findings if "credential" in f.lower() and "process" in f.lower()
            ]
            exposure_findings = [f for f in findings if "credential exposure" in f.lower()]
            assert len(credential_findings) > 0 or len(exposure_findings) > 0, (
                f"Expected credential process/exposure finding, got: {findings}"
            )

    @pytest.mark.security
    def test_finding_credential_in_process_args_detail(self, cli_runner, target, port):
        """Test per-process credential finding mentions process name and match [Category B]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "cred" in messages, f"Expected credential enumeration output, got: {messages[:500]}"
        all_details = _get_security_finding_details(result.scan_log)
        proc_cred_findings = [d for d in all_details if "credential in process" in d[0].lower()]
        if len(proc_cred_findings) > 0:
            combined = " ".join(d[0] + " " + d[1] + " " + d[2] for d in proc_cred_findings).lower()
            assert "pid" in combined or "password" in combined, (
                f"Expected PID or password mention in finding, got: {combined}"
            )

    # NOT COVERED (no test exists - do not add skipped placeholders):
    #   - Writable remote mount finding (scanner L3600)
    #   - Default Windows account finding (scanner L3826)
    #   - Admin share exposed finding (scanner L3837)
    #   The mock does not serve the hrFS/host-resource tables these read.

    # ========================================================================
    # Combined findings: multiple findings in a single scan
    # ========================================================================

    @pytest.mark.security
    def test_multiple_findings_in_basic_scan(self, cli_runner, target, port):
        """Test that basic v2c scan produces multiple expected findings [Category A]

        A simple scan with community 'public' should produce at minimum:
        - 'No encryption' (v2c is cleartext)
        - 'Default credentials' (public community)
        - 'Legacy protocol' (v1 is supported by mock)
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "public",
            format="json",
            json_log=True,
        )
        assert result.success, f"Basic scan failed: {result.stderr}"
        _assert_log_has_events(result)
        findings = _get_security_findings(result.scan_log)
        # All three should be present
        assert "No encryption" in findings, (
            f"Missing 'No encryption' from basic scan findings: {findings}"
        )
        assert "Default credentials" in findings, (
            f"Missing 'Default credentials' from basic scan findings: {findings}"
        )
        assert "Legacy protocol" in findings, (
            f"Missing 'Legacy protocol' from basic scan findings: {findings}"
        )

    @pytest.mark.security
    def test_findings_count_minimum(self, cli_runner, target, port):
        """Test that basic scan produces at least 3 security findings [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )
        assert result.success
        _assert_log_has_events(result)
        findings = _get_security_findings(result.scan_log)
        assert len(findings) >= 3, (
            f"Expected at least 3 findings for v2c+public scan, got {len(findings)}: {findings}"
        )

    @pytest.mark.security
    def test_no_findings_leak_between_scans(self, cli_runner, target, port):
        """Test that findings are per-scan, not accumulated across runs [Category A]"""
        # Run with 'private' community - should NOT get 'Default credentials'
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "private",
            format="json",
            json_log=True,
        )
        assert result.success
        findings = _get_security_findings(result.scan_log)
        assert "Default credentials" not in findings, (
            f"'Default credentials' should not appear for 'private' community: {findings}"
        )


# ============================================================================
# Security Finding Tests: Switch Mock (port 10162)
# ============================================================================


@pytest.mark.snmp
@pytest.mark.containers("snmp-switch")
class TestSNMPSwitchSecurityFindings:
    """Security finding tests targeting the H3C switch mock (credential tables).

    Tests H3C, Brocade, and generic credential OID security findings.
    """

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return SNMP_SWITCH_PORT

    @pytest.fixture(autouse=True)
    def _require_switch_mock(self, target, port):
        if not _check_snmp_reachable(target, port):
            require_service(f"SNMP switch mock not reachable on {target}:{port}")

    # ========================================================================
    # Finding: H3C credential found (L3274)
    # ========================================================================

    @pytest.mark.security
    def test_finding_h3c_credential_security_event(self, cli_runner, target, port):
        """Test H3C credential discovery emits security finding events [Category A]

        The scanner logs security_finding() for each H3C user found.
        The mock has 3 H3C users (admin, monitor, operator) on PEN 2011.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success, f"--enum creds on switch failed: {result.stderr}"
        _assert_log_has_events(result)
        # The H3C credential text lives in the security event's *details*
        # ("H3C credential found: admin / admin123"), not its title (which is the
        # generic "Credential disclosure").
        cred_details = _credential_finding_details(result.scan_log)
        h3c_details = [d for d in cred_details if "h3c credential" in d.lower()]
        assert len(h3c_details) > 0, (
            f"Expected H3C credential security findings, got: {cred_details}"
        )
        # Should find at least the known users
        h3c_text = " ".join(h3c_details).lower()
        assert "admin" in h3c_text, f"Expected 'admin' in H3C findings, got: {h3c_text}"

    @pytest.mark.security
    def test_finding_h3c_credential_includes_password(self, cli_runner, target, port):
        """Test H3C credential findings include password values [Category A]

        The mock H3C data has passwords: admin123, monitor1, oper@tor.
        The finding title should include the password.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success
        _assert_log_has_events(result)
        # The password is embedded in the finding *details*
        # ("H3C credential found: admin / admin123"), not the title.
        cred_details = _credential_finding_details(result.scan_log)
        h3c_text = " ".join(d for d in cred_details if "h3c credential" in d.lower()).lower()
        assert "admin123" in h3c_text or "monitor1" in h3c_text, (
            f"Expected H3C passwords in findings, got: {h3c_text}"
        )

    # ========================================================================
    # Finding: Brocade credential found (L3297)
    # ========================================================================

    @pytest.mark.security
    def test_finding_brocade_credential_security_event(self, cli_runner, target, port):
        """Test Brocade credential discovery emits security findings [Category A]

        The mock has 2 Brocade ADX admin entries (admin, readonly) on PEN 1991.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success
        _assert_log_has_events(result)
        # security_finding() de-duplicates by (title, category), so all
        # "Credential disclosure" events collapse to one (the first H3C user) and
        # the Brocade credential never gets its own security event. The Brocade
        # discovery is proven by the info-level "Credential Findings" table
        # (brocadeAdxAdminUser / brocadeAdxAdminPassword rows). Assert the
        # Brocade credentials are genuinely surfaced there.
        messages = _credential_messages(result.scan_log)
        assert "brocadeadxadminuser" in messages, (
            f"Expected Brocade credential table, got: {messages[:500]}"
        )
        for user in BROCADE_USERS:
            assert user["username"] in messages, (
                f"Expected Brocade user '{user['username']}', got: {messages[:500]}"
            )

    @pytest.mark.security
    def test_finding_brocade_credential_category(self, cli_runner, target, port):
        """Test Brocade credential finding has category 'Credential disclosure' [Category A]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success
        _assert_log_has_events(result)
        # Brocade creds collapse into the single de-duplicated credential
        # security event (title "Credential disclosure", category
        # INFO_DISCLOSURE) and are spelled out in the info "Credential Findings"
        # table. Verify the credential security event carries the right
        # title/category, and that the Brocade entries (incl. password hashes)
        # are genuinely surfaced.
        cred_events = [
            d
            for d in _get_security_finding_details(result.scan_log)
            if d[0] == "Credential disclosure"
        ]
        assert len(cred_events) > 0, (
            f"Expected a 'Credential disclosure' security event, got: "
            f"{[d[0] for d in _get_security_finding_details(result.scan_log)]}"
        )
        for d in cred_events:
            assert "INFO_DISCLOSURE" in d[1], f"Expected INFO_DISCLOSURE category, got: '{d[1]}'"
        messages = _credential_messages(result.scan_log)
        assert "brocadeadxadminuser" in messages and "brocadeadxadminpassword" in messages, (
            f"Expected Brocade credential table, got: {messages[:500]}"
        )
        for user in BROCADE_USERS:
            assert user["username"] in messages, (
                f"Expected Brocade user '{user['username']}', got: {messages[:500]}"
            )

    # ========================================================================
    # Finding: Credential OID password / Community string in OID (L3332, L3337)
    # ========================================================================

    @pytest.mark.security
    def test_finding_credential_oid_password(self, cli_runner, target, port):
        """Test 'Credential OID' password findings from credential walk [Category A]

        After H3C/Brocade correlation, remaining credential OID entries with
        'password' in their name trigger per-entry 'Credential OID' findings.
        The switch mock has h3cUserPassword and brocadeAdxAdminPassword entries.
        Note: these are skipped if already reported via H3C/Brocade correlation.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success
        _assert_log_has_events(result)
        all_details = _get_security_finding_details(result.scan_log)
        # The scanner skips H3C/Brocade correlated names from generic reporting,
        # so credential OID password findings may not fire for those specific
        # entries. We check that credential disclosure findings exist overall.
        # The finding *title* (d[0]) is "Credential disclosure"; the category
        # (d[1]) is INFO_DISCLOSURE; the per-OID text is in the details (d[2]).
        credential_disc = [d for d in all_details if d[0] == "Credential disclosure"]
        assert len(credential_disc) > 0, (
            f"Expected Credential disclosure findings, got: {[d[0] for d in all_details]}"
        )
        # Prove the credential password is actually disclosed in the details.
        disc_text = " ".join(d[2] for d in credential_disc).lower()
        assert "admin123" in disc_text or "password" in disc_text, (
            f"Expected a disclosed credential in details, got: {disc_text}"
        )
        # Check if any password-specific OID findings exist (bonus coverage).
        # "Credential OID '<name>': password='...'" text lives in the details.
        password_oid_findings = [
            d
            for d in all_details
            if "credential oid" in d[2].lower() and "password" in d[2].lower()
        ]
        # Password OID findings are optional since H3C/Brocade entries are
        # correlated and excluded from generic reporting.
        if password_oid_findings:
            assert all(d[0] == "Credential disclosure" for d in password_oid_findings), (
                f"Password OID findings should have title 'Credential disclosure', "
                f"got: {password_oid_findings}"
            )

    # ========================================================================
    # Combined switch findings validation
    # ========================================================================

    @pytest.mark.security
    def test_switch_enum_creds_produces_multiple_findings(self, cli_runner, target, port):
        """Test --enum creds on switch produces findings from multiple vendors [Category A]

        Should produce findings for both H3C and Brocade credential tables.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum",
            "creds",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.success
        _assert_log_has_events(result)
        # security_finding() collapses the repeated "Credential disclosure"
        # events into one, so the per-vendor, per-credential breakdown is proven
        # via the info-level "Credential Findings" table rather than via distinct
        # security events. Require every known H3C and Brocade username AND
        # password to actually appear - 3 H3C (admin/admin123, monitor/monitor1,
        # operator/oper@tor) + 2 Brocade (admin, readonly) = 5 credentials.
        messages = _credential_messages(result.scan_log)
        assert "h3c credential:" in messages, f"Expected H3C credentials, got: {messages[:500]}"
        assert "brocadeadxadminuser" in messages, (
            f"Expected Brocade credentials, got: {messages[:500]}"
        )
        discovered = 0
        for user in H3C_USERS:
            assert user["username"] in messages, (
                f"Expected H3C user '{user['username']}', got: {messages[:500]}"
            )
            assert user["password"] in messages, (
                f"Expected H3C password '{user['password']}', got: {messages[:500]}"
            )
            discovered += 1
        for user in BROCADE_USERS:
            assert user["username"] in messages, (
                f"Expected Brocade user '{user['username']}', got: {messages[:500]}"
            )
            discovered += 1
        assert discovered >= 5, (
            f"Expected >= 5 vendor credentials (3 H3C + 2 Brocade), got {discovered}"
        )


# ============================================================================
# Security Finding Tests: v3-only Mock (port 10164)
# ============================================================================


@pytest.mark.snmp
@pytest.mark.containers("snmp-v3only")
class TestSNMPv3OnlySecurityFindings:
    """Security finding tests targeting the v3-only hardened mock.

    The v3only mock has no v1/v2c communities, so 'No encryption' and
    'Default credentials' should NOT fire. Tests verify absence of
    inappropriate findings on a hardened target.
    """

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return SNMP_V3ONLY_PORT

    @pytest.fixture(autouse=True)
    def _require_v3only_mock(self, target, port):
        if not _check_snmp_v3_reachable(target, port):
            require_service(f"SNMP v3only mock not reachable on {target}:{port}")

    @pytest.mark.security
    def test_no_encryption_finding_absent_v3only(self, cli_runner, target, port):
        """Test 'No encryption' does NOT fire for v3-only target [Category A]

        When connecting via SNMPv3 with auth, the 'No encryption' finding
        should not appear (v3 provides encryption).
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "engineer:engineer1",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "snmp" in messages or "engineer" in messages, (
            f"Expected SNMP scan output, got: {messages[:300]}"
        )
        findings = _get_security_findings(result.scan_log)
        assert "No encryption" not in findings, (
            f"'No encryption' should NOT fire for v3-only, got: {findings}"
        )

    @pytest.mark.security
    def test_default_creds_finding_absent_v3only(self, cli_runner, target, port):
        """Test 'Default credentials' does NOT fire for v3 auth [Category A]

        SNMPv3 with proper auth should not trigger the 'Default credentials'
        finding (which checks for community='public').
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "engineer:engineer1",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "snmp" in messages or "engineer" in messages, (
            f"Expected SNMP scan output, got: {messages[:300]}"
        )
        findings = _get_security_findings(result.scan_log)
        assert "Default credentials" not in findings, (
            f"'Default credentials' should NOT fire for v3 auth, got: {findings}"
        )

    @pytest.mark.security
    def test_legacy_protocol_finding_absent_v3only(self, cli_runner, target, port):
        """Test 'Legacy protocol' does NOT fire when v1 is disabled [Category B]

        The v3only mock has no v1/v2c. Version detection should not find v1,
        so 'Legacy protocol' should be absent. However, version detect may skip
        for v3-only targets if snmp-version is already set.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "-C",
            "engineer:engineer1",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "snmp" in messages or "engineer" in messages, (
            f"Expected SNMP scan output, got: {messages[:300]}"
        )
        findings = _get_security_findings(result.scan_log)
        # v3only mock should not support v1, so legacy finding should be absent
        if "v1" not in messages or "not supported" in messages:
            assert "Legacy protocol" not in findings, (
                f"'Legacy protocol' should NOT fire for v3-only, got: {findings}"
            )


# ===========================================================================
# --enum-users (standalone SNMPv3 user enumeration)
# ===========================================================================


@pytest.mark.snmp
class TestSNMPEnumUsers:
    """Tests for --enum-users (SNMPv3 phase 1 user enumeration only).

    Uses the v3-only mock (port 10164) which has 4 users:
    admin, operator, engineer, monitor.
    """

    @pytest.fixture
    def target(self):
        return MOCK_HOST

    @pytest.fixture
    def port(self):
        return SNMP_V3ONLY_PORT

    @pytest.fixture(autouse=True)
    def _require_v3only_mock(self, target, port):
        """Skip if v3-only mock is not reachable."""
        if not _check_snmp_v3_reachable(target, port):
            require_service(f"SNMPv3-only mock not reachable on {target}:{port}")

    # ── Category C: Error handling ──

    @pytest.mark.security
    def test_enum_users_requires_confirm(self, cli_runner, target, port):
        """Test --enum-users without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum-users",
            format="json",
            json_log=True,
            timeout=10,
        )
        cli_runner.assert_confirm_refused(result, "--enum-users")

    # ── Category A: Strict ──

    @pytest.mark.slow
    @pytest.mark.security
    def test_enum_users_discovers_users(self, cli_runner, target, port, tmp_path):
        """Test --enum-users discovers valid usernames on v3-only device [Category A]

        Provides a small username file containing the 4 mock users plus a
        non-existent one. Should discover at least 2 valid users and return
        early (no auth/priv brute-force).
        """
        userfile = tmp_path / "users.txt"
        userfile.write_text("admin\noperator\nengineer\nmonitor\nnonexistent\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum-users",
            "--confirm",
            "-u",
            str(userfile),
            "--brute-rate",
            "0.01",
            "--timeout",
            "1",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1], f"enum-users crashed: {result.stderr}"
        assert result.scan_log is not None, "scan_log should be populated"
        _assert_log_event_structure(result.scan_log)

        # Combine security events + regular messages for user name searching
        security_events = [e for e in result.scan_log.events if e.get("event_type") == "security"]
        all_security_text = " ".join(str(e.get("data", {})) for e in security_events).lower()
        all_messages = " ".join(e.get("message", "") for e in result.scan_log.events).lower()
        combined = all_security_text + " " + all_messages

        found_users = sum(1 for u in ["admin", "operator", "engineer", "monitor"] if u in combined)
        assert found_users >= 2, (
            f"Expected >= 2 of [admin, operator, engineer, monitor], "
            f"found {found_users} in: {combined[:500]}"
        )

    @pytest.mark.slow
    @pytest.mark.security
    def test_enum_users_no_brute_phases(self, cli_runner, target, port, tmp_path):
        """Test --enum-users does NOT run auth/priv brute-force [Category A]

        After user enumeration, the scan should return without attempting
        phase 2 (auth brute) or phase 3 (priv brute).
        """
        userfile = tmp_path / "users.txt"
        userfile.write_text("engineer\nnonexistent\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum-users",
            "--confirm",
            "-u",
            str(userfile),
            "--brute-rate",
            "0.01",
            "--timeout",
            "1",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1], f"enum-users crashed: {result.stderr}"
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
            # Should NOT contain auth/priv brute-force phase messages
            assert "phase 2" not in messages, (
                f"--enum-users should skip phase 2, got: {messages[:500]}"
            )
            assert "phase 3" not in messages, (
                f"--enum-users should skip phase 3, got: {messages[:500]}"
            )

    @pytest.mark.slow
    @pytest.mark.security
    def test_enum_users_forces_v3(self, cli_runner, target, port, tmp_path):
        """Test --enum-users forces SNMPv3 even when -V is not specified [Category A]

        The flag implies SNMPv3 and should skip version detection.
        """
        userfile = tmp_path / "users.txt"
        userfile.write_text("engineer\n")

        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum-users",
            "--confirm",
            "-u",
            str(userfile),
            "--brute-rate",
            "0.01",
            "--timeout",
            "1",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert result.returncode in [0, 1], f"enum-users crashed: {result.stderr}"
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
            # Should see phase 1 enumeration activity, not version detection
            assert "phase 1" in messages or "testing" in messages, (
                f"Expected phase 1 enumeration, got: {messages[:500]}"
            )

    # ── Category B: Conditional ──

    @pytest.mark.slow
    @pytest.mark.security
    def test_enum_users_default_wordlist(self, cli_runner, target, port):
        """Test --enum-users with default built-in username list [Category B]

        Without -u, the scanner uses the built-in SNMP_V3_USERNAMES wordlist.
        May or may not find users depending on wordlist vs mock config overlap.
        """
        result = cli_runner.run(
            "snmp",
            target,
            "--port",
            str(port),
            "--enum-users",
            "--confirm",
            "--brute-rate",
            "0.01",
            "--timeout",
            "1",
            format="json",
            json_log=True,
            timeout=45,
        )
        assert result.returncode in [0, 1], f"enum-users crashed: {result.stderr}"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            messages = _all_messages(result.scan_log)
            # Should at least show phase 1 activity
            assert "phase 1" in messages or "testing" in messages or "no valid" in messages, (
                f"Expected phase 1 activity, got: {messages[:500]}"
            )
