"""Integration tests for SNMP passive listener in EK mode.

Tests cover:
- Community string extraction (v1/v2c)
- SNMPv3 username extraction
- T1 field coverage: request_id, error_index, variable_bindings,
  msgID, msgSecurityModel, msgAuthoritativeEngineBoots,
  msgAuthoritativeEngineTime, msgAuthenticationParameters,
  contextEngineID, contextName
- SET operation detection
- Trap field extraction
- Harvest table output quality
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestSNMPPassiveEK:
    """SNMP-specific tests beyond the parametrized quality suite."""

    def test_snmp_community_extraction(self):
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv1_get.pcap",
            expect_details=["community"],
        )
        # SNMP should extract community strings as credentials
        assert len(listener.credentials) >= 1, (
            f"Expected >= 1 SNMP credential, got {len(listener.credentials)}"
        )

        # Check that at least one credential has a community string
        communities = [c.community_or_username for c in listener.credentials]
        assert any(communities), "No community strings extracted"

        # SNMP has no custom harvest tables (interaction/credential tables
        # are now built centrally by the scanner)

    # ------------------------------------------------------------------
    # T1 field coverage: request_id
    # ------------------------------------------------------------------

    def test_request_id_v1(self):
        """request_id is extracted from SNMPv1 GET packets."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv1_get.pcap",
            expect_details=["request_id"],
        )
        # Verify at least one interaction has a non-empty request_id
        has_req_id = any(
            ix.details.get("request_id") not in (None, "") for ix in listener.interactions
        )
        assert has_req_id, (
            "No interaction has a truthy request_id; "
            f"sample details: {listener.interactions[0].details}"
        )

    def test_request_id_v3(self):
        """request_id is extracted from SNMPv3 packets (when PDU is not encrypted)."""
        # credslayer_snmp_v3.pcap uses 127.0.0.1 -> no devices created
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/credslayer_snmp_v3.pcap",
            min_devices=0,
            expect_details=["request_id"],
        )
        # Some v3 packets have encrypted PDUs so request_id may be empty;
        # but the first discovery exchange (unencrypted) should have it.
        has_req_id = any(
            ix.details.get("request_id") not in (None, "") for ix in listener.interactions
        )
        assert has_req_id, "No v3 interaction has request_id"

    # ------------------------------------------------------------------
    # T1 field coverage: error_index
    # ------------------------------------------------------------------

    def test_error_index_extracted(self):
        """error_index is extracted alongside error_status."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv1_get.pcap",
            expect_details=["error_index"],
        )
        # Every non-trap packet should have error_index (usually "0")
        has_err_idx = any(ix.details.get("error_index") is not None for ix in listener.interactions)
        assert has_err_idx, "No interaction has error_index in details"

    # ------------------------------------------------------------------
    # T1 field coverage: variable_bindings
    # ------------------------------------------------------------------

    def test_variable_bindings_count(self):
        """variable_bindings count is extracted from PDU."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv1_get.pcap",
            expect_details=["variable_bindings"],
        )
        # At least one interaction should have a varbind count
        has_vb = any(
            ix.details.get("variable_bindings") not in (None, "") for ix in listener.interactions
        )
        assert has_vb, "No interaction has variable_bindings count"

    # ------------------------------------------------------------------
    # T1 field coverage: SNMPv3 msgID
    # ------------------------------------------------------------------

    def test_v3_msg_id(self):
        """msgID is extracted from SNMPv3 message header."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/credslayer_snmp_v3.pcap",
            min_devices=0,
        )
        has_msg_id = any(ix.details.get("msg_id") not in (None, "") for ix in listener.interactions)
        assert has_msg_id, (
            "No v3 interaction has msg_id; "
            f"sample: {listener.interactions[0].details if listener.interactions else 'none'}"
        )

    # ------------------------------------------------------------------
    # T1 field coverage: SNMPv3 msgSecurityModel
    # ------------------------------------------------------------------

    def test_v3_security_model(self):
        """msgSecurityModel is extracted and resolved to human-readable name."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/credslayer_snmp_v3.pcap",
            min_devices=0,
        )
        has_sec_model = any(
            ix.details.get("security_model") not in (None, "") for ix in listener.interactions
        )
        assert has_sec_model, "No v3 interaction has security_model"
        # Should be resolved to "USM" for SNMPv3
        usm_found = any(ix.details.get("security_model") == "USM" for ix in listener.interactions)
        assert usm_found, (
            "Expected security_model='USM' in at least one interaction; "
            f"got: {[ix.details.get('security_model') for ix in listener.interactions[:5]]}"
        )

    # ------------------------------------------------------------------
    # T1 field coverage: SNMPv3 msgAuthoritativeEngineBoots
    # ------------------------------------------------------------------

    def test_v3_engine_boots(self):
        """msgAuthoritativeEngineBoots is extracted for replay protection analysis."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/credslayer_snmp_v3.pcap",
            min_devices=0,
        )
        has_boots = any(
            ix.details.get("engine_boots") not in (None, "") for ix in listener.interactions
        )
        assert has_boots, "No v3 interaction has engine_boots"

    # ------------------------------------------------------------------
    # T1 field coverage: SNMPv3 msgAuthoritativeEngineTime
    # ------------------------------------------------------------------

    def test_v3_engine_time(self):
        """msgAuthoritativeEngineTime is extracted for replay protection analysis."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/credslayer_snmp_v3.pcap",
            min_devices=0,
        )
        has_time = any(
            ix.details.get("engine_time") not in (None, "") for ix in listener.interactions
        )
        assert has_time, "No v3 interaction has engine_time"

    # ------------------------------------------------------------------
    # T1 field coverage: SNMPv3 msgAuthenticationParameters
    # ------------------------------------------------------------------

    def test_v3_auth_params(self):
        """msgAuthenticationParameters (HMAC) is extracted when present."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/credslayer_snmp_v3.pcap",
            min_devices=0,
        )
        # Not all v3 packets have auth params (discovery phase is noAuth),
        # but the authenticated packets should have the HMAC bytes.
        has_auth = any(
            ix.details.get("auth_params") not in (None, "") for ix in listener.interactions
        )
        assert has_auth, (
            "No v3 interaction has auth_params; expected HMAC bytes in authenticated packets"
        )

    # ------------------------------------------------------------------
    # T1 field coverage: SNMPv3 contextEngineID
    # ------------------------------------------------------------------

    def test_v3_context_engine_id(self):
        """contextEngineID is extracted from SNMPv3 scoped PDU."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/credslayer_snmp_v3.pcap",
            min_devices=0,
        )
        has_ctx = any(
            ix.details.get("context_engine_id") not in (None, "") for ix in listener.interactions
        )
        assert has_ctx, "No v3 interaction has context_engine_id"

    # ------------------------------------------------------------------
    # T1 field coverage: SNMPv3 contextName
    # ------------------------------------------------------------------

    def test_v3_context_name(self):
        """contextName is extracted from SNMPv3 scoped PDU.

        contextName may be empty string (default context), which is valid.
        We verify the field exists in details (not that it's non-empty).
        """
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/credslayer_snmp_v3.pcap",
            min_devices=0,
        )
        has_ctx_name = any(
            "context_name" in ix.details
            for ix in listener.interactions
            if ix.details.get("version") == "v3"
        )
        assert has_ctx_name, "No v3 interaction has context_name key in details"

    # ------------------------------------------------------------------
    # SET operation detection
    # ------------------------------------------------------------------

    def test_set_operation_detected(self):
        """SET operations are detected and flagged in interactions."""
        # zeek_snmpv1_set.pcap uses 127.0.0.1 -> no devices created
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv1_set.pcap",
            min_devices=0,
            expect_operations=["SET"],
        )
        # At least one interaction should be a SET
        set_interactions = [
            ix for ix in listener.interactions if ix.details.get("operation") == "SET"
        ]
        assert len(set_interactions) >= 1, (
            f"Expected SET operations in zeek_snmpv1_set.pcap; "
            f"ops seen: {[ix.details.get('operation') for ix in listener.interactions[:10]]}"
        )

    # ------------------------------------------------------------------
    # Trap fields
    # ------------------------------------------------------------------

    def test_trap_fields_extracted(self):
        """Trap-specific fields (enterprise, agent_addr, generic/specific trap) are extracted."""
        # zeek_snmpv1_trap.pcap uses 127.0.0.1 -> no devices
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv1_trap.pcap",
            min_devices=0,
            min_interactions=1,
        )
        trap_ixs = [ix for ix in listener.interactions if "TRAP" in ix.details.get("operation", "")]
        assert len(trap_ixs) >= 1, "No TRAP interactions found"
        # At least one trap should have enterprise OID
        has_enterprise = any(ix.details.get("trap_enterprise") not in (None, "") for ix in trap_ixs)
        assert has_enterprise, "No trap has trap_enterprise field"

    # ------------------------------------------------------------------
    # GET-BULK operations
    # ------------------------------------------------------------------

    def test_get_bulk_operation(self):
        """GET-BULK operations are detected in v2c traffic."""
        # zeek_snmpv2_get_bulk.pcap uses 127.0.0.1 -> no devices
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv2_get_bulk.pcap",
            min_devices=0,
            expect_operations=["GET-BULK"],
            min_interactions=1,
        )
        bulk_ixs = [ix for ix in listener.interactions if ix.details.get("operation") == "GET-BULK"]
        assert len(bulk_ixs) >= 1, "No GET-BULK interactions found"

    # ------------------------------------------------------------------
    # Harvest quality checks
    # ------------------------------------------------------------------

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict (no custom tables for SNMP)."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv1_get.pcap",
        )
        assert isinstance(result, dict)

    def test_v3_credentials_extracted(self):
        """SNMPv3 username extraction produces credentials."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/credslayer_snmp_v3.pcap",
            min_devices=0,
        )
        # credslayer_snmp_v3 has username "pippo"
        cred_summaries = listener.get_credentials_summary()
        usernames = [c.get("username", "") for c in cred_summaries]
        assert "pippo" in usernames, (
            f"Expected username 'pippo' in v3 credentials; got: {usernames}"
        )

    # ------------------------------------------------------------------
    # SNMPv3 security level analysis
    # ------------------------------------------------------------------

    def test_v3_security_level_noauth(self):
        """Discovery packets show noAuth security level."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/credslayer_snmp_v3.pcap",
            min_devices=0,
        )
        # The first v3 discovery packet should be noAuth
        noauth_found = any(
            ix.details.get("v3_security") == "noAuth" for ix in listener.interactions
        )
        assert noauth_found, "No v3 interaction with noAuth security level found"

    def test_v3_security_level_auth_priv(self):
        """Encrypted v3 packets show auth+priv security level."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/credslayer_snmp_v3.pcap",
            min_devices=0,
        )
        authpriv_found = any(
            ix.details.get("v3_security") == "auth+priv" for ix in listener.interactions
        )
        assert authpriv_found, (
            "No v3 interaction with auth+priv security level; "
            f"levels seen: {set(ix.details.get('v3_security', '') for ix in listener.interactions)}"
        )

    # ------------------------------------------------------------------
    # Cross-version: SNMPv2c
    # ------------------------------------------------------------------

    def test_snmpv2c_get_next(self):
        """SNMPv2c GET-NEXT operations are correctly detected."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv2_get_next.pcap",
            expect_operations=["GET-NEXT"],
        )
        v2c_ixs = [ix for ix in listener.interactions if ix.details.get("version") == "v2c"]
        assert len(v2c_ixs) >= 1, "No v2c interactions found"

    # ------------------------------------------------------------------
    # Error status mapping
    # ------------------------------------------------------------------

    def test_error_status_zero_no_error_name(self):
        """When error_status is 0, no error_name key is set (no error)."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv1_get.pcap",
        )
        # Normal GET/RESPONSE with status=0 should not have error_name
        normal_ixs = [ix for ix in listener.interactions if ix.details.get("error_status") == "0"]
        assert len(normal_ixs) >= 1, "Expected at least one interaction with error_status=0"
        for ix in normal_ixs:
            assert "error_name" not in ix.details, (
                f"error_name should not be set when error_status=0; "
                f"got: {ix.details.get('error_name')}"
            )

    # ------------------------------------------------------------------
    # Device tracking
    # ------------------------------------------------------------------

    def test_both_endpoints_tracked(self):
        """Both SNMP manager (client) and agent (server) devices are created."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv1_get.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_manager = any("Manager" in t for t in device_types)
        has_agent = any("Agent" in t for t in device_types)
        assert has_manager, f"No SNMP Manager device found; types: {device_types}"
        assert has_agent, f"No SNMP Agent device found; types: {device_types}"

    # ------------------------------------------------------------------
    # SNMPv3 get_next with real IPs (zeek_snmpv3_get_next.pcap)
    # ------------------------------------------------------------------

    def test_v3_get_next_full_fields(self):
        """SNMPv3 GET-NEXT with real IPs extracts all v3 fields and creates devices."""
        listener, devices, result = _run_listener_test(
            "snmp",
            "SNMPPassiveListener",
            "snmp",
            "snmp/zeek_snmpv3_get_next.pcap",
            min_devices=0,
            min_interactions=1,
        )
        # Verify v3 fields are extracted
        v3_ixs = [ix for ix in listener.interactions if ix.details.get("version") == "v3"]
        assert len(v3_ixs) >= 1, "No v3 interactions found in zeek_snmpv3_get_next.pcap"
        # At least one should have engine_boots and security_model
        has_v3_fields = any(
            ix.details.get("engine_boots") not in (None, "")
            and ix.details.get("security_model") not in (None, "")
            for ix in v3_ixs
        )
        assert has_v3_fields, "v3 interactions missing engine_boots or security_model"
