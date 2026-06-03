"""
OPC UA Protocol Fuzzer -- Audit Validation Tests

These tests enforce coverage invariants discovered during the deep audit
of the OPC UA fuzzer (2026-02-15). They codify the current baseline and
flag regressions.

Audit report: tasks/opcua_fuzzer_deep_audit.md
"""

import pytest

pytestmark = pytest.mark.core


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_opcua_request_definitions():
    """Get OPC UA request definitions without instantiation."""
    from oida.fuzz.protocols.opcua import OPCUAFuzzer

    return OPCUAFuzzer.get_request_definitions()


def _get_opcua_constants():
    """Get OPC UA service ID constants."""
    from oida.fuzz.protocols.opcua_constants import OPCUAServiceIds

    return OPCUAServiceIds


# ---------------------------------------------------------------------------
# 1. Request Count and Tier Compliance
# ---------------------------------------------------------------------------


class TestOPCUARequestCount:
    """Verify OPC UA fuzzer meets P0 tier minimum request count."""

    def test_minimum_request_count(self):
        """OPC UA is P0 tier: requires >= 8 request definitions."""
        defs = _get_opcua_request_definitions()
        assert len(defs) >= 8, (
            f"OPC UA P0 fuzzer has {len(defs)} requests, minimum is 8 for P0 tier"
        )

    def test_actual_request_count_baseline(self):
        """Baseline: OPC UA should have >= 21 request definitions.

        Baseline was 22 until 2026-05-26 when the phantom OPCUA_Query
        RequestInfo entry (advertised but never implemented) was removed.
        """
        defs = _get_opcua_request_definitions()
        assert len(defs) >= 21, f"OPC UA request count regression: expected >= 21, got {len(defs)}"


# ---------------------------------------------------------------------------
# 2. Category Coverage
# ---------------------------------------------------------------------------


class TestOPCUACategoryCoverage:
    """Verify all required categories have at least one request."""

    REQUIRED_CATEGORIES = {
        "baseline",
        "discovery",
        "channel",
        "session",
        "auth",
        "read",
        "write",
        "subscription",
        "attack",
    }

    def test_all_required_categories_present(self):
        """Every required category must have at least one request."""
        defs = _get_opcua_request_definitions()
        found_categories = {d.category for d in defs}
        missing = self.REQUIRED_CATEGORIES - found_categories
        assert not missing, (
            f"OPC UA missing request categories: {missing}. "
            f"Found categories: {sorted(found_categories)}"
        )

    @pytest.mark.parametrize("category", REQUIRED_CATEGORIES)
    def test_category_has_requests(self, category):
        """Each required category must have >= 1 request."""
        defs = _get_opcua_request_definitions()
        count = sum(1 for d in defs if d.category == category)
        assert count >= 1, f"OPC UA category '{category}' has {count} requests, needs >= 1"

    def test_read_category_minimum(self):
        """Read category should have >= 3 requests (Read, Browse, Query, History)."""
        defs = _get_opcua_request_definitions()
        count = sum(1 for d in defs if d.category == "read")
        assert count >= 3, f"OPC UA 'read' category has {count} requests, needs >= 3"

    def test_attack_category_minimum(self):
        """Attack category should have >= 4 requests."""
        defs = _get_opcua_request_definitions()
        count = sum(1 for d in defs if d.category == "attack")
        assert count >= 4, f"OPC UA 'attack' category has {count} requests, needs >= 4"


# ---------------------------------------------------------------------------
# 3. State Requirements
# ---------------------------------------------------------------------------


class TestOPCUAStateRequirements:
    """Verify state requirements are consistent and valid."""

    VALID_STATES = {
        "CONNECTED",
        "HELLO_COMPLETE",
        "SECURE_CHANNEL",
        "SESSION_ACTIVE",
    }

    def test_all_requests_have_state_requirement(self):
        """Every request must specify a requires_state."""
        defs = _get_opcua_request_definitions()
        for d in defs:
            assert d.requires_state is not None, f"Request '{d.name}' has no requires_state"

    def test_state_values_are_valid(self):
        """All requires_state values must be valid state names or ANY."""
        from oida.fuzz.core.base_fuzzer import CommonState

        defs = _get_opcua_request_definitions()
        for d in defs:
            state = d.requires_state
            if isinstance(state, CommonState):
                continue  # CommonState.ANY is always valid
            if isinstance(state, str):
                assert state in self.VALID_STATES, (
                    f"Request '{d.name}' references unknown state '{state}'. "
                    f"Valid states: {self.VALID_STATES}"
                )
            elif isinstance(state, list):
                for s in state:
                    if isinstance(s, CommonState):
                        continue
                    assert s in self.VALID_STATES, (
                        f"Request '{d.name}' references unknown state '{s}'"
                    )

    def test_session_active_requests_exist(self):
        """There must be requests requiring SESSION_ACTIVE state."""
        defs = _get_opcua_request_definitions()
        session_reqs = [d for d in defs if d.requires_state == "SESSION_ACTIVE"]
        assert len(session_reqs) >= 5, (
            f"Only {len(session_reqs)} requests require SESSION_ACTIVE, "
            f"expected >= 5 (Read, Browse, Write, Subscription, etc.)"
        )

    def test_pre_channel_requests_exist(self):
        """There must be requests for CONNECTED state (pre-channel operations)."""
        defs = _get_opcua_request_definitions()
        connected_reqs = [d for d in defs if d.requires_state == "CONNECTED"]
        assert len(connected_reqs) >= 2, (
            f"Only {len(connected_reqs)} requests for CONNECTED state, "
            f"expected >= 2 (baseline + state confusion)"
        )


# ---------------------------------------------------------------------------
# 4. OPC UA Service Set Coverage
# ---------------------------------------------------------------------------


class TestOPCUAServiceSetCoverage:
    """Verify all 9 OPC UA service sets are covered."""

    def _request_names(self):
        defs = _get_opcua_request_definitions()
        return {d.name for d in defs}

    def test_discovery_services(self):
        """Discovery service set must have a request."""
        names = self._request_names()
        assert "OPCUA_Discovery" in names, "Missing OPCUA_Discovery request"

    def test_secure_channel_services(self):
        """SecureChannel service set must have a request."""
        names = self._request_names()
        assert "OPCUA_SecureChannel" in names, "Missing OPCUA_SecureChannel request"

    def test_session_services(self):
        """Session service set must have a request."""
        names = self._request_names()
        assert "OPCUA_Session" in names, "Missing OPCUA_Session request"

    def test_auth_services(self):
        """Authentication fuzzing must have a request."""
        names = self._request_names()
        assert "OPCUA_Auth" in names, "Missing OPCUA_Auth request"

    def test_read_services(self):
        """Attribute Read service must have a request."""
        names = self._request_names()
        assert "OPCUA_Read" in names, "Missing OPCUA_Read request"

    def test_browse_services(self):
        """View Browse service must have a request."""
        names = self._request_names()
        assert "OPCUA_Browse" in names, "Missing OPCUA_Browse request"

    def test_write_services(self):
        """Attribute Write service must have a request."""
        names = self._request_names()
        assert "OPCUA_Write" in names, "Missing OPCUA_Write request"

    def test_call_services(self):
        """Method Call service must have a request."""
        names = self._request_names()
        assert "OPCUA_Call" in names, "Missing OPCUA_Call request"

    def test_subscription_services(self):
        """Subscription service set must have a request."""
        names = self._request_names()
        assert "OPCUA_Subscription" in names, "Missing OPCUA_Subscription request"

    def test_monitored_items_services(self):
        """MonitoredItem service set must have a request."""
        names = self._request_names()
        assert "OPCUA_MonitoredItems" in names, "Missing OPCUA_MonitoredItems request"

    def test_node_management_services(self):
        """NodeManagement service set must have a request."""
        names = self._request_names()
        assert "OPCUA_NodeManagement" in names, "Missing OPCUA_NodeManagement request"

    def test_publish_services(self):
        """Publish/Republish must have a request."""
        names = self._request_names()
        assert "OPCUA_Publish" in names, "Missing OPCUA_Publish request"

    def test_history_read_services(self):
        """HistoryRead must have a request."""
        names = self._request_names()
        assert "OPCUA_History_Read" in names, "Missing OPCUA_History_Read request"

    def test_history_update_services(self):
        """HistoryUpdate must have a request."""
        names = self._request_names()
        assert "OPCUA_History_Update" in names, "Missing OPCUA_History_Update request"


# ---------------------------------------------------------------------------
# 5. CVE Coverage
# ---------------------------------------------------------------------------


class TestOPCUACVECoverage:
    """Verify that fuzzer-relevant CVE patterns have corresponding requests."""

    def _request_names(self):
        defs = _get_opcua_request_definitions()
        return {d.name for d in defs}

    def test_chunk_flooding_cve_2022_25761(self):
        """CVE-2022-25761: Chunk exhaustion must have a request."""
        names = self._request_names()
        assert "OPCUA_ChunkFlood" in names, (
            "Missing OPCUA_ChunkFlood for CVE-2022-25761 (open62541 chunk exhaustion)"
        )

    def test_nested_recursion_cve_2021_27432(self):
        """CVE-2021-27432: Uncontrolled recursion must have a request."""
        names = self._request_names()
        has_coverage = "OPCUA_NestedMessage" in names or "OPCUA_NodeIdEncodingOverflow" in names
        assert has_coverage, (
            "Missing recursion attack for CVE-2021-27432 (uncontrolled recursion / stack overflow)"
        )

    def test_memory_exhaustion_cve_2022_29863(self):
        """CVE-2022-29863: Memory exhaustion must have a request."""
        names = self._request_names()
        has_coverage = "OPCUA_MalformedCert" in names or "OPCUA_Malformed" in names
        assert has_coverage, "Missing memory exhaustion attack for CVE-2022-29863"

    def test_resource_consumption_cve_2022_29864(self):
        """CVE-2022-29864: Resource consumption must have a request."""
        names = self._request_names()
        assert "OPCUA_ChunkFlood" in names, "Missing resource consumption attack for CVE-2022-29864"

    def test_browse_uaf_cve_2022_39823(self):
        """CVE-2022-39823: Browse continuation point UAF must have coverage."""
        names = self._request_names()
        assert "OPCUA_Browse" in names, (
            "Missing Browse request for CVE-2022-39823 (Softing UAF in continuation points)"
        )

    def test_cert_attack_exists(self):
        """Certificate chain attack patterns must exist."""
        names = self._request_names()
        assert "OPCUA_CertAttack" in names, "Missing certificate chain attack request"

    def test_malformed_cert_exists(self):
        """Oversized certificate attack must exist (§4 sweep 2026-06-03)."""
        names = self._request_names()
        assert "OPCUA_MalformedCert" in names, (
            "Missing malformed certificate request (CVE-2022-29863 pattern)"
        )

    def test_nodeid_encoding_overflow_exists(self):
        """NodeId encoding overflow must exist (§4 sweep 2026-06-03)."""
        names = self._request_names()
        assert "OPCUA_NodeIdEncodingOverflow" in names, (
            "Missing NodeId encoding overflow request (CVE-2021-27432 pattern)"
        )


# ---------------------------------------------------------------------------
# 6. Attack Pattern Coverage
# ---------------------------------------------------------------------------


class TestOPCUAAttackPatterns:
    """Verify key attack patterns are present."""

    def _request_names(self):
        defs = _get_opcua_request_definitions()
        return {d.name for d in defs}

    def test_boundary_testing_exists(self):
        """Boundary testing must be present for message size/field limits."""
        names = self._request_names()
        assert "OPCUA_Boundary" in names, "Missing boundary testing request"

    def test_malformed_testing_exists(self):
        """Malformed message testing must be present."""
        names = self._request_names()
        assert "OPCUA_Malformed" in names, "Missing malformed message request"

    def test_state_confusion_exists(self):
        """State confusion testing must be present (§4 sweep 2026-06-03).

        The §4 sweep landed a single OPCUA_State_Confusion request that
        rotates 6 service IDs (Read/Browse/Write/Call/CreateSubscription/
        CloseSession) all issued at SECURE_CHANNEL state pre-session.
        The original test wanted >=2 separate requests; the implementation
        merged them into one Group-driven request (more efficient — one
        boofuzz Request handles the full pre-session matrix).
        """
        defs = _get_opcua_request_definitions()
        state_confusion = [
            d
            for d in defs
            if "state_confusion" in d.category.lower() or "State_Confusion" in d.name
        ]
        assert len(state_confusion) >= 1, (
            f"Missing OPCUA_State_Confusion request — §4 sweep added it "
            f"as a Group covering pre-session service-ID attacks."
        )


# ---------------------------------------------------------------------------
# 7. Constants Completeness
# ---------------------------------------------------------------------------


class TestOPCUAConstants:
    """Verify OPC UA constants file has required service IDs."""

    def test_discovery_service_ids(self):
        """Discovery service IDs must be defined."""
        svc = _get_opcua_constants()
        assert hasattr(svc, "FIND_SERVERS_REQUEST")
        assert hasattr(svc, "GET_ENDPOINTS_REQUEST")
        assert hasattr(svc, "REGISTER_SERVER_REQUEST")

    def test_secure_channel_service_ids(self):
        """SecureChannel service IDs must be defined."""
        svc = _get_opcua_constants()
        assert hasattr(svc, "OPEN_SECURE_CHANNEL_REQUEST")
        assert hasattr(svc, "CLOSE_SECURE_CHANNEL_REQUEST")

    def test_session_service_ids(self):
        """Session service IDs must be defined."""
        svc = _get_opcua_constants()
        assert hasattr(svc, "CREATE_SESSION_REQUEST")
        assert hasattr(svc, "ACTIVATE_SESSION_REQUEST")
        assert hasattr(svc, "CLOSE_SESSION_REQUEST")
        assert hasattr(svc, "CANCEL_REQUEST")

    def test_query_service_ids(self):
        """Query service IDs must be defined (even if not yet implemented)."""
        svc = _get_opcua_constants()
        assert hasattr(svc, "QUERY_FIRST_REQUEST"), (
            "QUERY_FIRST_REQUEST missing from OPCUAServiceIds"
        )
        assert hasattr(svc, "QUERY_NEXT_REQUEST"), "QUERY_NEXT_REQUEST missing from OPCUAServiceIds"

    def test_query_service_id_values(self):
        """Query service ID values must match OPC UA spec."""
        svc = _get_opcua_constants()
        assert svc.QUERY_FIRST_REQUEST == 615
        assert svc.QUERY_NEXT_REQUEST == 621

    def test_all_monitored_item_service_ids(self):
        """All MonitoredItem service IDs must be defined."""
        svc = _get_opcua_constants()
        required = [
            "CREATE_MONITORED_ITEMS_REQUEST",
            "MODIFY_MONITORED_ITEMS_REQUEST",
            "SET_MONITORING_MODE_REQUEST",
            "SET_TRIGGERING_REQUEST",
            "DELETE_MONITORED_ITEMS_REQUEST",
        ]
        for attr in required:
            assert hasattr(svc, attr), f"Missing {attr} in OPCUAServiceIds"

    def test_all_subscription_service_ids(self):
        """All Subscription service IDs must be defined."""
        svc = _get_opcua_constants()
        required = [
            "CREATE_SUBSCRIPTION_REQUEST",
            "MODIFY_SUBSCRIPTION_REQUEST",
            "SET_PUBLISHING_MODE_REQUEST",
            "PUBLISH_REQUEST",
            "REPUBLISH_REQUEST",
            "TRANSFER_SUBSCRIPTIONS_REQUEST",
            "DELETE_SUBSCRIPTIONS_REQUEST",
        ]
        for attr in required:
            assert hasattr(svc, attr), f"Missing {attr} in OPCUAServiceIds"


# ---------------------------------------------------------------------------
# 8. Codec Completeness
# ---------------------------------------------------------------------------


class TestOPCUACodec:
    """Verify the OPC UA codec has required encoding/decoding methods."""

    def _get_codec(self):
        from oida.fuzz.core.codecs.opcua import OPCUACodec

        return OPCUACodec

    def test_primitive_encoding_methods(self):
        """Codec must have all primitive encoding methods."""
        codec = self._get_codec()
        required = [
            "encode_boolean",
            "encode_byte",
            "encode_uint16",
            "encode_int32",
            "encode_uint32",
            "encode_int64",
            "encode_uint64",
            "encode_float",
            "encode_double",
            "encode_string",
            "encode_byte_string",
            "encode_datetime",
            "encode_guid",
        ]
        for method in required:
            assert hasattr(codec, method), f"Codec missing {method}"

    def test_nodeid_encoding(self):
        """Codec must support all 6 NodeId encoding types."""
        from oida.fuzz.core.codecs.opcua import OPCUACodec, NodeId, NodeIdType

        codec = OPCUACodec()

        # TwoByte
        result = codec.encode_node_id(NodeId(42, 0, NodeIdType.TWO_BYTE))
        assert result[0] == 0x00  # TwoByte type

        # FourByte
        result = codec.encode_node_id(NodeId(2253, 0, NodeIdType.FOUR_BYTE))
        assert result[0] == 0x01  # FourByte type

        # Numeric
        result = codec.encode_node_id(NodeId(100000, 2, NodeIdType.NUMERIC))
        assert result[0] == 0x02  # Numeric type

    def test_hello_builder(self):
        """Codec must build valid Hello messages."""
        from oida.fuzz.core.codecs.opcua import OPCUACodec

        msg = OPCUACodec.build_hello("opc.tcp://localhost:4840")
        assert msg[:3] == b"HEL"
        assert msg[3:4] == b"F"

    def test_acknowledge_parser(self):
        """Codec must parse Acknowledge messages."""
        from oida.fuzz.core.codecs.opcua import OPCUACodec
        import struct

        # Build a valid ACK
        ack = b"ACKF" + struct.pack("<IIIII", 28, 0, 65535, 65535, 0) + struct.pack("<I", 0)
        result = OPCUACodec.parse_acknowledge(ack)
        assert result is not None
        assert result["message_type"] == "Acknowledge"

    def test_error_parser(self):
        """Codec must parse Error messages."""
        from oida.fuzz.core.codecs.opcua import OPCUACodec
        import struct

        err = b"ERRF" + struct.pack("<II", 16, 0x80000000)
        # Add reason string (length-prefixed)
        reason = b"Bad"
        err += struct.pack("<i", len(reason)) + reason
        result = OPCUACodec.parse_error(err)
        assert result is not None
        assert result["message_type"] == "Error"


# ---------------------------------------------------------------------------
# 9. Monitor Coverage
# ---------------------------------------------------------------------------


class TestOPCUAMonitor:
    """Verify the OPC UA monitor has required capabilities."""

    def test_monitor_class_exists(self):
        """OPCUAMonitor class must exist."""
        from oida.fuzz.monitors.opcua import OPCUAMonitor

        assert OPCUAMonitor is not None

    def test_monitor_inherits_protocol_monitor(self):
        """OPCUAMonitor must inherit from ProtocolMonitor."""
        from oida.fuzz.monitors.opcua import OPCUAMonitor
        from oida.fuzz.monitors.base import ProtocolMonitor

        assert issubclass(OPCUAMonitor, ProtocolMonitor)

    def test_monitor_has_check_alive(self):
        """Monitor must implement _check_alive_once."""
        from oida.fuzz.monitors.opcua import OPCUAMonitor

        assert hasattr(OPCUAMonitor, "_check_alive_once")

    def test_monitor_builds_hello(self):
        """Monitor must build Hello messages for health checks."""
        from oida.fuzz.monitors.opcua import OPCUAMonitor

        monitor = OPCUAMonitor("127.0.0.1", 4840)
        msg = monitor._build_hello_message()
        assert msg[:3] == b"HEL"
        assert len(msg) >= 28  # Minimum Hello size

    def test_monitor_parses_ack(self):
        """Monitor must correctly parse valid ACK responses."""
        import struct
        from oida.fuzz.monitors.opcua import OPCUAMonitor

        monitor = OPCUAMonitor("127.0.0.1", 4840)

        # Valid ACK: header (ACKF + MessageSize) + body (5 x UInt32)
        # Total = 8 header + 20 body = 28 bytes
        body = struct.pack("<IIIII", 0, 65535, 65535, 0, 0)
        header = b"ACKF" + struct.pack("<I", 8 + len(body))
        ack = header + body
        assert len(ack) == 28, f"ACK should be 28 bytes, got {len(ack)}"
        result = monitor._parse_acknowledge(ack)
        assert result is True

    def test_monitor_rejects_err(self):
        """Monitor must reject ERR responses."""
        import struct
        from oida.fuzz.monitors.opcua import OPCUAMonitor

        monitor = OPCUAMonitor("127.0.0.1", 4840)

        # ERR response
        err = b"ERRF" + struct.pack("<II", 16, 0x80000000)
        err += struct.pack("<i", 3) + b"Bad"
        result = monitor._parse_acknowledge(err)
        assert result is False

    def test_monitor_default_port(self):
        """Monitor default port must be 4840."""
        from oida.fuzz.monitors.opcua import OPCUAMonitor

        monitor = OPCUAMonitor("127.0.0.1")
        assert monitor.port == 4840


# ---------------------------------------------------------------------------
# 10. Fuzzer Class Structure
# ---------------------------------------------------------------------------


class TestOPCUAFuzzerStructure:
    """Verify the OPC UA fuzzer class has required attributes and methods."""

    def test_inherits_base_fuzzer(self):
        """OPCUAFuzzer must inherit from BaseFuzzer."""
        from oida.fuzz.protocols.opcua import OPCUAFuzzer
        from oida.fuzz.core.base_fuzzer import BaseFuzzer

        assert issubclass(OPCUAFuzzer, BaseFuzzer)

    def test_has_default_monitors(self):
        """OPCUAFuzzer must specify default monitors."""
        from oida.fuzz.protocols.opcua import OPCUAFuzzer

        assert hasattr(OPCUAFuzzer, "DEFAULT_MONITORS")
        assert OPCUAFuzzer.DEFAULT_MONITORS == "opcua"

    def test_has_protocol_options(self):
        """OPCUAFuzzer must have protocol-specific options."""
        from oida.fuzz.protocols.opcua import OPCUAFuzzer

        opts = OPCUAFuzzer.PROTOCOL_OPTIONS
        required_opts = [
            "security_policy",
            "security_mode",
            "endpoint_url",
            "application_uri",
            "use_session",
        ]
        for opt in required_opts:
            assert opt in opts, f"Missing protocol option: {opt}"

    def test_has_auth_options(self):
        """OPCUAFuzzer must have authentication options."""
        from oida.fuzz.protocols.opcua import OPCUAFuzzer

        opts = OPCUAFuzzer.PROTOCOL_OPTIONS
        assert "opcua_username" in opts, "Missing opcua_username option"
        assert "opcua_password" in opts, "Missing opcua_password option"

    def test_get_request_definitions_is_classmethod(self):
        """get_request_definitions must be a classmethod (no instantiation needed)."""
        from oida.fuzz.protocols.opcua import OPCUAFuzzer

        # This should work without creating an instance
        defs = OPCUAFuzzer.get_request_definitions()
        assert isinstance(defs, list)
        assert len(defs) > 0

    def test_has_state_machine_method(self):
        """OPCUAFuzzer must define _define_state_machine."""
        from oida.fuzz.protocols.opcua import OPCUAFuzzer

        assert hasattr(OPCUAFuzzer, "_define_state_machine")

    def test_has_define_protocol_method(self):
        """OPCUAFuzzer must define _define_protocol."""
        from oida.fuzz.protocols.opcua import OPCUAFuzzer

        assert hasattr(OPCUAFuzzer, "_define_protocol")

    def test_registered_in_protocol_fuzzers(self):
        """OPCUAFuzzer must be registered in PROTOCOL_FUZZERS."""
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        assert "opcua" in PROTOCOL_FUZZERS, "OPCUAFuzzer not registered in PROTOCOL_FUZZERS"


# ---------------------------------------------------------------------------
# 11. Request Name Uniqueness
# ---------------------------------------------------------------------------


class TestOPCUARequestUniqueness:
    """Verify request names are unique (no collisions)."""

    def test_no_duplicate_request_names(self):
        """All RequestInfo names must be unique."""
        defs = _get_opcua_request_definitions()
        names = [d.name for d in defs]
        duplicates = [n for n in names if names.count(n) > 1]
        assert not duplicates, f"Duplicate request names: {set(duplicates)}"

    def test_no_empty_request_names(self):
        """No request should have an empty name."""
        defs = _get_opcua_request_definitions()
        for d in defs:
            assert d.name, f"Empty request name found: {d}"
            assert d.name.strip(), f"Whitespace-only request name found: {d}"

    def test_all_requests_have_descriptions(self):
        """All requests must have non-empty descriptions."""
        defs = _get_opcua_request_definitions()
        for d in defs:
            assert d.description, f"Request '{d.name}' has no description"
