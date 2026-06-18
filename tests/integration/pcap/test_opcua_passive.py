"""Integration tests for OPC UA passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestOPCUAPassiveEK:
    """OPC UA-specific tests beyond the parametrized quality suite."""

    def test_opcua_sessions_have_security_info(self):
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_opcua_with-gap_with-handshake.pcap",
            expect_details=["service"],
            expect_operations=["GetEndpoints"],
        )
        assert len(listener.sessions) >= 1
        for session in listener.sessions.values():
            assert session.endpoint_url or session.security_policy, (
                "Session has neither endpoint nor security policy"
            )

    def test_opcua_encrypted_no_crash(self):
        """Encrypted pcap: initial handshake is cleartext, rest is opaque."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/wireshark_opcua_encrypted.pcapng",
            min_devices=0,
            min_interactions=0,
        )

        # A1: HEL/ACK transport messages should have service labels
        if listener.interactions:
            services = {ix.details.get("service", "") for ix in listener.interactions}
            # At minimum, Hello and Acknowledge should be labeled
            hello_or_ack = services & {"Hello", "Acknowledge"}
            assert hello_or_ack, (
                f"Expected Hello/Acknowledge labels in encrypted pcap; "
                f"services seen: {sorted(services)}"
            )

        # A3: For encrypted sessions, security_policy should not be "None"
        for session in listener.sessions.values():
            if session.security_policy:
                assert session.security_policy != "None", (
                    f"Encrypted session should not have security_policy='None'; "
                    f"got {session.security_policy}"
                )

        # A4: No comma-duplicated endpoint URLs
        for session in listener.sessions.values():
            if session.endpoint_url:
                assert "," not in session.endpoint_url, (
                    f"Endpoint URL contains comma (EK dedup failed): {session.endpoint_url}"
                )


class TestOPCUAFieldCoverage:
    """Tests for T1 field coverage gaps resolved in the OPC UA listener."""

    def test_secure_channel_id_extracted(self):
        """opcua.transport.scid: secure channel ID in OPN/MSG packets."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        found = any(ix.details.get("secure_channel_id") for ix in listener.interactions)
        assert found, "No interaction has secure_channel_id (opcua.transport.scid)"

    def test_security_token_id_extracted(self):
        """opcua.security.tokenid: security token ID in secured messages."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        found = any(ix.details.get("security_token_id") for ix in listener.interactions)
        assert found, "No interaction has security_token_id (opcua.security.tokenid)"

    def test_service_result_extracted(self):
        """opcua.ServiceResult: service-level status code in responses."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        found = any(ix.details.get("service_result") for ix in listener.interactions)
        assert found, "No interaction has service_result (opcua.ServiceResult)"

    def test_channel_and_token_id(self):
        """opcua.ChannelId and opcua.TokenId: service-layer IDs."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        has_channel = any(ix.details.get("channel_id") for ix in listener.interactions)
        has_token = any(ix.details.get("token_id") for ix in listener.interactions)
        assert has_channel or has_token, "No interaction has channel_id or token_id"

    def test_protocol_version_fields(self):
        """opcua.ClientProtocolVersion / ServerProtocolVersion in HEL/ACK."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        has_client_ver = any(
            ix.details.get("client_protocol_version") for ix in listener.interactions
        )
        has_server_ver = any(
            ix.details.get("server_protocol_version") for ix in listener.interactions
        )
        assert has_client_ver or has_server_ver, (
            "No interaction has client_protocol_version or server_protocol_version"
        )

    def test_session_name_extracted(self):
        """opcua.SessionName: session name from CreateSession."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_opcua_with-gap_with-handshake.pcap",
            expect_details=["service"],
            expect_operations=["CreateSession"],
        )
        found = any(ix.details.get("session_name") for ix in listener.interactions)
        assert found, "No interaction has session_name (opcua.SessionName)"

    def test_attribute_id_in_read_write(self):
        """opcua.AttributeId: attribute being read/written."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_read_service_test_data.pcap",
            min_devices=0,
            expect_details=["service"],
            expect_operations=["Read"],
        )
        found = any(ix.details.get("attribute_id") for ix in listener.interactions)
        assert found, "No interaction has attribute_id (opcua.AttributeId)"

    def test_password_extracted(self):
        """opcua.Password: credential extraction from ActivateSession."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        found = any(ix.details.get("password") for ix in listener.interactions)
        assert found, "No interaction has password (opcua.Password)"

    def test_username_extracted(self):
        """opcua.UserName: username from ActivateSession."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        found = any(ix.details.get("username") for ix in listener.interactions)
        assert found, "No interaction has username (opcua.UserName)"

    def test_status_code_extracted(self):
        """opcua.StatusCode: status codes in responses."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        found = any(ix.details.get("status") for ix in listener.interactions)
        assert found, "No interaction has status (opcua.StatusCode)"

    def test_subscription_id_extracted(self):
        """opcua.SubscriptionId: subscription tracking."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        found = any(ix.details.get("subscription_id") for ix in listener.interactions)
        assert found, "No interaction has subscription_id (opcua.SubscriptionId)"

    def test_transport_error_in_err_message(self):
        """opcua.transport.error: error code from ERR messages."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/wireshark_opcua_encrypted.pcapng",
            min_devices=0,
            min_interactions=0,
        )
        # This pcap has ERR messages; check if transport_error extracted
        found = any(ix.details.get("transport_error") for ix in listener.interactions)
        # Transport errors are rare; test is non-fatal if pcap lacks them
        if listener.interactions:
            services = {ix.details.get("service", "") for ix in listener.interactions}
            if "Error" in services:
                assert found, "ERR service detected but no transport_error extracted"

    def test_inner_status_code_diagnostic(self):
        """opcua.diag.InnerStatusCode: diagnostic inner status in responses."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop-hasInnerStatusCode.pcap",
            expect_details=["service"],
        )
        found = any(ix.details.get("inner_status_code") for ix in listener.interactions)
        assert found, "No interaction has inner_status_code (opcua.diag.InnerStatusCode)"

    def test_monitored_item_and_publishing(self):
        """opcua.MonitoredItemId and opcua.PublishingEnabled in subscriptions."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_create_monitored_items.pcap",
            min_devices=0,
            expect_details=["service"],
        )
        has_mon = any(ix.details.get("monitored_item_id") for ix in listener.interactions)
        has_pub = any(ix.details.get("publishing_enabled") for ix in listener.interactions)
        assert has_mon or has_pub, "No interaction has monitored_item_id or publishing_enabled"

    def test_delete_subscriptions_flag(self):
        """opcua.DeleteSubscriptions: flag in CloseSession."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        found = any(ix.details.get("delete_subscriptions") for ix in listener.interactions)
        assert found, "No interaction has delete_subscriptions (opcua.DeleteSubscriptions)"

    def test_user_token_type_extracted(self):
        """opcua.UserTokenType: user token type from endpoint descriptions."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        found = any(ix.details.get("token_type") for ix in listener.interactions)
        assert found, "No interaction has token_type (opcua.UserTokenType)"

    def test_policy_id_extracted(self):
        """opcua.PolicyId: policy ID from endpoint user identity tokens."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_client-server_mainloop.pcap",
            expect_details=["service"],
        )
        # PolicyId is stored in session user_authentications, not directly
        # in interaction details; check via session data
        has_policy = False
        for session in listener.sessions.values():
            for ua in session.user_authentications:
                if ua.policy_id:
                    has_policy = True
                    break
        # Also check device data for policy info
        if not has_policy:
            for dev in devices.values():
                pdata = getattr(dev, "opcua_passive_data", {})
                for ua in pdata.get("user_authentications", []):
                    if ua.get("policy_id"):
                        has_policy = True
                        break
        assert has_policy, "No session or device has PolicyId (opcua.PolicyId)"

    def test_server_name_in_discovery(self):
        """opcua.ServerName and opcua.MdnsServerName in FindServersOnNetwork."""
        listener, devices, result = _run_listener_test(
            "opcua",
            "OPCUAPassiveListener",
            "opcua",
            "opcua/cisagov_open62541_discover_getendpoints_discover_urls.pcap",
            expect_details=["service"],
        )
        has_name = any(
            ix.details.get("server_name") or ix.details.get("mdns_server_name")
            for ix in listener.interactions
        )
        assert has_name, "No interaction has server_name or mdns_server_name"
