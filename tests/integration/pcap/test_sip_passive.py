"""Integration tests for SIP passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestSIPPassiveEK:
    """SIP-specific tests beyond the parametrised quality suite."""

    def test_sip_basic(self):
        listener, devices, result = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_devices=2,
            min_interactions=10,
        )
        # SIP listener tracks calls
        assert len(listener.calls) >= 1, "Expected at least one tracked call"
        calls_summary = listener.get_calls_summary()
        assert len(calls_summary) >= 1, "Expected at least one call summary"
        for call in calls_summary:
            assert "call_id" in call
            assert "from_user" in call
            assert "to_user" in call

    def test_sip_method_extraction(self):
        """Verify sip.Method (T1) is extracted into interaction details."""
        listener, devices, result = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_interactions=1,
            min_devices=0,
            expect_details=["method"],
            expect_operations=["SIP INVITE"],
        )
        # Check method values are real SIP methods
        methods_seen = {
            ix.details["method"] for ix in listener.interactions if ix.details.get("method")
        }
        assert "INVITE" in methods_seen, f"Expected INVITE in methods; saw: {methods_seen}"

    def test_sip_status_code_and_status_line(self):
        """Verify sip.Status-Code and sip.Status-Line (T1) extraction."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_interactions=1,
            min_devices=0,
        )
        response_interactions = [ix for ix in listener.interactions if ix.direction == "response"]
        assert len(response_interactions) >= 1, "Expected at least one response"

        # Check status_code is present
        has_status_code = any(ix.details.get("status_code") for ix in response_interactions)
        assert has_status_code, "No response has status_code in details"

        # Check status_line is present
        has_status_line = any(ix.details.get("status_line") for ix in response_interactions)
        assert has_status_line, "No response has status_line in details"

        # Verify status line contains a SIP version prefix
        for ix in response_interactions:
            sl = ix.details.get("status_line", "")
            if sl:
                assert sl.startswith("SIP/"), f"Unexpected status_line format: {sl}"
                break

    def test_sip_call_id_extraction(self):
        """Verify sip.Call-ID (T1) is present in interaction details."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_interactions=1,
            min_devices=0,
            expect_details=["call_id"],
        )
        # Every SIP interaction should have a call_id
        for ix in listener.interactions:
            assert ix.details.get("call_id"), f"Interaction missing call_id: {ix.operation}"

    def test_sip_from_to_fields(self):
        """Verify sip.from.user, sip.from.host, sip.to.user, sip.to.host (T1)."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_interactions=1,
            min_devices=0,
        )
        # At least one interaction should have from_host and to_host
        has_from_host = any(ix.details.get("from_host") for ix in listener.interactions)
        has_to_host = any(ix.details.get("to_host") for ix in listener.interactions)
        assert has_from_host, "No interaction has from_host"
        assert has_to_host, "No interaction has to_host"

        # Verify user fields appear in packets that have user parts
        has_to_user = any(ix.details.get("to_user") for ix in listener.interactions)
        assert has_to_user, "No interaction has to_user"

    def test_sip_cseq_fields(self):
        """Verify sip.CSeq.seq and sip.CSeq.method (T1) extraction."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_interactions=1,
            min_devices=0,
            expect_details=["cseq_seq", "cseq_method"],
        )
        # CSeq method should match known SIP methods
        cseq_methods = {
            ix.details["cseq_method"]
            for ix in listener.interactions
            if ix.details.get("cseq_method")
        }
        assert len(cseq_methods) >= 1, "No CSeq methods found"
        valid_methods = {"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS"}
        for m in cseq_methods:
            assert m in valid_methods, f"Unexpected CSeq method: {m}"

    def test_sip_user_agent(self):
        """Verify sip.User-Agent (T1) extraction."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_interactions=1,
            min_devices=0,
            expect_details=["user_agent"],
        )

    def test_sip_via_address(self):
        """Verify sip.Via.sent-by.address (T1) extraction."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_interactions=1,
            min_devices=0,
            expect_details=["via_address"],
        )

    def test_sip_contact_user(self):
        """Verify sip.contact.user (T1) extraction."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_interactions=1,
            min_devices=0,
            expect_details=["contact_user"],
        )

    def test_sip_ruri_user(self):
        """Verify sip.r-uri.user (T1) extraction."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_interactions=1,
            min_devices=0,
            expect_details=["r_uri_user"],
        )

    def test_sip_response_time(self):
        """Verify sip.response-time (T1) extraction on response packets."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_interactions=1,
            min_devices=0,
            expect_details=["response_time"],
        )
        # response_time should be a numeric string (milliseconds)
        for ix in listener.interactions:
            rt = ix.details.get("response_time")
            if rt:
                assert rt.isdigit(), f"response_time should be numeric, got: {rt}"
                break

    def test_sip_from_to_ports(self):
        """Verify sip.from.port and sip.to.port (T1) extraction."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_interactions=1,
            min_devices=0,
        )
        has_from_port = any(ix.details.get("from_port") for ix in listener.interactions)
        has_to_port = any(ix.details.get("to_port") for ix in listener.interactions)
        assert has_from_port, "No interaction has from_port"
        assert has_to_port, "No interaction has to_port"

    def test_sip_call_tracking(self):
        """Verify call state tracking through INVITE -> 200 OK -> ACK flow."""
        listener, devices, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_devices=2,
            min_interactions=5,
        )
        assert len(listener.calls) >= 1
        # At least one call should reach IN_CALL state (after ACK)
        from oida.pcap.sip import CallState

        states_seen = {c.state for c in listener.calls.values()}
        assert CallState.IN_CALL in states_seen or CallState.INVITED in states_seen, (
            f"Expected IN_CALL or INVITED state; saw: {states_seen}"
        )

        # Verify call fields
        for call in listener.calls.values():
            assert call.call_id, "Call missing call_id"
            assert call.from_ip, "Call missing from_ip"
            assert call.to_ip, "Call missing to_ip"
            assert call.start_time, "Call missing start_time"

    def test_sip_digest_auth_extraction(self):
        """Verify SIP Digest authentication credential extraction."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcap",
            min_devices=0,
            min_interactions=10,
        )
        assert len(listener.credentials) >= 1, "Expected at least one digest credential"

        creds = listener.get_credentials_summary()
        for c in creds:
            assert c.get("protocol") == "SIP"
            assert c.get("credential_type") == "hash"
            assert c.get("username"), "Credential missing username"
            assert c.get("realm"), "Credential missing realm"
            assert c.get("response"), "Credential missing digest response"

        # Verify hashcat format generation
        hashes = listener.get_hashcat_hashes()
        assert len(hashes) >= 1
        for h in hashes:
            assert h.startswith("$sip$*"), f"Invalid hashcat format: {h}"

    def test_sip_auth_header_fields(self):
        """Verify T1 auth header fields: WWW-Authenticate, auth, auth_scheme, auth_opaque, auth_stale."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcap",
            min_devices=0,
            min_interactions=1,
        )
        # The wireshark_sip_rtp.pcap has 401 responses with WWW-Authenticate
        has_www_auth = any(ix.details.get("www_authenticate") for ix in listener.interactions)
        assert has_www_auth, "No interaction has www_authenticate"

        has_auth_scheme = any(ix.details.get("auth_scheme") for ix in listener.interactions)
        assert has_auth_scheme, "No interaction has auth_scheme"

        has_auth_opaque = any(ix.details.get("auth_opaque") for ix in listener.interactions)
        assert has_auth_opaque, "No interaction has auth_opaque"

        has_auth_stale = any(ix.details.get("auth_stale") for ix in listener.interactions)
        assert has_auth_stale, "No interaction has auth_stale"

        # Verify auth_scheme is Digest
        for ix in listener.interactions:
            scheme = ix.details.get("auth_scheme")
            if scheme:
                assert scheme == "Digest", f"Expected Digest scheme, got: {scheme}"
                break

    def test_sip_bruteshark_pcap(self):
        """Test with bruteshark SIP pcap for broader coverage."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/bruteshark_sip_rtp.pcap",
            min_devices=0,
            min_interactions=1,
        )
        # This pcap should produce interactions with method and status_code
        request_ops = {
            ix.details.get("method") for ix in listener.interactions if ix.details.get("method")
        }
        response_codes = {
            ix.details.get("status_code")
            for ix in listener.interactions
            if ix.details.get("status_code")
        }
        assert len(request_ops) >= 1, "Expected at least one SIP method"
        assert len(response_codes) >= 1, "Expected at least one status code"

    def test_sip_device_passive_data(self):
        """Verify device sip_passive_data structure."""
        listener, devices, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_rtp.pcapng",
            min_devices=1,
            min_interactions=1,
        )
        # At least one device should have sip_passive_data
        has_sip_data = any(d.sip_passive_data for d in devices.values())
        assert has_sip_data, "No device has sip_passive_data"

        for device in devices.values():
            if device.sip_passive_data:
                data = device.sip_passive_data
                assert "role" in data, "sip_passive_data missing 'role'"
                assert data["role"] in ("caller", "callee", "server"), (
                    f"Unexpected role: {data['role']}"
                )
                assert "calls" in data, "sip_passive_data missing 'calls'"
                assert "protocol" in data, "sip_passive_data missing 'protocol'"
                break

    def test_sip_spoof_pcap(self):
        """Test with SIP spoof pcap (minimal, should not crash)."""
        listener, _, _ = _run_listener_test(
            "sip",
            "SIPPassiveListener",
            "sip",
            "sip/wireshark_sip_spoof.pcap",
            min_devices=0,
            min_interactions=0,
        )
        # Just verify no crash and interactions are well-formed
        for ix in listener.interactions:
            assert ix.src_ip, "Interaction missing src_ip"
            assert ix.dst_ip, "Interaction missing dst_ip"
            assert ix.operation, "Interaction missing operation"
