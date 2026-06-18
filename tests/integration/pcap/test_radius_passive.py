"""Integration tests for RADIUS passive listener in EK mode.

Tests cover:
- Basic credential extraction from generated PAP fixture
- CHAP credential extraction from wireshark fixture (radius.CHAP_Password)
- Message-Authenticator extraction (radius.Message_Authenticator)
- Filter-Id extraction from Access-Accept/Challenge (radius.Filter_Id)
- Service-Type extraction (radius.Service_Type)
- Identifier and authenticator in interaction details
- Response correlation (auth_result from Accept/Reject/Challenge)
- Credential summary canonical key names for scanner compatibility
"""

import pytest

from .conftest import _run_listener_test, _skip_unless_pyshark, _pcap_path, _load_packets

pytestmark = [pytest.mark.integration]


class TestRADIUSPassiveEK:
    """RADIUS-specific tests beyond the parametrised quality suite."""

    def test_radius_basic(self):
        listener, devices, result = _run_listener_test(
            "radius",
            "RADIUSPassiveListener",
            "radius",
            "radius/generated_radius.pcap",
            expect_details=["code"],
        )
        # RADIUS listener should extract credentials
        creds = listener.get_credentials_summary()
        if listener.credentials:
            assert len(creds) >= 1, "Expected at least one credential summary entry"
            for c in creds:
                assert c.get("protocol") == "RADIUS"
                assert "username" in c

            # get_users_by_realm should return data
            realms = listener.get_users_by_realm()
            assert isinstance(realms, dict)
            assert len(realms) >= 1, "Expected at least one realm"

    def test_radius_identifier_in_details(self):
        """radius.id should appear as 'identifier' in interaction details."""
        listener, devices, result = _run_listener_test(
            "radius",
            "RADIUSPassiveListener",
            "radius",
            "radius/generated_radius.pcap",
            expect_details=["code", "identifier"],
        )
        # At least one interaction should have a non-zero identifier
        found = any(
            ix.details.get("identifier") is not None and ix.details["identifier"] != ""
            for ix in listener.interactions
        )
        assert found, (
            "No interaction has 'identifier' in details; "
            f"sample: {listener.interactions[0].details if listener.interactions else 'none'}"
        )

    def test_radius_authenticator_in_details(self):
        """radius.authenticator should appear in interaction details."""
        listener, devices, result = _run_listener_test(
            "radius",
            "RADIUSPassiveListener",
            "radius",
            "radius/generated_radius.pcap",
            expect_details=["code", "authenticator"],
        )
        found_auth = any(ix.details.get("authenticator") for ix in listener.interactions)
        assert found_auth, "No interaction has 'authenticator' in details"

    def test_radius_encrypted_password_extraction(self):
        """radius.User_Password_encrypted should be extracted on PAP requests."""
        _skip_unless_pyshark()
        import importlib

        pcap = _pcap_path("radius/generated_radius.pcap")
        mod = importlib.import_module("oida.pcap.passive.radius")
        listener = mod.RADIUSPassiveListener(interface="lo", timeout=10)
        packets = _load_packets(pcap, display_filter="radius")
        listener.feed_packets(iter(packets))

        assert len(listener.credentials) >= 1, "Expected at least one credential"
        cred = listener.credentials[0]
        assert cred.username == "radiususer", f"Expected 'radiususer', got {cred.username!r}"
        assert cred.encrypted_password, "Expected encrypted_password to be non-empty"
        assert cred.auth_method == "RADIUS-PAP", (
            f"Expected RADIUS-PAP auth method, got {cred.auth_method!r}"
        )

    def test_radius_response_correlation(self):
        """Access-Accept response should set auth_result on correlated credential."""
        _skip_unless_pyshark()
        import importlib

        pcap = _pcap_path("radius/generated_radius.pcap")
        mod = importlib.import_module("oida.pcap.passive.radius")
        listener = mod.RADIUSPassiveListener(interface="lo", timeout=10)
        packets = _load_packets(pcap, display_filter="radius")
        listener.feed_packets(iter(packets))

        assert len(listener.credentials) >= 1
        cred = listener.credentials[0]
        # The generated pcap has Access-Request(code=1) then Access-Accept(code=2)
        assert cred.auth_result == "accept", (
            f"Expected auth_result='accept', got {cred.auth_result!r}"
        )


class TestRADIUSWiresharkFixture:
    """Tests using the wireshark_radius.pcapng fixture which contains
    CHAP, EAP-MD5, Message-Authenticator, Filter-Id, and Service-Type."""

    def _load_wireshark_listener(self):
        """Helper to load wireshark RADIUS fixture."""
        _skip_unless_pyshark()
        import importlib

        pcap = _pcap_path("radius/wireshark_radius.pcapng")
        mod = importlib.import_module("oida.pcap.passive.radius")
        listener = mod.RADIUSPassiveListener(interface="lo", timeout=10)
        packets = _load_packets(pcap, display_filter="radius")
        listener.feed_packets(iter(packets))
        return listener

    def test_chap_password_extraction(self):
        """radius.CHAP_Password should be extracted from CHAP auth requests."""
        listener = self._load_wireshark_listener()

        # Find credential with CHAP data (pkt 21 in fixture has CHAP)
        chap_creds = [c for c in listener.credentials if c.chap_password]
        assert len(chap_creds) >= 1, (
            "Expected at least one credential with CHAP password; "
            f"got {len(listener.credentials)} total creds, none with chap_password"
        )
        chap_cred = chap_creds[0]
        assert chap_cred.username == "steve"
        assert chap_cred.auth_method == "RADIUS-CHAP"
        assert len(chap_cred.chap_password) > 0, "CHAP password should be non-empty hex"

    def test_chap_ident_extraction(self):
        """radius.CHAP_Ident should be extracted alongside CHAP-Password."""
        listener = self._load_wireshark_listener()

        chap_creds = [c for c in listener.credentials if c.chap_password]
        if chap_creds:
            # CHAP_Ident should be present when CHAP_Password is present
            assert chap_creds[0].chap_ident, (
                "Expected chap_ident to be populated alongside chap_password"
            )

    def test_message_authenticator_extraction(self):
        """radius.Message_Authenticator should appear in interaction details."""
        listener = self._load_wireshark_listener()

        # Message-Authenticator appears in many requests in the wireshark fixture
        found = any(ix.details.get("message_authenticator") for ix in listener.interactions)
        assert found, (
            "No interaction has 'message_authenticator' in details; "
            "expected from wireshark fixture which has Message-Authenticator attributes"
        )

    def test_message_authenticator_on_credential(self):
        """Message-Authenticator should be stored on credential objects."""
        listener = self._load_wireshark_listener()

        ma_creds = [c for c in listener.credentials if c.message_authenticator]
        assert len(ma_creds) >= 1, (
            "Expected at least one credential with message_authenticator; "
            f"got {len(listener.credentials)} creds, none with message_authenticator"
        )

    def test_filter_id_extraction(self):
        """radius.Filter_Id from Access-Accept/Challenge should update credential."""
        listener = self._load_wireshark_listener()

        # Filter-Id "std.ppp" appears in Accept and Challenge responses
        filter_creds = [c for c in listener.credentials if c.filter_id]
        assert len(filter_creds) >= 1, (
            "Expected at least one credential with filter_id from Accept/Challenge; "
            f"got {len(listener.credentials)} creds, none with filter_id"
        )
        assert filter_creds[0].filter_id == "std.ppp", (
            f"Expected filter_id='std.ppp', got {filter_creds[0].filter_id!r}"
        )

    def test_service_type_from_response(self):
        """radius.Service_Type from response should be available on credential."""
        listener = self._load_wireshark_listener()

        # Service-Type=2 (Framed) appears in Accept/Challenge responses
        svc_creds = [
            c for c in listener.credentials if c.service_type and c.service_type != "Unknown"
        ]
        assert len(svc_creds) >= 1, (
            "Expected at least one credential with service_type from response; "
            f"service_types seen: {[c.service_type for c in listener.credentials]}"
        )

    def test_credential_summary_has_new_fields(self):
        """get_credentials_summary() should include CHAP and Message-Authenticator."""
        listener = self._load_wireshark_listener()

        creds = listener.get_credentials_summary()
        assert len(creds) >= 1

        # All credentials should have auth_method key
        for c in creds:
            assert "auth_method" in c, f"Missing 'auth_method' key in summary: {c.keys()}"
            assert c["auth_method"] in ("RADIUS-PAP", "RADIUS-CHAP"), (
                f"Unexpected auth_method: {c['auth_method']}"
            )

        # At least one summary entry should have chap_password (if CHAP cred exists)
        chap_summaries = [c for c in creds if c.get("chap_password")]
        chap_creds = [c for c in listener.credentials if c.chap_password]
        if chap_creds:
            assert len(chap_summaries) >= 1, (
                "CHAP credentials exist but get_credentials_summary() lacks 'chap_password'"
            )

        # At least one summary should have message_authenticator
        ma_summaries = [c for c in creds if c.get("message_authenticator")]
        ma_creds = [c for c in listener.credentials if c.message_authenticator]
        if ma_creds:
            assert len(ma_summaries) >= 1, (
                "Credentials with message_authenticator exist but summary lacks the key"
            )

    def test_reject_response_correlation(self):
        """Access-Reject (code=3) should set auth_result='reject'."""
        listener = self._load_wireshark_listener()

        # The wireshark fixture has Access-Reject responses
        reject_creds = [c for c in listener.credentials if c.auth_result == "reject"]
        assert len(reject_creds) >= 1, (
            "Expected at least one credential with auth_result='reject'; "
            f"results seen: {[c.auth_result for c in listener.credentials]}"
        )

    def test_challenge_response_correlation(self):
        """Access-Challenge (code=11) should set auth_result='challenge'."""
        listener = self._load_wireshark_listener()

        challenge_creds = [c for c in listener.credentials if c.auth_result == "challenge"]
        assert len(challenge_creds) >= 1, (
            "Expected at least one credential with auth_result='challenge'; "
            f"results seen: {[c.auth_result for c in listener.credentials]}"
        )

    def test_interaction_operations(self):
        """Interactions should have descriptive RADIUS operation strings."""
        listener = self._load_wireshark_listener()

        ops = {ix.operation for ix in listener.interactions}
        assert "RADIUS Access-Request" in ops, f"Missing 'RADIUS Access-Request' in {ops}"
        assert any("Accept" in op or "Reject" in op or "Challenge" in op for op in ops), (
            f"Missing response operation in {ops}"
        )

    def test_both_devices_tracked(self):
        """Both RADIUS server and NAS client should be tracked as devices.

        Uses the generated fixture because the wireshark fixture uses 127.0.0.1
        for both endpoints, which is_valid_discovered_ip() rejects.
        """
        _skip_unless_pyshark()
        import importlib

        pcap = _pcap_path("radius/generated_radius.pcap")
        mod = importlib.import_module("oida.pcap.passive.radius")
        listener = mod.RADIUSPassiveListener(interface="lo", timeout=10)
        packets = _load_packets(pcap, display_filter="radius")
        listener.feed_packets(iter(packets))

        assert len(listener.credentials) >= 1, "Need credentials to verify device tracking"
        devices = listener.discovered_devices
        device_types = [getattr(d, "device_type", "") for d in devices.values()]
        assert any("Server" in t for t in device_types), (
            f"No RADIUS Server device found; types: {device_types}"
        )
        assert any("NAS" in t or "Client" in t for t in device_types), (
            f"No NAS/RADIUS Client device found; types: {device_types}"
        )


class TestRADIUSCredentialDataclass:
    """Test RADIUSCredential dataclass properties for scanner compatibility."""

    def test_pap_credential_properties(self):
        """PAP credential should have correct scanner-compatible properties."""
        from oida.pcap.passive.radius import RADIUSCredential

        cred = RADIUSCredential(
            username="testuser",
            realm="example.com",
            nas_identifier="nas1",
            nas_ip="10.0.0.1",
            calling_station="AA:BB:CC:DD:EE:FF",
            service_type="Login",
            authenticator="deadbeef" * 4,
            encrypted_password="aabbccdd" * 4,
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
        )
        assert cred.auth_method == "RADIUS-PAP"
        assert cred.credential_type == "hash"
        assert cred.password == "aabbccdd" * 4
        assert cred.hash_value == "aabbccdd" * 4
        assert cred.server_ip == "10.0.0.2"
        assert cred.client_ip == "10.0.0.1"

    def test_chap_credential_properties(self):
        """CHAP credential should use CHAP-Password for hash_value."""
        from oida.pcap.passive.radius import RADIUSCredential

        cred = RADIUSCredential(
            username="chapuser",
            realm="",
            nas_identifier="",
            nas_ip="10.0.0.1",
            calling_station="",
            service_type="Framed",
            authenticator="deadbeef" * 4,
            encrypted_password="",
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
            chap_password="a8" + "0574ae2c413a393f07b5564984bda740",
            chap_ident="168",
        )
        assert cred.auth_method == "RADIUS-CHAP"
        assert cred.password == "a8" + "0574ae2c413a393f07b5564984bda740"
        assert cred.hash_value == "a8" + "0574ae2c413a393f07b5564984bda740"

    def test_new_dataclass_fields_have_defaults(self):
        """New fields should have defaults so existing code is not broken."""
        from oida.pcap.passive.radius import RADIUSCredential

        cred = RADIUSCredential(
            username="u",
            realm="",
            nas_identifier="",
            nas_ip="",
            calling_station="",
            service_type="",
            authenticator="",
            encrypted_password="",
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
        )
        assert cred.chap_password == ""
        assert cred.chap_ident == ""
        assert cred.message_authenticator == ""
        assert cred.filter_id == ""
        assert cred.nas_port == ""
