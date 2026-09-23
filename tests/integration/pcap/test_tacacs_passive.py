"""Integration tests for TACACS+ passive listener in EK mode.

Tests cover all T1 tshark field extractions and key T2 fields:
- T1: session_id, majvers, minvers, remote_address, authentication_type,
       service, user_len, address_len, authen_action, password_length
- T2: type (msg_type), seqno, flags_unencrypted, privilege_level, port
- Credential extraction with auth_method enrichment
- Device data enrichment (version, authen_type, service, priv_level)
- Interaction table via PROTOCOL_COLUMNS / _format_protocol_columns
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


def _get_listener():
    """Helper: run the tacacs listener and return (listener, devices, result)."""
    return _run_listener_test(
        "tacacs",
        "TACACSPassiveListener",
        "tacacs or tacplus",
        "tacacs/generated_tacacs.pcap",
        expect_details=["session_id", "authentication_type_name", "service_name"],
        expect_operations=["TACACS+"],
    )


class TestTACACSCredentials:
    """Credential extraction and scanner compatibility."""

    def test_credentials_extracted(self):
        listener, devices, result = _get_listener()
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected at least 1 credential, got {len(creds)}"
        for cred in creds:
            assert cred["protocol"] == "TACACS+"
            assert cred["username"], "Credential missing username"

    def test_credential_has_canonical_fields(self):
        """Scanner credential loop requires these exact keys."""
        listener, devices, result = _get_listener()
        creds = listener.get_credentials_summary()
        assert creds, "No credentials extracted"
        cred = creds[0]
        for key in (
            "username",
            "password",
            "credential_type",
            "auth_method",
            "server_ip",
            "client_ip",
        ):
            assert key in cred, f"Missing canonical key: {key}"

    def test_credential_auth_method_includes_authen_type(self):
        """auth_method should include the TACACS+ authentication type."""
        listener, devices, result = _get_listener()
        creds = listener.get_credentials_summary()
        assert creds, "No credentials extracted"
        # The fixture uses PAP authentication
        assert "PAP" in creds[0]["auth_method"], (
            f"auth_method should include authen type, got: {creds[0]['auth_method']}"
        )

    def test_credential_dataclass_properties(self):
        """TACACSCredential dataclass should have canonical @property aliases."""
        listener, devices, result = _get_listener()
        assert listener.credentials, "No credential objects"
        cred = listener.credentials[0]
        # Direct fields
        assert cred.username == "tacacsuser"
        assert cred.password == "tacacspass"
        assert cred.credential_type == "plaintext"
        assert cred.server_ip  # non-empty
        assert cred.client_ip  # non-empty
        # Property alias
        assert "TACACS+" in cred.auth_method

    def test_credential_enriched_with_session_data(self):
        """Credential object stores authen_type, privilege_level, session_id."""
        listener, devices, result = _get_listener()
        cred = listener.credentials[0]
        assert cred.authen_type == "PAP", f"Expected PAP, got {cred.authen_type}"
        assert cred.privilege_level == "15", f"Expected 15, got {cred.privilege_level}"
        assert cred.session_id, "session_id should be populated"


class TestTACACST1Fields:
    """T1 (high-value) tshark field extraction in interaction details."""

    def test_session_id_extracted(self):
        """tacplus.session_id should be in interaction details."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        sid = ix.details.get("session_id", "")
        assert sid and sid != "?", f"session_id not extracted: {sid}"

    def test_version_fields_extracted(self):
        """tacplus.majvers and tacplus.minvers should be extracted."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        majvers = ix.details.get("majvers", "")
        minvers = ix.details.get("minvers", "")
        assert majvers and majvers != "?", f"majvers not extracted: {majvers}"
        assert minvers is not None and str(minvers) != "?", f"minvers not extracted: {minvers}"

    def test_remote_address_extracted(self):
        """tacplus.remote_address should be in interaction details."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        ra = ix.details.get("remote_address", "")
        assert ra and ra != "?", f"remote_address not extracted: {ra}"
        # The fixture has remote_address = 192.168.1.100
        assert "192.168.1.100" in ra, f"Unexpected remote_address: {ra}"

    def test_authentication_type_extracted(self):
        """tacplus.authentication_type should be extracted and resolved."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        raw = ix.details.get("authentication_type", "")
        name = ix.details.get("authentication_type_name", "")
        assert raw and raw != "?", f"authentication_type not extracted: {raw}"
        assert name == "PAP", f"Expected PAP, got: {name}"

    def test_service_extracted(self):
        """tacplus.service should be extracted and resolved."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        raw = ix.details.get("service", "")
        name = ix.details.get("service_name", "")
        assert raw and raw != "?", f"service not extracted: {raw}"
        assert name == "Login", f"Expected Login, got: {name}"

    def test_authen_action_extracted(self):
        """tacplus.authen_action should be extracted and resolved."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        raw = ix.details.get("authen_action", "")
        name = ix.details.get("authen_action_name", "")
        assert raw and raw != "?", f"authen_action not extracted: {raw}"
        assert name == "Login", f"Expected Login, got: {name}"

    def test_user_len_extracted(self):
        """tacplus.user_len should be in interaction details."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        ul = ix.details.get("user_len", "")
        assert ul and ul != "?", f"user_len not extracted: {ul}"

    def test_address_len_extracted(self):
        """tacplus.address_len should be in interaction details."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        al = ix.details.get("address_len", "")
        assert al and al != "?", f"address_len not extracted: {al}"

    def test_password_length_extracted(self):
        """tacplus.password_length should be in interaction details."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        pl = ix.details.get("password_length", "")
        assert pl and pl != "?", f"password_length not extracted: {pl}"


class TestTACACST2Fields:
    """T2 (useful context) tshark field extraction."""

    def test_msg_type_extracted(self):
        """tacplus.type should be extracted and resolved to name."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        raw = ix.details.get("msg_type", "")
        name = ix.details.get("msg_type_name", "")
        assert raw and raw != "?", f"msg_type not extracted: {raw}"
        assert name == "Authentication", f"Expected Authentication, got: {name}"

    def test_seqno_extracted(self):
        """tacplus.seqno should be in interaction details."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        seq = ix.details.get("seqno", "")
        assert seq and seq != "?", f"seqno not extracted: {seq}"

    def test_flags_unencrypted_extracted(self):
        """tacplus.flags.unencrypted should be extracted (security-critical)."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        flag = ix.details.get("flags_unencrypted", "")
        assert flag and flag != "?", f"flags_unencrypted not extracted: {flag}"
        # The fixture uses unencrypted mode
        assert flag.lower() in ("true", "1"), f"Expected unencrypted=True, got: {flag}"

    def test_privilege_level_extracted(self):
        """tacplus.privilege_level should be in interaction details."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        pl = ix.details.get("privilege_level", "")
        assert pl and pl != "?", f"privilege_level not extracted: {pl}"
        assert pl == "15", f"Expected privilege level 15, got: {pl}"

    def test_port_extracted(self):
        """tacplus.port (terminal identifier) should be in details."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        port = ix.details.get("port", "")
        assert port and port != "?", f"port not extracted: {port}"


class TestTACACSDeviceEnrichment:
    """Device data should include protocol-specific fields."""

    def test_server_device_created(self):
        listener, devices, result = _get_listener()
        servers = [d for d in devices.values() if d.device_type == "AAA Server"]
        assert servers, "No AAA Server device created"

    def test_client_device_created(self):
        listener, devices, result = _get_listener()
        clients = [d for d in devices.values() if d.device_type == "Network Device"]
        assert clients, "No Network Device (client) created"

    def test_server_has_version(self):
        """Server device should have version from majvers/minvers."""
        listener, devices, result = _get_listener()
        servers = [d for d in devices.values() if d.device_type == "AAA Server"]
        assert servers
        data = getattr(servers[0], "tacacs_passive_data", {})
        assert "version" in data, f"Server missing version, data={data}"

    def test_client_has_authen_type(self):
        """Client device should have authen_type from authentication_type."""
        listener, devices, result = _get_listener()
        clients = [d for d in devices.values() if d.device_type == "Network Device"]
        assert clients
        data = getattr(clients[0], "tacacs_passive_data", {})
        assert data.get("authen_type") == "PAP", f"Client missing authen_type, data={data}"

    def test_client_has_service(self):
        """Client device should have service field."""
        listener, devices, result = _get_listener()
        clients = [d for d in devices.values() if d.device_type == "Network Device"]
        assert clients
        data = getattr(clients[0], "tacacs_passive_data", {})
        assert data.get("service") == "Login", f"Client missing service, data={data}"

    def test_client_has_privilege_level(self):
        """Client device should have privilege_level."""
        listener, devices, result = _get_listener()
        clients = [d for d in devices.values() if d.device_type == "Network Device"]
        assert clients
        data = getattr(clients[0], "tacacs_passive_data", {})
        assert data.get("privilege_level") == "15", f"Client missing privilege_level, data={data}"

    def test_client_has_remote_address(self):
        """Client device should have remote_address."""
        listener, devices, result = _get_listener()
        clients = [d for d in devices.values() if d.device_type == "Network Device"]
        assert clients
        data = getattr(clients[0], "tacacs_passive_data", {})
        assert data.get("remote_address"), f"Client missing remote_address, data={data}"

    def test_server_has_session_ids(self):
        """Server device should track session IDs."""
        listener, devices, result = _get_listener()
        servers = [d for d in devices.values() if d.device_type == "AAA Server"]
        assert servers
        data = getattr(servers[0], "tacacs_passive_data", {})
        assert "session_ids" in data, f"Server missing session_ids, data={data}"
        assert len(data["session_ids"]) >= 1


class TestTACACSInteractionTable:
    """Interaction table via PROTOCOL_COLUMNS / _format_protocol_columns."""

    def test_protocol_columns_set(self):
        from oida.pcap.tacacs import TACACSPassiveListener

        assert TACACSPassiveListener.PROTOCOL_COLUMNS
        assert len(TACACSPassiveListener.PROTOCOL_COLUMNS) == 8

    def test_harvest_returns_valid_dict(self):
        """harvest() should return a valid dict (no custom tables for TACACS)."""
        listener, devices, result = _get_listener()
        assert isinstance(result, dict)


class TestTACACSInteractionDetails:
    """Interaction recording quality."""

    def test_interaction_has_flow_id(self):
        listener, devices, result = _get_listener()
        for ix in listener.interactions:
            assert ix.flow_id, f"Interaction missing flow_id: {ix}"

    def test_interaction_direction_from_seqno(self):
        """Direction should be determined from sequence number parity."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        # seqno=1 (odd) -> request
        assert ix.direction == "request", f"Expected request, got {ix.direction}"

    def test_interaction_operation_descriptive(self):
        """Operation should be human-readable, not raw codes."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        assert "TACACS+" in ix.operation
        assert "Authentication" in ix.operation, (
            f"Operation should include message type: {ix.operation}"
        )

    def test_interaction_summary_complete(self):
        """Summary should include user, auth type, service, priv level."""
        listener, devices, result = _get_listener()
        ix = listener.interactions[0]
        assert "tacacsuser" in ix.summary
        assert "PAP" in ix.summary
        assert "Login" in ix.summary


class TestTACACSHarvestQuality:
    """harvest() output quality and scanner compatibility."""

    def test_harvest_returns_valid_dict(self):
        """harvest() should return a valid dict (no custom tables for TACACS)."""
        listener, devices, result = _get_listener()
        assert isinstance(result, dict)
