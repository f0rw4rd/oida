"""Integration tests for PAP passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestPAPPassiveEK:
    """PAP-specific tests beyond the parametrised quality suite."""

    def test_pap_basic(self):
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
        )
        # PAP listener should extract credentials when present
        if listener.credentials:
            creds = listener.get_credentials_summary()
            assert len(creds) >= 1, "Expected at least one credential summary entry"
            for c in creds:
                assert c.get("protocol") == "PAP"
                assert c.get("auth_method") == "PAP"
                assert "username" in c

    def test_pap_identifier_extracted(self):
        """T1 field: pap.identifier must be extracted into interaction details."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
            expect_details=["identifier"],
        )
        # Verify identifier has a concrete value (not empty or "?")
        for ix in listener.interactions:
            ident = ix.details.get("identifier", "")
            assert ident, f"Interaction missing identifier: {ix.details}"
            assert ident != "?", f"Identifier is placeholder '?': {ix.details}"

    def test_pap_identifier_in_credential(self):
        """T1 field: pap.identifier must be stored on the PAPCredential dataclass."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
        )
        assert listener.credentials, "Expected at least one credential"
        for cred in listener.credentials:
            assert hasattr(cred, "identifier"), "PAPCredential missing 'identifier' field"
            assert cred.identifier, f"Credential identifier is empty: {cred}"
            assert cred.identifier != "?", f"Credential identifier is placeholder: {cred}"

    def test_pap_password_length_extracted(self):
        """T1 field: pap.password.length must be extracted into interaction details."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
            expect_details=["password_length"],
        )
        # Verify password_length has a numeric value
        for ix in listener.interactions:
            pwd_len = ix.details.get("password_length", "")
            if pwd_len:
                assert pwd_len.isdigit(), f"password_length not numeric: {pwd_len!r}"

    def test_pap_password_length_in_credential(self):
        """T1 field: pap.password.length must be stored on the PAPCredential."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
        )
        assert listener.credentials, "Expected at least one credential"
        for cred in listener.credentials:
            assert hasattr(cred, "password_length"), "PAPCredential missing 'password_length'"
            assert cred.password_length, f"Credential password_length is empty: {cred}"

    def test_pap_code_extracted(self):
        """T2 field: pap.code must be extracted and translated to human-readable name."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
            expect_details=["code", "code_name"],
        )
        for ix in listener.interactions:
            code = ix.details.get("code", "")
            code_name = ix.details.get("code_name", "")
            assert code, f"Interaction missing code: {ix.details}"
            assert code_name, f"Interaction missing code_name: {ix.details}"
            # Code 1 = Authenticate-Request
            if code == "1":
                assert "Request" in code_name, f"Auth-Request not in code_name: {code_name}"

    def test_pap_direction_from_code(self):
        """Direction should be 'request' for Auth-Request (code=1), 'response' for Ack/Nak."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
        )
        for ix in listener.interactions:
            code = ix.details.get("code", "")
            if code == "1":
                assert ix.direction == "request", "Auth-Request should be direction=request"
            elif code in ("2", "3"):
                assert ix.direction == "response", "Auth-Ack/Nak should be direction=response"

    def test_pap_harvest_returns_valid_dict(self):
        """harvest() should return a valid dict (no custom tables for PAP)."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
        )
        assert isinstance(result, dict)

    def test_pap_credential_scanner_compat(self):
        """Credential dataclass must expose canonical field names for scanner loop."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
        )
        assert listener.credentials, "Expected at least one credential"
        cred = listener.credentials[0]

        # Scanner credential loop canonical fields
        assert hasattr(cred, "username"), "Missing 'username' field"
        assert hasattr(cred, "password"), "Missing 'password' field"
        assert hasattr(cred, "credential_type"), "Missing 'credential_type' field"
        assert hasattr(cred, "server_ip"), "Missing 'server_ip' field"
        assert hasattr(cred, "client_ip"), "Missing 'client_ip' field"
        assert hasattr(cred, "auth_method"), "Missing 'auth_method' property"

        # Values should be populated
        assert cred.username, "username is empty"
        assert cred.password, "password is empty"
        assert cred.credential_type == "plaintext", (
            f"Expected 'plaintext', got {cred.credential_type!r}"
        )
        assert cred.auth_method == "PAP", f"Expected 'PAP', got {cred.auth_method!r}"

    def test_pap_credentials_summary_keys(self):
        """get_credentials_summary() must return dicts with harvest()-compatible keys."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
        )
        creds = listener.get_credentials_summary()
        assert creds, "Expected at least one credential summary"

        required_keys = {
            "protocol",
            "credential_type",
            "auth_method",
            "username",
            "server_ip",
            "client_ip",
        }
        for c in creds:
            missing = required_keys - set(c.keys())
            assert not missing, f"Credential summary missing keys: {missing}; got: {set(c.keys())}"

    def test_pap_interaction_details_completeness(self):
        """All T1/T2 fields should appear in interaction details for Auth-Request packets."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
        )
        assert listener.interactions, "No interactions recorded"

        # Find Auth-Request interactions
        auth_reqs = [ix for ix in listener.interactions if ix.details.get("code") == "1"]
        assert auth_reqs, "No Auth-Request interactions found"

        for ix in auth_reqs:
            d = ix.details
            # T1 fields
            assert "identifier" in d, f"Missing T1 field 'identifier': {d}"
            assert "password_length" in d, f"Missing T1 field 'password_length': {d}"
            # T2 fields
            assert "code" in d, f"Missing T2 field 'code': {d}"
            assert "code_name" in d, f"Missing T2 field 'code_name': {d}"
            assert "peer_id_length" in d, f"Missing T2 field 'peer_id_length': {d}"
            assert "pap_length" in d, f"Missing T2 field 'pap_length': {d}"

    def test_pap_harvest_no_raw_types(self):
        """No raw dicts, sets, or lists in table cells."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
            check_harvest=True,
        )
        # _run_listener_test already checks this, but be explicit
        for table in result.get("tables", []):
            for row in table.get("rows", []):
                for cell in row:
                    assert not isinstance(cell, (dict, set, list)), (
                        f"Raw collection type in table cell: {type(cell).__name__}: {cell}"
                    )

    def test_pap_operation_names(self):
        """Interaction operations should use descriptive names with code type."""
        listener, devices, result = _run_listener_test(
            "pap",
            "PAPPassiveListener",
            "pap",
            "pap/generated_pap.pcap",
            min_devices=0,
        )
        for ix in listener.interactions:
            assert ix.operation, f"Empty operation string: {ix}"
            # Should contain "PAP" prefix
            assert "PAP" in ix.operation, f"Operation missing 'PAP' prefix: {ix.operation}"
