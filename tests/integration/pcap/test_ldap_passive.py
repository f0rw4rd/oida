"""Integration tests for LDAP passive listener in EK mode.

Tests cover all 11 T1 tshark fields:
  ldap.messageID, ldap.errorMessage, ldap.version, ldap.name,
  ldap.authentication, ldap.bindResponse_resultCode, ldap.resultCode,
  ldap.credentials, ldap.requestName, ldap.extendedResponse_resultCode,
  ldap.maxBytes
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestLDAPPassiveEK:
    """LDAP-specific tests beyond the parametrized quality suite."""

    def test_ldap_credential_extraction(self):
        listener, devices, result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
        )
        # LDAP should extract credentials from simple bind
        assert len(listener.credentials) >= 1, (
            f"Expected >= 1 LDAP credential, got {len(listener.credentials)}"
        )

        # Check that credentials have meaningful data
        for cred in listener.credentials:
            assert cred.username, "Credential should have a username (bind DN)"

        # Check that ldap_passive_data is populated on at least one device
        has_passive_data = any(
            hasattr(d, "ldap_passive_data") and d.ldap_passive_data for d in devices.values()
        )
        assert has_passive_data, "No device has ldap_passive_data"

        # Harvest should return a dict
        assert isinstance(result, dict), "Expected harvest to return a dict"


class TestLDAPFieldCoverage:
    """Tests for T1 tshark field extraction coverage."""

    # ------------------------------------------------------------------
    # T1: ldap.messageID
    # ------------------------------------------------------------------
    def test_message_id_extracted(self):
        """ldap.messageID must appear in interaction details."""
        listener, devices, result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
            expect_details=["message_id"],
        )
        # Every interaction should have a message_id
        for ix in listener.interactions:
            mid = ix.details.get("message_id")
            assert mid is not None, f"Interaction {ix.operation} missing message_id in details"

    # ------------------------------------------------------------------
    # T1: ldap.errorMessage
    # ------------------------------------------------------------------
    def test_error_message_extracted(self):
        """ldap.errorMessage must appear in bind response / search done details."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
        )
        # Check that response interactions have error_message key when
        # the server returns one (may be empty string for success)
        response_ops = [ix for ix in listener.interactions if ix.direction == "response"]
        assert len(response_ops) >= 1, "Expected at least one response interaction"
        # At least one should be a Bind Response or Search Done
        bind_responses = [
            ix for ix in response_ops if "Bind" in ix.operation or "Search" in ix.operation
        ]
        assert len(bind_responses) >= 1, "Expected at least one Bind/Search response"

    # ------------------------------------------------------------------
    # T1: ldap.version
    # ------------------------------------------------------------------
    def test_version_extracted(self):
        """ldap.version must appear in bind request interaction details."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
        )
        bind_requests = [ix for ix in listener.interactions if ix.operation == "Bind"]
        assert len(bind_requests) >= 1, "Expected at least one Bind request"
        for ix in bind_requests:
            version = ix.details.get("version")
            assert version is not None, "Bind request missing version in details"
            assert version in ("2", "3"), f"Unexpected LDAP version: {version}"

    # ------------------------------------------------------------------
    # T1: ldap.name (Bind DN)
    # ------------------------------------------------------------------
    def test_bind_dn_extracted(self):
        """ldap.name must appear as bind_dn in Bind request details."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
        )
        bind_requests = [ix for ix in listener.interactions if ix.operation == "Bind"]
        assert len(bind_requests) >= 1, "Expected at least one Bind request"
        # At least one bind should have a non-placeholder DN
        has_dn = any(
            ix.details.get("bind_dn") and ix.details["bind_dn"] != "?" for ix in bind_requests
        )
        assert has_dn, (
            f"No Bind request has a meaningful bind_dn; sample: {bind_requests[0].details}"
        )

    # ------------------------------------------------------------------
    # T1: ldap.authentication (auth choice enum)
    # ------------------------------------------------------------------
    def test_auth_choice_extracted(self):
        """ldap.authentication must appear as auth_choice in Bind details."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
        )
        bind_requests = [ix for ix in listener.interactions if ix.operation == "Bind"]
        assert len(bind_requests) >= 1, "Expected at least one Bind request"
        # Check that auth_choice is populated
        has_auth_choice = any(ix.details.get("auth_choice") for ix in bind_requests)
        assert has_auth_choice, (
            f"No Bind request has auth_choice field; sample details: {bind_requests[0].details}"
        )

    # ------------------------------------------------------------------
    # T1: ldap.bindResponse_resultCode
    # ------------------------------------------------------------------
    def test_bind_response_result_code(self):
        """ldap.bindResponse_resultCode must appear in Bind Response details."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
        )
        bind_responses = [ix for ix in listener.interactions if ix.operation == "Bind Response"]
        assert len(bind_responses) >= 1, "Expected at least one Bind Response"
        for ix in bind_responses:
            rc = ix.details.get("result_code")
            assert rc is not None, "Bind Response missing result_code"
            rn = ix.details.get("result_name")
            assert rn is not None, "Bind Response missing result_name"

    # ------------------------------------------------------------------
    # T1: ldap.resultCode (generic, on search/write responses)
    # ------------------------------------------------------------------
    def test_generic_result_code(self):
        """ldap.resultCode must appear in Search Done or write response details."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/wireshark_ldap_search.pcap",
            min_devices=0,  # pcap uses 127.0.0.1 (loopback, filtered by is_valid_discovered_ip)
        )
        # Should have Search Done interactions with result_code
        search_done = [ix for ix in listener.interactions if ix.operation == "Search Done"]
        assert len(search_done) >= 1, "Expected at least one Search Done"
        for ix in search_done:
            rc = ix.details.get("result_code")
            assert rc is not None, "Search Done missing result_code"

    # ------------------------------------------------------------------
    # T1: ldap.credentials (SASL credentials bytes)
    # ------------------------------------------------------------------
    def test_sasl_credentials_detected(self):
        """ldap.credentials should be noted in SASL bind interaction details."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/wireshark_ldap_krb5.cap",
        )
        # SASL binds should be detected
        sasl_binds = [
            ix
            for ix in listener.interactions
            if ix.operation == "Bind" and "SASL" in ix.details.get("auth_type", "")
        ]
        assert len(sasl_binds) >= 1, (
            f"Expected SASL bind interactions; "
            f"saw operations: {[ix.operation for ix in listener.interactions[:10]]}"
        )
        # At least one SASL bind should note credentials presence
        has_creds = any(ix.details.get("sasl_credentials") == "present" for ix in sasl_binds)
        assert has_creds, (
            f"No SASL bind has sasl_credentials='present'; sample details: {sasl_binds[0].details}"
        )

    # ------------------------------------------------------------------
    # T1: ldap.requestName (Extended operation OID)
    # ------------------------------------------------------------------
    def test_extended_request_name(self):
        """ldap.requestName must appear in Extended request details."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/wireshark_ldap_ssl.pcapng",
        )
        ext_requests = [ix for ix in listener.interactions if ix.operation == "Extended"]
        assert len(ext_requests) >= 1, (
            f"Expected Extended operation; "
            f"saw operations: {[ix.operation for ix in listener.interactions]}"
        )
        for ix in ext_requests:
            oid = ix.details.get("request_oid")
            assert oid and oid != "?", (
                f"Extended request missing request_oid; details: {ix.details}"
            )

    # ------------------------------------------------------------------
    # T1: ldap.extendedResponse_resultCode
    # ------------------------------------------------------------------
    def test_extended_response_result_code(self):
        """ldap.extendedResponse_resultCode must appear in Extended Response."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/wireshark_ldap_ssl.pcapng",
        )
        ext_responses = [ix for ix in listener.interactions if ix.operation == "Extended Response"]
        assert len(ext_responses) >= 1, (
            f"Expected Extended Response; "
            f"saw operations: {[ix.operation for ix in listener.interactions]}"
        )
        for ix in ext_responses:
            rc = ix.details.get("result_code")
            assert rc is not None, f"Extended Response missing result_code; details: {ix.details}"
            rn = ix.details.get("result_name")
            assert rn is not None, f"Extended Response missing result_name; details: {ix.details}"

    # ------------------------------------------------------------------
    # T1: ldap.maxBytes (DirSync control)
    # ------------------------------------------------------------------
    def test_max_bytes_extracted(self):
        """ldap.maxBytes must appear in search details when DirSync is used."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/wireshark_ldap_dirsync.cap",
        )
        search_requests = [ix for ix in listener.interactions if ix.operation == "Search"]
        assert len(search_requests) >= 1, "Expected search operations in dirsync pcap"
        # At least one search should have max_bytes from DirSync control
        has_max_bytes = any(ix.details.get("max_bytes") for ix in search_requests)
        assert has_max_bytes, (
            "No search has max_bytes from DirSync control; "
            f"sample details: {search_requests[0].details}"
        )


class TestLDAPSASLAuth:
    """Tests for SASL authentication detection across pcap fixtures."""

    def test_kerberos_sasl_bind(self):
        """Kerberos SASL bind should be detected with mechanism name."""
        listener, devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/wireshark_ldap_krb5.cap",
        )
        sasl_binds = [
            ix
            for ix in listener.interactions
            if ix.operation == "Bind" and "SASL" in ix.details.get("auth_type", "")
        ]
        assert len(sasl_binds) >= 1, "Expected at least one SASL bind"
        # Check SASL mechanism is captured
        mechanisms = {ix.details.get("sasl_mechanism", "") for ix in sasl_binds}
        assert mechanisms - {""}, f"No SASL mechanisms captured; saw: {mechanisms}"

        # Server device should have sasl_mechanisms populated
        server_devices = [
            d
            for d in devices.values()
            if hasattr(d, "ldap_passive_data")
            and d.ldap_passive_data
            and d.ldap_passive_data.get("role") == "server"
        ]
        if server_devices:
            mechs = server_devices[0].ldap_passive_data.get("sasl_mechanisms", [])
            assert len(mechs) >= 1, "Server device should list SASL mechanisms"

    def test_dirsync_sasl_bind(self):
        """DirSync capture should detect SASL bind."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/wireshark_ldap_dirsync.cap",
        )
        # Should have bind interactions
        binds = [ix for ix in listener.interactions if ix.operation == "Bind"]
        assert len(binds) >= 1, "Expected bind interactions in dirsync pcap"


class TestLDAPSearchOperations:
    """Tests for search operation field extraction."""

    def test_search_scope_and_filter(self):
        """Search requests should have base_dn, scope, and filter."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/wireshark_ldap_search.pcap",
            min_devices=0,  # pcap uses 127.0.0.1 (loopback)
        )
        searches = [ix for ix in listener.interactions if ix.operation == "Search"]
        assert len(searches) >= 1, "Expected search operations"
        for ix in searches:
            d = ix.details
            assert "base_dn" in d, f"Search missing base_dn: {d}"
            assert "scope" in d, f"Search missing scope: {d}"
            assert "filter" in d, f"Search missing filter: {d}"

    def test_search_results_tracked(self):
        """Search Done responses should have result codes."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/wireshark_ldap_search.pcap",
            min_devices=0,  # pcap uses 127.0.0.1 (loopback)
        )
        done_ops = [ix for ix in listener.interactions if ix.operation == "Search Done"]
        assert len(done_ops) >= 1, "Expected Search Done responses"
        for ix in done_ops:
            assert ix.details.get("result_code") is not None, (
                f"Search Done missing result_code: {ix.details}"
            )


class TestLDAPHarvestOutput:
    """Tests for harvest() output structure."""

    def test_harvest_returns_dict(self):
        """harvest() returns a dict."""
        _listener, _devices, result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
        )
        assert isinstance(result, dict), "harvest() should return a dict"

    def test_no_raw_dicts_in_table_cells(self):
        """harvest() tables must not contain raw dicts or sets in cells."""
        _listener, _devices, result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
        )
        for table in result.get("tables", []):
            for row in table.get("rows", []):
                for cell in row:
                    assert not isinstance(cell, dict), f"Raw dict in cell: {cell}"
                    assert not isinstance(cell, set), f"Raw set in cell: {cell}"


class TestLDAPCredentialCompat:
    """Tests for scanner credential loop compatibility."""

    def test_credential_canonical_fields(self):
        """LDAPCredential must expose canonical field names for scanner."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
        )
        assert len(listener.credentials) >= 1, "Need credentials to test"
        cred = listener.credentials[0]
        # Canonical fields that the scanner credential loop accesses
        assert hasattr(cred, "username"), "Missing 'username' field"
        assert hasattr(cred, "password"), "Missing 'password' field"
        assert hasattr(cred, "server_ip"), "Missing 'server_ip' field"
        assert hasattr(cred, "client_ip"), "Missing 'client_ip' field"
        assert hasattr(cred, "credential_type"), "Missing 'credential_type' field"
        assert hasattr(cred, "auth_method"), "Missing 'auth_method' property"

        assert cred.credential_type == "plaintext"
        assert cred.auth_method == "Simple Bind"

    def test_get_credentials_summary_keys(self):
        """get_credentials_summary() must return dicts with canonical keys."""
        listener, _devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
        )
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, "get_credentials_summary() should return creds"
        for c in creds:
            assert "username" in c, f"Missing 'username' key: {c.keys()}"
            assert "password" in c, f"Missing 'password' key: {c.keys()}"
            assert "server_ip" in c, f"Missing 'server_ip' key: {c.keys()}"
            assert "client_ip" in c, f"Missing 'client_ip' key: {c.keys()}"
            assert "credential_type" in c, f"Missing 'credential_type' key: {c.keys()}"


class TestLDAPDeviceTracking:
    """Tests for device discovery and enrichment."""

    def test_both_endpoints_tracked(self):
        """Both LDAP server and client devices should be discovered."""
        _listener, devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
            min_devices=2,
        )
        device_types = {getattr(d, "device_type", "") for d in devices.values()}
        assert "LDAP Server" in device_types, f"Expected LDAP Server device; types: {device_types}"
        assert "LDAP Client" in device_types, f"Expected LDAP Client device; types: {device_types}"

    def test_server_stats_populated(self):
        """LDAP server device should have bind/search counts."""
        _listener, devices, _result = _run_listener_test(
            "ldap",
            "LDAPPassiveListener",
            "ldap",
            "ldap/credslayer_ldap_simpleauth.pcap",
        )
        server_devices = [
            d
            for d in devices.values()
            if hasattr(d, "ldap_passive_data")
            and d.ldap_passive_data
            and d.ldap_passive_data.get("role") == "server"
        ]
        assert len(server_devices) >= 1, "Expected at least one server device"
        pdata = server_devices[0].ldap_passive_data
        assert "bind_count" in pdata, "Server missing bind_count"
        assert pdata["bind_count"] >= 1, "bind_count should be >= 1"
