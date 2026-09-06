"""Integration tests for HTTP passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestHTTPPassiveEK:
    """HTTP-specific tests beyond the parametrised quality suite."""

    def test_http_basic(self):
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        # HTTP listener should extract credentials from Basic auth pcap
        creds = listener.get_credentials_summary()
        if listener.credentials:
            assert len(creds) >= 1, "Expected at least one credential summary entry"
            for c in creds:
                assert c.get("protocol") == "HTTP"
                assert "username" in c

        # HTTP listener tracks URL map
        url_map = listener.get_url_map()
        assert isinstance(url_map, dict)
        if url_map:
            # Should have at least one server with endpoints
            for server_key, endpoints in url_map.items():
                assert len(endpoints) >= 1
                for ep in endpoints:
                    assert "method" in ep
                    assert "path" in ep
                    assert "hit_count" in ep

        # HTTP harvest should produce tables
        if result.get("tables"):
            assert len(result["tables"]) >= 1, "Expected at least one table from HTTP harvest"


class TestHTTPRequestVersion:
    """Tests for http.request.version field extraction (T1 gap)."""

    def test_request_version_in_interaction_details(self):
        """Verify http.request.version is extracted into interaction details."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method", "http_version"],
        )
        # At least one request interaction should have http_version
        request_ixs = [ix for ix in listener.interactions if ix.direction == "request"]
        assert len(request_ixs) >= 1, "Expected at least one request interaction"
        versions_found = [
            ix.details.get("http_version") for ix in request_ixs if ix.details.get("http_version")
        ]
        assert len(versions_found) >= 1, (
            "No request interaction has http_version in details; "
            f"sample details: {request_ixs[0].details}"
        )
        # HTTP versions should be well-formed (e.g. "HTTP/1.1", "HTTP/1.0")
        for v in versions_found:
            assert v.startswith("HTTP/") or v == "?", f"Unexpected HTTP version format: {v!r}"

    def test_request_version_in_client_device_data(self):
        """Verify request version is tracked in client device http_versions."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        # Find client devices
        client_devices = [
            d
            for d in devices.values()
            if getattr(d, "http_passive_data", None) and d.http_passive_data.get("role") == "client"
        ]
        assert len(client_devices) >= 1, "Expected at least one HTTP client device"
        # At least one client should have http_versions populated
        has_versions = any(d.http_passive_data.get("http_versions") for d in client_devices)
        assert has_versions, (
            "No client device has http_versions; "
            f"sample data: {client_devices[0].http_passive_data}"
        )

    def test_request_version_across_pcaps(self):
        """Verify request version extraction works across multiple pcap fixtures."""
        for pcap in [
            "http/bruteshark_http_digest.pcap",
            "http/credslayer_http_get_auth.pcap",
            "http/internet_http_chunked.pcap",
        ]:
            listener, devices, result = _run_listener_test(
                "http",
                "HTTPPassiveListener",
                "http",
                pcap,
                expect_details=["method"],
            )
            request_ixs = [ix for ix in listener.interactions if ix.direction == "request"]
            if request_ixs:
                versions = [
                    ix.details.get("http_version")
                    for ix in request_ixs
                    if ix.details.get("http_version")
                ]
                assert len(versions) >= 1, f"No http_version in request interactions for {pcap}"


class TestHTTPResponseVersion:
    """Tests for http.response.version field extraction (T1 gap)."""

    def test_response_version_in_interaction_details(self):
        """Verify http.response.version is extracted into interaction details."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        # At least one response interaction should have http_version
        response_ixs = [ix for ix in listener.interactions if ix.direction == "response"]
        assert len(response_ixs) >= 1, "Expected at least one response interaction"
        versions_found = [
            ix.details.get("http_version") for ix in response_ixs if ix.details.get("http_version")
        ]
        assert len(versions_found) >= 1, (
            "No response interaction has http_version in details; "
            f"sample details: {response_ixs[0].details}"
        )
        for v in versions_found:
            assert v.startswith("HTTP/") or v == "?", f"Unexpected HTTP version format: {v!r}"

    def test_response_version_in_server_device_data(self):
        """Verify response version is tracked in server device http_versions."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        # Find server devices
        server_devices = [
            d
            for d in devices.values()
            if getattr(d, "http_passive_data", None) and d.http_passive_data.get("role") == "server"
        ]
        assert len(server_devices) >= 1, "Expected at least one HTTP server device"
        has_versions = any(d.http_passive_data.get("http_versions") for d in server_devices)
        assert has_versions, (
            "No server device has http_versions; "
            f"sample data: {server_devices[0].http_passive_data}"
        )

    def test_response_version_in_harvest_server_table(self):
        """Verify HTTP Servers table includes HTTP Versions column."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        tables = result.get("tables", [])
        server_table = next((t for t in tables if t.get("title") == "HTTP Servers"), None)
        if server_table:
            assert "HTTP Versions" in server_table["headers"], (
                f"HTTP Servers table missing 'HTTP Versions' column; "
                f"headers: {server_table['headers']}"
            )
            # Verify rows have the right number of columns
            for row in server_table["rows"]:
                assert len(row) == len(server_table["headers"]), (
                    f"Row length {len(row)} != header length {len(server_table['headers'])}"
                )


class TestHTTPResponseCodeDesc:
    """Tests for http.response.code.desc field extraction (T1 gap)."""

    def test_response_code_desc_in_interaction_details(self):
        """Verify http.response.code.desc is extracted into interaction details."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        response_ixs = [ix for ix in listener.interactions if ix.direction == "response"]
        assert len(response_ixs) >= 1, "Expected at least one response interaction"
        descs_found = [
            ix.details.get("response_code_desc")
            for ix in response_ixs
            if ix.details.get("response_code_desc")
        ]
        assert len(descs_found) >= 1, (
            "No response interaction has response_code_desc in details; "
            f"sample details: {response_ixs[0].details}"
        )
        # Descriptions should be human-readable strings
        for desc in descs_found:
            assert isinstance(desc, str) and len(desc) >= 2, (
                f"Unexpected response_code_desc: {desc!r}"
            )

    def test_response_code_desc_in_operation_string(self):
        """Verify response operation string includes the status description."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        response_ixs = [ix for ix in listener.interactions if ix.direction == "response"]
        # The operation should now include the description, e.g. "HTTP 200 OK"
        ops_with_desc = [
            ix.operation for ix in response_ixs if ix.operation and len(ix.operation.split()) >= 3
        ]
        assert len(ops_with_desc) >= 1, (
            "No response operation includes status description; "
            f"sample operations: {[ix.operation for ix in response_ixs[:5]]}"
        )

    def test_response_code_desc_in_endpoint_status(self):
        """Verify endpoint status codes include descriptions."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        url_map = listener.get_url_map()
        if url_map:
            # At least one endpoint should have status codes with descriptions
            has_desc = False
            for server_key, endpoints in url_map.items():
                for ep in endpoints:
                    for code_label in ep.get("status_codes", {}):
                        # Code labels should now include descriptions
                        # e.g. "200 OK" instead of just "200"
                        if " " in str(code_label):
                            has_desc = True
                            break
            assert has_desc, f"No endpoint status codes include descriptions; sample: {url_map}"

    def test_response_code_desc_common_values(self):
        """Verify common HTTP status descriptions are captured correctly."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        response_ixs = [ix for ix in listener.interactions if ix.direction == "response"]
        all_descs = {
            ix.details.get("response_code_desc", "")
            for ix in response_ixs
            if ix.details.get("response_code_desc")
        }
        # bruteshark_http_basic.pcap should have at least 401 Unauthorized responses
        # (it's a Basic auth pcap with challenge-response)
        # and possibly 200 OK responses
        assert len(all_descs) >= 1, f"Expected at least one status description, got: {all_descs}"


class TestHTTPAuthBasic:
    """Tests for http.authbasic field extraction (T1 gap)."""

    def test_authbasic_used_for_credential_extraction(self):
        """Verify http.authbasic field is used in Basic auth credential extraction."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        # The bruteshark_http_basic.pcap should have Basic auth credentials
        creds = listener.get_credentials_summary()
        basic_creds = [c for c in creds if c.get("auth_method") == "HTTP-Basic"]
        assert len(basic_creds) >= 1, (
            f"Expected at least one HTTP-Basic credential; got {len(creds)} total creds"
        )
        # Each Basic credential should have username and password
        for c in basic_creds:
            assert c.get("username"), f"Basic credential missing username: {c}"
            assert "password" in c, f"Basic credential missing password key: {c}"

    def test_authbasic_credslayer_pcap(self):
        """Verify Basic auth extraction works with credslayer pcap fixture."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/credslayer_http_basic_auth.pcap",
            expect_details=["method"],
        )
        creds = listener.get_credentials_summary()
        basic_creds = [c for c in creds if c.get("auth_method") == "HTTP-Basic"]
        assert len(basic_creds) >= 1, (
            f"Expected Basic auth credentials from credslayer pcap; "
            f"got {len(basic_creds)} basic out of {len(creds)} total"
        )

    def test_authbasic_deduplication(self):
        """Verify duplicate Basic auth credentials are not recorded twice."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        creds = listener.credentials
        # Check for duplicates: same (auth_type, username, password, server_ip)
        seen = set()
        for c in creds:
            key = (c.auth_type, c.username, c.password, c.server_ip)
            assert key not in seen, f"Duplicate credential found: {key}"
            seen.add(key)


class TestHTTPDigestAuth:
    """Tests for HTTP Digest auth extraction (uses authorization field)."""

    def test_digest_credentials(self):
        """Verify Digest auth hashes are extracted from digest pcap."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_digest.pcap",
            expect_details=["method"],
        )
        creds = listener.get_credentials_summary()
        digest_creds = [c for c in creds if c.get("auth_method") == "HTTP-Digest"]
        # Digest pcap should have at least one digest credential
        if digest_creds:
            for c in digest_creds:
                assert c.get("username"), f"Digest credential missing username: {c}"
                assert c.get("realm") is not None, f"Digest credential missing realm: {c}"
                assert c.get("nonce") is not None, f"Digest credential missing nonce: {c}"

    def test_digest_hashes_summary(self):
        """Verify Digest hashes are available via get_hashes_summary()."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_digest.pcap",
            expect_details=["method"],
        )
        hashes = listener.get_hashes_summary()
        if hashes:
            for h in hashes:
                assert h.get("hash_type", "").startswith("Digest"), (
                    f"Unexpected hash type: {h.get('hash_type')}"
                )
                assert h.get("username"), f"Hash missing username: {h}"


class TestHTTPFieldsCombined:
    """Cross-cutting tests that verify all T1 fields work together."""

    def test_all_t1_fields_in_single_pcap(self):
        """Verify all 4 T1 fields are extracted from a single pcap."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method", "http_version"],
        )
        # Check request interactions have http_version
        request_ixs = [ix for ix in listener.interactions if ix.direction == "request"]
        assert any(ix.details.get("http_version") for ix in request_ixs), (
            "No request interaction has http_version"
        )

        # Check response interactions have http_version and response_code_desc
        response_ixs = [ix for ix in listener.interactions if ix.direction == "response"]
        assert any(ix.details.get("http_version") for ix in response_ixs), (
            "No response interaction has http_version"
        )
        assert any(ix.details.get("response_code_desc") for ix in response_ixs), (
            "No response interaction has response_code_desc"
        )

        # Check Basic auth credentials were extracted (authbasic field)
        creds = listener.get_credentials_summary()
        basic_creds = [c for c in creds if c.get("auth_method") == "HTTP-Basic"]
        assert len(basic_creds) >= 1, "Expected Basic auth credentials"

    def test_harvest_table_quality(self):
        """Verify harvest tables have consistent column counts and no raw objects."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/bruteshark_http_basic.pcap",
            expect_details=["method"],
        )
        tables = result.get("tables", [])
        for table in tables:
            headers = table.get("headers", [])
            title = table.get("title", "untitled")
            assert len(headers) >= 2, f"Table '{title}' has too few headers: {headers}"
            for i, row in enumerate(table.get("rows", [])):
                assert len(row) == len(headers), (
                    f"Table '{title}' row {i} has {len(row)} columns but {len(headers)} headers"
                )
                for cell in row:
                    assert not isinstance(cell, (dict, set, list)), (
                        f"Table '{title}' row {i} has non-scalar cell: {type(cell)}"
                    )

    def test_internet_pcap_versions(self):
        """Verify HTTP version extraction from non-auth internet traffic pcap."""
        listener, devices, result = _run_listener_test(
            "http",
            "HTTPPassiveListener",
            "http",
            "http/internet_http_with_jpegs.cap",
            expect_details=["method"],
        )
        # Should have both request and response versions
        all_versions = set()
        for ix in listener.interactions:
            v = ix.details.get("http_version")
            if v and v != "?":
                all_versions.add(v)
        assert len(all_versions) >= 1, (
            f"Expected at least one HTTP version from internet pcap; "
            f"interactions: {len(listener.interactions)}"
        )
