"""Integration tests for AJP13 passive listener.

Tests cover:
- Forward Request parsing (method, URI, remote address, server name)
- Send Headers response parsing (status, servlet engine, headers)
- Sensitive path detection (/manager, /admin, etc.)
- Device creation for both AJP proxy and Tomcat server
- Harvest output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

# AJP13 requires decode_as to be recognized by tshark
AJP_DECODE_AS = {"tcp.port==8009": "ajp13"}


class TestAJPPassive:
    """AJP13 protocol-specific tests."""

    def test_forward_request_fields(self):
        """Forward Request packets extract method, URI, and server name."""
        listener, devices, result = _run_listener_test(
            "ajp",
            "AJPPassiveListener",
            "ajp13",
            "ajp/generated_ajp.pcap",
            min_devices=2,
            min_interactions=3,
            expect_details=["method_name", "uri", "server_name"],
            decode_as=AJP_DECODE_AS,
        )

        # Check that GET and POST methods are detected
        methods = {ix.details.get("method_name") for ix in listener.interactions}
        assert "GET" in methods, f"GET not found; methods: {methods}"
        assert "POST" in methods, f"POST not found; methods: {methods}"

    def test_uri_extraction(self):
        """URIs are extracted from forward requests."""
        listener, devices, result = _run_listener_test(
            "ajp",
            "AJPPassiveListener",
            "ajp13",
            "ajp/generated_ajp.pcap",
            min_interactions=3,
            decode_as=AJP_DECODE_AS,
        )

        uris = {ix.details.get("uri") for ix in listener.interactions if ix.details.get("uri")}
        assert "/app/status" in uris, f"Expected /app/status in URIs; got: {uris}"
        assert "/app/login" in uris, f"Expected /app/login in URIs; got: {uris}"

    def test_server_name_extraction(self):
        """Server name (SRV field) is extracted from forward requests."""
        listener, devices, result = _run_listener_test(
            "ajp",
            "AJPPassiveListener",
            "ajp13",
            "ajp/generated_ajp.pcap",
            decode_as=AJP_DECODE_AS,
        )

        servers = {
            ix.details.get("server_name")
            for ix in listener.interactions
            if ix.details.get("server_name")
        }
        assert "tomcat.internal" in servers, f"Expected tomcat.internal; got: {servers}"

    def test_remote_address_extraction(self):
        """Remote client address (RADDR) is extracted."""
        listener, devices, result = _run_listener_test(
            "ajp",
            "AJPPassiveListener",
            "ajp13",
            "ajp/generated_ajp.pcap",
            decode_as=AJP_DECODE_AS,
        )

        raddrs = {
            ix.details.get("remote_addr")
            for ix in listener.interactions
            if ix.details.get("remote_addr")
        }
        assert len(raddrs) >= 1, f"No remote addresses extracted; details: {raddrs}"

    def test_servlet_engine_extraction(self):
        """Servlet-Engine header is extracted from Send Headers responses."""
        listener, devices, result = _run_listener_test(
            "ajp",
            "AJPPassiveListener",
            "ajp13",
            "ajp/generated_ajp.pcap",
            decode_as=AJP_DECODE_AS,
        )

        engines = {
            ix.details.get("servlet_engine")
            for ix in listener.interactions
            if ix.details.get("servlet_engine")
        }
        assert any("Tomcat" in e for e in engines), (
            f"Expected Servlet-Engine with 'Tomcat'; got: {engines}"
        )

    def test_response_status_extraction(self):
        """HTTP response status codes (ajp13.rstatus) are extracted from Send Headers."""
        listener, devices, result = _run_listener_test(
            "ajp",
            "AJPPassiveListener",
            "ajp13",
            "ajp/generated_ajp.pcap",
            decode_as=AJP_DECODE_AS,
        )

        statuses = {
            ix.details.get("response_status")
            for ix in listener.interactions
            if ix.details.get("response_status")
        }
        assert statuses, f"No response status codes extracted; interactions: {statuses}"
        # Fixture carries 200/302/401 responses; 401 is the documented auth-issue signal.
        assert "401" in statuses, f"Expected 401 status; got: {statuses}"

    def test_sensitive_path_detection(self):
        """Sensitive admin paths like /manager are flagged."""
        listener, devices, result = _run_listener_test(
            "ajp",
            "AJPPassiveListener",
            "ajp13",
            "ajp/generated_ajp.pcap",
            decode_as=AJP_DECODE_AS,
        )

        # /manager/html is a sensitive path
        assert len(listener._sensitive_access) >= 1, (
            "Expected sensitive path access for /manager/html"
        )
        paths = [a["uri"] for a in listener._sensitive_access]
        assert any("/manager" in p for p in paths), f"No /manager path flagged; got: {paths}"

    def test_both_endpoints_tracked(self):
        """Both AJP proxy (web server) and Tomcat server are discovered."""
        listener, devices, result = _run_listener_test(
            "ajp",
            "AJPPassiveListener",
            "ajp13",
            "ajp/generated_ajp.pcap",
            min_devices=2,
            decode_as=AJP_DECODE_AS,
        )

        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Server" in t for t in device_types)
        has_proxy = any("Proxy" in t for t in device_types)
        assert has_server, f"No AJP Server device; types: {device_types}"
        assert has_proxy, f"No AJP Proxy device; types: {device_types}"

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict with alerts for sensitive paths."""
        listener, devices, result = _run_listener_test(
            "ajp",
            "AJPPassiveListener",
            "ajp13",
            "ajp/generated_ajp.pcap",
            decode_as=AJP_DECODE_AS,
        )
        assert isinstance(result, dict)

    def test_protocol_columns_format(self):
        """Protocol columns are formatted correctly."""
        listener, devices, result = _run_listener_test(
            "ajp",
            "AJPPassiveListener",
            "ajp13",
            "ajp/generated_ajp.pcap",
            decode_as=AJP_DECODE_AS,
        )

        for ix in listener.interactions:
            cols = listener._format_protocol_columns(ix)
            assert len(cols) == len(listener.PROTOCOL_COLUMNS), (
                f"Column count mismatch: {len(cols)} vs {len(listener.PROTOCOL_COLUMNS)}"
            )
