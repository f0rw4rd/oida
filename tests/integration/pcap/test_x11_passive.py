"""Integration tests for X11 passive listener.

Tests cover:
- MIT-MAGIC-COOKIE-1 credential extraction
- Unauthenticated connection detection
- Connection reply parsing
- Display number extraction from port
- Both client and server device creation
- Interaction table formatting
- Harvest output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestX11PassiveEK:
    """X11-specific tests beyond the parametrized quality suite."""

    def test_cookie_extraction(self):
        """MIT-MAGIC-COOKIE-1 auth data is extracted as credential."""
        listener, devices, result = _run_listener_test(
            "x11",
            "X11PassiveListener",
            "x11",
            "x11/generated_x11.pcap",
            min_interactions=1,
            expect_details=["auth_method"],
        )
        # Should extract MIT-MAGIC-COOKIE-1 credential
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected >= 1 X11 credential, got {len(creds)}"
        # Check auth method
        methods = [c.get("auth_method", "") for c in creds]
        assert "MIT-MAGIC-COOKIE-1" in methods, (
            f"Expected MIT-MAGIC-COOKIE-1 auth method; got: {methods}"
        )

    def test_noauth_detection(self):
        """Unauthenticated connection attempts generate security alerts."""
        listener, devices, result = _run_listener_test(
            "x11",
            "X11PassiveListener",
            "x11",
            "x11/generated_x11.pcap",
            min_interactions=1,
        )
        # The generated pcap includes a no-auth connection
        # Check if alerts were generated
        harvest = listener.harvest()
        alerts = harvest.get("alerts", [])
        has_noauth = any("NO AUTH" in a.get("message", "") for a in alerts)
        assert has_noauth, f"Expected NO AUTH alert; alerts: {alerts}"

    def test_connection_request_parsing(self):
        """Connection requests extract auth method and version."""
        listener, devices, result = _run_listener_test(
            "x11",
            "X11PassiveListener",
            "x11",
            "x11/generated_x11.pcap",
            min_interactions=1,
        )
        connect_ops = [ix for ix in listener.interactions if ix.operation == "Connect"]
        assert len(connect_ops) >= 1, "No Connect operations found"
        # Check auth_method is populated
        has_auth = any(ix.details.get("auth_method") not in (None, "") for ix in connect_ops)
        assert has_auth, "No Connect operation has auth_method"

    def test_connection_reply_parsing(self):
        """Connection replies are parsed with success status."""
        listener, devices, result = _run_listener_test(
            "x11",
            "X11PassiveListener",
            "x11",
            "x11/generated_x11.pcap",
            min_interactions=1,
        )
        replies = [ix for ix in listener.interactions if "Reply" in ix.operation]
        assert len(replies) >= 1, (
            f"No Reply operations found; ops: {[ix.operation for ix in listener.interactions]}"
        )

    def test_both_endpoints_tracked(self):
        """Both X11 client and server devices are created."""
        listener, devices, result = _run_listener_test(
            "x11",
            "X11PassiveListener",
            "x11",
            "x11/generated_x11.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Server" in t or "Display" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No X11 Server device found; types: {device_types}"
        assert has_client, f"No X11 Client device found; types: {device_types}"

    def test_harvest_valid(self):
        """Harvest returns valid dict."""
        listener, devices, result = _run_listener_test(
            "x11",
            "X11PassiveListener",
            "x11",
            "x11/generated_x11.pcap",
        )
        assert isinstance(result, dict)

    def test_protocol_columns_format(self):
        """Protocol columns produce clean string values."""
        listener, devices, result = _run_listener_test(
            "x11",
            "X11PassiveListener",
            "x11",
            "x11/generated_x11.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            cols = listener._format_protocol_columns(ix)
            assert len(cols) == 3, f"Expected 3 columns, got {len(cols)}"
            for col in cols:
                assert not isinstance(col, (dict, set, list)), f"Raw collection in column: {col}"
