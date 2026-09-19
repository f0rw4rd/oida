"""Integration tests for RTSP passive listener.

Tests cover:
- Request method extraction (OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN)
- Response status code extraction
- Stream URL extraction
- Session ID extraction
- Transport parameter extraction
- Server header fingerprinting
- User-Agent extraction
- Basic auth credential extraction
- Digest auth username extraction
- Camera/server device tracking
- Client device tracking
- Multiple client detection
- Harvest table output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestRTSPPassiveEK:
    """RTSP-specific tests beyond the parametrized quality suite."""

    def test_rtsp_method_extraction(self):
        """RTSP request methods are extracted from packets."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            min_interactions=4,
            expect_details=["method"],
        )
        methods = {
            ix.details.get("method", "") for ix in listener.interactions if ix.details.get("method")
        }
        # Should see multiple RTSP methods
        assert len(methods) >= 3, f"Expected >= 3 distinct methods; got: {methods}"

    def test_rtsp_options_detected(self):
        """OPTIONS method is detected."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            expect_operations=["RTSP OPTIONS"],
        )

    def test_rtsp_describe_detected(self):
        """DESCRIBE method is detected."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            expect_operations=["RTSP DESCRIBE"],
        )

    def test_rtsp_setup_detected(self):
        """SETUP method is detected."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            expect_operations=["RTSP SETUP"],
        )

    def test_rtsp_play_detected(self):
        """PLAY method is detected."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            expect_operations=["RTSP PLAY"],
        )

    def test_rtsp_teardown_detected(self):
        """TEARDOWN method is detected."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            expect_operations=["RTSP TEARDOWN"],
        )

    def test_rtsp_url_extraction(self):
        """Stream URLs are extracted from RTSP requests."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            min_interactions=4,
        )
        urls = {ix.details.get("url", "") for ix in listener.interactions if ix.details.get("url")}
        assert len(urls) >= 1, f"Expected at least 1 URL; got: {urls}"
        assert any("rtsp://" in u for u in urls), f"No rtsp:// URL found; got: {urls}"

    def test_rtsp_session_extraction(self):
        """Session IDs are extracted from RTSP headers."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            min_interactions=4,
        )
        sessions = {
            ix.details.get("session", "")
            for ix in listener.interactions
            if ix.details.get("session")
        }
        assert len(sessions) >= 1, "No session IDs extracted"

    def test_rtsp_server_header(self):
        """Server header is extracted from RTSP responses.

        The listener pulls Server/User-Agent/Authorization from the generic
        EK "text" field (header lines without registered dissectors) in EK
        mode, and from unnamed fields in XML mode.
        """
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            min_interactions=4,
        )
        servers = {
            ix.details.get("server", "") for ix in listener.interactions if ix.details.get("server")
        }
        assert len(servers) >= 1, "No server headers extracted"
        assert any("Hikvision" in s for s in servers), (
            f"Expected Hikvision server header; got: {servers}"
        )

    def test_rtsp_basic_auth_credentials(self):
        """Basic auth credentials are extracted from Authorization header.

        Requires XML mode; EK mode does not expose Authorization as a
        named RTSP field.
        """
        from .conftest import _ek_mode_available

        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            min_interactions=4,
        )
        creds = listener.get_credentials_summary()
        basic_creds = [c for c in creds if c.get("auth_method") == "RTSP-Basic"]
        if _ek_mode_available and not basic_creds:
            pytest.skip("RTSP Authorization header not available in EK mode")
        assert len(basic_creds) >= 1, f"Expected at least 1 Basic auth credential; got: {creds}"
        usernames = [c.get("username", "") for c in basic_creds]
        assert "admin" in usernames, f"Expected 'admin' in credentials; got: {usernames}"

    def test_rtsp_digest_auth_username(self):
        """Digest auth username is extracted from Authorization header.

        Requires XML mode; EK mode does not expose Authorization as a
        named RTSP field.
        """
        from .conftest import _ek_mode_available

        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            min_interactions=4,
        )
        creds = listener.get_credentials_summary()
        digest_creds = [c for c in creds if c.get("auth_method") == "RTSP-Digest"]
        if _ek_mode_available and not digest_creds:
            pytest.skip("RTSP Authorization header not available in EK mode")
        assert len(digest_creds) >= 1, f"Expected at least 1 Digest auth credential; got: {creds}"
        usernames = [c.get("username", "") for c in digest_creds]
        assert "operator" in usernames, f"Expected 'operator' in credentials; got: {usernames}"

    def test_rtsp_camera_device_tracked(self):
        """IP camera (RTSP server) is tracked as a device."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            min_devices=2,
        )
        camera_devices = [
            d
            for d in devices.values()
            if hasattr(d, "device_type") and "Camera" in (d.device_type or "")
        ]
        assert len(camera_devices) >= 1, (
            f"Expected at least 1 camera device; types: {[d.device_type for d in devices.values()]}"
        )

    def test_rtsp_client_device_tracked(self):
        """RTSP client is tracked as a device."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            min_devices=2,
        )
        client_devices = [
            d
            for d in devices.values()
            if hasattr(d, "device_type") and "Client" in (d.device_type or "")
        ]
        assert len(client_devices) >= 1, (
            f"Expected at least 1 client device; types: {[d.device_type for d in devices.values()]}"
        )

    def test_rtsp_operation_prefix(self):
        """All RTSP operations start with 'RTSP'."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            assert ix.operation.startswith("RTSP"), (
                f"Operation should start with 'RTSP'; got: {ix.operation}"
            )

    def test_rtsp_harvest_valid(self):
        """Harvest returns a valid dict."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            check_harvest=True,
        )
        assert isinstance(result, dict)

    def test_rtsp_protocol_columns_format(self):
        """Protocol columns return correct number of values."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            cols = listener._format_protocol_columns(ix)
            assert len(cols) == len(listener.PROTOCOL_COLUMNS), (
                f"Expected {len(listener.PROTOCOL_COLUMNS)} columns, got {len(cols)}: {cols}"
            )

    def test_rtsp_passive_data_fields(self):
        """Device rtsp_passive_data contains expected fields."""
        listener, devices, result = _run_listener_test(
            "rtsp",
            "RTSPPassiveListener",
            "rtsp",
            "rtsp/generated_rtsp.pcap",
            min_devices=2,
        )
        for d in devices.values():
            data = getattr(d, "rtsp_passive_data", None)
            if data:
                assert "role" in data, f"Missing 'role' in rtsp_passive_data: {data}"
                assert "protocol" in data, f"Missing 'protocol' in rtsp_passive_data: {data}"
