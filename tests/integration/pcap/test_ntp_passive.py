"""Integration tests for NTP passive listener.

Tests cover:
- NTP version and mode extraction
- Stratum and reference ID resolution
- Root delay/dispersion extraction
- Server and client device tracking
- Leap indicator extraction
- Poll interval and precision fields
- Server info tracking
- Harvest output quality
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestNTPPassive:
    """NTP-specific tests beyond the parametrized quality suite."""

    def test_ntp_basic_extraction(self):
        """Basic NTP field extraction from real NTP traffic."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
            min_devices=2,
            min_interactions=2,
            expect_details=["version", "mode_name", "stratum"],
        )
        assert len(listener.interactions) >= 2, (
            f"Expected >= 2 NTP interactions, got {len(listener.interactions)}"
        )

    def test_ntp_version_extracted(self):
        """NTP version is extracted from packets."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
            expect_details=["version"],
        )
        versions = {ix.details.get("version") for ix in listener.interactions}
        assert versions, "No NTP versions extracted"
        # The filtered_ntp.pcap should contain NTPv3 traffic
        assert "3" in versions, f"Expected NTPv3 in versions; got: {versions}"

    def test_ntp_mode_client_server(self):
        """Both client and server modes are detected."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
            min_interactions=2,
        )
        modes = {ix.details.get("mode_name") for ix in listener.interactions}
        assert "client" in modes, f"Expected 'client' mode; got: {modes}"
        assert "server" in modes, f"Expected 'server' mode; got: {modes}"

    def test_ntp_stratum_extracted(self):
        """Stratum values are extracted from server responses."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
            expect_details=["stratum"],
        )
        strata = {
            ix.details.get("stratum")
            for ix in listener.interactions
            if ix.details.get("stratum") != "?"
        }
        assert strata, "No stratum values extracted"

    def test_ntp_refid_extracted(self):
        """Reference ID is extracted from NTP packets."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
            expect_details=["refid"],
        )
        refids = {
            ix.details.get("refid") for ix in listener.interactions if ix.details.get("refid")
        }
        assert refids, "No reference IDs extracted"

    def test_ntp_root_delay_extracted(self):
        """Root delay is extracted from NTP packets."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
            expect_details=["root_delay"],
        )
        has_delay = any(
            ix.details.get("root_delay") not in (None, "", "?") for ix in listener.interactions
        )
        assert has_delay, "No root delay values extracted"

    def test_ntp_root_dispersion_extracted(self):
        """Root dispersion is extracted from NTP packets."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
            expect_details=["root_dispersion"],
        )
        has_dispersion = any(
            ix.details.get("root_dispersion") not in (None, "", "?") for ix in listener.interactions
        )
        assert has_dispersion, "No root dispersion values extracted"

    def test_ntp_direction_correct(self):
        """Client packets are requests, server packets are responses."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
            min_interactions=2,
        )
        for ix in listener.interactions:
            mode = ix.details.get("mode_name", "")
            if mode == "client":
                assert ix.direction == "request", (
                    f"Client mode should be request direction, got {ix.direction}"
                )
            elif mode == "server":
                assert ix.direction == "response", (
                    f"Server mode should be response direction, got {ix.direction}"
                )

    def test_ntp_both_endpoints_tracked(self):
        """Both NTP server and client devices are created."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Server" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No NTP Server device found; types: {device_types}"
        assert has_client, f"No NTP Client device found; types: {device_types}"

    def test_ntp_server_info_tracked(self):
        """Server info dict is populated for NTP servers."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
            min_interactions=2,
        )
        # Server responses should populate server_info
        assert len(listener.server_info) >= 1, (
            f"Expected >= 1 server in server_info, got {len(listener.server_info)}"
        )
        for ip, info in listener.server_info.items():
            assert "stratum" in info, f"Server {ip} missing 'stratum' in server_info"
            assert "version" in info, f"Server {ip} missing 'version' in server_info"

    def test_ntp_leap_indicator_extracted(self):
        """Leap indicator is extracted from NTP packets."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
        )
        has_leap = any(ix.details.get("leap_indicator") is not None for ix in listener.interactions)
        assert has_leap, "No leap indicator values extracted"

    def test_ntp_poll_interval_extracted(self):
        """Poll interval is extracted from NTP packets."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
            expect_details=["poll_interval"],
        )
        has_poll = any(
            ix.details.get("poll_interval") not in (None, "") for ix in listener.interactions
        )
        assert has_poll, "No poll interval values extracted"

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict."""
        listener, devices, result = _run_listener_test(
            "ntp",
            "NTPPassiveListener",
            "ntp",
            "ntp/filtered_ntp.pcap",
        )
        assert isinstance(result, dict)
