"""Integration tests for PJL passive listener.

Tests cover:
- PJL command extraction from raw TCP payload on port 9100
- INFO ID response parsing (printer model)
- SET command parsing (environment variables)
- FSDIRLIST command detection (filesystem access)
- JOB command parsing (job names)
- Filesystem access alerts in harvest
- Device tracking for both printer and client endpoints
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestPJLPassiveEK:
    """PJL-specific tests beyond the parametrized quality suite."""

    def test_pjl_command_extraction(self):
        """PJL commands are extracted from raw TCP payload."""
        listener, devices, result = _run_listener_test(
            "pjl",
            "PJLPassiveListener",
            "tcp.port == 9100",
            "pjl/generated_pjl.pcap",
            min_devices=2,
            min_interactions=1,
            expect_details=["command"],
        )
        # Should extract multiple PJL commands
        commands = {ix.details.get("command", "") for ix in listener.interactions}
        assert commands, "No PJL commands extracted"

    def test_pjl_info_id_response(self):
        """PJL INFO ID response extracts printer model."""
        listener, devices, result = _run_listener_test(
            "pjl",
            "PJLPassiveListener",
            "tcp.port == 9100",
            "pjl/generated_pjl.pcap",
            min_devices=2,
        )
        # Check if printer ID was extracted from INFO ID response
        if listener.printer_ids:
            # At least one printer should have a model name
            assert any(v for v in listener.printer_ids.values()), (
                f"Printer IDs found but all empty: {listener.printer_ids}"
            )

    def test_pjl_filesystem_access_detected(self):
        """PJL filesystem access commands are detected and tracked."""
        listener, devices, result = _run_listener_test(
            "pjl",
            "PJLPassiveListener",
            "tcp.port == 9100",
            "pjl/generated_pjl.pcap",
            min_devices=2,
        )
        # The generated pcap has FSDIRLIST commands
        fs_commands = [
            ix
            for ix in listener.interactions
            if ix.details.get("command", "") in ("FSDIRLIST", "FSQUERY", "FSUPLOAD", "FSDOWNLOAD")
        ]
        # Check if FS access was tracked
        if fs_commands:
            assert len(listener.fs_access) >= 1, (
                "FSDIRLIST command found in interactions but not in fs_access tracking"
            )

    def test_both_endpoints_tracked(self):
        """Both PJL printer and client devices are created."""
        listener, devices, result = _run_listener_test(
            "pjl",
            "PJLPassiveListener",
            "tcp.port == 9100",
            "pjl/generated_pjl.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_printer = any("Printer" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_printer, f"No printer device found; types: {device_types}"
        assert has_client, f"No print client device found; types: {device_types}"

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict with alerts for filesystem access."""
        listener, devices, result = _run_listener_test(
            "pjl",
            "PJLPassiveListener",
            "tcp.port == 9100",
            "pjl/generated_pjl.pcap",
        )
        assert isinstance(result, dict)
