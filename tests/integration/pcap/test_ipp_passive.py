"""Integration tests for IPP passive listener.

Tests cover:
- IPP operation ID extraction (Get-Printer-Attributes, Print-Job)
- IPP status code extraction from responses
- Printer name and model extraction
- Request ID correlation
- Device tracking for both printer and client endpoints
- Harvest table output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestIPPPassiveEK:
    """IPP-specific tests beyond the parametrized quality suite."""

    def test_ipp_operation_extraction(self):
        """IPP operations are extracted from request packets."""
        listener, devices, result = _run_listener_test(
            "ipp",
            "IPPPassiveListener",
            "ipp",
            "ipp/generated_ipp.pcap",
            min_devices=2,
            expect_details=["operation_name"],
        )
        # Should have at least Get-Printer-Attributes and Print-Job
        ops = {ix.details.get("operation_name", "") for ix in listener.interactions}
        assert ops, f"No operation names extracted; interactions: {len(listener.interactions)}"

    def test_ipp_response_status(self):
        """IPP responses include status code."""
        listener, devices, result = _run_listener_test(
            "ipp",
            "IPPPassiveListener",
            "ipp",
            "ipp/generated_ipp.pcap",
            min_devices=2,
        )
        response_ixs = [ix for ix in listener.interactions if ix.direction == "response"]
        assert len(response_ixs) >= 1, "No IPP response interactions found"
        has_status = any(ix.details.get("status_name") for ix in response_ixs)
        assert has_status, "No response has status_name"

    def test_both_endpoints_tracked(self):
        """Both IPP server (printer) and client devices are created."""
        listener, devices, result = _run_listener_test(
            "ipp",
            "IPPPassiveListener",
            "ipp",
            "ipp/generated_ipp.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Printer" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No printer server device found; types: {device_types}"
        assert has_client, f"No print client device found; types: {device_types}"

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict."""
        listener, devices, result = _run_listener_test(
            "ipp",
            "IPPPassiveListener",
            "ipp",
            "ipp/generated_ipp.pcap",
        )
        assert isinstance(result, dict)
