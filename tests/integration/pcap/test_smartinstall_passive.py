"""Integration tests for Cisco Smart Install passive listener.

Tests cover:
- TCP connection detection on port 4786
- Smart Install header parsing (version, length, type)
- Operation type identification (IMAGE_LIST, COPY_CONFIG)
- Director vs Switch role assignment
- CVE-2018-0171 exposure flagging
- Multiple target switch detection
- Harvest table output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestSmartInstallPassiveEK:
    """Smart Install-specific tests beyond the parametrized quality suite."""

    def test_smi_interactions_created(self):
        """Smart Install packets create interactions with operation field."""
        listener, devices, result = _run_listener_test(
            "smartinstall",
            "SmartInstallPassiveListener",
            "tcp.port == 4786",
            "smartinstall/generated_smartinstall.pcap",
            min_devices=2,
            min_interactions=1,
            expect_details=["operation"],
        )
        ops = {ix.details.get("operation", "") for ix in listener.interactions}
        assert any(op != "" for op in ops), f"No operations found; got: {ops}"

    def test_smi_switch_device_tracked(self):
        """Cisco switches (port 4786 targets) are tracked as devices."""
        listener, devices, result = _run_listener_test(
            "smartinstall",
            "SmartInstallPassiveListener",
            "tcp.port == 4786",
            "smartinstall/generated_smartinstall.pcap",
            min_devices=2,
        )
        # At least one device should be a switch
        switch_devices = [
            d
            for d in devices.values()
            if hasattr(d, "device_type") and "Switch" in (d.device_type or "")
        ]
        assert len(switch_devices) >= 1, (
            f"Expected at least 1 switch device; types: {[d.device_type for d in devices.values()]}"
        )

    def test_smi_director_device_tracked(self):
        """Smart Install Director (client) is tracked as a device."""
        listener, devices, result = _run_listener_test(
            "smartinstall",
            "SmartInstallPassiveListener",
            "tcp.port == 4786",
            "smartinstall/generated_smartinstall.pcap",
            min_devices=2,
        )
        director_devices = [
            d
            for d in devices.values()
            if hasattr(d, "device_type") and "Director" in (d.device_type or "")
        ]
        assert len(director_devices) >= 1, (
            f"Expected at least 1 director device; "
            f"types: {[d.device_type for d in devices.values()]}"
        )

    def test_smi_cve_flagged(self):
        """CVE-2018-0171 exposure is flagged in device data."""
        listener, devices, result = _run_listener_test(
            "smartinstall",
            "SmartInstallPassiveListener",
            "tcp.port == 4786",
            "smartinstall/generated_smartinstall.pcap",
            min_devices=2,
        )
        has_cve = any(
            hasattr(d, "smartinstall_data")
            and d.smartinstall_data
            and d.smartinstall_data.get("cve_2018_0171") is True
            for d in devices.values()
        )
        assert has_cve, "No device flagged with CVE-2018-0171"

    def test_smi_multiple_operations(self):
        """Multiple operation types are detected."""
        listener, devices, result = _run_listener_test(
            "smartinstall",
            "SmartInstallPassiveListener",
            "tcp.port == 4786",
            "smartinstall/generated_smartinstall.pcap",
            min_interactions=3,
        )
        ops = {ix.details.get("operation", "") for ix in listener.interactions}
        assert len(ops) >= 2, f"Expected >= 2 distinct operations; got: {ops}"

    def test_smi_operation_prefix(self):
        """All Smart Install operations start with 'SMI'."""
        listener, devices, result = _run_listener_test(
            "smartinstall",
            "SmartInstallPassiveListener",
            "tcp.port == 4786",
            "smartinstall/generated_smartinstall.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            assert ix.operation.startswith("SMI"), (
                f"Operation should start with 'SMI'; got: {ix.operation}"
            )

    def test_smi_harvest_valid(self):
        """Harvest returns a valid dict."""
        listener, devices, result = _run_listener_test(
            "smartinstall",
            "SmartInstallPassiveListener",
            "tcp.port == 4786",
            "smartinstall/generated_smartinstall.pcap",
            check_harvest=True,
        )
        assert isinstance(result, dict)

    def test_smi_protocol_columns_format(self):
        """Protocol columns return correct number of values."""
        listener, devices, result = _run_listener_test(
            "smartinstall",
            "SmartInstallPassiveListener",
            "tcp.port == 4786",
            "smartinstall/generated_smartinstall.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            cols = listener._format_protocol_columns(ix)
            assert len(cols) == len(listener.PROTOCOL_COLUMNS), (
                f"Expected {len(listener.PROTOCOL_COLUMNS)} columns, got {len(cols)}: {cols}"
            )

    def test_smi_smartinstall_data_fields(self):
        """Device smartinstall_data contains expected fields."""
        listener, devices, result = _run_listener_test(
            "smartinstall",
            "SmartInstallPassiveListener",
            "tcp.port == 4786",
            "smartinstall/generated_smartinstall.pcap",
            min_devices=2,
        )
        for d in devices.values():
            data = getattr(d, "smartinstall_data", None)
            if data:
                assert "role" in data, f"Missing 'role' in smartinstall_data: {data}"
                assert "protocol" in data, f"Missing 'protocol' in smartinstall_data: {data}"

    def test_smi_both_endpoints_different_ips(self):
        """Director and switch have different IP addresses."""
        listener, devices, result = _run_listener_test(
            "smartinstall",
            "SmartInstallPassiveListener",
            "tcp.port == 4786",
            "smartinstall/generated_smartinstall.pcap",
            min_devices=2,
        )
        ips = set()
        for d in devices.values():
            for ip in d.ip_addresses:
                ips.add(ip)
        assert len(ips) >= 2, f"Expected >= 2 distinct IPs; got: {ips}"
