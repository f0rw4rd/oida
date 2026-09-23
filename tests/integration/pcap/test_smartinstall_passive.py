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

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


# ---------------------------------------------------------------------------
# Fake-packet helpers for the CVE-2018-0171 false-positive regression test.
#
# These build minimal duck-typed packets so process_packet() can run without
# pyshark/tshark, letting us assert that a bare scan SYN to port 4786 does NOT
# raise a CVE exposure finding while a real SMI server response does.
# ---------------------------------------------------------------------------


class _FakeLayer:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class _FakeTCP(_FakeLayer):
    layer_name = "tcp"


class _FakePacket:
    """Minimal stand-in for a pyshark packet with tcp/ip/eth layers."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, flags, payload=None):
        self.ip = _FakeLayer(src=src_ip, dst=dst_ip)
        self.eth = _FakeLayer(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")
        tcp_fields = {
            "srcport": str(src_port),
            "dstport": str(dst_port),
            "flags": flags,
            "stream": "0",
        }
        if payload is not None:
            tcp_fields["payload"] = payload
        self.tcp = _FakeTCP(**tcp_fields)


def _make_listener():
    from oida.pcap.smartinstall import SmartInstallPassiveListener

    listener = SmartInstallPassiveListener(interface="lo", timeout=10)
    return listener


class TestSmartInstallCVEFalsePositive:
    """Regression: only assert CVE-2018-0171 when a real SMI service is seen."""

    CLIENT_IP = "10.0.0.10"
    SWITCH_IP = "10.0.0.20"

    def test_bare_syn_scan_does_not_flag_cve(self):
        """A lone client SYN to closed/filtered 4786 must NOT flag exposure."""
        listener = _make_listener()
        # Bare SYN (flags 0x002) from client -> switch:4786, no SMI payload,
        # no server response. This is an nmap-style scan probe.
        syn = _FakePacket(
            self.CLIENT_IP,
            self.SWITCH_IP,
            src_port=49200,
            dst_port=4786,
            flags="0x00000002",
        )
        listener.process_packet(syn)

        # No switch device, no CVE flag, no exposure recorded.
        assert self.SWITCH_IP not in listener.exposed_switches
        switch_devices = [
            d
            for d in listener.discovered_devices.values()
            if "Switch" in (getattr(d, "device_type", "") or "")
        ]
        assert not switch_devices, f"Scan SYN should not mint a switch device; got {switch_devices}"
        cve_devices = [
            d
            for d in listener.discovered_devices.values()
            if getattr(d, "smartinstall_data", None)
            and d.smartinstall_data.get("cve_2018_0171") is True
        ]
        assert not cve_devices, "Scan SYN must not raise CVE-2018-0171"

        # And harvest must not emit a CVE alert.
        result = listener.harvest()
        alerts = result.get("alerts", []) if result else []
        assert not any("CVE-2018-0171" in a.get("message", "") for a in alerts)

    def test_server_response_flags_cve(self):
        """A real packet originating FROM port 4786 confirms the service."""
        listener = _make_listener()
        # Server response: src_port == 4786 (the switch answered).
        resp = _FakePacket(
            self.SWITCH_IP,
            self.CLIENT_IP,
            src_port=4786,
            dst_port=49200,
            flags="0x00000018",  # PSH+ACK
        )
        listener.process_packet(resp)

        assert self.SWITCH_IP in listener.exposed_switches
        cve_devices = [
            d
            for d in listener.discovered_devices.values()
            if getattr(d, "smartinstall_data", None)
            and d.smartinstall_data.get("cve_2018_0171") is True
        ]
        assert cve_devices, "Server response from 4786 should flag CVE-2018-0171"

        result = listener.harvest()
        alerts = result.get("alerts", []) if result else []
        assert any("CVE-2018-0171" in a.get("message", "") for a in alerts)

    def test_parsed_smi_header_flags_cve(self):
        """A client request carrying a parseable SMI header confirms the service."""
        listener = _make_listener()
        # version=1, length=24, type=1 (IMAGE_LIST), big-endian uint32 x3.
        import struct

        payload = struct.pack("!III", 1, 24, 1).hex()
        req = _FakePacket(
            self.CLIENT_IP,
            self.SWITCH_IP,
            src_port=49200,
            dst_port=4786,
            flags="0x00000018",
            payload=payload,
        )
        listener.process_packet(req)

        assert self.SWITCH_IP in listener.exposed_switches
        cve_devices = [
            d
            for d in listener.discovered_devices.values()
            if getattr(d, "smartinstall_data", None)
            and d.smartinstall_data.get("cve_2018_0171") is True
        ]
        assert cve_devices, "Parsed SMI header should flag CVE-2018-0171"


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
