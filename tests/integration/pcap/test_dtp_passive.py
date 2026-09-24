"""Integration tests for DTP passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestDTPPassiveEK:
    """DTP-specific tests using wireshark_dtp.pcapng (2 DTP frames, single switch)."""

    # -- Pcap: wireshark_dtp.pcapng --
    # 2 identical DTP frames from e0:2f:6d:3a:a5:1a (Cisco)
    # TAS=0x01 (On), TAT=0x05 (802.1Q), TOS=0x01 (Trunk), TOT=0x05 (802.1Q)
    # NOTE: dtp.tos is its own enum (0=Access, 1=Trunk), NOT the admin-status
    # enum -- see tests/integration/pcap/test_dtp_review.py.
    # Empty domain, sender_id=e0:2f:6d:3a:a5:1a

    PCAP = "dtp/wireshark_dtp.pcapng"

    def test_dtp_basic_smoke(self):
        """Listener produces devices and interactions from real DTP traffic."""
        listener, devices, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
            min_devices=1,
            min_interactions=1,
        )
        # Confirm the parsed device is the actual Cisco switch that sent the
        # real DTP frames in this pcap, not just "some device dict".
        mac = "e0:2f:6d:3a:a5:1a"
        macs_seen = {d.mac_address for d in devices.values()}
        assert mac in macs_seen, f"Expected switch {mac} among discovered devices: {macs_seen}"
        assert listener.interactions[0].details["sender_id"] == mac

    def test_dtp_sender_id_extracted(self):
        """Verify sender_id (switch MAC) is parsed."""
        listener, _, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
            expect_details=["sender_id"],
        )
        d = listener.interactions[0].details
        assert d["sender_id"] == "e0:2f:6d:3a:a5:1a"

    def test_dtp_admin_status(self):
        """Verify Trunk Administrative Status is 'On' (TAS=0x01)."""
        listener, _, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
            expect_details=["admin_status_name"],
        )
        d = listener.interactions[0].details
        assert d["admin_status_name"] == "On"

    def test_dtp_oper_status(self):
        """Verify Trunk Operating Status is 'Trunk' (TOS=0x01)."""
        listener, _, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
            expect_details=["oper_status_name"],
        )
        d = listener.interactions[0].details
        assert d["oper_status_name"] == "Trunk"

    def test_dtp_trunk_type_802_1q(self):
        """Verify trunk encapsulation type is 802.1Q."""
        listener, _, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
            expect_details=["oper_type_name"],
        )
        d = listener.interactions[0].details
        assert "802.1Q" in d["oper_type_name"]

    def test_dtp_is_trunking_flag(self):
        """TOS=0x01 (On) should set is_trunking=True."""
        listener, _, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
            expect_details=["is_trunking"],
        )
        d = listener.interactions[0].details
        assert d["is_trunking"] is True

    def test_dtp_version_field(self):
        """Verify DTP version extraction."""
        listener, _, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
            expect_details=["version"],
        )
        d = listener.interactions[0].details
        assert d["version"] == "1"

    def test_dtp_src_mac_extracted(self):
        """Verify source MAC is captured in interaction details."""
        listener, _, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
            expect_details=["src_mac"],
        )
        d = listener.interactions[0].details
        assert d["src_mac"] == "e0:2f:6d:3a:a5:1a"

    def test_dtp_operation_contains_trunk(self):
        """Active trunk should produce operation mentioning 'Trunk Active'."""
        listener, _, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
            expect_operations=["DTP Trunk Active"],
        )
        ops = {ix.operation for ix in listener.interactions if ix.operation}
        assert any("DTP Trunk Active" in op for op in ops), (
            f"Expected a 'DTP Trunk Active' operation string, saw: {sorted(ops)}"
        )

    def test_dtp_switch_tracked(self):
        """Verify switch is tracked in listener.switches dict."""
        listener, _, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
        )
        assert len(listener.switches) >= 1
        mac = "e0:2f:6d:3a:a5:1a"
        assert mac in listener.switches
        sw = listener.switches[mac]
        assert sw["admin_status"] == "On"
        assert sw["is_trunking"] is True

    def test_dtp_device_type(self):
        """Device type should indicate DTP Trunk for active trunk."""
        _, devices, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
        )
        dev = next(iter(devices.values()))
        assert "DTP" in dev.device_type

    def test_dtp_device_data_populated(self):
        """Verify dtp_data is set on the device."""
        _, devices, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
        )
        dev = next(d for d in devices.values() if hasattr(d, "dtp_data") and d.dtp_data)
        data = dev.dtp_data
        assert data["protocol"] == "DTP/L2"
        assert data["admin_status"] == "On"
        assert data["is_trunking"] is True

    def test_dtp_harvest_table(self):
        """Harvest produces a DTP Switches table with no raw objects."""
        _, _, result = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
            check_harvest=True,
        )
        assert isinstance(result, dict)
        tables = result.get("tables", [])
        assert len(tables) >= 1
        assert "DTP" in tables[0]["title"]
        assert len(tables[0]["rows"]) >= 1

    def test_dtp_harvest_security_alert(self):
        """Active trunk should produce a warning-level security alert."""
        _, _, result = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
            check_harvest=True,
        )
        alerts = result.get("alerts", [])
        assert len(alerts) >= 1
        trunk_alerts = [a for a in alerts if "TRUNK" in a["message"]]
        assert trunk_alerts, f"Expected DTP TRUNK alert, got: {alerts}"

    def test_dtp_tlv_fields_extracted(self):
        """Verify TLV type/length fields are captured."""
        listener, _, _ = _run_listener_test(
            "dtp",
            "DTPPassiveListener",
            "dtp",
            self.PCAP,
        )
        d = listener.interactions[0].details
        assert "tlv_types" in d or "tlv_lens" in d
