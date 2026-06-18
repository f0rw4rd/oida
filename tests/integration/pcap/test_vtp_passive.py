"""Integration tests for VTP passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestVTPPassiveEK:
    """VTP-specific tests using tranalyzer_vtp.pcap.

    Pcap contents (13 frames, 2 switches):
      - 00:22:be:82:71:09 — VTP server, domain "CautionThisIsSparta", rev 5→6
      - 00:11:93:1e:52:97 — VTP client, same domain
      - Message types: Summary (0x01), Subset (0x02), Advertisement Request (0x03)
      - Subset ads contain 7 VLANs: default(1), Fnord(23), ThisIsSparta(42),
        fddi-default(1002), trcrf-default(1003), fddinet-default(1004),
        trbrf-default(1005)
      - MD5 authentication present on summary advertisements
      - Updater identities: 192.168.1.254 and 192.168.1.253
    """

    PCAP = "vtp/tranalyzer_vtp.pcap"

    def test_vtp_basic_smoke(self):
        """Listener produces devices and interactions from real VTP traffic."""
        _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
            min_devices=1,
            min_interactions=1,
        )

    def test_vtp_two_switches_discovered(self):
        """Two distinct source MACs should produce two devices."""
        _, devices, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
            min_devices=2,
        )

    def test_vtp_domain_name(self):
        """Verify VTP domain name is extracted."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
            expect_details=["domain_name"],
        )
        d = listener.interactions[0].details
        assert d["domain_name"] == "CautionThisIsSparta"

    def test_vtp_version(self):
        """Verify VTP version is extracted (v2 in this pcap)."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
            expect_details=["version"],
        )
        # Version may come as "0x02" or "2" depending on EK mode
        d = listener.interactions[0].details
        assert d["version"] in ("2", "0x02"), f"Expected VTPv2, got {d['version']}"

    def test_vtp_message_types(self):
        """Verify all three VTP message types are seen."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
        )
        code_names = {ix.details.get("code_name") for ix in listener.interactions}
        assert "Summary Advertisement" in code_names, f"Missing Summary, saw: {code_names}"
        assert "Advertisement Request" in code_names, f"Missing Request, saw: {code_names}"
        assert "Subset Advertisement" in code_names, f"Missing Subset, saw: {code_names}"

    def test_vtp_revision_number(self):
        """Verify configuration revision number is extracted."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
            expect_details=["revision"],
        )
        revisions = {
            ix.details.get("revision") for ix in listener.interactions if ix.details.get("revision")
        }
        assert revisions, "No revision numbers found"
        # Pcap has rev 5 and 6
        assert "5" in revisions or "6" in revisions

    def test_vtp_md5_digest_extracted(self):
        """Summary advertisements should have MD5 digest."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
        )
        has_md5 = any(ix.details.get("md5_digest") for ix in listener.interactions)
        assert has_md5, "Expected at least one interaction with md5_digest"

    def test_vtp_has_auth_flag(self):
        """MD5 presence should set has_auth=True."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
        )
        has_auth = any(ix.details.get("has_auth") for ix in listener.interactions)
        assert has_auth, "Expected has_auth=True on summary advertisements"

    def test_vtp_updater_identity(self):
        """Verify updater IP is extracted from summary advertisements."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
        )
        updaters = {
            ix.details.get("updater") for ix in listener.interactions if ix.details.get("updater")
        }
        assert "192.168.1.254" in updaters or "192.168.1.253" in updaters, (
            f"Expected updater IP, got: {updaters}"
        )

    def test_vtp_vlans_parsed(self):
        """Subset advertisements should yield VLAN info."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
        )
        # Find subset advertisements with VLAN data
        subset_ix = [
            ix
            for ix in listener.interactions
            if ix.details.get("code_name") == "Subset Advertisement"
        ]
        assert subset_ix, "No Subset Advertisement interactions found"

        # At least one should have vlans
        has_vlans = any(ix.details.get("vlans") for ix in subset_ix)
        assert has_vlans, "No VLANs parsed from subset advertisements"

        # Check specific VLAN IDs from the pcap
        all_vlans = []
        for ix in subset_ix:
            all_vlans.extend(ix.details.get("vlans", []))
        vlan_ids = {v["id"] for v in all_vlans}
        assert 1 in vlan_ids, f"Missing VLAN 1 (default), got: {vlan_ids}"
        assert 42 in vlan_ids, f"Missing VLAN 42 (ThisIsSparta), got: {vlan_ids}"

    def test_vtp_vlan_names(self):
        """Verify VLAN names are extracted."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
        )
        all_vlans = []
        for ix in listener.interactions:
            all_vlans.extend(ix.details.get("vlans", []))
        vlan_names = {v.get("name") for v in all_vlans if v.get("name")}
        assert "default" in vlan_names, f"Missing 'default' VLAN name, got: {vlan_names}"
        assert "ThisIsSparta" in vlan_names, f"Missing 'ThisIsSparta', got: {vlan_names}"
        assert "Fnord" in vlan_names, f"Missing 'Fnord', got: {vlan_names}"

    def test_vtp_domain_tracking(self):
        """Verify listener.domains tracks the VTP domain."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
        )
        assert "CautionThisIsSparta" in listener.domains
        domain = listener.domains["CautionThisIsSparta"]
        assert len(domain["switches"]) >= 2, "Expected 2 switches in domain"
        assert domain["has_auth"] is True

    def test_vtp_vlan_inventory_tracking(self):
        """Verify listener.vlans accumulates VLAN inventory."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
        )
        assert len(listener.vlans) >= 4, f"Expected 4+ VLANs, got {len(listener.vlans)}"
        assert 1 in listener.vlans
        assert listener.vlans[1].get("name") == "default"

    def test_vtp_switch_tracking(self):
        """Verify listener.switches tracks both source MACs."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
        )
        assert len(listener.switches) >= 2

    def test_vtp_device_data_populated(self):
        """Verify vtp_data is set on discovered devices."""
        _, devices, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
        )
        dev = next(d for d in devices.values() if hasattr(d, "vtp_data") and d.vtp_data)
        data = dev.vtp_data
        assert data["protocol"] == "VTP/L2"
        assert data["domain_name"] == "CautionThisIsSparta"

    def test_vtp_harvest_domain_table(self):
        """Harvest produces a VTP Domains table."""
        _, _, result = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
            check_harvest=True,
        )
        assert isinstance(result, dict)
        tables = result.get("tables", [])
        domain_tables = [t for t in tables if "Domain" in t.get("title", "")]
        assert domain_tables, f"No domain table in harvest, titles: {[t['title'] for t in tables]}"

    def test_vtp_harvest_vlan_table(self):
        """Harvest produces a VTP VLANs table."""
        _, _, result = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
            check_harvest=True,
        )
        tables = result.get("tables", [])
        vlan_tables = [t for t in tables if "VLAN" in t.get("title", "")]
        assert vlan_tables, f"No VLAN table in harvest, titles: {[t['title'] for t in tables]}"
        # Should have 7 VLANs in the final state (after rev 6 with Area51)
        rows = vlan_tables[0]["rows"]
        assert len(rows) >= 7, f"Expected 7+ VLAN rows, got {len(rows)}"

    def test_vtp_harvest_no_auth_alert(self):
        """Domain with auth should NOT produce a no-auth alert."""
        _, _, result = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
            check_harvest=True,
        )
        alerts = result.get("alerts", [])
        no_auth = [a for a in alerts if "NO AUTH" in a.get("message", "")]
        # This pcap HAS MD5 auth, so no-auth alert should NOT fire
        assert not no_auth, f"Unexpected NO AUTH alert for authenticated domain: {no_auth}"

    def test_vtp_operation_strings(self):
        """Verify operation strings contain VTP message type names."""
        _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
            expect_operations=["VTP Summary Advertisement"],
        )

    def test_vtp_followers_field(self):
        """Summary advertisements should have followers count."""
        listener, _, _ = _run_listener_test(
            "vtp",
            "VTPPassiveListener",
            "vtp",
            self.PCAP,
        )
        # Summaries with followers=1 exist (packets 6, 8, 10, 12)
        has_followers = any(ix.details.get("followers") == "1" for ix in listener.interactions)
        assert has_followers, "Expected at least one summary with followers=1"
