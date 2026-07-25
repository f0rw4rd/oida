"""Integration tests for CDP passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestCDPPassiveEK:
    """CDP-specific tests beyond the parametrized quality suite."""

    def test_cdp_device_discovery(self):
        listener, devices, result = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
            min_devices=2,
            min_interactions=2,
        )
        # Check that cdp_data is populated on at least one device
        has_cdp_data = any(hasattr(d, "cdp_data") and d.cdp_data for d in devices.values())
        assert has_cdp_data, "No device has cdp_data"

        assert isinstance(result, dict)

    def test_cdp_core_identity_fields(self):
        """Verify core identity fields: device_id, platform, port_id."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
            expect_details=["device_id", "platform", "port_id"],
        )
        ix = listener.interactions[0]
        d = ix.details
        assert d["device_id"], "device_id should be non-empty"
        assert "cisco" in d["platform"].lower() or "WS-" in d["platform"]
        assert d["port_id"], "port_id should be non-empty"

    def test_cdp_software_version_extraction(self):
        """Verify software version is extracted and shortened."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
            expect_details=["software_version", "software_version_short"],
        )
        d = listener.interactions[0].details
        assert "Version" in d["software_version"] or "IOS" in d["software_version"]
        assert d["software_version_short"], "software_version_short should be non-empty"

    def test_cdp_version_field(self):
        """Verify CDP protocol version extraction (T1 gap fix)."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
            expect_details=["cdp_version"],
        )
        d = listener.interactions[0].details
        assert d["cdp_version"] == "2", f"Expected CDP version 2, got {d['cdp_version']}"

    def test_cdp_native_vlan_and_vtp_domain(self):
        """Verify native VLAN and VTP management domain."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
            expect_details=["native_vlan", "vtp_domain"],
        )
        d = listener.interactions[0].details
        assert d["native_vlan"], "native_vlan should be non-empty"
        assert d["vtp_domain"] == "webernetz.net"

    def test_cdp_capabilities_parsed(self):
        """Verify CDP capabilities are parsed into human-readable names."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
            expect_details=["capabilities"],
        )
        d = listener.interactions[0].details
        caps = d["capabilities"]
        assert "Switch" in caps, f"Expected 'Switch' in capabilities, got {caps}"
        assert "IGMP" in caps, f"Expected 'IGMP' in capabilities, got {caps}"

    def test_cdp_management_addresses(self):
        """Verify management address extraction (IPv4 and IPv6)."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
            expect_details=["management_address"],
        )
        # Check at least one interaction has management addresses
        has_ipv4 = any(
            "192.168" in ix.details.get("management_address", "") for ix in listener.interactions
        )
        assert has_ipv4, "Expected at least one device with IPv4 management address"

        # Check for IPv6 addresses (from the S1 switch)
        has_ipv6 = any(
            "2003:" in ix.details.get("management_address", "")
            or "fe80:" in ix.details.get("management_address", "")
            for ix in listener.interactions
        )
        assert has_ipv6, "Expected at least one device with IPv6 management address"

    def test_cdp_duplex(self):
        """Verify duplex field extraction."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
            expect_details=["duplex"],
        )
        d = listener.interactions[0].details
        assert d["duplex"], "duplex should be non-empty"

    def test_cdp_trust_bitmap(self):
        """Verify trust bitmap extraction (T1/T2 gap fix)."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
            expect_details=["trust_bitmap"],
        )
        # At least one interaction should have trust_bitmap
        has_trust = any(ix.details.get("trust_bitmap") is not None for ix in listener.interactions)
        assert has_trust, "Expected at least one interaction with trust_bitmap"

    def test_cdp_cluster_fields(self):
        """Verify cluster management fields (T1 gap fix)."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
        )
        # Find an interaction with cluster data
        cluster_ix = [ix for ix in listener.interactions if ix.details.get("cluster")]
        assert cluster_ix, "Expected at least one interaction with cluster data"
        cluster = cluster_ix[0].details["cluster"]
        assert "version" in cluster, f"Missing cluster version, got {cluster}"
        assert "sub_version" in cluster, f"Missing cluster sub_version, got {cluster}"
        assert "status" in cluster, f"Missing cluster status, got {cluster}"

    def test_cdp_cluster_mac_addresses(self):
        """Verify cluster commander and switch MAC fields."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
        )
        cluster_ix = [ix for ix in listener.interactions if ix.details.get("cluster")]
        assert cluster_ix
        cluster = cluster_ix[0].details["cluster"]
        assert "commander_mac" in cluster
        assert "switch_mac" in cluster

    def test_cdp_power_fields(self):
        """Verify power negotiation fields (T1 gap: request_id, management_id)."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
        )
        # Some packets have power fields (S1 has power_available, request_id, management_id)
        has_power = any(
            ix.details.get("power_available") or ix.details.get("request_id")
            for ix in listener.interactions
        )
        assert has_power, "Expected at least one interaction with power fields"

    def test_cdp_spare_poe_fields(self):
        """Verify spare PoE TLV extraction."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
        )
        poe_ix = [ix for ix in listener.interactions if ix.details.get("spare_poe")]
        assert poe_ix, "Expected at least one interaction with spare_poe data"
        poe = poe_ix[0].details["spare_poe"]
        assert "poe" in poe
        assert isinstance(poe["poe"], bool)

    def test_cdp_device_data_completeness(self):
        """Verify cdp_data on devices includes new fields."""
        listener, devices, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
        )
        dev = next(d for d in devices.values() if hasattr(d, "cdp_data") and d.cdp_data)
        data = dev.cdp_data
        assert data["protocol"] == "CDP/L2"
        assert data["cdp_version"], "cdp_version should be in cdp_data"
        assert "trust_bitmap" in data
        assert "untrusted_port_cos" in data

    def test_cdp_two_distinct_devices(self):
        """Verify two distinct Cisco switches are discovered (S1 and S2)."""
        listener, devices, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
            min_devices=2,
        )
        device_ids = [
            d.cdp_data["device_id"]
            for d in devices.values()
            if hasattr(d, "cdp_data") and d.cdp_data
        ]
        assert len(device_ids) >= 2, f"Expected 2+ distinct devices, got {device_ids}"
        # Verify both S1 and S2 are present
        has_s1 = any("S1" in did for did in device_ids)
        has_s2 = any("S2" in did for did in device_ids)
        assert has_s1 and has_s2, f"Expected both S1 and S2, got {device_ids}"

    def test_cdp_extracts_number_of_addresses(self):
        """Verify Address TLV number_of_addresses extraction (T1 gap fix)."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
        )
        found = any(ix.details.get("number_of_addresses") for ix in listener.interactions)
        assert found, (
            "Expected number_of_addresses in interaction details; "
            f"sample: {listener.interactions[0].details if listener.interactions else 'none'}"
        )
        # S1's standard Address TLV advertises 3 management addresses.
        # EK mode joins the per-TLV counts (e.g. "3,1"); check for the token.
        has_multi = any(
            "3" in ix.details.get("number_of_addresses", "").split(",")
            for ix in listener.interactions
        )
        assert has_multi, "Expected at least one device advertising 3 addresses (S1)"

    def test_cdp_extracts_address_length(self):
        """Verify Address TLV address_length extraction (T1 gap fix)."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
        )
        found = any(ix.details.get("address_length") for ix in listener.interactions)
        assert found, (
            "Expected address_length in interaction details; "
            f"sample: {listener.interactions[0].details if listener.interactions else 'none'}"
        )

    def test_cdp_extracts_address_protocol_id(self):
        """Verify Address TLV protocol_id extraction (T1 gap fix)."""
        listener, _, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
        )
        found = any(ix.details.get("address_protocol_id") for ix in listener.interactions)
        assert found, (
            "Expected address_protocol_id in interaction details; "
            f"sample: {listener.interactions[0].details if listener.interactions else 'none'}"
        )

    def test_cdp_device_address_tlv_fields(self):
        """Verify Address TLV fields propagate into device cdp_data."""
        _, devices, _ = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
        )
        has_field = any(
            hasattr(d, "cdp_data") and d.cdp_data and "number_of_addresses" in d.cdp_data
            for d in devices.values()
        )
        assert has_field, "No device has number_of_addresses in cdp_data"

    def test_cdp_harvest_table_no_raw_objects(self):
        """Verify harvest table cells contain no raw dicts or sets."""
        _, _, result = _run_listener_test(
            "cdp",
            "CDPPassiveListener",
            "cdp",
            "cdp/filtered_cdp.pcap",
            check_harvest=True,
        )
        assert isinstance(result, dict)
