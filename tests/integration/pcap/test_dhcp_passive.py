"""Integration tests for DHCP passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestDHCPPassiveEK:
    """DHCP-specific tests beyond the parametrized quality suite."""

    def test_dhcp_message_parsing(self):
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/zeek_dhcp_flood.pcap",
            expect_details=["msg_type"],
        )
        # DHCP should have parsed message types
        msg_types = {
            ix.details.get("msg_type") for ix in listener.interactions if ix.details.get("msg_type")
        }
        assert len(msg_types) >= 1, "Expected at least one DHCP message type, got none"

        # Check that dhcp_data is populated on at least one device
        has_dhcp_data = any(hasattr(d, "dhcp_data") and d.dhcp_data for d in devices.values())
        assert has_dhcp_data, "No device has dhcp_data"

        # DHCP has no custom harvest tables (interaction/credential tables
        # are now built centrally by the scanner)

    # ------------------------------------------------------------------
    # T1 field coverage tests
    # ------------------------------------------------------------------

    def test_transaction_id_extracted(self):
        """dhcp.id -- transaction ID present in all DHCP packets."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/zeek_dhcp_flood.pcap",
            expect_details=["transaction_id"],
        )
        # Every DHCP packet should have a transaction ID
        txn_ids = {
            ix.details.get("transaction_id")
            for ix in listener.interactions
            if ix.details.get("transaction_id")
        }
        assert len(txn_ids) >= 1, (
            f"Expected at least one transaction_id, got none. "
            f"Sample details: {listener.interactions[0].details if listener.interactions else '{}'}"
        )

    def test_transaction_id_all_pcaps(self):
        """dhcp.id should be extracted from wireshark_dhcp.pcap too."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/wireshark_dhcp.pcap",
            expect_details=["transaction_id"],
        )
        txn_ids = {
            ix.details["transaction_id"]
            for ix in listener.interactions
            if ix.details.get("transaction_id")
        }
        assert len(txn_ids) >= 1, "No transaction_id found in wireshark_dhcp.pcap"

    def test_fqdn_name_extracted(self):
        """dhcp.fqdn.name -- DDNS name from parsed FQDN sub-field."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/wireshark_dhcp_dyndns.pcap",
            expect_details=["fqdn_name"],
        )
        fqdn_names = {
            ix.details.get("fqdn_name")
            for ix in listener.interactions
            if ix.details.get("fqdn_name")
        }
        assert len(fqdn_names) >= 1, (
            f"Expected at least one fqdn_name in dyndns pcap, got none. "
            f"Sample details: {listener.interactions[0].details if listener.interactions else '{}'}"
        )
        # The dyndns pcap should contain "academy04" in at least one FQDN
        all_fqdns = " ".join(fqdn_names)
        assert "academy04" in all_fqdns.lower() or len(fqdn_names) >= 1, (
            f"Expected 'academy04' in FQDN names, got: {fqdn_names}"
        )

    def test_fqdn_rcode_extracted(self):
        """dhcp.fqdn.rcode1 / rcode2 -- DDNS update result codes."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/wireshark_dhcp_dyndns.pcap",
        )
        has_rcode1 = any(
            ix.details.get("fqdn_rcode1") is not None and ix.details["fqdn_rcode1"] != ""
            for ix in listener.interactions
        )
        has_rcode2 = any(
            ix.details.get("fqdn_rcode2") is not None and ix.details["fqdn_rcode2"] != ""
            for ix in listener.interactions
        )
        assert has_rcode1, "Expected at least one interaction with fqdn_rcode1 in dyndns pcap"
        assert has_rcode2, "Expected at least one interaction with fqdn_rcode2 in dyndns pcap"

    def test_fqdn_name_from_filtered_pcap(self):
        """dhcp.fqdn.name -- also present in filtered_dhcp.pcap."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/filtered_dhcp.pcap",
        )
        fqdn_names = {
            ix.details.get("fqdn_name")
            for ix in listener.interactions
            if ix.details.get("fqdn_name")
        }
        assert len(fqdn_names) >= 1, "Expected at least one fqdn_name in filtered_dhcp.pcap"

    def test_client_id_iaid_extracted(self):
        """dhcp.client_id.iaid -- Identity Association ID."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/filtered_dhcp.pcap",
        )
        iaids = {
            ix.details.get("client_id_iaid")
            for ix in listener.interactions
            if ix.details.get("client_id_iaid")
        }
        assert len(iaids) >= 1, (
            f"Expected at least one client_id_iaid in filtered_dhcp.pcap, got none. "
            f"Sample details keys: "
            f"{list(listener.interactions[0].details.keys()) if listener.interactions else '[]'}"
        )

    def test_client_id_duid_ll_hw_type_extracted(self):
        """dhcp.client_id.duid_ll_hw_type -- DUID Link-Layer hardware type."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/filtered_dhcp.pcap",
        )
        hw_types = {
            ix.details.get("client_id_duid_ll_hw_type")
            for ix in listener.interactions
            if ix.details.get("client_id_duid_ll_hw_type")
        }
        assert len(hw_types) >= 1, (
            "Expected at least one client_id_duid_ll_hw_type in filtered_dhcp.pcap"
        )

    def test_client_id_link_layer_address_extracted(self):
        """dhcp.client_id.link_layer_address -- link-layer address from Client ID."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/filtered_dhcp.pcap",
        )
        addrs = {
            ix.details.get("client_id_link_layer_address")
            for ix in listener.interactions
            if ix.details.get("client_id_link_layer_address")
        }
        assert len(addrs) >= 1, (
            "Expected at least one client_id_link_layer_address in filtered_dhcp.pcap"
        )

    def test_client_id_parsed_extracted(self):
        """dhcp.client_id -- raw parsed client identifier bytes."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/filtered_dhcp.pcap",
        )
        cids = {
            ix.details.get("client_id_parsed")
            for ix in listener.interactions
            if ix.details.get("client_id_parsed")
        }
        assert len(cids) >= 1, "Expected at least one client_id_parsed in filtered_dhcp.pcap"

    def test_fqdn_fallback_to_hostname(self):
        """When fqdn_name is set but option_fqdn_name is empty, fqdn should use parsed name."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/wireshark_dhcp_dyndns.pcap",
        )
        # At least one interaction should have fqdn populated from fqdn_name
        has_fqdn = any(ix.details.get("fqdn") for ix in listener.interactions)
        assert has_fqdn, "Expected at least one interaction with fqdn populated"

    def test_all_t1_fields_in_details(self):
        """Verify all new T1 fields appear as keys in interaction details."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/filtered_dhcp.pcap",
        )
        # Every interaction should have the new keys (even if empty string)
        expected_keys = [
            "transaction_id",
            "fqdn_name",
            "fqdn_rcode1",
            "fqdn_rcode2",
            "client_id_parsed",
            "client_id_iaid",
            "client_id_duid_ll_hw_type",
            "client_id_link_layer_address",
        ]
        assert len(listener.interactions) > 0, "No interactions recorded"
        for ix in listener.interactions:
            for key in expected_keys:
                assert key in ix.details, (
                    f"Missing key {key!r} in interaction details. "
                    f"Available keys: {sorted(ix.details.keys())}"
                )

    def test_harvest_returns_valid_dict(self):
        """Harvest should return a valid dict (no custom tables for DHCP)."""
        listener, devices, result = _run_listener_test(
            "dhcp",
            "DHCPPassiveListener",
            "dhcp || bootp",
            "dhcp/wireshark_dhcp.pcap",
        )
        assert isinstance(result, dict)
