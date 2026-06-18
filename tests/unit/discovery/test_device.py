"""
Tests for DiscoveredDevice dataclass and merge logic
"""

import pytest


@pytest.fixture
def discovery_module():
    """Import discovery module"""
    from oida.protocols.discovery import DiscoveredDevice

    return DiscoveredDevice


class TestDiscoveredDeviceConstruction:
    """Test DiscoveredDevice dataclass initialization"""

    def test_default_values(self, discovery_module):
        """Test device with all default values"""
        DiscoveredDevice = discovery_module
        device = DiscoveredDevice()

        assert device.mac_address == ""
        assert device.ip_addresses == []
        assert device.name == ""
        assert device.manufacturer == ""
        assert device.model == ""
        assert device.description == ""
        assert device.device_type == ""
        assert device.discovered_by == []
        assert device.first_seen == ""
        assert device.last_seen == ""
        assert device.arp_data is None
        assert device.lldp_data is None
        assert device.dcp_data is None
        assert device.mdns_services is None
        assert device.ssdp_data is None
        assert device.dnssd_data is None
        assert device.wsdiscovery_data is None
        assert device.llmnr_data is None
        assert device.cdp_data is None

    def test_with_mac_and_ip(self, discovery_module):
        """Test device with MAC and IP addresses"""
        DiscoveredDevice = discovery_module
        device = DiscoveredDevice(
            mac_address="00:11:22:33:44:55",
            ip_addresses=["192.168.1.100", "10.0.0.100"],
        )

        assert device.mac_address == "00:11:22:33:44:55"
        assert device.ip_addresses == ["192.168.1.100", "10.0.0.100"]

    def test_with_all_protocol_data(self, discovery_module):
        """Test device with all protocol-specific data"""
        DiscoveredDevice = discovery_module
        device = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.1"],
            name="TestDevice",
            manufacturer="TestVendor",
            model="Model123",
            description="A test device",
            device_type="PLC",
            discovered_by=["arp", "lldp"],
            first_seen="2024-01-01T10:00:00",
            last_seen="2024-01-01T10:30:00",
            arp_data={"response_time": "2024-01-01T10:00:00"},
            lldp_data={"chassis_id": "test"},
            dcp_data={"name_of_station": "station1"},
            mdns_services=[{"type": "_http._tcp.local.", "port": 80}],
            ssdp_data={"location": "http://192.168.1.1:8080"},
            dnssd_data={"services": [{"type": "_ssh._tcp.local."}]},
            wsdiscovery_data={"types": ["wsdp:Device"]},
            llmnr_data={"name": "WORKSTATION"},
            cdp_data={"device_id": "switch01"},
        )

        assert device.name == "TestDevice"
        assert device.manufacturer == "TestVendor"
        assert device.model == "Model123"
        assert device.description == "A test device"
        assert device.device_type == "PLC"
        assert device.arp_data == {"response_time": "2024-01-01T10:00:00"}
        assert device.lldp_data == {"chassis_id": "test"}
        assert device.dcp_data == {"name_of_station": "station1"}
        assert device.mdns_services == [{"type": "_http._tcp.local.", "port": 80}]
        assert device.ssdp_data == {"location": "http://192.168.1.1:8080"}
        assert device.dnssd_data == {"services": [{"type": "_ssh._tcp.local."}]}
        assert device.wsdiscovery_data == {"types": ["wsdp:Device"]}
        assert device.llmnr_data == {"name": "WORKSTATION"}
        assert device.cdp_data == {"device_id": "switch01"}

    def test_discovered_by_list(self, discovery_module):
        """Test discovered_by field is a proper list"""
        DiscoveredDevice = discovery_module
        device = DiscoveredDevice(discovered_by=["arp", "mdns", "ssdp"])

        assert len(device.discovered_by) == 3
        assert "arp" in device.discovered_by
        assert "mdns" in device.discovered_by
        assert "ssdp" in device.discovered_by

    def test_ip_addresses_list_independence(self, discovery_module):
        """Test that ip_addresses lists are independent between instances"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice()
        device2 = DiscoveredDevice()

        device1.ip_addresses.append("192.168.1.1")

        assert "192.168.1.1" in device1.ip_addresses
        assert "192.168.1.1" not in device2.ip_addresses


class TestDiscoveredDeviceMerge:
    """Test merge_from() method - CRITICAL for device consolidation"""

    def test_merge_ip_addresses_deduplication(self, discovery_module):
        """Test that merged IPs are deduplicated"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.1", "192.168.1.2"],
        )
        device2 = DiscoveredDevice(
            ip_addresses=["192.168.1.2", "192.168.1.3"],
        )

        device1.merge_from(device2)

        assert len(device1.ip_addresses) == 3
        assert "192.168.1.1" in device1.ip_addresses
        assert "192.168.1.2" in device1.ip_addresses
        assert "192.168.1.3" in device1.ip_addresses

    def test_merge_mac_address_precedence(self, discovery_module):
        """Test that existing MAC is preserved, empty MAC gets updated"""
        DiscoveredDevice = discovery_module

        # Existing MAC preserved
        device1 = DiscoveredDevice(mac_address="aa:bb:cc:dd:ee:ff")
        device2 = DiscoveredDevice(mac_address="11:22:33:44:55:66")
        device1.merge_from(device2)
        assert device1.mac_address == "aa:bb:cc:dd:ee:ff"

        # Empty MAC gets updated
        device3 = DiscoveredDevice(mac_address="")
        device4 = DiscoveredDevice(mac_address="11:22:33:44:55:66")
        device3.merge_from(device4)
        assert device3.mac_address == "11:22:33:44:55:66"

    def test_merge_name_first_wins(self, discovery_module):
        """Test that existing name is preserved"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(name="OriginalName")
        device2 = DiscoveredDevice(name="NewName")

        device1.merge_from(device2)

        assert device1.name == "OriginalName"

    def test_merge_name_updated_if_empty(self, discovery_module):
        """Test that empty name gets updated"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(name="")
        device2 = DiscoveredDevice(name="NewName")

        device1.merge_from(device2)

        assert device1.name == "NewName"

    def test_merge_manufacturer_first_wins(self, discovery_module):
        """Test that existing manufacturer is preserved"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(manufacturer="Siemens")
        device2 = DiscoveredDevice(manufacturer="ABB")

        device1.merge_from(device2)

        assert device1.manufacturer == "Siemens"

    def test_merge_discovered_by_combines(self, discovery_module):
        """Test that discovered_by lists are combined without duplicates"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(discovered_by=["arp", "lldp"])
        device2 = DiscoveredDevice(discovered_by=["lldp", "mdns", "ssdp"])

        device1.merge_from(device2)

        assert len(device1.discovered_by) == 4
        assert "arp" in device1.discovered_by
        assert "lldp" in device1.discovered_by
        assert "mdns" in device1.discovered_by
        assert "ssdp" in device1.discovered_by

    def test_merge_timestamp_earliest_first_seen(self, discovery_module):
        """Test that first_seen keeps earliest timestamp"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(first_seen="2024-01-01T12:00:00")
        device2 = DiscoveredDevice(first_seen="2024-01-01T10:00:00")

        device1.merge_from(device2)

        assert device1.first_seen == "2024-01-01T10:00:00"

    def test_merge_timestamp_first_seen_not_overwritten_if_later(self, discovery_module):
        """Test that first_seen is not overwritten with later timestamp"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(first_seen="2024-01-01T10:00:00")
        device2 = DiscoveredDevice(first_seen="2024-01-01T12:00:00")

        device1.merge_from(device2)

        assert device1.first_seen == "2024-01-01T10:00:00"

    def test_merge_timestamp_updates_last_seen(self, discovery_module):
        """Test that last_seen is updated on merge"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(last_seen="2024-01-01T10:00:00")
        device2 = DiscoveredDevice(last_seen="2024-01-01T12:00:00")

        device1.merge_from(device2)

        # last_seen should be updated to current time
        assert device1.last_seen != "2024-01-01T10:00:00"

    def test_merge_mdns_services_extends_list(self, discovery_module):
        """Test that mDNS services are extended, not replaced"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(mdns_services=[{"type": "_http._tcp.local.", "port": 80}])
        device2 = DiscoveredDevice(mdns_services=[{"type": "_ssh._tcp.local.", "port": 22}])

        device1.merge_from(device2)

        assert len(device1.mdns_services) == 2
        types = [s["type"] for s in device1.mdns_services]
        assert "_http._tcp.local." in types
        assert "_ssh._tcp.local." in types

    def test_merge_dnssd_services_extends_list(self, discovery_module):
        """Test that DNS-SD services are extended, not replaced"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(dnssd_data={"services": [{"type": "_ipp._tcp.local."}]})
        device2 = DiscoveredDevice(dnssd_data={"services": [{"type": "_printer._tcp.local."}]})

        device1.merge_from(device2)

        assert len(device1.dnssd_data["services"]) == 2

    def test_merge_protocol_data_keeps_existing(self, discovery_module):
        """Test that protocol-specific data is kept (not overwritten) if already set"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(arp_data={"old": "data"})
        device2 = DiscoveredDevice(arp_data={"new": "data"})

        device1.merge_from(device2)

        # Existing data is kept, not overwritten
        assert device1.arp_data == {"old": "data"}

    def test_merge_empty_into_populated(self, discovery_module):
        """Test merging empty device into populated one"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.1"],
            name="Device1",
            manufacturer="Vendor1",
        )
        device2 = DiscoveredDevice()

        device1.merge_from(device2)

        assert device1.mac_address == "aa:bb:cc:dd:ee:ff"
        assert device1.ip_addresses == ["192.168.1.1"]
        assert device1.name == "Device1"
        assert device1.manufacturer == "Vendor1"

    def test_merge_populated_into_empty(self, discovery_module):
        """Test merging populated device into empty one"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice()
        device2 = DiscoveredDevice(
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_addresses=["192.168.1.1"],
            name="Device2",
            manufacturer="Vendor2",
        )

        device1.merge_from(device2)

        assert device1.mac_address == "aa:bb:cc:dd:ee:ff"
        assert device1.ip_addresses == ["192.168.1.1"]
        assert device1.name == "Device2"
        assert device1.manufacturer == "Vendor2"

    def test_merge_both_have_same_ips(self, discovery_module):
        """Test merging devices with identical IPs"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(ip_addresses=["192.168.1.1", "192.168.1.2"])
        device2 = DiscoveredDevice(ip_addresses=["192.168.1.1", "192.168.1.2"])

        device1.merge_from(device2)

        assert device1.ip_addresses == ["192.168.1.1", "192.168.1.2"]

    def test_merge_none_values_handling(self, discovery_module):
        """Test merging with None protocol data"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(lldp_data=None, dcp_data={"existing": True})
        device2 = DiscoveredDevice(lldp_data={"new": True}, dcp_data=None)

        device1.merge_from(device2)

        assert device1.lldp_data == {"new": True}
        assert device1.dcp_data == {"existing": True}

    def test_merge_model_first_wins(self, discovery_module):
        """Test that existing model is preserved"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(model="S7-1500")
        device2 = DiscoveredDevice(model="S7-1200")

        device1.merge_from(device2)

        assert device1.model == "S7-1500"

    def test_merge_description_first_wins(self, discovery_module):
        """Test that existing description is preserved"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(description="PLC Controller")
        device2 = DiscoveredDevice(description="Industrial Controller")

        device1.merge_from(device2)

        assert device1.description == "PLC Controller"

    def test_merge_device_type_first_wins(self, discovery_module):
        """Test that existing device_type is preserved"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(device_type="PLC")
        device2 = DiscoveredDevice(device_type="HMI")

        device1.merge_from(device2)

        assert device1.device_type == "PLC"

    def test_merge_wsdiscovery_data_keeps_existing(self, discovery_module):
        """Test that WS-Discovery data is kept (not overwritten) if already set"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(wsdiscovery_data={"types": ["old"]})
        device2 = DiscoveredDevice(wsdiscovery_data={"types": ["new"]})

        device1.merge_from(device2)

        # Existing data is kept, not overwritten
        assert device1.wsdiscovery_data == {"types": ["old"]}

    def test_merge_llmnr_data_keeps_existing(self, discovery_module):
        """Test that LLMNR data is kept (not overwritten) if already set"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(llmnr_data={"name": "OLD"})
        device2 = DiscoveredDevice(llmnr_data={"name": "NEW"})

        device1.merge_from(device2)

        # Existing data is kept, not overwritten
        assert device1.llmnr_data == {"name": "OLD"}

    def test_merge_cdp_data_keeps_existing(self, discovery_module):
        """Test that CDP data is kept (not overwritten) if already set"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(cdp_data={"device_id": "old"})
        device2 = DiscoveredDevice(cdp_data={"device_id": "new"})

        device1.merge_from(device2)

        # Existing data is kept, not overwritten
        assert device1.cdp_data == {"device_id": "old"}

    def test_merge_ssdp_data_keeps_existing(self, discovery_module):
        """Test that SSDP data is kept (not overwritten) if already set"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(ssdp_data={"location": "http://old"})
        device2 = DiscoveredDevice(ssdp_data={"location": "http://new"})

        device1.merge_from(device2)

        # Existing data is kept, not overwritten
        assert device1.ssdp_data == {"location": "http://old"}

    def test_merge_mdns_none_to_list(self, discovery_module):
        """Test merging mDNS when target has None"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(mdns_services=None)
        device2 = DiscoveredDevice(mdns_services=[{"type": "_http._tcp.local."}])

        device1.merge_from(device2)

        assert device1.mdns_services == [{"type": "_http._tcp.local."}]

    def test_merge_dnssd_none_to_dict(self, discovery_module):
        """Test merging DNS-SD when target has None"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(dnssd_data=None)
        device2 = DiscoveredDevice(dnssd_data={"services": [{"type": "_ipp._tcp.local."}]})

        device1.merge_from(device2)

        assert device1.dnssd_data is not None
        assert len(device1.dnssd_data["services"]) == 1

    def test_merge_empty_ip_not_added(self, discovery_module):
        """Test that empty/None IPs are not added"""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(ip_addresses=["192.168.1.1"])
        device2 = DiscoveredDevice(ip_addresses=["", None, "192.168.1.2"])

        device1.merge_from(device2)

        assert "" not in device1.ip_addresses
        assert None not in device1.ip_addresses
        assert "192.168.1.2" in device1.ip_addresses

    def test_merge_ipv6_normalization_dedup(self, discovery_module):
        """Test that IPv6 addresses with different formats are normalized and deduplicated.

        fe80::280:f4ff:fe0c:7be0 and fe80::0280:f4ff:fe0c:7be0 are the same address.
        """
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(
            mac_address="00:80:f4:0c:7b:e0",
            ip_addresses=["fe80::280:f4ff:fe0c:7be0"],
        )
        device2 = DiscoveredDevice(
            ip_addresses=["fe80::0280:f4ff:fe0c:7be0"],  # Same address with leading zero
        )

        device1.merge_from(device2)

        # Should only have one IPv6 address (normalized)
        assert len(device1.ip_addresses) == 1
        assert device1.ip_addresses[0] == "fe80::280:f4ff:fe0c:7be0"

    def test_merge_ipv6_with_zone_id_normalized(self, discovery_module):
        """Test that IPv6 addresses with zone IDs are normalized."""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(ip_addresses=[])
        device2 = DiscoveredDevice(ip_addresses=["fe80::1%eth0"])

        device1.merge_from(device2)

        # Zone ID should be stripped during normalization
        assert device1.ip_addresses[0] == "fe80::1"

    def test_merge_ipv6_different_addresses_kept(self, discovery_module):
        """Test that different IPv6 addresses are not deduplicated."""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(
            ip_addresses=["fe80::1"],
        )
        device2 = DiscoveredDevice(
            ip_addresses=["fe80::2"],
        )

        device1.merge_from(device2)

        assert len(device1.ip_addresses) == 2
        assert "fe80::1" in device1.ip_addresses
        assert "fe80::2" in device1.ip_addresses

    def test_merge_mixed_ipv4_ipv6(self, discovery_module):
        """Test merging devices with both IPv4 and IPv6 addresses."""
        DiscoveredDevice = discovery_module
        device1 = DiscoveredDevice(
            ip_addresses=["192.168.1.100", "fe80::280:f4ff:fe0c:7be0"],
        )
        device2 = DiscoveredDevice(
            ip_addresses=["10.0.0.50", "fe80::0280:f4ff:fe0c:7be0"],  # IPv6 dup
        )

        device1.merge_from(device2)

        # IPv4: 2 unique, IPv6: 1 (deduplicated)
        assert len(device1.ip_addresses) == 3
        assert "192.168.1.100" in device1.ip_addresses
        assert "10.0.0.50" in device1.ip_addresses
        assert "fe80::280:f4ff:fe0c:7be0" in device1.ip_addresses


class TestNormalizeIPv6:
    """Test normalize_ipv6() function"""

    def test_normalize_ipv6_removes_leading_zeros(self):
        """Test that leading zeros are removed from IPv6 segments"""
        from oida.protocols.discovery.core import normalize_ipv6

        # Standard case with leading zeros
        assert normalize_ipv6("fe80::0280:f4ff:fe0c:7be0") == "fe80::280:f4ff:fe0c:7be0"

        # Multiple segments with leading zeros
        assert normalize_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"

    def test_normalize_ipv6_strips_zone_id(self):
        """Test that zone IDs are stripped"""
        from oida.protocols.discovery.core import normalize_ipv6

        assert normalize_ipv6("fe80::1%eth0") == "fe80::1"
        assert normalize_ipv6("fe80::280:f4ff:fe0c:7be0%enp0s12u1c2") == "fe80::280:f4ff:fe0c:7be0"

    def test_normalize_ipv6_passthrough_invalid(self):
        """Test that invalid IPv6 addresses are returned unchanged"""
        from oida.protocols.discovery.core import normalize_ipv6

        assert normalize_ipv6("not-an-ip") == "not-an-ip"
        assert normalize_ipv6("192.168.1.1") == "192.168.1.1"  # IPv4 returned as-is
        assert normalize_ipv6("") == ""
        assert normalize_ipv6(None) is None

    def test_normalize_ipv6_already_normalized(self):
        """Test that already normalized addresses are unchanged"""
        from oida.protocols.discovery.core import normalize_ipv6

        assert normalize_ipv6("fe80::1") == "fe80::1"
        assert normalize_ipv6("2001:db8::1") == "2001:db8::1"
        assert normalize_ipv6("::1") == "::1"

    def test_normalize_ipv6_full_expansion(self):
        """Test normalization of fully expanded addresses"""
        from oida.protocols.discovery.core import normalize_ipv6

        assert (
            normalize_ipv6("fe80:0000:0000:0000:0280:f4ff:fe0c:7be0") == "fe80::280:f4ff:fe0c:7be0"
        )
