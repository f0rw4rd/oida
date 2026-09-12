"""Spec-anchored regression tests for src/oida/shared/ constants tables.

Every assertion here is anchored to an EXTERNAL authority, not to the code:

* IANA IPv4 Multicast Address Registry
  https://www.iana.org/assignments/multicast-addresses/multicast-addresses.txt
* IANA PIM Parameters (PIM-Hello Options, PIM Message Types)
  https://www.iana.org/assignments/pim-parameters/pim-parameters.txt
* Wireshark epan/dissectors/packet-pim.c (pim_opt_vals / pimtypevals)
* tshark 4.4.15 ``-G values`` for hsrp/hsrp2/glbp/igmp/ospf value_strings
* RFC 2328 (OSPF), RFC 3376 (IGMPv3), RFC 2281 (HSRP), RFC 7761 (PIM-SM)

Background: a bug hunt found five fabricated/mislabelled multicast group names in
``igmp_constants`` (e.g. 224.0.0.120 claimed as "BACnet/IP" when IANA assigns it to
3GPP MBMS SACH, and 224.0.1.129 claimed as "Multicast VLAN Registration" when it is
PTP-primary), plus a fabricated ``PIM_HELLO_OPTIONS[65001] = "Cisco VxLAN"`` where
both IANA and Wireshark record it as the legacy Address List option.
"""


class TestIGMPMulticastGroupNames:
    """MULTICAST_GROUPS must match the IANA IPv4 multicast registry."""

    def test_no_fabricated_bacnet_multicast_group(self):
        """224.0.0.120 is 3GPP MBMS SACH per IANA; BACnet/IP is not multicast at all.

        BACnet/IP (ASHRAE 135 Annex J) uses UDP/47808 directed broadcast plus BBMDs;
        it has no IANA multicast assignment.
        """
        from oida.shared.igmp_constants import ICS_MULTICAST_GROUPS, MULTICAST_GROUPS

        assert "BACnet" not in MULTICAST_GROUPS.get("224.0.0.120", "")
        assert "224.0.0.120" not in ICS_MULTICAST_GROUPS
        assert not any("BACnet" in name for name in ICS_MULTICAST_GROUPS.values())

    def test_ptp_primary_not_mislabelled_as_vlan_registration(self):
        """224.0.1.129 is PTP-primary (IEEE 1588) per IANA, not MVR."""
        from oida.shared.igmp_constants import MULTICAST_GROUPS

        assert "PTP" in MULTICAST_GROUPS["224.0.1.129"]
        assert "VLAN" not in MULTICAST_GROUPS["224.0.1.129"]

    def test_profinet_dcp_is_not_an_ipv4_multicast_group(self):
        """PROFINET DCP is layer 2 (EtherType 0x8892, MAC 01:0E:CF:00:00:00).

        IANA assigns 224.0.23.0 to ECHONET and 224.0.23.1 to Ricoh-device-ctrl.
        """
        from oida.shared.igmp_constants import ICS_MULTICAST_GROUPS, MULTICAST_GROUPS

        for table in (MULTICAST_GROUPS, ICS_MULTICAST_GROUPS):
            assert not any("PROFINET" in name for name in table.values())
        assert "ECHONET" in MULTICAST_GROUPS["224.0.23.0"]
        assert "Ricoh" in MULTICAST_GROUPS["224.0.23.1"]

    def test_239_255_255_253_is_slp_not_ssdp(self):
        """Relative offset 2 in an admin-scoped range is SLPv2 Discovery.

        SSDP is relative offset 5, i.e. 239.255.255.250 -- which the table already
        has, so listing .253 as "SSDP Search" is a second, bogus SSDP entry.
        """
        from oida.shared.igmp_constants import MULTICAST_GROUPS

        assert "SSDP" not in MULTICAST_GROUPS["239.255.255.253"]
        assert "SLP" in MULTICAST_GROUPS["239.255.255.253"]
        assert "SSDP" in MULTICAST_GROUPS["239.255.255.250"]

    def test_knxnet_ip_is_present_as_a_real_ics_group(self):
        """224.0.23.12 KNXnet/IP is the one genuinely-ICS group in that block."""
        from oida.shared.igmp_constants import ICS_MULTICAST_GROUPS, MULTICAST_GROUPS

        assert "KNX" in MULTICAST_GROUPS["224.0.23.12"]
        assert "224.0.23.12" in ICS_MULTICAST_GROUPS

    def test_unchanged_entries_still_match_iana(self):
        """Guard the entries that were already correct."""
        from oida.shared.igmp_constants import MULTICAST_GROUPS

        expected = {
            "224.0.0.1": "All Hosts",
            "224.0.0.2": "All Routers",
            "224.0.0.5": "OSPF Routers",
            "224.0.0.6": "OSPF DRs",
            "224.0.0.9": "RIPv2",
            "224.0.0.10": "EIGRP",
            "224.0.0.13": "PIM",
            "224.0.0.18": "VRRP",
            "224.0.0.251": "mDNS",
            "224.0.0.252": "LLMNR",
        }
        for addr, name in expected.items():
            assert MULTICAST_GROUPS[addr] == name


class TestIGMPTypeConstants:
    """RFC 3376 / tshark igmp.type value_string."""

    def test_igmp_message_types(self):
        from oida.shared import igmp_constants as c

        assert c.IGMP_PROTOCOL == 2
        assert c.IGMP_MEMBERSHIP_QUERY == 0x11
        assert c.IGMP_V1_MEMBERSHIP_REPORT == 0x12
        assert c.IGMP_V2_MEMBERSHIP_REPORT == 0x16
        assert c.IGMP_V2_LEAVE_GROUP == 0x17
        assert c.IGMP_V3_MEMBERSHIP_REPORT == 0x22


class TestPIMConstants:
    """IANA PIM Parameters + Wireshark packet-pim.c."""

    def test_hello_option_65001_is_the_legacy_address_list(self):
        """packet-pim.c: PIM_HELLO_ADDR_LST 65001 "Address list, old implementation".

        IANA reserves 65001-65535 for private use and records no VxLAN option.
        """
        from oida.shared.pim_constants import PIM_HELLO_OPTIONS

        assert "VxLAN" not in PIM_HELLO_OPTIONS[65001]
        assert "Address List" in PIM_HELLO_OPTIONS[65001]

    def test_hello_options_match_iana(self):
        from oida.shared.pim_constants import PIM_HELLO_OPTIONS

        expected = {
            1: "Hold Time",
            2: "LAN Prune Delay",
            17: "Label Parameters",
            18: "Deprecated",
            19: "DR Priority",
            20: "Generation ID",
            23: "VCI Capability",
            24: "Address List",
            25: "Neighbor List TLV",
        }
        for value, name in expected.items():
            assert PIM_HELLO_OPTIONS[value] == name
        assert "State" in PIM_HELLO_OPTIONS[21]
        assert "Bidir" in PIM_HELLO_OPTIONS[22]

    def test_message_types_cover_the_registry(self):
        """tshark pim.type defines 0-13; stopping at 8 renders State-Refresh as Unknown(9)."""
        from oida.shared.pim_constants import PIM_TYPES

        assert PIM_TYPES[0] == "Hello"
        assert PIM_TYPES[1] == "Register"
        assert PIM_TYPES[2] == "Register-Stop"
        assert PIM_TYPES[3] == "Join/Prune"
        assert PIM_TYPES[4] == "Bootstrap"
        assert PIM_TYPES[5] == "Assert"
        assert PIM_TYPES[8] == "Candidate-RP-Advertisement"
        assert "State" in PIM_TYPES[9] and "Refresh" in PIM_TYPES[9]
        assert "DF" in PIM_TYPES[10]
        assert "ECMP" in PIM_TYPES[11]


class TestOSPFConstants:
    """RFC 2328 + tshark ospf value_strings."""

    def test_ospf_tables(self):
        from oida.shared import ospf_constants as c

        assert c.OSPF_PROTOCOL == 89
        assert c.OSPF_MULTICAST_ALL_ROUTERS == "224.0.0.5"
        assert c.OSPF_MULTICAST_DR == "224.0.0.6"
        assert c.OSPF_TYPES == {
            1: "Hello",
            2: "Database Description",
            3: "Link State Request",
            4: "Link State Update",
            5: "Link State Acknowledgment",
        }
        assert c.OSPF_AUTH_TYPES[0] == "None"
        assert c.OSPF_AUTH_TYPES[1] == "Simple Password"
        assert "MD5" in c.OSPF_AUTH_TYPES[2]


class TestHSRPConstants:
    """tshark hsrp.opcode / hsrp.state / hsrp2.state value_strings (4.4.15)."""

    def test_v1_states_are_the_rfc2281_bitmap(self):
        from oida.shared.hsrp_constants import HSRP_V1_STATES

        assert HSRP_V1_STATES == {
            0: "Initial",
            1: "Learn",
            2: "Listen",
            4: "Speak",
            8: "Standby",
            16: "Active",
        }

    def test_v2_states_are_sequential(self):
        from oida.shared.hsrp_constants import HSRP_V2_STATES

        for value, name in {
            1: "Init",
            2: "Learn",
            3: "Listen",
            4: "Speak",
            5: "Standby",
            6: "Active",
        }.items():
            assert HSRP_V2_STATES[value] == name

    def test_opcodes(self):
        from oida.shared.hsrp_constants import HSRP_OPCODES, HSRP_PORT

        assert HSRP_PORT == 1985
        assert HSRP_OPCODES == {0: "Hello", 1: "Coup", 2: "Resign", 3: "Advertise"}


class TestGLBPConstants:
    """tshark glbp.hello.vgstate / glbp.reqresp.vfstate / glbp.auth.authtype."""

    def test_vg_states(self):
        from oida.shared.glbp_constants import GLBP_VG_STATES

        for value, name in {
            0x04: "Listen",
            0x08: "Speak",
            0x10: "Standby",
            0x20: "Active",
        }.items():
            assert GLBP_VG_STATES[value] == name

    def test_vf_states(self):
        from oida.shared.glbp_constants import GLBP_VF_STATES

        assert GLBP_VF_STATES[0x04] == "Listen"
        assert GLBP_VF_STATES[0x20] == "Active"

    def test_auth_types(self):
        from oida.shared.glbp_constants import GLBP_AUTH_TYPES

        assert GLBP_AUTH_TYPES == {
            0: "None",
            1: "Plain text",
            2: "MD5 string",
            3: "MD5 chain",
        }
