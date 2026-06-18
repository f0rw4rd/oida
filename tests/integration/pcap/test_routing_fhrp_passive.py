"""Integration tests for routing/FHRP passive listeners in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestOSPFPassiveEK:
    """OSPF-specific field extraction tests."""

    # -- Basic Hello extraction (generated pcap, no auth) --

    def test_ospf_hello_msg_type(self):
        """EK field 'msg' correctly identifies Hello (type 1) packets."""
        listener, devices, result = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/generated_ospf.pcap",
            expect_details=["router_id"],
        )
        assert isinstance(result, dict)
        # Message type should be "Hello", not "Type_0" (the old EK bug)
        hello_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == 1]
        assert hello_ixs, "Expected at least one Hello interaction"
        assert hello_ixs[0].details["msg_type_name"] == "Hello"
        assert "Hello" in hello_ixs[0].operation

    def test_ospf_hello_neighbors(self):
        """EK field 'hello_active_neighbor' extracts neighbor router IDs."""
        listener, _, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/generated_ospf.pcap",
            expect_details=["router_id"],
        )
        # The generated pcap has router 10.0.0.1 with neighbor 10.0.0.3
        hello_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == 1]
        assert hello_ixs, "Expected Hello interactions"
        neighbors = hello_ixs[0].details.get("neighbors", [])
        assert len(neighbors) >= 1, f"Expected at least 1 neighbor, got {neighbors}"

    def test_ospf_hello_dr_role(self):
        """DR/BDR role detection uses EK field 'hello_designated_router'."""
        listener, devices, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/generated_ospf.pcap",
            expect_details=["router_id"],
        )
        # At least one device should have DR or BDR role (not DROther for all)
        roles = set()
        for dev in devices.values():
            if hasattr(dev, "ospf_data"):
                roles.add(dev.ospf_data.get("role", ""))
        # Generated pcap has 10.0.0.1 as DR
        assert "DR" in roles or "BDR" in roles, f"Expected DR/BDR role, got {roles}"

    def test_ospf_hello_device_data(self):
        """Device ospf_data contains hello-specific fields from EK extraction."""
        listener, devices, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/generated_ospf.pcap",
            expect_details=["router_id"],
        )
        assert devices, "Expected at least one device"
        dev = next(iter(devices.values()))
        assert hasattr(dev, "ospf_data"), "Expected ospf_data on device"
        data = dev.ospf_data
        # Hello-specific fields populated from EK field names
        assert data.get("hello_interval") is not None, "hello_interval missing"
        assert data.get("dead_interval") is not None, "dead_interval missing"
        assert data.get("priority") is not None, "priority missing"
        assert data.get("network_mask"), "network_mask missing"
        assert data.get("designated_router"), "designated_router missing"

    # -- T1 field: checksum --

    def test_ospf_checksum_extracted(self):
        """T1 field 'ospf.checksum' is extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/generated_ospf.pcap",
            expect_details=["router_id"],
        )
        for ix in listener.interactions:
            checksum = ix.details.get("checksum")
            assert checksum is not None, "checksum missing from interaction details"
            assert checksum != "?", "checksum should not be '?' for valid packets"

    def test_ospf_checksum_in_device(self):
        """T1 field 'ospf.checksum' is stored in device ospf_data."""
        _, devices, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/generated_ospf.pcap",
            expect_details=["router_id"],
        )
        dev = next(iter(devices.values()))
        assert "checksum" in dev.ospf_data, "checksum missing from device ospf_data"

    # -- T1 field: instance_id --

    def test_ospf_instance_id_extracted(self):
        """T1 field 'ospf.instance_id' is extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/generated_ospf.pcap",
            expect_details=["router_id"],
        )
        for ix in listener.interactions:
            instance_id = ix.details.get("instance_id")
            assert instance_id is not None, "instance_id missing from interaction details"
            assert instance_id != "?", "instance_id should not be '?' for valid packets"

    def test_ospf_instance_id_in_device(self):
        """T1 field 'ospf.instance_id' is stored in device ospf_data."""
        _, devices, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/generated_ospf.pcap",
            expect_details=["router_id"],
        )
        dev = next(iter(devices.values()))
        assert "instance_id" in dev.ospf_data, "instance_id missing from device ospf_data"

    # -- T1 fields: MD5 crypto (auth_crypt_key_id, auth_crypt_data_length, auth_crypt_seq_nbr) --

    def test_ospf_md5_crypt_key_id(self):
        """T1 field 'ospf.auth.crypt.key_id' extracted from MD5-authenticated packets."""
        listener, _, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/wireshark_ospf_md5.cap",
            expect_details=["router_id"],
        )
        assert listener.credentials, "Expected MD5 credentials"
        for cred in listener.credentials:
            assert cred.crypt_key_id, f"crypt_key_id empty for {cred.router_ip}"
            assert cred.crypt_key_id != "?", f"crypt_key_id is '?' for {cred.router_ip}"

    def test_ospf_md5_crypt_data_length(self):
        """T1 field 'ospf.auth.crypt.data_length' extracted from MD5 packets."""
        listener, _, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/wireshark_ospf_md5.cap",
            expect_details=["router_id"],
        )
        assert listener.credentials, "Expected MD5 credentials"
        for cred in listener.credentials:
            assert cred.crypt_data_length, f"crypt_data_length empty for {cred.router_ip}"
            assert cred.crypt_data_length == "16", (
                f"Expected MD5 data length 16, got {cred.crypt_data_length}"
            )

    def test_ospf_md5_crypt_seq_nbr(self):
        """T1 field 'ospf.auth.crypt.seq_nbr' extracted for replay detection."""
        listener, _, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/wireshark_ospf_md5.cap",
            expect_details=["router_id"],
        )
        assert listener.credentials, "Expected MD5 credentials"
        for cred in listener.credentials:
            assert cred.crypt_seq_nbr, f"crypt_seq_nbr empty for {cred.router_ip}"
            assert cred.crypt_seq_nbr != "?", f"crypt_seq_nbr is '?' for {cred.router_ip}"
            # Sequence numbers should be large integers
            assert int(cred.crypt_seq_nbr) > 0, "crypt_seq_nbr should be > 0"

    def test_ospf_md5_credentials_in_summary(self):
        """MD5 crypto fields appear in get_credentials_summary() output."""
        listener, _, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/wireshark_ospf_md5.cap",
            expect_details=["router_id"],
        )
        summaries = listener.get_credentials_summary()
        assert summaries, "Expected credential summaries"
        for entry in summaries:
            assert entry["credential_type"] == "hash"
            assert entry["auth_method"] == "Cryptographic (MD5)"
            assert "crypt_key_id" in entry, "crypt_key_id missing from summary"
            assert "crypt_seq_nbr" in entry, "crypt_seq_nbr missing from summary"

    # -- T1 field: db_dd_sequence (Database Description) --

    def test_ospf_dbd_dd_sequence(self):
        """T1 field 'ospf.db.dd_sequence' extracted from DBD packets."""
        listener, _, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/wireshark_ospf.cap",
            expect_details=["router_id"],
        )
        # Find DBD interactions (msg_type == 2)
        dbd_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == 2]
        assert dbd_ixs, "Expected Database Description interactions"
        for ix in dbd_ixs:
            dd_seq = ix.details.get("dd_sequence")
            assert dd_seq is not None, "dd_sequence missing from DBD interaction"
            assert dd_seq != "?", "dd_sequence should not be '?' for valid DBD packets"
            assert int(dd_seq) > 0, f"dd_sequence should be > 0, got {dd_seq}"

    def test_ospf_dbd_interface_mtu(self):
        """T2 field 'ospf.db.interface_mtu' extracted from DBD packets."""
        listener, _, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/wireshark_ospf.cap",
            expect_details=["router_id"],
        )
        dbd_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == 2]
        assert dbd_ixs, "Expected Database Description interactions"
        for ix in dbd_ixs:
            mtu = ix.details.get("interface_mtu")
            assert mtu is not None, "interface_mtu missing from DBD interaction"
            assert mtu != "?", "interface_mtu should not be '?' for valid DBD packets"

    # -- Multi-message-type coverage (wireshark_ospf.cap) --

    def test_ospf_all_message_types(self):
        """wireshark_ospf.cap contains Hello, DBD, LSR, LSU, LSAck -- all identified."""
        listener, _, _ = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/wireshark_ospf.cap",
            expect_details=["router_id"],
        )
        ops = {ix.operation for ix in listener.interactions}
        expected = {
            "OSPF Hello",
            "OSPF Database Description",
            "OSPF Link State Request",
            "OSPF Link State Update",
            "OSPF Link State Acknowledgment",
        }
        for exp in expected:
            assert exp in ops, f"Missing operation: {exp}; got {ops}"

    # -- Harvest output quality --

    def test_ospf_harvest_returns_dict(self):
        """harvest() returns a dict."""
        _, _, result = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/wireshark_ospf.cap",
            expect_details=["router_id"],
        )
        assert isinstance(result, dict), "harvest() should return a dict"


# ---------------------------------------------------------------------------
# HSRP integration tests
# ---------------------------------------------------------------------------


class TestHSRPPassiveEK:
    """HSRP passive listener integration tests.

    Validates that the HSRP listener correctly extracts fields from both
    HSRPv1 and HSRPv2 packets in EK mode, including the hsrp2_* field
    naming required by tshark's EK JSON output.
    """

    def test_hsrp_basic_smoke(self):
        """Smoke test: listener discovers devices and records interactions."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
            min_devices=2,
            min_interactions=10,
        )
        assert isinstance(result, dict), "Expected harvest to return a dict"

    def test_hsrp_v2_version_detected(self):
        """HSRPv2 packets must be identified as version=2, not 1."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        v2_interactions = [ix for ix in listener.interactions if ix.details.get("version") == 2]
        assert len(v2_interactions) > 0, (
            "No HSRPv2 interactions found -- version detection likely broken. "
            f"Versions seen: {set(ix.details.get('version') for ix in listener.interactions)}"
        )

    def test_hsrp_v2_opcode_extracted(self):
        """HSRPv2 opcode field (hsrp2.opcode) must be extracted."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        v2_hellos = [
            ix
            for ix in listener.interactions
            if ix.details.get("version") == 2 and "Hello" in ix.operation
        ]
        assert len(v2_hellos) > 0, "No HSRPv2 Hello interactions found"

    def test_hsrp_v2_state_correct(self):
        """HSRPv2 state must use v2 state names (Active=6, not Initial=0)."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        v2_states = {
            ix.details.get("state")
            for ix in listener.interactions
            if ix.details.get("version") == 2
        }
        assert "Active" in v2_states or "Standby" in v2_states, (
            f"Expected Active or Standby in v2 states, got: {v2_states}. "
            "State extraction likely using v1 state map for v2 packets."
        )

    def test_hsrp_v2_virtual_ip(self):
        """HSRPv2 virtual IP (hsrp2.virt_ip) must be extracted."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        v2_with_vip = [
            ix
            for ix in listener.interactions
            if ix.details.get("version") == 2 and ix.details.get("virtual_ip")
        ]
        assert len(v2_with_vip) > 0, (
            "No HSRPv2 interaction has a virtual_ip. "
            "hsrp2_virt_ip field likely not extracted in EK mode."
        )
        vips = {ix.details["virtual_ip"] for ix in v2_with_vip}
        assert any(vip and vip != "?" for vip in vips), f"All v2 VIPs are empty or '?': {vips}"

    def test_hsrp_v2_group_and_priority(self):
        """HSRPv2 group (hsrp2.group) and priority (hsrp2.priority) must be extracted."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        v2_ixs = [ix for ix in listener.interactions if ix.details.get("version") == 2]
        assert len(v2_ixs) > 0
        groups = {ix.details.get("group") for ix in v2_ixs}
        assert groups != {0}, (
            f"All v2 groups are 0 (default) -- hsrp2_group not extracted. Groups: {groups}"
        )
        priorities = {ix.details.get("priority") for ix in v2_ixs}
        assert priorities != {100}, (
            "All v2 priorities are 100 (default) -- hsrp2_priority not extracted."
        )

    def test_hsrp_v2_holdtime(self):
        """HSRPv2 holdtime (hsrp2.holdtime) must be in interaction details."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        v2_with_holdtime = [
            ix
            for ix in listener.interactions
            if ix.details.get("version") == 2 and ix.details.get("hold_time") is not None
        ]
        assert len(v2_with_holdtime) > 0, "No HSRPv2 interaction has hold_time in details"
        hold_times = {ix.details["hold_time"] for ix in v2_with_holdtime}
        assert any(ht > 0 for ht in hold_times), f"All hold_times are 0: {hold_times}"

    def test_hsrp_v2_ipversion(self):
        """HSRPv2 IP version (hsrp2.ipversion) must be in interaction details."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        v2_with_ipver = [
            ix
            for ix in listener.interactions
            if ix.details.get("version") == 2 and ix.details.get("ip_version") is not None
        ]
        assert len(v2_with_ipver) > 0, "No HSRPv2 interaction has ip_version in details"

    def test_hsrp_v2_md5_auth_tlv(self):
        """HSRPv2 MD5 auth TLV type (hsrp2.md5_auth_tlv) must be extracted."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        md5_ixs = [ix for ix in listener.interactions if ix.details.get("md5_auth_tlv") is not None]
        assert len(md5_ixs) > 0, (
            "No interaction has md5_auth_tlv -- hsrp2_md5_auth_tlv not extracted"
        )
        tlv_types = {ix.details["md5_auth_tlv"] for ix in md5_ixs}
        assert 4 in tlv_types, f"Expected md5_auth_tlv=4 (MD5 Authentication), got: {tlv_types}"

    def test_hsrp_v2_md5_key_id(self):
        """HSRPv2 MD5 key ID (hsrp2.md5_key_id) must be extracted."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        md5_ixs = [ix for ix in listener.interactions if ix.details.get("md5_key_id") is not None]
        assert len(md5_ixs) > 0, "No interaction has md5_key_id -- hsrp2_md5_key_id not extracted"

    def test_hsrp_v2_md5_auth_data(self):
        """HSRPv2 MD5 digest (hsrp2.md5_auth_data) must be extracted."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        md5_ixs = [
            ix
            for ix in listener.interactions
            if ix.details.get("md5_auth_data") and ix.details["md5_auth_data"] != "?"
        ]
        assert len(md5_ixs) > 0, "No interaction has a non-placeholder md5_auth_data digest"
        sample = md5_ixs[0].details["md5_auth_data"]
        assert ":" in sample, f"MD5 digest doesn't look like hex bytes: {sample!r}"

    def test_hsrp_v1_plaintext_auth(self):
        """HSRPv1 plaintext auth (hsrp.auth_data) must be extracted."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        v1_with_auth = [
            ix
            for ix in listener.interactions
            if ix.details.get("version") == 1
            and ix.details.get("auth_data")
            and ix.details["auth_type"] == "plaintext"
        ]
        assert len(v1_with_auth) > 0, "No HSRPv1 interaction has plaintext auth_data."
        auth_values = {ix.details["auth_data"] for ix in v1_with_auth}
        assert "cisco" in auth_values, (
            f"Expected 'cisco' plaintext auth in v1 packets, got: {auth_values}"
        )

    def test_hsrp_v1_virt_ip(self):
        """HSRPv1 virtual IP (hsrp.virt_ip) must be extracted."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        v1_with_vip = [
            ix
            for ix in listener.interactions
            if ix.details.get("version") == 1
            and ix.details.get("virtual_ip")
            and ix.details["virtual_ip"] != "?"
        ]
        assert len(v1_with_vip) > 0, (
            "No HSRPv1 interaction has a virtual_ip -- hsrp.virt_ip likely not read"
        )

    def test_hsrp_device_data_populated(self):
        """Discovered devices must have hsrp_data with protocol fields."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
            min_devices=2,
        )
        for _key, device in devices.items():
            hsrp_data = getattr(device, "hsrp_data", None)
            if hsrp_data and hsrp_data.get("version") == 2:
                assert hsrp_data.get("virtual_ip"), f"v2 device missing virtual_ip: {hsrp_data}"
                assert hsrp_data.get("group") is not None, "Missing group"
                assert hsrp_data.get("state_name"), "Missing state_name"
                assert hsrp_data.get("md5_auth_data"), (
                    "v2 device with MD5 should have md5_auth_data"
                )
                break
        else:
            pytest.fail("No v2 device found in discovered_devices")

    def test_hsrp_credentials_summary(self):
        """get_credentials_summary() must return scanner-compatible dicts."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, "Expected at least one credential from HSRP"
        for c in creds:
            assert "credential_type" in c, f"Missing credential_type: {c}"
            assert "username" in c, f"Missing username: {c}"
            assert "server_ip" in c, f"Missing server_ip: {c}"
            assert "client_ip" in c, f"Missing client_ip: {c}"
            assert "auth_method" in c, f"Missing auth_method: {c}"

    def test_hsrp_harvest_returns_dict(self):
        """harvest() must return a dict."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        assert isinstance(result, dict), "harvest() should return a dict"

    def test_hsrp_no_raw_dicts_in_table_cells(self):
        """Table cells must not contain raw dict/set objects."""
        listener, devices, result = _run_listener_test(
            "hsrp",
            "HSRPPassiveListener",
            "hsrp",
            "hsrp/filtered_hsrp.pcap",
        )
        for table in result.get("tables", []):
            for row in table.get("rows", []):
                for cell in row:
                    assert not isinstance(cell, dict), f"Raw dict in {table['title']} cell: {cell}"
                    assert not isinstance(cell, set), f"Raw set in {table['title']} cell: {cell}"


class TestVRRPPassiveEK:
    """VRRP-specific field extraction tests using EK-mode pcap fixtures."""

    # -- Basic field extraction --

    def test_vrrp_basic_extraction(self):
        """VRRP listener extracts devices, interactions, and produces tables."""
        listener, devices, result = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["vrid", "version", "priority"],
        )
        assert devices, "Expected at least one device"
        assert isinstance(result, dict)

    # -- T1 field: vrrp.version --

    def test_vrrp_version_extracted(self):
        """T1 field 'vrrp.version' correctly extracted (not falling to default)."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["version"],
        )
        for ix in listener.interactions:
            version = ix.details.get("version")
            assert version is not None, "version missing from interaction details"
            assert version == 2, f"Expected version 2, got {version}"

    # -- T1 field: vrrp.virt_rtr_id --

    def test_vrrp_virt_rtr_id_extracted(self):
        """T1 field 'vrrp.virt_rtr_id' correctly extracted (not zero default)."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["vrid"],
        )
        for ix in listener.interactions:
            vrid = ix.details.get("vrid")
            assert vrid is not None, "vrid missing from interaction details"
            # The fixture has VRID=1, not the old broken 0
            assert vrid == 1, f"Expected VRID 1, got {vrid}"

    def test_vrrp_vrid_in_device_data(self):
        """VRID stored in device vrrp_data from 'vrrp.virt_rtr_id' field."""
        _, devices, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["vrid"],
        )
        dev = next(iter(devices.values()))
        assert hasattr(dev, "vrrp_data"), "Expected vrrp_data on device"
        assert dev.vrrp_data["vrid"] == 1, (
            f"Expected VRID 1 in device data, got {dev.vrrp_data['vrid']}"
        )

    # -- T1 field: vrrp.addr_count --

    def test_vrrp_addr_count_extracted(self):
        """T1 field 'vrrp.addr_count' extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["addr_count"],
        )
        for ix in listener.interactions:
            addr_count = ix.details.get("addr_count")
            assert addr_count is not None, "addr_count missing from interaction details"
            assert addr_count == 1, f"Expected addr_count 1, got {addr_count}"

    def test_vrrp_addr_count_in_device_data(self):
        """addr_count stored in device vrrp_data."""
        _, devices, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["addr_count"],
        )
        dev = next(iter(devices.values()))
        assert dev.vrrp_data.get("addr_count") == 1, "addr_count missing or wrong in device data"

    # -- T1 field: vrrp.checksum --

    def test_vrrp_checksum_extracted(self):
        """T1 field 'vrrp.checksum' extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["checksum"],
        )
        for ix in listener.interactions:
            checksum = ix.details.get("checksum")
            assert checksum is not None, "checksum missing from interaction details"
            assert checksum != "?", "checksum should not be '?' for valid packets"

    # -- T1 field: vrrp.checksum.status --

    def test_vrrp_checksum_status_extracted(self):
        """T1 field 'vrrp.checksum.status' extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["checksum_status"],
        )
        for ix in listener.interactions:
            cs_status = ix.details.get("checksum_status")
            assert cs_status is not None, "checksum_status missing from interaction details"
            # Status 1 = good checksum in tshark
            assert cs_status == 1, f"Expected checksum_status 1 (good), got {cs_status}"

    # -- T1 field: vrrp.md5_auth_data --

    def test_vrrp_md5_auth_data_extracted(self):
        """T1 field 'vrrp.md5_auth_data' extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["md5_auth_data"],
        )
        md5_ixs = [ix for ix in listener.interactions if ix.details.get("md5_auth_data")]
        assert md5_ixs, "Expected interactions with md5_auth_data"
        # MD5 digest should be a hex string with colons
        md5_val = md5_ixs[0].details["md5_auth_data"]
        assert ":" in md5_val, f"Expected colon-separated hex MD5 digest, got {md5_val}"

    def test_vrrp_md5_credential_extracted(self):
        """MD5 auth data creates a hash-type credential."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["md5_auth_data"],
        )
        assert listener.credentials, "Expected at least one credential"
        md5_creds = [c for c in listener.credentials if c.credential_type == "hash"]
        assert md5_creds, "Expected MD5 hash credentials"
        cred = md5_creds[0]
        assert cred.auth_type == 254, f"Expected auth_type 254, got {cred.auth_type}"
        assert cred.auth_type_name == "MD5", f"Expected MD5, got {cred.auth_type_name}"
        assert cred.md5_hash, "MD5 hash should not be empty"
        assert ":" in cred.md5_hash, "MD5 hash should be colon-separated hex"

    def test_vrrp_md5_credential_dedup(self):
        """Duplicate MD5 credentials from repeated advertisements are deduped."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
        )
        # The fixture has 818 VRRP packets from two routers (192.168.42.5 and
        # 192.168.42.4) sharing VRID 1 with the same MD5 hash. Should have
        # exactly 2 credentials (one per router_ip), not 818.
        md5_creds = [c for c in listener.credentials if c.credential_type == "hash"]
        router_ips = {c.router_ip for c in md5_creds}
        assert len(md5_creds) == len(router_ips), (
            f"Expected 1 credential per router, got {len(md5_creds)} creds "
            f"for {len(router_ips)} routers"
        )
        # Each router has exactly one credential (dedup works within same router_ip+vrid)
        assert len(md5_creds) <= 2, (
            f"Expected at most 2 deduped MD5 credentials (one per router), got {len(md5_creds)}"
        )

    def test_vrrp_md5_credential_canonical_fields(self):
        """MD5 credential exposes canonical field names for scanner compatibility."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
        )
        assert listener.credentials, "Expected credentials"
        cred = listener.credentials[0]
        # Canonical fields via @property
        assert cred.server_ip, "server_ip should not be empty"
        assert cred.client_ip, "client_ip should not be empty"
        assert cred.username, "username should not be empty"
        assert cred.auth_method == "MD5", "auth_method should be 'MD5'"
        assert cred.hash_value, "hash_value should not be empty"
        assert cred.credential_type == "hash", "credential_type should be 'hash'"

    def test_vrrp_md5_in_credentials_summary(self):
        """MD5 hash appears in get_credentials_summary() with hash_value key."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
        )
        summaries = listener.get_credentials_summary()
        assert summaries, "Expected credential summaries"
        md5_entries = [s for s in summaries if s.get("credential_type") == "hash"]
        assert md5_entries, "Expected hash-type credential in summary"
        entry = md5_entries[0]
        assert "hash_value" in entry, "hash_value missing from summary"
        assert entry["auth_method"] == "MD5"
        assert entry["server_ip"], "server_ip missing from summary"

    # -- Virtual IP extraction (EK field: ip_addr) --

    def test_vrrp_virtual_ips_extracted(self):
        """Virtual IPs extracted using EK field 'ip_addr' (not broken 'ip')."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["virtual_ips"],
        )
        for ix in listener.interactions:
            vips = ix.details.get("virtual_ips", [])
            assert vips, f"Expected virtual_ips, got {vips}"
            assert "192.168.42.1" in vips, f"Expected 192.168.42.1 in {vips}"

    def test_vrrp_virtual_ips_in_device_data(self):
        """Virtual IPs stored in device vrrp_data."""
        _, devices, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
        )
        dev = next(iter(devices.values()))
        assert dev.vrrp_data.get("virtual_ips"), "virtual_ips missing from device data"
        assert "192.168.42.1" in dev.vrrp_data["virtual_ips"]

    # -- Auth type extraction --

    def test_vrrp_auth_type_in_details(self):
        """Auth type name appears in interaction details."""
        listener, _, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
        )
        for ix in listener.interactions:
            auth_type_name = ix.details.get("auth_type_name")
            assert auth_type_name is not None, "auth_type_name missing"
            # The fixture uses auth_type 254 = MD5
            assert auth_type_name == "MD5", f"Expected MD5, got {auth_type_name}"

    def test_vrrp_auth_type_in_device_data(self):
        """Auth type stored in device vrrp_data."""
        _, devices, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
        )
        dev = next(iter(devices.values()))
        assert dev.vrrp_data.get("auth_type") == 254, "auth_type should be 254"
        assert dev.vrrp_data.get("auth_type_name") == "MD5", "auth_type_name should be MD5"

    # -- Harvest output quality --

    def test_vrrp_harvest_returns_dict(self):
        """harvest() returns a dict."""
        _, _, result = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
        )
        assert isinstance(result, dict), "harvest() should return a dict"

    def test_vrrp_harvest_no_raw_dicts_in_cells(self):
        """No raw dicts or sets in any table cell."""
        _, _, result = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
        )
        for table in result.get("tables", []):
            for row in table.get("rows", []):
                for cell in row:
                    assert not isinstance(cell, dict), f"Raw dict in cell: {cell}"
                    assert not isinstance(cell, set), f"Raw set in cell: {cell}"

    # -- Device data quality --

    def test_vrrp_device_data_complete(self):
        """Device vrrp_data contains all expected fields."""
        _, devices, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
        )
        dev = next(iter(devices.values()))
        assert hasattr(dev, "vrrp_data"), "Expected vrrp_data on device"
        data = dev.vrrp_data
        required = [
            "version",
            "vrid",
            "priority",
            "state",
            "state_name",
            "is_master",
            "virtual_ips",
            "addr_count",
            "adver_int",
            "auth_type",
            "auth_type_name",
            "protocol",
            "multicast_dst",
        ]
        for field in required:
            assert field in data, f"Missing '{field}' in vrrp_data"

    def test_vrrp_device_type(self):
        """Device type reflects VRRP master/backup role."""
        _, devices, _ = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
        )
        dev = next(iter(devices.values()))
        assert "VRRP" in dev.device_type, f"Expected VRRP in device_type, got {dev.device_type}"
        # The fixture router has priority 100 (not 255), so it's Backup
        assert "Backup" in dev.device_type, f"Expected Backup in device_type, got {dev.device_type}"


class TestRoutingFHRPPassiveEK:
    """Routing and FHRP protocol tests beyond the parametrized quality suite."""

    def test_ospf(self):
        listener, devices, result = _run_listener_test(
            "ospf",
            "OSPFPassiveListener",
            "ospf",
            "ospf/generated_ospf.pcap",
            expect_details=["router_id"],
        )
        # Harvest should produce tables (PROTOCOL_COLUMNS is set)
        assert isinstance(result, dict)

    def test_eigrp(self):
        listener, devices, result = _run_listener_test(
            "eigrp",
            "EIGRPPassiveListener",
            "eigrp",
            "eigrp/generated_eigrp.pcap",
            expect_details=["opcode"],
        )
        assert isinstance(result, dict)

    def test_rip(self):
        listener, devices, result = _run_listener_test(
            "rip",
            "RIPPassiveListener",
            "rip",
            "rip/generated_rip.pcap",
        )
        assert isinstance(result, dict)

    def test_pim(self):
        listener, devices, result = _run_listener_test(
            "pim",
            "PIMPassiveListener",
            "pim",
            "pim/generated_pim.pcap",
        )
        assert isinstance(result, dict)

    def test_glbp(self):
        listener, devices, result = _run_listener_test(
            "glbp",
            "GLBPPassiveListener",
            "glbp",
            "glbp/generated_glbp.pcap",
        )
        assert isinstance(result, dict)

    def test_vrrp(self):
        listener, devices, result = _run_listener_test(
            "vrrp",
            "VRRPPassiveListener",
            "vrrp",
            "vrrp/filtered_vrrp.pcap",
            expect_details=["vrid", "version"],
        )
        assert isinstance(result, dict)

    def test_bfd(self):
        listener, devices, result = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
            min_interactions=0,
        )
        # BFD may have zero interactions -- just assert no crash
        assert isinstance(devices, dict)
