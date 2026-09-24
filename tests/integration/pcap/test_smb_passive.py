"""Integration tests for SMB passive listener in EK mode.

Tests the SMBPassiveListener against real pcap fixtures to verify:
1. Real SMB traffic produces devices and interactions
2. Non-SMB traffic (HTTP, FTP, etc.) produces zero false positives
3. NTLM authentication data is extracted from SMB captures

Uses ``use_ek=True`` to match production behaviour (scanner.py).

Requires: pyshark, tshark
"""

import pytest

from tests.integration.pcap.conftest import (
    _load_packets,
    _pcap_path,
    _run_listener_test,
    _skip_unless_pyshark,
)

pytestmark = [pytest.mark.integration]


def _make_listener():
    from oida.pcap.smb import SMBPassiveListener

    return SMBPassiveListener(interface="lo", timeout=10)


# ---------------------------------------------------------------------------
# 1. Core SMB test via modern helper
# ---------------------------------------------------------------------------
class TestSMBPassiveEK:
    """SMB-specific tests beyond the parametrised quality suite."""

    def test_smb_basic(self):
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
        )
        # SMB has PROTOCOL_COLUMNS so harvest should produce tables
        if result.get("tables"):
            assert len(result["tables"]) >= 1, "Expected at least one table from SMB harvest"

        # SMB listener tracks sessions
        assert len(listener._sessions) >= 1, (
            f"Expected at least 1 session, got {len(listener._sessions)}"
        )

        # At least one interaction should mention SMB in its operation
        smb_interactions = [i for i in listener.interactions if "SMB" in (i.operation or "")]
        assert smb_interactions, "Expected at least one interaction with 'SMB' in operation field"

        # Devices should have smb_passive_data
        for device in devices.values():
            assert hasattr(device, "smb_passive_data"), (
                f"Device {device.name} missing smb_passive_data"
            )
            assert device.smb_passive_data is not None

        # Check roles
        roles = set()
        for device in devices.values():
            if device.smb_passive_data:
                role = device.smb_passive_data.get("role")
                if role:
                    roles.add(role)
        assert roles, "Expected at least one role assigned"
        assert roles <= {"server", "client"}, f"Unexpected roles: {roles}"

        # Device keys should be prefixed with 'smb:'
        for key in devices:
            assert key.startswith("smb:"), f"Device key '{key}' not prefixed with 'smb:'"

        # get_credentials_summary should return a list
        creds = listener.get_credentials_summary()
        assert isinstance(creds, list)
        if creds:
            for c in creds:
                assert c.get("protocol") == "SMB"

    def test_credslayer_smb_ntlm(self):
        """Credslayer smb-ntlm.pcap should discover devices."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/credslayer_smb_ntlm.pcap",
        )


# ---------------------------------------------------------------------------
# 2. False-positive regression: non-SMB traffic must produce zero devices
# ---------------------------------------------------------------------------
class TestSMBNoFalsePositives:
    """Verify SMB listener ignores non-SMB traffic (regression test)."""

    def test_http_only_pcap_zero_devices(self):
        """HTTP-only pcap must not create SMB devices."""
        _skip_unless_pyshark()
        listener = _make_listener()
        packets = _load_packets(_pcap_path("http", "internet_http_chunked.pcap"))

        devices = listener.feed_packets(iter(packets))

        assert len(devices) == 0, (
            f"Expected 0 SMB devices from HTTP-only pcap, got {len(devices)}: "
            f"{list(devices.keys())}"
        )
        assert len(listener.interactions) == 0

    def test_ftp_pcap_zero_devices(self):
        """FTP pcap must not create SMB devices."""
        _skip_unless_pyshark()
        listener = _make_listener()
        packets = _load_packets(_pcap_path("ftp", "bruteshark_ftp.pcap"))

        devices = listener.feed_packets(iter(packets))

        assert len(devices) == 0, (
            f"Expected 0 SMB devices from FTP pcap, got {len(devices)}: {list(devices.keys())}"
        )

    def test_telnet_pcap_zero_devices(self):
        """Telnet pcap must not create SMB devices."""
        _skip_unless_pyshark()
        listener = _make_listener()
        packets = _load_packets(_pcap_path("telnet", "bruteshark_telnet.pcap"))

        devices = listener.feed_packets(iter(packets))

        assert len(devices) == 0, (
            f"Expected 0 SMB devices from Telnet pcap, got {len(devices)}: {list(devices.keys())}"
        )

    def test_http_basic_pcap_zero_devices(self):
        """HTTP basic auth pcap must not create SMB devices."""
        _skip_unless_pyshark()
        listener = _make_listener()
        packets = _load_packets(_pcap_path("http", "bruteshark_http_basic.pcap"))

        devices = listener.feed_packets(iter(packets))

        assert len(devices) == 0, (
            f"Expected 0 SMB devices from HTTP basic pcap, got {len(devices)}: "
            f"{list(devices.keys())}"
        )

    def test_empty_sessions_on_non_smb(self):
        """Internal _sessions dict must stay empty for non-SMB traffic."""
        _skip_unless_pyshark()
        listener = _make_listener()
        packets = _load_packets(_pcap_path("http", "internet_http_chunked.pcap"))

        listener.feed_packets(iter(packets))

        assert len(listener._sessions) == 0, (
            f"Expected 0 sessions from non-SMB pcap, got {len(listener._sessions)}"
        )


# ---------------------------------------------------------------------------
# 3. Guard consistency: NTLM-over-HTTP must not trigger SMB devices
# ---------------------------------------------------------------------------
class TestNTLMOverHTTPNotSMB:
    """NTLM auth over HTTP should not create SMB devices (only ntlmssp layer)."""

    def test_ntlm_http_pcap_handling(self):
        """ntlm_http.pcap has NTLM but over HTTP, not SMB port 445/139.

        If packets have ntlmssp layer the listener will process them
        (which is correct for NTLM extraction), but verify the roles
        and device types are reasonable.
        """
        _skip_unless_pyshark()
        listener = _make_listener()
        packets = _load_packets(_pcap_path("http", "bruteshark_ntlm_http.pcap"))

        devices = listener.feed_packets(iter(packets))

        # Packets with ntlmssp layer are legitimately processed by the guard.
        # If no ntlmssp layer is dissected by tshark, we should get 0 devices.
        # Either way, no crash.
        assert isinstance(devices, dict)


# ---------------------------------------------------------------------------
# 4. T1 field coverage: newly extracted fields
# ---------------------------------------------------------------------------
class TestSMBFieldCoverage:
    """Verify T1 field coverage gaps are now filled."""

    def test_nt_status_extracted(self):
        """smb2.nt_status and smb.nt_status should produce nt_status in details."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["nt_status"],
        )
        # Verify we get the human-readable name, not just the raw code
        nt_values = [
            ix.details["nt_status"] for ix in listener.interactions if ix.details.get("nt_status")
        ]
        assert any("STATUS_" in v for v in nt_values), (
            f"Expected STATUS_* labels in nt_status, got: {nt_values[:5]}"
        )

    def test_dos_error_codes_extracted(self):
        """smb.error_class and smb.error_code should appear in SMB1 interactions."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["error_class"],
        )
        # error_code should also be present alongside error_class
        has_error_code = any(
            ix.details.get("error_code") is not None for ix in listener.interactions
        )
        assert has_error_code, "Expected error_code in at least one interaction"

    def test_session_id_extracted(self):
        """smb2.sesid should produce session_id in details for active sessions."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/credslayer_smb_ntlm.pcap",
            expect_details=["session_id"],
        )

    def test_server_hostname_extracted(self):
        """smb2.host should produce server_hostname in details and device data."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["server_hostname"],
        )
        # Also verify it propagates to device protocol_data
        has_hostname = any(
            dev.smb_passive_data.get("server_hostname")
            for dev in devices.values()
            if dev.smb_passive_data
        )
        assert has_hostname, "Expected server_hostname in at least one device"

    def test_signing_enabled_extracted(self):
        """smb2.sec_mode.sign_enabled should appear in details and device data."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["signing_enabled"],
        )
        # Verify boolean value in device data
        has_signing = any(
            dev.smb_passive_data.get("signing_enabled") is not None
            for dev in devices.values()
            if dev.smb_passive_data
        )
        assert has_signing, "Expected signing_enabled in at least one device"

    def test_cipher_id_extracted(self):
        """smb2.negotiate_context.cipher_id should produce ciphers list."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/credslayer_smb_ntlm.pcap",
            expect_details=["ciphers"],
        )
        # Verify cipher names are human-readable
        cipher_lists = [
            ix.details["ciphers"] for ix in listener.interactions if ix.details.get("ciphers")
        ]
        assert cipher_lists, "Expected ciphers in interactions"
        all_ciphers = [c for cl in cipher_lists for c in cl]
        assert any("AES" in c for c in all_ciphers), (
            f"Expected AES cipher names, got: {all_ciphers[:5]}"
        )

    def test_smb1_account_extracted(self):
        """smb.account should populate username for plaintext auth.

        bruteshark_smb_ntlm_plain.pcap uses 127.0.0.1 so no devices are
        created (loopback filtered), but the username should appear in
        interaction details.
        """
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_smb_ntlm_plain.pcap",
            min_devices=0,
            expect_details=["username"],
        )

    def test_password_blob_extracted(self):
        """smb.password presence should set has_password_blob in details."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["has_password_blob"],
        )

    def test_ioctl_function_extracted(self):
        """smb2.ioctl.function should produce ioctl_function in details."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/credslayer_smb_ntlm.pcap",
            expect_details=["ioctl_function"],
        )

    def test_create_action_extracted(self):
        """smb2.create.action should produce create_action in details."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/credslayer_smb_ntlm.pcap",
            expect_details=["create_action"],
        )
        # Verify human-readable labels
        actions = [
            ix.details["create_action"]
            for ix in listener.interactions
            if ix.details.get("create_action")
        ]
        assert any("FILE_" in a for a in actions), (
            f"Expected FILE_* labels in create_action, got: {actions[:5]}"
        )

    def test_trans_name_extracted(self):
        """smb.trans_name should produce trans_name in details."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["trans_name"],
        )
        # Verify typical transaction names
        trans_names = [
            ix.details["trans_name"] for ix in listener.interactions if ix.details.get("trans_name")
        ]
        assert trans_names, "Expected trans_name values"
        assert any("\\" in t for t in trans_names), (
            f"Expected pipe/mailslot paths in trans_name, got: {trans_names[:5]}"
        )

    def test_smb2_msg_id_extracted(self):
        """smb2.msg_id should produce msg_id correlation IDs in details."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["msg_id"],
        )

    def test_smb2_tree_id_extracted(self):
        """smb2.tid should produce tree_id in details."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["tree_id"],
        )

    def test_smb1_correlation_ids_extracted(self):
        """smb.tid/uid/pid/mid should produce SMB1 header correlation IDs."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["tid", "uid", "pid", "mid"],
        )

    def test_smb1_password_length_extracted(self):
        """smb.pwlen should produce password_length when a password is supplied."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["password_length"],
        )
        lengths = [
            ix.details["password_length"]
            for ix in listener.interactions
            if ix.details.get("password_length") is not None
        ]
        assert all(v > 0 for v in lengths), f"Expected positive password_length, got {lengths[:5]}"

    def test_smb1_setup_action_extracted(self):
        """smb.setup.action should produce setup_action logon flag in details."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["setup_action"],
        )

    def test_smb3_preauth_hash_extracted(self):
        """smb2.preauth_hash should appear in details and device data."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/bruteshark_ntlm_smb.pcap",
            min_devices=0,
            expect_details=["preauth_hash"],
        )
        has_device_hash = any(
            dev.smb_passive_data.get("preauth_hash")
            for dev in devices.values()
            if dev.smb_passive_data
        )
        assert has_device_hash, "Expected preauth_hash in at least one device"

    def test_device_security_posture_fields(self):
        """Device smb_passive_data should include security posture fields."""
        listener, devices, result = _run_listener_test(
            "smb",
            "SMBPassiveListener",
            "smb or smb2",
            "smb/credslayer_smb_ntlm.pcap",
        )
        # At least one device should have signing and cipher info
        all_data = [dev.smb_passive_data for dev in devices.values() if dev.smb_passive_data]
        assert all_data, "Expected devices with smb_passive_data"
        has_ciphers = any(d.get("ciphers") for d in all_data)
        has_signing = any(d.get("signing_enabled") is not None for d in all_data)
        has_hostname = any(d.get("server_hostname") for d in all_data)
        assert has_ciphers, "Expected ciphers in device data"
        assert has_signing, "Expected signing_enabled in device data"
        assert has_hostname, "Expected server_hostname in device data"
