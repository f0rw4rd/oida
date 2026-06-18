"""Integration tests for VNC passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestVNCPassiveEK:
    """VNC-specific tests beyond the parametrised quality suite."""

    def test_vnc_basic(self):
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/generated_vnc.pcap",
        )
        # VNC listener should extract credentials and hashes
        creds = listener.get_credentials_summary()
        if listener.credentials:
            assert len(creds) >= 1, "Expected at least one credential summary entry"
            for c in creds:
                assert c.get("protocol") == "VNC"
                assert c.get("credential_type") == "hash"

            # get_hashes_summary should return data
            hashes = listener.get_hashes_summary()
            assert len(hashes) >= 1, "Expected at least one hash summary entry"
            for h in hashes:
                assert h.get("hash_type") == "VNC-DES"

            # get_hashcat_hashes should return formatted hashes
            hashcat = listener.get_hashcat_hashes()
            assert len(hashcat) >= 1
            for line in hashcat:
                assert line.startswith("$vnc$*"), f"Bad hashcat format: {line}"

        # VNC tracks sessions
        if listener._sessions:
            assert len(listener._sessions) >= 1

    # ------------------------------------------------------------------
    # T1 field: vnc.client_proto_ver
    # ------------------------------------------------------------------

    def test_client_proto_ver_extracted(self):
        """client_proto_ver should be extracted and stored in session."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/generated_vnc.pcap",
        )
        # Session must record the client RFB version
        assert listener._sessions, "Expected at least one VNC session"
        for session in listener._sessions.values():
            assert session.client_rfb_version, (
                f"client_rfb_version not populated; got {session.client_rfb_version!r}"
            )
            # RFB versions are like "003.008", "003.007", etc.
            assert "." in session.client_rfb_version, (
                f"client_rfb_version does not look like an RFB version: "
                f"{session.client_rfb_version!r}"
            )

    def test_client_proto_ver_in_interaction_details(self):
        """client_proto_ver should appear in a 'Client Version' interaction."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/generated_vnc.pcap",
        )
        client_ver_interactions = [
            ix for ix in listener.interactions if ix.operation == "Client Version"
        ]
        assert len(client_ver_interactions) >= 1, (
            "Expected at least one 'Client Version' interaction; "
            f"operations seen: {[ix.operation for ix in listener.interactions]}"
        )
        for ix in client_ver_interactions:
            assert "client_proto_ver" in ix.details, (
                f"Missing 'client_proto_ver' in details: {ix.details}"
            )
            assert ix.details["client_proto_ver"], (
                f"client_proto_ver is empty in details: {ix.details}"
            )

    # ------------------------------------------------------------------
    # T1 field: vnc.num_security_types
    # ------------------------------------------------------------------

    def test_num_security_types_extracted(self):
        """num_security_types should be extracted and stored in session."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/generated_vnc.pcap",
        )
        assert listener._sessions, "Expected at least one VNC session"
        for session in listener._sessions.values():
            assert session.num_security_types >= 1, (
                f"num_security_types not populated or zero; got {session.num_security_types}"
            )

    def test_num_security_types_in_interaction_details(self):
        """num_security_types should appear in 'Security Type Offered' interactions."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/generated_vnc.pcap",
        )
        sec_type_interactions = [
            ix for ix in listener.interactions if ix.operation == "Security Type Offered"
        ]
        assert len(sec_type_interactions) >= 1, (
            "Expected at least one 'Security Type Offered' interaction; "
            f"operations seen: {[ix.operation for ix in listener.interactions]}"
        )
        for ix in sec_type_interactions:
            assert "num_security_types" in ix.details, (
                f"Missing 'num_security_types' in details: {ix.details}"
            )

    # ------------------------------------------------------------------
    # T1 field: vnc.desktop_name
    # ------------------------------------------------------------------

    def test_desktop_name_extracted(self):
        """desktop_name should be extracted from wireshark pcap (has ServerInit)."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/wireshark_vnc.pcap",
            # wireshark pcap uses 127.0.0.1 -> 0 devices but don't crash
            min_devices=0,
        )
        assert listener._sessions, "Expected at least one VNC session"
        desktop_found = any(s.desktop_name for s in listener._sessions.values())
        assert desktop_found, (
            "desktop_name not populated in any session; "
            f"sessions: {[(s.server_ip, s.desktop_name) for s in listener._sessions.values()]}"
        )

    def test_desktop_name_in_interaction_details(self):
        """desktop_name should appear in a 'Desktop Name' interaction."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/wireshark_vnc.pcap",
            min_devices=0,
        )
        dn_interactions = [ix for ix in listener.interactions if ix.operation == "Desktop Name"]
        assert len(dn_interactions) >= 1, (
            "Expected at least one 'Desktop Name' interaction; "
            f"operations seen: {sorted({ix.operation for ix in listener.interactions})}"
        )
        for ix in dn_interactions:
            assert "desktop_name" in ix.details, f"Missing 'desktop_name' in details: {ix.details}"
            assert ix.details["desktop_name"], f"desktop_name is empty in details: {ix.details}"

    # ------------------------------------------------------------------
    # Sessions summary includes new fields
    # ------------------------------------------------------------------

    def test_sessions_summary_contains_new_fields(self):
        """get_sessions_summary should expose all T1 fields."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/generated_vnc.pcap",
        )
        sessions = listener.get_sessions_summary()
        assert len(sessions) >= 1, "Expected at least one session summary"
        for s in sessions:
            # Verify all expected keys are present
            for key in (
                "client_ip",
                "server_ip",
                "server_port",
                "server_rfb_version",
                "client_rfb_version",
                "security_type",
                "num_security_types",
                "desktop_name",
                "state",
            ):
                assert key in s, f"Missing key {key!r} in session summary: {s}"
            # client_rfb_version should be populated
            assert s["client_rfb_version"] != "?", (
                f"client_rfb_version should be populated from generated_vnc.pcap: {s}"
            )
            # num_security_types should be > 0
            assert s["num_security_types"] >= 1, f"num_security_types should be >= 1: {s}"

    def test_sessions_summary_desktop_name(self):
        """get_sessions_summary should include desktop_name from wireshark pcap."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/wireshark_vnc.pcap",
            min_devices=0,
        )
        sessions = listener.get_sessions_summary()
        assert len(sessions) >= 1, "Expected at least one session summary"
        desktop_found = any(s.get("desktop_name") for s in sessions)
        assert desktop_found, f"desktop_name not found in any session summary; sessions: {sessions}"

    # ------------------------------------------------------------------
    # Device protocol_data includes new fields
    # ------------------------------------------------------------------

    def test_device_protocol_data_new_fields(self):
        """Server device vnc_passive_data should include new T1 fields."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/generated_vnc.pcap",
        )
        # generated pcap uses non-loopback IPs, so devices should be created
        assert devices, "Expected at least one device from generated_vnc.pcap"
        server_devices = [
            d
            for d in devices.values()
            if hasattr(d, "vnc_passive_data")
            and d.vnc_passive_data
            and d.vnc_passive_data.get("role") == "server"
        ]
        assert server_devices, (
            f"Expected a VNC Server device; got device types: "
            f"{[getattr(d, 'device_type', '?') for d in devices.values()]}"
        )
        for dev in server_devices:
            data = dev.vnc_passive_data
            assert "num_security_types" in data, (
                f"Missing 'num_security_types' in vnc_passive_data: {data}"
            )
            assert "desktop_name" in data, f"Missing 'desktop_name' in vnc_passive_data: {data}"

    def test_client_device_protocol_data(self):
        """Client device vnc_passive_data should include client_rfb_version."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/generated_vnc.pcap",
        )
        assert devices, "Expected at least one device from generated_vnc.pcap"
        client_devices = [
            d
            for d in devices.values()
            if hasattr(d, "vnc_passive_data")
            and d.vnc_passive_data
            and d.vnc_passive_data.get("role") == "client"
        ]
        assert client_devices, (
            f"Expected a VNC Client device; got roles: "
            f"{[getattr(d, 'vnc_passive_data', {}).get('role', '?') for d in devices.values()]}"
        )
        for dev in client_devices:
            data = dev.vnc_passive_data
            assert "client_rfb_version" in data, (
                f"Missing 'client_rfb_version' in client vnc_passive_data: {data}"
            )

    # ------------------------------------------------------------------
    # Interaction recording quality
    # ------------------------------------------------------------------

    def test_interactions_are_specific_not_generic(self):
        """Interactions should have specific operation names, not just 'VNC/RFB'."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/generated_vnc.pcap",
        )
        operations = {ix.operation for ix in listener.interactions}
        # Should have specific operations, not just generic "VNC/RFB"
        expected_ops = {"Server Version", "Client Version", "Security Type Offered"}
        found = operations & expected_ops
        assert found, f"Expected specific operations like {expected_ops}; got only: {operations}"
        # The old generic "VNC/RFB" should NOT appear
        assert "VNC/RFB" not in operations, (
            f"Generic 'VNC/RFB' operation should be replaced with specific names; "
            f"operations: {operations}"
        )

    def test_interactions_have_flow_id(self):
        """All interactions should have a non-empty flow_id."""
        listener, devices, result = _run_listener_test(
            "vnc",
            "VNCPassiveListener",
            "vnc",
            "vnc/generated_vnc.pcap",
        )
        for ix in listener.interactions:
            assert ix.flow_id, f"Interaction {ix.operation} has empty flow_id"
