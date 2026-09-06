"""Integration tests for HART-IP passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestHARTIPPassiveEK:
    """HART-IP-specific tests beyond the parametrized quality suite."""

    def test_hartip_sessions_and_commands(self):
        listener, devices, result = _run_listener_test(
            "hartip",
            "HARTIPPassiveListener",
            "hart_ip",
            "hart/iti_hart_ip.pcap",
            expect_details=["command"],
        )
        # HART-IP should track sessions between hosts and field devices
        assert len(listener.sessions) >= 1, (
            f"Expected >= 1 HART-IP session, got {len(listener.sessions)}"
        )

        # Check that hartip_passive_data is populated on at least one device
        has_passive_data = any(
            hasattr(d, "hartip_passive_data") and d.hartip_passive_data for d in devices.values()
        )
        assert has_passive_data, "No device has hartip_passive_data"

        # HART-IP has no custom harvest tables (interaction/credential tables
        # are now built centrally by the scanner)

    def test_hartip_version_and_transaction_id(self):
        """Verify HART-IP version and transaction_id are extracted."""
        listener, devices, result = _run_listener_test(
            "hartip",
            "HARTIPPassiveListener",
            "hart_ip",
            "hart/iti_hart_ip.pcap",
            expect_details=["command"],
        )

        # iti_hart_ip.pcap has version=1 and transaction_id on all packets
        has_version = any(ix.details.get("version") is not None for ix in listener.interactions)
        assert has_version, (
            f"No interaction has version field; sample details: {listener.interactions[0].details}"
        )

        has_tid = any(ix.details.get("transaction_id") is not None for ix in listener.interactions)
        assert has_tid, (
            "No interaction has transaction_id field; "
            f"sample details: {listener.interactions[0].details}"
        )

        # Version should be 1 for all HART-IP v1 traffic
        for ix in listener.interactions:
            v = ix.details.get("version")
            if v is not None:
                assert v == 1, f"Expected HART-IP version 1, got {v}"

    def test_hartip_device_variables_count(self):
        """Verify device_variables count is extracted from cmd 0 responses."""
        listener, devices, result = _run_listener_test(
            "hartip",
            "HARTIPPassiveListener",
            "hart_ip",
            "hart/iti_hart_ip.pcap",
            expect_details=["command"],
        )

        # Cmd 0 (Read Unique Identifier) response includes device_variables count
        cmd0_responses = [
            ix
            for ix in listener.interactions
            if ix.details.get("command") == 0 and ix.direction == "response"
        ]
        assert len(cmd0_responses) >= 1, "Expected at least 1 cmd 0 response"

        has_vars = any("vars=" in (ix.details.get("data_str") or "") for ix in cmd0_responses)
        assert has_vars, (
            "No cmd 0 response has vars= in data_str; "
            f"data_strs: {[ix.details.get('data_str') for ix in cmd0_responses]}"
        )

    def test_hartip_slot_device_var_status(self):
        """Verify slot device variable status is extracted from cmd 9 responses."""
        listener, devices, result = _run_listener_test(
            "hartip",
            "HARTIPPassiveListener",
            "hart_ip",
            "hart/iti_hart_ip.pcap",
            expect_details=["command"],
        )

        # Cmd 9 responses in iti_hart_ip.pcap have slot0_device_var_status=16
        cmd9_responses = [
            ix
            for ix in listener.interactions
            if ix.details.get("command") == 9 and ix.direction == "response"
        ]
        assert len(cmd9_responses) >= 1, "Expected at least 1 cmd 9 response"

        # At least one cmd 9 response should include slot status "(st=...)"
        has_slot_status = any("(st=" in (ix.details.get("data_str") or "") for ix in cmd9_responses)
        assert has_slot_status, (
            "No cmd 9 response has slot status in data_str; "
            f"data_strs: {[ix.details.get('data_str') for ix in cmd9_responses]}"
        )

    def test_hartip_standardized_status(self):
        """Verify standardized status bytes are extracted from cmd 48 responses."""
        listener, devices, result = _run_listener_test(
            "hartip",
            "HARTIPPassiveListener",
            "hart_ip",
            "hart/iti_hart_ip.pcap",
            expect_details=["command"],
        )

        # Cmd 48 responses in iti_hart_ip.pcap have standardized_status_0
        cmd48_responses = [
            ix
            for ix in listener.interactions
            if ix.details.get("command") == 48 and ix.direction == "response"
        ]
        assert len(cmd48_responses) >= 1, "Expected at least 1 cmd 48 response"

        has_std_status = any(
            "std_status_" in (ix.details.get("data_str") or "") for ix in cmd48_responses
        )
        assert has_std_status, (
            "No cmd 48 response has standardized status in data_str; "
            f"data_strs: {[ix.details.get('data_str') for ix in cmd48_responses]}"
        )

    def test_hartip_device_sp_status(self):
        """Verify device-specific status is extracted from cmd 48 responses."""
        listener, devices, result = _run_listener_test(
            "hartip",
            "HARTIPPassiveListener",
            "hart_ip",
            "hart/iti_hart_ip.pcap",
            expect_details=["command"],
        )

        cmd48_responses = [
            ix
            for ix in listener.interactions
            if ix.details.get("command") == 48 and ix.direction == "response"
        ]
        assert len(cmd48_responses) >= 1, "Expected at least 1 cmd 48 response"

        has_sp_status = any(
            "sp_status=" in (ix.details.get("data_str") or "") for ix in cmd48_responses
        )
        assert has_sp_status, (
            "No cmd 48 response has sp_status in data_str; "
            f"data_strs: {[ix.details.get('data_str') for ix in cmd48_responses]}"
        )

    def test_hartip_command_number_embedded(self):
        """Verify embedded command_number is extracted (aggregated commands)."""
        listener, devices, result = _run_listener_test(
            "hartip",
            "HARTIPPassiveListener",
            "hart_ip",
            "hart/cisagov_hart_ip_publish_keepalive.pcapng",
            expect_details=["command"],
        )

        # cisagov publish/keepalive pcap has cmd 31 with command_number=533
        has_cmd_num = any(
            "cmd_num=" in (ix.details.get("data_str") or "") for ix in listener.interactions
        )
        assert has_cmd_num, (
            "No interaction has cmd_num= in data_str; "
            "expected embedded command_number extraction from cmd 31"
        )

    def test_hartip_publish_slot_status(self):
        """Verify slot status is extracted from publish (msg_type=2) packets."""
        listener, devices, result = _run_listener_test(
            "hartip",
            "HARTIPPassiveListener",
            "hart_ip",
            "hart/cisagov_hart_ip_publish_keepalive.pcapng",
            expect_details=["command"],
        )

        # Publish packets with cmd 9 should have slot status
        publish_cmd9 = [
            ix
            for ix in listener.interactions
            if ix.details.get("command") == 9 and ix.details.get("publish")
        ]
        assert len(publish_cmd9) >= 1, "Expected at least 1 publish cmd 9 interaction"

        has_slot_status = any("(st=" in (ix.details.get("data_str") or "") for ix in publish_cmd9)
        assert has_slot_status, (
            "No publish cmd 9 has slot status in data_str; "
            f"data_strs: {[ix.details.get('data_str') for ix in publish_cmd9]}"
        )

    def test_hartip_extracts_pt_checksum(self):
        """Verify pass-through frame checksum (hart_ip.pt.checksum) is extracted."""
        listener, devices, result = _run_listener_test(
            "hartip",
            "HARTIPPassiveListener",
            "hart_ip",
            "hart/iti_hart_ip.pcap",
            expect_details=["command"],
        )

        # Every pass-through HART frame carries a checksum byte
        found = any(ix.details.get("pt_checksum") is not None for ix in listener.interactions)
        assert found, (
            "No interaction has pt_checksum in details; "
            f"sample details: {listener.interactions[0].details if listener.interactions else 'no interactions'}"
        )

    def test_hartip_poll_address(self):
        """Verify poll_address is extracted from embedded command messages."""
        listener, devices, result = _run_listener_test(
            "hartip",
            "HARTIPPassiveListener",
            "hart_ip",
            "hart/cisagov_hart_ip_all_types_commands.pcapng",
            expect_details=["command"],
        )

        # This pcap has cmd 6 (Write Polling Address) with poll_address=0
        # poll_address is extracted into details dict (appears in both req/rsp)
        has_poll_addr = any(
            ix.details.get("poll_address") is not None for ix in listener.interactions
        )
        assert has_poll_addr, (
            "No interaction has poll_address in details; "
            "expected poll_address extraction from cmd 6"
        )

    def test_hartip_all_types_standardized_status(self):
        """Verify standardized status bytes from iti_hart_ip.pcap cmd 48 responses."""
        listener, devices, result = _run_listener_test(
            "hartip",
            "HARTIPPassiveListener",
            "hart_ip",
            "hart/iti_hart_ip.pcap",
            expect_details=["command"],
        )

        # iti_hart_ip.pcap has cmd 48 responses with standardized_status_0
        cmd48_responses = [
            ix
            for ix in listener.interactions
            if ix.details.get("command") == 48 and ix.direction == "response"
        ]
        assert len(cmd48_responses) >= 1, "Expected at least 1 cmd 48 response"

        # Check that standardized status fields appear in data_str
        has_std = any(
            "std_status_0=" in (ix.details.get("data_str") or "") for ix in cmd48_responses
        )
        assert has_std, (
            "No cmd 48 response has std_status_0= in data_str; "
            f"data_strs: {[ix.details.get('data_str') for ix in cmd48_responses]}"
        )
