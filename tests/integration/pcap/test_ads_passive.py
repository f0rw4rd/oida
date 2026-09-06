"""Integration tests for ADS passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestADSPassiveEK:
    """ADS-specific tests beyond the parametrized quality suite."""

    def test_ads_sessions_and_commands(self):
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_addroute1.pcapng",
            expect_details=["command_name"],
        )

        # A1: sessions populated
        assert len(listener.sessions) >= 1, (
            f"Expected >= 1 ADS session, got {len(listener.sessions)}"
        )

        # A2: session has commands seen
        for session in listener.sessions.values():
            assert session.commands_seen, "Session has no commands_seen"

        # A3: passive_data on at least one device
        has_data = any(
            hasattr(d, "ads_passive_data") and d.ads_passive_data for d in devices.values()
        )
        assert has_data, "No device has ads_passive_data"

        # A4: harvest returns a dict (tables are now built centrally by scanner)
        assert isinstance(result, dict)


class TestADSInvokeID:
    """Tests for ams.invokeid field extraction (T1 gap fix)."""

    def test_invoke_id_extracted_in_interactions(self):
        """invoke_id must appear in interaction details for every packet."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["command_name", "invoke_id"],
        )

        # Every interaction should have an invoke_id in its details
        interactions_with_invoke = [
            ix for ix in listener.interactions if ix.details.get("invoke_id") is not None
        ]
        assert len(interactions_with_invoke) > 0, "No interactions have invoke_id in details"

        # Most interactions should have invoke_id (some may lack it if
        # tshark doesn't dissect it for certain packet types)
        ratio = len(interactions_with_invoke) / len(listener.interactions)
        assert ratio >= 0.8, f"Only {ratio:.0%} of interactions have invoke_id; expected >= 80%"

    def test_invoke_id_in_interaction_details(self):
        """Invoke ID must appear in interaction details dict."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["command_name"],
        )

        # Verify PROTOCOL_COLUMNS includes "Invoke ID"
        from oida.pcap.ads import ADSPassiveListener

        assert "invoke_id" in ADSPassiveListener.PROTOCOL_COLUMNS

        # Check that at least one interaction has a non-None invoke_id in details
        found_invoke_id = any(
            ix.details.get("invoke_id") is not None for ix in listener.interactions
        )
        assert found_invoke_id, "No interaction has a non-None invoke_id in details"

    def test_invoke_id_correlation(self):
        """Requests and responses with matching invoke IDs should exist."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["invoke_id"],
        )

        # Collect invoke IDs by direction
        request_ids = set()
        response_ids = set()
        for ix in listener.interactions:
            inv_id = ix.details.get("invoke_id")
            if inv_id is None:
                continue
            if ix.direction == "request":
                request_ids.add(inv_id)
            else:
                response_ids.add(inv_id)

        # There should be matching invoke IDs between requests and responses
        matched = request_ids & response_ids
        assert len(matched) > 0, (
            f"No invoke IDs match between requests and responses; "
            f"request IDs sample: {sorted(request_ids)[:5]}, "
            f"response IDs sample: {sorted(response_ids)[:5]}"
        )

    def test_invoke_id_on_simple_pcap(self):
        """invoke_id should be extracted even from simple ReadState pcaps."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_invokeid12.pcapng",
            expect_details=["command_name"],
        )

        # Even in a simple pcap with just ReadState, invoke_id should be present
        has_invoke = any(ix.details.get("invoke_id") is not None for ix in listener.interactions)
        assert has_invoke, (
            "No interactions have invoke_id in the invokeid12 pcap; "
            f"sample details: {listener.interactions[0].details if listener.interactions else 'none'}"
        )


class TestADSStateFlags:
    """Tests for ams.state_* boolean flag extraction (T2 fields)."""

    def test_state_flags_extracted(self):
        """At least some interactions should have state_flags in details."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["command_name"],
        )

        # state_flags should be present on interactions where flags are active
        has_flags = any(ix.details.get("state_flags") for ix in listener.interactions)
        # state_adscmd is True for ADS commands (not system commands), so
        # it should appear on many packets
        assert has_flags, (
            "No interactions have state_flags in details; "
            "expected at least state_adscmd=True on ADS command packets"
        )

    def test_state_flags_contain_known_values(self):
        """State flags should contain recognizable flag names."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["command_name"],
        )

        known_flags = {
            "state_noreturn",
            "state_adscmd",
            "state_syscmd",
            "state_highprio",
            "state_timestampadded",
            "state_udp",
            "state_initcmd",
            "state_broadcast",
        }

        all_flags = set()
        for ix in listener.interactions:
            flags = ix.details.get("state_flags", [])
            all_flags.update(flags)

        # At least one known flag should appear
        valid = all_flags & known_flags
        assert valid, (
            f"No known state flags found; got: {all_flags}; expected subset of: {known_flags}"
        )


class TestADSCbdata:
    """Tests for ams.cbdata (AMS data length) extraction (T2 field)."""

    def test_cbdata_in_details(self):
        """cbdata should appear in interaction details."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["command_name"],
        )

        has_cbdata = any(ix.details.get("cbdata") is not None for ix in listener.interactions)
        assert has_cbdata, (
            "No interactions have cbdata in details; "
            "expected AMS-level data length field on at least some packets"
        )

    def test_cbdata_values_are_integers(self):
        """cbdata values should be non-negative integers."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["command_name"],
        )

        for ix in listener.interactions:
            cbdata = ix.details.get("cbdata")
            if cbdata is not None:
                assert isinstance(cbdata, int), f"cbdata should be int, got {type(cbdata)}"
                assert cbdata >= 0, f"cbdata should be non-negative, got {cbdata}"


class TestADSRichPcap:
    """Tests using the feature-rich iti_beckoffiplinktc3.pcapng."""

    def test_multiple_command_types(self):
        """Rich pcap should produce multiple ADS command types."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["command_name"],
        )

        operations = {ix.details.get("command_name") for ix in listener.interactions}
        # iti_beckoffiplinktc3 has Read, ReadState, ReadWrite,
        # AddDeviceNotification, DeleteDeviceNotification, ReadDeviceInfo
        assert len(operations) >= 3, (
            f"Expected >= 3 distinct command types, got {len(operations)}: {operations}"
        )

    def test_request_response_pairs(self):
        """Interactions should include both requests and responses."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["command_name"],
        )

        directions = {ix.direction for ix in listener.interactions}
        assert "request" in directions, "No request interactions found"
        assert "response" in directions, "No response interactions found"

    def test_format_protocol_columns_count(self):
        """_format_protocol_columns output must match PROTOCOL_COLUMNS length."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["command_name"],
        )

        from oida.pcap.ads import ADSPassiveListener

        expected_cols = len(ADSPassiveListener.PROTOCOL_COLUMNS)

        for ix in listener.interactions:
            row = listener._format_protocol_columns(ix)
            assert len(row) == expected_cols, (
                f"Row has {len(row)} columns but PROTOCOL_COLUMNS has {expected_cols}: {row}"
            )

    def test_device_info_extracted(self):
        """ReadDeviceInfo response should populate device_name and version."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["command_name"],
        )

        # Check if any interaction captured device info
        has_device_info = any(
            ix.details.get("device_name") or ix.details.get("device_version")
            for ix in listener.interactions
        )
        # Device info may or may not be present in this specific pcap,
        # but if ReadDeviceInfo responses exist, they should have it
        readdevinfo_responses = [
            ix
            for ix in listener.interactions
            if ix.details.get("command_name") == "ReadDeviceInfo" and ix.direction == "response"
        ]
        if readdevinfo_responses:
            assert has_device_info, (
                "ReadDeviceInfo responses found but no device_name/device_version extracted"
            )

    def test_index_group_extraction(self):
        """Read/Write/ReadWrite commands should have index_group in details."""
        listener, devices, result = _run_listener_test(
            "ads",
            "ADSPassiveListener",
            "ams",
            "ads/iti_beckoffiplinktc3.pcapng",
            expect_details=["command_name"],
        )

        # Commands with index group: Read (2), Write (3), ReadWrite (9),
        # AddDeviceNotification (6)
        rw_commands = {"Read", "Write", "ReadWrite", "AddDeviceNotification"}
        rw_interactions = [
            ix
            for ix in listener.interactions
            if ix.details.get("command_name") in rw_commands and ix.direction == "request"
        ]

        if rw_interactions:
            has_ig = any(ix.details.get("index_group") is not None for ix in rw_interactions)
            assert has_ig, (
                "Read/Write/ReadWrite request interactions found but none have index_group"
            )
