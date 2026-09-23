"""Integration tests for FINS passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestFINSPassiveEK:
    """FINS-specific tests beyond the parametrized quality suite."""

    def test_fins_cisagov(self):
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/cisagov_omron_fins_tcp.pcap",
            expect_details=["command_code"],
        )

        # A1: passive_data on at least one device
        has_data = any(
            hasattr(d, "fins_passive_data") and d.fins_passive_data for d in devices.values()
        )
        assert has_data, "No device has fins_passive_data"

        # A2: harvest returns a dict (tables are now built centrally by scanner)
        assert isinstance(result, dict)

    def test_fins_generated(self):
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/generated_fins.pcap",
            expect_details=["command_code"],
        )

        # At least one device with passive_data
        has_data = any(
            hasattr(d, "fins_passive_data") and d.fins_passive_data for d in devices.values()
        )
        assert has_data, "No device has fins_passive_data"


class TestFINSFieldCoverage:
    """Tests for T1 field coverage gap fixes."""

    def test_sid_extracted(self):
        """Service ID (omron.sid) should be extracted on every FINS frame."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/cisagov_omron.pcap",
            expect_details=["command_code", "sid"],
        )
        # Verify at least one interaction carries the sid
        sids = [ix.details["sid"] for ix in listener.interactions if "sid" in ix.details]
        assert len(sids) > 0, "No interaction has sid field"

    def test_unit_address_extracted(self):
        """Unit address (omron.unit_address) should appear in interactions."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/emreekin_omron3.pcap",
            expect_details=["command_code"],
        )
        found = any("unit_address" in ix.details for ix in listener.interactions)
        assert found, "No interaction has unit_address field"

    def test_network_address_extracted(self):
        """Network address (omron.network_address) should appear in interactions."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/emreekin_omron3.pcap",
            expect_details=["command_code"],
        )
        found = any("network_address" in ix.details for ix in listener.interactions)
        assert found, "No interaction has network_address field"

    def test_memory_address_bits_extracted(self):
        """Bit offset (omron.memory.address.bits) should appear on memory ops."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/cisagov_omron.pcap",
            expect_details=["command_code"],
        )
        # Memory area read/write interactions should have address_bits
        mem_ops = [
            ix
            for ix in listener.interactions
            if ix.details.get("command_code") in (0x0101, 0x0102, 0x0103, 0x0104)
        ]
        assert len(mem_ops) > 0, "No memory operations found"
        found = any("address_bits" in ix.details for ix in mem_ops)
        assert found, "No memory operation has address_bits field"

    def test_cpu_status_fields_emreekin3(self):
        """CPU Unit Status Read response should extract status/error fields."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/emreekin_omron3.pcap",
            expect_details=["command_code"],
        )
        # Look for CPU Unit Status Read (0x0601) or CPU Unit Data Read (0x0501)
        cpu_ops = [
            ix for ix in listener.interactions if ix.details.get("command_code") in (0x0501, 0x0601)
        ]
        assert len(cpu_ops) > 0, "No CPU status/data read interactions found"

        # At least one should have status-related fields
        all_details_keys = set()
        for ix in cpu_ops:
            all_details_keys.update(ix.details.keys())

        # Check for the core status fields we extract
        status_fields = {"model_number", "cpu_status", "pc_status", "fatal_error_data"}
        found_fields = status_fields & all_details_keys
        assert len(found_fields) >= 1, (
            f"Expected at least one of {status_fields} in CPU status interactions; "
            f"got keys: {sorted(all_details_keys)}"
        )

    def test_error_diagnostics_emreekin3(self):
        """Error/diagnostic fields should be extracted from CPU status responses."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/emreekin_omron3.pcap",
            expect_details=["command_code"],
        )
        all_keys = set()
        for ix in listener.interactions:
            all_keys.update(ix.details.keys())

        # Should find at least some error/cyclic fields
        error_fields = {
            "cyclic_operation",
            "cyclic_trans_status",
            "cyclic_error_status",
            "node_error_count",
            "error_message",
            "error_reset_fals_no",
        }
        found = error_fields & all_keys
        assert len(found) >= 1, (
            f"Expected at least one of {error_fields}; got keys: {sorted(all_keys)}"
        )

    def test_model_number_extracted(self):
        """PLC model_number (omron.model_number) should be extracted."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/emreekin_omron3.pcap",
            expect_details=["command_code"],
        )
        found = any("model_number" in ix.details for ix in listener.interactions)
        assert found, "No interaction has model_number field"

    def test_program_number_extracted(self):
        """Program number (omron.program_number) should be extracted."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/emreekin_omron3.pcap",
            expect_details=["command_code"],
        )
        found = any("program_number" in ix.details for ix in listener.interactions)
        assert found, "No interaction has program_number field"

    def test_program_area_size_extracted(self):
        """Program area size (omron.area_data.program_area_size) should be extracted."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/emreekin_omron3.pcap",
            expect_details=["command_code"],
        )
        found = any("program_area_size" in ix.details for ix in listener.interactions)
        assert found, "No interaction has program_area_size field"

    def test_file_data_filename_extracted(self):
        """Filename (omron.file_data.filename) should be extracted on file ops."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/emreekin_omron3.pcap",
            expect_details=["command_code"],
        )
        found = any("filename" in ix.details for ix in listener.interactions)
        assert found, "No interaction has filename field"

    def test_tcp_command_extracted(self):
        """FINS/TCP command (omron.tcp.command) should be extracted."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/cisagov_omron_fins_tcp.pcap",
            expect_details=["command_code"],
        )
        # tcp_command can appear on FINS command frames or TCP-only frames
        found = any("tcp_command" in ix.details for ix in listener.interactions)
        assert found, "No interaction has tcp_command field"

    def test_tcp_error_code_extracted(self):
        """FINS/TCP error code (omron.tcp.error_code) should be extracted."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/cisagov_omron_fins_tcp.pcap",
            expect_details=["command_code"],
        )
        found = any("tcp_error_code" in ix.details for ix in listener.interactions)
        assert found, "No interaction has tcp_error_code field"

    def test_tcp_node_addresses_ndpi(self):
        """FINS/TCP node addresses should be extracted from ndpi pcap."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/ndpi_fins.pcap",
            expect_details=["command_code"],
            min_interactions=0,
        )
        all_keys = set()
        for ix in listener.interactions:
            all_keys.update(ix.details.keys())
        # ndpi pcap has tcp_client_node_address and tcp_server_node_address
        node_fields = {"tcp_client_node", "tcp_server_node"}
        found = node_fields & all_keys
        assert len(found) >= 1, (
            f"Expected at least one of {node_fields}; got keys: {sorted(all_keys)}"
        )

    def test_device_model_fingerprinting(self):
        """Model info should be stored on device protocol_data."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/emreekin_omron3.pcap",
            expect_details=["command_code"],
        )
        # Check if any PLC device has model info in fins_passive_data
        plc_devices = [
            d
            for d in devices.values()
            if hasattr(d, "fins_passive_data")
            and d.fins_passive_data
            and d.fins_passive_data.get("role") == "plc"
        ]
        if plc_devices:
            pdata_keys = set()
            for d in plc_devices:
                pdata_keys.update(d.fins_passive_data.keys())
            model_keys = {"controller_model", "model_number", "controller_version"}
            found = model_keys & pdata_keys
            # Only assert if CPU data read responses were present
            cpu_ops = [
                ix
                for ix in listener.interactions
                if ix.details.get("command_code") in (0x0501, 0x0601) and ix.direction == "response"
            ]
            if cpu_ops:
                assert len(found) >= 1, (
                    f"PLC device should have model info in fins_passive_data; "
                    f"got keys: {sorted(pdata_keys)}"
                )

    # ------------------------------------------------------------------
    # T1 gap fixes: pc_status sub-bits, rack_num, fatal/non_fatal errors
    # ------------------------------------------------------------------

    def test_pc_status_subfields_extracted(self):
        """pc_status hi/r1/r2 sub-bits and rack_num should be extracted."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/cisagov_omron.pcap",
            expect_details=["command_code"],
        )
        all_keys = set()
        for ix in listener.interactions:
            all_keys.update(ix.details.keys())
        subfields = {"pc_status_hi", "pc_status_r1", "pc_status_r2", "rack_num"}
        found = subfields & all_keys
        assert len(found) >= 1, (
            f"Expected at least one of {subfields}; got keys: {sorted(all_keys)}"
        )

    def test_fatal_errors_extracted(self):
        """Active fatal error conditions should be collected from status read."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/cisagov_omron.pcap",
            expect_details=["command_code"],
        )
        fatal_lists = [
            ix.details.get("fatal_errors")
            for ix in listener.interactions
            if ix.details.get("fatal_errors")
        ]
        assert fatal_lists, (
            "Expected at least one interaction with active fatal_errors list "
            "from CPU Unit Status Read response"
        )
        # Each entry should be a list of named conditions
        assert all(isinstance(fl, list) and fl for fl in fatal_lists)

    def test_non_fatal_errors_extracted(self):
        """Active non-fatal error conditions should be collected."""
        listener, devices, result = _run_listener_test(
            "fins",
            "FINSPassiveListener",
            "omron",
            "fins/cisagov_omron.pcap",
            expect_details=["command_code"],
        )
        non_fatal_lists = [
            ix.details.get("non_fatal_errors")
            for ix in listener.interactions
            if ix.details.get("non_fatal_errors")
        ]
        assert non_fatal_lists, (
            "Expected at least one interaction with active non_fatal_errors list"
        )
        assert all(isinstance(nfl, list) and nfl for nfl in non_fatal_lists)
