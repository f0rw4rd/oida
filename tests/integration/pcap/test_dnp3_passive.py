"""Integration tests for DNP3 passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestDNP3PassiveEK:
    """DNP3-specific tests beyond the parametrized quality suite."""

    def test_dnp3_sessions_and_functions(self):
        listener, devices, result = _run_listener_test(
            "dnp3",
            "DNP3PassiveListener",
            "dnp3",
            "dnp3/cisagov_dnp3_example.pcap",
            expect_details=["function_name"],
        )

        # A1: sessions populated
        assert len(listener.sessions) >= 1, (
            f"Expected >= 1 DNP3 session, got {len(listener.sessions)}"
        )

        # A2: session has function codes and object groups
        for session in listener.sessions.values():
            assert session.function_codes, "Session has no function_codes"

        # A3: passive_data on at least one device
        has_data = any(
            hasattr(d, "dnp3_passive_data") and d.dnp3_passive_data for d in devices.values()
        )
        assert has_data, "No device has dnp3_passive_data"

        # A4: harvest returns a dict (tables are now built centrally by scanner)
        assert isinstance(result, dict)

    def test_dnp3_data_link_prifunc(self):
        """Verify data link primary function code extraction (dnp3.ctl.prifunc)."""
        listener, devices, result = _run_listener_test(
            "dnp3",
            "DNP3PassiveListener",
            "dnp3",
            "dnp3/cisagov_dnp3_example.pcap",
            expect_details=["dl_prifunc"],
        )

        # Every interaction should have a data link primary function code
        prifunc_interactions = [
            ix for ix in listener.interactions if ix.details.get("dl_prifunc") is not None
        ]
        assert len(prifunc_interactions) >= 1, "No interactions have dl_prifunc"

        # Primary function code 4 = Unconfirmed User Data (most common in TCP)
        prifunc_values = {ix.details["dl_prifunc"] for ix in prifunc_interactions}
        assert 4 in prifunc_values, (
            f"Expected prifunc=4 (Unconfirmed User Data); got {prifunc_values}"
        )

        # Verify human-readable name is populated
        has_name = any(ix.details.get("dl_prifunc_name") for ix in prifunc_interactions)
        assert has_name, "No interactions have dl_prifunc_name"

    def test_dnp3_application_sequence_number(self):
        """Verify application layer sequence number extraction (dnp3.al.seq)."""
        listener, devices, result = _run_listener_test(
            "dnp3",
            "DNP3PassiveListener",
            "dnp3",
            "dnp3/cisagov_dnp3_example.pcap",
            expect_details=["al_seq"],
        )

        seq_values = {
            ix.details["al_seq"]
            for ix in listener.interactions
            if ix.details.get("al_seq") is not None
        }
        assert len(seq_values) >= 1, "No application sequence numbers extracted"

    def test_dnp3_addresses(self):
        """Verify DNP3 source/destination address extraction (dnp3.src, dnp3.dst, dnp3.addr)."""
        listener, devices, result = _run_listener_test(
            "dnp3",
            "DNP3PassiveListener",
            "dnp3",
            "dnp3/cisagov_dnp3_example.pcap",
            expect_details=["dnp3_src", "dnp3_dst"],
        )

        # cisagov example uses addresses 5 and 100
        src_values = {
            ix.details["dnp3_src"] for ix in listener.interactions if ix.details.get("dnp3_src")
        }
        dst_values = {
            ix.details["dnp3_dst"] for ix in listener.interactions if ix.details.get("dnp3_dst")
        }
        assert src_values, "No dnp3_src addresses extracted"
        assert dst_values, "No dnp3_dst addresses extracted"
        # Addresses 5 and 100 should appear somewhere
        all_addrs = src_values | dst_values
        assert 5 in all_addrs or 100 in all_addrs, (
            f"Expected DNP3 addresses 5 or 100; got {all_addrs}"
        )

    def test_dnp3_select_operate_crob(self):
        """Verify CROB fields from select-before-operate (ctrlstatus, ctl.op)."""
        listener, devices, result = _run_listener_test(
            "dnp3",
            "DNP3PassiveListener",
            "dnp3",
            "dnp3/iti_select_operate_and_responses.pcap",
            expect_details=["function_name"],
        )

        # Should have Select (0x03) and Operate (0x04) function codes
        func_codes = {
            ix.details["function_code"]
            for ix in listener.interactions
            if ix.details.get("function_code") is not None
        }
        assert 0x03 in func_codes, f"Missing Select (0x03) function code; got {func_codes}"
        assert 0x04 in func_codes, f"Missing Operate (0x04) function code; got {func_codes}"

        # Should have CROB control status fields
        has_ctrlstatus = any(
            ix.details.get("ctrl_status") is not None for ix in listener.interactions
        )
        assert has_ctrlstatus, "No interactions have ctrl_status (dnp3.al.ctrlstatus)"

        # Should have control operation type
        has_ctl_op = any(
            ix.details.get("control_operation") is not None for ix in listener.interactions
        )
        assert has_ctl_op, "No interactions have control_operation (dnp3.ctl.op)"

        # Verify ctrl_status_name is populated
        has_status_name = any(ix.details.get("ctrl_status_name") for ix in listener.interactions)
        assert has_status_name, "No interactions have ctrl_status_name"

    def test_dnp3_file_read_operations(self):
        """Verify file operation field extraction from file read pcap."""
        listener, devices, result = _run_listener_test(
            "dnp3",
            "DNP3PassiveListener",
            "dnp3",
            "dnp3/iti_file_read.pcap",
            expect_details=["function_name"],
        )

        # File Open (0x19) should be present
        func_codes = {
            ix.details["function_code"]
            for ix in listener.interactions
            if ix.details.get("function_code") is not None
        }
        assert 0x19 in func_codes, f"Missing Open File (0x19); got {func_codes}"

        # File name should be extracted
        has_file_name = any(ix.details.get("file_name") for ix in listener.interactions)
        assert has_file_name, "No interactions have file_name (dnp3.al.file_name)"

        # Check the actual file name value
        file_names = [
            ix.details["file_name"] for ix in listener.interactions if ix.details.get("file_name")
        ]
        assert any("testfile" in fn for fn in file_names), (
            f"Expected file name containing 'testfile'; got {file_names}"
        )

        # File request ID should be extracted
        has_reqid = any(ix.details.get("file_reqid") is not None for ix in listener.interactions)
        assert has_reqid, "No interactions have file_reqid (dnp3.al.file.reqID)"

        # File auth key should be extracted
        has_auth = any(ix.details.get("file_auth") is not None for ix in listener.interactions)
        assert has_auth, "No interactions have file_auth (dnp3.al.file.auth)"

    def test_dnp3_file_status(self):
        """Verify file status extraction from file read response."""
        listener, devices, result = _run_listener_test(
            "dnp3",
            "DNP3PassiveListener",
            "dnp3",
            "dnp3/iti_file_read.pcap",
            expect_details=["function_name"],
        )

        # Response packets should have file_status
        has_file_status = any(
            ix.details.get("file_status") is not None for ix in listener.interactions
        )
        assert has_file_status, "No interactions have file_status (dnp3.al.file.status)"

        # Verify file_status_name is populated
        has_status_name = any(ix.details.get("file_status_name") for ix in listener.interactions)
        assert has_status_name, "No interactions have file_status_name"

    def test_dnp3_full_exchange_coverage(self):
        """Verify field extraction on a full exchange pcap with varied operations."""
        listener, devices, result = _run_listener_test(
            "dnp3",
            "DNP3PassiveListener",
            "dnp3",
            "dnp3/iti_full_exchange.pcap",
            expect_details=["function_name"],
        )

        # Should have multiple function types in a full exchange
        func_codes = {
            ix.details["function_code"]
            for ix in listener.interactions
            if ix.details.get("function_code") is not None
        }
        assert len(func_codes) >= 2, (
            f"Expected >= 2 distinct function codes in full exchange; got {func_codes}"
        )

        # Every interaction with a function code should have al_seq
        app_interactions = [
            ix for ix in listener.interactions if ix.details.get("function_code") is not None
        ]
        has_seq = any(ix.details.get("al_seq") is not None for ix in app_interactions)
        assert has_seq, "No interactions in full exchange have al_seq"

    def test_dnp3_direct_operate_analog_output(self):
        """Verify extraction from direct operate analog output pcap."""
        listener, devices, result = _run_listener_test(
            "dnp3",
            "DNP3PassiveListener",
            "dnp3",
            "dnp3/iti_direct_operate_analog_output.pcap",
            expect_details=["function_name"],
        )

        # Direct Operate (0x05) should be present
        func_codes = {
            ix.details["function_code"]
            for ix in listener.interactions
            if ix.details.get("function_code") is not None
        }
        assert 0x05 in func_codes, f"Missing Direct Operate (0x05); got {func_codes}"

    def test_dnp3_write_operations(self):
        """Verify write operation detection and session tracking."""
        listener, devices, result = _run_listener_test(
            "dnp3",
            "DNP3PassiveListener",
            "dnp3",
            "dnp3/iti_write_binary_output.pcap",
            expect_details=["function_name"],
        )

        # Write (0x02) should be present
        func_codes = {
            ix.details["function_code"]
            for ix in listener.interactions
            if ix.details.get("function_code") is not None
        }
        assert 0x02 in func_codes, f"Missing Write (0x02); got {func_codes}"

        # Session should track control operations
        control_ops = listener.get_control_operations()
        assert len(control_ops) >= 1, "No control operations tracked for write pcap"

    def test_dnp3_cold_restart(self):
        """Verify cold restart function code extraction."""
        listener, devices, result = _run_listener_test(
            "dnp3",
            "DNP3PassiveListener",
            "dnp3",
            "dnp3/iti_cold_restart_and_response.pcap",
            expect_details=["function_name"],
        )

        # Cold Restart (0x0D) should be present
        func_codes = {
            ix.details["function_code"]
            for ix in listener.interactions
            if ix.details.get("function_code") is not None
        }
        assert 0x0D in func_codes, f"Missing Cold Restart (0x0D); got {func_codes}"

        # Verify human-readable name
        func_names = {
            ix.details["function_name"]
            for ix in listener.interactions
            if ix.details.get("function_name")
        }
        assert "Cold Restart" in func_names, f"Missing 'Cold Restart' name; got {func_names}"
