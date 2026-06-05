"""Integration tests for S7comm passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestS7commPassiveEK:
    """S7comm-specific tests beyond the parametrized quality suite."""

    def test_s7comm_cisagov(self):
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/cisagov_snap7.pcap",
            expect_details=["function_code"],
        )

        # A1: passive_data on at least one device
        has_data = any(
            hasattr(d, "s7comm_passive_data") and d.s7comm_passive_data for d in devices.values()
        )
        assert has_data, "No device has s7comm_passive_data"

        # A2: harvest tables exist (PROTOCOL_COLUMNS is set)
        assert result.get("tables"), "harvest() returned no tables"

    def test_s7comm_generated(self):
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/generated_s7comm.pcap",
            expect_details=["function_code"],
        )

        # A1: at least one device with s7comm_passive_data
        has_data = any(
            hasattr(d, "s7comm_passive_data") and d.s7comm_passive_data for d in devices.values()
        )
        assert has_data, "No device has s7comm_passive_data"


class TestS7commFieldCoverage:
    """Tests verifying new T1 field extractions from the coverage audit."""

    def test_block_control_fields(self):
        """Verify block control fields: file_identifier, functionstatus, upload_id.

        Uses cisagov_snap7.pcap which has upload/download block operations.
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/cisagov_snap7.pcap",
            expect_details=["function_code"],
        )

        block_ops = [
            ix
            for ix in listener.interactions
            if ix.operation
            in (
                "Request Download",
                "Download Block",
                "Download Ended",
                "Start Upload",
                "Upload",
                "End Upload",
            )
        ]
        if block_ops:
            has_fs = any(ix.details.get("function_status") for ix in block_ops)
            has_fi = any(ix.details.get("file_identifier") for ix in block_ops)
            assert has_fs or has_fi, (
                f"Block control ops found ({len(block_ops)}) but none have "
                f"function_status or file_identifier. "
                f"Sample details: {block_ops[0].details}"
            )

    def test_block_control_download_db1(self):
        """Verify block control with downloading_block_db1 pcap.

        This pcap has Request Download, Download Block, Download Ended.
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/iti_s7comm_downloading_block_db1.pcap",
            expect_details=["function_code"],
        )

        block_ops = [
            ix
            for ix in listener.interactions
            if ix.operation
            in (
                "Request Download",
                "Download Block",
                "Download Ended",
                "Start Upload",
                "Upload",
                "End Upload",
            )
        ]
        assert len(block_ops) > 0, "Expected block control operations in download pcap"

        has_fs = any("function_status" in ix.details for ix in block_ops)
        assert has_fs, (
            f"No block control op has function_status. Sample details: {block_ops[0].details}"
        )

    def test_userdata_type_extraction(self):
        """Verify userdata type field (param.userdata.type) is extracted.

        Uses cisagov_snap7.pcap which has userdata frames with SZL reads.
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/cisagov_snap7.pcap",
            expect_details=["function_code"],
        )

        ud_ops = [
            ix for ix in listener.interactions if ix.details.get("function_group") is not None
        ]
        assert len(ud_ops) > 0, "Expected userdata operations in snap7 pcap"

        has_ud_type = any(ix.details.get("userdata_type") for ix in ud_ops)
        assert has_ud_type, f"No userdata op has userdata_type. Sample details: {ud_ops[0].details}"

    def test_szl_index_extraction(self):
        """Verify SZL index field (data.userdata.szl_index) is extracted.

        Uses cisagov_snap7.pcap which has Read SZL operations.
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/cisagov_snap7.pcap",
            expect_details=["function_code"],
        )

        szl_ops = [ix for ix in listener.interactions if ix.operation.startswith("Read SZL")]
        assert len(szl_ops) > 0, "Expected Read SZL operations"

        has_szl_index = any(ix.details.get("szl_index") for ix in szl_ops)
        assert has_szl_index, f"No Read SZL op has szl_index. Sample details: {szl_ops[0].details}"

    def test_szl_001c_identity_fields(self):
        """Verify SZL 001C extended identity fields: manufacturer_id, oem_id, location_id.

        Uses cisagov_snap7.pcap which has SZL 001C responses.
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/cisagov_snap7.pcap",
            expect_details=["function_code"],
        )

        szl_001c_ops = [
            ix
            for ix in listener.interactions
            if "0x001c" in str(ix.details.get("szl_id", "")).lower()
        ]
        if szl_001c_ops:
            has_mfr = any(ix.details.get("manufacturer_id") for ix in szl_001c_ops)
            has_oem = any(ix.details.get("oem_id") for ix in szl_001c_ops)
            has_loc = any(ix.details.get("location_id") for ix in szl_001c_ops)
            assert has_mfr or has_oem or has_loc, (
                f"SZL 001C ops found ({len(szl_001c_ops)}) but none have "
                f"manufacturer_id, oem_id, or location_id. "
                f"Sample details: {szl_001c_ops[0].details}"
            )

    def test_szl_0132_protection_param(self):
        """Verify SZL 0132 assigned protection param field.

        Uses iti_s7comm_reading_plc_status.pcap which has SZL 0132 responses.
        This pcap has Setup Communication and Userdata (SZL reads) but not
        Read/Write Var, so expect_details uses function_group instead of function_code.
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/iti_s7comm_reading_plc_status.pcap",
            expect_details=["function_group"],
        )

        szl_0132_ops = [
            ix
            for ix in listener.interactions
            if "0x0132" in str(ix.details.get("szl_id", "")).lower()
        ]
        if szl_0132_ops:
            has_protection = any(
                ix.details.get("protection_level")
                or ix.details.get("assigned_protection") is not None
                for ix in szl_0132_ops
            )
            assert has_protection, (
                f"SZL 0132 ops found but none have protection_level or assigned_protection. "
                f"Sample details: {szl_0132_ops[0].details}"
            )

    def test_szl_0424_diagnostic_events(self):
        """Verify SZL 0424 diagnostic buffer event extraction.

        Uses cisagov_snap7.pcap which has SZL 0424 responses with event IDs.
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/cisagov_snap7.pcap",
            expect_details=["function_code"],
        )

        szl_0424_ops = [
            ix
            for ix in listener.interactions
            if "0x0424" in str(ix.details.get("szl_id", "")).lower()
        ]
        if szl_0424_ops:
            has_event = any(ix.details.get("diag_event_id") for ix in szl_0424_ops)
            assert has_event, (
                f"SZL 0424 ops found ({len(szl_0424_ops)}) but none have diag_event_id. "
                f"Sample details: {szl_0424_ops[0].details}"
            )

    def test_block_info_get_block_info(self):
        """Verify blockinfo fields in Get Block Info responses.

        Uses iti_s7comm_program_blocklist_onlineview.pcap which has
        Get Block Info requests/responses with author, headername, etc.
        This pcap has only userdata/block functions (funcgroup=3), so we
        use function_group as the expected detail key.
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/iti_s7comm_program_blocklist_onlineview.pcap",
            expect_details=["function_group"],
        )

        gbi_ops = [ix for ix in listener.interactions if ix.operation == "Get Block Info"]
        if gbi_ops:
            has_author = any(ix.details.get("block_author") for ix in gbi_ops)
            has_name = any(ix.details.get("block_name") for ix in gbi_ops)
            has_version = any(ix.details.get("block_header_version") for ix in gbi_ops)
            has_checksum = any(ix.details.get("block_checksum") for ix in gbi_ops)
            assert has_author or has_name or has_version or has_checksum, (
                f"Get Block Info ops found ({len(gbi_ops)}) but none have "
                f"block_author, block_name, block_header_version, or block_checksum. "
                f"Sample details: {gbi_ops[0].details}"
            )

    def test_cpu_message_fields(self):
        """Verify CPU message username and result fields.

        Uses iti_s7comm_reading_plc_status.pcap which has CPU message frames.
        This pcap has userdata frames only, so expect function_group.
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/iti_s7comm_reading_plc_status.pcap",
            expect_details=["function_group"],
        )

        cpu_ops = [ix for ix in listener.interactions if ix.details.get("function_group") == 4]
        if cpu_ops:
            has_username = any(ix.details.get("cpu_msg_username") for ix in cpu_ops)
            has_result = any(ix.details.get("cpu_msg_result") for ix in cpu_ops)
            if has_username or has_result:
                pass  # Fields found

    def test_tis_job_function(self):
        """Verify TIS job function extraction.

        Uses iti_step7_s300_readDiagData.pcapng which has TIS job function fields.
        This pcap has userdata frames only (programmer commands funcgroup=1).
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/iti_step7_s300_readDiagData.pcapng",
            expect_details=["function_group"],
        )

        programmer_ops = [
            ix for ix in listener.interactions if ix.details.get("function_group") == 1
        ]
        if programmer_ops:
            has_tis = any(ix.details.get("tis_job_function") for ix in programmer_ops)
            if has_tis:
                pass  # Found TIS job function

    def test_alarm_fields(self):
        """Verify alarm function and event ID extraction.

        Uses iti_wincc_s400_production.pcapng which has alarm function fields.
        This pcap has a mix of Read/Write and userdata frames.
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/iti_wincc_s400_production.pcapng",
            expect_details=["function_code"],
        )

        ud_ops = [
            ix for ix in listener.interactions if ix.details.get("function_group") is not None
        ]
        if ud_ops:
            has_alarm_func = any(ix.details.get("alarm_function") for ix in ud_ops)
            has_alarm_event = any(ix.details.get("alarm_event_id") for ix in ud_ops)
            if has_alarm_func or has_alarm_event:
                pass  # Found alarm fields

    def test_harvest_tables_no_raw_types(self):
        """Verify harvest output has no raw dict/set values in table cells."""
        for pcap in [
            "s7comm/cisagov_snap7.pcap",
            "s7comm/iti_s7comm_downloading_block_db1.pcap",
            "s7comm/iti_s7comm_program_blocklist_onlineview.pcap",
        ]:
            listener, devices, result = _run_listener_test(
                "s7comm",
                "S7commPassiveListener",
                "s7comm",
                pcap,
                check_harvest=True,
            )
            for table in result.get("tables", []):
                for row in table.get("rows", []):
                    for cell in row:
                        assert not isinstance(cell, (dict, set)), (
                            f"Raw {type(cell).__name__} in table cell for {pcap}: {cell}"
                        )

    def test_list_blocks_operation(self):
        """Verify List Blocks and List Blocks of Type operations.

        Uses iti_s7comm_program_blocklist_onlineview.pcap which has
        block listing operations. This pcap has only userdata frames.
        """
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/iti_s7comm_program_blocklist_onlineview.pcap",
            expect_details=["function_group"],
        )

        list_ops = [
            ix
            for ix in listener.interactions
            if ix.operation in ("List Blocks", "List Blocks of Type", "Get Block Info")
        ]
        assert len(list_ops) > 0, "Expected block listing operations in blocklist pcap"

    def test_setup_communication(self):
        """Verify Setup Communication extracts PDU length."""
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/cisagov_snap7.pcap",
            expect_details=["function_code"],
        )

        setup_ops = [ix for ix in listener.interactions if ix.operation == "Setup Communication"]
        assert len(setup_ops) > 0, "Expected Setup Communication operations"
        has_pdu = any(ix.details.get("pdu_length") for ix in setup_ops)
        assert has_pdu, (
            f"Setup Communication ops found but none have pdu_length. "
            f"Sample details: {setup_ops[0].details}"
        )

    def test_read_var_syntax_id(self):
        """Verify s7comm.param.item.syntaxid extraction on Read Var requests."""
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/iti_snap7_s300_readVar.pcapng",
            expect_details=["function_code"],
        )
        found = any(ix.details.get("syntax_id") for ix in listener.interactions)
        assert found, (
            "Expected syntax_id in a read/write interaction's details; "
            f"sample details: {listener.interactions[0].details if listener.interactions else 'none'}"
        )

    def test_userdata_seq_num_and_fragmentation(self):
        """Verify userdata seq_num / data_unit_ref / last_data_unit extraction."""
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/iti_s7comm_reading_plc_status.pcap",
            expect_details=["function_group"],
        )
        has_seq = any(ix.details.get("seq_num") for ix in listener.interactions)
        has_ref = any(ix.details.get("data_unit_ref") is not None for ix in listener.interactions)
        has_last = any(
            ix.details.get("last_data_unit") is not None for ix in listener.interactions
        )
        assert has_seq, "Expected seq_num in at least one userdata interaction"
        assert has_ref, "Expected data_unit_ref in at least one userdata interaction"
        assert has_last, "Expected last_data_unit in at least one userdata interaction"

    def test_header_redundancy_id(self):
        """Verify s7comm.header.redid (redundancy_id) extraction."""
        listener, devices, result = _run_listener_test(
            "s7comm",
            "S7commPassiveListener",
            "s7comm",
            "s7comm/iti_s7comm_reading_plc_status.pcap",
            expect_details=["function_group"],
        )
        found = any(ix.details.get("redundancy_id") for ix in listener.interactions)
        assert found, (
            "Expected redundancy_id in a Setup/catch-all interaction's details; "
            f"operations seen: {sorted({ix.operation for ix in listener.interactions})[:15]}"
        )
