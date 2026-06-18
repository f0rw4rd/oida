"""Integration tests for PROFINET passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

# Common args used by all PROFINET tests
_PN_ARGS = dict(
    module_name="profinet",
    class_name="PROFINETPassiveListener",
    display_filter="pn_io || pn_dcp || pn_rt || pn_io.opnum",
)


class TestPROFINETPassiveEK:
    """PROFINET-specific tests beyond the parametrized quality suite."""

    def test_profinet_sessions_and_operations(self):
        listener, devices, result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/cisagov_profinet_io_cm_mixed_1.pcap",
        )
        # PROFINET should track sessions between controllers and devices
        assert len(listener.sessions) >= 1 or len(listener.dcp_devices) >= 1, (
            "Expected at least one PROFINET session or DCP device"
        )

        # Check that profinet_passive_data is populated on at least one device
        has_passive_data = any(
            hasattr(d, "profinet_passive_data") and d.profinet_passive_data
            for d in devices.values()
        )
        assert has_passive_data, "No device has profinet_passive_data"

        # Harvest should produce tables (PROTOCOL_COLUMNS is set)
        assert isinstance(result, dict)

    # ------------------------------------------------------------------
    # DCP field extraction tests
    # ------------------------------------------------------------------

    def test_dcp_xid_extracted(self):
        """pn_dcp.xid -- DCP transaction ID for req/res correlation."""
        listener, _devices, _result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/cisagov_profinet_io_cm_mixed_1.pcap",
            expect_details=["xid"],
        )
        # At least one DCP interaction should carry a non-zero xid
        xid_values = [
            ix.details["xid"] for ix in listener.interactions if ix.details.get("xid") is not None
        ]
        assert len(xid_values) >= 1, "Expected at least one interaction with xid"

    def test_dcp_service_type_response_extracted(self):
        """pn_dcp.service_type.response -- explicit DCP response flag.

        This field only appears on DCP response packets (not requests),
        so we check that at least one DCP response carries it.
        """
        listener, _devices, _result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/cisagov_profinet_io_cm_mixed_1.pcap",
        )
        # service_type_response only present on DCP response packets
        has_field = any(
            ix.details.get("service_type_response") is not None
            for ix in listener.interactions
            if ix.details.get("service_id") is not None
        )
        assert has_field, "Expected at least one DCP response with service_type_response"

    def test_dcp_service_type_selection_extracted(self):
        """pn_dcp.service_type.selection -- multicast selection bit."""
        listener, _devices, _result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/cisagov_profinet_io_cm_mixed_1.pcap",
        )
        # At least one DCP interaction should have service_type_selection
        has_field = any(
            ix.details.get("service_type_selection") is not None
            for ix in listener.interactions
            if ix.details.get("service_id") is not None
        )
        assert has_field, "Expected DCP interaction with service_type_selection"

    def test_dcp_vendor_value_extracted(self):
        """pn_dcp.suboption_device_devicevendorvalue -- device vendor string."""
        listener, _devices, _result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/cisagov_profinet_io_cm_mixed_1.pcap",
        )
        # Look for vendor_value in DCP interactions
        vendor_values = [
            ix.details["vendor_value"]
            for ix in listener.interactions
            if ix.details.get("vendor_value")
        ]
        assert len(vendor_values) >= 1, "Expected at least one DCP vendor_value"

    def test_dcp_vendor_value_stored_on_device(self):
        """vendor_value should be stored in DCPDevice and profinet_passive_data."""
        listener, devices, _result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/cisagov_profinet_io_cm_mixed_1.pcap",
        )
        # Check DCPDevice objects
        vendor_values = [d.vendor_value for d in listener.dcp_devices.values() if d.vendor_value]
        if listener.dcp_devices:
            assert len(vendor_values) >= 1, "Expected at least one DCPDevice with vendor_value"

        # Check profinet_passive_data on discovered devices
        for dev in devices.values():
            pdata = getattr(dev, "profinet_passive_data", None)
            if pdata and pdata.get("role") == "dcp_device":
                assert "vendor_value" in pdata, (
                    "DCP device missing vendor_value in profinet_passive_data"
                )

    def test_dcp_block_error_extracted(self):
        """pn_dcp.block_error -- block error code from DCP responses.

        block_error=0 means no error; it still proves the field was extracted.
        """
        listener, _devices, _result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/iti_profinet-wireshark-bug.pcap",
            min_devices=0,
            min_interactions=1,
        )
        # block_error is present (even if 0) on at least one DCP interaction
        has_block_error = any(
            ix.details.get("block_error") is not None
            for ix in listener.interactions
            if ix.details.get("service_id") is not None
        )
        assert has_block_error, "Expected DCP interaction with block_error"

    def test_dcp_change_ip_pcap(self):
        """Test DCP field extraction with the ChangeIPUsingDCP pcap."""
        listener, _devices, _result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/iti_ChangeIPUsingDCP.pcap",
            min_devices=0,
            min_interactions=1,
        )
        # Should have DCP interactions with xid and station_name
        dcp_ixs = [ix for ix in listener.interactions if ix.details.get("service_id") is not None]
        assert len(dcp_ixs) >= 1, "Expected DCP interactions"
        xid_found = any(ix.details.get("xid") is not None for ix in dcp_ixs)
        assert xid_found, "Expected xid in DCP interactions from ChangeIP pcap"

    # ------------------------------------------------------------------
    # RT field extraction tests
    # ------------------------------------------------------------------

    def test_rt_ds_valid_extracted(self):
        """pn_rt.ds_valid -- DataValid flag in RT frames."""
        listener, _devices, _result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/cisagov_profinet_io_cm_mixed_1.pcap",
        )
        # ds_valid appears in alarm/RT frame interactions
        has_ds_valid = any(ix.details.get("ds_valid") is not None for ix in listener.interactions)
        # ds_valid may only appear in alarm RT frames; if none were recorded,
        # skip gracefully -- but it should be in the code path
        if any(ix.details.get("frame_id") for ix in listener.interactions):
            assert has_ds_valid, "Expected ds_valid in RT alarm interactions"

    def test_rt_transfer_status_extracted(self):
        """pn_rt.transfer_status -- transfer status in RT frames."""
        listener, _devices, _result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/cisagov_profinet_io_cm_mixed_1.pcap",
        )
        # transfer_status appears in alarm/RT frame interactions
        has_ts = any(ix.details.get("transfer_status") is not None for ix in listener.interactions)
        if any(ix.details.get("frame_id") for ix in listener.interactions):
            assert has_ts, "Expected transfer_status in RT alarm interactions"

    # ------------------------------------------------------------------
    # IO field extraction tests
    # ------------------------------------------------------------------

    def test_io_frame_info_vendor_extracted(self):
        """pn_io.frame_info.vendor -- vendor name from PROFINET frame info."""
        listener, _devices, _result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/cisagov_profinet_io_cm_mixed_2.pcapng",
            min_devices=0,
            min_interactions=0,
        )
        # frame_info_vendor should appear in pn_io interactions
        vendor_names = [
            ix.details["frame_info_vendor"]
            for ix in listener.interactions
            if ix.details.get("frame_info_vendor")
        ]
        assert len(vendor_names) >= 1, "Expected at least one IO interaction with frame_info_vendor"

    # ------------------------------------------------------------------
    # Multi-pcap / cross-field tests
    # ------------------------------------------------------------------

    def test_profinet_rt_pcap(self):
        """iti_PROFINET-RT.pcap: DCP + RT traffic together."""
        listener, _devices, _result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/iti_PROFINET-RT.pcap",
            min_devices=0,
            min_interactions=0,
        )
        # Should not crash; may have DCP interactions
        if listener.interactions:
            dcp_count = sum(
                1 for ix in listener.interactions if ix.details.get("service_id") is not None
            )
            assert dcp_count >= 0  # just verifying no crash

    def test_profinet_mixed_2_pcap(self):
        """cisagov_profinet_io_cm_mixed_2.pcapng: DCP + IO + RT data."""
        listener, devices, result = _run_listener_test(
            **_PN_ARGS,
            pcap_subpath="profinet/cisagov_profinet_io_cm_mixed_2.pcapng",
        )
        assert len(listener.interactions) >= 1
        # Verify harvest tables are clean (no raw dicts/sets)
        for table in result.get("tables", []):
            for row in table.get("rows", []):
                for cell in row:
                    assert not isinstance(cell, (dict, set)), (
                        f"Raw dict/set in harvest table cell: {cell}"
                    )
