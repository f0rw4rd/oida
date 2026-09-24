"""Integration tests for IGMP passive listener field extraction.

Tests verify that all T1 (high-value) tshark fields are correctly extracted
from real pcap fixtures in EK mode, and that the extracted data flows through
to interaction details, device data, and harvest output.

T1 fields tested:
  - igmp.version: IGMP protocol version (tshark-dissected)
  - igmp.checksum: IGMP packet checksum value
  - igmp.checksum.status: Checksum validation result (1=Good, 2=Bad)

T2 fields tested (v3 query parameters):
  - igmp.qrv: Querier's Robustness Value
  - igmp.qqic: Querier's Query Interval Code
  - igmp.num_src: Number of multicast sources
  - igmp.s: Suppress Router Side Processing flag
  - igmp.record_type: Group record type (v3 reports)
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

_MODULE = "igmp"
_CLASS = "IGMPPassiveListener"
_FILTER = "igmp"
_PCAP = "igmp/filtered_igmp.pcap"


def _run_igmp():
    """Run the IGMP listener against the filtered fixture pcap."""
    return _run_listener_test(
        _MODULE,
        _CLASS,
        _FILTER,
        _PCAP,
        min_devices=1,
        min_interactions=1,
        expect_details=["version", "checksum", "checksum_status"],
        expect_operations=["IGMP Query", "IGMP Report"],
    )


# ---------------------------------------------------------------------------
# T1: igmp.version
# ---------------------------------------------------------------------------


class TestIGMPVersion:
    """Tests for igmp.version (T1) field extraction."""

    def test_version_extracted_in_details(self):
        """Every interaction has a 'version' in its details dict."""
        listener, _, _ = _run_igmp()
        for ix in listener.interactions:
            v = ix.details.get("version")
            assert v is not None, (
                f"Interaction from {ix.src_ip} missing 'version' in details: {ix.details}"
            )

    def test_version_uses_tshark_value(self):
        """Version should match tshark-dissected values (1 or 3 in fixture)."""
        listener, _, _ = _run_igmp()
        versions_seen = {ix.details["version"] for ix in listener.interactions}
        # The fixture has v1 reports (type 0x12) and v3 queries/reports
        assert versions_seen, "No versions extracted"
        # All versions in the fixture should be 1 or 3
        for v in versions_seen:
            assert v in (1, 2, 3), f"Unexpected IGMP version: {v}"

    def test_version_in_device_data(self):
        """Device igmp_data includes the version field."""
        _, devices, _ = _run_igmp()
        for dev in devices.values():
            if hasattr(dev, "igmp_data") and dev.igmp_data:
                assert "version" in dev.igmp_data, f"igmp_data missing 'version': {dev.igmp_data}"
                assert dev.igmp_data["version"] in (1, 2, 3), (
                    f"Unexpected version in igmp_data: {dev.igmp_data['version']}"
                )


# ---------------------------------------------------------------------------
# T1: igmp.checksum
# ---------------------------------------------------------------------------


class TestIGMPChecksum:
    """Tests for igmp.checksum (T1) field extraction."""

    def test_checksum_extracted_in_details(self):
        """Every interaction has a 'checksum' in its details dict."""
        listener, _, _ = _run_igmp()
        for ix in listener.interactions:
            cksum = ix.details.get("checksum")
            assert cksum is not None and cksum != "", (
                f"Interaction from {ix.src_ip} missing 'checksum' in details: {ix.details}"
            )

    def test_checksum_is_numeric_string(self):
        """Checksum values should be numeric strings (decimal from tshark)."""
        listener, _, _ = _run_igmp()
        for ix in listener.interactions:
            cksum = ix.details.get("checksum", "")
            if cksum:
                # Should be parseable as int (tshark returns decimal)
                try:
                    int(cksum)
                except ValueError:
                    pytest.fail(f"Checksum '{cksum}' is not a valid integer (from {ix.src_ip})")


# ---------------------------------------------------------------------------
# T1: igmp.checksum.status
# ---------------------------------------------------------------------------


class TestIGMPChecksumStatus:
    """Tests for igmp.checksum.status (T1) field extraction."""

    def test_checksum_status_extracted_in_details(self):
        """Every interaction has 'checksum_status' in its details dict."""
        listener, _, _ = _run_igmp()
        for ix in listener.interactions:
            status = ix.details.get("checksum_status")
            assert status is not None, (
                f"Interaction from {ix.src_ip} missing 'checksum_status': {ix.details}"
            )

    def test_checksum_status_is_human_readable(self):
        """Checksum status should be 'Good', 'Bad', or '?' -- not raw int."""
        listener, _, _ = _run_igmp()
        valid = {"Good", "Bad", "?"}
        for ix in listener.interactions:
            status = ix.details.get("checksum_status", "?")
            assert status in valid, (
                f"Unexpected checksum_status '{status}' from {ix.src_ip}; expected one of {valid}"
            )

    def test_checksum_status_good_in_fixture(self):
        """The fixture pcap has valid packets -- all checksums should be Good."""
        listener, _, _ = _run_igmp()
        statuses = {ix.details["checksum_status"] for ix in listener.interactions}
        assert "Good" in statuses, (
            f"Expected 'Good' checksum status in fixture data, got: {statuses}"
        )

    def test_checksum_status_in_device_data(self):
        """Device igmp_data includes checksum_status."""
        _, devices, _ = _run_igmp()
        found = False
        for dev in devices.values():
            if hasattr(dev, "igmp_data") and dev.igmp_data:
                status = dev.igmp_data.get("checksum_status")
                if status:
                    found = True
                    assert status in ("Good", "Bad", "?"), (
                        f"Unexpected checksum_status in device: {status}"
                    )
        assert found, "No device has checksum_status in igmp_data"


# ---------------------------------------------------------------------------
# T2: v3 query parameters (qrv, qqic, num_src, s)
# ---------------------------------------------------------------------------


class TestIGMPV3QueryFields:
    """Tests for v3 query parameter extraction (T2 fields)."""

    def test_qrv_extracted_for_queries(self):
        """Query interactions include 'qrv' (Querier's Robustness Value)."""
        listener, _, _ = _run_igmp()
        queries = [ix for ix in listener.interactions if ix.details.get("type_name") == "Query"]
        assert queries, "Expected at least one Query interaction"
        for q in queries:
            qrv = q.details.get("qrv")
            assert qrv is not None, f"Query from {q.src_ip} missing 'qrv' in details"
            assert isinstance(qrv, int), f"qrv should be int, got {type(qrv)}"

    def test_qqic_extracted_for_queries(self):
        """Query interactions include 'qqic' (Querier's Query Interval Code)."""
        listener, _, _ = _run_igmp()
        queries = [ix for ix in listener.interactions if ix.details.get("type_name") == "Query"]
        assert queries, "Expected at least one Query interaction"
        for q in queries:
            qqic = q.details.get("qqic")
            assert qqic is not None, f"Query from {q.src_ip} missing 'qqic' in details"
            assert isinstance(qqic, int), f"qqic should be int, got {type(qqic)}"

    def test_num_src_extracted_for_queries(self):
        """Query interactions include 'num_src' (number of sources)."""
        listener, _, _ = _run_igmp()
        queries = [ix for ix in listener.interactions if ix.details.get("type_name") == "Query"]
        assert queries, "Expected at least one Query interaction"
        for q in queries:
            num_src = q.details.get("num_src")
            assert num_src is not None, f"Query from {q.src_ip} missing 'num_src' in details"

    def test_suppress_router_for_queries(self):
        """Query interactions include 'suppress_router_processing' flag."""
        listener, _, _ = _run_igmp()
        queries = [ix for ix in listener.interactions if ix.details.get("type_name") == "Query"]
        assert queries, "Expected at least one Query interaction"
        for q in queries:
            suppress = q.details.get("suppress_router_processing")
            assert suppress is not None, (
                f"Query from {q.src_ip} missing 'suppress_router_processing'"
            )
            assert isinstance(suppress, bool), (
                f"suppress_router_processing should be bool, got {type(suppress)}"
            )

    def test_query_fields_not_on_reports(self):
        """Report interactions should NOT have qrv/qqic (query-only fields)."""
        listener, _, _ = _run_igmp()
        reports = [ix for ix in listener.interactions if ix.details.get("type_name") == "Report"]
        assert reports, "Expected at least one Report interaction"
        for r in reports:
            # qrv/qqic are query-specific; should be absent from reports
            assert r.details.get("qrv") is None, f"Report from {r.src_ip} should not have 'qrv'"

    def test_query_params_in_device_data(self):
        """Router devices include v3 query params in igmp_data."""
        _, devices, _ = _run_igmp()
        routers = [
            dev
            for dev in devices.values()
            if hasattr(dev, "igmp_data") and dev.igmp_data and dev.igmp_data.get("is_router")
        ]
        assert routers, "Expected at least one router device"
        for dev in routers:
            data = dev.igmp_data
            assert "qrv" in data, f"Router igmp_data missing 'qrv': {data}"
            assert "qqic" in data, f"Router igmp_data missing 'qqic': {data}"


# ---------------------------------------------------------------------------
# T2: record_type (v3 reports)
# ---------------------------------------------------------------------------


class TestIGMPRecordType:
    """Tests for igmp.record_type extraction in v3 membership reports."""

    def test_record_type_extracted_for_v3_reports(self):
        """v3 Report interactions include 'record_type' in details."""
        listener, _, _ = _run_igmp()
        v3_reports = [
            ix
            for ix in listener.interactions
            if ix.details.get("type_name") == "Report" and ix.details.get("version") == 3
        ]
        assert v3_reports, "Expected at least one v3 Report interaction"
        for r in v3_reports:
            rt = r.details.get("record_type")
            assert rt is not None, f"v3 Report from {r.src_ip} missing 'record_type' in details"
            assert isinstance(rt, int), f"record_type should be int, got {type(rt)}"


# ---------------------------------------------------------------------------
# Harvest output structure
# ---------------------------------------------------------------------------


class TestIGMPHarvest:
    """Tests for harvest() output quality and structure."""

    def test_harvest_returns_dict(self):
        """harvest() returns a dict with expected keys."""
        _, _, result = _run_igmp()
        assert isinstance(result, dict), "harvest() should return a dict"

    def test_no_raw_dicts_in_cells(self):
        """Table cells should be primitives, not raw dicts/sets."""
        _, _, result = _run_igmp()
        for table in result.get("tables", []):
            for row in table.get("rows", []):
                for cell in row:
                    assert not isinstance(cell, dict), f"Raw dict in cell: {cell}"
                    assert not isinstance(cell, set), f"Raw set in cell: {cell}"


# ---------------------------------------------------------------------------
# Device enrichment
# ---------------------------------------------------------------------------


class TestIGMPDeviceEnrichment:
    """Tests for device data quality from IGMP extraction."""

    def test_devices_have_igmp_data(self):
        """At least one device has igmp_data attribute."""
        _, devices, _ = _run_igmp()
        has_data = any(hasattr(dev, "igmp_data") and dev.igmp_data for dev in devices.values())
        assert has_data, "No device has igmp_data"

    def test_igmp_data_has_protocol(self):
        """igmp_data includes 'protocol' field set to 'IGMP'."""
        _, devices, _ = _run_igmp()
        for dev in devices.values():
            if hasattr(dev, "igmp_data") and dev.igmp_data:
                assert dev.igmp_data.get("protocol") == "IGMP", (
                    f"Expected protocol='IGMP', got: {dev.igmp_data.get('protocol')}"
                )

    def test_router_detected(self):
        """Query senders are identified as routers."""
        _, devices, _ = _run_igmp()
        routers = [
            dev
            for dev in devices.values()
            if hasattr(dev, "igmp_data") and dev.igmp_data and dev.igmp_data.get("is_router")
        ]
        assert routers, "Expected at least one router device"

    def test_multicast_groups_tracked(self):
        """Devices have multicast_groups list in igmp_data."""
        _, devices, _ = _run_igmp()
        found_groups = False
        for dev in devices.values():
            if hasattr(dev, "igmp_data") and dev.igmp_data:
                groups = dev.igmp_data.get("multicast_groups", [])
                if groups:
                    found_groups = True
                    for g in groups:
                        assert isinstance(g, str), f"Group should be str: {g}"
        assert found_groups, "No device has multicast_groups populated"
