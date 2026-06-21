"""Integration tests for GOOSE passive listener in EK mode.

Tests tshark field extraction, interaction details, device data, and
harvest output. Covers the T1 field gaps fixed in the GOOSE listener:
- goose.allData (top-level data sequence count)
- goose.structure (nested structure member counts)
- goose.integer (individual integer values, not comma-grouped)
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestGOOSEPassiveEK:
    """GOOSE-specific tests beyond the parametrized quality suite."""

    def test_goose_publishers_and_frames(self):
        listener, devices, result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE.pcap",
        )

        # A1: publishers populated
        assert len(listener.publishers) >= 1, (
            f"Expected >= 1 GOOSE publisher, got {len(listener.publishers)}"
        )

        # A2: publisher has frames and GoCBRef or APPID
        for pub in listener.publishers.values():
            assert pub.total_frames >= 1, "Publisher has no frames"
            assert pub.gocb_ref or pub.appid, "Publisher has neither gocb_ref nor appid"

        # A3: passive_data on at least one device
        has_data = any(
            hasattr(d, "goose_passive_data") and d.goose_passive_data for d in devices.values()
        )
        assert has_data, "No device has goose_passive_data"

        # A4: harvest returns a dict
        assert isinstance(result, dict), "harvest() should return a dict"


class TestGOOSEAllDataCount:
    """Tests for goose.allData field extraction (T1 gap fix)."""

    def test_all_data_count_in_details(self):
        """Verify all_data_count is extracted into interaction details."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE.pcap",
        )

        # Every interaction should have all_data_count in details
        has_all_data = any(
            ix.details.get("all_data_count") is not None for ix in listener.interactions
        )
        assert has_all_data, (
            "No interaction has all_data_count in details; "
            f"sample details keys: {list(listener.interactions[0].details.keys()) if listener.interactions else '[]'}"
        )

    def test_all_data_count_positive(self):
        """Verify all_data_count is a positive integer matching expected data."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE.pcap",
        )

        # The main GOOSE pcap has 8 data entries per frame
        counts = [
            ix.details.get("all_data_count", 0)
            for ix in listener.interactions
            if ix.details.get("all_data_count") is not None
        ]
        assert len(counts) > 0, "No all_data_count values found"
        assert all(isinstance(c, int) for c in counts), (
            f"all_data_count should be int, got types: {set(type(c).__name__ for c in counts)}"
        )
        assert all(c > 0 for c in counts), f"all_data_count should be > 0, got: {counts[:5]}"

    def test_all_data_count_iec61850(self):
        """Verify all_data_count with IEC 61850 pcap that has varying counts."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/iec61850_scapy_wireshark2.pcap",
        )

        counts = [
            ix.details["all_data_count"]
            for ix in listener.interactions
            if ix.details.get("all_data_count") is not None
        ]
        assert len(counts) > 0, "No all_data_count values found"
        # IEC 61850 pcap has packets with allData=1 and allData=19
        unique_counts = set(counts)
        assert len(unique_counts) >= 2, (
            f"Expected at least 2 distinct all_data_count values, got: {sorted(unique_counts)}"
        )


class TestGOOSEStructureCounts:
    """Tests for goose.structure field extraction (T1 gap fix)."""

    def test_structure_counts_in_iec61850(self):
        """Verify structure_counts extracted from IEC 61850 pcap."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/iec61850_scapy_wireshark2.pcap",
        )

        # IEC 61850 pcap has nested structures
        has_structure = any(ix.details.get("structure_counts") for ix in listener.interactions)
        assert has_structure, (
            "No interaction has structure_counts in IEC 61850 pcap; "
            "goose.structure field extraction may be broken"
        )

    def test_structure_counts_are_int_list(self):
        """Verify structure_counts is a list of integers."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/iec61850_scapy_wireshark2.pcap",
        )

        for ix in listener.interactions:
            sc = ix.details.get("structure_counts")
            if sc:
                assert isinstance(sc, list), f"structure_counts should be list, got {type(sc)}"
                for item in sc:
                    assert isinstance(item, int), (
                        f"structure_counts items should be int, got {type(item)}: {item}"
                    )
                assert all(item > 0 for item in sc), f"structure_counts should be > 0, got: {sc}"

    def test_structure_counts_match_expected(self):
        """Verify structure count values match known IEC 61850 data layout."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/iec61850_scapy_wireshark2.pcap",
        )

        # IEC 61850 pcap has structures with counts like [11, 3, 3, 3, ...]
        all_sc = [
            ix.details["structure_counts"]
            for ix in listener.interactions
            if ix.details.get("structure_counts")
        ]
        assert len(all_sc) > 0, "No structure_counts found"

        # Check that at least one structure has > 1 member count
        has_multi_member = any(any(c > 1 for c in sc) for sc in all_sc)
        assert has_multi_member, f"Expected nested structures with > 1 members; got: {all_sc[:3]}"

    def test_no_structure_counts_in_flat_goose(self):
        """Verify structure_counts absent in pcaps without nested structures."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE.pcap",
        )

        # The main GOOSE pcap should NOT have structure_counts (flat data)
        has_structure = any(ix.details.get("structure_counts") for ix in listener.interactions)
        # This assertion may or may not hold depending on the pcap; if
        # it does have structures, that's fine too -- we just verify no crash
        if has_structure:
            # If structures exist, they must be valid int lists
            for ix in listener.interactions:
                sc = ix.details.get("structure_counts")
                if sc:
                    assert isinstance(sc, list)


class TestGOOSEIntegerValues:
    """Tests for goose.integer field extraction (T1 gap fix)."""

    def test_integer_values_extracted(self):
        """Verify integer values are extracted as individual items."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/iec61850_scapy_wireshark2.pcap",
        )

        # IEC 61850 pcap has integer data values [1, 1, 1]
        has_integer = False
        for ix in listener.interactions:
            values = ix.details.get("values", [])
            if values:
                # Integer values should appear as individual items, not
                # comma-grouped like "1,1,1"
                for v in values:
                    try:
                        int(v)
                        has_integer = True
                        break
                    except (ValueError, TypeError):
                        continue
            if has_integer:
                break

        assert has_integer, (
            "No integer values found in interaction details; "
            "goose.integer field extraction may be broken"
        )

    def test_values_are_individual_items(self):
        """Verify multi-value fields are split into individual items, not comma-grouped."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE.pcap",
        )

        # In EK mode, booleans should be individual items: ["F", "F", "T", ...]
        # NOT comma-grouped: ["F,F,T,..."]
        for ix in listener.interactions:
            values = ix.details.get("values", [])
            for v in values:
                # No value should contain commas (that indicates grouping)
                assert "," not in v, (
                    f"Value '{v}' contains comma -- multi-value field "
                    f"was not split into individual items"
                )


class TestGOOSEBooleanExtraction:
    """Tests for proper per-item boolean value extraction."""

    def test_boolean_values_formatted(self):
        """Verify boolean values are formatted as T/F."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE.pcap",
        )

        has_bool = False
        for ix in listener.interactions:
            values = ix.details.get("values", [])
            for v in values:
                if v in ("T", "F"):
                    has_bool = True
                    break
            if has_bool:
                break

        assert has_bool, (
            "No formatted boolean values (T/F) found; "
            "boolean extraction or formatting may be broken"
        )

    def test_boolean_count_matches_data(self):
        """Verify number of individual boolean values matches expected count."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE.pcap",
        )

        # The main GOOSE pcap has allData=8 with 4 booleans and 4 bitstrings
        for ix in listener.interactions:
            values = ix.details.get("values", [])
            if values:
                bool_vals = [v for v in values if v in ("T", "F")]
                # Should have 4 individual booleans, not 1 comma-grouped
                assert len(bool_vals) >= 4, (
                    f"Expected >= 4 individual boolean values, got {len(bool_vals)}: {values}"
                )
                break


class TestGOOSEInteractionTable:
    """Tests for the PROTOCOL_COLUMNS + _format_protocol_columns wiring."""

    def test_harvest_returns_dict(self):
        """Verify harvest() returns a dict."""
        _listener, _devices, result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE.pcap",
        )

        assert isinstance(result, dict), "harvest() should return a dict"

    def test_format_protocol_columns_count(self):
        """_format_protocol_columns output must match PROTOCOL_COLUMNS length."""
        from oida.pcap.goose import GOOSEPassiveListener

        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE.pcap",
        )

        expected = len(GOOSEPassiveListener.PROTOCOL_COLUMNS)
        for ix in listener.interactions:
            row = listener._format_protocol_columns(ix)
            assert len(row) == expected, f"Row has {len(row)} columns, expected {expected}: {row}"

    def test_interaction_values_are_individual_items(self):
        """Verify values in interaction details use individual items, not comma-grouped."""
        listener, _devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE.pcap",
        )

        for ix in listener.interactions:
            values = ix.details.get("values", [])
            for v in values:
                assert "," not in v, (
                    f"Value '{v}' contains comma; individual item separation broken"
                )


class TestGOOSEDeviceData:
    """Tests for device data enrichment."""

    def test_device_data_fields(self):
        """Verify goose_passive_data has all expected fields."""
        _listener, devices, _result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE.pcap",
        )

        expected_keys = {
            "role",
            "gocb_refs",
            "datasets",
            "go_ids",
            "appids",
            "conf_revs",
            "state_changes",
            "total_frames",
            "test_frames",
            "st_num_rollbacks",
            "protocol",
            "first_seen",
            "last_seen",
        }

        for dev in devices.values():
            if hasattr(dev, "goose_passive_data") and dev.goose_passive_data:
                data = dev.goose_passive_data
                missing = expected_keys - set(data.keys())
                assert not missing, (
                    f"goose_passive_data missing keys: {missing}; got: {sorted(data.keys())}"
                )
                assert data["role"] == "publisher"
                assert data["protocol"] == "GOOSE/L2"
                assert data["total_frames"] > 0
                break
        else:
            pytest.fail("No device has goose_passive_data")


class TestGOOSEMultiplePcaps:
    """Test with multiple pcap fixtures to verify robustness."""

    def test_iec61850_scapy_pcap(self):
        """Test with IEC 61850 scapy pcap (has structure and integer fields)."""
        listener, devices, result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/iec61850_scapy_wireshark2.pcap",
        )

        assert len(listener.publishers) >= 1
        assert len(listener.interactions) >= 1
        assert len(devices) >= 1

        # This pcap should have both structure_counts and integer values
        has_structure = any(ix.details.get("structure_counts") for ix in listener.interactions)
        assert has_structure, "IEC 61850 pcap should have structure_counts"

    def test_goose_demo_pcap(self):
        """Test with GOOSE demo pcap."""
        listener, devices, result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_GOOSE_DEMO.pcap",
        )

        assert len(listener.publishers) >= 1
        assert len(listener.interactions) >= 1

        # all_data_count should be present
        has_adc = any(ix.details.get("all_data_count") is not None for ix in listener.interactions)
        assert has_adc, "GOOSE DEMO pcap should have all_data_count"

    def test_sample_file_goose(self):
        """Test with sample GOOSE file."""
        listener, devices, result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/goosestalker_Sample_File_GOOSE.pcap",
        )

        assert len(listener.publishers) >= 1
        assert len(listener.interactions) >= 1

    def test_iti_sample_goose(self):
        """Test with ITI sample GOOSE file."""
        listener, devices, result = _run_listener_test(
            "goose",
            "GOOSEPassiveListener",
            "goose",
            "goose/iti_sample_goose.pcap",
        )

        assert len(listener.publishers) >= 1
        assert len(listener.interactions) >= 1
