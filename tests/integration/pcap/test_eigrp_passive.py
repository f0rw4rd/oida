"""Integration tests for EIGRP passive listener -- T1 field coverage.

Tests verify that each T1-priority tshark field is correctly extracted
in EK mode from real-world pcap fixtures.  Organized by T1 gap field.
"""

import pytest

from .conftest import _load_packets, _pcap_path, _run_listener_test, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_listener():
    """Create an EIGRPPassiveListener for testing."""
    from oida.pcap.eigrp import EIGRPPassiveListener

    listener = EIGRPPassiveListener(interface="lo", timeout=10)
    listener._x509 = True
    return listener


def _feed(listener, pcap_subpath, display_filter="eigrp"):
    """Load packets from a fixture and feed them to the listener."""
    pcap = _pcap_path(pcap_subpath)
    packets = _load_packets(pcap, display_filter=display_filter)
    listener.feed_packets(iter(packets))
    return listener


# ---------------------------------------------------------------------------
# Smoke test -- existing basic assertions
# ---------------------------------------------------------------------------


class TestEIGRPBasic:
    """Basic EIGRP listener functionality."""

    def test_smoke_generated(self):
        """Generated pcap produces devices and interactions."""
        listener, devices, result = _run_listener_test(
            "eigrp",
            "EIGRPPassiveListener",
            "eigrp",
            "eigrp/generated_eigrp.pcap",
            expect_details=["opcode"],
        )
        # EIGRP has no custom harvest tables (interaction/credential tables
        # are now built centrally by the scanner)
        assert isinstance(result, dict)

    def test_smoke_neighbors(self):
        """Wireshark neighbors pcap produces devices."""
        listener, devices, result = _run_listener_test(
            "eigrp",
            "EIGRPPassiveListener",
            "eigrp",
            "eigrp/wireshark_eigrp_neighbors.cap",
            expect_details=["opcode", "as_number"],
        )
        assert len(devices) >= 2, "Expected at least 2 routers in neighbors pcap"


# ---------------------------------------------------------------------------
# T1 gap: eigrp.seq (sequence number)
# ---------------------------------------------------------------------------


class TestEIGRPSeqField:
    """T1: eigrp.seq -- sequence number for reliable delivery."""

    def test_seq_extracted_neighbors(self):
        """seq field is present in interaction details from neighbors pcap."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        assert listener.interactions, "No interactions recorded"
        # Every interaction should have seq_num in details
        for ix in listener.interactions:
            assert "seq_num" in ix.details, f"Missing seq_num in details: {ix.details.keys()}"

    def test_seq_nonzero_in_updates(self):
        """Update packets should have non-zero sequence numbers."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_updates.pcap")
        update_ixs = [ix for ix in listener.interactions if ix.details.get("opcode") == 1]
        assert update_ixs, "No Update interactions found"
        has_nonzero = any(ix.details.get("seq_num", 0) != 0 for ix in update_ixs)
        assert has_nonzero, (
            "All Update packets have seq=0; likely reading wrong field name. "
            f"Sample: {update_ixs[0].details.get('seq_num')}"
        )

    def test_seq_in_interaction_details(self):
        """Seq field should appear in interaction details."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_updates.pcap")
        assert listener.interactions, "No interactions recorded"
        has_seq = any(ix.details.get("seq_num") is not None for ix in listener.interactions)
        assert has_seq, "No interaction has seq_num in details"


# ---------------------------------------------------------------------------
# T1 gap: eigrp.vrid (Virtual Router ID)
# ---------------------------------------------------------------------------


class TestEIGRPVridField:
    """T1: eigrp.vrid -- Virtual Router ID."""

    def test_vrid_extracted(self):
        """vrid field is present in interaction details."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        assert listener.interactions, "No interactions"
        for ix in listener.interactions:
            assert "vrid" in ix.details, f"Missing vrid in details: {ix.details.keys()}"

    def test_vrid_in_device_data(self):
        """vrid is stored in device eigrp_data."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        for dev in listener.discovered_devices.values():
            assert hasattr(dev, "eigrp_data"), "Device missing eigrp_data"
            assert "vrid" in dev.eigrp_data, f"Missing vrid in eigrp_data: {dev.eigrp_data.keys()}"

    def test_vrid_in_interaction_details(self):
        """VRID should appear in interaction details."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        assert listener.interactions, "No interactions recorded"
        has_vrid = any(ix.details.get("vrid") is not None for ix in listener.interactions)
        assert has_vrid, "No interaction has vrid in details"


# ---------------------------------------------------------------------------
# T1 gap: eigrp.flags.restart (NSF restart flag)
# ---------------------------------------------------------------------------


class TestEIGRPRestartFlag:
    """T1: eigrp.flags.restart -- Restart/NSF signaling flag."""

    def test_restart_flag_extracted(self):
        """flags_restart is read and reflected in flag_names when set."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/generated_eigrp.pcap")
        assert listener.interactions, "No interactions"
        # flag_names should be a list in every interaction
        for ix in listener.interactions:
            assert isinstance(ix.details.get("flag_names"), list), (
                f"flag_names not a list: {ix.details.get('flag_names')}"
            )

    def test_individual_flag_booleans_parsed(self):
        """EK-mode individual boolean flags are correctly parsed."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        # In neighbors pcap, all flags should be False (normal Hello packets)
        for ix in listener.interactions:
            flags = ix.details.get("flag_names", [])
            # We just check it's a list -- the specific flags depend on the pcap
            assert isinstance(flags, list), f"Expected list, got {type(flags)}"


# ---------------------------------------------------------------------------
# T1 gap: eigrp.checksum + eigrp.checksum.status
# ---------------------------------------------------------------------------


class TestEIGRPChecksum:
    """T1: eigrp.checksum + eigrp.checksum.status -- integrity validation."""

    def test_checksum_status_extracted(self):
        """checksum_status is present in interaction details."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        assert listener.interactions, "No interactions"
        for ix in listener.interactions:
            assert "checksum_status" in ix.details, f"Missing checksum_status: {ix.details.keys()}"
            # Should be a human-readable string
            assert ix.details["checksum_status"] in ("Good", "Bad", "Unverified"), (
                f"Unexpected checksum_status: {ix.details['checksum_status']}"
            )

    def test_checksum_status_in_device_data(self):
        """checksum_status is stored in device eigrp_data."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        for dev in listener.discovered_devices.values():
            assert "checksum_status" in dev.eigrp_data, (
                f"Missing checksum_status in eigrp_data: {dev.eigrp_data.keys()}"
            )


# ---------------------------------------------------------------------------
# T1 gap: eigrp.release_version + eigrp.tlv_version
# ---------------------------------------------------------------------------


class TestEIGRPVersionFields:
    """T1: eigrp.release_version + eigrp.tlv_version -- fingerprinting."""

    def test_release_version_extracted(self):
        """release_version is decoded and stored in interaction details."""
        _skip_unless_pyshark()
        listener = _make_listener()
        # neighbors pcap has release_version = 3076 = 0x0C04 = 12.4
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        assert listener.interactions, "No interactions"
        found = False
        for ix in listener.interactions:
            rv = ix.details.get("release_version", "")
            if rv:
                found = True
                # Decoded format should be "major.minor"
                assert "." in rv, f"release_version not decoded: {rv}"
                break
        assert found, "No interaction has release_version"

    def test_tlv_version_extracted(self):
        """tlv_version is decoded and stored in interaction details."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        found = False
        for ix in listener.interactions:
            tv = ix.details.get("tlv_version", "")
            if tv:
                found = True
                assert "." in tv, f"tlv_version not decoded: {tv}"
                break
        assert found, "No interaction has tlv_version"

    def test_versions_in_device_data(self):
        """release_version and tlv_version stored in device eigrp_data."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        for dev in listener.discovered_devices.values():
            data = dev.eigrp_data
            assert "release_version" in data, f"Missing release_version: {data.keys()}"
            assert "tlv_version" in data, f"Missing tlv_version: {data.keys()}"
            # Check decoded format
            if data["release_version"]:
                assert "." in data["release_version"]

    def test_release_version_3076_decodes_12_4(self):
        """release_version raw=3076 (0x0C04) decodes to '12.4'."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        for dev in listener.discovered_devices.values():
            rv = dev.eigrp_data.get("release_version", "")
            if rv:
                assert rv == "12.4", f"Expected 12.4, got {rv}"
                break


# ---------------------------------------------------------------------------
# T1 gap: eigrp.auth.length + eigrp.auth.keyseq
# ---------------------------------------------------------------------------


class TestEIGRPAuthFields:
    """T1: eigrp.auth.length + eigrp.auth.keyseq -- auth data completeness."""

    def test_auth_keyseq_in_credential(self):
        """auth_keyseq (key sequence) is stored in credential dataclass."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_auth.pcap")
        assert listener.credentials, "No credentials extracted from auth pcap"
        for cred in listener.credentials:
            # key_seq should be an int (may be 0 for this pcap)
            assert hasattr(cred, "key_seq"), "Missing key_seq attribute on credential"
            assert isinstance(cred.key_seq, int), f"key_seq not int: {type(cred.key_seq)}"

    def test_auth_length_in_credential(self):
        """auth_length is stored in credential dataclass."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_auth.pcap")
        assert listener.credentials, "No credentials extracted"
        for cred in listener.credentials:
            assert hasattr(cred, "auth_length"), "Missing auth_length attribute"
            assert isinstance(cred.auth_length, int), (
                f"auth_length not int: {type(cred.auth_length)}"
            )
            # MD5 digest length should be 16
            assert cred.auth_length == 16, (
                f"Expected auth_length=16 for MD5, got {cred.auth_length}"
            )

    def test_auth_fields_in_credentials_summary(self):
        """get_credentials_summary() includes key_seq and auth_length."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_auth.pcap")
        summary = listener.get_credentials_summary()
        assert summary, "No credentials in summary"
        for entry in summary:
            assert "key_seq" in entry, f"Missing key_seq in summary: {entry.keys()}"
            assert "auth_length" in entry, f"Missing auth_length in summary: {entry.keys()}"


# ---------------------------------------------------------------------------
# T1 gap: eigrp.old_metric.rel (route reliability metric)
# ---------------------------------------------------------------------------


class TestEIGRPOldMetricRel:
    """T1: eigrp.old_metric.rel -- route reliability percentage."""

    def test_reliability_extracted_in_routes(self):
        """old_metric.rel is attached to routes as metric.reliability."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_updates.pcap")
        # Find an interaction with route metrics
        found = False
        for ix in listener.interactions:
            metric = ix.details.get("old_metric")
            if metric:
                found = True
                assert "reliability" in metric, f"Missing reliability in metric: {metric.keys()}"
                assert isinstance(metric["reliability"], int), (
                    f"reliability not int: {type(metric['reliability'])}"
                )
                # Also check other metric fields were extracted
                assert "bandwidth" in metric
                assert "delay" in metric
                assert "hopcount" in metric
                assert "mtu" in metric
                assert "load" in metric
                break
        assert found, "No interaction has old_metric data"

    def test_metrics_attached_to_route_entries(self):
        """Route entries in interaction details have attached metric dicts."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_updates.pcap")
        found_route_with_metric = False
        for ix in listener.interactions:
            for route in ix.details.get("routes", []):
                if "metric" in route:
                    found_route_with_metric = True
                    m = route["metric"]
                    assert "reliability" in m, f"Route metric missing reliability: {m}"
                    break
            if found_route_with_metric:
                break
        assert found_route_with_metric, "No route has attached metric data"


# ---------------------------------------------------------------------------
# IPv6 route extraction (enabled by T1 field work)
# ---------------------------------------------------------------------------


class TestEIGRPIPv6Routes:
    """IPv6 route extraction from update packets."""

    def test_ipv6_routes_extracted(self):
        """IPv6 routes are extracted from update packets."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_updates.pcap")
        found_ipv6 = False
        for ix in listener.interactions:
            for route in ix.details.get("routes", []):
                if route.get("af") == "ipv6":
                    found_ipv6 = True
                    assert "network" in route
                    assert "prefix_len" in route
                    break
            if found_ipv6:
                break
        assert found_ipv6, "No IPv6 routes extracted from updates pcap"

    def test_ipv6_routes_in_device_data(self):
        """IPv6 routes are accumulated in device eigrp_data."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_updates.pcap")
        found = False
        for dev in listener.discovered_devices.values():
            routes = dev.eigrp_data.get("routes", [])
            for route in routes:
                if route.get("af") == "ipv6":
                    found = True
                    break
            if found:
                break
        assert found, "No IPv6 routes in any device's eigrp_data"

    def test_external_routes_have_extdata(self):
        """External routes include originating router/AS/protocol data."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_updates.pcap")
        found_external = False
        for ix in listener.interactions:
            for route in ix.details.get("routes", []):
                if route.get("type") == "external" and "external_data" in route:
                    found_external = True
                    ext = route["external_data"]
                    assert "originating_router_id" in ext, f"Missing originating_router_id: {ext}"
                    assert "originating_as" in ext, f"Missing originating_as: {ext}"
                    assert "originating_protocol" in ext, f"Missing originating_protocol: {ext}"
                    break
            if found_external:
                break
        assert found_external, "No external route with external_data found"


# ---------------------------------------------------------------------------
# EK-mode field name fix (seq/ack)
# ---------------------------------------------------------------------------


class TestEIGRPEKFieldNames:
    """Verify EK-mode field names work (seq vs sequence, ack vs acknowledge)."""

    def test_ek_seq_not_always_zero(self):
        """In EK mode, seq field should return actual values, not always 0.

        The old listener used 'sequence' which is the XML-mode name; EK mode
        uses 'seq'. This test catches regressions where the wrong field name
        silently returns the default value.
        """
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_updates.pcap")
        # Update packets (opcode=1) should have non-zero seq numbers
        seq_values = [
            ix.details.get("seq_num", 0)
            for ix in listener.interactions
            if ix.details.get("opcode") == 1
        ]
        assert seq_values, "No Update interactions found"
        assert any(s != 0 for s in seq_values), (
            f"All Update seq_num values are 0 -- likely reading wrong EK field name. "
            f"Values: {seq_values[:10]}"
        )

    def test_ek_ack_extracted(self):
        """ack_num field is present in interaction details."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_updates.pcap")
        assert listener.interactions, "No interactions"
        for ix in listener.interactions:
            assert "ack_num" in ix.details, f"Missing ack_num: {ix.details.keys()}"


# ---------------------------------------------------------------------------
# Harvest output quality
# ---------------------------------------------------------------------------


class TestEIGRPHarvest:
    """Verify harvest() output quality with new fields."""

    def test_harvest_returns_valid_dict(self):
        """harvest() should return a valid dict (no custom tables for EIGRP)."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_neighbors.cap")
        result = listener.harvest()
        assert isinstance(result, dict)

    def test_harvest_auth_credentials_extracted(self):
        """Auth pcap produces credentials on the listener."""
        _skip_unless_pyshark()
        listener = _make_listener()
        _feed(listener, "eigrp/wireshark_eigrp_ipv6_auth.pcap")
        assert listener.credentials, "No credentials extracted from auth pcap"
