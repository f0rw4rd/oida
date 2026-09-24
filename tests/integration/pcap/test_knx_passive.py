"""Integration tests for KNX passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestKNXPassiveEK:
    """KNX-specific tests beyond the parametrized quality suite."""

    def test_knx_sessions_and_services(self):
        listener, devices, result = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )
        # KNX should track sessions between clients and gateways
        assert len(listener.sessions) >= 1, (
            f"Expected >= 1 KNX session, got {len(listener.sessions)}"
        )

        # Check that knx_passive_data is populated on at least one device
        has_passive_data = any(
            hasattr(d, "knx_passive_data") and d.knx_passive_data for d in devices.values()
        )
        assert has_passive_data, "No device has knx_passive_data"

        # KNX has no custom harvest tables (interaction/credential tables
        # are now built centrally by the scanner)


class TestKNXVersion:
    """knxip.version -- KNXnet/IP protocol version field extraction."""

    def test_version_in_interaction_details(self):
        """Every interaction should have a 'version' in its details dict."""
        listener, _, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )

        assert listener.interactions, "No interactions recorded"

        with_version = [ix for ix in listener.interactions if ix.details.get("version")]
        assert with_version, (
            f"No interaction has details['version']; "
            f"sample details: {listener.interactions[0].details}"
        )

    def test_version_value_is_decoded(self):
        """Version should be decoded as 'major.minor' string (e.g. '1.0')."""
        listener, _, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )

        versions = {
            ix.details["version"] for ix in listener.interactions if ix.details.get("version")
        }
        assert versions, "No version values found"

        for v in versions:
            # Must be in "X.Y" format
            parts = v.split(".")
            assert len(parts) == 2, f"Version {v!r} not in 'major.minor' format"
            assert parts[0].isdigit(), f"Version major {parts[0]!r} not numeric"
            assert parts[1].isdigit(), f"Version minor {parts[1]!r} not numeric"

        # ndpi_knxip.pcapng has version 0x10 = 1.0
        assert "1.0" in versions, f"Expected version '1.0', got {versions}"

    def test_version_in_device_passive_data(self):
        """At least one device should have protocol_version in passive data."""
        _, devices, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )

        devices_with_version = [
            d
            for d in devices.values()
            if hasattr(d, "knx_passive_data")
            and d.knx_passive_data
            and d.knx_passive_data.get("protocol_version")
        ]
        assert devices_with_version, "No device has protocol_version in knx_passive_data"
        assert devices_with_version[0].knx_passive_data["protocol_version"] == "1.0"


class TestKNXService:
    """knxip.service -- KNXnet/IP service type field extraction."""

    def test_service_type_in_interaction_details(self):
        """Every interaction should have service_type in its details."""
        listener, _, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )

        assert listener.interactions, "No interactions recorded"

        with_service = [
            ix for ix in listener.interactions if ix.details.get("service_type") is not None
        ]
        assert len(with_service) == len(listener.interactions), (
            f"Only {len(with_service)}/{len(listener.interactions)} interactions have service_type"
        )

    def test_service_name_resolved(self):
        """service_name should be human-readable, not raw hex."""
        listener, _, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )

        service_names = {
            ix.details.get("service_name")
            for ix in listener.interactions
            if ix.details.get("service_name")
        }
        assert service_names, "No service names found"

        # ndpi_knxip.pcapng contains search requests (0x0201, 0x020B)
        known_services = {
            "SEARCH_REQUEST",
            "SEARCH_REQUEST_EXT",
            "TUNNELING_FEATURE_GET",
            "TUNNELING_FEATURE_SET",
            "TUNNELING_FEATURE_RESP",
            "TUNNELING_FEATURE_INFO",
        }
        found = service_names & known_services
        assert found, (
            f"Expected at least one known service name from {known_services}, got {service_names}"
        )

    def test_service_type_is_integer(self):
        """service_type should be parsed as integer, not raw string."""
        listener, _, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )

        for ix in listener.interactions:
            st = ix.details.get("service_type")
            assert isinstance(st, int), (
                f"service_type should be int, got {type(st).__name__}: {st!r}"
            )


class TestKNXServiceFamily:
    """knxip.service.family -- KNXnet/IP service family byte extraction."""

    def test_service_family_in_interaction_details(self):
        """Interactions should have service_family in their details."""
        listener, _, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )

        assert listener.interactions, "No interactions recorded"

        with_family = [
            ix for ix in listener.interactions if ix.details.get("service_family") is not None
        ]
        assert with_family, (
            f"No interaction has service_family; sample details: {listener.interactions[0].details}"
        )

    def test_service_family_is_integer(self):
        """service_family should be parsed as integer."""
        listener, _, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )

        for ix in listener.interactions:
            sf = ix.details.get("service_family")
            if sf is not None:
                assert isinstance(sf, int), (
                    f"service_family should be int, got {type(sf).__name__}: {sf!r}"
                )

    def test_service_family_tracked_in_session(self):
        """Sessions should accumulate service_families seen."""
        listener, _, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )

        assert listener.sessions, "No sessions recorded"

        has_families = any(session.service_families for session in listener.sessions.values())
        assert has_families, "No session has service_families populated"

    def test_service_families_in_device_passive_data(self):
        """Device passive data should include service_families list."""
        _, devices, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )

        devices_with_families = [
            d
            for d in devices.values()
            if hasattr(d, "knx_passive_data")
            and d.knx_passive_data
            and d.knx_passive_data.get("service_families")
        ]
        assert devices_with_families, "No device has service_families in knx_passive_data"
        families = devices_with_families[0].knx_passive_data["service_families"]
        assert isinstance(families, list), f"Expected list, got {type(families)}"
        assert len(families) >= 1, "Expected at least 1 service family"


class TestKNXSecureServices:
    """KNX Secure detection across different pcap fixtures."""

    def test_secure_wrapper_pcap(self):
        """SecureWrapper pcap should flag secure_seen on session."""
        listener, _, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/knxip_SecureWrapper.pcap",
            min_devices=0,
            min_interactions=1,
        )

        secure_sessions = [s for s in listener.sessions.values() if s.secure_seen]
        assert secure_sessions, "SecureWrapper traffic should set secure_seen=True"

    def test_timer_notify_pcap(self):
        """TimerNotify pcap should flag secure_seen on session."""
        listener, _, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/knxip_TimerNotify.pcap",
            min_devices=0,
            min_interactions=1,
        )

        secure_sessions = [s for s in listener.sessions.values() if s.secure_seen]
        assert secure_sessions, "TimerNotify traffic should set secure_seen=True"


class TestKNXDataSec:
    """DataSec pcap should extract tunneling fields."""

    def test_datasec_version_and_service(self):
        """DataSec pcap should have version and service fields extracted."""
        listener, _, _ = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/knxip_DataSec.pcap",
            min_devices=0,
            min_interactions=1,
        )

        assert listener.interactions, "No interactions from DataSec pcap"

        ix = listener.interactions[0]
        assert ix.details.get("version"), (
            f"DataSec interaction missing version; details: {ix.details}"
        )
        assert ix.details.get("service_type") is not None, (
            f"DataSec interaction missing service_type; details: {ix.details}"
        )
        assert ix.details.get("service_family") is not None, (
            f"DataSec interaction missing service_family; details: {ix.details}"
        )


class TestKNXHarvestOutput:
    """Verify harvest() output structure -- KNX has no custom tables."""

    def test_harvest_returns_valid_dict(self):
        """Harvest should return a valid dict (no custom tables for KNX)."""
        _, _, result = _run_listener_test(
            "knx",
            "KNXPassiveListener",
            "kip",
            "knx/ndpi_knxip.pcapng",
        )

        assert isinstance(result, dict)
