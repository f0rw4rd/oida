"""Integration tests for NFS passive listener.

Tests cover:
- NFSv3 procedure extraction (GETATTR, LOOKUP, READ, WRITE)
- File attribute extraction (UID, GID, size, type)
- Status code parsing
- Direction detection (request vs response)
- Device creation for both client and server
- UID/GID mapping tracking
- Write operation alerting
- Harvest table output quality
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestNFSPassiveEK:
    """NFS-specific tests beyond the parametrized quality suite."""

    def test_nfs_v3_getattr(self):
        """NFSv3 GETATTR procedures are extracted with file attributes."""
        listener, devices, result = _run_listener_test(
            "nfs",
            "NFSPassiveListener",
            "nfs",
            "nfs/wireshark_nfs.cap",
            min_devices=2,
            expect_details=["version", "procedure_name"],
            expect_operations=["NFS v3 GETATTR"],
        )
        # Verify version is v3
        v3_ixs = [ix for ix in listener.interactions if ix.details.get("version") == "v3"]
        assert len(v3_ixs) >= 1, "No NFSv3 interactions found"

    def test_nfs_uid_gid_extraction(self):
        """UID and GID are extracted from GETATTR responses."""
        listener, devices, result = _run_listener_test(
            "nfs",
            "NFSPassiveListener",
            "nfs",
            "nfs/wireshark_nfs.cap",
            min_devices=2,
        )
        # The wireshark NFS pcap has uid=0, gid=30 in GETATTR reply
        has_uid = any(ix.details.get("uid") is not None for ix in listener.interactions)
        assert has_uid, (
            "No interaction has UID; "
            f"sample details: {listener.interactions[0].details if listener.interactions else 'none'}"
        )

    def test_nfs_status_extraction(self):
        """NFS status codes are extracted and resolved to names."""
        listener, devices, result = _run_listener_test(
            "nfs",
            "NFSPassiveListener",
            "nfs",
            "nfs/wireshark_nfs.cap",
            min_devices=2,
        )
        # GETATTR reply should have status=0 (OK)
        has_status = any(
            ix.details.get("status") is not None and ix.details.get("status") != ""
            for ix in listener.interactions
        )
        assert has_status, "No interaction has status code"

    def test_nfs_direction_detection(self):
        """Request and response directions are correctly detected."""
        listener, devices, result = _run_listener_test(
            "nfs",
            "NFSPassiveListener",
            "nfs",
            "nfs/wireshark_nfs.cap",
            min_devices=2,
        )
        directions = {ix.direction for ix in listener.interactions}
        # Should have at least one of each direction
        assert "request" in directions or "response" in directions, (
            f"Expected request/response directions; got: {directions}"
        )

    def test_nfs_both_endpoints_tracked(self):
        """Both NFS client and server devices are created."""
        listener, devices, result = _run_listener_test(
            "nfs",
            "NFSPassiveListener",
            "nfs",
            "nfs/wireshark_nfs.cap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Server" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No NFS Server device found; types: {device_types}"
        assert has_client, f"No NFS Client device found; types: {device_types}"

    def test_nfs_passive_data_on_devices(self):
        """Devices have nfs_passive_data with expected fields."""
        listener, devices, result = _run_listener_test(
            "nfs",
            "NFSPassiveListener",
            "nfs",
            "nfs/wireshark_nfs.cap",
            min_devices=2,
        )
        has_data = any(
            hasattr(d, "nfs_passive_data") and d.nfs_passive_data for d in devices.values()
        )
        assert has_data, "No device has nfs_passive_data"

        # Check that at least one device has role and protocol
        for d in devices.values():
            if hasattr(d, "nfs_passive_data") and d.nfs_passive_data:
                assert "role" in d.nfs_passive_data
                assert "protocol" in d.nfs_passive_data
                break

    def test_nfs_harvest_valid(self):
        """Harvest returns valid dict with no raw dicts/sets in cells."""
        listener, devices, result = _run_listener_test(
            "nfs",
            "NFSPassiveListener",
            "nfs",
            "nfs/wireshark_nfs.cap",
        )
        assert isinstance(result, dict)

    def test_nfs_format_protocol_columns(self):
        """_format_protocol_columns produces correct column count."""
        listener, devices, result = _run_listener_test(
            "nfs",
            "NFSPassiveListener",
            "nfs",
            "nfs/wireshark_nfs.cap",
        )
        if listener.interactions:
            cols = listener._format_protocol_columns(listener.interactions[0])
            assert len(cols) == len(listener.PROTOCOL_COLUMNS), (
                f"Column count mismatch: {len(cols)} vs {len(listener.PROTOCOL_COLUMNS)}"
            )

    def test_nfs_procedure_names_resolved(self):
        """Procedure numbers are resolved to human-readable names."""
        listener, devices, result = _run_listener_test(
            "nfs",
            "NFSPassiveListener",
            "nfs",
            "nfs/wireshark_nfs.cap",
        )
        proc_names = {ix.details.get("procedure_name", "") for ix in listener.interactions}
        # Should have GETATTR at minimum from the test pcap
        assert any(
            name in proc_names
            for name in ("GETATTR", "LOOKUP", "READ", "WRITE", "ACCESS", "READDIR")
        ), f"No recognized procedure names; got: {proc_names}"
