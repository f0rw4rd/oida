"""Integration tests for Rsync passive listener.

Tests cover:
- Protocol version handshake (@RSYNCD: greeting)
- Module name extraction from client queries
- Module list parsing from server responses
- Command argument extraction
- Server version tracking
- Device creation for both client and server
- Harvest output quality
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

# Rsync requires decode_as to be recognized by tshark
RSYNC_DECODE_AS = {"tcp.port==873": "rsync"}


class TestRsyncPassive:
    """Rsync protocol-specific tests."""

    def test_version_handshake(self):
        """@RSYNCD version handshake packets are parsed."""
        listener, devices, result = _run_listener_test(
            "rsync",
            "RsyncPassiveListener",
            "rsync",
            "rsync/generated_rsync.pcap",
            min_devices=2,
            min_interactions=3,
            expect_details=["version"],
            expect_operations=["Rsync Version"],
            decode_as=RSYNC_DECODE_AS,
        )

        # Check version is extracted
        versions = {
            ix.details.get("version") for ix in listener.interactions if ix.details.get("version")
        }
        assert "31.0" in versions, f"Expected version 31.0; got: {versions}"

    def test_server_version_tracking(self):
        """Server protocol version is tracked."""
        listener, devices, result = _run_listener_test(
            "rsync",
            "RsyncPassiveListener",
            "rsync",
            "rsync/generated_rsync.pcap",
            decode_as=RSYNC_DECODE_AS,
        )

        assert len(listener.server_versions) >= 1, "No server versions tracked"

    def test_module_query_extraction(self):
        """Client module queries are extracted."""
        listener, devices, result = _run_listener_test(
            "rsync",
            "RsyncPassiveListener",
            "rsync",
            "rsync/generated_rsync.pcap",
            decode_as=RSYNC_DECODE_AS,
        )

        # Check for module access or list requests
        query_ixs = [
            ix
            for ix in listener.interactions
            if ix.details.get("operation_type") in ("Module Access", "Module List Request")
        ]
        assert len(query_ixs) >= 1, (
            "No module query interactions found; operations: "
            f"{[ix.details.get('operation_type') for ix in listener.interactions]}"
        )

    def test_module_names_extracted(self):
        """Module names are extracted from queries and listings."""
        listener, devices, result = _run_listener_test(
            "rsync",
            "RsyncPassiveListener",
            "rsync",
            "rsync/generated_rsync.pcap",
            decode_as=RSYNC_DECODE_AS,
        )

        all_modules = set()
        for modules in listener.modules.values():
            all_modules.update(modules)

        assert "backups" in all_modules, f"Expected 'backups' module; got: {all_modules}"

    def test_module_list_from_server(self):
        """Module list responses from server are parsed."""
        listener, devices, result = _run_listener_test(
            "rsync",
            "RsyncPassiveListener",
            "rsync",
            "rsync/generated_rsync.pcap",
            decode_as=RSYNC_DECODE_AS,
        )

        # Check for module list interactions
        list_ixs = [
            ix for ix in listener.interactions if ix.details.get("operation_type") == "Module List"
        ]
        assert len(list_ixs) >= 1, (
            "No module list interactions found; operations: "
            f"{[ix.details.get('operation_type') for ix in listener.interactions]}"
        )

        # The module list should contain our test modules
        modules_in_list = set()
        for ix in list_ixs:
            for m in ix.details.get("modules", []):
                modules_in_list.add(m)
        assert "backups" in modules_in_list, (
            f"Expected 'backups' in module list; got: {modules_in_list}"
        )

    def test_command_extraction(self):
        """Rsync command arguments are extracted."""
        listener, devices, result = _run_listener_test(
            "rsync",
            "RsyncPassiveListener",
            "rsync",
            "rsync/generated_rsync.pcap",
            decode_as=RSYNC_DECODE_AS,
        )

        cmd_ixs = [
            ix for ix in listener.interactions if ix.details.get("operation_type") == "Command"
        ]
        assert len(cmd_ixs) >= 1, "No command interactions found"
        # Verify command contains rsync arguments
        cmd = cmd_ixs[0].details.get("command", "")
        assert "--server" in cmd, f"Expected --server in command; got: {cmd}"

    def test_both_endpoints_tracked(self):
        """Both rsync client and server devices are discovered."""
        listener, devices, result = _run_listener_test(
            "rsync",
            "RsyncPassiveListener",
            "rsync",
            "rsync/generated_rsync.pcap",
            min_devices=2,
            decode_as=RSYNC_DECODE_AS,
        )

        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Server" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No Rsync Server device; types: {device_types}"
        assert has_client, f"No Rsync Client device; types: {device_types}"

    def test_server_modules_on_device(self):
        """Server device has module list in passive data."""
        listener, devices, result = _run_listener_test(
            "rsync",
            "RsyncPassiveListener",
            "rsync",
            "rsync/generated_rsync.pcap",
            min_devices=2,
            decode_as=RSYNC_DECODE_AS,
        )

        server_devs = [
            d
            for d in devices.values()
            if hasattr(d, "rsync_passive_data")
            and d.rsync_passive_data
            and d.rsync_passive_data.get("role") == "server"
        ]
        assert len(server_devs) >= 1, "No rsync server device with passive data"
        modules = server_devs[0].rsync_passive_data.get("modules", [])
        assert len(modules) >= 1, (
            f"No modules on server device; data: {server_devs[0].rsync_passive_data}"
        )

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict."""
        listener, devices, result = _run_listener_test(
            "rsync",
            "RsyncPassiveListener",
            "rsync",
            "rsync/generated_rsync.pcap",
            decode_as=RSYNC_DECODE_AS,
        )
        assert isinstance(result, dict)

    def test_protocol_columns_format(self):
        """Protocol columns are formatted correctly."""
        listener, devices, result = _run_listener_test(
            "rsync",
            "RsyncPassiveListener",
            "rsync",
            "rsync/generated_rsync.pcap",
            decode_as=RSYNC_DECODE_AS,
        )

        for ix in listener.interactions:
            cols = listener._format_protocol_columns(ix)
            assert len(cols) == len(listener.PROTOCOL_COLUMNS), (
                f"Column count mismatch: {len(cols)} vs {len(listener.PROTOCOL_COLUMNS)}"
            )
