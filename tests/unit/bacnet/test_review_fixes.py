"""
Regression tests for CODE_REVIEW MEDIUM findings in nxc_connection.py:

[1] --monitor/--diff are dead in the default (bacpypes3) path -> must fail()
    loudly instead of silently doing nothing.
[2] Network-layer recon must still run when device discovery fails
    (device_id is None) -- the early return was short-circuiting it.
[4] The --use-bac0 path must call enum_host_info() so results["data"] is
    populated, mirroring the raw path.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from oida.protocols.bacnet import bacnet
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _create_instance(**kwargs):
    instance = object.__new__(bacnet)
    instance.args = create_mock_args(**kwargs)
    instance.logger = create_mock_logger()
    instance.results = {"data": {}}
    instance.host = "192.168.1.100"
    instance.devices = {}
    instance.objects = {}
    instance.remote_networks = []
    return instance


def _patch_app_and_types():
    return {
        "DeviceObject": Mock(return_value=Mock()),
        "DeviceStatus": Mock(operational=Mock()),
        "NormalApplication": Mock(return_value=Mock(close=Mock())),
        "Address": Mock(side_effect=lambda s: Mock()),
    }


# --- Finding [1]: --monitor / --diff dead in default path ------------------


class TestMonitorDiffRequireBac0(unittest.TestCase):
    def _run_proto_flow(self, **kwargs):
        scanner = _create_instance(**kwargs)
        scanner._raw_scan = Mock()
        scanner._apply_shortcuts = Mock()
        with (
            patch(
                "oida.protocols.bacnet.nxc_connection._load_bacpypes3",
                return_value=_patch_app_and_types(),
            ),
            patch(
                "oida.protocols.bacnet.nxc_connection._is_bac0_available",
                return_value=False,
            ),
        ):
            scanner.proto_flow()
        return scanner

    def test_monitor_fails_loudly_without_bac0(self):
        scanner = self._run_proto_flow(monitor=True)
        fail_msgs = " ".join(str(c) for c in scanner.logger.fail.call_args_list)
        self.assertIn("--monitor", fail_msgs)
        self.assertIn("--use-bac0", fail_msgs)
        # Raw scan still runs (we only warn about the dead flag).
        scanner._raw_scan.assert_called_once()

    def test_diff_fails_loudly_without_bac0(self):
        scanner = self._run_proto_flow(diff="baseline.json")
        fail_msgs = " ".join(str(c) for c in scanner.logger.fail.call_args_list)
        self.assertIn("--diff", fail_msgs)
        self.assertIn("--use-bac0", fail_msgs)

    def test_no_fail_when_flags_absent(self):
        scanner = self._run_proto_flow()
        self.assertEqual(scanner.logger.fail.call_args_list, [])


# --- Finding [2]: recon must run when device discovery fails ----------------


class TestReconRunsWhenDiscoveryFails(unittest.TestCase):
    RECON_METHODS = [
        "_bacpypes3_enum_bbmd",
        "_bacpypes3_enum_fdt",
        "_bacpypes3_enum_routers",
        "_bacpypes3_who_has",
        "_bacpypes3_discover_networks",
    ]

    def _run(self):
        # device_id None AND discovery returns None -> the old code returned
        # early, skipping recon entirely.
        scanner = _create_instance(
            device_id=None,
            enum_bbmd=True,
            enum_fdt=True,
            enum_routers=True,
            who_has="AnyObj",
            networks=True,
        )
        recon = {name: AsyncMock() for name in self.RECON_METHODS}
        for name, mock in recon.items():
            setattr(scanner, name, mock)

        scanner._bacpypes3_discover_device = AsyncMock(return_value=None)
        scanner._bacpypes3_read_properties = AsyncMock(return_value={})

        with (
            patch(
                "oida.protocols.bacnet.nxc_connection._load_bacpypes3",
                return_value=_patch_app_and_types(),
            ),
            patch(
                "oida.utils.socket_helpers.get_local_ip",
                return_value=("192.168.1.10", None),
            ),
        ):
            asyncio.run(scanner._async_raw_scan())
        return scanner, recon

    def test_recon_runs_despite_discovery_failure(self):
        scanner, recon = self._run()
        for name, mock in recon.items():
            self.assertTrue(
                mock.called,
                f"{name} must run even when device discovery fails (device_id None)",
            )

    def test_property_read_not_attempted_without_device_id(self):
        scanner, recon = self._run()
        # No device_id -> never call the application-layer property read.
        scanner._bacpypes3_read_properties.assert_not_called()


# --- Finding [4]: --use-bac0 path populates results["data"] -----------------


class TestBac0PathPopulatesResults(unittest.TestCase):
    def test_async_proto_flow_calls_enum_host_info(self):
        scanner = _create_instance()
        scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100:47808"}}

        scanner._async_create_conn_obj = AsyncMock(return_value=True)
        scanner._async_handle_who_is = AsyncMock()
        scanner._disconnect = Mock()
        scanner._export_results = Mock()

        asyncio.run(scanner._async_proto_flow())

        # enum_host_info() should have populated the structured result surface.
        self.assertIn("device_info", scanner.results["data"])
        self.assertEqual(scanner.results["data"]["device_info"]["device_count"], 1)
        scanner._export_results.assert_called_once()


if __name__ == "__main__":
    unittest.main()
