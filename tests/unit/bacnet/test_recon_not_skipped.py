"""
Regression for CODE_REVIEW finding nxc_connection.py:304-476 —
BBMD/FDT/router/network recon must NOT be silently skipped when the
application-layer device-property read fails (returns empty or raises).

The network-layer recon (enum_bbmd/enum_fdt/enum_routers/who_has/networks/
test_bbmd_injection) operates at the BVLL / network layer and is independent
of being able to read the device object's properties.
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
    """Patch the bacpypes3 surface used by _async_raw_scan setup."""
    types = {
        "DeviceObject": Mock(return_value=Mock()),
        "DeviceStatus": Mock(operational=Mock()),
        "NormalApplication": Mock(return_value=Mock(close=Mock())),
        "Address": Mock(side_effect=lambda s: Mock()),
    }
    return types


class _ReconHarness:
    """Run _async_raw_scan with device discovery short-circuited and the
    recon mixin methods replaced by AsyncMocks so we can assert dispatch.
    """

    RECON_METHODS = [
        "_bacpypes3_enum_bbmd",
        "_bacpypes3_enum_fdt",
        "_bacpypes3_enum_routers",
        "_bacpypes3_who_has",
        "_bacpypes3_discover_networks",
    ]

    def __init__(self, properties_behavior, **args):
        self.args = args
        self.properties_behavior = properties_behavior

    def run(self):
        scanner = _create_instance(
            device_id=1001,
            enum_bbmd=True,
            enum_fdt=True,
            enum_routers=True,
            who_has="AnyObj",
            networks=True,
            **self.args,
        )

        # Replace recon methods with AsyncMocks.
        recon = {name: AsyncMock() for name in self.RECON_METHODS}
        for name, mock in recon.items():
            setattr(scanner, name, mock)

        # _bacpypes3_read_properties is the failing application-layer read.
        if self.properties_behavior == "empty":
            scanner._bacpypes3_read_properties = AsyncMock(return_value={})
        elif self.properties_behavior == "raise":
            scanner._bacpypes3_read_properties = AsyncMock(
                side_effect=RuntimeError("device aborted ReadProperty")
            )
        else:
            scanner._bacpypes3_read_properties = AsyncMock(return_value={"vendor_name": "ACME"})

        types = _patch_app_and_types()
        with (
            patch(
                "oida.protocols.bacnet.nxc_connection._load_bacpypes3",
                return_value=types,
            ),
            patch(
                "oida.utils.socket_helpers.get_local_ip",
                return_value=("192.168.1.10", None),
            ),
        ):
            asyncio.run(scanner._async_raw_scan())

        return scanner, recon


class TestReconNotSkipped(unittest.TestCase):
    def test_empty_properties_still_runs_recon(self):
        scanner, recon = _ReconHarness("empty").run()
        for name, mock in recon.items():
            self.assertTrue(mock.called, f"{name} must still run when property read returns empty")
        # Operator must be told why properties were unavailable.
        warn_msgs = " ".join(str(c) for c in scanner.logger.warning.call_args_list)
        self.assertIn("propert", warn_msgs.lower())

    def test_property_read_exception_does_not_skip_recon(self):
        scanner, recon = _ReconHarness("raise").run()
        for name, mock in recon.items():
            self.assertTrue(mock.called, f"{name} must still run when property read raises")
        warn_msgs = " ".join(str(c) for c in scanner.logger.warning.call_args_list)
        self.assertIn("propert", warn_msgs.lower())

    def test_recon_runs_in_normal_path_too(self):
        scanner, recon = _ReconHarness("ok").run()
        for name, mock in recon.items():
            self.assertTrue(mock.called, f"{name} must run in the normal path")


if __name__ == "__main__":
    unittest.main()
