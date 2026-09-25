"""Unit tests for the async/network reconnaissance methods of NetworkMixin.

Covers the parts of network.py that the existing test_network_mixin.py and
test_mstp_discovery.py skip: Who-Has, BBMD/FDT/router enumeration, remote
network discovery + scan, BBMD injection (with the Category.ACCESS_CONTROL
Writable-access finding on a BDT-write accept), and the synchronous
_mstp_report_security summary/findings generator.

External I/O only is mocked: the bacpypes3 type catalog and app.request. The
mixin branching, the bvlciResultCode interpretation, and the MS/TP security
heuristics run for real.
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
    instance.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}
    instance.objects = {}
    instance.bacnet = Mock()
    return instance


def _error_classes():
    return {
        "AbortPDU": type("AbortPDU", (), {}),
        "ErrorPDU": type("ErrorPDU", (), {}),
        "ErrorRejectAbortNack": type("ErrorRejectAbortNack", (BaseException,), {}),
        "RejectPDU": type("RejectPDU", (), {}),
        "Error": type("Error", (), {}),
    }


def _net_types():
    t = _error_classes()
    for name in (
        "WhoHasRequest",
        "WhoHasObject",
        "CharacterString",
        "ReadBroadcastDistributionTable",
        "ReadForeignDeviceTable",
        "WhoIsRouterToNetwork",
        "ReadPropertyRequest",
        "ObjectIdentifier",
        "PropertyIdentifier",
        "WhoIsRequest",
        "GlobalBroadcast",
        "RegisterForeignDevice",
        "WriteBroadcastDistributionTable",
        "Address",
    ):
        t[name] = Mock(return_value=Mock())
    return t


def _ack():
    return Mock(spec=[])


def _bvll(code):
    """A BVLL result response carrying a bvlciResultCode."""
    r = Mock(spec=["bvlciResultCode"])
    r.bvlciResultCode = code
    return r


def _uint_tag_response(value):
    """ReadProperty response whose first tag decodes to an unsigned int."""
    tag = Mock()
    tag.tag_data = value.to_bytes(2, "big")
    pv = Mock()
    pv.tagList = [tag]
    resp = Mock(spec=["propertyValue"])
    resp.propertyValue = pv
    return resp


def _str_tag_response(text):
    """ReadProperty response whose first tag decodes to a UTF-8 string."""
    tag = Mock()
    tag.tag_data = text.encode("utf-8")
    pv = Mock()
    pv.tagList = [tag]
    resp = Mock(spec=["propertyValue"])
    resp.propertyValue = pv
    return resp


# ---------------------------------------------------------------------------
# Who-Has
# ---------------------------------------------------------------------------
class TestWhoHas(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_object_found(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        resp = Mock(spec=["deviceIdentifier", "objectIdentifier"])
        resp.deviceIdentifier = ("device", 1001)
        resp.objectIdentifier = ("analogValue", 1)
        app.request = AsyncMock(return_value=resp)

        asyncio.run(scanner._bacpypes3_who_has(app, Mock(), "ZoneTemp", 2.0))

        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("ZoneTemp", succ)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_object_not_found_on_error(self, mock_load):
        types = _net_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())

        asyncio.run(scanner._bacpypes3_who_has(app, Mock(), "Missing", 2.0))

        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("not found", out)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_timeout_reports_no_response(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_who_has(app, Mock(), "X", 2.0))
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("timeout", out.lower())


# ---------------------------------------------------------------------------
# BBMD / FDT / Router enumeration
# ---------------------------------------------------------------------------
class TestEnumTables(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_bbmd_table_readable(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_ack())
        asyncio.run(scanner._bacpypes3_enum_bbmd(app, Mock(), 2.0))
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("BBMD Table readable", succ)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_bbmd_timeout(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())
        asyncio.run(scanner._bacpypes3_enum_bbmd(app, Mock(), 2.0))
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("No BBMD response", out)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_fdt_readable_warns_registration(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_ack())
        asyncio.run(scanner._bacpypes3_enum_fdt(app, Mock(), 2.0))
        warn = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("rogue device registration", warn)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_routers_found(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_ack())
        asyncio.run(scanner._bacpypes3_enum_routers(app, Mock(), 2.0))
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("Router(s) found", succ)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_bbmd_not_enabled_when_falsy(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=None)  # falsy -> not enabled
        asyncio.run(scanner._bacpypes3_enum_bbmd(app, Mock(), 2.0))
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("BBMD not enabled", out)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_fdt_not_accessible_when_falsy(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=None)
        asyncio.run(scanner._bacpypes3_enum_fdt(app, Mock(), 2.0))
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("FDT not accessible", out)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_routers_none_responding(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=None)
        asyncio.run(scanner._bacpypes3_enum_routers(app, Mock(), 2.0))
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("No routers found", out)


# ---------------------------------------------------------------------------
# Remote network discovery / scan
# ---------------------------------------------------------------------------
class TestDiscoverNetworks(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_no_network_ports(self, mock_load):
        types = _net_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        # Every networkPort objectName read returns an error -> nothing found.
        app.request = AsyncMock(return_value=types["ErrorPDU"]())
        asyncio.run(scanner._bacpypes3_discover_networks(app, Mock(), 2.0))
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("No network-port objects found", out)
        self.assertEqual(scanner.remote_networks, [])

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_one_port_with_network_discovered(self, mock_load):
        types = _net_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        err = types["ErrorPDU"]
        # Port instance 1: objectName ack, networkNumber=2000, networkType=2 (MS/TP).
        # Port instances 2..9: objectName read errors -> loop continues.
        responses = [
            _str_tag_response("MSTP-Port"),  # port1 objectName
            _uint_tag_response(2000),  # port1 networkNumber
            _uint_tag_response(2),  # port1 networkType (MS/TP)
        ] + [err() for _ in range(8)]  # ports 2..9 objectName -> error
        app.request = AsyncMock(side_effect=responses)

        asyncio.run(scanner._bacpypes3_discover_networks(app, Mock(), 2.0))

        # Network number captured, port reported as MS/TP.
        self.assertIn(2000, scanner.remote_networks)
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("MSTP-Port", out)
        self.assertIn("MS/TP", out)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_scan_all_networks_with_none_found(self, mock_load):
        types = _net_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())
        asyncio.run(scanner._bacpypes3_scan_all_networks(app, Mock(), 2.0))
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("No remote networks found to scan", out)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_scan_remote_network_timeout(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())
        asyncio.run(scanner._bacpypes3_scan_remote_network(app, Mock(), 99, 0.01))
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("No devices responded on network 99", out)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_scan_remote_network_device_responds(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_ack())  # an I-Am-ish response
        asyncio.run(scanner._bacpypes3_scan_remote_network(app, Mock(), 5, 0.01))
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("Found 1 device(s) on network 5", succ)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_scan_all_networks_discovers_then_scans(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        scanner.remote_networks = [11, 22]  # pre-seeded so scan runs directly
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())
        asyncio.run(scanner._bacpypes3_scan_all_networks(app, Mock(), 0.01))
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("Scanning 2 network(s)", out)
        self.assertIn("Network 11", out)
        self.assertIn("Network 22", out)


# ---------------------------------------------------------------------------
# MS/TP discovery (async multi-phase)
# ---------------------------------------------------------------------------
class TestDiscoverMstp(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_not_a_router_returns_early(self, mock_load):
        types = _net_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        # No networkPort objectName responds -> "not a router", early return.
        app.request = AsyncMock(return_value=types["ErrorPDU"]())

        asyncio.run(scanner._bacpypes3_discover_mstp(app, Mock(), 1001, 0.05))

        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("requires a BACnet router target", out)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_mstp_port_no_devices_reaches_summary(self, mock_load):
        types = _net_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        err = types["ErrorPDU"]
        max_master = 2  # keep the per-MAC probe loop tiny/fast

        def reqs():
            # Phase 1, port 1 (MS/TP):
            yield _str_tag_response("MSTP-1")  # objectName
            yield _uint_tag_response(2)  # networkType = MS/TP
            yield _uint_tag_response(2000)  # networkNumber
            yield _str_tag_response("\x05")  # macAddress (1 byte)
            yield _uint_tag_response(max_master)  # maxMaster
            yield _uint_tag_response(50)  # maxInfoFrames
            yield _uint_tag_response(0)  # slaveProxyEnable (False)
            yield _uint_tag_response(0)  # autoSlaveDiscovery (False)
            # Phase 1, ports 2..10 objectName -> error (stop probing).
            for _ in range(9):
                yield err()
            # Phase 2: Who-Is broadcast to net 2000 -> timeout, then per-MAC
            # probes 0..max_master all timeout. Use a generous error fountain.
            while True:
                yield asyncio.TimeoutError()

        gen = reqs()

        async def fake_request(_req):
            item = next(gen)
            if isinstance(item, BaseException):
                raise item
            return item

        app.request = AsyncMock(side_effect=fake_request)

        asyncio.run(scanner._bacpypes3_discover_mstp(app, Mock(), 1001, 0.01))

        # Reaches Phase 4 summary with the MS/TP port reported and no devices.
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("MS/TP Discovery Summary", out)
        warn = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("no built-in authentication", warn)

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_device_found_runs_phase3_enumeration(self, mock_load):
        types = _net_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        err = types["ErrorPDU"]
        max_master = 1  # probe MAC 0 and 1 only

        # An I-Am-shaped probe response for MAC 0.
        iam = Mock(
            spec=[
                "iAmDeviceIdentifier",
                "maxAPDULengthAccepted",
                "segmentationSupported",
                "vendorID",
            ]
        )
        iam.iAmDeviceIdentifier = ("device", 555)
        iam.maxAPDULengthAccepted = 480
        iam.segmentationSupported = 3
        iam.vendorID = 99

        def reqs():
            # Phase 1, port 1 (MS/TP) - networkNumber 2000, maxMaster 1.
            yield _str_tag_response("MSTP-A")  # objectName
            yield _uint_tag_response(2)  # networkType MS/TP
            yield _uint_tag_response(2000)  # networkNumber
            yield _str_tag_response("\x01")  # macAddress
            yield _uint_tag_response(max_master)  # maxMaster
            yield _uint_tag_response(50)  # maxInfoFrames
            yield _uint_tag_response(0)  # slaveProxyEnable
            yield _uint_tag_response(0)  # autoSlaveDiscovery
            for _ in range(9):  # ports 2..10 absent
                yield err()
            # Phase 2: Who-Is broadcast to net 2000 -> timeout.
            yield asyncio.TimeoutError()
            # MAC probe 0 -> I-Am (device found); MAC probe 1 -> timeout.
            yield iam
            yield asyncio.TimeoutError()
            # Phase 3: every device-property read errors gracefully -> None.
            while True:
                yield err()

        gen = reqs()

        async def fake_request(_req):
            item = next(gen)
            if isinstance(item, BaseException):
                raise item
            return item

        app.request = AsyncMock(side_effect=fake_request)

        asyncio.run(scanner._bacpypes3_discover_mstp(app, Mock(), 1001, 0.01))

        # Phase 3 ran for the discovered device, and the summary lists it.
        out = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("Enumerating", out)
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertIn("2000:0", succ)  # the discovered device at net 2000 MAC 0
        # Devices-respond-remotely isolation finding fires.
        warn = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("no network-level isolation", warn)


# ---------------------------------------------------------------------------
# BBMD injection
# ---------------------------------------------------------------------------
class TestBbmdInjection(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_bdt_write_accepted_emits_writable_finding(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        # BDT read -> ack; FD registration -> rejected (code=1); BDT write -> accepted (code=0)
        app.request = AsyncMock(side_effect=[_ack(), _bvll(1), _bvll(0)])

        asyncio.run(scanner._bacpypes3_test_bbmd_injection(app, Mock(), 2.0))

        call = scanner.logger.security_finding.call_args
        self.assertEqual(call.args[0], "Writable access")
        self.assertIn("BDT write accepted", call.kwargs["detail"])

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_no_reply_is_inconclusive_no_finding(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        # BDT read None; FD reg None; BDT write None - all inconclusive.
        app.request = AsyncMock(return_value=None)

        asyncio.run(scanner._bacpypes3_test_bbmd_injection(app, Mock(), 2.0))

        # Absence of evidence must NOT become a security finding.
        scanner.logger.security_finding.assert_not_called()

    @patch("oida.protocols.bacnet.mixins.network._load_bacpypes3")
    def test_foreign_device_accept_is_a_textual_finding_not_security(self, mock_load):
        mock_load.return_value = _net_types()
        scanner = _create_instance()
        app = AsyncMock()
        # BDT read None; FD registration accepted (code=0); BDT write rejected.
        app.request = AsyncMock(side_effect=[None, _bvll(0), _bvll(2)])

        asyncio.run(scanner._bacpypes3_test_bbmd_injection(app, Mock(), 2.0))

        # FD registration accept is reported via warning, not security_finding;
        # only the BDT-write accept path emits a structured finding.
        scanner.logger.security_finding.assert_not_called()
        warn = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("Foreign device registration ACCEPTED", warn)


# ---------------------------------------------------------------------------
# _mstp_report_security  (synchronous summary + heuristics)
# ---------------------------------------------------------------------------
class TestMstpReportSecurity(unittest.TestCase):
    def test_baseline_no_auth_finding_always_present(self):
        scanner = _create_instance()
        mstp_ports = [{"instance": 1, "name": "MSTP-1", "networkNumber": 2000, "maxMaster": 20}]
        findings = []
        scanner._mstp_report_security(mstp_ports, {}, findings)
        joined = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("no built-in authentication", joined)

    def test_slave_proxy_flagged_as_pivot(self):
        scanner = _create_instance()
        mstp_ports = [
            {
                "instance": 1,
                "name": "MSTP-1",
                "networkNumber": 2000,
                "maxMaster": 10,
                "slaveProxyEnable": True,
            }
        ]
        findings = []
        scanner._mstp_report_security(mstp_ports, {}, findings)
        joined = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("slaveProxyEnable=True", joined)
        self.assertIn("pivot point", joined)

    def test_large_max_master_flagged(self):
        scanner = _create_instance()
        mstp_ports = [{"instance": 2, "name": "MSTP-2", "networkNumber": 2001, "maxMaster": 127}]
        findings = []
        scanner._mstp_report_security(mstp_ports, {}, findings)
        joined = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("maxMaster=127", joined)

    def test_constrained_device_small_apdu_and_no_segmentation(self):
        scanner = _create_instance()
        mstp_ports = [{"instance": 1, "name": "MSTP-1", "networkNumber": 2000, "maxMaster": 10}]
        devices = {
            (2000, 5): {
                "deviceId": 77,
                "objectName": "TinyCtrl",
                "maxApduLengthAccepted": 50,
                "segmentationSupported": "no-segmentation",
            }
        }
        findings = []
        scanner._mstp_report_security(mstp_ports, devices, findings)
        joined = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("very small APDU limit", joined)
        self.assertIn("no segmentation support", joined)
        # The device appears in the topology + summary table.
        disp = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("TinyCtrl", disp)

    def test_devices_respond_remotely_isolation_finding(self):
        scanner = _create_instance()
        mstp_ports = [{"instance": 1, "name": "MSTP-1", "networkNumber": 2000, "maxMaster": 10}]
        devices = {(2000, 3): {"deviceId": 42, "maxApduLengthAccepted": 480}}
        findings = []
        scanner._mstp_report_security(mstp_ports, devices, findings)
        joined = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("no network-level isolation", joined)


if __name__ == "__main__":
    unittest.main()
