"""
Unit tests for the NXC-style CAN connection class (oida.protocols.can.cli_runner).

These tests drive the feature-dispatch and feature-handler logic of the ``can``
connection class for real. Only the external I/O boundary is mocked: the Layer-1
``CANScanner`` (which talks to a real python-can Bus) and the python-can Message
constructor. The dispatch in ``_execute_features`` and every ``_handle_*`` method
runs unmodified -- no monkey-patching of the code under test.

The ``can`` class auto-runs ``proto_flow()`` from ``connection.__init__``, so the
handlers are exercised on an instance built via ``object.__new__`` with exactly the
collaborators each handler reads (``args``, ``conn``, ``scanner``, ``logger``,
``results``, ``channel``).
"""

import argparse
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from oida.protocols.can.constants import (
    CANopenNode,
    CANopenSDOResponse,
    CCPScanResult,
    UDSScanResult,
    XCPScanResult,
)
from oida.protocols.can.cli_runner import can as CANConnection

pytestmark = pytest.mark.core


# ---------------------------------------------------------------------------
# Fixtures / builders
# ---------------------------------------------------------------------------


def _make_conn(**arg_overrides):
    """Build a ``can`` connection instance WITHOUT running proto_flow().

    Returns the instance with a mocked Layer-1 scanner, a mocked connection
    object, a mocked logger, and a fresh results dict -- exactly the
    collaborators the ``_handle_*`` methods touch.
    """
    inst = CANConnection.__new__(CANConnection)

    args_dict = {
        "confirm": False,
        "verbose": 0,
        "debug": False,
    }
    args_dict.update(arg_overrides)
    inst.args = argparse.Namespace(**args_dict)

    inst.channel = "vcan0"
    inst.bus_type = "socketcan"
    inst.baudrate = 500000
    inst.fd = False
    inst.extended = False
    inst.sniff_time = 5
    inst.no_sniff = False

    inst.conn = MagicMock(name="bus")
    inst.scanner = MagicMock(name="CANScanner")
    inst.logger = MagicMock(name="logger")
    inst.results = {"data": {}}
    return inst


# ---------------------------------------------------------------------------
# enum / print host info
# ---------------------------------------------------------------------------


class TestEnumAndPrintHostInfo:
    def test_enum_host_info_populates_results(self):
        inst = _make_conn()
        inst.fd = True
        inst.enum_host_info()
        data = inst.results["data"]
        assert data["interface"] == "vcan0"
        assert data["bus_type"] == "socketcan"
        assert data["baudrate"] == 500000
        assert data["fd_enabled"] is True

    def test_enum_host_info_no_conn_is_noop(self):
        inst = _make_conn()
        inst.conn = None
        inst.enum_host_info()
        assert inst.results["data"] == {}

    def test_print_host_info_flags_displayed(self):
        inst = _make_conn()
        inst.fd = True
        inst.extended = True
        inst.print_host_info()
        msgs = [c.args[0] for c in inst.logger.display.call_args_list]
        assert any("CAN FD: enabled" in m for m in msgs)
        assert any("Extended IDs: enabled" in m for m in msgs)

    def test_print_host_info_no_flags_quiet(self):
        inst = _make_conn()
        inst.print_host_info()
        inst.logger.display.assert_not_called()


# ---------------------------------------------------------------------------
# Passive sniff
# ---------------------------------------------------------------------------


class TestHandleSniff:
    def _stats(self, total=42):
        stats = SimpleNamespace(
            total_messages=total,
            unique_ids=3,
            duration_seconds=5.0,
            messages_per_second=8.4,
            error_frames=0,
            remote_frames=1,
        )
        stats.get_top_ids = lambda n: [(0x123, 30), (0x7E8, 12)]
        return stats

    def test_sniff_with_traffic_emits_encryption_finding(self):
        inst = _make_conn()
        inst.scanner._sniff_traffic.return_value = self._stats(total=42)

        inst._handle_sniff()

        inst.scanner._sniff_traffic.assert_called_once_with(inst.conn, duration=5)
        # CAN traffic => "No encryption" finding under the ENCRYPTION category
        finding = inst.logger.security_finding.call_args
        assert finding.args[0] == "No encryption"

        stats = inst.results["data"]["traffic_stats"]
        assert stats["total_messages"] == 42
        assert stats["unique_ids"] == 3
        assert stats["top_ids"][0] == {"id": "0x123", "count": 30, "extended": False}

    def test_sniff_no_traffic_no_finding(self):
        inst = _make_conn()
        inst.scanner._sniff_traffic.return_value = self._stats(total=0)

        inst._handle_sniff()

        inst.logger.security_finding.assert_not_called()
        assert inst.results["data"]["traffic_stats"]["total_messages"] == 0


# ---------------------------------------------------------------------------
# UDS service discovery
# ---------------------------------------------------------------------------


class TestHandleUDSScan:
    def test_uds_scan_requires_confirm(self):
        # --uds-scan actively probes ECUs / enumerates state-changing SIDs, so it
        # is gated on --confirm like the other active CAN operations.
        inst = _make_conn(confirm=False, uds_scan=True)
        inst._handle_uds_scan()
        inst.scanner._scan_uds.assert_not_called()
        assert "--confirm" in inst.logger.fail.call_args.args[0]

    def test_uds_scan_serializes_results(self):
        inst = _make_conn(confirm=True)
        result = UDSScanResult(
            request_id=0x7E0,
            response_id=0x7E8,
            supported_services=[0x10, 0x22],
            diagnostic_sessions=[0x01, 0x03],
            vehicle_info={"vin": "ABC"},
            negative_responses={0x27: 0x33},
        )
        inst.scanner._scan_uds.return_value = [result]

        inst._handle_uds_scan()

        entries = inst.results["data"]["uds_results"]
        assert len(entries) == 1
        e = entries[0]
        assert e["request_id"] == "0x7E0"
        assert e["response_id"] == "0x7E8"
        # 0x10 -> DiagnosticSessionControl per UDS_SERVICES map
        svc_ids = {s["id"] for s in e["services"]}
        assert svc_ids == {"0x10", "0x22"}
        assert e["sessions"] == [0x01, 0x03]
        assert e["negative_responses"] == {"0x27": "0x33"}


# ---------------------------------------------------------------------------
# ID scan (gated on --confirm)
# ---------------------------------------------------------------------------


class TestHandleIDScan:
    def test_id_scan_requires_confirm(self):
        inst = _make_conn(confirm=False, id_scan_range="0x700-0x701")
        inst._handle_id_scan()
        inst.logger.fail.assert_called_once()
        assert "--confirm" in inst.logger.fail.call_args.args[0]
        assert "id_scan" not in inst.results["data"]

    def test_id_scan_invalid_range_fails(self, monkeypatch):
        inst = _make_conn(confirm=True, id_scan_range="not-a-range")
        # patch the python-can module reference in the module under test only
        monkeypatch.setattr(
            "oida.protocols.can.cli_runner._python_can",
            MagicMock(),
        )
        inst._handle_id_scan()
        inst.logger.fail.assert_called_once()
        assert "Invalid scan range" in inst.logger.fail.call_args.args[0]

    def test_id_scan_collects_responding_ids(self, monkeypatch):
        inst = _make_conn(confirm=True, id_scan_range="0x700-0x702")
        fake_can = MagicMock()
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", fake_can)

        # Only 0x701 responds
        def recv(conn, arb_id, timeout):
            if arb_id == 0x701:
                return (0x709, b"\x02\x7e\x00")
            return None

        inst.scanner._recv_uds_response.side_effect = recv

        inst._handle_id_scan()

        scan = inst.results["data"]["id_scan"]
        assert len(scan) == 1
        assert scan[0]["request_id"] == "0x701"
        assert scan[0]["response_id"] == "0x709"
        assert scan[0]["data"] == "02 7E 00"
        # Three IDs were probed -> three sends attempted
        assert inst.conn.send.call_count == 3


# ---------------------------------------------------------------------------
# XCP handlers
# ---------------------------------------------------------------------------


class TestHandleXCP:
    def test_xcp_scan_requires_confirm(self):
        inst = _make_conn(confirm=False)
        inst._handle_xcp_scan()
        inst.logger.fail.assert_called_once()
        assert "xcp_results" not in inst.results["data"]

    def test_xcp_scan_serializes(self):
        inst = _make_conn(confirm=True)
        r = XCPScanResult(
            request_id=0x100,
            response_id=0x101,
            connected=True,
            xcp_version="1.0",
            max_cto=8,
            max_dto=8,
            resource_protection=0x05,
            comm_mode_basic=0xC0,
        )
        inst.scanner.scan_xcp.return_value = [r]
        inst._handle_xcp_scan()
        e = inst.results["data"]["xcp_results"][0]
        assert e["request_id"] == "0x100"
        assert e["connected"] is True
        assert e["resource_protection"] == "0x05"
        assert e["comm_mode_basic"] == "0xC0"

    def test_xcp_info_missing_ids_fails(self):
        inst = _make_conn(xcp_req_id=None, xcp_resp_id=None)
        inst._handle_xcp_info()
        inst.logger.fail.assert_called_once()
        assert "xcp_info" not in inst.results["data"]

    def test_xcp_info_invalid_ids_fails(self):
        inst = _make_conn(xcp_req_id="zzz", xcp_resp_id="0x101")
        inst._handle_xcp_info()
        inst.logger.fail.assert_called_once()
        assert "Invalid XCP arb IDs" in inst.logger.fail.call_args.args[0]

    def test_xcp_info_serializes(self):
        inst = _make_conn(xcp_req_id="0x100", xcp_resp_id="0x101")
        r = XCPScanResult(
            request_id=0x100,
            response_id=0x101,
            connected=True,
            xcp_version="1.1",
            transport_version="1.0",
            identification="ECU-X",
            status={"ok": True},
            max_cto=8,
            max_dto=16,
            comm_mode_basic=0xC0,
            error="",
        )
        inst.scanner.xcp_get_info.return_value = r
        inst._handle_xcp_info()
        info = inst.results["data"]["xcp_info"]
        assert info["identification"] == "ECU-X"
        assert info["max_dto"] == 16
        assert info["comm_mode_basic"] == "0xC0"
        inst.scanner.xcp_get_info.assert_called_once_with(inst.conn, 0x100, 0x101)

    def test_xcp_memory_read_requires_confirm(self):
        inst = _make_conn(confirm=False, xcp_req_id="0x100", xcp_resp_id="0x101")
        inst._handle_xcp_memory_read()
        inst.logger.fail.assert_called_once()
        assert "xcp_memory_read" not in inst.results["data"]

    def test_xcp_memory_read_missing_params_fails(self):
        inst = _make_conn(confirm=True, xcp_req_id="0x100", xcp_resp_id="0x101", xcp_address=None)
        inst._handle_xcp_memory_read()
        inst.logger.fail.assert_called_once()
        assert "xcp_memory_read" not in inst.results["data"]

    def test_xcp_memory_read_invalid_params_fails(self):
        inst = _make_conn(
            confirm=True,
            xcp_req_id="0x100",
            xcp_resp_id="0x101",
            xcp_address="nope",
        )
        inst._handle_xcp_memory_read()
        inst.logger.fail.assert_called_once()
        assert "Invalid XCP memory read parameters" in inst.logger.fail.call_args.args[0]

    def test_xcp_memory_read_serializes(self):
        inst = _make_conn(
            confirm=True,
            xcp_req_id="0x100",
            xcp_resp_id="0x101",
            xcp_address="0x1000",
            xcp_length=4,
        )
        inst.scanner.xcp_memory_read.return_value = b"\xde\xad\xbe\xef"
        inst._handle_xcp_memory_read()
        mr = inst.results["data"]["xcp_memory_read"]
        assert mr["address"] == "0x00001000"
        assert mr["length"] == 4
        assert mr["data"] == "DE AD BE EF"
        inst.scanner.xcp_memory_read.assert_called_once_with(inst.conn, 0x100, 0x101, 0x1000, 4)

    def test_xcp_memory_read_none_data(self):
        inst = _make_conn(
            confirm=True,
            xcp_req_id="0x100",
            xcp_resp_id="0x101",
            xcp_address="0x2000",
            xcp_length=6,
        )
        inst.scanner.xcp_memory_read.return_value = None
        inst._handle_xcp_memory_read()
        assert inst.results["data"]["xcp_memory_read"]["data"] is None


# ---------------------------------------------------------------------------
# CCP handler
# ---------------------------------------------------------------------------


class TestHandleCCP:
    def test_ccp_scan_requires_confirm(self):
        inst = _make_conn(confirm=False)
        inst._handle_ccp_scan()
        inst.logger.fail.assert_called_once()
        assert "ccp_results" not in inst.results["data"]

    def test_ccp_scan_serializes_with_default_ids(self):
        inst = _make_conn(confirm=True, ccp_cro_id=None, ccp_dto_id=None)
        r = CCPScanResult(
            cro_id=0x701,
            dto_id=0x702,
            station_address=3,
            connected=True,
            ccp_version="2.1",
        )
        inst.scanner.scan_ccp.return_value = [r]
        inst._handle_ccp_scan()
        # Defaults 0x701 / 0x702 are parsed and passed through
        inst.scanner.scan_ccp.assert_called_once_with(inst.conn, cro_id=0x701, dto_id=0x702)
        e = inst.results["data"]["ccp_results"][0]
        assert e["cro_id"] == "0x701"
        assert e["station_address"] == 3
        assert e["connected"] is True


# ---------------------------------------------------------------------------
# Enhanced UDS handlers
# ---------------------------------------------------------------------------


class TestUDSTargetId:
    def test_default_target_id(self):
        inst = _make_conn(uds_target_id=None)
        assert inst._get_uds_target_id() == 0x7E0

    def test_explicit_target_id(self):
        inst = _make_conn(uds_target_id="0x7E1")
        assert inst._get_uds_target_id() == 0x7E1

    def test_invalid_target_id(self):
        inst = _make_conn(uds_target_id="garbage")
        assert inst._get_uds_target_id() is None
        inst.logger.fail.assert_called_once()


class TestHandleUDSSessions:
    def test_sessions_requires_confirm(self):
        inst = _make_conn(confirm=False, uds_target_id="0x7E0")
        inst._handle_uds_sessions()
        inst.scanner.uds_session_scan.assert_not_called()
        assert "uds_sessions" not in inst.results["data"]
        assert "--confirm" in inst.logger.fail.call_args.args[0]

    def test_sessions_serializes(self):
        inst = _make_conn(confirm=True, uds_target_id="0x7E0")
        inst.scanner.uds_session_scan.return_value = [0x01, 0x03, 0x7F]
        inst._handle_uds_sessions()
        out = inst.results["data"]["uds_sessions"]
        assert out["request_id"] == "0x7E0"
        ids = {s["id"] for s in out["supported_sessions"]}
        assert ids == {"0x01", "0x03", "0x7F"}
        # 0x7F is not a known session -> VendorSpecific naming
        vendor = [s for s in out["supported_sessions"] if s["id"] == "0x7F"][0]
        assert "VendorSpecific" in vendor["name"]

    def test_sessions_aborts_on_bad_target(self):
        inst = _make_conn(confirm=True, uds_target_id="bad")
        inst._handle_uds_sessions()
        inst.scanner.uds_session_scan.assert_not_called()
        assert "uds_sessions" not in inst.results["data"]


class TestHandleUDSDids:
    def test_dids_with_range(self):
        inst = _make_conn(uds_target_id="0x7E0")
        inst.scanner.uds_did_scan.return_value = {0xF190: b"VIN12"}
        inst._handle_uds_dids("0xF190-0xF1A0")
        inst.scanner.uds_did_scan.assert_called_once_with(
            inst.conn, 0x7E0, did_range=(0xF190, 0xF1A0)
        )
        out = inst.results["data"]["uds_dids"]
        assert out["readable_dids"][0]["did"] == "0xF190"
        assert out["readable_dids"][0]["data"] == "56 49 4E 31 32"

    def test_dids_true_means_full_range(self):
        inst = _make_conn(uds_target_id="0x7E0")
        inst.scanner.uds_did_scan.return_value = {}
        inst._handle_uds_dids("true")
        # "true" => did_range stays None (full default scan)
        inst.scanner.uds_did_scan.assert_called_once_with(inst.conn, 0x7E0, did_range=None)

    def test_dids_invalid_range_fails(self):
        inst = _make_conn(uds_target_id="0x7E0")
        inst._handle_uds_dids("0xZZ-")
        inst.logger.fail.assert_called_once()
        assert "uds_dids" not in inst.results["data"]


class TestHandleUDSSeeds:
    def test_seeds_serializes(self):
        inst = _make_conn(uds_target_id="0x7E0", seed_level="0x01", seed_count=2)
        inst.scanner.uds_security_seed_collect.return_value = [b"\x11\x22", b"\x33\x44"]
        inst._handle_uds_seeds()
        out = inst.results["data"]["uds_seeds"]
        assert out["security_level"] == "0x01"
        assert out["count"] == 2
        assert out["seeds"] == ["11 22", "33 44"]
        inst.scanner.uds_security_seed_collect.assert_called_once_with(
            inst.conn, 0x7E0, security_level=0x01, count=2
        )

    def test_seeds_integer_level(self):
        inst = _make_conn(uds_target_id="0x7E0", seed_level=3, seed_count=1)
        inst.scanner.uds_security_seed_collect.return_value = [b"\xaa"]
        inst._handle_uds_seeds()
        assert inst.results["data"]["uds_seeds"]["security_level"] == "0x03"


class TestHandleUDSRoutines:
    def test_routines_requires_confirm(self):
        inst = _make_conn(confirm=False, uds_target_id="0x7E0")
        inst._handle_uds_routines()
        inst.scanner.uds_routine_scan.assert_not_called()
        assert "uds_routines" not in inst.results["data"]
        assert "--confirm" in inst.logger.fail.call_args.args[0]

    def test_routines_serializes(self):
        inst = _make_conn(confirm=True, uds_target_id="0x7E0")
        inst.scanner.uds_routine_scan.return_value = [0x0203, 0xFF00]
        inst._handle_uds_routines()
        out = inst.results["data"]["uds_routines"]
        assert out["routines"] == ["0x0203", "0xFF00"]


class TestHandleUDSReset:
    def test_reset_requires_confirm(self):
        inst = _make_conn(confirm=False, uds_target_id="0x7E0")
        inst._handle_uds_reset()
        inst.logger.fail.assert_called_once()
        inst.scanner.uds_ecu_reset.assert_not_called()

    def test_reset_serializes(self):
        inst = _make_conn(confirm=True, uds_target_id="0x7E0", uds_reset_type="0x01")
        inst.scanner.uds_ecu_reset.return_value = True
        inst._handle_uds_reset()
        out = inst.results["data"]["uds_reset"]
        assert out["reset_type"] == "0x01"
        assert out["success"] is True
        inst.scanner.uds_ecu_reset.assert_called_once_with(inst.conn, 0x7E0, reset_type=0x01)

    def test_reset_bad_target_aborts(self):
        inst = _make_conn(confirm=True, uds_target_id="bad")
        inst._handle_uds_reset()
        inst.scanner.uds_ecu_reset.assert_not_called()


# ---------------------------------------------------------------------------
# CANopen handlers
# ---------------------------------------------------------------------------


def _node(node_id=1, **kw):
    base = dict(
        node_id=node_id,
        nmt_state=5,
        nmt_state_name="Operational",
        device_type=0x00020191,
        device_profile=401,
        device_profile_name="Generic I/O",
        device_name="IO-Module",
        hw_version="1.0",
        sw_version="2.0",
        vendor_id=0x12345678,
        vendor_name="Acme",
        product_code=0xABCD,
        revision=0x0001,
        serial_number=42,
        error_register=0,
    )
    base.update(kw)
    return CANopenNode(**base)


class TestHandleCANopenScan:
    def test_scan_merges_heartbeat_and_sdo_info(self):
        inst = _make_conn()
        discovered = _node(node_id=7, nmt_state_name="Operational", nmt_state=5)
        inst.scanner.canopen_node_scan.return_value = [discovered]
        # device_info returns a node; handler overrides nmt_state from discovery
        inst.scanner.canopen_device_info.return_value = _node(
            node_id=7, nmt_state_name="", nmt_state=0, device_name="Drive"
        )
        inst._handle_canopen_scan()
        nodes = inst.results["data"]["canopen_nodes"]
        assert len(nodes) == 1
        assert nodes[0]["node_id"] == 7
        assert nodes[0]["nmt_state"] == "Operational"  # merged from discovery
        assert nodes[0]["device_name"] == "Drive"
        assert nodes[0]["device_type"] == "0x00020191"
        assert nodes[0]["vendor_id"] == "0x12345678"


class TestHandleCANopenInfo:
    def test_info_invalid_node_fails(self):
        inst = _make_conn()
        inst._handle_canopen_info("notanint")
        inst.logger.fail.assert_called_once()
        assert "canopen_info" not in inst.results["data"]

    def test_info_serializes(self):
        inst = _make_conn()
        inst.scanner.canopen_device_info.return_value = _node(
            node_id=3, od_entries_found=[0x1000, 0x1018]
        )
        inst._handle_canopen_info("3")
        out = inst.results["data"]["canopen_info"]
        assert out["node_id"] == 3
        assert out["device_profile"] == "Generic I/O"
        assert out["od_entries_found"] == ["0x1000", "0x1018"]
        assert out["error_register"] == "0x00"


class TestHandleCANopenSDORead:
    def test_invalid_spec_fails(self):
        inst = _make_conn()
        inst._handle_canopen_sdo_read("bogus")
        inst.logger.fail.assert_called_once()
        assert "canopen_sdo_read" not in inst.results["data"]

    def test_sdo_read_error_records_abort(self):
        inst = _make_conn()
        resp = CANopenSDOResponse(
            node_id=1,
            index=0x1000,
            subindex=0,
            error=True,
            abort_code=0x06020000,
            abort_message="Object does not exist",
        )
        inst.scanner.canopen_sdo_read.return_value = resp
        inst._handle_canopen_sdo_read("1:0x1000:0")
        out = inst.results["data"]["canopen_sdo_read"]
        assert out["error"] == "Object does not exist"
        assert out["abort_code"] == "0x06020000"
        inst.logger.fail.assert_called_once()

    def test_sdo_read_string_value(self):
        inst = _make_conn()
        resp = CANopenSDOResponse(node_id=1, index=0x1008, subindex=0, data=b"DEV-X", error=False)
        inst.scanner.canopen_sdo_read.return_value = resp
        inst._handle_canopen_sdo_read("1:0x1008:0")
        out = inst.results["data"]["canopen_sdo_read"]
        assert out["data"] == "44 45 56 2D 58"
        assert '"DEV-X"' in out["display"]

    def test_sdo_read_uint32_value(self):
        inst = _make_conn()
        resp = CANopenSDOResponse(
            node_id=1, index=0x1000, subindex=0, data=b"\x91\x01\x02\x00", error=False
        )
        inst.scanner.canopen_sdo_read.return_value = resp
        inst._handle_canopen_sdo_read("1:0x1000:0")
        out = inst.results["data"]["canopen_sdo_read"]
        # 0x00020191 little-endian
        assert "0x00020191" in out["display"]

    def test_sdo_read_uint16_value(self):
        inst = _make_conn()
        resp = CANopenSDOResponse(
            node_id=1, index=0x6000, subindex=0, data=b"\x34\x12", error=False
        )
        inst.scanner.canopen_sdo_read.return_value = resp
        inst._handle_canopen_sdo_read("1:0x6000:0")
        out = inst.results["data"]["canopen_sdo_read"]
        assert "0x1234" in out["display"]


class TestHandleCANopenODScan:
    def test_invalid_node_fails(self):
        inst = _make_conn()
        inst._handle_canopen_od_scan("bad")
        inst.logger.fail.assert_called_once()

    def test_invalid_range_fails(self):
        inst = _make_conn(canopen_od_range="zz-")
        inst._handle_canopen_od_scan("1")
        inst.logger.fail.assert_called_once()
        assert "canopen_od_scan" not in inst.results["data"]

    def test_od_scan_with_range_serializes(self):
        inst = _make_conn(canopen_od_range="0x1000-0x1018")
        inst.scanner.canopen_od_scan.return_value = [
            (0x1000, 0, b"\x91\x01\x02\x00"),
            (0x1018, 1, b"\x78\x56\x34\x12"),
        ]
        inst._handle_canopen_od_scan("1")
        inst.scanner.canopen_od_scan.assert_called_once_with(
            inst.conn, 1, index_range=(0x1000, 0x1018)
        )
        entries = inst.results["data"]["canopen_od_scan"]["entries"]
        assert entries[0]["index"] == "0x1000"
        assert entries[1]["subindex"] == 1
        assert entries[1]["data"] == "78 56 34 12"


class TestHandleCANopenMonitor:
    def test_monitor_serializes(self):
        inst = _make_conn(duration=4)
        inst.scanner.canopen_heartbeat_monitor.return_value = {
            5: {"state_name": "Operational", "count": 8, "avg_interval_ms": 500.0}
        }
        inst.scanner.canopen_emcy_monitor.return_value = [{"node_id": 5, "code": "0x1000"}]
        inst._handle_canopen_monitor()
        out = inst.results["data"]["canopen_monitor"]
        assert out["heartbeat_nodes"]["5"]["state"] == "Operational"
        assert out["heartbeat_nodes"]["5"]["count"] == 8
        assert out["emcy_messages"][0]["code"] == "0x1000"
        # duration is split in half between heartbeat and emcy monitors
        inst.scanner.canopen_heartbeat_monitor.assert_called_once_with(inst.conn, duration=2.0)


class TestHandleCANopenPDO:
    def test_pdo_explicit_node(self):
        inst = _make_conn(canopen_pdo_node="5")
        inst.scanner.canopen_pdo_discover.return_value = {"tpdo1": {"cob_id": 0x185}}
        inst._handle_canopen_pdo()
        out = inst.results["data"]["canopen_pdo"]
        assert out["node_id"] == 5
        assert out["pdo_config"]["tpdo1"]["cob_id"] == 0x185

    def test_pdo_invalid_node_fails(self):
        inst = _make_conn(canopen_pdo_node="bad")
        inst._handle_canopen_pdo()
        inst.logger.fail.assert_called_once()
        assert "canopen_pdo" not in inst.results["data"]

    def test_pdo_no_node_scans_for_first(self):
        inst = _make_conn(canopen_pdo_node=None)
        inst.scanner.canopen_node_scan.return_value = [_node(node_id=9)]
        inst.scanner.canopen_pdo_discover.return_value = {}
        inst._handle_canopen_pdo()
        assert inst.results["data"]["canopen_pdo"]["node_id"] == 9

    def test_pdo_no_nodes_found_fails(self):
        inst = _make_conn(canopen_pdo_node=None)
        inst.scanner.canopen_node_scan.return_value = []
        inst._handle_canopen_pdo()
        inst.logger.fail.assert_called_once()
        assert "canopen_pdo" not in inst.results["data"]


class TestHandleModbusGateway:
    def test_gateway_detect_with_cia309_register_map(self):
        inst = _make_conn()
        gw = _node(
            node_id=11,
            device_name="GW-309",
            device_profile=309,
            device_profile_name="CiA 309 Gateway",
            vendor_name="Acme",
            is_gateway=True,
            gateway_type="modbus",
        )
        inst.scanner.canopen_modbus_gateway_detect.return_value = [gw]
        inst.scanner.canopen_modbus_register_map.return_value = {
            0x2000: b"\x00\x01",
        }
        inst._handle_modbus_gateway()
        gws = inst.results["data"]["modbus_gateways"]
        assert gws[0]["node_id"] == 11
        assert gws[0]["gateway_type"] == "modbus"
        assert gws[0]["register_mappings"] == {"0x2000": "00 01"}
        inst.scanner.canopen_modbus_register_map.assert_called_once_with(inst.conn, 11)

    def test_gateway_non_309_skips_register_map(self):
        inst = _make_conn()
        gw = _node(node_id=12, device_profile=401, gateway_type="generic")
        inst.scanner.canopen_modbus_gateway_detect.return_value = [gw]
        inst._handle_modbus_gateway()
        gws = inst.results["data"]["modbus_gateways"]
        assert "register_mappings" not in gws[0]
        inst.scanner.canopen_modbus_register_map.assert_not_called()


# ---------------------------------------------------------------------------
# Send / replay handlers
# ---------------------------------------------------------------------------


class TestHandleSend:
    def test_send_requires_confirm(self):
        inst = _make_conn(confirm=False)
        inst._handle_send("0x123#DEADBEEF")
        inst.logger.fail.assert_called_once()
        inst.scanner.send_message.assert_not_called()

    def test_send_invalid_format_fails(self):
        inst = _make_conn(confirm=True)
        inst._handle_send("nothex#ZZ")
        inst.logger.fail.assert_called_once()
        inst.scanner.send_message.assert_not_called()

    def test_send_standard_frame(self):
        inst = _make_conn(confirm=True)
        inst.scanner.send_message.return_value = True
        inst.scanner.recv_message.return_value = None
        inst._handle_send("0x123#DE AD BE EF")
        # bytes parsed with spaces stripped
        inst.scanner.send_message.assert_called_once_with(
            inst.conn, 0x123, b"\xde\xad\xbe\xef", is_extended=False
        )
        inst.logger.success.assert_called_once()

    def test_send_extended_frame_and_response(self):
        inst = _make_conn(confirm=True)
        inst.scanner.send_message.return_value = True
        resp = SimpleNamespace(id_hex="0x18DAF110", data_hex="50 03")
        inst.scanner.recv_message.return_value = resp
        inst._handle_send("0x18DAF111#0210")
        # arb id > CAN_STD_ID_MAX => extended
        inst.scanner.send_message.assert_called_once_with(
            inst.conn, 0x18DAF111, b"\x02\x10", is_extended=True
        )
        # Response line is displayed
        display_msgs = [c.args[0] for c in inst.logger.display.call_args_list]
        assert any("0x18DAF110" in m for m in display_msgs)


class TestHandleSendFile:
    def test_send_file_requires_confirm(self):
        inst = _make_conn(confirm=False)
        inst._handle_send_file("/tmp/does-not-matter.txt")
        inst.logger.fail.assert_called_once()

    def test_send_file_unreadable_fails(self, tmp_path):
        inst = _make_conn(confirm=True)
        inst._handle_send_file(str(tmp_path / "missing.txt"))
        inst.logger.fail.assert_called_once()
        assert "Could not read send file" in inst.logger.fail.call_args.args[0]

    def test_send_file_skips_comments_and_blanks(self, tmp_path):
        f = tmp_path / "frames.txt"
        f.write_text("# comment\n\n0x123#DEAD\n0x124#BEEF\n")
        inst = _make_conn(confirm=True)
        inst.scanner.send_message.return_value = True
        inst.scanner.recv_message.return_value = None
        inst._handle_send_file(str(f))
        # Two real frames sent (comment and blank skipped)
        assert inst.scanner.send_message.call_count == 2


class TestHandleReplay:
    def test_replay_requires_confirm(self):
        inst = _make_conn(confirm=False)
        inst._handle_replay("/tmp/x.log")
        inst.logger.fail.assert_called_once()

    def test_replay_unreadable_fails(self, tmp_path, monkeypatch):
        inst = _make_conn(confirm=True, replay_speed=1.0)
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", MagicMock())
        inst._handle_replay(str(tmp_path / "missing.log"))
        inst.logger.fail.assert_called_once()
        assert "Could not read replay file" in inst.logger.fail.call_args.args[0]

    def test_replay_candump_format(self, tmp_path, monkeypatch):
        log = tmp_path / "dump.log"
        # candump format: (timestamp) interface ID#DATA
        log.write_text("# header\n(1000.000000) vcan0 123#DEADBEEF\n(1000.000000) vcan0 7E0#0210\n")
        inst = _make_conn(confirm=True, replay_speed=0)  # speed 0 => no sleeps
        fake_can = MagicMock()
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", fake_can)
        inst._handle_replay(str(log))
        # Two frames parsed and sent on the bus
        assert inst.conn.send.call_count == 2


# ---------------------------------------------------------------------------
# Fuzz handler (requires --confirm)
# ---------------------------------------------------------------------------


class TestHandleFuzz:
    def test_fuzz_requires_confirm(self):
        inst = _make_conn(confirm=False)
        inst._handle_fuzz()
        inst.logger.fail.assert_called_once()
        assert "fuzz_results" not in inst.results["data"]

    def test_fuzz_requires_fuzz_id(self, monkeypatch):
        inst = _make_conn(confirm=True, fuzz_id=None)
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", MagicMock())
        inst._handle_fuzz()
        inst.logger.fail.assert_called_once()
        assert "--fuzz-id is required" in inst.logger.fail.call_args.args[0]

    def test_fuzz_invalid_id(self, monkeypatch):
        inst = _make_conn(confirm=True, fuzz_id="zzz")
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", MagicMock())
        inst._handle_fuzz()
        inst.logger.fail.assert_called_once()
        assert "Invalid fuzz ID" in inst.logger.fail.call_args.args[0]

    def test_fuzz_boundary_mode_records_results(self, monkeypatch):
        inst = _make_conn(
            confirm=True,
            fuzz_id="0x7E0",
            fuzz_iterations=3,
            fuzz_mode="boundary",
        )
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", MagicMock())
        # First iteration gets a response, others don't
        responses = [SimpleNamespace(id_hex="0x7E8", data_hex="50 03"), None, None]
        inst.scanner.recv_message.side_effect = responses
        inst._handle_fuzz()
        results = inst.results["data"]["fuzz_results"]
        assert len(results) == 3
        assert results[0]["response"] == {"id": "0x7E8", "data": "50 03"}
        assert results[1]["response"] is None

    def test_fuzz_sequential_mode(self, monkeypatch):
        inst = _make_conn(confirm=True, fuzz_id="0x100", fuzz_iterations=2, fuzz_mode="sequential")
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", MagicMock())
        inst.scanner.recv_message.return_value = None
        inst._handle_fuzz()
        assert len(inst.results["data"]["fuzz_results"]) == 2


# ---------------------------------------------------------------------------
# Feature dispatch (_execute_features)
# ---------------------------------------------------------------------------


class TestExecuteFeatures:
    def test_no_conn_short_circuits(self):
        inst = _make_conn()
        inst.conn = None
        inst._execute_features()
        # Nothing recorded
        assert inst.results["data"] == {}

    def test_sniff_runs_by_default(self):
        inst = _make_conn()
        # Make the sniff path a no-op observable via the scanner mock
        stats = SimpleNamespace(
            total_messages=0,
            unique_ids=0,
            duration_seconds=1.0,
            messages_per_second=0.0,
            error_frames=0,
            remote_frames=0,
        )
        stats.get_top_ids = lambda n: []
        inst.scanner._sniff_traffic.return_value = stats
        inst._execute_features()
        inst.scanner._sniff_traffic.assert_called_once()

    def test_no_sniff_skips_sniff(self):
        inst = _make_conn()
        inst.no_sniff = True
        inst._execute_features()
        inst.scanner._sniff_traffic.assert_not_called()

    def test_dispatch_routes_to_uds_scan(self):
        inst = _make_conn(uds_scan=True, confirm=True)
        inst.no_sniff = True
        inst.scanner._scan_uds.return_value = []
        inst._execute_features()
        inst.scanner._scan_uds.assert_called_once()


# ---------------------------------------------------------------------------
# cleanup / dependency
# ---------------------------------------------------------------------------


class TestCleanupAndDeps:
    def test_cleanup_shuts_down_bus(self):
        inst = _make_conn()
        bus = inst.conn
        inst.cleanup()
        bus.shutdown.assert_called_once()
        assert inst.conn is None

    def test_cleanup_swallows_errors(self):
        inst = _make_conn()
        inst.conn.shutdown.side_effect = RuntimeError("boom")
        inst.cleanup()  # must not raise
        assert inst.conn is None

    def test_cleanup_no_conn(self):
        inst = _make_conn()
        inst.conn = None
        inst.logger = MagicMock()
        inst.cleanup()  # no-op, no raise
        assert inst.conn is None
        inst.logger.debug.assert_not_called()

    def test_check_dependencies_reflects_availability(self):
        # check_dependencies just reflects the lazy_import availability flag
        assert isinstance(CANConnection.check_dependencies(), bool)


# ---------------------------------------------------------------------------
# __init__ option parsing (no proto_flow)
# ---------------------------------------------------------------------------


class TestInitOptionParsing:
    """__init__ reads CAN options off args; verify it without running the
    full proto_flow by stubbing the parent connection.__init__."""

    def _init(self, monkeypatch, **arg_overrides):
        # Replace ONLY the external base-class __init__ so we can observe the
        # CAN-specific attribute parsing in can.__init__ in isolation.
        captured = {}

        def fake_super_init(self, args, db, host):
            captured["host"] = host

        monkeypatch.setattr("oida.connection.SerialConnection.__init__", fake_super_init)
        args = argparse.Namespace(**arg_overrides)
        inst = CANConnection(args, None, "can0")
        return inst

    def test_defaults_when_args_missing(self, monkeypatch):
        inst = self._init(monkeypatch)
        assert inst.baudrate == 500000
        assert inst.bus_type == "socketcan"
        assert inst.channel == "can0"  # falls back to host
        assert inst.fd is False
        assert inst.extended is False
        assert inst.sniff_time == 10
        assert inst.no_sniff is False
        assert inst.scanner is None

    def test_overrides_from_args(self, monkeypatch):
        inst = self._init(
            monkeypatch,
            baudrate=250000,
            bus_type="pcan",
            channel="vcan9",
            fd=True,
            extended=True,
            sniff_time=3,
            no_sniff=True,
        )
        assert inst.baudrate == 250000
        assert inst.bus_type == "pcan"
        assert inst.channel == "vcan9"
        assert inst.fd is True
        assert inst.sniff_time == 3
        assert inst.no_sniff is True

    def test_empty_bus_type_falls_back_to_socketcan(self, monkeypatch):
        inst = self._init(monkeypatch, bus_type="")
        assert inst.bus_type == "socketcan"

    def test_none_sniff_time_falls_back_to_10(self, monkeypatch):
        inst = self._init(monkeypatch, sniff_time=None)
        assert inst.sniff_time == 10


# ---------------------------------------------------------------------------
# create_conn_obj
# ---------------------------------------------------------------------------


class TestCreateConnObj:
    def test_missing_dependency_raises(self, monkeypatch):
        fake = MagicMock()
        fake.is_available = False
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", fake)
        from oida.utils.exceptions import DependencyError

        inst = _make_conn()
        with pytest.raises(DependencyError):
            inst.create_conn_obj()

    def test_successful_connect_sets_conn(self, monkeypatch):
        fake = MagicMock()
        fake.is_available = True
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", fake)
        fake_bus = MagicMock(name="bus")
        scanner_cls = MagicMock(name="CANScanner")
        scanner_cls.return_value.connect.return_value = fake_bus
        monkeypatch.setattr("oida.protocols.can.cli_runner.CANScanner", scanner_cls)

        inst = _make_conn(filter_id="0x123", uds_scan=True)
        inst.conn = None
        inst.create_conn_obj()

        assert inst.conn is fake_bus
        # CANScanner built from the connection's parsed options
        args_dict = scanner_cls.call_args.args[0]
        assert args_dict["channel"] == "vcan0"
        assert args_dict["bus-type"] == "socketcan"
        assert args_dict["filter-id"] == "0x123"
        inst.logger.success.assert_called_once()

    def test_failed_connect_logs_fail(self, monkeypatch):
        fake = MagicMock()
        fake.is_available = True
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", fake)
        scanner_cls = MagicMock(name="CANScanner")
        scanner_cls.return_value.connect.return_value = None
        monkeypatch.setattr("oida.protocols.can.cli_runner.CANScanner", scanner_cls)

        inst = _make_conn()
        inst.conn = None
        inst.create_conn_obj()

        assert inst.conn is None
        inst.logger.fail.assert_called_once()


# ---------------------------------------------------------------------------
# proto_flow orchestration
# ---------------------------------------------------------------------------


class TestProtoFlow:
    """proto_flow runs end-to-end with only the external boundary mocked:
    _python_can availability and the Layer-1 CANScanner whose connect()
    yields the bus. create_conn_obj itself runs unmodified."""

    def _wire_scanner(self, monkeypatch, connect_result):
        fake = MagicMock()
        fake.is_available = True
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", fake)
        scanner_cls = MagicMock(name="CANScanner")
        scanner_cls.return_value.connect.return_value = connect_result
        monkeypatch.setattr("oida.protocols.can.cli_runner.CANScanner", scanner_cls)
        return scanner_cls

    def test_proto_flow_connect_failure_marks_unsuccessful(self, monkeypatch):
        self._wire_scanner(monkeypatch, connect_result=None)
        inst = _make_conn()
        inst.conn = None
        inst.proto_flow()
        assert inst.results["success"] is False
        inst.logger.fail.assert_called()

    def test_proto_flow_runs_enum_and_features(self, monkeypatch):
        fake_bus = MagicMock(name="bus")
        scanner_cls = self._wire_scanner(monkeypatch, connect_result=fake_bus)
        # no_sniff avoids the sniff path; route to UDS scan instead
        inst = _make_conn(no_sniff=True, uds_scan=True, confirm=True)
        inst.no_sniff = True
        inst.conn = None
        scanner_cls.return_value._scan_uds.return_value = []
        inst.proto_flow()
        # enum_host_info ran against the freshly connected bus
        assert inst.results["data"]["interface"] == "vcan0"
        # the feature dispatch reached the UDS scan
        scanner_cls.return_value._scan_uds.assert_called_once()


# ---------------------------------------------------------------------------
# OBD-II probing
# ---------------------------------------------------------------------------


class TestHandleOBD2:
    def _msg_cls(self, monkeypatch):
        fake = MagicMock()
        monkeypatch.setattr("oida.protocols.can.cli_runner._python_can", fake)
        return fake

    def test_obd2_send_failure_aborts(self, monkeypatch):
        self._msg_cls(monkeypatch)
        inst = _make_conn()
        inst.conn.send.side_effect = RuntimeError("bus off")
        inst._handle_obd2()
        inst.logger.fail.assert_called_once()
        assert "obd2" not in inst.results["data"]

    def test_obd2_parses_supported_pids(self, monkeypatch):
        self._msg_cls(monkeypatch)
        inst = _make_conn()

        # Mode 01 PID 00 response: bit 0 set => PID 1 supported
        resp = SimpleNamespace(
            arbitration_id=0x7E8,
            data=bytes([0x06, 0x41, 0x00, 0x80, 0x00, 0x00, 0x00]),
        )
        # First recv returns the PID response, then None to end the loop
        recv_results = [resp] + [None] * 50
        inst.conn.recv.side_effect = recv_results
        # isotp_recv (VIN read) returns nothing
        inst.isotp_recv = MagicMock(return_value=None)

        inst._handle_obd2()

        obd2 = inst.results["data"]["obd2"]
        assert "0x7E8" in obd2
        pids = obd2["0x7E8"]["supported_pids"]
        assert any(p["pid"] == "0x01" for p in pids)

    def test_obd2_reads_vin(self, monkeypatch):
        self._msg_cls(monkeypatch)
        inst = _make_conn()
        inst.conn.recv.return_value = None  # no PID responses
        # De-framed Mode 09 PID 02 reply: [0x49, 0x02, NODI, <vin ascii>]
        vin_payload = bytes([0x49, 0x02, 0x01]) + b"1HGCM82633A004352"
        inst.isotp_recv = MagicMock(return_value=(0x7E8, vin_payload))

        inst._handle_obd2()

        assert inst.results["data"]["obd2"]["VIN"] == "1HGCM82633A004352"

    def test_obd2_no_responses(self, monkeypatch):
        self._msg_cls(monkeypatch)
        inst = _make_conn()
        inst.conn.recv.return_value = None
        inst.isotp_recv = MagicMock(return_value=None)
        inst._handle_obd2()
        assert inst.results["data"]["obd2"] == {}


# ---------------------------------------------------------------------------
# Continuous monitor (blocking loop bounded by duration)
# ---------------------------------------------------------------------------


class TestHandleMonitor:
    def test_monitor_bounded_by_duration_and_logs(self, monkeypatch):
        inst = _make_conn(duration=999, on_change=False, log_file=None)
        # Empty bus then Ctrl+C -> clean exit through the finally summary
        inst.conn.recv.side_effect = [None, KeyboardInterrupt()]
        inst._handle_monitor()
        # The "Monitor stopped" summary always prints
        msgs = [c.args[0] for c in inst.logger.display.call_args_list]
        assert any("Monitor stopped" in m for m in msgs)

    def test_monitor_writes_messages_and_log_file(self, tmp_path, monkeypatch):
        log_path = tmp_path / "mon.log"
        inst = _make_conn(duration=999, on_change=False, log_file=str(log_path))

        msg = SimpleNamespace(
            arbitration_id=0x123,
            data=b"\xde\xad",
            dlc=2,
            is_extended_id=False,
        )
        # One message, then KeyboardInterrupt to break out of the loop
        inst.conn.recv.side_effect = [msg, KeyboardInterrupt()]

        inst._handle_monitor()

        # Frame line displayed and log file written + closed
        msgs = [c.args[0] for c in inst.logger.display.call_args_list]
        assert any("0x123" in m for m in msgs)
        assert log_path.exists()
        assert "123#dead" in log_path.read_text()

    def test_monitor_on_change_filters_duplicates(self, monkeypatch):
        inst = _make_conn(duration=999, on_change=True, log_file=None)
        same = SimpleNamespace(arbitration_id=0x200, data=b"\x01", dlc=1, is_extended_id=False)
        dup = SimpleNamespace(arbitration_id=0x200, data=b"\x01", dlc=1, is_extended_id=False)
        inst.conn.recv.side_effect = [same, dup, KeyboardInterrupt()]
        inst._handle_monitor()
        # Only the first frame for 0x200 is displayed (the dup is filtered)
        frame_lines = [
            c.args[0] for c in inst.logger.display.call_args_list if "0x200" in c.args[0]
        ]
        assert len(frame_lines) == 1
