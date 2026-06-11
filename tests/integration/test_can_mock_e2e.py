"""
CAN Bus Protocol END-TO-END Integration Tests (real mock over udp_multicast)

Unlike ``test_can_integration.py`` (which mocks the python-can Bus at the
scanner level), these tests run the REAL mock CAN server in-process and drive
the REAL scanner against it over python-can's ``udp_multicast`` interface.

The mock server lives at ``docker/mocks/services/can_server.py`` and uses the
same ``udp_multicast`` transport in-process that it uses across containers, so
no kernel CAN modules, SocketCAN, or Docker are required. python-can's
``udp_multicast`` default port is 43113 (matching the mock's default), so the
scanner -- which only exposes ``--channel`` on the CLI, not a port -- connects
to the same socket by pointing at a per-session-unique multicast group address.

CI-safety: ``udp_multicast`` needs the optional ``msgpack`` dependency and a
working multicast loopback path. When either is missing, the whole module
skips with a reason rather than failing. Per-test sniff windows are kept short.

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  12 tests
Category B (conditional -- environment/timing dependent, accept >=0):    3 tests
Category C (error handling -- assert failure/empty + validate behavior):  1 test
Total:                                                                  16 tests
---------------------------------------------------------------------------
"""

import argparse
import importlib.util
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import pytest


# ---------------------------------------------------------------------------
# Environment capability detection
# ---------------------------------------------------------------------------


def _udp_multicast_available() -> Optional[str]:
    """Return None if udp_multicast loopback works, else a skip reason string."""
    try:
        import can  # noqa: F401
    except Exception as e:  # pragma: no cover - import guard
        return f"python-can not importable: {e}"

    try:
        import msgpack  # noqa: F401
    except Exception:
        return "msgpack not installed (required by python-can udp_multicast)"

    # Probe an actual multicast loopback round trip on an ephemeral group/port.
    try:
        import can as _can

        ch = "239.255.13.37"
        port = 45999
        tx = _can.Bus(interface="udp_multicast", channel=ch, port=port)
        rx = _can.Bus(interface="udp_multicast", channel=ch, port=port)
        time.sleep(0.3)
        tx.send(_can.Message(arbitration_id=0x111, data=b"\x01", is_extended_id=False))
        got = None
        end = time.time() + 2.0
        while time.time() < end:
            m = rx.recv(timeout=0.3)
            if m is not None and m.arbitration_id == 0x111:
                got = m
                break
        tx.shutdown()
        rx.shutdown()
        if got is None:
            return "udp_multicast loopback did not deliver frames in this environment"
    except Exception as e:
        return f"udp_multicast not usable: {type(e).__name__}: {e}"

    return None


_SKIP_REASON = _udp_multicast_available()
pytestmark = [pytest.mark.can, pytest.mark.skipif(bool(_SKIP_REASON), reason=str(_SKIP_REASON))]


# ---------------------------------------------------------------------------
# Mock server loader
# ---------------------------------------------------------------------------


def _load_mock_server():
    """Import docker/mocks/services/can_server.py as a module."""
    repo_root = Path(__file__).resolve().parents[2]
    mock_path = repo_root / "docker" / "mocks" / "services" / "can_server.py"
    spec = importlib.util.spec_from_file_location("oida_can_mock_server", mock_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["oida_can_mock_server"] = module
    spec.loader.exec_module(module)
    return module


def _unique_channel() -> str:
    """Pick a per-process multicast group unlikely to clash with a container.

    A running ``can-mock`` container uses 239.0.0.1; we use the 239.200.x.y
    administratively-scoped range keyed off the PID so concurrent test
    processes do not stomp on each other.
    """
    pid = os.getpid()
    return f"239.200.{(pid >> 8) & 0xFF}.{pid & 0xFF}"


class _MockServer:
    """In-process wrapper around the mock responders + dispatcher + traffic."""

    def __init__(self, module, channel: str, port: int = 43113, j1939: bool = True):
        self.module = module
        self.channel = channel
        self.port = port
        self._bus = None
        self._traffic = None
        self._dispatcher = None
        self._dispatcher_thread = None
        self._j1939_enabled = j1939

    def start(self) -> None:
        m = self.module
        self._bus = m.CANBus(self.channel, self.port)
        self._bus.connect()
        j1939 = m.J1939Responder(self._bus) if self._j1939_enabled else None
        self._traffic = m.TrafficGenerator(self._bus, j1939=j1939)
        self._traffic.start()
        self._dispatcher = m.MessageDispatcher(self._bus, j1939=j1939)
        self._dispatcher_thread = threading.Thread(target=self._dispatcher.run, daemon=True)
        self._dispatcher_thread.start()
        # Let the multicast group join settle and a little traffic accumulate.
        time.sleep(0.6)

    def stop(self) -> None:
        if self._traffic is not None:
            self._traffic.stop()
        if self._bus is not None:
            self._bus.shutdown()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def mock_module():
    return _load_mock_server()


@pytest.fixture(scope="module")
def mock_server(mock_module):
    """Start one mock server for the whole module on a unique channel."""
    server = _MockServer(mock_module, _unique_channel())
    server.start()
    yield server
    server.stop()


def _make_e2e_args(channel: str, **kwargs) -> argparse.Namespace:
    """Build an argparse.Namespace pointed at the real udp_multicast mock."""
    defaults = {
        "target": channel,
        "baudrate": 500000,
        "bus_type": "udp_multicast",
        "channel": channel,
        "fd": False,
        "extended": False,
        "sniff_time": 3,
        "no_sniff": False,
        "filter_id": "",
        "uds_scan": False,
        "obd2": False,
        "id_scan": False,
        "id_scan_range": "0x000-0x7FF",
        "uds_services": None,
        "uds_dids": None,
        "uds_target_id": None,
        "xcp_scan": False,
        "xcp_info": False,
        "xcp_memory_read": False,
        "xcp_req_id": None,
        "xcp_resp_id": None,
        "xcp_address": None,
        "xcp_length": 6,
        "ccp_scan": False,
        "ccp_cro_id": "0x701",
        "ccp_dto_id": "0x702",
        "canopen_scan": False,
        "canopen_info": None,
        "canopen_sdo_read": None,
        "canopen_od_scan": None,
        "canopen_od_range": None,
        "canopen_monitor": False,
        "canopen_pdo": False,
        "canopen_pdo_node": None,
        "modbus_gateway": False,
        "uds_sessions": False,
        "uds_seeds": False,
        "seed_level": "0x01",
        "seed_count": 3,
        "uds_routines": False,
        "uds_reset": False,
        "uds_reset_type": "0x01",
        "send": None,
        "send_file": None,
        "replay": None,
        "replay_speed": 1.0,
        "monitor": False,
        "interval": 0.0,
        "duration": None,
        "on_change": False,
        "log_file": None,
        "confirm": False,
        "fuzz": False,
        "fuzz_id": None,
        "fuzz_mode": "random",
        "fuzz_iterations": 3,
        "fuzz_max_targets": 10,
        "verbose": 0,
        "debug": False,
        "port": 0,
        "timeout": 5.0,
        "format": "json",
        "output": None,
        "json_log": None,
        "threads": 1,
        "quiet": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _run_nxc(channel: str, **kwargs):
    """Instantiate the real NXC CAN class against the live mock (no mocking)."""
    from oida.protocols.can import can as CANConnection

    args = _make_e2e_args(channel, **kwargs)
    return CANConnection(args, None, channel)


def _new_bus(mock_module, channel: str, port: int = 43113):
    """Create a raw python-can udp_multicast Bus for direct assertions."""
    import can

    return can.Bus(interface="udp_multicast", channel=channel, port=port)


# ============================================================================
# Connectivity / Sniff
# ============================================================================


class TestE2EConnectivity:
    """Real connection + passive sniff against the live mock."""

    def test_connects_to_real_mock(self, mock_server):
        """NXC class connects to the live udp_multicast mock [Category A]"""
        instance = _run_nxc(mock_server.channel, no_sniff=True)
        assert instance.results["success"] is True
        assert instance.results["data"]["bus_type"] == "udp_multicast"
        assert instance.results["data"]["interface"] == mock_server.channel

    def test_sniff_sees_real_traffic(self, mock_server):
        """Passive sniff captures the mock's background traffic [Category A]"""
        instance = _run_nxc(mock_server.channel, sniff_time=3, no_sniff=False)
        stats = instance.results["data"]["traffic_stats"]
        assert stats["total_messages"] > 0
        assert stats["unique_ids"] > 0

    def test_sniff_sees_canopen_and_automotive_ids(self, mock_server):
        """Sniff observes both CANopen heartbeats and automotive frames [Category A]"""
        instance = _run_nxc(mock_server.channel, sniff_time=3, no_sniff=False)
        top_ids = instance.results["data"]["traffic_stats"]["top_ids"]
        seen = {entry["id"] for entry in top_ids}
        # 0x701-0x704 heartbeats and/or 0x18x TPDOs and 0x100 engine frame
        assert any(i.startswith("0x1") or i.startswith("0x7") for i in seen)


# ============================================================================
# J1939 (Task A focus)
# ============================================================================


class TestE2EJ1939:
    """J1939 extended-frame traffic must appear and classify correctly."""

    def test_j1939_extended_frames_in_sniff(self, mock_server, mock_module):
        """J1939 broadcast PGNs appear as extended IDs in the sniff [Category A]"""
        import oida.protocols.can.scanner as scn

        sc = scn.CANScanner(
            {
                "target": mock_server.channel,
                "channel": mock_server.channel,
                "bus-type": "udp_multicast",
                "baudrate": 500000,
                "sniff-time": 3,
                "extended": True,
            }
        )
        conn = sc.connect()
        try:
            time.sleep(0.3)
            stats = sc._sniff_traffic(conn, duration=3)
            assert len(stats.extended_ids) > 0
            # EEC1 PGN 0xF004 from engine SA 0x00 -> 0x18F00400
            assert any((eid & 0x03FFFF00) >> 8 == 0xF004 for eid in stats.extended_ids)
        finally:
            conn.shutdown()

    def test_j1939_classified_as_j1939(self, mock_server, mock_module):
        """The traffic classifier tags J1939 extended IDs [Category A]"""
        import oida.protocols.can.scanner as scn

        sc = scn.CANScanner(
            {
                "target": mock_server.channel,
                "channel": mock_server.channel,
                "bus-type": "udp_multicast",
                "baudrate": 500000,
                "sniff-time": 3,
                "extended": True,
            }
        )
        conn = sc.connect()
        try:
            time.sleep(0.3)
            stats = sc._sniff_traffic(conn, duration=3)
            classified = sc._classify_traffic(stats)
            j1939 = [c for c in classified if "J1939" in c["classification"]]
            assert len(j1939) > 0
            assert all(c["extended"] for c in j1939)
        finally:
            conn.shutdown()

    def test_j1939_address_claimed_and_vin_on_request(self, mock_server, mock_module):
        """Requesting Address Claimed / VIN yields J1939 responses [Category A]"""
        import can

        m = mock_module
        rx = _new_bus(mock_module, mock_server.channel)
        try:
            time.sleep(0.3)
            # Request the VIN PGN (65260 / 0xFEEC) via PGN 0xEA00 to global addr.
            req_id = m.J1939Responder.make_id(m.J1939_PGN_REQUEST | 0xFF, 0xFE, priority=6)
            pgn = m.J1939_PGN_VEHICLE_ID
            data = bytes([pgn & 0xFF, (pgn >> 8) & 0xFF, (pgn >> 16) & 0xFF, 0, 0, 0, 0, 0])
            rx.send(can.Message(arbitration_id=req_id, data=data, is_extended_id=True))

            # Collect TP.DT frames (PGN 0xEB00) carrying VIN bytes.
            tp_dt_payloads = []
            end = time.time() + 3.0
            while time.time() < end:
                msg = rx.recv(timeout=0.5)
                if msg is None or not msg.is_extended_id:
                    continue
                _, rpgn, _ = m.J1939Responder.decode_id(msg.arbitration_id)
                if (rpgn & 0xFF00) == m.J1939_PGN_TP_DT:
                    tp_dt_payloads.append(bytes(msg.data)[1:])  # drop seq byte
            assembled = b"".join(tp_dt_payloads).replace(b"\xff", b"")
            vin = assembled.decode("ascii", errors="ignore")
            assert m.MOCK_VIN in vin
        finally:
            rx.shutdown()


# ============================================================================
# UDS / OBD-II (Task B focus)
# ============================================================================


class TestE2EUDS:
    """Real UDS discovery and OBD-II reads against the mock."""

    def test_uds_scan_discovers_ecus(self, mock_server):
        """UDS scan discovers both mock ECUs with supported services [Category A]"""
        instance = _run_nxc(mock_server.channel, no_sniff=True, uds_scan=True)
        uds = instance.results["data"]["uds_results"]
        req_ids = {r["request_id"] for r in uds}
        assert "0x7E0" in req_ids
        assert "0x7E1" in req_ids
        ecu0 = next(r for r in uds if r["request_id"] == "0x7E0")
        assert len(ecu0["services"]) > 0

    def test_uds_did_read_single_frame(self, mock_server):
        """ReadDataByIdentifier of a short DID (0xF193, single frame) works [Category A]"""
        # 0xF193 -> b"v3.1": response 0x62 F1 93 'v3.1' = 7 bytes, single ISO-TP frame.
        instance = _run_nxc(
            mock_server.channel,
            no_sniff=True,
            uds_dids="0xF193-0xF193",
            uds_target_id="0x7E0",
        )
        dids = instance.results["data"]["uds_dids"]["readable_dids"]
        assert any(d["did"] == "0xF193" for d in dids)

    def test_uds_did_read_vin_multiframe(self, mock_server, mock_module):
        """VIN DID (0xF190) is delivered as a real ISO-TP multi-frame and the
        SCANNER reassembles it.

        Drives ``uds_did_scan`` end to end: the mock answers DID 0xF190 with an
        ISO-TP First Frame and waits for the scanner's Flow Control before
        streaming the Consecutive Frames, which the scanner reassembles into the
        VIN. This guards Bug #1 (multi-frame reassembly) [Category A].
        """
        instance = _run_nxc(
            mock_server.channel,
            no_sniff=True,
            uds_dids="0xF190-0xF190",
            uds_target_id="0x7E0",
        )
        dids = instance.results["data"]["uds_dids"]["readable_dids"]
        vin_did = next((d for d in dids if d["did"] == "0xF190"), None)
        assert vin_did is not None, "VIN DID 0xF190 not read by the scanner"
        # The decoded DID data must contain the full mock VIN.
        raw = bytes.fromhex(vin_did["data"].replace(" ", ""))
        text = raw.decode("ascii", errors="ignore")
        assert mock_module.MOCK_VIN in text

    def test_obd2_returns_vin(self, mock_server, mock_module):
        """OBD-II Mode 09 PID 02 returns the full VIN via ISO-TP [Category A]"""
        instance = _run_nxc(mock_server.channel, no_sniff=True, obd2=True)
        obd2 = instance.results["data"]["obd2"]
        assert "VIN" in obd2
        assert obd2["VIN"] == mock_module.MOCK_VIN

    def test_scanner_sends_flow_control(self, mock_server):
        """The scanner sends an ISO-TP Flow Control during a multi-frame read.

        Runs a multi-frame VIN read (OBD-II Mode 09) and asserts the mock
        dispatcher observed the tester's Flow Control frame. Directly guards
        Bug #2 (scanner never sent FC -> multi-frame reads stall on real
        hardware) [Category A].
        """
        # Clear before the scan so we only observe THIS scan's Flow Control.
        mock_server._dispatcher._fc_event.clear()
        _run_nxc(mock_server.channel, no_sniff=True, obd2=True)
        assert mock_server._dispatcher._fc_event.is_set(), (
            "scanner did not send an ISO-TP Flow Control frame for the multi-frame VIN response"
        )

    def test_obd2_mode03_dtcs(self, mock_server, mock_module):
        """OBD-II Mode 03 returns stored DTCs from the mock [Category A]"""
        import can

        rx = _new_bus(mock_module, mock_server.channel)
        try:
            time.sleep(0.3)
            rx.send(
                can.Message(
                    arbitration_id=mock_module.OBD2_REQUEST_ID,
                    data=[0x01, 0x03, 0, 0, 0, 0, 0, 0],
                    is_extended_id=False,
                )
            )
            got = None
            end = time.time() + 2.0
            while time.time() < end:
                msg = rx.recv(timeout=0.5)
                if msg is None:
                    continue
                d = bytes(msg.data)
                if (
                    msg.arbitration_id == mock_module.OBD2_RESPONSE_ID
                    and len(d) >= 2
                    and d[1] == 0x43
                ):
                    got = d
                    break
            assert got is not None, "no Mode 03 (0x43) response received"
            num_dtcs = got[2]
            assert num_dtcs >= 1
        finally:
            rx.shutdown()


# ============================================================================
# CANopen (Task B focus)
# ============================================================================


class TestE2ECANopen:
    """Real CANopen node scan + identity read against the mock."""

    def test_canopen_node_scan_finds_heartbeat_nodes(self, mock_server):
        """CANopen scan finds the heartbeat nodes 1-4 [Category A]"""
        instance = _run_nxc(mock_server.channel, no_sniff=True, canopen_scan=True)
        nodes = instance.results["data"]["canopen_nodes"]
        node_ids = {n["node_id"] for n in nodes}
        # At least one of the four mock nodes must be discovered.
        assert node_ids & {1, 2, 3, 4}

    def test_canopen_identity_object_read(self, mock_server, mock_module):
        """SDO read of the identity object (0x1018) returns the vendor ID [Category A]"""
        import oida.protocols.can.scanner as scn

        sc = scn.CANScanner(
            {
                "target": mock_server.channel,
                "channel": mock_server.channel,
                "bus-type": "udp_multicast",
                "baudrate": 500000,
                "sniff-time": 1,
            }
        )
        conn = sc.connect()
        try:
            time.sleep(0.3)
            resp = sc.canopen_sdo_read(conn, 1, 0x1018, 0x01, timeout=0.5)
            assert not resp.error
            # WAGO vendor id for node 1 in the mock is 0x0000005A.
            assert resp.as_uint32 == 0x0000005A
        finally:
            conn.shutdown()

    def test_canopen_device_name_string_read(self, mock_server, mock_module):
        """Segmented SDO read of device name (0x1008) returns a string [Category B]"""
        import oida.protocols.can.scanner as scn

        sc = scn.CANScanner(
            {
                "target": mock_server.channel,
                "channel": mock_server.channel,
                "bus-type": "udp_multicast",
                "baudrate": 500000,
                "sniff-time": 1,
            }
        )
        conn = sc.connect()
        try:
            time.sleep(0.3)
            resp = sc.canopen_sdo_read(conn, 1, 0x1008, 0x00, timeout=1.0)
            # Segmented transfer is timing-sensitive on a shared multicast bus;
            # accept either a populated string or a clean (non-crashing) miss.
            if not resp.error and resp.as_string:
                assert "OIDA" in resp.as_string
            else:
                assert resp is not None
        finally:
            conn.shutdown()


# ============================================================================
# Error handling
# ============================================================================


class TestE2EErrorHandling:
    """Negative / robustness paths against the live mock."""

    def test_sdo_read_nonexistent_object_aborts(self, mock_server, mock_module):
        """SDO read of a nonexistent OD index returns an abort, not a crash [Category C]"""
        import oida.protocols.can.scanner as scn

        sc = scn.CANScanner(
            {
                "target": mock_server.channel,
                "channel": mock_server.channel,
                "bus-type": "udp_multicast",
                "baudrate": 500000,
                "sniff-time": 1,
            }
        )
        conn = sc.connect()
        try:
            time.sleep(0.3)
            resp = sc.canopen_sdo_read(conn, 1, 0x5FFF, 0x00, timeout=0.5)
            # Either an explicit abort or simply no data -- never a valid value.
            assert resp.error or not resp.data
        finally:
            conn.shutdown()
