"""
CAN bus protocol scanner (NXC-style callable class).

Controller Area Network (CAN) scanner for automotive and industrial
security testing. Supports passive traffic sniffing, UDS/OBD-II
service discovery, CANopen node detection, and raw frame operations.

Dependency: python-can >= 4.0.0
    pip install oida-ics[can]

Layer 2 (NXC-style): Instantiation triggers the full scan workflow
via proto_flow(). For standalone use, see scanner.py (Layer 1).
"""

import os
import time
from typing import Any, Dict, List, Optional

from oida.connection import SerialConnection
from oida.utils.lazy_import import lazy_import
from oida.protocols.can.constants import (
    CAN_STD_ID_MAX,
    CANOPEN_OD_ENTRIES,
    DEFAULT_BAUDRATE,
    OBD2_PIDS,
    OBD2_REQUEST_ID,
    OBD2_RESPONSE_RANGE,
    UDS_SERVICES,
    UDS_SESSIONS,
    split_traffic_key,
)
from oida.protocols.can.mixins import ISOTPMixin
from oida.protocols.can.scanner import CANScanner

_python_can = lazy_import("can", "CAN")


class can(ISOTPMixin, SerialConnection):
    """
    NXC-style CAN bus scanner (callable).

    Wraps CANScanner to provide NXC-style callable behavior where
    scanning triggers automatically via proto_flow() in __init__.

    Usage:
        args = argparse.Namespace(target='can0', ...)
        scanner = can(args, None, 'can0')
        # Scan executes automatically
    """

    name = "CAN"
    protocol_name = "CAN"
    default_port = 0  # Not applicable for CAN bus

    def __init__(self, args: Any, db: Any, host: str) -> None:
        # CAN-specific options from args
        self.baudrate = int(getattr(args, "baudrate", DEFAULT_BAUDRATE))
        self.bus_type = getattr(args, "bus_type", "socketcan") or "socketcan"
        self.channel = getattr(args, "channel", None) or host
        self.fd = getattr(args, "fd", False)
        self.extended = getattr(args, "extended", False)
        self.sniff_time = int(getattr(args, "sniff_time", None) or 10)
        self.no_sniff = getattr(args, "no_sniff", False)

        # Scanner instance (Layer 1)
        self.scanner = None

        # Trigger proto_flow via parent
        super().__init__(args, db, host)

    def proto_flow(self) -> None:
        """
        Main CAN bus scanning workflow.

        Orchestrates the scanning process:
        1. Setup logging
        2. Create connection (python-can Bus)
        3. Passive traffic sniffing
        4. Active UDS/OBD-II scanning (if requested)
        5. Send/replay operations (if requested)
        6. Monitoring mode (if requested, blocking)
        7. Fuzzing (if requested)
        """
        self.logger.debug(
            f"Starting CAN workflow on {self.channel} "
            f"(bus_type={self.bus_type}, bitrate={self.baudrate})"
        )

        # Create connection
        self.create_conn_obj()
        if not self.conn:
            self.logger.fail(f"Failed to connect to CAN interface: {self.channel}")
            self.results["success"] = False
            return

        # Enumerate basic info
        self.enum_host_info()
        self.print_host_info()

        # Execute scan features based on arguments
        self._execute_features()

    def create_conn_obj(self) -> None:
        """Create python-can Bus connection object."""
        if not _python_can.is_available:
            from oida.utils.exceptions import DependencyError

            raise DependencyError(
                "python-can library required for CAN protocol.\n"
                "Install with: pip install oida-ics[can]",
                protocol="CAN",
            )

        # Build scanner args dict
        args_dict = {
            "interface": self.channel,
            "target": self.channel,
            "baudrate": self.baudrate,
            "bus-type": self.bus_type,
            "channel": self.channel,
            "fd": self.fd,
            "extended": self.extended,
            "sniff-time": self.sniff_time,
            "filter-id": getattr(self.args, "filter_id", ""),
            "uds-scan": getattr(self.args, "uds_scan", False),
            "uds-services": getattr(self.args, "uds_services", None),
            "verbose": getattr(self.args, "verbose", 0),
            "debug": getattr(self.args, "debug", False),
        }

        self.scanner = CANScanner(args_dict)
        self.logger.info(f"Connecting to CAN bus: {self.channel} ({self.bus_type})")
        self.conn = self.scanner.connect()

        if self.conn:
            self.logger.success(
                f"Connected to CAN bus: {self.channel} ({self.bus_type}, {self.baudrate} bps)"
            )
        else:
            self.logger.fail(f"Connection failed to CAN bus: {self.channel}")

    def enum_host_info(self) -> None:
        """Enumerate CAN bus information."""
        if not self.conn:
            return

        self.results["data"]["interface"] = self.channel
        self.results["data"]["bus_type"] = self.bus_type
        self.results["data"]["baudrate"] = self.baudrate
        self.results["data"]["fd_enabled"] = self.fd

    def print_host_info(self) -> None:
        """Display additional CAN bus information.

        ``create_conn_obj`` already emitted
        "Connected to CAN bus: {channel} ({bus_type}, {baudrate} bps)";
        skip the redundant "CAN Bus: {channel}" / "Bitrate" repeats and
        print only the extra flags.
        """
        if self.fd:
            self.logger.display("    CAN FD: enabled")
        if self.extended:
            self.logger.display("    Extended IDs: enabled")

    def _execute_features(self) -> None:
        """Execute scan features based on command-line arguments."""
        if not self.conn:
            return

        # Phase 1: Passive sniffing (unless skipped)
        if not self.no_sniff:
            self._handle_sniff()

        # Phase 2: Active scanning
        if getattr(self.args, "uds_scan", False):
            self._handle_uds_scan()

        if getattr(self.args, "obd2", False):
            self._handle_obd2()

        if getattr(self.args, "id_scan", False):
            self._handle_id_scan()

        # Phase 2b: XCP/CCP protocol discovery
        if getattr(self.args, "xcp_scan", False):
            self._handle_xcp_scan()

        if getattr(self.args, "xcp_info", False):
            self._handle_xcp_info()

        if getattr(self.args, "xcp_memory_read", False):
            self._handle_xcp_memory_read()

        if getattr(self.args, "ccp_scan", False):
            self._handle_ccp_scan()

        # Phase 2c: CANopen protocol scanning
        if getattr(self.args, "canopen_scan", False):
            self._handle_canopen_scan()

        canopen_info_node = getattr(self.args, "canopen_info", None)
        if canopen_info_node:
            self._handle_canopen_info(canopen_info_node)

        canopen_sdo = getattr(self.args, "canopen_sdo_read", None)
        if canopen_sdo:
            self._handle_canopen_sdo_read(canopen_sdo)

        canopen_od_node = getattr(self.args, "canopen_od_scan", None)
        if canopen_od_node:
            self._handle_canopen_od_scan(canopen_od_node)

        if getattr(self.args, "canopen_monitor", False):
            self._handle_canopen_monitor()

        if getattr(self.args, "canopen_pdo", False):
            self._handle_canopen_pdo()

        if getattr(self.args, "modbus_gateway", False):
            self._handle_modbus_gateway()

        # Phase 2d: Enhanced UDS capabilities
        if getattr(self.args, "uds_sessions", False):
            self._handle_uds_sessions()

        uds_dids = getattr(self.args, "uds_dids", None)
        if uds_dids:
            self._handle_uds_dids(uds_dids)

        if getattr(self.args, "uds_seeds", False):
            self._handle_uds_seeds()

        if getattr(self.args, "uds_routines", False):
            self._handle_uds_routines()

        if getattr(self.args, "uds_reset", False):
            self._handle_uds_reset()

        # Phase 3: Send/replay operations
        send_spec = getattr(self.args, "send", None)
        if send_spec:
            self._handle_send(send_spec)

        send_file = getattr(self.args, "send_file", None)
        if send_file:
            self._handle_send_file(send_file)

        replay_file = getattr(self.args, "replay", None)
        if replay_file:
            self._handle_replay(replay_file)

        # Phase 4: Monitoring (blocking, runs last)
        if getattr(self.args, "monitor", False):
            self._handle_monitor()

        # Phase 5: Fuzzing (requires --confirm)
        if getattr(self.args, "fuzz", False):
            self._handle_fuzz()

    # -------------------------------------------------------------------
    # Feature handlers
    # -------------------------------------------------------------------

    def _handle_sniff(self) -> None:
        """Handle passive CAN traffic sniffing."""
        self.logger.display(f"[Sniff] Listening on {self.channel} for {self.sniff_time}s...")
        stats = self.scanner._sniff_traffic(self.conn, duration=self.sniff_time)
        self.scanner._print_traffic_stats(stats)

        # Positive result: real CAN frames were observed on the bus. CAN is
        # plaintext-by-design (no encryption/authentication at the protocol
        # layer), so confirmed live traffic is itself the finding.
        if stats.total_messages > 0:
            self.logger.security_finding(
                "No encryption",
                detail="CAN bus has no encryption or authentication",
            )

        self.results["data"]["traffic_stats"] = {
            "total_messages": stats.total_messages,
            "unique_ids": stats.unique_ids,
            "duration_seconds": stats.duration_seconds,
            "messages_per_second": stats.messages_per_second,
            "error_frames": stats.error_frames,
            "remote_frames": stats.remote_frames,
            "top_ids": [
                {
                    "id": f"0x{arb_id:08X}" if is_ext else f"0x{arb_id:03X}",
                    "count": count,
                    "extended": is_ext,
                }
                for arb_id, is_ext, count in (
                    (*split_traffic_key(key), count) for key, count in stats.get_top_ids(20)
                )
            ],
        }

    def _handle_uds_scan(self) -> None:
        """Handle UDS service discovery."""
        # --uds-scan actively probes ECUs and enumerates state-changing service
        # IDs (ECUReset 0x11, WriteDataByID 0x2E, RoutineControl 0x31,
        # RequestDownload 0x34...) whose standalone equivalents are all gated;
        # with --extended it also TesterPresent-sweeps 512+ arbitration IDs.
        # Gate it on --confirm like every other active operation in this module.
        if not self.require_confirm(
            "--uds-scan",
            detail="--uds-scan actively probes ECUs and enumerates state-changing UDS "
            "services (disruptive on a live bus) - requires --confirm",
        ):
            return
        self.logger.display("[UDS] Scanning for UDS-capable ECUs...")
        results = self.scanner._scan_uds(self.conn)

        self.results["data"]["uds_results"] = []
        for r in results:
            entry = {
                "request_id": f"0x{r.request_id:03X}",
                "response_id": f"0x{r.response_id:03X}",
                "services": [
                    {"id": f"0x{s:02X}", "name": UDS_SERVICES.get(s, "Unknown")}
                    for s in r.supported_services
                ],
                "sessions": r.diagnostic_sessions,
                "vehicle_info": r.vehicle_info,
                "negative_responses": {
                    f"0x{svc:02X}": f"0x{nrc:02X}" for svc, nrc in r.negative_responses.items()
                },
            }
            self.results["data"]["uds_results"].append(entry)

    def _handle_obd2(self) -> None:
        """Handle OBD-II service probing."""
        can_mod = _python_can()

        self.logger.display("[OBD-II] Probing OBD-II services...")

        obd2_data: Dict[str, Any] = {}

        # Send OBD-II Mode 01 PID 00 (supported PIDs)
        request_data = [0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        msg = can_mod.Message(
            arbitration_id=OBD2_REQUEST_ID,
            data=request_data,
            is_extended_id=False,
        )

        try:
            self.conn.send(msg)
        except Exception as e:
            self.logger.fail(f"OBD-II request failed: {e}")
            return

        # Collect responses
        end_time = time.time() + 1.0
        while time.time() < end_time:
            try:
                resp = self.conn.recv(timeout=0.1)
            except StopIteration:
                # An iterator-backed bus is exhausted -- no more frames to read.
                break
            except Exception as exc:
                # udp_multicast datagrams can coalesce under load, yielding
                # msgpack decode failures; skip the corrupt packet and continue.
                # python-can raises these as CanOperationError, which is not an
                # OSError/ValueError - a narrow tuple here let one coalesced
                # datagram abort the whole scan.
                self.logger.debug(f"Ignoring malformed CAN response: {exc}")
                continue
            if resp is None:
                continue

            if OBD2_RESPONSE_RANGE[0] <= resp.arbitration_id <= OBD2_RESPONSE_RANGE[1]:
                data = bytes(resp.data)
                if len(data) >= 7 and data[1] == 0x41 and data[2] == 0x00:
                    # Parse supported PIDs bitmap
                    bitmap = (data[3] << 24) | (data[4] << 16) | (data[5] << 8) | data[6]
                    supported = []
                    for bit in range(32):
                        if bitmap & (1 << (31 - bit)):
                            pid = bit + 1
                            pid_name = OBD2_PIDS.get(pid, f"PID 0x{pid:02X}")
                            supported.append({"pid": f"0x{pid:02X}", "name": pid_name})

                    ecu_id = f"0x{resp.arbitration_id:03X}"
                    obd2_data[ecu_id] = {"supported_pids": supported}
                    self.logger.display(f"  ECU {ecu_id}: {len(supported)} supported PIDs")

        # Try to read VIN (Mode 09, PID 02)
        vin_request = [0x02, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]
        msg = can_mod.Message(
            arbitration_id=OBD2_REQUEST_ID,
            data=vin_request,
            is_extended_id=False,
        )

        try:
            self.conn.send(msg)
            # VIN response uses ISO-TP multi-frame: isotp_recv sends Flow Control
            # after the First Frame and reassembles the de-framed payload. It now
            # returns (source_arbitration_id, payload); the VIN read only needs
            # the payload.
            recv = self.isotp_recv(self.conn, OBD2_REQUEST_ID, OBD2_RESPONSE_RANGE[0], timeout=1.0)
            payload = recv[1] if recv is not None else None
            # De-framed Mode 09 PID 02 response: [0x49, 0x02, NODI, <17 VIN bytes>]
            if payload and len(payload) > 3 and payload[0] == 0x49 and payload[1] == 0x02:
                try:
                    vin_str = payload[3:].decode("ascii", errors="ignore").strip("\x00")
                    if len(vin_str) >= 5:
                        obd2_data["VIN"] = vin_str
                        self.logger.display(f"  VIN: {vin_str}")
                except Exception as e:
                    self.logger.debug(f"VIN decode failed: {e}")
        except Exception as e:
            self.logger.debug(f"VIN read failed: {e}")

        if not obd2_data:
            self.logger.display("  No OBD-II responses received")

        self.results["data"]["obd2"] = obd2_data

    def _handle_id_scan(self) -> None:
        """Handle active arbitration ID scanning."""
        # --id-scan floods every standard CAN ID with TesterPresent - this
        # is loud on a live bus and can trigger flood detection / safety
        # interlocks on a vehicle bench. Gated on --confirm.
        if not self.require_confirm(
            "--id-scan",
            detail="--id-scan floods every CAN arbitration ID with TesterPresent "
            "(disruptive on live bus) - requires --confirm",
        ):
            return
        can_mod = _python_can()

        scan_range_str = getattr(self.args, "id_scan_range", "0x000-0x7FF")
        try:
            parts = scan_range_str.split("-")
            start_id = int(parts[0].strip(), 0)
            end_id = int(parts[1].strip(), 0) if len(parts) > 1 else start_id
        except (ValueError, IndexError):
            self.logger.fail(f"Invalid scan range: {scan_range_str}")
            return

        total = end_id - start_id + 1
        self.logger.display(
            f"[ID Scan] Probing {total} arbitration IDs (0x{start_id:03X}-0x{end_id:03X})..."
        )

        responding_ids: List[Dict[str, Any]] = []

        for arb_id in range(start_id, end_id + 1):
            # Send TesterPresent to each ID
            data = [0x02, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            try:
                msg = can_mod.Message(
                    arbitration_id=arb_id,
                    data=data,
                    is_extended_id=False,
                )
                self.conn.send(msg)
            except Exception as e:
                self.logger.debug(f"ID scan send 0x{arb_id:03X} failed: {e}")
                continue

            # Quick listen for response
            resp = self.scanner._recv_uds_response(self.conn, arb_id, timeout=0.02)
            if resp is not None:
                resp_id, resp_data = resp
                responding_ids.append(
                    {
                        "request_id": f"0x{arb_id:03X}",
                        "response_id": f"0x{resp_id:03X}",
                        "data": " ".join(f"{b:02X}" for b in resp_data),
                    }
                )
                self.logger.success(f"  Response: 0x{arb_id:03X} -> 0x{resp_id:03X}")

        self.logger.display(f"  {len(responding_ids)} responding IDs out of {total} probed")
        self.results["data"]["id_scan"] = responding_ids

    # -------------------------------------------------------------------
    # XCP/CCP feature handlers
    # -------------------------------------------------------------------

    def _handle_xcp_scan(self) -> None:
        """Handle XCP protocol discovery scan."""
        # scan_xcp sends a CONNECT to every arbitration ID (0x000-0x7FF) -
        # comparable bus load to --id-scan, so gate it the same way.
        if not self.require_confirm(
            "--xcp-scan",
            detail="--xcp-scan sends XCP CONNECT to every arbitration ID "
            "(disruptive on live bus) - requires --confirm",
        ):
            return
        xcp_results = self.scanner.scan_xcp(self.conn)

        self.results["data"]["xcp_results"] = []
        for r in xcp_results:
            entry = {
                "request_id": f"0x{r.request_id:03X}",
                "response_id": f"0x{r.response_id:03X}",
                "connected": r.connected,
                "xcp_version": r.xcp_version,
                "max_cto": r.max_cto,
                "max_dto": r.max_dto,
                "resource_protection": f"0x{r.resource_protection:02X}",
                "comm_mode_basic": f"0x{r.comm_mode_basic:02X}",
            }
            self.results["data"]["xcp_results"].append(entry)

    def _handle_xcp_info(self) -> None:
        """Handle XCP info gathering on a specific slave."""
        xcp_req = getattr(self.args, "xcp_req_id", None)
        xcp_resp = getattr(self.args, "xcp_resp_id", None)

        if not xcp_req or not xcp_resp:
            self.logger.fail("--xcp-info requires --xcp-req-id and --xcp-resp-id")
            return

        try:
            req_id = int(xcp_req, 0)
            resp_id = int(xcp_resp, 0)
        except ValueError:
            self.logger.fail("Invalid XCP arb IDs")
            return

        result = self.scanner.xcp_get_info(self.conn, req_id, resp_id)
        self.results["data"]["xcp_info"] = {
            "request_id": f"0x{result.request_id:03X}",
            "response_id": f"0x{result.response_id:03X}",
            "connected": result.connected,
            "xcp_version": result.xcp_version,
            "transport_version": result.transport_version,
            "identification": result.identification,
            "status": result.status,
            "max_cto": result.max_cto,
            "max_dto": result.max_dto,
            "comm_mode_basic": f"0x{result.comm_mode_basic:02X}",
            "error": result.error,
        }

    def _handle_xcp_memory_read(self) -> None:
        """Handle XCP memory read (requires --confirm)."""
        if not self.require_confirm(
            "--confirm",
            detail="XCP memory read requires --confirm flag. This actively reads ECU memory!",
        ):
            return
        xcp_req = getattr(self.args, "xcp_req_id", None)
        xcp_resp = getattr(self.args, "xcp_resp_id", None)
        xcp_addr = getattr(self.args, "xcp_address", None)
        xcp_len = getattr(self.args, "xcp_length", 6)

        if not xcp_req or not xcp_resp or xcp_addr is None:
            self.logger.fail(
                "--xcp-memory-read requires --xcp-req-id, --xcp-resp-id, and --xcp-address"
            )
            return

        try:
            req_id = int(xcp_req, 0)
            resp_id = int(xcp_resp, 0)
            address = int(xcp_addr, 0)
            length = int(xcp_len)
        except ValueError:
            self.logger.fail("Invalid XCP memory read parameters")
            return

        data = self.scanner.xcp_memory_read(self.conn, req_id, resp_id, address, length)
        self.results["data"]["xcp_memory_read"] = {
            "address": f"0x{address:08X}",
            "length": length,
            "data": " ".join(f"{b:02X}" for b in data) if data else None,
        }

    def _handle_ccp_scan(self) -> None:
        """Handle CCP protocol discovery scan."""
        # scan_ccp broadcasts CONNECT across all 256 station addresses -
        # comparable bus load to --id-scan, so gate it the same way.
        if not self.require_confirm(
            "--ccp-scan",
            detail="--ccp-scan sends CCP CONNECT to all 256 station addresses "
            "(disruptive on live bus) - requires --confirm",
        ):
            return
        cro_id = int(getattr(self.args, "ccp_cro_id", None) or "0x701", 0)
        dto_id = int(getattr(self.args, "ccp_dto_id", None) or "0x702", 0)

        ccp_results = self.scanner.scan_ccp(self.conn, cro_id=cro_id, dto_id=dto_id)

        self.results["data"]["ccp_results"] = []
        for r in ccp_results:
            entry = {
                "cro_id": f"0x{r.cro_id:03X}",
                "dto_id": f"0x{r.dto_id:03X}",
                "station_address": r.station_address,
                "connected": r.connected,
                "ccp_version": r.ccp_version,
            }
            self.results["data"]["ccp_results"].append(entry)

    # -------------------------------------------------------------------
    # Enhanced UDS feature handlers
    # -------------------------------------------------------------------

    def _handle_uds_sessions(self) -> None:
        """Handle UDS session enumeration (requires --confirm)."""
        if not self.require_confirm(
            "--uds-sessions",
            detail="--uds-sessions switches the ECU into programming/extended "
            "diagnostic sessions (disruptive on a live bus) - requires --confirm",
        ):
            return
        req_id = self._get_uds_target_id()
        if req_id is None:
            return

        sessions = self.scanner.uds_session_scan(self.conn, req_id)
        self.results["data"]["uds_sessions"] = {
            "request_id": f"0x{req_id:03X}",
            "supported_sessions": [
                {
                    "id": f"0x{s:02X}",
                    "name": UDS_SESSIONS.get(s, f"VendorSpecific(0x{s:02X})"),
                }
                for s in sessions
            ],
        }

    def _handle_uds_dids(self, did_range_str: str) -> None:
        """Handle UDS DID enumeration."""
        req_id = self._get_uds_target_id()
        if req_id is None:
            return

        # Parse DID range
        did_range = None
        if did_range_str and did_range_str != "true":
            try:
                parts = did_range_str.split("-")
                start_did = int(parts[0].strip(), 0)
                end_did = int(parts[1].strip(), 0) if len(parts) > 1 else start_did
                did_range = (start_did, end_did)
            except (ValueError, IndexError):
                self.logger.fail(f"Invalid DID range: {did_range_str}")
                return

        readable = self.scanner.uds_did_scan(self.conn, req_id, did_range=did_range)

        from oida.protocols.can.constants import UDS_STANDARD_DIDS

        self.results["data"]["uds_dids"] = {
            "request_id": f"0x{req_id:03X}",
            "readable_dids": [
                {
                    "did": f"0x{did:04X}",
                    "name": UDS_STANDARD_DIDS.get(did, f"DID 0x{did:04X}"),
                    "data": " ".join(f"{b:02X}" for b in data),
                }
                for did, data in readable.items()
            ],
        }

    def _handle_uds_seeds(self) -> None:
        """Handle UDS SecurityAccess seed collection."""
        req_id = self._get_uds_target_id()
        if req_id is None:
            return

        level = getattr(self.args, "seed_level", 0x01)
        count = getattr(self.args, "seed_count", 10)

        if isinstance(level, str):
            level = int(level, 0)
        count = int(count)

        seeds = self.scanner.uds_security_seed_collect(
            self.conn,
            req_id,
            security_level=level,
            count=count,
        )

        self.results["data"]["uds_seeds"] = {
            "request_id": f"0x{req_id:03X}",
            "security_level": f"0x{level:02X}",
            "count": len(seeds),
            "seeds": [" ".join(f"{b:02X}" for b in s) for s in seeds],
        }

    def _handle_uds_routines(self) -> None:
        """Handle UDS RoutineControl enumeration (requires --confirm)."""
        if not self.require_confirm(
            "--uds-routines",
            detail="--uds-routines runs RoutineControl startRoutine (executes ECU "
            "routines: actuator tests, resets) - requires --confirm",
        ):
            return
        req_id = self._get_uds_target_id()
        if req_id is None:
            return

        routines = self.scanner.uds_routine_scan(self.conn, req_id)
        self.results["data"]["uds_routines"] = {
            "request_id": f"0x{req_id:03X}",
            "routines": [f"0x{r:04X}" for r in routines],
        }

    def _handle_uds_reset(self) -> None:
        """Handle UDS ECUReset (requires --confirm)."""
        if not self.require_confirm(
            "--confirm", detail="ECU reset requires --confirm flag. This will reset the target ECU!"
        ):
            return
        req_id = self._get_uds_target_id()
        if req_id is None:
            return

        reset_type = getattr(self.args, "uds_reset_type", 0x01)
        if isinstance(reset_type, str):
            reset_type = int(reset_type, 0)

        success = self.scanner.uds_ecu_reset(self.conn, req_id, reset_type=reset_type)
        self.results["data"]["uds_reset"] = {
            "request_id": f"0x{req_id:03X}",
            "reset_type": f"0x{reset_type:02X}",
            "success": success,
        }

    def _get_uds_target_id(self) -> Optional[int]:
        """Get the UDS target request arbitration ID from args."""
        target_id = getattr(self.args, "uds_target_id", None)
        if target_id:
            try:
                return int(target_id, 0)
            except ValueError:
                self.logger.fail(f"Invalid --uds-target-id: {target_id}")
                return None

        # Default to 0x7E0 (ECU #1)
        self.logger.display("  Using default UDS target ID 0x7E0 (use --uds-target-id to override)")
        return 0x7E0

    # -------------------------------------------------------------------
    # CANopen feature handlers
    # -------------------------------------------------------------------

    def _handle_canopen_scan(self) -> None:
        """Handle full CANopen network scan."""
        nodes = self.scanner.canopen_node_scan(self.conn)

        # Gather device info for each discovered node
        detailed_nodes = []
        for node in nodes:
            info = self.scanner.canopen_device_info(self.conn, node.node_id)
            # Merge heartbeat-detected state with SDO-read info
            info.nmt_state = node.nmt_state
            info.nmt_state_name = node.nmt_state_name
            detailed_nodes.append(info)

        self.results["data"]["canopen_nodes"] = []
        for n in detailed_nodes:
            entry = {
                "node_id": n.node_id,
                "nmt_state": n.nmt_state_name,
                "device_type": f"0x{n.device_type:08X}" if n.device_type else "",
                "device_profile": n.device_profile_name,
                "device_name": n.device_name,
                "hw_version": n.hw_version,
                "sw_version": n.sw_version,
                "vendor_id": f"0x{n.vendor_id:08X}" if n.vendor_id else "",
                "vendor_name": n.vendor_name,
                "product_code": f"0x{n.product_code:08X}" if n.product_code else "",
                "serial_number": n.serial_number,
            }
            self.results["data"]["canopen_nodes"].append(entry)

    def _handle_canopen_info(self, node_id_str: str) -> None:
        """Handle CANopen device identification."""
        try:
            node_id = int(node_id_str, 0)
        except ValueError:
            self.logger.fail(f"Invalid node ID: {node_id_str}")
            return

        info = self.scanner.canopen_device_info(self.conn, node_id)
        self.results["data"]["canopen_info"] = {
            "node_id": info.node_id,
            "device_type": f"0x{info.device_type:08X}" if info.device_type else "",
            "device_profile": info.device_profile_name,
            "device_name": info.device_name,
            "hw_version": info.hw_version,
            "sw_version": info.sw_version,
            "vendor_id": f"0x{info.vendor_id:08X}" if info.vendor_id else "",
            "vendor_name": info.vendor_name,
            "product_code": f"0x{info.product_code:08X}" if info.product_code else "",
            "revision": f"0x{info.revision:08X}" if info.revision else "",
            "serial_number": info.serial_number,
            "error_register": f"0x{info.error_register:02X}",
            "od_entries_found": [f"0x{idx:04X}" for idx in info.od_entries_found],
        }

    def _handle_canopen_sdo_read(self, spec: str) -> None:
        """Handle SDO read operation. Format: NODE_ID:INDEX:SUBINDEX"""
        try:
            parts = spec.split(":")
            node_id = int(parts[0].strip(), 0)
            index = int(parts[1].strip(), 0)
            subindex = int(parts[2].strip(), 0) if len(parts) > 2 else 0
        except (ValueError, IndexError):
            self.logger.fail(
                f"Invalid SDO read spec: {spec} (expected NODE_ID:INDEX:SUBINDEX, e.g., 1:0x1000:0)"
            )
            return

        resp = self.scanner.canopen_sdo_read(self.conn, node_id, index, subindex)

        if resp.error:
            self.logger.fail(
                f"SDO read 0x{index:04X}:{subindex:02X} on node {node_id}: {resp.abort_message}"
            )
            self.results["data"]["canopen_sdo_read"] = {
                "node_id": node_id,
                "index": f"0x{index:04X}",
                "subindex": subindex,
                "error": resp.abort_message,
                "abort_code": f"0x{resp.abort_code:08X}" if resp.abort_code else "",
            }
        else:
            data_hex = " ".join(f"{b:02X}" for b in resp.data)
            od_name = CANOPEN_OD_ENTRIES.get(index, f"OD 0x{index:04X}")
            self.logger.success(
                f"SDO read {od_name} (0x{index:04X}:{subindex:02X}) on node {node_id}: [{data_hex}]"
            )

            # Try to display as string if appropriate
            display_val = data_hex
            if resp.as_string and all(32 <= ord(c) < 127 for c in resp.as_string):
                display_val = f'"{resp.as_string}" ({data_hex})'
            elif resp.as_uint32 is not None and len(resp.data) == 4:
                display_val = f"0x{resp.as_uint32:08X} ({resp.as_uint32}) [{data_hex}]"
            elif resp.as_uint16 is not None and len(resp.data) == 2:
                display_val = f"0x{resp.as_uint16:04X} ({resp.as_uint16}) [{data_hex}]"

            self.results["data"]["canopen_sdo_read"] = {
                "node_id": node_id,
                "index": f"0x{index:04X}",
                "subindex": subindex,
                "data": data_hex,
                "display": display_val,
            }

    def _handle_canopen_od_scan(self, node_id_str: str) -> None:
        """Handle Object Dictionary enumeration."""
        try:
            node_id = int(node_id_str, 0)
        except ValueError:
            self.logger.fail(f"Invalid node ID: {node_id_str}")
            return

        od_range_str = getattr(self.args, "canopen_od_range", None)
        od_range = None
        if od_range_str:
            try:
                parts = od_range_str.split("-")
                start = int(parts[0].strip(), 0)
                end = int(parts[1].strip(), 0) if len(parts) > 1 else start
                od_range = (start, end)
            except (ValueError, IndexError):
                self.logger.fail(f"Invalid OD range: {od_range_str}")
                return

        found = self.scanner.canopen_od_scan(self.conn, node_id, index_range=od_range)
        self.results["data"]["canopen_od_scan"] = {
            "node_id": node_id,
            "entries": [
                {
                    "index": f"0x{idx:04X}",
                    "subindex": sub,
                    "name": CANOPEN_OD_ENTRIES.get(idx, f"0x{idx:04X}"),
                    "data": " ".join(f"{b:02X}" for b in data),
                }
                for idx, sub, data in found
            ],
        }

    def _handle_canopen_monitor(self) -> None:
        """Handle EMCY + heartbeat monitoring."""
        duration = getattr(self.args, "duration", None) or 10

        # Monitor heartbeats
        hb_map = self.scanner.canopen_heartbeat_monitor(self.conn, duration=float(duration) / 2)

        # Monitor EMCY
        emcy_msgs = self.scanner.canopen_emcy_monitor(self.conn, duration=float(duration) / 2)

        self.results["data"]["canopen_monitor"] = {
            "heartbeat_nodes": {
                str(nid): {
                    "state": entry["state_name"],
                    "count": entry["count"],
                    "avg_interval_ms": entry["avg_interval_ms"],
                }
                for nid, entry in hb_map.items()
            },
            "emcy_messages": emcy_msgs,
        }

    def _handle_canopen_pdo(self) -> None:
        """Handle PDO mapping discovery."""
        node_id_str = getattr(self.args, "canopen_pdo_node", None)
        if not node_id_str:
            # Try to use first node from a scan
            self.logger.display("  No node specified, scanning for nodes...")
            nodes = self.scanner.canopen_node_scan(self.conn)
            if not nodes:
                self.logger.fail("No CANopen nodes found for PDO discovery")
                return
            node_id = nodes[0].node_id
        else:
            try:
                node_id = int(node_id_str, 0)
            except ValueError:
                self.logger.fail(f"Invalid node ID: {node_id_str}")
                return

        pdo_info = self.scanner.canopen_pdo_discover(self.conn, node_id)
        self.results["data"]["canopen_pdo"] = {
            "node_id": node_id,
            "pdo_config": pdo_info,
        }

    def _handle_modbus_gateway(self) -> None:
        """Handle Modbus gateway detection and enumeration."""
        gateways = self.scanner.canopen_modbus_gateway_detect(self.conn)

        gateway_data = []
        for gw in gateways:
            entry = {
                "node_id": gw.node_id,
                "device_name": gw.device_name,
                "gateway_type": gw.gateway_type,
                "vendor": gw.vendor_name,
                "device_profile": gw.device_profile_name,
            }

            # If a CiA 309 gateway, try to enumerate register mappings
            if gw.device_profile == 309:
                mappings = self.scanner.canopen_modbus_register_map(self.conn, gw.node_id)
                entry["register_mappings"] = {
                    f"0x{idx:04X}": " ".join(f"{b:02X}" for b in data)
                    for idx, data in mappings.items()
                }

            gateway_data.append(entry)

        self.results["data"]["modbus_gateways"] = gateway_data

    # -------------------------------------------------------------------
    # Send / Replay handlers
    # -------------------------------------------------------------------

    def _handle_send(self, spec: str) -> None:
        """Handle sending a single raw CAN frame."""
        if not self.require_confirm(
            "--send",
            detail="--send injects raw frames onto the bus (can drive actuators) - requires --confirm",
        ):
            self.results["success"] = False
            self.results["data"]["refused"] = "--send requires --confirm"
            return
        try:
            parts = spec.split("#", 1)
            arb_id = int(parts[0].strip(), 0)
            data_hex = parts[1].strip() if len(parts) > 1 else ""
            data = bytes.fromhex(data_hex.replace(" ", ""))
        except (ValueError, IndexError) as e:
            self.logger.fail(f"Invalid send format (expected ID#HEXDATA): {e}")
            self.results["success"] = False
            return

        is_ext = arb_id > CAN_STD_ID_MAX
        success = self.scanner.send_message(self.conn, arb_id, data, is_extended=is_ext)

        if success:
            id_fmt = f"0x{arb_id:08X}" if is_ext else f"0x{arb_id:03X}"
            self.logger.success(f"Sent: ID={id_fmt} Data={' '.join(f'{b:02X}' for b in data)}")

            # Listen for response
            resp_msg = self.scanner.recv_message(self.conn, timeout=1.0)
            if resp_msg:
                self.logger.display(f"  Response: ID={resp_msg.id_hex} Data={resp_msg.data_hex}")

    def _handle_send_file(self, filepath: str) -> None:
        """Handle sending CAN frames from a file."""
        if not self.require_confirm(
            "--send-file",
            detail="--send-file injects raw frames onto the bus (can drive actuators) - "
            "requires --confirm",
        ):
            self.results["success"] = False
            self.results["data"]["refused"] = "--send-file requires --confirm"
            return
        filepath = os.path.realpath(filepath)
        try:
            with open(filepath) as f:
                lines = f.readlines()
        except Exception as e:
            self.logger.fail(f"Could not read send file: {e}")
            self.results["success"] = False
            return

        sent = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self._handle_send(line)
            sent += 1

        self.logger.display(f"  Sent {sent} frames from {filepath}")

    def _handle_replay(self, filepath: str) -> None:
        """Handle replaying CAN traffic from a log file."""
        if not self.require_confirm(
            "--replay",
            detail="--replay re-sends every captured frame onto the bus (incl. write/diagnostic "
            "commands) - requires --confirm",
        ):
            self.results["success"] = False
            self.results["data"]["refused"] = "--replay requires --confirm"
            return
        can_mod = _python_can()

        speed = float(getattr(self.args, "replay_speed", 1.0))
        filepath = os.path.realpath(filepath)
        self.logger.display(f"[Replay] Replaying {filepath} (speed={speed}x)...")

        try:
            with open(filepath) as f:
                lines = f.readlines()
        except Exception as e:
            self.logger.fail(f"Could not read replay file: {e}")
            self.results["success"] = False
            return

        sent = 0
        prev_ts = None

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse candump format: (timestamp) interface ID#DATA
            try:
                parts = line.split()

                # Extract timestamp if present: (1234567890.123456)
                line_ts = None
                for part in parts:
                    if part.startswith("(") and part.endswith(")"):
                        try:
                            line_ts = float(part.strip("()"))
                        except ValueError as e:
                            self.logger.debug(f"Failed to get line_ts: {e}")
                        break

                # Apply inter-frame delay based on timestamps and speed
                if speed > 0 and line_ts is not None and prev_ts is not None:
                    delay = (line_ts - prev_ts) / speed
                    if 0 < delay < 10:  # Cap at 10s to avoid hanging
                        time.sleep(delay)
                if line_ts is not None:
                    prev_ts = line_ts

                # Find the ID#DATA part
                id_data = None
                for part in parts:
                    if "#" in part:
                        id_data = part
                        break

                if id_data is None:
                    continue

                id_str, data_str = id_data.split("#", 1)
                arb_id = int(id_str, 16)
                data = bytes.fromhex(data_str)

                is_ext = arb_id > CAN_STD_ID_MAX
                msg = can_mod.Message(
                    arbitration_id=arb_id,
                    data=data,
                    is_extended_id=is_ext,
                )
                self.conn.send(msg)
                sent += 1

            except Exception as e:
                self.logger.debug(f"Replay parse error: {e}")
                continue

        self.logger.display(f"  Replayed {sent} frames")

    def _handle_monitor(self) -> None:
        """Handle continuous CAN bus monitoring."""
        duration = getattr(self.args, "duration", None)
        on_change = getattr(self.args, "on_change", False)
        log_file = getattr(self.args, "log_file", None)

        self.logger.display("[Monitor] Continuous monitoring started (Ctrl+C to stop)...")

        log_fh = None
        if log_file:
            try:
                log_fh = open(os.path.realpath(log_file), "w")  # noqa: SIM115
                self.logger.display(f"  Logging to: {log_file}")
            except Exception as e:
                self.logger.warning(f"Could not open log file: {e}")

        last_data: Dict[int, bytes] = {}
        start_time = time.time()
        msg_count = 0

        try:
            while True:
                if duration and (time.time() - start_time) >= duration:
                    break

                try:
                    msg = self.conn.recv(timeout=1.0)
                except Exception as exc:
                    # udp_multicast datagrams can coalesce under load, yielding
                    # msgpack decode failures; skip the corrupt packet and keep
                    # monitoring rather than aborting the capture.
                    self.logger.debug(f"Ignoring malformed CAN frame: {exc}")
                    continue
                if msg is None:
                    continue

                msg_count += 1
                arb_id = msg.arbitration_id
                data = bytes(msg.data)

                # On-change filter
                if on_change:
                    if arb_id in last_data and last_data[arb_id] == data:
                        continue
                    last_data[arb_id] = data

                is_ext = msg.is_extended_id
                id_fmt = f"0x{arb_id:08X}" if is_ext else f"0x{arb_id:03X}"
                data_str = " ".join(f"{b:02X}" for b in data)
                ts = time.time() - start_time

                line = f"  [{ts:10.3f}] {id_fmt}  [{msg.dlc}]  {data_str}"
                self.logger.display(line)

                if log_fh:
                    log_fh.write(f"({time.time():.6f}) {self.channel} {arb_id:03X}#{data.hex()}\n")
                    log_fh.flush()

        except KeyboardInterrupt as e:
            self.logger.debug(f"Operation failed: {e}")
        finally:
            if log_fh:
                log_fh.close()

            elapsed = time.time() - start_time
            self.logger.display(f"  Monitor stopped. {msg_count} messages in {elapsed:.1f}s")

    def _handle_fuzz(self) -> None:
        """Handle CAN bus fuzzing (requires --confirm)."""
        if not self.require_confirm(
            "--confirm",
            detail="CAN fuzzing requires --confirm flag. This can disrupt bus operations!",
        ):
            return
        can_mod = _python_can()

        fuzz_id_str = getattr(self.args, "fuzz_id", None)
        if not fuzz_id_str:
            self.logger.fail("--fuzz-id is required for fuzzing (target arbitration ID)")
            return

        try:
            fuzz_id = int(fuzz_id_str, 0)
        except ValueError:
            self.logger.fail(f"Invalid fuzz ID: {fuzz_id_str}")
            return

        iterations = getattr(self.args, "fuzz_iterations", 10)
        fuzz_mode = getattr(self.args, "fuzz_mode", "random")
        is_ext = fuzz_id > CAN_STD_ID_MAX

        self.logger.display(
            f"[Fuzz] Target: 0x{fuzz_id:03X}, Mode: {fuzz_mode}, Iterations: {iterations}"
        )
        self.logger.warning("WARNING: Fuzzing may disrupt CAN bus operations!")

        fuzz_results = []

        for i in range(iterations):
            if fuzz_mode == "random":
                dlc = int.from_bytes(os.urandom(1), "big") % 9  # 0-8 bytes
                data = os.urandom(dlc) if dlc > 0 else b""
            elif fuzz_mode == "sequential":
                data = bytes([(i >> (j * 8)) & 0xFF for j in range(8)])
            elif fuzz_mode == "boundary":
                # Test boundary values
                boundary_cases = [
                    b"\x00" * 8,
                    b"\xff" * 8,
                    b"\x00\x00\x00\x00\xff\xff\xff\xff",
                    b"\xff\xff\xff\xff\x00\x00\x00\x00",
                    b"\x7f" * 8,
                    b"\x80" * 8,
                    b"",  # DLC=0
                    b"\x01",  # DLC=1
                ]
                data = boundary_cases[i % len(boundary_cases)]
            else:
                # Smart mode: UDS-aware payloads
                data = os.urandom(8)

            try:
                msg = can_mod.Message(
                    arbitration_id=fuzz_id,
                    data=data,
                    is_extended_id=is_ext,
                )
                self.conn.send(msg)

                # Check for response
                resp = self.scanner.recv_message(self.conn, timeout=0.05)
                response_info = None
                if resp:
                    response_info = {
                        "id": resp.id_hex,
                        "data": resp.data_hex,
                    }

                fuzz_results.append(
                    {
                        "iteration": i + 1,
                        "data": " ".join(f"{b:02X}" for b in data),
                        "response": response_info,
                    }
                )

                if resp:
                    self.logger.debug(
                        f"  Fuzz #{i + 1}: Sent {' '.join(f'{b:02X}' for b in data)} "
                        f"-> Response: {resp.data_hex}"
                    )

            except Exception as e:
                self.logger.debug(f"  Fuzz #{i + 1} failed: {e}")
                fuzz_results.append(
                    {
                        "iteration": i + 1,
                        "data": " ".join(f"{b:02X}" for b in data),
                        "error": str(e),
                    }
                )

        responses = sum(1 for r in fuzz_results if r.get("response"))
        errors = sum(1 for r in fuzz_results if r.get("error"))
        self.logger.display(
            f"  Fuzz complete: {iterations} iterations, {responses} responses, {errors} errors"
        )

        self.results["data"]["fuzz_results"] = fuzz_results

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------
    # NOTE: _assemble_isotp_data and isotp_recv are inherited from ISOTPMixin.

    def cleanup(self) -> None:
        """Clean up CAN bus connection."""
        if self.conn:
            try:
                self.conn.shutdown()
                self.logger.debug("CAN bus connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing CAN bus: {e}")
            finally:
                self.conn = None

    @staticmethod
    def check_dependencies() -> bool:
        """Check if CAN dependencies are available."""
        return _python_can.is_available
