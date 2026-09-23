"""
IEC 60870-5-104 Passive Listener (PyShark-based).

Passively monitors IEC 104 telecontrol traffic to identify:
- Controlling stations (SCADA/master) and controlled stations (RTU/slave)
- Common addresses (ASDU addresses) in use
- Type IDs (data types) observed
- Information object addresses (IOAs) with actual data values
- Quality flags (IV, NT, SB, BL, OV)
- Control commands vs monitoring data

Based on IEC 60870-5-104:2006.

Frame formats:
- I-format: Data transfer (sequence numbered)
- S-format: Supervisory (ACK only)
- U-format: Unnumbered (STARTDT, STOPDT, TESTFR)

Reference: IEC 60870-5-104:2006
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from ._iec_common import (
    CONTROL_TYPE_IDS,
    COT_NAMES,
    TYPE_IDS,
    IecAsduValueMixin,
)
from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

import logging

logger = logging.getLogger(__name__)

# U-frame types — tshark applies mask 0xfc and right-shifts by 2,
# so values are half the raw wire-format bit positions.
UTYPE_STARTDT_ACT = 0x01
UTYPE_STARTDT_CON = 0x02
UTYPE_STOPDT_ACT = 0x04
UTYPE_STOPDT_CON = 0x08
UTYPE_TESTFR_ACT = 0x10
UTYPE_TESTFR_CON = 0x20

# Quality flag abbreviations for display
_QUALITY_ABBREVS = {
    "iv": "IV",  # Invalid
    "nt": "NT",  # Not topical
    "sb": "SB",  # Substituted
    "bl": "BL",  # Blocked
    "ov": "OV",  # Overflow
}


@dataclass
class IEC104Session:
    """Track IEC 104 session statistics."""

    controlling_ip: str  # SCADA/master
    controlled_ip: str  # RTU/slave
    common_addresses: Set[int] = field(default_factory=set)
    type_ids: Set[int] = field(default_factory=set)
    ioa_seen: Set[int] = field(default_factory=set)
    control_count: int = 0
    monitor_count: int = 0
    startdt_seen: bool = False
    stopdt_seen: bool = False
    first_seen: str = ""
    last_seen: str = ""


class IEC104PassiveListener(IecAsduValueMixin, PySharkListenerBase):
    """Passive IEC 60870-5-104 traffic listener (PyShark-based).

    Monitors IEC 104 telecontrol traffic without sending packets to:
    - Identify controlling stations (SCADA) and controlled stations (RTU)
    - Track common addresses (ASDU addresses)
    - Monitor type IDs (data types)
    - Extract actual data values per IOA (measurements, commands, setpoints)
    - Report quality flags (IV, NT, SB, BL, OV) for ICS security analysis
    - Detect control commands
    - Map information object address ranges

    Usage:
        listener = IEC104PassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Get session details
        for session in listener.sessions.values():
            print(f"{session.controlling_ip} -> {session.controlled_ip}")
            print(f"  Common addresses: {session.common_addresses}")
            print(f"  Type IDs: {session.type_ids}")
    """

    PROTOCOL_NAME = "iec104"
    DISPLAY_FILTER = "iec60870_104"
    REQUIRED_LAYERS = ("iec60870_104",)
    SERVER_PORTS = (2404,)
    PROTOCOL_COLUMNS = (
        "rw",
        "operation",
        "type_id",
        "cot",
        "common_addr",
        "ioa",
        "value",
        "quality",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], IEC104Session] = {}

    def process_packet(self, packet) -> None:
        """Process IEC 104 packet using PyShark."""
        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        # Get port info to determine direction
        src_port, dst_port = self.get_port_info(packet)

        # Get MAC addresses
        src_mac, dst_mac = self.get_mac_info(packet)

        # Determine controlling/controlled roles via the shared cascade. The
        # standard permits any TCP port, so we cannot key off 2404 alone; the
        # cascade unions canonical 2404 with any user --decode-as / OVERRIDE_PREFS
        # override and falls back to the lower-port heuristic. There is no clean
        # frame-level request/response signal available this early (the COT lives
        # per-ASDU and drives the per-interaction direction separately), so pass
        # native=None and let the port + heuristic tiers decide who is the
        # controlling (SCADA, client) vs controlled (RTU, server) station.
        d = self.resolve_direction(
            packet,
            native=None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        if d.is_request:
            # To controlled station (RTU): src is controlling (SCADA)
            controlling_ip = src_ip
            controlled_ip = dst_ip
            controlling_mac = src_mac
            controlled_mac = dst_mac
        else:
            # From controlled station: dst is controlling (SCADA)
            controlling_ip = dst_ip
            controlled_ip = src_ip
            controlling_mac = dst_mac
            controlled_mac = src_mac

        # Check if we have the IEC 104 layer
        if not hasattr(packet, "iec60870_104"):
            return

        iec104_layer = packet.iec60870_104

        # Get frame type from iec60870_104.type field
        # 0x00 = I-format, 0x01 = S-format, 0x03 = U-format
        # Multi-APDU TCP segments in EK mode have _fields_dict as a list of
        # dicts — PyShark's EkLayer can't parse them, so we read type directly
        # from the dicts.
        frame_type = self.get_field(iec104_layer, "type", None)

        recorded = False
        if frame_type is None:
            # EK array case: extract frame types from raw dicts
            ek_dicts = self._get_ek_layer_dicts(iec104_layer)
            if ek_dicts:
                frame_type_vals: set[int] = set()
                for fd in ek_dicts:
                    ft = fd.get("iec60870_104_iec60870_104_type")
                    if ft is not None:
                        try:
                            s = str(ft).strip()
                            frame_type_vals.add(int(s, 16) if s.startswith("0x") else int(s))
                        except (ValueError, TypeError) as e:
                            self.logger.debug(
                                f"IEC104: frame_type int parse from EK PDU failed: {e}"
                            )
                if 0x00 in frame_type_vals:
                    self._process_i_frame(
                        packet, controlling_ip, controlled_ip, src_ip, dst_ip, flow_id
                    )
                    recorded = True
                if 0x03 in frame_type_vals:
                    self._process_u_frame(
                        packet, controlling_ip, controlled_ip, src_ip, dst_ip, flow_id
                    )
                    recorded = True
                if frame_type_vals and frame_type_vals <= {0x01}:
                    self._process_s_frame(
                        packet, controlling_ip, controlled_ip, src_ip, dst_ip, flow_id
                    )
                    recorded = True
        else:
            try:
                frame_type_val = (
                    int(frame_type, 16) if isinstance(frame_type, str) else int(frame_type)
                )

                if frame_type_val == 0x00:
                    self._process_i_frame(
                        packet, controlling_ip, controlled_ip, src_ip, dst_ip, flow_id
                    )
                    recorded = True
                elif frame_type_val == 0x01:
                    self._process_s_frame(
                        packet, controlling_ip, controlled_ip, src_ip, dst_ip, flow_id
                    )
                    recorded = True
                elif frame_type_val == 0x03:
                    self._process_u_frame(
                        packet, controlling_ip, controlled_ip, src_ip, dst_ip, flow_id
                    )
                    recorded = True
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get frame_type_val: {e}")

        # Fallback: malformed or unrecognized APDU -- still record an interaction
        if not recorded:
            apdu_len = self.get_field(iec104_layer, "apdulen", "?")
            apdu_data = self.get_field(iec104_layer, "data", "")
            self.logger.debug(
                f"Malformed/short APDU from {src_ip} -> {dst_ip}: len={apdu_len} data={apdu_data}"
            )
            now = datetime.now().isoformat()
            _sp, _dp = self.get_port_info(packet)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "Malformed APDU",
                {"frame_type": "malformed", "apdu_len": str(apdu_len)},
                f"Malformed APDU (len={apdu_len})",
                flow_id=flow_id,
                src_port=_sp,
                dst_port=_dp,
                stream_id=self.get_stream_id(packet),
            )

        # Update devices
        self._update_devices(controlling_ip, controlling_mac, controlled_ip, controlled_mac)

    def _ensure_session(self, controlling_ip: str, controlled_ip: str) -> IEC104Session:
        """Ensure session exists and return it."""
        session_key = (controlling_ip, controlled_ip)
        now = datetime.now().isoformat()

        if session_key not in self.sessions:
            self.sessions[session_key] = IEC104Session(
                controlling_ip=controlling_ip,
                controlled_ip=controlled_ip,
                first_seen=now,
                last_seen=now,
            )

        session = self.sessions[session_key]
        session.last_seen = now
        return session

    def _process_i_frame(
        self,
        packet,
        controlling_ip: str,
        controlled_ip: str,
        src_ip: str,
        dst_ip: str,
        flow_id: str = "",
    ) -> None:
        """Process I-format frame (data transfer) using PyShark ASDU fields.

        Multi-APDU TCP segments in EK mode produce a *list* of dicts in
        ``_fields_dict`` instead of a single dict.  PyShark's EkLayer can't
        handle this (crashes on ``startswith``).  We detect the array case,
        create synthetic EkLayer objects, parse each ASDU, and then collapse
        them into a single interaction row (one TCP segment = one row).
        """
        session = self._ensure_session(controlling_ip, controlled_ip)

        if not hasattr(packet, "iec60870_asdu"):
            # I-frame without ASDU layer (malformed or truncated)
            now = datetime.now().isoformat()
            _sp, _dp = self.get_port_info(packet)
            self.logger.debug(f"I-frame without ASDU layer from {src_ip} -> {dst_ip}")
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "I-frame (no ASDU)",
                {"frame_type": "I", "malformed": True},
                "I-frame without ASDU data",
                flow_id=flow_id,
                src_port=_sp,
                dst_port=_dp,
                stream_id=self.get_stream_id(packet),
            )
            return

        asdu_layer = packet.iec60870_asdu

        # Detect multi-ASDU EK array (list of dicts in _fields_dict)
        asdu_dicts = self._get_ek_layer_dicts(asdu_layer)
        if asdu_dicts is not None and len(asdu_dicts) > 1:
            from pyshark.packet.layers.ek_layer import EkLayer as _EkLayer

            parsed = []
            for fd in asdu_dicts:
                synthetic = _EkLayer(asdu_layer._layer_name, fd)
                info = self._parse_asdu_core(session, synthetic)
                if info:
                    parsed.append(info)
            if parsed:
                self._record_merged_interaction(packet, parsed, src_ip, dst_ip, flow_id)
        elif asdu_dicts is not None:
            # Single-element EK array
            from pyshark.packet.layers.ek_layer import EkLayer as _EkLayer

            synthetic = _EkLayer(asdu_layer._layer_name, asdu_dicts[0])
            self._process_single_asdu(packet, session, synthetic, src_ip, dst_ip, flow_id)
        else:
            self._process_single_asdu(packet, session, asdu_layer, src_ip, dst_ip, flow_id)

    def _process_single_asdu(
        self,
        packet,
        session: "IEC104Session",
        asdu_layer,
        src_ip: str,
        dst_ip: str,
        flow_id: str = "",
    ) -> None:
        """Process a single ASDU layer (real or synthetic from EK array)."""
        type_id_raw = self.get_field(asdu_layer, "typeid", None)
        if not type_id_raw:
            self.logger.debug(f"I-frame ASDU missing typeid from {src_ip} -> {dst_ip}")
            now = datetime.now().isoformat()
            _sp, _dp = self.get_port_info(packet)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "I-frame (malformed ASDU)",
                {"frame_type": "I", "malformed": True},
                "I-frame with empty/malformed ASDU",
                flow_id=flow_id,
                src_port=_sp,
                dst_port=_dp,
                stream_id=self.get_stream_id(packet),
            )
            return

        parsed = self._parse_asdu_core(session, asdu_layer)
        if parsed is None:
            self.logger.debug(
                f"I-frame ASDU unparseable typeid={type_id_raw!r} from {src_ip} -> {dst_ip}"
            )
            now = datetime.now().isoformat()
            _sp, _dp = self.get_port_info(packet)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "I-frame (bad typeid)",
                {"frame_type": "I", "malformed": True, "raw_typeid": str(type_id_raw)},
                f"I-frame with unparseable typeid={type_id_raw}",
                flow_id=flow_id,
                src_port=_sp,
                dst_port=_dp,
                stream_id=self.get_stream_id(packet),
            )
            return

        type_id = parsed["type_id"]
        type_name = parsed["type_name"]
        common_addr = parsed["common_address"]
        cause_tx = parsed["cause_of_transmission"]
        cot_name = parsed["cot_name"]
        rw = parsed["rw"]
        is_negative = parsed["negative"]
        is_control = parsed["is_control"]
        is_error_cot = parsed["is_error_cot"]
        ioa_list = parsed["ioa_list"]
        values = parsed["values"]
        quality_list = parsed["quality"]

        direction = "request" if is_control else "response"

        details: Dict[str, Any] = {
            "type_id": type_id,
            "type_name": type_name,
            "common_address": common_addr,
            "cause_of_transmission": cause_tx,
            "cot_name": cot_name,
            "rw": rw,
            "negative": is_negative,
        }
        if ioa_list:
            details["ioa"] = ioa_list[0] if len(ioa_list) == 1 else ioa_list
        if values:
            details["values"] = values
        if quality_list:
            details["quality"] = quality_list

        summary = self._build_asdu_summary(
            type_id,
            type_name,
            ioa_list,
            common_addr,
            is_control,
            values,
            cot_name=cot_name,
            is_error=is_error_cot,
        )
        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            type_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

    def _record_merged_interaction(
        self,
        packet,
        parsed: List[Dict[str, Any]],
        src_ip: str,
        dst_ip: str,
        flow_id: str = "",
    ) -> None:
        """Record a single interaction row for multiple ASDUs in one TCP segment.

        Uses the first ASDU as the primary, with additional COTs and type IDs
        shown pipe-separated.  This matches Wireshark's display of multi-APDU
        TCP segments as a single frame.
        """
        primary = parsed[0]

        # Merge COT names: "neg_actcon | neg_unknown_ca"
        cot_parts = [p["cot_name"] for p in parsed]
        merged_cot = " | ".join(cot_parts)

        # Merge IOAs across all ASDUs
        all_ioas: List[int] = []
        for p in parsed:
            all_ioas.extend(p["ioa_list"])

        # Merge values across all ASDUs
        all_values: List[str] = []
        for p in parsed:
            all_values.extend(p.get("values") or [])

        # Merge quality
        all_quality: List[str] = []
        for p in parsed:
            all_quality.extend(p.get("quality") or [])

        # Use primary type for the operation column; include others if different
        type_names = [p["type_name"] for p in parsed]
        unique_types = list(dict.fromkeys(type_names))  # preserve order, dedupe
        if len(unique_types) == 1:
            operation = unique_types[0]
            type_str = f"{primary['type_id']} ({unique_types[0]})"
        else:
            operation = unique_types[0]
            type_str = ",".join(f"{p['type_id']} ({p['type_name']})" for p in parsed)

        # Use worst-case rw (error > write > read)
        rw_priority = {"error": 0, "write": 1, "control": 2, "file": 3, "read": 4}
        merged_rw = min((p["rw"] for p in parsed), key=lambda r: rw_priority.get(r, 99))
        merged_negative = any(p["negative"] for p in parsed)
        merged_error = any(p["is_error_cot"] for p in parsed)

        details: Dict[str, Any] = {
            "type_id": primary["type_id"],
            "type_name": primary["type_name"],
            "type_str": type_str,
            "common_address": primary["common_address"],
            "cause_of_transmission": primary["cause_of_transmission"],
            "cot_name": merged_cot,
            "rw": merged_rw,
            "negative": merged_negative,
            "asdu_count": len(parsed),
        }
        if all_ioas:
            details["ioa"] = all_ioas[0] if len(all_ioas) == 1 else all_ioas
        if all_values:
            details["values"] = all_values
        if all_quality:
            details["quality"] = all_quality

        direction = "request" if primary["is_control"] else "response"

        summary = self._build_asdu_summary(
            primary["type_id"],
            primary["type_name"],
            all_ioas,
            primary["common_address"],
            primary["is_control"],
            all_values or None,
            cot_name=merged_cot,
            is_error=merged_error,
        )

        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

    def _process_s_frame(
        self,
        packet,
        controlling_ip: str,
        controlled_ip: str,
        src_ip: str,
        dst_ip: str,
        flow_id: str = "",
    ) -> None:
        """Process S-format frame (supervisory / receive-acknowledge)."""
        self._ensure_session(controlling_ip, controlled_ip)
        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "S-frame (ACK)",
            {"frame_type": "S"},
            "S-frame (ACK)",
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

    def _process_u_frame(
        self,
        packet,
        controlling_ip: str,
        controlled_ip: str,
        src_ip: str,
        dst_ip: str,
        flow_id: str = "",
    ) -> None:
        """Process U-format frame (STARTDT, STOPDT, TESTFR)."""
        session = self._ensure_session(controlling_ip, controlled_ip)

        if not hasattr(packet, "iec60870_104"):
            return

        iec104_layer = packet.iec60870_104
        utype_raw = self.get_field(iec104_layer, "utype", None)

        if utype_raw:
            try:
                utype = int(utype_raw, 16) if isinstance(utype_raw, str) else int(utype_raw)

                utype_names = {
                    UTYPE_STARTDT_ACT: "STARTDT act",
                    UTYPE_STARTDT_CON: "STARTDT con",
                    UTYPE_STOPDT_ACT: "STOPDT act",
                    UTYPE_STOPDT_CON: "STOPDT con",
                    UTYPE_TESTFR_ACT: "TESTFR act",
                    UTYPE_TESTFR_CON: "TESTFR con",
                }

                if utype in (UTYPE_STARTDT_ACT, UTYPE_STARTDT_CON):
                    session.startdt_seen = True
                if utype in (UTYPE_STOPDT_ACT, UTYPE_STOPDT_CON):
                    session.stopdt_seen = True

                uname = utype_names.get(utype, f"U-type 0x{utype:02x}")
                now = datetime.now().isoformat()
                _sp, _dp = self.get_port_info(packet)
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "request",
                    uname,
                    {"utype": utype},
                    uname,
                    flow_id=flow_id,
                    src_port=_sp,
                    dst_port=_dp,
                    stream_id=self.get_stream_id(packet),
                )
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Operation failed: {e}")
        else:
            # Truncated/malformed U-APDU: tshark emitted no utype. Record a
            # generic interaction and debug-log so a filter-matching packet is
            # never silently dropped (mirrors the ASDU/S-frame/I-frame paths).
            self.logger.debug(
                f"IEC104 U-frame with no utype field {src_ip} -> {dst_ip} (malformed U-APDU)"
            )
            now = datetime.now().isoformat()
            _sp, _dp = self.get_port_info(packet)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "U-frame (malformed)",
                {},
                "U-frame (malformed)",
                flow_id=flow_id,
                src_port=_sp,
                dst_port=_dp,
                stream_id=self.get_stream_id(packet),
            )

    # ------------------------------------------------------------------
    # EK array helper (multi-APDU support)
    # ------------------------------------------------------------------

    @staticmethod
    def _get_ek_layer_dicts(layer) -> Optional[List[dict]]:
        """Return the raw list of dicts when an EK layer wraps multiple PDUs.

        In PyShark's EK mode, multi-APDU TCP segments store ``_fields_dict``
        as a *list* of dicts instead of a single dict.  PyShark's ``EkLayer``
        cannot handle this and crashes.  This helper detects the case and
        returns the list, or ``None`` for normal single-PDU layers.
        """
        try:
            fd = object.__getattribute__(layer, "_fields_dict")
            if isinstance(fd, list):
                return fd
        except AttributeError as e:
            logger.debug(f"IEC104 EK layer _fields_dict access failed: {e}")
        return None

    # ------------------------------------------------------------------
    # Summary and formatting
    # ------------------------------------------------------------------

    def _update_devices(
        self,
        controlling_ip: str,
        controlling_mac: str,
        controlled_ip: str,
        controlled_mac: str,
    ) -> None:
        """Update device entries."""
        session_key = (controlling_ip, controlled_ip)
        session = self.sessions.get(session_key)
        if not session:
            return

        # Controlled station (RTU)
        if is_valid_discovered_ip(controlled_ip):
            controlled_vendor = lookup_mac_vendor(controlled_mac) if controlled_mac else ""
            key = f"iec104-controlled:{controlled_ip}"
            device, is_new = self._ensure_device(
                key,
                controlled_ip,
                mac=controlled_mac,
                manufacturer=controlled_vendor if controlled_vendor else "",
                device_type="IEC 104 Controlled Station (RTU)",
            )
            device.iec104_passive_data = self._build_data("controlled_station", session)
            if is_new:
                self.logger.debug(
                    f"IEC104: RTU {controlled_ip} CA={list(session.common_addresses)}"
                )
        # Controlling station (SCADA)
        if is_valid_discovered_ip(controlling_ip):
            controlling_vendor = lookup_mac_vendor(controlling_mac) if controlling_mac else ""
            key = f"iec104-controlling:{controlling_ip}"
            device, is_new = self._ensure_device(
                key,
                controlling_ip,
                mac=controlling_mac,
                manufacturer=controlling_vendor,
                device_type="IEC 104 Controlling Station (SCADA)",
            )
            device.iec104_passive_data = self._build_data("controlling_station", session)

    def _build_data(self, role: str, session: IEC104Session) -> Dict[str, Any]:
        """Build iec104_passive_data dict."""
        return {
            "role": role,
            "common_addresses": sorted(list(session.common_addresses)),
            "type_ids_seen": sorted(list(session.type_ids)),
            "type_names": [TYPE_IDS.get(t, f"Type{t}") for t in sorted(session.type_ids)],
            "ioa_ranges": self._merge_ioa_ranges(session.ioa_seen),
            "control_commands": session.control_count,
            "monitor_messages": session.monitor_count,
            "startdt_seen": session.startdt_seen,
            "stopdt_seen": session.stopdt_seen,
            "protocol": "IEC104/TCP",
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
        }

    def _merge_ioa_ranges(self, ioas: Set[int]) -> List[Tuple[int, int]]:
        """Merge IOAs into ranges."""
        if not ioas:
            return []

        sorted_ioas = sorted(ioas)
        ranges = []
        start = end = sorted_ioas[0]

        for ioa in sorted_ioas[1:]:
            if ioa <= end + 10:  # Allow small gaps
                end = ioa
            else:
                ranges.append((start, end))
                start = end = ioa

        ranges.append((start, end))
        return ranges

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        type_id = d.get("type_id", "")
        type_name = d.get("type_name", "")
        common_addr = d.get("common_address", "")

        # Format IOA column
        ioa = d.get("ioa", "")
        if isinstance(ioa, list):
            if len(ioa) == 1:
                ioa_str = str(ioa[0])
            elif len(ioa) <= 5:
                ioa_str = " | ".join(str(a) for a in ioa)
            elif len(ioa) > 1:
                ioa_str = f"{ioa[0]}-{ioa[-1]}"
            else:
                ioa_str = ""
        else:
            ioa_str = str(ioa) if ioa != "" else ""

        # Merged multi-ASDU rows provide a pre-built type_str
        type_str = d.get("type_str") or (f"{type_id} ({type_name})" if type_id else "")

        # Format COT column
        cot_name = d.get("cot_name", "")
        if not cot_name:
            # Fallback: derive from raw COT value
            cot_raw = d.get("cause_of_transmission", 0)
            if cot_raw:
                cot_name = COT_NAMES.get(cot_raw, str(cot_raw))

        # Format Value column — use " | " to avoid CSV column ambiguity
        values = d.get("values", [])
        if isinstance(values, list) and values:
            val_str = " | ".join(values)
        else:
            val_str = ""

        # Format Quality column
        quality = d.get("quality", [])
        if isinstance(quality, list) and quality:
            # Filter out empty quality strings and join non-empty ones
            active = [q for q in quality if q]
            if active:
                qual_str = ";".join(active)
            else:
                qual_str = ""
        else:
            qual_str = ""

        rw = d.get("rw", "")

        return [
            rw,
            ix.operation,
            type_str,
            cot_name,
            common_addr if common_addr else "",
            ioa_str,
            val_str,
            qual_str,
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed IEC 104 sessions."""
        return [
            {
                "controlling": session.controlling_ip,
                "controlled": session.controlled_ip,
                "common_addresses": sorted(list(session.common_addresses)),
                "type_ids": sorted(list(session.type_ids)),
                "control_count": session.control_count,
                "monitor_count": session.monitor_count,
            }
            for session in self.sessions.values()
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with control operations."""
        return [
            {
                "controlling": session.controlling_ip,
                "controlled": session.controlled_ip,
                "control_count": session.control_count,
                "control_types": [
                    TYPE_IDS.get(t, f"Type{t}") for t in session.type_ids if t in CONTROL_TYPE_IDS
                ],
            }
            for session in self.sessions.values()
            if session.control_count > 0
        ]
