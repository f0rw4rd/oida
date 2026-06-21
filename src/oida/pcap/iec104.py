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

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

import logging

logger = logging.getLogger(__name__)


# IEC 104 Type IDs (common subset)
TYPE_IDS = {
    # Monitoring (process info in monitor direction)
    1: "M_SP_NA_1",  # Single-point information
    3: "M_DP_NA_1",  # Double-point information
    5: "M_ST_NA_1",  # Step position information
    7: "M_BO_NA_1",  # Bitstring of 32 bits
    9: "M_ME_NA_1",  # Measured value, normalized
    11: "M_ME_NB_1",  # Measured value, scaled
    13: "M_ME_NC_1",  # Measured value, short floating point
    15: "M_IT_NA_1",  # Integrated totals
    20: "M_PS_NA_1",  # Packed single-point with status
    21: "M_ME_ND_1",  # Measured value, normalized without quality
    30: "M_SP_TB_1",  # Single-point with time tag CP56Time2a
    31: "M_DP_TB_1",  # Double-point with time tag CP56Time2a
    32: "M_ST_TB_1",  # Step position with time tag
    33: "M_BO_TB_1",  # Bitstring with time tag
    34: "M_ME_TD_1",  # Measured value, normalized with time tag
    35: "M_ME_TE_1",  # Measured value, scaled with time tag
    36: "M_ME_TF_1",  # Measured value, float with time tag
    37: "M_IT_TB_1",  # Integrated totals with time tag
    38: "M_EP_TD_1",  # Event of protection equipment
    39: "M_EP_TE_1",  # Packed start events
    40: "M_EP_TF_1",  # Packed output circuit info
    # Control (command direction)
    45: "C_SC_NA_1",  # Single command
    46: "C_DC_NA_1",  # Double command
    47: "C_RC_NA_1",  # Regulating step command
    48: "C_SE_NA_1",  # Setpoint command, normalized
    49: "C_SE_NB_1",  # Setpoint command, scaled
    50: "C_SE_NC_1",  # Setpoint command, float
    51: "C_BO_NA_1",  # Bitstring command
    58: "C_SC_TA_1",  # Single command with time tag
    59: "C_DC_TA_1",  # Double command with time tag
    60: "C_RC_TA_1",  # Regulating step with time tag
    61: "C_SE_TA_1",  # Setpoint normalized with time tag
    62: "C_SE_TB_1",  # Setpoint scaled with time tag
    63: "C_SE_TC_1",  # Setpoint float with time tag
    64: "C_BO_TA_1",  # Bitstring command with time tag
    # System info
    70: "M_EI_NA_1",  # End of initialization
    100: "C_IC_NA_1",  # Interrogation command
    101: "C_CI_NA_1",  # Counter interrogation
    102: "C_RD_NA_1",  # Read command
    103: "C_CS_NA_1",  # Clock synchronization
    104: "C_TS_NA_1",  # Test command
    105: "C_RP_NA_1",  # Reset process
    106: "C_CD_NA_1",  # Delay acquisition
    107: "C_TS_TA_1",  # Test command with time tag
    # Parameter
    110: "P_ME_NA_1",  # Parameter of measured value, normalized
    111: "P_ME_NB_1",  # Parameter of measured value, scaled
    112: "P_ME_NC_1",  # Parameter of measured value, float
    113: "P_AC_NA_1",  # Parameter activation
    # File transfer
    120: "F_FR_NA_1",  # File ready
    121: "F_SR_NA_1",  # Section ready
    122: "F_SC_NA_1",  # Call directory
    123: "F_LS_NA_1",  # Last section
    124: "F_AF_NA_1",  # Ack file
    125: "F_SG_NA_1",  # Segment
    126: "F_DR_TA_1",  # Directory
    127: "F_SC_NB_1",  # Query log
}

# Control type IDs (commands — all types in the control direction)
CONTROL_TYPE_IDS = {
    45,
    46,
    47,
    48,
    49,
    50,
    51,  # Direct commands
    58,
    59,
    60,
    61,
    62,
    63,
    64,  # Commands with time tag
    100,
    101,
    102,
    103,
    104,
    105,
    106,
    107,  # System commands
    110,
    111,
    112,
    113,  # Parameter commands
    120,
    121,
    122,
    123,
    124,
    125,
    126,
    127,  # File transfer
}

# Write commands — types that actually modify process state
_WRITE_TYPE_IDS = {
    45,
    46,
    47,
    48,
    49,
    50,
    51,  # C_SC/DC/RC/SE commands
    58,
    59,
    60,
    61,
    62,
    63,
    64,  # Same with time tag
    110,
    111,
    112,
    113,  # Parameter set commands
}

# Read/query commands — request data but don't modify state
_READ_COMMAND_TYPE_IDS = {100, 101, 102}  # GI, CI, Read command

# System/management commands
_SYSTEM_TYPE_IDS = {103, 104, 105, 106, 107}  # Clock sync, test, reset, delay, test+time

# File transfer types
_FILE_TYPE_IDS = {120, 121, 122, 123, 124, 125, 126, 127}

# Cause of Transmission (COT) names per IEC 60870-5-101 §7.2.3
COT_NAMES = {
    1: "periodic",
    2: "background",
    3: "spontaneous",
    4: "initialized",
    5: "request",
    6: "activation",
    7: "actcon",
    8: "deactivation",
    9: "deactcon",
    10: "actterm",
    11: "retrem",
    12: "retloc",
    13: "file_transfer",
    20: "inrogen",
    37: "reqcogen",
    44: "unknown_type",
    45: "unknown_cot",
    46: "unknown_ca",
    47: "unknown_ioa",
}

# Error COTs (44-47)
_ERROR_COTS = {44, 45, 46, 47}

# U-frame types — tshark applies mask 0xfc and right-shifts by 2,
# so values are half the raw wire-format bit positions.
UTYPE_STARTDT_ACT = 0x01
UTYPE_STARTDT_CON = 0x02
UTYPE_STOPDT_ACT = 0x04
UTYPE_STOPDT_CON = 0x08
UTYPE_TESTFR_ACT = 0x10
UTYPE_TESTFR_CON = 0x20

# Double-point interpretation (DPI field values)
_DPI_VALUES = {0: "INTERMEDIATE", 1: "OFF", 2: "ON", 3: "INDETERMINATE"}

# Regulating step command interpretation (RCO.up field values)
_RCO_VALUES = {0: "NOT_PERMITTED", 1: "LOWER", 2: "HIGHER", 3: "NOT_PERMITTED"}

# Quality flag abbreviations for display
_QUALITY_ABBREVS = {
    "iv": "IV",  # Invalid
    "nt": "NT",  # Not topical
    "sb": "SB",  # Substituted
    "bl": "BL",  # Blocked
    "ov": "OV",  # Overflow
}

# Map type IDs to their value extraction category.
# Each tuple: (value_field, quality_source)
# quality_source: "qds" (QDS descriptor), "siq" (SIQ), "diq" (DIQ), None
_TYPE_CATEGORIES: Dict[int, Tuple[str, Optional[str]]] = {
    # Single-point: siq.spi (bool) with SIQ quality
    1: ("spi", "siq"),
    30: ("spi", "siq"),
    # Double-point: diq.dpi (int) with DIQ quality
    3: ("dpi", "diq"),
    31: ("dpi", "diq"),
    # Step position: vti.v (int) + vti.t (bool) with QDS quality
    5: ("vti", "qds"),
    32: ("vti", "qds"),
    # Bitstring: bitstring (hex) with QDS quality
    7: ("bitstring", "qds"),
    33: ("bitstring", "qds"),
    # Normalized value: normval (float) with QDS quality
    9: ("normval", "qds"),
    34: ("normval", "qds"),
    # Normalized without quality
    21: ("normval", None),
    # Scaled value: scalval (int) with QDS quality
    11: ("scalval", "qds"),
    35: ("scalval", "qds"),
    # Short float: float (float) with QDS quality
    13: ("float", "qds"),
    36: ("float", "qds"),
    # Integrated totals: bcr.count (int), no standard QDS
    15: ("bcr", None),
    37: ("bcr", None),
    # Single command: sco.on (bool)
    45: ("sco", None),
    58: ("sco", None),
    # Double command: dco.on (int)
    46: ("dco", None),
    59: ("dco", None),
    # Regulating step command: rco.up (int)
    47: ("rco", None),
    60: ("rco", None),
    # Setpoint normalized: normval with QOS
    48: ("normval", None),
    61: ("normval", None),
    # Parameter of measured value, normalized
    110: ("normval", None),
    # Setpoint scaled: scalval with QOS
    49: ("scalval", None),
    62: ("scalval", None),
    # Parameter of measured value, scaled
    111: ("scalval", None),
    # Setpoint float: float with QOS
    50: ("float", None),
    63: ("float", None),
    # Parameter of measured value, float
    112: ("float", None),
    # Bitstring command
    51: ("bitstring", None),
    64: ("bitstring", None),
    # Interrogation command: qoi (int)
    100: ("qoi", None),
    # Counter interrogation: qcc (int)
    101: ("qcc", None),
    # End of initialization: coi (int)
    70: ("coi", None),
    # Clock sync: cp56time
    103: ("cp56time", None),
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


class IEC104PassiveListener(PySharkListenerBase):
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

        # Determine direction. Default IEC 104 port is 2404 but the standard
        # permits any TCP port — the captured peer may be running on 2405, 2406,
        # etc. (mocks in this repo use 2405/2409). Use the canonical port if it
        # appears on either side; otherwise fall back to "lower port wins"
        # (the listening side has the smaller ephemeral-vs-fixed port).
        if dst_port == 2404 or (dst_port != 2404 and src_port != 2404 and dst_port < src_port):
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
                info = self._parse_asdu_fields(session, synthetic)
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
            # ASDU layer present but no typeid (malformed/empty)
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

        try:
            type_id = int(type_id_raw)
        except (ValueError, TypeError):
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

        common_addr_raw = self.get_field(asdu_layer, "addr", None)
        common_addr = 0
        if common_addr_raw:
            try:
                common_addr = int(common_addr_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get common_addr: {e}")
        session.common_addresses.add(common_addr)

        # Parse IOAs
        ioa_list = self._get_multi_field_ints(asdu_layer, "ioa")
        for ioa in ioa_list:
            session.ioa_seen.add(ioa)

        # Parse cause of transmission
        cause_tx = 0
        cause_tx_raw = self.get_field(asdu_layer, "causetx", None)
        if cause_tx_raw:
            try:
                cause_tx = int(cause_tx_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get cause_tx: {e}")

        # Parse negative (P/N) bit
        is_negative = False
        nega_raw = self.get_field(asdu_layer, "nega", None)
        if nega_raw is not None:
            is_negative = str(nega_raw) in ("True", "1", "true")

        session.type_ids.add(type_id)
        is_control = type_id in CONTROL_TYPE_IDS
        if is_control:
            session.control_count += 1
        else:
            session.monitor_count += 1

        type_name = TYPE_IDS.get(type_id, f"Type{type_id}")
        direction = "request" if is_control else "response"

        cot_name = COT_NAMES.get(cause_tx, str(cause_tx))
        if is_negative:
            cot_name = f"neg_{cot_name}"
        is_error_cot = cause_tx in _ERROR_COTS or is_negative

        values = self._extract_values(asdu_layer, type_id)
        quality_list = self._extract_quality(asdu_layer, type_id)

        # Classify rw
        if is_error_cot:
            rw = "error"
        elif type_id in _WRITE_TYPE_IDS:
            rw = "write"
        elif type_id in _READ_COMMAND_TYPE_IDS:
            rw = "read"
        elif type_id in _SYSTEM_TYPE_IDS:
            rw = "control"
        elif type_id in _FILE_TYPE_IDS:
            rw = "file"
        elif type_id <= 44:
            rw = "read"
        else:
            rw = "write"

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

        summary = self._build_i_frame_summary(
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

    def _parse_asdu_fields(self, session: "IEC104Session", asdu_layer) -> Optional[Dict[str, Any]]:
        """Extract fields from a single ASDU layer without recording.

        Returns a dict with parsed fields, or ``None`` on parse failure.
        Used by the multi-APDU merge path.
        """
        type_id_raw = self.get_field(asdu_layer, "typeid", None)
        if not type_id_raw:
            return None
        try:
            type_id = int(type_id_raw)
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to get type_id: {e}")
            return None

        common_addr = 0
        common_addr_raw = self.get_field(asdu_layer, "addr", None)
        if common_addr_raw:
            try:
                common_addr = int(common_addr_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get common_addr: {e}")
        session.common_addresses.add(common_addr)

        ioa_list = self._get_multi_field_ints(asdu_layer, "ioa")
        for ioa in ioa_list:
            session.ioa_seen.add(ioa)

        cause_tx = 0
        cause_tx_raw = self.get_field(asdu_layer, "causetx", None)
        if cause_tx_raw:
            try:
                cause_tx = int(cause_tx_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get cause_tx: {e}")

        is_negative = False
        nega_raw = self.get_field(asdu_layer, "nega", None)
        if nega_raw is not None:
            is_negative = str(nega_raw) in ("True", "1", "true")

        session.type_ids.add(type_id)
        is_control = type_id in CONTROL_TYPE_IDS
        if is_control:
            session.control_count += 1
        else:
            session.monitor_count += 1

        type_name = TYPE_IDS.get(type_id, f"Type{type_id}")
        cot_name = COT_NAMES.get(cause_tx, str(cause_tx))
        if is_negative:
            cot_name = f"neg_{cot_name}"
        is_error_cot = cause_tx in _ERROR_COTS or is_negative

        values = self._extract_values(asdu_layer, type_id)
        quality_list = self._extract_quality(asdu_layer, type_id)

        if is_error_cot:
            rw = "error"
        elif type_id in _WRITE_TYPE_IDS:
            rw = "write"
        elif type_id in _READ_COMMAND_TYPE_IDS:
            rw = "read"
        elif type_id in _SYSTEM_TYPE_IDS:
            rw = "control"
        elif type_id in _FILE_TYPE_IDS:
            rw = "file"
        elif type_id <= 44:
            rw = "read"
        else:
            rw = "write"

        return {
            "type_id": type_id,
            "type_name": type_name,
            "common_address": common_addr,
            "cause_of_transmission": cause_tx,
            "cot_name": cot_name,
            "rw": rw,
            "negative": is_negative,
            "is_control": is_control,
            "is_error_cot": is_error_cot,
            "ioa_list": ioa_list,
            "values": values,
            "quality": quality_list,
        }

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

        summary = self._build_i_frame_summary(
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
    # Value extraction
    # ------------------------------------------------------------------

    def _get_multi_field_ints(self, layer, field_name: str) -> List[int]:
        """Get all instances of an integer field from a PyShark layer.

        Handles multi-IOA packets by using ``all_fields`` when available,
        falling back to the single scalar value.
        """
        result: List[int] = []
        raw = self.get_field(layer, field_name, None)
        if raw is None:
            return result

        # Try all_fields for multi-value support
        try:
            for f in getattr(layer, field_name).all_fields:
                result.append(int(f.show))
        except Exception:
            # Fallback: parse comma-separated or single value
            for part in str(raw).split(","):
                try:
                    result.append(int(part.strip()))
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"result.append(int(part.strip())): {e}")
        return result

    def _get_multi_field_strs(self, layer, field_name: str) -> List[str]:
        """Get all instances of a field as strings from a PyShark layer."""
        result: List[str] = []
        raw = self.get_field(layer, field_name, None)
        if raw is None:
            return result

        try:
            for f in getattr(layer, field_name).all_fields:
                result.append(str(f.show))
        except Exception:
            result.append(str(raw))
        return result

    def _extract_values(self, asdu_layer, type_id: int) -> List[str]:
        """Extract per-IOA values from the ASDU layer based on type ID.

        Returns a list of human-readable value strings, one per IOA.
        """
        cat = _TYPE_CATEGORIES.get(type_id)
        if cat is None:
            return []

        value_kind = cat[0]

        if value_kind == "spi":
            return self._extract_spi_values(asdu_layer)
        elif value_kind == "dpi":
            return self._extract_dpi_values(asdu_layer)
        elif value_kind == "vti":
            return self._extract_vti_values(asdu_layer)
        elif value_kind == "bitstring":
            return self._get_multi_field_strs(asdu_layer, "bitstring")
        elif value_kind == "normval":
            return self._get_multi_field_strs(asdu_layer, "normval")
        elif value_kind == "scalval":
            return self._get_multi_field_strs(asdu_layer, "scalval")
        elif value_kind == "float":
            return self._extract_float_values(asdu_layer)
        elif value_kind == "bcr":
            return self._extract_bcr_values(asdu_layer)
        elif value_kind == "sco":
            return self._extract_sco_values(asdu_layer)
        elif value_kind == "dco":
            return self._extract_dco_values(asdu_layer)
        elif value_kind == "rco":
            return self._extract_rco_values(asdu_layer)
        elif value_kind == "qoi":
            return self._extract_simple_field(asdu_layer, "qoi", "QOI=")
        elif value_kind == "qcc":
            return self._extract_simple_field(asdu_layer, "qcc", "QCC=")
        elif value_kind == "coi":
            return self._extract_coi_values(asdu_layer)
        elif value_kind == "cp56time":
            return self._get_multi_field_strs(asdu_layer, "cp56time")
        return []

    def _extract_spi_values(self, asdu_layer) -> List[str]:
        """Extract single-point SPI values (ON/OFF)."""
        result: List[str] = []
        raw = self.get_field(asdu_layer, "siq_spi", None)
        if raw is None:
            return result
        try:
            for f in getattr(asdu_layer, "siq_spi").all_fields:
                val = str(f.show)
                result.append("ON" if val in ("True", "On", "1") else "OFF")
        except Exception:
            val = str(raw)
            result.append("ON" if val in ("True", "On", "1") else "OFF")
        return result

    def _extract_dpi_values(self, asdu_layer) -> List[str]:
        """Extract double-point DPI values."""
        result: List[str] = []
        raw = self.get_field(asdu_layer, "diq_dpi", None)
        if raw is None:
            return result
        try:
            for f in getattr(asdu_layer, "diq_dpi").all_fields:
                val = int(f.show)
                result.append(_DPI_VALUES.get(val, str(val)))
        except Exception:
            try:
                val = int(raw)
                result.append(_DPI_VALUES.get(val, str(val)))
            except (ValueError, TypeError):
                result.append(str(raw))
        return result

    def _extract_vti_values(self, asdu_layer) -> List[str]:
        """Extract step position VTI values (value + transient flag)."""
        result: List[str] = []
        vals = self._get_multi_field_strs(asdu_layer, "vti_v")
        transients = self._get_multi_field_strs(asdu_layer, "vti_t")
        for i, v in enumerate(vals):
            t = transients[i] if i < len(transients) else ""
            if t and t in ("True", "Transient", "1"):
                result.append(f"{v}(T)")
            else:
                result.append(v)
        if not result:
            # Fallback: try the raw vti field
            raw_vals = self._get_multi_field_strs(asdu_layer, "vti")
            result.extend(raw_vals)
        return result

    def _extract_float_values(self, asdu_layer) -> List[str]:
        """Extract short floating point values, cleaning up trailing zeros."""
        result: List[str] = []
        raw = self.get_field(asdu_layer, "float", None)
        if raw is None:
            return result
        try:
            for f in getattr(asdu_layer, "float").all_fields:
                result.append(self._format_float(f.show))
        except Exception:
            result.append(self._format_float(str(raw)))
        return result

    def _extract_bcr_values(self, asdu_layer) -> List[str]:
        """Extract binary counter reading (integrated totals) values."""
        result: List[str] = []
        raw = self.get_field(asdu_layer, "bcr_count", None)
        if raw is not None:
            try:
                for f in getattr(asdu_layer, "bcr_count").all_fields:
                    result.append(str(f.show))
            except Exception:
                result.append(str(raw))
        if not result:
            # Fallback to bcr field
            raw = self.get_field(asdu_layer, "bcr", None)
            if raw is not None:
                result.append(str(raw))
        return result

    def _extract_sco_values(self, asdu_layer) -> List[str]:
        """Extract single command values (ON/OFF with select/execute)."""
        result: List[str] = []
        on_raw = self.get_field(asdu_layer, "sco_on", None)
        se_raw = self.get_field(asdu_layer, "sco_se", None)
        if on_raw is None:
            return result
        try:
            on_fields = list(getattr(asdu_layer, "sco_on").all_fields)
            se_fields: list = []
            if se_raw is not None:
                try:
                    se_fields = list(getattr(asdu_layer, "sco_se").all_fields)
                except Exception as e:
                    self.logger.debug(f"Failed to get se_fields: {e}")
            for i, f in enumerate(on_fields):
                val = "ON" if str(f.show) == "True" else "OFF"
                if i < len(se_fields) and str(se_fields[i].show) == "True":
                    val += "(S)"  # Select
                result.append(val)
        except Exception:
            val = "ON" if str(on_raw) == "True" else "OFF"
            if se_raw is not None and str(se_raw) == "True":
                val += "(S)"
            result.append(val)
        return result

    def _extract_dco_values(self, asdu_layer) -> List[str]:
        """Extract double command values."""
        result: List[str] = []
        on_raw = self.get_field(asdu_layer, "dco_on", None)
        se_raw = self.get_field(asdu_layer, "dco_se", None)
        if on_raw is None:
            return result
        try:
            on_fields = list(getattr(asdu_layer, "dco_on").all_fields)
            se_fields: list = []
            if se_raw is not None:
                try:
                    se_fields = list(getattr(asdu_layer, "dco_se").all_fields)
                except Exception as e:
                    self.logger.debug(f"Failed to get se_fields: {e}")
            for i, f in enumerate(on_fields):
                val = _DPI_VALUES.get(int(f.show), str(f.show))
                if i < len(se_fields) and str(se_fields[i].show) == "True":
                    val += "(S)"
                result.append(val)
        except Exception:
            try:
                val = _DPI_VALUES.get(int(on_raw), str(on_raw))
            except (ValueError, TypeError):
                val = str(on_raw)
            if se_raw is not None and str(se_raw) == "True":
                val += "(S)"
            result.append(val)
        return result

    def _extract_rco_values(self, asdu_layer) -> List[str]:
        """Extract regulating step command values."""
        result: List[str] = []
        up_raw = self.get_field(asdu_layer, "rco_up", None)
        se_raw = self.get_field(asdu_layer, "rco_se", None)
        if up_raw is None:
            return result
        try:
            up_fields = list(getattr(asdu_layer, "rco_up").all_fields)
            se_fields: list = []
            if se_raw is not None:
                try:
                    se_fields = list(getattr(asdu_layer, "rco_se").all_fields)
                except Exception as e:
                    self.logger.debug(f"Failed to get se_fields: {e}")
            for i, f in enumerate(up_fields):
                val = _RCO_VALUES.get(int(f.show), str(f.show))
                if i < len(se_fields) and str(se_fields[i].show) == "True":
                    val += "(S)"
                result.append(val)
        except Exception:
            try:
                val = _RCO_VALUES.get(int(up_raw), str(up_raw))
            except (ValueError, TypeError):
                val = str(up_raw)
            if se_raw is not None and str(se_raw) == "True":
                val += "(S)"
            result.append(val)
        return result

    def _extract_coi_values(self, asdu_layer) -> List[str]:
        """Extract cause of initialization values."""
        raw = self.get_field(asdu_layer, "coi_r", None)
        if raw is None:
            return []
        coi_reasons = {0: "local_power", 1: "local_reset", 2: "remote_reset"}
        try:
            reason = coi_reasons.get(int(raw), str(raw))
        except (ValueError, TypeError):
            reason = str(raw)
        return [f"COI={reason}"]

    def _extract_simple_field(self, asdu_layer, field_name: str, prefix: str = "") -> List[str]:
        """Extract a simple single-valued field."""
        raw = self.get_field(asdu_layer, field_name, None)
        if raw is None:
            return []
        return [f"{prefix}{raw}"]

    # ------------------------------------------------------------------
    # Quality extraction
    # ------------------------------------------------------------------

    def _extract_quality(self, asdu_layer, type_id: int) -> List[str]:
        """Extract quality flags per IOA as abbreviated strings.

        Returns a list of quality strings (one per IOA), e.g. ["IV,NT", "", "OV"].
        Empty strings mean no quality issues (all flags OK).
        """
        cat = _TYPE_CATEGORIES.get(type_id)
        if cat is None:
            return []

        quality_source = cat[1]
        if quality_source is None:
            return []

        if quality_source == "qds":
            return self._extract_qds_flags(asdu_layer)
        elif quality_source == "siq":
            return self._extract_siq_flags(asdu_layer)
        elif quality_source == "diq":
            return self._extract_diq_flags(asdu_layer)
        return []

    def _extract_qds_flags(self, asdu_layer) -> List[str]:
        """Extract QDS quality descriptor set flags per IOA."""
        flag_fields = [
            ("qds_iv", "IV"),
            ("qds_nt", "NT"),
            ("qds_sb", "SB"),
            ("qds_bl", "BL"),
            ("qds_ov", "OV"),
        ]
        return self._collect_quality_flags(asdu_layer, flag_fields)

    def _extract_siq_flags(self, asdu_layer) -> List[str]:
        """Extract SIQ quality flags per IOA."""
        flag_fields = [
            ("siq_iv", "IV"),
            ("siq_nt", "NT"),
            ("siq_sb", "SB"),
            ("siq_bl", "BL"),
        ]
        return self._collect_quality_flags(asdu_layer, flag_fields)

    def _extract_diq_flags(self, asdu_layer) -> List[str]:
        """Extract DIQ quality flags per IOA."""
        flag_fields = [
            ("diq_iv", "IV"),
            ("diq_nt", "NT"),
            ("diq_sb", "SB"),
            ("diq_bl", "BL"),
        ]
        return self._collect_quality_flags(asdu_layer, flag_fields)

    def _collect_quality_flags(self, asdu_layer, flag_fields: List[Tuple[str, str]]) -> List[str]:
        """Collect quality flags across multiple IOAs.

        For each IOA, builds a comma-separated string of active flag abbreviations.
        """
        # Determine how many IOAs we have from the first available flag field
        n_ioas = 0
        flag_arrays: List[List[bool]] = []

        for attr_name, _abbrev in flag_fields:
            raw = self.get_field(asdu_layer, attr_name, None)
            if raw is None:
                flag_arrays.append([])
                continue

            bools: List[bool] = []
            try:
                for f in getattr(asdu_layer, attr_name).all_fields:
                    bools.append(str(f.show) == "True")
            except Exception:
                bools.append(str(raw) == "True")

            flag_arrays.append(bools)
            if len(bools) > n_ioas:
                n_ioas = len(bools)

        if n_ioas == 0:
            return []

        result: List[str] = []
        for i in range(n_ioas):
            active: List[str] = []
            for j, (_attr, abbrev) in enumerate(flag_fields):
                arr = flag_arrays[j]
                if i < len(arr) and arr[i]:
                    active.append(abbrev)
            result.append("|".join(active))
        return result

    # ------------------------------------------------------------------
    # Summary and formatting
    # ------------------------------------------------------------------

    @staticmethod
    def _build_i_frame_summary(
        type_id: int,
        type_name: str,
        ioa_list: List[int],
        common_addr: int,
        is_control: bool,
        values: Optional[List[str]] = None,
        cot_name: str = "",
        is_error: bool = False,
    ) -> str:
        """Build summary for I-frame interaction."""
        if is_error:
            prefix = "ERR"
        elif is_control:
            prefix = "CMD"
        else:
            prefix = "MON"

        ioa_str = ""
        if ioa_list:
            if len(ioa_list) == 1:
                ioa_str = f" IOA={ioa_list[0]}"
            else:
                ioa_str = f" IOA={ioa_list[0]}-{ioa_list[-1]}"

        ca_str = f" CA={common_addr}" if common_addr else ""
        cot_str = f" COT={cot_name}" if cot_name else ""
        val_str = ""
        if values:
            if len(values) == 1:
                val_str = f" val={values[0]}"
            else:
                val_str = f" val=[{','.join(values)}]"
        return f"{prefix} {type_name}{ioa_str}{ca_str}{cot_str}{val_str}"

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
