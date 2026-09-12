"""
IEC 60870-5-101 Passive Listener (PyShark-based).

Passively monitors IEC 101 serial telecontrol traffic (often tunneled over
TCP in modern deployments) to identify:
- Controlling stations (SCADA/master) and controlled stations (RTU/slave)
- Link addresses and data link layer function codes
- ASDU type IDs, cause of transmission, common addresses, IOAs
- Measurement values (single/double point, measured values, counters)
- Control commands and their parameters
- Quality flags (IV, NT, SB, BL, OV)

IEC 101 is the serial sibling of IEC 104.  Both share the same ASDU layer
(iec60870_asdu) but differ at the link layer: IEC 101 uses FT1.2 framing
with link addresses, while IEC 104 uses TCP with APCI framing.

tshark fields used:
- iec60870_101.linkaddr: Data link address (FT_UINT16)
- iec60870_101.ctrl_prm: Primary message flag (FT_UINT8)
- iec60870_101.ctrl_fcb: Frame count bit (FT_UINT8)
- iec60870_101.ctrl_fcv: Frame count bit valid (FT_UINT8)
- iec60870_101.ctrl_dfc: Data flow control (FT_UINT8)
- iec60870_101.ctrl_func_pri_to_sec: Function code, primary to secondary (FT_UINT8)
- iec60870_101.ctrl_func_sec_to_pri: Function code, secondary to primary (FT_UINT8)
- iec60870_101.header: Frame format byte (FT_UINT8)
- iec60870_101.length: Frame length (FT_UINT8)
- iec60870_asdu.*: Shared ASDU layer fields (same as IEC 104)

References:
- IEC 60870-5-101:2003 Telecontrol companion standard
- IEC 60870-5-5:2000 Basic application functions
- Wireshark dissector: packet-iec104.c (handles both 101 and 104)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

from ._iec_common import classify_rw, parse_asdu_field

# Reuse the comprehensive ASDU type ID definitions from IEC 104
from .iec104 import (
    TYPE_IDS,
    CONTROL_TYPE_IDS,
    COT_NAMES,
    _WRITE_TYPE_IDS,
    _READ_COMMAND_TYPE_IDS,
    _SYSTEM_TYPE_IDS,
    _FILE_TYPE_IDS,
    _ERROR_COTS,
    _TYPE_CATEGORIES,
    _DPI_VALUES,
    _DCO_VALUES,
    _RCO_VALUES,
)

# IEC 101 link layer function codes (primary station -> secondary station)
# FT1.2 framing per IEC 60870-5-1 / IEC 60870-5-2
LINK_FUNC_PRI_TO_SEC = {
    0: "Reset Remote Link",
    1: "Reset User Process",
    2: "Test Function for Link",
    3: "User Data (Confirmed)",
    4: "User Data (No Reply)",
    8: "Expected Response Specifies Access Demand",
    9: "Request Status of Link",
    10: "Request User Data Class 1",
    11: "Request User Data Class 2",
}

# IEC 101 link layer function codes (secondary station -> primary station)
LINK_FUNC_SEC_TO_PRI = {
    0: "ACK (positive)",
    1: "NACK (link busy)",
    8: "User Data",
    9: "No Data Available (NACK)",
    11: "Status of Link / Access Demand",
    14: "Link Not Functioning",
    15: "Link Not Implemented",
}


@dataclass
class IEC101Session:
    """Track IEC 101 session statistics."""

    controlling_ip: str  # SCADA/master
    controlled_ip: str  # RTU/slave
    link_addresses: Set[int] = field(default_factory=set)
    common_addresses: Set[int] = field(default_factory=set)
    type_ids: Set[int] = field(default_factory=set)
    ioa_seen: Set[int] = field(default_factory=set)
    control_count: int = 0
    monitor_count: int = 0
    first_seen: str = ""
    last_seen: str = ""


class IEC101PassiveListener(PySharkListenerBase):
    """Passive IEC 60870-5-101 traffic listener (PyShark-based).

    Monitors IEC 101 telecontrol traffic (serial protocol, commonly tunneled
    over TCP) without sending packets to:
    - Identify controlling stations (SCADA) and controlled stations (RTU)
    - Track link addresses and data link layer functions
    - Track common addresses (ASDU addresses) and type IDs
    - Extract actual data values per IOA (measurements, commands, setpoints)
    - Report quality flags (IV, NT, SB, BL, OV)
    - Detect control commands in the command direction

    Usage:
        listener = IEC101PassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "iec101"
    DISPLAY_FILTER = "iec60870_101"
    REQUIRED_LAYERS = ("iec60870_101",)
    PROTOCOL_COLUMNS = (
        "rw",
        "operation",
        "link_addr",
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
        self.sessions: Dict[Tuple[str, str], IEC101Session] = {}

    def process_packet(self, packet) -> None:
        """Process IEC 101 packet using PyShark."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        if not hasattr(packet, "iec60870_101"):
            return

        iec101_layer = packet.iec60870_101

        # Extract link address
        link_addr_raw = self.get_field(iec101_layer, "linkaddr", None)
        link_addr = self._parse_int(link_addr_raw, 0)

        # Determine direction from PRM (Primary Message) bit
        # PRM=1: primary station sending (master -> slave)
        # PRM=0: secondary station sending (slave -> master)
        prm_raw = self.get_field(iec101_layer, "ctrl_prm", None)
        is_primary = self._parse_int(prm_raw, 0) == 1

        if is_primary:
            # Master sending to slave
            controlling_ip = src_ip
            controlled_ip = dst_ip
            controlling_mac = src_mac
            controlled_mac = dst_mac
        else:
            # Slave responding to master
            controlling_ip = dst_ip
            controlled_ip = src_ip
            controlling_mac = dst_mac
            controlled_mac = src_mac

        session = self._ensure_session(controlling_ip, controlled_ip)
        session.link_addresses.add(link_addr)

        # Extract link layer function code
        func_pri_raw = self.get_field(iec101_layer, "ctrl_func_pri_to_sec", None)
        func_sec_raw = self.get_field(iec101_layer, "ctrl_func_sec_to_pri", None)

        # Check frame format to determine variable-length vs fixed-length
        header_raw = self.get_field(iec101_layer, "header", None)
        # EK mode (oida pcap -r) hands over a bare DECIMAL int for this BASE_HEX
        # field (229, not "0xe5"); base=16 turned 229 into 553 and 16 into 22, so
        # the 0xE5 single-char-ACK test below could never fire.  _parse_int still
        # auto-detects the "0x" prefix XML mode produces.
        header_val = self._parse_int(header_raw, 0)

        # Process ASDU if present (variable-length frames with user data)
        if hasattr(packet, "iec60870_asdu"):
            self._process_asdu(packet, session, src_ip, dst_ip, flow_id, link_addr, is_primary)
        else:
            # Link-layer only frame (fixed-length or no ASDU)
            self._process_link_frame(
                packet,
                src_ip,
                dst_ip,
                flow_id,
                link_addr,
                is_primary,
                func_pri_raw,
                func_sec_raw,
                header_val,
            )

        # Update devices
        self._update_devices(controlling_ip, controlling_mac, controlled_ip, controlled_mac)

    def _ensure_session(self, controlling_ip: str, controlled_ip: str) -> IEC101Session:
        """Ensure session exists and return it."""
        session_key = (controlling_ip, controlled_ip)
        now = datetime.now().isoformat()

        if session_key not in self.sessions:
            self.sessions[session_key] = IEC101Session(
                controlling_ip=controlling_ip,
                controlled_ip=controlled_ip,
                first_seen=now,
                last_seen=now,
            )

        session = self.sessions[session_key]
        session.last_seen = now
        return session

    def _process_link_frame(
        self,
        packet,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        link_addr: int,
        is_primary: bool,
        func_pri_raw: Any,
        func_sec_raw: Any,
        header_val: int,
    ) -> None:
        """Process link-layer only frame (no ASDU)."""
        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)

        if is_primary and func_pri_raw is not None:
            func_code = self._parse_int(func_pri_raw, -1)
            func_name = LINK_FUNC_PRI_TO_SEC.get(func_code, f"PRI Func {func_code}")
            direction = "request"
        elif not is_primary and func_sec_raw is not None:
            func_code = self._parse_int(func_sec_raw, -1)
            func_name = LINK_FUNC_SEC_TO_PRI.get(func_code, f"SEC Func {func_code}")
            direction = "response"
        else:
            func_code = -1
            func_name = "Unknown Link Func"
            direction = "request" if is_primary else "response"

        # Fixed-length frames (0x10) vs single-char frames (0xE5)
        if header_val == 0xE5:
            operation = "Single Char ACK (E5h)"
        elif header_val == 0x10:
            operation = f"Link: {func_name}"
        else:
            operation = f"Link: {func_name}"

        details: Dict[str, Any] = {
            "link_addr": link_addr,
            "frame_type": "link",
            "is_primary": is_primary,
        }
        if func_code >= 0:
            details["link_func_code"] = func_code
            details["link_func_name"] = func_name

        summary = f"Link {func_name} addr={link_addr}"

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

    def _process_asdu(
        self,
        packet,
        session: IEC101Session,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        link_addr: int,
        is_primary: bool,
    ) -> None:
        """Process ASDU layer (shared with IEC 104)."""
        asdu_layer = packet.iec60870_asdu

        type_id_raw = self.get_field(asdu_layer, "typeid", None)
        if not type_id_raw:
            now = datetime.now().isoformat()
            _sp, _dp = self.get_port_info(packet)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request" if is_primary else "response",
                "ASDU (malformed)",
                {"link_addr": link_addr, "malformed": True},
                f"Malformed ASDU link_addr={link_addr}",
                flow_id=flow_id,
                src_port=_sp,
                dst_port=_dp,
                stream_id=self.get_stream_id(packet),
            )
            return

        try:
            type_id = int(type_id_raw)
        except (ValueError, TypeError):
            # Unparseable or multi-value EK typeid (e.g. "1,3"): record a
            # malformed interaction and log, rather than silently dropping the
            # frame (mirrors the empty-typeid branch above and the iec104 path).
            self.logger.debug(
                "IEC101 unparseable ASDU typeid %r link_addr=%s", type_id_raw, link_addr
            )
            now = datetime.now().isoformat()
            _sp, _dp = self.get_port_info(packet)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request" if is_primary else "response",
                "ASDU (malformed)",
                {"link_addr": link_addr, "malformed": True, "typeid_raw": str(type_id_raw)},
                f"Malformed ASDU typeid={type_id_raw} link_addr={link_addr}",
                flow_id=flow_id,
                src_port=_sp,
                dst_port=_dp,
                stream_id=self.get_stream_id(packet),
            )
            return

        # Parse common address
        common_addr_raw = self.get_field(asdu_layer, "addr", None)
        common_addr = 0
        if common_addr_raw:
            try:
                common_addr = int(common_addr_raw)
            except (ValueError, TypeError):
                pass
        session.common_addresses.add(common_addr)

        # Parse IOAs
        ioa_list = self._get_multi_field_ints(asdu_layer, "ioa")
        for ioa in ioa_list:
            session.ioa_seen.add(ioa)

        # Parse cause of transmission
        cause_tx = parse_asdu_field(self.get_field(asdu_layer, "causetx", None), 0)

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
        rw = classify_rw(
            type_id,
            is_error_cot,
            write_ids=_WRITE_TYPE_IDS,
            read_ids=_READ_COMMAND_TYPE_IDS,
            system_ids=_SYSTEM_TYPE_IDS,
            file_ids=_FILE_TYPE_IDS,
        )

        details: Dict[str, Any] = {
            "type_id": type_id,
            "type_name": type_name,
            "link_addr": link_addr,
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
            link_addr,
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

    # ------------------------------------------------------------------
    # Multi-field helpers (same pattern as IEC 104)
    # ------------------------------------------------------------------

    def _get_multi_field_ints(self, layer, field_name: str) -> List[int]:
        """Get all instances of an integer field from a PyShark layer."""
        result: List[int] = []
        raw = self.get_field(layer, field_name, None)
        if raw is None:
            return result
        try:
            for f in getattr(layer, field_name).all_fields:
                result.append(int(f.show))
        except Exception:
            for part in str(raw).split(","):
                try:
                    result.append(int(part.strip()))
                except (ValueError, TypeError):
                    pass
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

    # ------------------------------------------------------------------
    # Value extraction (reuse IEC 104 ASDU type categories)
    # ------------------------------------------------------------------

    def _extract_values(self, asdu_layer, type_id: int) -> List[str]:
        """Extract per-IOA values from the ASDU layer based on type ID."""
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
        """Extract step position VTI values."""
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
            raw_vals = self._get_multi_field_strs(asdu_layer, "vti")
            result.extend(raw_vals)
        return result

    def _extract_float_values(self, asdu_layer) -> List[str]:
        """Extract short floating point values."""
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
        """Extract binary counter reading values."""
        result: List[str] = []
        raw = self.get_field(asdu_layer, "bcr_count", None)
        if raw is not None:
            try:
                for f in getattr(asdu_layer, "bcr_count").all_fields:
                    result.append(str(f.show))
            except Exception:
                result.append(str(raw))
        if not result:
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
                except Exception:
                    pass
            for i, f in enumerate(on_fields):
                val = "ON" if str(f.show) == "True" else "OFF"
                if i < len(se_fields) and str(se_fields[i].show) == "True":
                    val += "(S)"
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
                except Exception:
                    pass
            for i, f in enumerate(on_fields):
                val = _DCO_VALUES.get(int(f.show), str(f.show))
                if i < len(se_fields) and str(se_fields[i].show) == "True":
                    val += "(S)"
                result.append(val)
        except Exception:
            try:
                val = _DCO_VALUES.get(int(on_raw), str(on_raw))
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
                except Exception:
                    pass
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
    # Quality extraction (same as IEC 104)
    # ------------------------------------------------------------------

    def _extract_quality(self, asdu_layer, type_id: int) -> List[str]:
        """Extract quality flags per IOA."""
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
        """Collect quality flags across multiple IOAs."""
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
    def _build_asdu_summary(
        type_id: int,
        type_name: str,
        ioa_list: List[int],
        common_addr: int,
        link_addr: int,
        is_control: bool,
        values: Optional[List[str]] = None,
        cot_name: str = "",
        is_error: bool = False,
    ) -> str:
        """Build summary for ASDU interaction."""
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
        la_str = f" LA={link_addr}" if link_addr else ""
        cot_str = f" COT={cot_name}" if cot_name else ""
        val_str = ""
        if values:
            if len(values) == 1:
                val_str = f" val={values[0]}"
            else:
                val_str = f" val=[{','.join(values)}]"
        return f"{prefix} {type_name}{la_str}{ioa_str}{ca_str}{cot_str}{val_str}"

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        type_id = d.get("type_id", "")
        type_name = d.get("type_name", "")
        common_addr = d.get("common_address", "")
        link_addr = d.get("link_addr", "")

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

        # Type ID column
        type_str = f"{type_id} ({type_name})" if type_id else ""

        # COT column
        cot_name = d.get("cot_name", "")
        if not cot_name:
            cot_raw = d.get("cause_of_transmission", 0)
            if cot_raw:
                cot_name = COT_NAMES.get(cot_raw, str(cot_raw))

        # Value column
        values = d.get("values", [])
        if isinstance(values, list) and values:
            val_str = " | ".join(values)
        else:
            val_str = ""

        # Quality column
        quality = d.get("quality", [])
        if isinstance(quality, list) and quality:
            active = [q for q in quality if q]
            qual_str = ";".join(active) if active else ""
        else:
            qual_str = ""

        rw = d.get("rw", "")

        return [
            rw,
            ix.operation,
            link_addr if link_addr else "",
            type_str,
            cot_name,
            common_addr if common_addr else "",
            ioa_str,
            val_str,
            qual_str,
        ]

    # ------------------------------------------------------------------
    # Device management
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
            key = f"iec101-controlled:{controlled_ip}"
            device, is_new = self._ensure_device(
                key,
                controlled_ip,
                mac=controlled_mac,
                manufacturer=controlled_vendor if controlled_vendor else "",
                device_type="IEC 101 Controlled Station (RTU)",
            )
            device.protocol_data = self._build_data("controlled_station", session)
            if is_new:
                self.logger.debug(
                    f"IEC101: RTU {controlled_ip} LA={list(session.link_addresses)} "
                    f"CA={list(session.common_addresses)}"
                )

        # Controlling station (SCADA)
        if is_valid_discovered_ip(controlling_ip):
            controlling_vendor = lookup_mac_vendor(controlling_mac) if controlling_mac else ""
            key = f"iec101-controlling:{controlling_ip}"
            device, is_new = self._ensure_device(
                key,
                controlling_ip,
                mac=controlling_mac,
                manufacturer=controlling_vendor,
                device_type="IEC 101 Controlling Station (SCADA)",
            )
            device.protocol_data = self._build_data("controlling_station", session)

    def _build_data(self, role: str, session: IEC101Session) -> Dict[str, Any]:
        """Build protocol_data dict."""
        return {
            "role": role,
            "link_addresses": sorted(list(session.link_addresses)),
            "common_addresses": sorted(list(session.common_addresses)),
            "type_ids_seen": sorted(list(session.type_ids)),
            "type_names": [TYPE_IDS.get(t, f"Type{t}") for t in sorted(session.type_ids)],
            "ioa_ranges": self._merge_ioa_ranges(session.ioa_seen),
            "control_commands": session.control_count,
            "monitor_messages": session.monitor_count,
            "protocol": "IEC101/Serial",
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
            if ioa <= end + 10:
                end = ioa
            else:
                ranges.append((start, end))
                start = end = ioa
        ranges.append((start, end))
        return ranges

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed IEC 101 sessions."""
        return [
            {
                "controlling": session.controlling_ip,
                "controlled": session.controlled_ip,
                "link_addresses": sorted(list(session.link_addresses)),
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
