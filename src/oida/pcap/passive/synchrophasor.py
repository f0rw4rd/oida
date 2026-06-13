"""
IEEE C37.118 Synchrophasor Passive Listener (PyShark-based).

Passively monitors IEEE C37.118 synchrophasor protocol traffic to identify:
- Phasor Measurement Units (PMUs) by IDCODE
- Phasor Data Concentrators (PDCs) aggregating PMU streams
- Frame types: DATA, CONFIG-1/2/3, HEADER, COMMAND
- Data rates and PMU configuration
- STAT word flags (data quality, time quality, sync status)
- COMMAND frames (security-relevant: enable/disable transmission, config changes)
- Time quality indicators and PMU clock synchronization status

IEEE C37.118 is the standard protocol for wide-area power grid monitoring
using synchronized phasor measurements.  PMUs measure voltage/current phasors
at precise GPS-synchronized timestamps and stream data to PDCs.

tshark fields used:
- synphasor.frtype: Frame type (FT_UINT16, mask 0x70)
- synphasor.version: Protocol version (FT_UINT16, mask 0x0F)
- synphasor.frsize: Frame size in bytes (FT_UINT16)
- synphasor.idcode_stream_source: PMU/DC ID for stream source (FT_UINT16)
- synphasor.idcode_data_source: PMU/DC ID for data source (FT_UINT16)
- synphasor.soc: SOC timestamp (FT_ABSOLUTE_TIME)
- synphasor.fracsec_raw: Fractional second (FT_UINT24)
- synphasor.fracsec_ms: Fractional second in milliseconds (FT_FLOAT)
- synphasor.timeqal.timequalindic: Time quality indicator (FT_UINT8)
- synphasor.timeqal.lsocc: Leap second occurred (FT_BOOLEAN)
- synphasor.timeqal.lspend: Leap second pending (FT_BOOLEAN)
- synphasor.command: Command word (FT_UINT16)
- synphasor.data.status: STAT word data error bits (FT_UINT16)
- synphasor.data.sync: Time synchronized flag (FT_BOOLEAN)
- synphasor.data.sorting: Data sorting flag (FT_BOOLEAN)
- synphasor.data.trigger: Trigger detected flag (FT_BOOLEAN)
- synphasor.data.CFGchange: Configuration changed flag (FT_BOOLEAN)
- synphasor.data.data_modified: Data modified indicator (FT_BOOLEAN)
- synphasor.data.pmu_tq: PMU time quality (FT_UINT16)
- synphasor.data.t_unlock: Unlocked time (FT_UINT16)
- synphasor.data.trigger_reason: Trigger reason (FT_UINT16)
- synphasor.conf.numpmu: Number of PMU blocks in config (FT_UINT16)
- synphasor.conf.fnom: Nominal line frequency (FT_BOOLEAN)
- synphasor.conf.cfgcnt: Configuration change count (FT_UINT16)
- synphasor.station_name: Station name string (FT_STRING)
- synphasor.num_phasors: Number of phasors (FT_UINT16)
- synphasor.num_analog_values: Number of analog values (FT_UINT16)
- synphasor.num_digital_status_words: Number of digital status words (FT_UINT16)
- synphasor.rate_of_transmission: Reporting rate (FT_INT16)
- synphasor.actual_frequency_value: Actual frequency (FT_FLOAT)
- synphasor.rate_change_frequency: ROCOF (FT_FLOAT)
- synphasor.phasor: Phasor value string (FT_STRING)

References:
- IEEE C37.118.1-2011: Synchrophasor measurements for power systems
- IEEE C37.118.2-2011: Synchrophasor data transfer for power systems
- Wireshark dissector: packet-synphasor.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# IEEE C37.118 Frame Types (from synphasor.frtype, shifted)
# The frtype field has mask 0x70, so values are 0x00-0x70 in steps of 0x10
# After mask extraction by tshark: 0=DATA, 1=HEADER, 2=CFG1, 3=CFG2, 4=CMD, 5=CFG3
FRAME_TYPES = {
    0x00: "DATA",
    0x10: "HEADER",
    0x20: "CONFIG-1",
    0x30: "CONFIG-2",
    0x40: "COMMAND",
    0x50: "CONFIG-3",
}

# Alternative mapping for when tshark returns already-shifted values (0-5)
_FRAME_TYPE_SHORT = {
    0: "DATA",
    1: "HEADER",
    2: "CONFIG-1",
    3: "CONFIG-2",
    4: "COMMAND",
    5: "CONFIG-3",
}

# IEEE C37.118 Command Words
COMMAND_WORDS = {
    0x0001: "Turn off data transmission",
    0x0002: "Turn on data transmission",
    0x0003: "Send HDR frame",
    0x0004: "Send CFG-1 frame",
    0x0005: "Send CFG-2 frame",
    0x0006: "Send CFG-3 frame",
    0x0008: "Extended frame",
}

# Security-relevant commands (can affect PMU operation)
_DANGEROUS_COMMANDS = {
    0x0001,  # Turn off data transmission
    0x0002,  # Turn on data transmission
    0x0008,  # Extended frame (vendor-specific, potentially dangerous)
}

# Data error values from STAT word (bits 15-14)
_DATA_ERRORS = {
    0x0000: "Good measurement data, no errors",
    0x4000: "PMU error, no information about data",
    0x8000: "PMU in test mode",
    0xC000: "PMU error (not connected or not accessible)",
}

# Time quality indicator codes (synphasor.timeqal.timequalindic)
_TIME_QUALITY = {
    0x0: "Normal, clock locked",
    0x1: "10 seconds",
    0x2: "1 second",
    0x3: "100 milliseconds",
    0x4: "10 milliseconds",
    0x5: "1 millisecond",
    0x6: "100 microseconds",
    0x7: "10 microseconds",
    0x8: "1 microsecond",
    0x9: "100 nanoseconds",
    0xA: "Not used",
    0xB: "Not used",
    0xC: "Not used",
    0xD: "Not used",
    0xE: "Not used",
    0xF: "Clock failure, time not reliable",
}

# PMU time quality codes (synphasor.data.pmu_tq)
_PMU_TIME_QUALITY = {
    0x00: "Not used (normal operation)",
    0x40: "Max time error < 100 ns",
    0x80: "Max time error < 1 us",
    0xC0: "Max time error < 10 us",
    0x100: "Max time error < 100 us",
    0x140: "Max time error < 1 ms",
    0x180: "Max time error < 10 ms",
    0x1C0: "Time error > 10 ms or unknown",
}

# Unlock time codes (synphasor.data.t_unlock)
_UNLOCK_TIME = {
    0x00: "Sync locked or unlocked < 10 s",
    0x10: "Unlocked > 10 s",
    0x20: "Unlocked > 100 s",
    0x30: "Unlocked > 1000 s",
}


def _resolve_frame_type(raw_val: int) -> str:
    """Resolve frame type from tshark value (handles both shifted and unshifted)."""
    if raw_val in FRAME_TYPES:
        return FRAME_TYPES[raw_val]
    if raw_val in _FRAME_TYPE_SHORT:
        return _FRAME_TYPE_SHORT[raw_val]
    return f"Unknown (0x{raw_val:02x})"


@dataclass
class PMUInfo:
    """Track information about a PMU/PDC endpoint."""

    idcode: int
    ip: str
    station_name: str = ""
    num_phasors: int = 0
    num_analog: int = 0
    num_digital: int = 0
    data_rate: int = 0
    nominal_freq: str = ""  # "50Hz" or "60Hz"
    config_change_count: int = 0
    data_frames_seen: int = 0
    command_frames_seen: int = 0
    config_frames_seen: int = 0
    unsync_count: int = 0
    data_error_count: int = 0
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class SynchrophasorSession:
    """Track a synchrophasor communication session."""

    src_ip: str
    dst_ip: str
    frame_types_seen: Set[str] = field(default_factory=set)
    idcodes: Set[int] = field(default_factory=set)
    command_count: int = 0
    data_count: int = 0
    config_count: int = 0
    first_seen: str = ""
    last_seen: str = ""


class SynchrophasorPassiveListener(PySharkListenerBase):
    """Passive IEEE C37.118 synchrophasor traffic listener (PyShark-based).

    Monitors PMU/PDC synchrophasor traffic without sending packets to:
    - Identify PMUs and PDCs by IDCODE and station name
    - Track data rates and phasor configurations
    - Monitor STAT word for data quality and time sync issues
    - Detect COMMAND frames (especially enable/disable transmission)
    - Track configuration changes and version information
    - Map PMU-to-PDC aggregation topology

    Usage:
        listener = SynchrophasorPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "synchrophasor"
    DISPLAY_FILTER = "synphasor"
    REQUIRED_LAYERS = ("synphasor",)
    PROTOCOL_COLUMNS = (
        "rw",
        "operation",
        "idcode",
        "frame_type",
        "detail",
    )

    # Default synchrophasor ports
    _DEFAULT_PORTS = {4712, 4713}

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], SynchrophasorSession] = {}
        self.pmu_info: Dict[int, PMUInfo] = {}  # IDCODE -> PMUInfo

    def process_packet(self, packet) -> None:
        """Process IEEE C37.118 synchrophasor packet."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        if not hasattr(packet, "synphasor"):
            return

        syn = packet.synphasor

        # Extract frame type
        frtype_raw = self.get_field(syn, "frtype", None)
        frtype_val = self._parse_int(frtype_raw, default=None, base=16)
        if frtype_val is None:
            return

        frame_type_name = _resolve_frame_type(frtype_val)

        # Extract IDCODE (try stream source first, then data source)
        idcode_raw = self.get_field(syn, "idcode_stream_source", None)
        if idcode_raw is None:
            idcode_raw = self.get_field(syn, "idcode_data_source", None)
        idcode = self._parse_int(idcode_raw, 0)

        # Extract version
        version_raw = self.get_field(syn, "version", None)
        version = self._parse_int(version_raw, 0)

        # Extract frame size
        frsize_raw = self.get_field(syn, "frsize", None)
        frsize = self._parse_int(frsize_raw, 0)

        # Update session
        session = self._ensure_session(src_ip, dst_ip)
        session.frame_types_seen.add(frame_type_name)
        if idcode:
            session.idcodes.add(idcode)

        # Route to frame-specific handler
        if frame_type_name == "DATA":
            self._process_data_frame(
                packet,
                syn,
                src_ip,
                dst_ip,
                flow_id,
                idcode,
                version,
                frsize,
                src_mac,
                dst_mac,
            )
            session.data_count += 1
        elif frame_type_name == "COMMAND":
            self._process_command_frame(
                packet,
                syn,
                src_ip,
                dst_ip,
                flow_id,
                idcode,
                version,
            )
            session.command_count += 1
        elif frame_type_name in ("CONFIG-1", "CONFIG-2", "CONFIG-3"):
            self._process_config_frame(
                packet,
                syn,
                src_ip,
                dst_ip,
                flow_id,
                idcode,
                version,
                frame_type_name,
                src_mac,
                dst_mac,
            )
            session.config_count += 1
        elif frame_type_name == "HEADER":
            self._process_header_frame(
                packet,
                syn,
                src_ip,
                dst_ip,
                flow_id,
                idcode,
                version,
            )
        else:
            self._process_unknown_frame(
                packet,
                src_ip,
                dst_ip,
                flow_id,
                idcode,
                frame_type_name,
            )

    def _ensure_session(self, src_ip: str, dst_ip: str) -> SynchrophasorSession:
        """Ensure session exists and return it."""
        session_key = (src_ip, dst_ip)
        now = datetime.now().isoformat()

        if session_key not in self.sessions:
            self.sessions[session_key] = SynchrophasorSession(
                src_ip=src_ip,
                dst_ip=dst_ip,
                first_seen=now,
                last_seen=now,
            )

        session = self.sessions[session_key]
        session.last_seen = now
        return session

    def _ensure_pmu(self, idcode: int, ip: str) -> PMUInfo:
        """Ensure PMU info entry exists and return it."""
        now = datetime.now().isoformat()
        if idcode not in self.pmu_info:
            self.pmu_info[idcode] = PMUInfo(
                idcode=idcode,
                ip=ip,
                first_seen=now,
                last_seen=now,
            )
        pmu = self.pmu_info[idcode]
        pmu.last_seen = now
        return pmu

    def _process_data_frame(
        self,
        packet,
        syn,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        idcode: int,
        version: int,
        frsize: int,
        src_mac: str,
        dst_mac: str,
    ) -> None:
        """Process DATA frame -- contains measurement data."""
        pmu = self._ensure_pmu(idcode, src_ip)
        pmu.data_frames_seen += 1

        # Extract STAT word flags
        stat_flags: List[str] = []
        data_error_raw = self.get_field(syn, "data_status", None)
        if data_error_raw is not None:
            data_error = self._parse_int(data_error_raw, 0, base=16)
            # Bits 15-14 are data error
            error_bits = data_error & 0xC000
            if error_bits != 0:
                error_desc = _DATA_ERRORS.get(error_bits, f"Error 0x{error_bits:04x}")
                stat_flags.append(f"ERR:{error_desc}")
                pmu.data_error_count += 1

        sync_raw = self.get_field(syn, "data_sync", None)
        if sync_raw is not None and not self._parse_bool(sync_raw):
            stat_flags.append("UNSYNC")
            pmu.unsync_count += 1

        trigger_raw = self.get_field(syn, "data_trigger", None)
        if trigger_raw is not None and self._parse_bool(trigger_raw):
            stat_flags.append("TRIGGER")

        cfg_change_raw = self.get_field(syn, "data_CFGchange", None)
        if cfg_change_raw is not None and self._parse_bool(cfg_change_raw):
            stat_flags.append("CFG_CHANGED")

        data_mod_raw = self.get_field(syn, "data_data_modified", None)
        if data_mod_raw is not None and self._parse_bool(data_mod_raw):
            stat_flags.append("MODIFIED")

        # Extract frequency if available
        freq_raw = self.get_field(syn, "actual_frequency_value", None)
        rocof_raw = self.get_field(syn, "rate_change_frequency", None)

        freq_str = ""
        if freq_raw is not None:
            freq_str = f"freq={self._format_float(freq_raw)}Hz"
        if rocof_raw is not None:
            rocof_val = self._format_float(rocof_raw)
            if freq_str:
                freq_str += f" ROCOF={rocof_val}"
            else:
                freq_str = f"ROCOF={rocof_val}"

        # Build detail string
        detail_parts: List[str] = []
        if stat_flags:
            detail_parts.append("STAT=" + ",".join(stat_flags))
        if freq_str:
            detail_parts.append(freq_str)

        detail_str = " ".join(detail_parts) if detail_parts else "OK"

        # Determine rw -- data frames are passive reads
        rw = "read"

        details: Dict[str, Any] = {
            "idcode": idcode,
            "frame_type": "DATA",
            "version": version,
            "frame_size": frsize,
            "rw": rw,
        }
        if stat_flags:
            details["stat_flags"] = stat_flags
        if freq_raw is not None:
            details["frequency"] = str(freq_raw)
        if rocof_raw is not None:
            details["rocof"] = str(rocof_raw)

        summary = f"DATA IDCODE={idcode} {detail_str}"

        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "DATA",
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

        # Update devices
        self._update_device_pmu(src_ip, src_mac, idcode)

    def _process_command_frame(
        self,
        packet,
        syn,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        idcode: int,
        version: int,
    ) -> None:
        """Process COMMAND frame -- sent by PDC to control PMU.

        Security-critical: COMMAND frames can turn off PMU transmission,
        request configuration, or invoke vendor-specific extended commands.
        """
        cmd_raw = self.get_field(syn, "command", None)
        cmd_val = self._parse_int(cmd_raw, 0, base=16)

        # Track command-frame count on the targeted PMU (commands are addressed
        # to a PMU/PDC by IDCODE). Without this, ptp_data.command_frames stays 0.
        if idcode:
            pmu = self._ensure_pmu(idcode, dst_ip)
            pmu.command_frames_seen += 1

        cmd_name = COMMAND_WORDS.get(cmd_val, f"Command 0x{cmd_val:04x}")
        is_dangerous = cmd_val in _DANGEROUS_COMMANDS

        # Commands are control operations
        rw = "write" if is_dangerous else "control"

        details: Dict[str, Any] = {
            "idcode": idcode,
            "frame_type": "COMMAND",
            "version": version,
            "command": cmd_val,
            "command_name": cmd_name,
            "dangerous": is_dangerous,
            "rw": rw,
        }

        danger_flag = " [DANGEROUS]" if is_dangerous else ""
        summary = f"COMMAND IDCODE={idcode} {cmd_name}{danger_flag}"

        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"COMMAND: {cmd_name}",
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

    def _process_config_frame(
        self,
        packet,
        syn,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        idcode: int,
        version: int,
        frame_type_name: str,
        src_mac: str,
        dst_mac: str,
    ) -> None:
        """Process CONFIG frame -- contains PMU configuration."""
        pmu = self._ensure_pmu(idcode, src_ip)
        pmu.config_frames_seen += 1

        # Extract configuration details
        numpmu_raw = self.get_field(syn, "conf_numpmu", None)
        numpmu = self._parse_int(numpmu_raw, 0)

        station_name_raw = self.get_field(syn, "station_name", None)
        station_name = str(station_name_raw).strip() if station_name_raw else ""
        if station_name:
            pmu.station_name = station_name

        num_phasors_raw = self.get_field(syn, "num_phasors", None)
        num_phasors = self._parse_int(num_phasors_raw, 0)
        if num_phasors:
            pmu.num_phasors = num_phasors

        num_analog_raw = self.get_field(syn, "num_analog_values", None)
        num_analog = self._parse_int(num_analog_raw, 0)
        if num_analog:
            pmu.num_analog = num_analog

        num_digital_raw = self.get_field(syn, "num_digital_status_words", None)
        num_digital = self._parse_int(num_digital_raw, 0)
        if num_digital:
            pmu.num_digital = num_digital

        data_rate_raw = self.get_field(syn, "rate_of_transmission", None)
        data_rate = self._parse_int(data_rate_raw, 0)
        if data_rate:
            pmu.data_rate = data_rate

        fnom_raw = self.get_field(syn, "conf_fnom", None)
        if fnom_raw is not None:
            # Fnom bit: 0 = 60Hz, 1 = 50Hz
            fnom = self._parse_bool(fnom_raw)
            pmu.nominal_freq = "50Hz" if fnom else "60Hz"

        cfgcnt_raw = self.get_field(syn, "conf_cfgcnt", None)
        cfgcnt = self._parse_int(cfgcnt_raw, 0)
        if cfgcnt:
            pmu.config_change_count = cfgcnt

        # Build detail string
        detail_parts: List[str] = []
        if station_name:
            detail_parts.append(f"station={station_name}")
        if numpmu:
            detail_parts.append(f"PMUs={numpmu}")
        if num_phasors:
            detail_parts.append(f"phasors={num_phasors}")
        if data_rate:
            detail_parts.append(f"rate={data_rate}")
        if pmu.nominal_freq:
            detail_parts.append(pmu.nominal_freq)
        if cfgcnt:
            detail_parts.append(f"cfgcnt={cfgcnt}")

        detail_str = " ".join(detail_parts) if detail_parts else ""

        details: Dict[str, Any] = {
            "idcode": idcode,
            "frame_type": frame_type_name,
            "version": version,
            "rw": "read",
        }
        if station_name:
            details["station_name"] = station_name
        if numpmu:
            details["num_pmu"] = numpmu
        if num_phasors:
            details["num_phasors"] = num_phasors
        if num_analog:
            details["num_analog"] = num_analog
        if num_digital:
            details["num_digital"] = num_digital
        if data_rate:
            details["data_rate"] = data_rate
        if pmu.nominal_freq:
            details["nominal_freq"] = pmu.nominal_freq

        summary = f"{frame_type_name} IDCODE={idcode} {detail_str}"

        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            frame_type_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

        # Update devices
        self._update_device_pmu(src_ip, src_mac, idcode)

    def _process_header_frame(
        self,
        packet,
        syn,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        idcode: int,
        version: int,
    ) -> None:
        """Process HEADER frame -- human-readable description from PMU."""
        details: Dict[str, Any] = {
            "idcode": idcode,
            "frame_type": "HEADER",
            "version": version,
            "rw": "read",
        }

        summary = f"HEADER IDCODE={idcode} v{version}"

        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "HEADER",
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

    def _process_unknown_frame(
        self,
        packet,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        idcode: int,
        frame_type_name: str,
    ) -> None:
        """Process unknown/unrecognized frame type."""
        details: Dict[str, Any] = {
            "idcode": idcode,
            "frame_type": frame_type_name,
            "rw": "",
        }

        summary = f"{frame_type_name} IDCODE={idcode}"

        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            frame_type_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        rw = d.get("rw", "")
        idcode = d.get("idcode", "")
        frame_type = d.get("frame_type", "")

        # Build detail from various possible fields
        detail_parts: List[str] = []

        # Command details
        cmd_name = d.get("command_name")
        if cmd_name:
            detail_parts.append(cmd_name)
            if d.get("dangerous"):
                detail_parts.append("[DANGEROUS]")

        # Config details
        station = d.get("station_name")
        if station:
            detail_parts.append(f"station={station}")
        num_pmu = d.get("num_pmu")
        if num_pmu:
            detail_parts.append(f"PMUs={num_pmu}")
        num_phasors = d.get("num_phasors")
        if num_phasors:
            detail_parts.append(f"phasors={num_phasors}")
        data_rate = d.get("data_rate")
        if data_rate:
            detail_parts.append(f"rate={data_rate}")

        # Data frame details
        stat_flags = d.get("stat_flags")
        if stat_flags:
            detail_parts.append("STAT=" + ",".join(stat_flags))
        freq = d.get("frequency")
        if freq:
            detail_parts.append(f"freq={self._format_float(freq)}Hz")

        detail_str = " ".join(detail_parts)

        return [
            rw,
            ix.operation,
            idcode if idcode else "",
            frame_type,
            detail_str,
        ]

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device_pmu(self, ip: str, mac: str, idcode: int) -> None:
        """Update device entry for a PMU/PDC."""
        if not is_valid_discovered_ip(ip) or not idcode:
            return

        pmu = self.pmu_info.get(idcode)
        if not pmu:
            return

        vendor = lookup_mac_vendor(mac) if mac else ""
        device_type = "Synchrophasor PMU"
        name = pmu.station_name if pmu.station_name else f"PMU IDCODE={idcode}"

        key = f"synchrophasor-pmu:{ip}:{idcode}"
        device, is_new = self._ensure_device(
            key,
            ip,
            mac=mac,
            name=name,
            manufacturer=vendor if vendor else "",
            device_type=device_type,
        )
        device.protocol_data = self._build_pmu_data(pmu)
        if is_new:
            self.logger.debug(
                f"Synchrophasor: PMU IDCODE={idcode} at {ip}"
                f" station={pmu.station_name or 'unknown'}"
            )

    def _build_pmu_data(self, pmu: PMUInfo) -> Dict[str, Any]:
        """Build protocol_data dict for a PMU."""
        data: Dict[str, Any] = {
            "idcode": pmu.idcode,
            "protocol": "IEEE C37.118",
            "data_frames": pmu.data_frames_seen,
            "config_frames": pmu.config_frames_seen,
            "command_frames": pmu.command_frames_seen,
            "first_seen": pmu.first_seen,
            "last_seen": pmu.last_seen,
        }
        if pmu.station_name:
            data["station_name"] = pmu.station_name
        if pmu.num_phasors:
            data["num_phasors"] = pmu.num_phasors
        if pmu.num_analog:
            data["num_analog"] = pmu.num_analog
        if pmu.num_digital:
            data["num_digital"] = pmu.num_digital
        if pmu.data_rate:
            data["data_rate"] = pmu.data_rate
        if pmu.nominal_freq:
            data["nominal_freq"] = pmu.nominal_freq
        if pmu.config_change_count:
            data["config_change_count"] = pmu.config_change_count
        if pmu.unsync_count:
            data["unsync_count"] = pmu.unsync_count
        if pmu.data_error_count:
            data["data_error_count"] = pmu.data_error_count
        return data

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed synchrophasor sessions."""
        return [
            {
                "src": s.src_ip,
                "dst": s.dst_ip,
                "frame_types": sorted(s.frame_types_seen),
                "idcodes": sorted(s.idcodes),
                "data_count": s.data_count,
                "command_count": s.command_count,
                "config_count": s.config_count,
            }
            for s in self.sessions.values()
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with COMMAND frames (control operations)."""
        return [
            {
                "controlling": s.src_ip,
                "controlled": s.dst_ip,
                "control_count": s.command_count,
            }
            for s in self.sessions.values()
            if s.command_count > 0
        ]

    def get_pmu_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all discovered PMUs."""
        return [
            {
                "idcode": pmu.idcode,
                "ip": pmu.ip,
                "station_name": pmu.station_name,
                "num_phasors": pmu.num_phasors,
                "data_rate": pmu.data_rate,
                "nominal_freq": pmu.nominal_freq,
                "data_frames": pmu.data_frames_seen,
                "unsync_count": pmu.unsync_count,
                "data_error_count": pmu.data_error_count,
            }
            for pmu in sorted(self.pmu_info.values(), key=lambda p: p.idcode)
        ]
