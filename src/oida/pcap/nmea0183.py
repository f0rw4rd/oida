"""
NMEA 0183 Passive Listener for marine electronics traffic analysis (ICS).

Passively captures NMEA 0183 protocol traffic to extract:
- Sentence types (GGA, GLL, RMC, VTG, HDT, DPT, VHW, ZDA, ROT)
- Talker IDs (GP=GPS, GL=GLONASS, GA=Galileo, GN=multi-GNSS, etc.)
- GPS position data (latitude, longitude, altitude)
- Speed and heading information
- Water depth measurements
- Time and date synchronization
- GPS quality and satellite count

NMEA 0183 is the standard protocol for marine electronics (GPS, AIS,
depth sounders, autopilots, wind instruments). In maritime OT/ICS contexts,
this protocol carries critical navigation data that, if manipulated, can
cause grounding, collision, or loss of vessel.

GPS spoofing detection: sudden large jumps in position, altitude changes
inconsistent with vessel type, quality indicator changes, or satellite
count drops are indicators of potential spoofing.

tshark fields used:
- nmea0183.talker: Talker ID (FT_STRING, e.g. "GP", "GL", "GN")
- nmea0183.sentence: Sentence ID (FT_STRING, e.g. "GGA", "RMC", "HDT")
- nmea0183.checksum: Checksum value (FT_STRING)
- nmea0183.unknown_field: Unparsed fields (FT_STRING)

GGA (GPS Fix):
- nmea0183.gga_latitude_degree, gga_latitude_minute, gga_latitude_direction
- nmea0183.gga_longitude_degree, gga_longitude_minute, gga_longitude_direction
- nmea0183.gga_quality: Fix quality (0=Invalid, 1=GPS, 2=DGPS, 4=RTK, 5=Float RTK)
- nmea0183.gga_number_satellites: Satellite count
- nmea0183.gga_horizontal_dilution: HDOP
- nmea0183.gga_altitude, gga_altitude_unit: Altitude above MSL
- nmea0183.gga_time_hour, gga_time_minute, gga_time_second

GLL (Geographic Position):
- nmea0183.gll_latitude_degree, gll_latitude_minute, gll_latitude_direction
- nmea0183.gll_longitude_degree, gll_longitude_minute, gll_longitude_direction
- nmea0183.gll_status: Status (A=Active, V=Void)

HDT (Heading True):
- nmea0183.hdt_heading: True heading in degrees
- nmea0183.hdt_unit: Unit (T=True)

DPT (Depth):
- nmea0183.dpt_depth: Water depth relative to transducer
- nmea0183.dpt_offset: Transducer offset
- nmea0183.dpt_max_range: Maximum range scale

ROT (Rate of Turn):
- nmea0183.rot_rate_of_turn: Degrees per minute
- nmea0183.rot_valid: Validity (A=valid)

VHW (Water Speed and Heading):
- nmea0183.vhw_true_heading, vhw_magnetic_heading
- nmea0183.vhw_water_speed_knot, vhw_water_speed_kilometer

ZDA (Time and Date):
- nmea0183.zda_time_hour, zda_time_minute, zda_time_second
- nmea0183.zda_date_day, zda_date_month, zda_date_year

References:
- NMEA 0183 Standard for Interfacing Marine Electronics
- Wireshark dissector: packet-nmea0183.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# Talker IDs
NMEA_TALKER_IDS = {
    "GP": "GPS",
    "GL": "GLONASS",
    "GA": "Galileo",
    "GB": "BeiDou",
    "GN": "Multi-GNSS",
    "GQ": "QZSS",
    "GI": "NavIC/IRNSS",
    "HC": "Heading Compass",
    "HE": "Heading Gyro (North Seeking)",
    "HN": "Heading Gyro (Non-North Seeking)",
    "II": "Integrated Instrumentation",
    "IN": "Integrated Navigation",
    "SD": "Sounder (Depth)",
    "TI": "Turn Rate Indicator",
    "VD": "Velocity Doppler",
    "VW": "Velocity Water",
    "WI": "Weather Instruments",
    "AI": "AIS (Mobile Station)",
    "AB": "AIS (Base Station)",
    "AD": "AIS (Dependent Station)",
    "AG": "Autopilot (General)",
    "AP": "Autopilot (Magnetic)",
    "RA": "RADAR",
    "EC": "ECDIS",
    "ER": "Engine Room",
    "SS": "Scanning Sonar",
}

# Sentence types
NMEA_SENTENCES = {
    "GGA": "GPS Fix Data",
    "GLL": "Geographic Position",
    "GSA": "GPS DOP and Satellites",
    "GSV": "Satellites in View",
    "RMC": "Recommended Minimum",
    "VTG": "Track Made Good and Ground Speed",
    "HDT": "Heading True",
    "HDG": "Heading with Deviation",
    "HDM": "Heading Magnetic",
    "DPT": "Depth",
    "DBT": "Depth Below Transducer",
    "DBS": "Depth Below Surface",
    "MWV": "Wind Speed and Angle",
    "MWD": "Wind Direction and Speed",
    "MTW": "Water Temperature",
    "VHW": "Water Speed and Heading",
    "VDR": "Set and Drift",
    "RSA": "Rudder Sensor Angle",
    "ROT": "Rate of Turn",
    "RPM": "Engine RPM",
    "XTE": "Cross-Track Error",
    "RMB": "Recommended Minimum Navigation",
    "BWC": "Bearing and Distance to Waypoint",
    "BOD": "Bearing Origin to Destination",
    "WPL": "Waypoint Location",
    "RTE": "Routes",
    "GBS": "GNSS Satellite Fault Detection",
    "ZDA": "Time and Date",
    "TLL": "Target Latitude and Longitude",
    "TTM": "Tracked Target Message",
    "OSD": "Own Ship Data",
    "VDM": "AIS VHF Data-Link Message",
    "VDO": "AIS VHF Data-Link Own-Vessel",
    "ABK": "AIS Addressed/Broadcast Ack",
    "ACA": "AIS Channel Assignment",
}

# GGA quality indicators
GGA_QUALITY = {
    "0": "Invalid",
    "1": "GPS Fix",
    "2": "DGPS Fix",
    "3": "PPS Fix",
    "4": "RTK Fixed",
    "5": "RTK Float",
    "6": "Estimated",
    "7": "Manual Input",
    "8": "Simulation",
}

# Position tracking for GPS spoofing detection
MAX_POSITION_JUMP_NM = 5.0  # nautical miles -- suspicious threshold for single update


@dataclass
class NMEASource:
    """Track an NMEA 0183 data source."""

    ip: str
    talker_ids: Set[str] = field(default_factory=set)
    sentences: Set[str] = field(default_factory=set)
    last_lat: Optional[float] = None
    last_lon: Optional[float] = None
    last_altitude: Optional[float] = None
    last_quality: Optional[str] = None
    position_jumps: int = 0
    quality_changes: int = 0
    packet_count: int = 0
    first_seen: str = ""
    last_seen: str = ""


class NMEA0183PassiveListener(PySharkListenerBase):
    """Passive NMEA 0183 traffic listener for marine navigation analysis.

    Captures NMEA 0183 traffic to extract:
    - Sentence types and talker IDs
    - GPS position, altitude, quality
    - Heading, speed, depth
    - GPS spoofing indicators (position jumps, quality changes)
    """

    PROTOCOL_NAME = "nmea0183"
    DISPLAY_FILTER = "nmea0183"
    REQUIRED_LAYERS = ("nmea0183",)
    PROTOCOL_COLUMNS = ("talker", "sentence", "position", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sources: Dict[str, NMEASource] = {}  # ip -> source info

    def process_packet(self, packet) -> None:
        """Process NMEA 0183 packet."""
        if not hasattr(packet, "nmea0183"):
            return

        nmea = packet.nmea0183
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip:
            src_mac, _ = self.get_mac_info(packet)
            src_ip = f"MAC:{src_mac}" if src_mac else "unknown"
        if not dst_ip:
            _, dst_mac = self.get_mac_info(packet)
            dst_ip = f"MAC:{dst_mac}" if dst_mac else "unknown"

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        stream_id = self.get_stream_id(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        now = datetime.now().isoformat()

        # Core fields
        talker = str(self.get_field(nmea, "talker", "") or "").strip()
        sentence = str(self.get_field(nmea, "sentence", "") or "").strip()

        talker_name = NMEA_TALKER_IDS.get(talker, talker)
        sentence_name = NMEA_SENTENCES.get(sentence, sentence)

        details: Dict[str, Any] = {
            "talker_id": talker,
            "talker_name": talker_name,
            "sentence_id": sentence,
            "sentence_name": sentence_name,
        }

        position_str = ""
        detail_str = ""

        # Parse sentence-specific fields
        if sentence == "GGA":
            position_str, detail_str = self._parse_gga(nmea, details, src_ip, now)
        elif sentence == "GLL":
            position_str, detail_str = self._parse_gll(nmea, details, src_ip, now)
        elif sentence == "HDT":
            detail_str = self._parse_hdt(nmea, details)
        elif sentence == "DPT":
            detail_str = self._parse_dpt(nmea, details)
        elif sentence == "VHW":
            detail_str = self._parse_vhw(nmea, details)
        elif sentence == "ROT":
            detail_str = self._parse_rot(nmea, details)
        elif sentence == "ZDA":
            detail_str = self._parse_zda(nmea, details)

        # Build summary
        summary_parts = [f"{talker_name} {sentence_name}"]
        if position_str:
            summary_parts.append(position_str)
        if detail_str:
            summary_parts.append(detail_str)
        summary = " ".join(summary_parts)

        operation = f"{talker}:{sentence}" if talker and sentence else sentence or "NMEA"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track source
        self._track_source(src_ip, talker, sentence, now)

        # Update devices
        for ip, mac in ((src_ip, src_mac), (dst_ip, dst_mac)):
            if is_valid_discovered_ip(ip):
                mac_vendor = lookup_mac_vendor(mac) if mac else ""
                key = f"nmea:{ip}"
                device, is_new = self._ensure_device(
                    key,
                    ip,
                    mac=mac,
                    name=f"NMEA Device ({ip})",
                    manufacturer=mac_vendor if mac_vendor else "",
                    device_type="Marine Electronics",
                )
                if is_new:
                    device.nmea0183_passive_data = {"protocol": "NMEA 0183"}

    def _parse_gga(self, nmea, details: Dict[str, Any], src_ip: str, now: str) -> Tuple[str, str]:
        """Parse GGA (GPS Fix) sentence fields. Returns (position_str, detail_str)."""
        lat = self._extract_lat(nmea, "gga")
        lon = self._extract_lon(nmea, "gga")
        quality_raw = str(self.get_field(nmea, "gga_quality", "") or "").strip()
        quality_name = GGA_QUALITY.get(quality_raw, quality_raw)
        num_sats = str(self.get_field(nmea, "gga_number_satellites", "") or "").strip()
        hdop = str(self.get_field(nmea, "gga_horizontal_dilution", "") or "").strip()
        altitude = str(self.get_field(nmea, "gga_altitude", "") or "").strip()

        if lat is not None:
            details["latitude"] = lat
        if lon is not None:
            details["longitude"] = lon
        if quality_raw:
            details["quality"] = quality_raw
            details["quality_name"] = quality_name
        if num_sats:
            details["satellites"] = num_sats
        if hdop:
            details["hdop"] = hdop
        if altitude:
            details["altitude"] = altitude

        # Check for spoofing indicators
        self._check_position_jump(src_ip, lat, lon, now)
        self._check_quality_change(src_ip, quality_raw, now)

        position_str = self._format_position(lat, lon)
        detail_parts = []
        if quality_name:
            detail_parts.append(f"Q={quality_name}")
        if num_sats:
            detail_parts.append(f"Sats={num_sats}")
        if altitude:
            detail_parts.append(f"Alt={altitude}m")
        return position_str, " ".join(detail_parts)

    def _parse_gll(self, nmea, details: Dict[str, Any], src_ip: str, now: str) -> Tuple[str, str]:
        """Parse GLL (Geographic Position) sentence. Returns (position_str, detail_str)."""
        lat = self._extract_lat(nmea, "gll")
        lon = self._extract_lon(nmea, "gll")
        status = str(self.get_field(nmea, "gll_status", "") or "").strip()

        if lat is not None:
            details["latitude"] = lat
        if lon is not None:
            details["longitude"] = lon
        if status:
            details["status"] = status

        self._check_position_jump(src_ip, lat, lon, now)
        position_str = self._format_position(lat, lon)
        detail_str = f"Status={'Active' if status == 'A' else 'Void'}" if status else ""
        return position_str, detail_str

    def _parse_hdt(self, nmea, details: Dict[str, Any]) -> str:
        """Parse HDT (Heading True) sentence."""
        heading = str(self.get_field(nmea, "hdt_heading", "") or "").strip()
        if heading:
            details["heading_true"] = heading
            return f"Heading={heading}T"
        return ""

    def _parse_dpt(self, nmea, details: Dict[str, Any]) -> str:
        """Parse DPT (Depth) sentence."""
        depth = str(self.get_field(nmea, "dpt_depth", "") or "").strip()
        offset = str(self.get_field(nmea, "dpt_offset", "") or "").strip()
        if depth:
            details["depth"] = depth
            parts = [f"Depth={depth}m"]
            if offset:
                details["offset"] = offset
                parts.append(f"Offset={offset}m")
            return " ".join(parts)
        return ""

    def _parse_vhw(self, nmea, details: Dict[str, Any]) -> str:
        """Parse VHW (Water Speed and Heading) sentence."""
        true_hdg = str(self.get_field(nmea, "vhw_true_heading", "") or "").strip()
        mag_hdg = str(self.get_field(nmea, "vhw_magnetic_heading", "") or "").strip()
        speed_kn = str(self.get_field(nmea, "vhw_water_speed_knot", "") or "").strip()
        if true_hdg:
            details["heading_true"] = true_hdg
        if mag_hdg:
            details["heading_magnetic"] = mag_hdg
        if speed_kn:
            details["speed_knots"] = speed_kn
        parts = []
        if true_hdg:
            parts.append(f"Hdg={true_hdg}T")
        if speed_kn:
            parts.append(f"Spd={speed_kn}kn")
        return " ".join(parts)

    def _parse_rot(self, nmea, details: Dict[str, Any]) -> str:
        """Parse ROT (Rate of Turn) sentence."""
        rot = str(self.get_field(nmea, "rot_rate_of_turn", "") or "").strip()
        valid = str(self.get_field(nmea, "rot_valid", "") or "").strip()
        if rot:
            details["rate_of_turn"] = rot
            if valid:
                details["rot_valid"] = valid
            return f"ROT={rot}deg/min"
        return ""

    def _parse_zda(self, nmea, details: Dict[str, Any]) -> str:
        """Parse ZDA (Time and Date) sentence."""
        hour = str(self.get_field(nmea, "zda_time_hour", "") or "").strip()
        minute = str(self.get_field(nmea, "zda_time_minute", "") or "").strip()
        second = str(self.get_field(nmea, "zda_time_second", "") or "").strip()
        day = str(self.get_field(nmea, "zda_date_day", "") or "").strip()
        month = str(self.get_field(nmea, "zda_date_month", "") or "").strip()
        year = str(self.get_field(nmea, "zda_date_year", "") or "").strip()
        if hour and minute:
            time_str = f"{hour}:{minute}:{second}" if second else f"{hour}:{minute}"
            details["utc_time"] = time_str
            if day and month and year:
                date_str = f"{year}-{month}-{day}"
                details["date"] = date_str
                return f"{date_str} {time_str}Z"
            return f"{time_str}Z"
        return ""

    def _extract_lat(self, nmea, prefix: str) -> Optional[float]:
        """Extract latitude from sentence fields as decimal degrees."""
        deg = str(self.get_field(nmea, f"{prefix}_latitude_degree", "") or "").strip()
        mins = str(self.get_field(nmea, f"{prefix}_latitude_minute", "") or "").strip()
        direction = str(self.get_field(nmea, f"{prefix}_latitude_direction", "") or "").strip()
        if deg and mins:
            try:
                lat = float(deg) + float(mins) / 60.0
                if direction == "S":
                    lat = -lat
                return lat
            except (ValueError, TypeError):
                pass
        return None

    def _extract_lon(self, nmea, prefix: str) -> Optional[float]:
        """Extract longitude from sentence fields as decimal degrees."""
        deg = str(self.get_field(nmea, f"{prefix}_longitude_degree", "") or "").strip()
        mins = str(self.get_field(nmea, f"{prefix}_longitude_minute", "") or "").strip()
        direction = str(self.get_field(nmea, f"{prefix}_longitude_direction", "") or "").strip()
        if deg and mins:
            try:
                lon = float(deg) + float(mins) / 60.0
                if direction == "W":
                    lon = -lon
                return lon
            except (ValueError, TypeError):
                pass
        return None

    @staticmethod
    def _format_position(lat: Optional[float], lon: Optional[float]) -> str:
        """Format lat/lon as a compact string."""
        if lat is not None and lon is not None:
            lat_dir = "N" if lat >= 0 else "S"
            lon_dir = "E" if lon >= 0 else "W"
            return f"{abs(lat):.5f}{lat_dir} {abs(lon):.5f}{lon_dir}"
        return ""

    def _check_position_jump(
        self, src_ip: str, lat: Optional[float], lon: Optional[float], now: str
    ) -> None:
        """Check for suspicious position jumps (GPS spoofing indicator)."""
        if lat is None or lon is None:
            return
        source = self.sources.get(src_ip)
        if source is None or source.last_lat is None or source.last_lon is None:
            return
        # Approximate distance in nautical miles (1 deg lat ~ 60 NM)
        dlat = abs(lat - source.last_lat) * 60.0
        # Longitude degrees vary with latitude
        import math

        dlon = abs(lon - source.last_lon) * 60.0 * math.cos(math.radians(lat))
        dist_nm = math.sqrt(dlat * dlat + dlon * dlon)
        if dist_nm > MAX_POSITION_JUMP_NM:
            source.position_jumps += 1
            self.logger.debug(
                f"NMEA: GPS spoofing indicator from {src_ip}: position jump {dist_nm:.1f} NM"
            )

    def _check_quality_change(self, src_ip: str, quality: str, now: str) -> None:
        """Track GPS quality indicator changes."""
        if not quality:
            return
        source = self.sources.get(src_ip)
        if source is None:
            return
        if source.last_quality is not None and source.last_quality != quality:
            source.quality_changes += 1
        source.last_quality = quality

    def _track_source(self, src_ip: str, talker: str, sentence: str, now: str) -> None:
        """Track an NMEA data source."""
        if src_ip not in self.sources:
            self.sources[src_ip] = NMEASource(ip=src_ip, first_seen=now, last_seen=now)
        source = self.sources[src_ip]
        source.last_seen = now
        source.packet_count += 1
        if talker:
            source.talker_ids.add(talker)
        if sentence:
            source.sentences.add(sentence)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        talker = d.get("talker_id", "")
        sentence = d.get("sentence_id", "")
        # Position
        lat = d.get("latitude")
        lon = d.get("longitude")
        position = self._format_position(lat, lon)
        # Detail varies by sentence
        detail_parts = []
        for key in (
            "quality_name",
            "satellites",
            "heading_true",
            "depth",
            "speed_knots",
            "rate_of_turn",
        ):
            val = d.get(key)
            if val:
                detail_parts.append(str(val))
        detail = " ".join(detail_parts)
        return [talker, sentence, position, detail]

    def harvest(self) -> Dict[str, Any]:
        """Return harvest with GPS spoofing alerts."""
        result = super().harvest()
        alerts = result.get("alerts", [])

        for src_ip, source in self.sources.items():
            if source.position_jumps > 0:
                alerts.append(
                    {
                        "level": "fail",
                        "category": "gps_spoofing",
                        "message": (
                            f"NMEA GPS SPOOFING INDICATOR: {src_ip} had "
                            f"{source.position_jumps} position jump(s) > "
                            f"{MAX_POSITION_JUMP_NM} NM"
                        ),
                    }
                )

        if alerts:
            result["alerts"] = alerts
        return result

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed NMEA sources."""
        return [
            {
                "source": s.ip,
                "talker_ids": sorted(s.talker_ids),
                "sentences": sorted(s.sentences),
                "packet_count": s.packet_count,
                "position_jumps": s.position_jumps,
                "quality_changes": s.quality_changes,
                "first_seen": s.first_seen,
                "last_seen": s.last_seen,
            }
            for s in self.sources.values()
        ]
