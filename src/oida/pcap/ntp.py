"""
NTP Passive Listener for time service discovery and analysis.

Passively captures NTP traffic to extract:
- NTP version and mode (client/server/broadcast/symmetric)
- Stratum level (distance from reference clock)
- Reference clock ID
- Root delay and dispersion (network quality indicators)
- Poll interval and precision

Security value:
- NTP amplification detection (monlist responses)
- Rogue NTP server detection (low stratum from unexpected sources)
- Time synchronization topology mapping

tshark fields used:
- ntp.flags.mode: NTP mode (1-7)
- ntp.flags.vn: Version number (1-4)
- ntp.flags.li: Leap indicator
- ntp.stratum: Stratum level (0=unspecified, 1=primary, 2-15=secondary)
- ntp.refid: Reference clock identifier
- ntp.rootdelay: Round-trip delay to reference clock
- ntp.rootdispersion: Maximum error relative to reference clock
- ntp.ppoll: Peer poll interval (log2 seconds)
- ntp.precision: Clock precision (log2 seconds)
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# NTP mode mapping (RFC 5905, Section 7.3)
NTP_MODES = {
    "0": "reserved",
    "1": "symmetric-active",
    "2": "symmetric-passive",
    "3": "client",
    "4": "server",
    "5": "broadcast",
    "6": "control",
    "7": "private",
    0: "reserved",
    1: "symmetric-active",
    2: "symmetric-passive",
    3: "client",
    4: "server",
    5: "broadcast",
    6: "control",
    7: "private",
}

# Well-known reference IDs for stratum 1
REFID_NAMES = {
    "GOES": "Geostationary Orbit Environment Satellite",
    "GPS": "Global Positioning System",
    "GAL": "Galileo Positioning System",
    "PPS": "Pulse Per Second",
    "IRIG": "Inter-Range Instrumentation Group",
    "WWVB": "NIST Radio Station (60 kHz)",
    "DCF": "DCF77 (77.5 kHz)",
    "HBG": "HBG (75 kHz)",
    "MSF": "MSF (60 kHz)",
    "JJY": "JJY (40/60 kHz)",
    "LORC": "LORAN-C",
    "TDF": "TDF (162 kHz)",
    "CHU": "CHU Radio Station",
    "WWV": "NIST Radio Station (various HF)",
    "WWVH": "NIST Radio Station (Hawaii)",
    "NIST": "NIST Modem Service",
    "ACTS": "Automated Computer Time Service",
    "USNO": "US Naval Observatory",
    "PTB": "Physikalisch-Technische Bundesanstalt",
    "LOCL": "Local clock (uncalibrated)",
    "CESM": "Cesium clock",
    "RBDM": "Rubidium clock",
    "OMEG": "OMEGA radio navigation",
    "DCN": "DCN routing protocol",
    "TSP": "TSP time protocol",
    "DTS": "Digital Time Service",
    "ATOM": "Atomic clock (calibrated)",
    "VLF": "VLF radio",
    "FREE": "Free running",
    "INIT": "Initialization",
    "STEP": "Step time change",
    "": "Unknown",
}

# Leap indicator descriptions
LEAP_INDICATOR = {
    "0": "no warning",
    "1": "last minute of day has 61 seconds",
    "2": "last minute of day has 59 seconds",
    "3": "alarm (clock not synchronized)",
    0: "no warning",
    1: "last minute of day has 61 seconds",
    2: "last minute of day has 59 seconds",
    3: "alarm (clock not synchronized)",
}


class NTPPassiveListener(PySharkListenerBase):
    """Passive NTP traffic listener for time service discovery.

    Captures NTP traffic to identify:
    - NTP servers and clients in the network
    - Stratum levels and reference clock sources
    - Potentially rogue or misconfigured NTP servers
    - NTP amplification attack indicators (mode 7 / monlist)

    Usage:
        listener = NTPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for ip, info in listener.server_info.items():
            print(f"Server {ip}: stratum={info['stratum']}")
    """

    PROTOCOL_NAME = "ntp"
    DISPLAY_FILTER = "ntp"
    REQUIRED_LAYERS = ("ntp",)
    PROTOCOL_COLUMNS = ("version", "mode", "stratum", "ref_id", "delay")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track NTP server details
        self.server_info: Dict[str, Dict[str, Any]] = {}
        self._warned_control_pairs: set = set()  # deduplicate control/private warnings

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format NTP interaction as protocol-specific table columns."""
        d = ix.details
        return [
            d.get("version", "?"),
            d.get("mode_name", "?"),
            d.get("stratum", "?"),
            d.get("refid_name", d.get("refid", "?")),
            d.get("root_delay", "?"),
        ]

    def should_process_packet(self, packet) -> bool:
        """Check if packet contains NTP data, including ICMP-encapsulated NTP."""
        if hasattr(packet, "ntp"):
            return True
        # ICMP error responses (e.g. port-unreachable) may carry the original
        # NTP packet in their payload.  tshark's "ntp" display filter matches
        # these, so we need to handle them to avoid silent drops.
        if hasattr(packet, "icmp"):
            icmp_fields = getattr(packet.icmp, "_fields_dict", {})
            if isinstance(icmp_fields, dict) and "ntp" in icmp_fields:
                return True
        return False

    def process_packet(self, packet) -> None:
        """Process NTP packet and extract time service information."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        # Handle ICMP-encapsulated NTP (e.g. ICMP port-unreachable carrying
        # the original NTP request in the error payload).
        if not hasattr(packet, "ntp") and hasattr(packet, "icmp"):
            self._handle_icmp_ntp(packet, src_ip, dst_ip)
            return

        if not hasattr(packet, "ntp"):
            return

        ntp = packet.ntp
        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        # Extract NTP fields
        mode_raw = self.get_field(ntp, "flags_mode", None)
        if mode_raw is None:
            self.logger.debug(f"NTP: missing mode field from {src_ip}")
            return

        mode = str(mode_raw)
        mode_name = NTP_MODES.get(mode, NTP_MODES.get(mode_raw, "unknown"))

        version_raw = self.get_field(ntp, "flags_vn", None)
        version = str(version_raw) if version_raw is not None else "?"

        stratum_raw = self.get_field(ntp, "stratum", None)
        stratum = str(stratum_raw) if stratum_raw is not None else "?"

        refid = str(self.get_field(ntp, "refid", "") or "")
        refid_name = self._resolve_refid(refid, stratum)

        root_delay = str(self.get_field(ntp, "rootdelay", "") or "")
        root_dispersion = str(self.get_field(ntp, "rootdispersion", "") or "")
        poll_interval = str(self.get_field(ntp, "ppoll", "") or "")
        precision = str(self.get_field(ntp, "precision", "") or "")

        leap_raw = self.get_field(ntp, "flags_li", None)
        leap = str(leap_raw) if leap_raw is not None else "?"
        leap_name = LEAP_INDICATOR.get(leap, LEAP_INDICATOR.get(leap_raw, "unknown"))

        # Determine direction based on mode
        is_response = mode in ("4", "5", "2")  # server, broadcast, symmetric-passive
        direction = "response" if is_response else "request"

        # Build operation string
        operation = f"NTP v{version} {mode_name}"

        # Build details
        details: Dict[str, Any] = {
            "version": version,
            "mode": mode,
            "mode_name": mode_name,
            "stratum": stratum,
            "refid": refid,
            "refid_name": refid_name,
            "root_delay": root_delay,
            "root_dispersion": root_dispersion,
            "poll_interval": poll_interval,
            "precision": precision,
            "leap_indicator": leap,
            "leap_name": leap_name,
        }

        # Build summary
        now = datetime.now().isoformat()
        summary = f"NTP v{version} {mode_name} {src_ip}"
        if stratum != "?":
            summary += f" stratum={stratum}"
        if refid_name and refid_name != refid:
            summary += f" ref={refid_name}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Track server info from server/broadcast responses
        if is_response and stratum != "?" and is_valid_discovered_ip(src_ip):
            self._update_server_info(src_ip, details)

        # Flag security-relevant conditions (once per src/dst pair)
        if mode in ("6", "7"):
            pair_key = (src_ip, dst_ip)
            if pair_key not in self._warned_control_pairs:
                self._warned_control_pairs.add(pair_key)
                self.logger.warning(
                    f"NTP control/private mode detected: {src_ip} -> {dst_ip} "
                    f"(mode={mode_name}) -- possible amplification"
                )

        if stratum == "1" and is_response:
            self.logger.debug(f"NTP stratum-1 server: {src_ip} refid={refid_name or refid}")

        # Track devices for both endpoints
        if is_valid_discovered_ip(src_ip):
            role = "server" if is_response else "client"
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            self._ensure_device(
                f"ntp-{role}:{src_ip}",
                src_ip,
                mac=src_mac or "",
                device_type=f"NTP {role.title()}",
                manufacturer=vendor if vendor != "Unknown" else "",
                data_attr="ntp_passive_data",
                protocol_data={
                    "role": role,
                    "version": version,
                    "stratum": stratum,
                    "refid": refid_name or refid,
                    "protocol": "NTP/UDP",
                },
            )

        if is_valid_discovered_ip(dst_ip):
            peer_role = "client" if is_response else "server"
            peer_mac = dst_mac or ""
            peer_vendor = lookup_mac_vendor(peer_mac) if peer_mac else ""
            self._ensure_device(
                f"ntp-{peer_role}:{dst_ip}",
                dst_ip,
                mac=peer_mac,
                device_type=f"NTP {peer_role.title()}",
                manufacturer=peer_vendor if peer_vendor != "Unknown" else "",
                data_attr="ntp_passive_data",
                protocol_data={
                    "role": peer_role,
                    "protocol": "NTP/UDP",
                },
            )

    def _handle_icmp_ntp(self, packet, src_ip: str, dst_ip: str) -> None:
        """Handle ICMP error packets that carry embedded NTP data.

        ICMP type=3 (Destination Unreachable) responses include the original
        IP/UDP/NTP headers in the error payload.  tshark dissects the embedded
        NTP and the ``ntp`` display filter matches, but PyShark doesn't expose
        a top-level ``ntp`` layer.  Record a minimal interaction so the packet
        is not silently dropped.
        """
        icmp_layer = packet.icmp
        icmp_type = self.get_field(icmp_layer, "type", "?")
        icmp_code = self.get_field(icmp_layer, "code", "?")
        now = self._get_timestamp()
        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "ICMP error (NTP payload)",
            {
                "version": "?",
                "mode": "?",
                "mode_name": "icmp-error",
                "stratum": "?",
                "refid": "",
                "refid_name": "",
                "root_delay": "",
                "root_dispersion": "",
                "poll_interval": "",
                "precision": "",
                "leap_indicator": "?",
                "leap_name": "",
                "icmp_type": str(icmp_type),
                "icmp_code": str(icmp_code),
            },
            f"ICMP type={icmp_type} code={icmp_code} (embedded NTP) {src_ip} -> {dst_ip}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

    def _resolve_refid(self, refid: str, stratum: str) -> str:
        """Resolve reference ID to human-readable name.

        For stratum 1, refid is a 4-character ASCII identifier.
        For stratum 2+, refid is the IP of the upstream server.
        """
        if not refid:
            return ""

        try:
            stratum_int = int(stratum)
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to get stratum_int: {e}")
            return refid

        if stratum_int <= 1:
            # Try to decode as ASCII
            clean = refid.strip().upper()
            if clean in REFID_NAMES:
                return f"{clean} ({REFID_NAMES[clean]})"
            return clean

        # For stratum 2+, refid is usually the upstream server IP (hex)
        # tshark may already return it as dotted decimal
        if "." in refid:
            return refid

        # Try hex to IP conversion
        try:
            hex_clean = refid.replace(":", "")
            if len(hex_clean) == 8:
                octets = [int(hex_clean[i : i + 2], 16) for i in range(0, 8, 2)]
                return ".".join(str(o) for o in octets)
        except (ValueError, IndexError) as e:
            self.logger.debug(f"Failed to get hex_clean: {e}")

        return refid

    def _update_server_info(self, ip: str, details: Dict[str, Any]) -> None:
        """Track NTP server details for analysis."""
        if ip not in self.server_info:
            self.server_info[ip] = {
                "stratum": details.get("stratum", "?"),
                "version": details.get("version", "?"),
                "refid": details.get("refid_name", details.get("refid", "")),
                "root_delay": details.get("root_delay", ""),
                "root_dispersion": details.get("root_dispersion", ""),
                "first_seen": datetime.now().isoformat(),
                "packet_count": 0,
            }
        info = self.server_info[ip]
        info["packet_count"] = info.get("packet_count", 0) + 1
        info["last_seen"] = datetime.now().isoformat()
        # Update stratum if it changed (could indicate tampering)
        if details.get("stratum") != info.get("stratum"):
            info["stratum_changed"] = True
            info["stratum"] = details.get("stratum", info["stratum"])
