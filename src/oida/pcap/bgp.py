"""
BGP Passive Listener for authentication data and session analysis.

Passively captures BGP traffic to extract:
- Authentication data from BGP OPEN messages
- BGP MD5 authentication presence detection
- OPEN capabilities: AS number, router ID, hostname (FQDN), Graceful
  Restart flags, BGPsec version
- UPDATE path attributes: origin, AS path, communities, NLRI prefixes,
  BGPsec signature algorithm
- NOTIFICATION error details: major/minor error codes, shutdown message

tshark fields (EK names):
- type: BGP message type (1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE)
- open_myas: Autonomous System number
- open_holdtime: Hold time (seconds)
- open_version: BGP version
- open_identifier: BGP Router ID (IPv4)
- open_opt_param_auth: Authentication data bytes
- cap_orf_fqdn_hostname: FQDN capability hostname
- cap_orf_fqdn_domain_name: FQDN capability domain name
- cap_gr_timers_restart_flag: Graceful Restart flag (boolean)
- cap_bgpsec_version: BGPsec capability version
- update_path_attribute_origin: Origin attribute (0=IGP, 1=EGP, 2=INCOMPLETE)
- update_path_attribute_community_as: Community AS number
- update_path_attribute_community_value: Community value
- update_path_attribute_bgpsec_sb_algo_id: BGPsec Signature Block algo ID
- nlri_prefix: Advertised NLRI prefixes
- notify_major_error: NOTIFICATION major error code
- notify_minor_error_cease: NOTIFICATION minor error (cease subcode)
- notify_communication: NOTIFICATION shutdown communication string

References:
- RFC 4271: Border Gateway Protocol 4
- RFC 2385: Protection of BGP Sessions via TCP MD5 Signature Option
- RFC 8538: Notification Message Support for BGP Graceful Restart
- RFC 8205: BGPsec Protocol Specification
- Wireshark dissector: packet-bgp.c
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase

# BGP NOTIFICATION major error code names (RFC 4271 Section 4.5)
_NOTIFY_MAJOR = {
    "1": "Message Header Error",
    "2": "OPEN Message Error",
    "3": "UPDATE Message Error",
    "4": "Hold Timer Expired",
    "5": "Finite State Machine Error",
    "6": "Cease",
    "7": "ROUTE-REFRESH Message Error",
}

# Cease sub-codes (RFC 4486 + RFC 8203)
_NOTIFY_CEASE_MINOR = {
    "1": "Maximum Number of Prefixes Reached",
    "2": "Administrative Shutdown",
    "3": "Peer De-configured",
    "4": "Administrative Reset",
    "5": "Connection Rejected",
    "6": "Other Configuration Change",
    "7": "Connection Collision Resolution",
    "8": "Out of Resources",
    "9": "Hard Reset",
}

# BGP Origin attribute values
_ORIGIN_VALUES = {
    "0": "IGP",
    "1": "EGP",
    "2": "INCOMPLETE",
}


@dataclass
class BGPCredential:
    """Extracted BGP authentication data."""

    auth_data: str
    credential_type: str = "plaintext"
    peer_ip: str = ""
    local_ip: str = ""
    timestamp: str = ""

    @property
    def username(self) -> str:
        """Canonical credential field: auth data as username."""
        return self.auth_data

    @property
    def password(self) -> str:
        """Canonical credential field."""
        return self.auth_data

    @property
    def server_ip(self) -> str:
        """Canonical credential field: peer is the server."""
        return self.peer_ip

    @property
    def client_ip(self) -> str:
        """Canonical credential field: local is the client."""
        return self.local_ip

    @property
    def auth_method(self) -> str:
        """Canonical credential field."""
        return "BGP Auth"


class BGPPassiveListener(PySharkListenerBase):
    """Passive BGP traffic listener for authentication and session analysis.

    Captures BGP OPEN messages to extract optional authentication
    parameters, capabilities (FQDN hostname, Graceful Restart, BGPsec),
    and router identification.  Tracks UPDATE path attributes (origin,
    communities, BGPsec signatures, NLRI prefixes) and NOTIFICATION
    error details.  Detects BGP sessions using TCP MD5 authentication.
    """

    PROTOCOL_NAME = "bgp"
    DISPLAY_FILTER = "bgp"
    REQUIRED_LAYERS = ("bgp",)
    PROTOCOL_COLUMNS = (
        "type",
        "as_num",
        "router_id",
        "hold_time",
        "detail",
        "auth",
    )
    # BGP message type codes
    BGP_MSG_TYPES = {
        "1": "OPEN",
        "2": "UPDATE",
        "3": "NOTIFICATION",
        "4": "KEEPALIVE",
        "5": "ROUTE-REFRESH",
    }

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[BGPCredential] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format BGP protocol-specific columns."""
        d = ix.details
        return [
            d.get("msg_type_name", ix.operation),
            d.get("as_number", ""),
            d.get("router_id", ""),
            d.get("hold_time", ""),
            d.get("detail", ""),
            d.get("has_auth", ""),
        ]

    def process_packet(self, packet) -> None:
        """Process BGP packet and extract authentication data + session info."""
        if not hasattr(packet, "bgp"):
            return

        bgp = packet.bgp
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)

        # Determine message type
        msg_type_raw = str(self.get_field(bgp, "type", "") or "").strip()
        if not msg_type_raw:
            msg_type_raw = "?"
            self.logger.debug(f"Missing BGP type field in packet from {src_ip} -> {dst_ip}")
        msg_type_name = self.BGP_MSG_TYPES.get(msg_type_raw, f"Type({msg_type_raw})")

        # Common interaction details
        details: Dict[str, Any] = {
            "msg_type": msg_type_raw,
            "msg_type_name": msg_type_name,
        }

        # ----- OPEN message (type 1) -----
        if msg_type_raw == "1":
            self._process_open(bgp, src_ip, dst_ip, details)

        # ----- UPDATE message (type 2) -----
        elif msg_type_raw == "2":
            self._process_update(bgp, src_ip, dst_ip, details)

        # ----- NOTIFICATION message (type 3) -----
        elif msg_type_raw == "3":
            self._process_notification(bgp, src_ip, dst_ip, details)

        # Extract authentication data from OPEN optional parameters
        auth_data = str(self.get_field(bgp, "open_opt_param_auth", "") or "").strip()
        details["has_auth"] = "Yes" if auth_data else "No"

        # Build a short detail summary for the table
        details["detail"] = self._build_detail_summary(msg_type_raw, details)

        # Record interaction
        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"BGP {msg_type_name}",
            details,
            f"BGP {msg_type_name} from {src_ip}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        # Update devices
        self._update_devices(src_ip, dst_ip, flow_id, details)

        # Store credential if auth data present
        if not auth_data:
            return

        if not self._is_duplicate(auth_data, src_ip, dst_ip):
            cred = BGPCredential(
                auth_data=auth_data,
                credential_type="plaintext",
                peer_ip=dst_ip,
                local_ip=src_ip,
                timestamp=datetime.now().isoformat(),
            )
            self.credentials.append(cred)
            self.logger.info(f"BGP: auth data from {src_ip} to {dst_ip}")

    # ------------------------------------------------------------------
    # Message-type-specific extraction
    # ------------------------------------------------------------------

    def _process_open(self, bgp: Any, src_ip: str, dst_ip: str, details: Dict[str, Any]) -> None:
        """Extract fields from a BGP OPEN message."""
        # Core OPEN fields (EK field name: open_myas, not open_my_as)
        as_number = str(self.get_field(bgp, "open_myas", "") or "").strip()
        if not as_number:
            as_number = "?"
            self.logger.debug(f"Missing open_myas in OPEN from {src_ip} -> {dst_ip}")
        details["as_number"] = as_number

        hold_time = str(self.get_field(bgp, "open_holdtime", "") or "").strip()
        if not hold_time:
            hold_time = "?"
            self.logger.debug(f"Missing open_holdtime in OPEN from {src_ip} -> {dst_ip}")
        details["hold_time"] = hold_time

        version = str(self.get_field(bgp, "open_version", "") or "").strip()
        if not version:
            version = "?"
            self.logger.debug(f"Missing open_version in OPEN from {src_ip} -> {dst_ip}")
        details["version"] = version

        # BGP Router ID (T2 field, but extremely valuable for device ID)
        router_id = str(self.get_field(bgp, "open_identifier", "") or "").strip()
        if not router_id:
            router_id = "?"
            self.logger.debug(f"Missing open_identifier in OPEN from {src_ip} -> {dst_ip}")
        details["router_id"] = router_id

        # --- T1 OPEN capability fields ---

        # FQDN hostname (bgp.cap.orf.fqdn.hostname -> cap_orf_fqdn_hostname)
        hostname = str(self.get_field(bgp, "cap_orf_fqdn_hostname", "") or "").strip()
        if hostname:
            details["hostname"] = hostname

        # FQDN domain name (bgp.cap.orf.fqdn.domain_name -> cap_orf_fqdn_domain_name)
        domain_name = str(self.get_field(bgp, "cap_orf_fqdn_domain_name", "") or "").strip()
        if domain_name:
            details["domain_name"] = domain_name

        # Graceful Restart flag (bgp.cap.gr.timers.restart_flag)
        gr_restart_flag = self.get_field(bgp, "cap_gr_timers_restart_flag", "")
        if gr_restart_flag not in (None, ""):
            details["gr_restart_flag"] = str(gr_restart_flag)

        # BGPsec version (bgp.cap.bgpsec.version -> cap_bgpsec_version)
        bgpsec_version = self.get_field(bgp, "cap_bgpsec_version", "")
        if bgpsec_version not in (None, ""):
            details["bgpsec_version"] = str(bgpsec_version)

        # 4-byte AS capability (useful for 32-bit AS numbers)
        cap_4as = str(self.get_field(bgp, "cap_4as", "") or "").strip()
        if cap_4as:
            details["cap_4as"] = cap_4as

    def _process_update(self, bgp: Any, src_ip: str, dst_ip: str, details: Dict[str, Any]) -> None:
        """Extract fields from a BGP UPDATE message."""
        # Origin attribute (bgp.update.path_attribute.origin)
        origin_raw = str(self.get_field(bgp, "update_path_attribute_origin", "") or "").strip()
        if origin_raw:
            origin_name = _ORIGIN_VALUES.get(origin_raw, f"Unknown({origin_raw})")
            details["origin"] = origin_name
            details["origin_raw"] = origin_raw

        # Community AS (bgp.update.path_attribute.community_as)
        community_as = str(self.get_field(bgp, "update_path_attribute_community_as", "") or "")
        community_as = community_as.strip()
        if community_as:
            details["community_as"] = community_as

        # Community value (bgp.update.path_attribute.community_value)
        community_val = str(
            self.get_field(bgp, "update_path_attribute_community_value", "") or ""
        ).strip()
        if community_val:
            details["community_value"] = community_val

        # Build community string e.g. "321:654"
        if community_as and community_val:
            details["community"] = f"{community_as}:{community_val}"

        # BGPsec signature block algorithm ID
        bgpsec_algo = str(
            self.get_field(bgp, "update_path_attribute_bgpsec_sb_algo_id", "") or ""
        ).strip()
        if bgpsec_algo:
            details["bgpsec_algo_id"] = bgpsec_algo

        # NLRI prefixes (advertised routes)
        nlri = self.get_field(bgp, "nlri_prefix", "")
        if nlri:
            if isinstance(nlri, list):
                details["nlri_prefixes"] = ", ".join(str(p) for p in nlri)
            else:
                details["nlri_prefixes"] = str(nlri)

        # Next hop
        next_hop = str(self.get_field(bgp, "update_path_attribute_next_hop", "") or "").strip()
        if next_hop and next_hop != "0.0.0.0":
            details["next_hop"] = next_hop

        # AS path segment (4-byte AS numbers)
        as_path = self.get_field(bgp, "update_path_attribute_as_path_segment_as4", "")
        if as_path:
            if isinstance(as_path, list):
                details["as_path"] = " ".join(str(a) for a in as_path)
            else:
                details["as_path"] = str(as_path)

    def _process_notification(
        self, bgp: Any, src_ip: str, dst_ip: str, details: Dict[str, Any]
    ) -> None:
        """Extract fields from a BGP NOTIFICATION message."""
        # Major error code (bgp.notify.major_error)
        major_raw = str(self.get_field(bgp, "notify_major_error", "") or "").strip()
        if major_raw:
            major_name = _NOTIFY_MAJOR.get(major_raw, f"Unknown({major_raw})")
            details["notify_major"] = major_raw
            details["notify_major_name"] = major_name
        else:
            details["notify_major"] = "?"
            self.logger.debug(
                f"Missing notify_major_error in NOTIFICATION from {src_ip} -> {dst_ip}"
            )

        # Minor error -- cease subcode (bgp.notify.minor_error_cease)
        minor_raw = str(self.get_field(bgp, "notify_minor_error_cease", "") or "").strip()
        if minor_raw:
            minor_name = _NOTIFY_CEASE_MINOR.get(minor_raw, f"Subcode({minor_raw})")
            details["notify_minor_cease"] = minor_raw
            details["notify_minor_cease_name"] = minor_name
        # Minor error is only present for Cease (major=6), so not a "?" if absent

        # Shutdown communication message (RFC 8203)
        comm_msg = str(self.get_field(bgp, "notify_communication", "") or "").strip()
        if comm_msg:
            details["notify_message"] = comm_msg

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_detail_summary(self, msg_type: str, details: Dict[str, Any]) -> str:
        """Build a concise detail string for the interaction table."""
        if msg_type == "1":
            parts = []
            if details.get("hostname"):
                parts.append(f"host={details['hostname']}")
            if details.get("gr_restart_flag"):
                parts.append(f"GR={details['gr_restart_flag']}")
            if details.get("bgpsec_version") is not None and details.get("bgpsec_version") != "":
                parts.append(f"BGPsec v{details['bgpsec_version']}")
            if details.get("cap_4as"):
                parts.append(f"4AS={details['cap_4as']}")
            return "; ".join(parts) if parts else ""

        if msg_type == "2":
            parts = []
            if details.get("origin"):
                parts.append(f"origin={details['origin']}")
            if details.get("community"):
                parts.append(f"comm={details['community']}")
            if details.get("nlri_prefixes"):
                prefixes = details["nlri_prefixes"]
                parts.append(f"nlri={prefixes}")
            if details.get("bgpsec_algo_id"):
                parts.append(f"bgpsec_algo={details['bgpsec_algo_id']}")
            return "; ".join(parts) if parts else ""

        if msg_type == "3":
            parts = []
            major_name = details.get("notify_major_name", "")
            minor_name = details.get("notify_minor_cease_name", "")
            if major_name:
                parts.append(major_name)
            if minor_name:
                parts.append(minor_name)
            msg = details.get("notify_message", "")
            if msg:
                parts.append(f'"{msg}"')
            return "; ".join(parts) if parts else ""

        return ""

    def _is_duplicate(self, auth_data: str, src_ip: str, dst_ip: str) -> bool:
        """Check if credential is already recorded."""
        for cred in self.credentials:
            if cred.auth_data == auth_data and cred.local_ip == src_ip and cred.peer_ip == dst_ip:
                return True
        return False

    def _update_devices(
        self,
        src_ip: str,
        dst_ip: str,
        flow_id: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update device entries with BGP session data."""
        if details is None:
            details = {}

        for ip in [src_ip, dst_ip]:
            device_key = f"bgp:{ip}"
            device, is_new = self._ensure_device(
                device_key,
                ip,
                name=f"BGP Router ({ip})",
                device_type="Router",
            )
            if is_new:
                device.bgp_passive_data = {
                    "role": "peer",
                    "protocol": "BGP/TCP",
                }

            if not device.bgp_passive_data:
                device.bgp_passive_data = {}

            # Enrich with OPEN data when sender is this IP
            if ip == src_ip:
                as_number = details.get("as_number", "")
                if as_number and as_number != "?":
                    device.bgp_passive_data["as_number"] = as_number

                router_id = details.get("router_id", "")
                if router_id and router_id != "?":
                    device.bgp_passive_data["router_id"] = router_id

                hostname = details.get("hostname", "")
                if hostname:
                    device.bgp_passive_data["hostname"] = hostname

                domain_name = details.get("domain_name", "")
                if domain_name:
                    device.bgp_passive_data["domain_name"] = domain_name

                gr_flag = details.get("gr_restart_flag", "")
                if gr_flag:
                    device.bgp_passive_data["graceful_restart"] = gr_flag

                bgpsec_ver = details.get("bgpsec_version", "")
                if bgpsec_ver not in ("", None):
                    device.bgp_passive_data["bgpsec_version"] = bgpsec_ver

                cap_4as = details.get("cap_4as", "")
                if cap_4as:
                    device.bgp_passive_data["as_number_4byte"] = cap_4as

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return [
            {
                "protocol": "BGP",
                "credential_type": cred.credential_type,
                "username": cred.auth_data,
                "server_ip": cred.peer_ip,
                "client_ip": cred.local_ip,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]
