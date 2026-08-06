"""
ANSI C12.22 Passive Listener (PyShark-based).

Passively monitors ANSI C12.22 (IEEE 1703) smart metering traffic to identify:
- Advanced Metering Infrastructure (AMI) endpoints by ApTitle
- ACSE service types (READ, WRITE, LOGON, LOGOFF, SECURITY, REGISTRATION)
- Table access patterns (table number, offset, count)
- Authentication attempts and credential exposure
- Configuration changes via WRITE services

ANSI C12.22 is the North American standard for utility meter communication
over IP networks. It wraps ANSI C12.18/C12.19 table-based commands inside
an ACSE (Association Control Service Element) transport layer, typically
on TCP/UDP port 1153.

Protocol format:
- ACSE wrapper: calling-AP-title (utility), called-AP-title (meter),
  mechanism-name (authentication OID), calling-authentication-value
- C12.22 message: service code + table data
- Services: IDENT (0x20), READ (0x30), WRITE (0x40), LOGON (0x50),
  SECURITY (0x51), LOGOFF (0x52), WAIT (0x70), REGISTRATION (0x27)

tshark fields used (names verified against the packet-c1222.c dissector;
PyShark strips the "c1222." layer prefix and joins the remaining dotted
path with underscores, so c1222.read.table is read via "read_table"):
- c1222.calling_AP_title: Calling Application Title
- c1222.called_AP_title: Called Application Title
- c1222.calling_AP_invocation_id: Calling AP Invocation ID
- c1222.called_AP_invocation_id: Called AP Invocation ID
- c1222.cmd: Service/command code (FT_UINT8)
- c1222.read.table / c1222.write.table: Table number (per service)
- c1222.read.offset / c1222.write.offset: Table offset (per service)
- c1222.read.count: READ byte count; c1222.write.size: WRITE byte count
- c1222.logon.id: User ID for LOGON service
- c1222.logon.user: Username string for LOGON
- c1222.security.password: Password for SECURITY service
- c1222.calling_authentication_value_octet_aligned: Auth value bytes
- c1222.procedure.num: Procedure number
- c1222.data: C12.22 message data payload

Security notes:
- WRITE services can modify meter configuration (billing, disconnect)
- LOGON attempts expose user IDs and potentially cleartext passwords
- SECURITY service requests may carry authentication tokens
- Table 0 (General Configuration) and Table 7 (Security) access is sensitive
- Unauthenticated requests indicate lack of C12.22 security deployment
- Registration services can re-associate meters to rogue head-end systems

References:
- ANSI C12.22-2008 / IEEE 1703: Transport of C12.19 table data
- ANSI C12.18: Protocol specification for meter communication
- ANSI C12.19: Utility industry end device data tables
- Wireshark dissector: packet-c1222.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip

# ANSI C12.22 service codes (ACSE service elements)
# EPSEM command codes as dissected into c1222.cmd (matches Wireshark's
# c1222.cmd value_string). Codes 0x00-0x12 are OK/error *response* codes; the
# service *requests* start at 0x20. There is no "service+1 = response" scheme --
# a response carries an OK/error code, not the request code echoed back.
C1222_SERVICES = {
    0x00: "OK",
    0x01: "Error",
    0x02: "Service Not Supported",
    0x03: "Insufficient Security Clearance",
    0x04: "Operation Not Possible",
    0x05: "Inappropriate Action Requested",
    0x06: "Device Busy",
    0x07: "Data Not Ready",
    0x08: "Data Locked",
    0x09: "Renegotiate Request",
    0x0A: "Invalid Service Sequence State",
    0x0B: "Security Mechanism Error",
    0x0C: "Unknown Application Title",
    0x0D: "Network Time-out",
    0x0E: "Network Not Reachable",
    0x0F: "Request Too Large",
    0x10: "Response Too Large",
    0x11: "Segmentation Not Possible",
    0x12: "Segmentation Error",
    0x20: "Identify",
    0x21: "Terminate",
    0x22: "Disconnect",
    0x30: "Full Read",
    0x3E: "Default Read",
    0x3F: "Partial Read Offset",
    0x40: "Full Write",
    0x4E: "Default Write",
    0x4F: "Partial Write Offset",
    0x50: "Logon",
    0x51: "Security",
    0x52: "Logoff",
    0x53: "Authenticate",
    0x60: "Negotiate",
    0x70: "Wait",
    0x71: "Timing Setup",
}

# Read services (Full/Default/Partial-Offset Read).
READ_SERVICES = {0x30, 0x3E, 0x3F}

# Write services (Full/Default/Partial-Offset Write) -- meter reconfiguration.
WRITE_SERVICES = {0x40, 0x4E, 0x4F}

# The largest OK/error response code; any c1222.cmd <= this is a response.
MAX_RESPONSE_CODE = 0x12

# Security-sensitive tables
SENSITIVE_TABLES = {
    0: "General Configuration (ST-0)",
    7: "Security Table (ST-7)",
    8: "Access Control Table (ST-8)",
    51: "Time/TOU Config (ST-51)",
    52: "Demand Config (ST-52)",
    55: "Registration (ST-55)",
    71: "Log Control (ST-71)",
    76: "Event Config (ST-76)",
}


@dataclass
class C1222Credential:
    """A credential observed in an ANSI C12.22 LOGON service.

    Exposes the canonical field names the scanner credential loop and the
    base-class ``_collect_credentials()`` builder consume directly, so no
    ``getattr`` fallback chains are needed.
    """

    source_ip: str
    dest_ip: str
    user: str = ""
    user_id_value: Optional[int] = None
    password_value: str = ""

    @property
    def client_ip(self) -> str:
        return self.source_ip

    @property
    def server_ip(self) -> str:
        return self.dest_ip

    @property
    def username(self) -> str:
        # Prefer the username string; fall back to the numeric user ID.
        if self.user:
            return self.user
        if self.user_id_value is not None:
            return f"uid={self.user_id_value}"
        return "?"

    @property
    def password(self) -> str:
        return self.password_value

    @property
    def auth_method(self) -> str:
        return "LOGON"

    @property
    def credential_type(self) -> str:
        return "plaintext"


@dataclass
class C1222Session:
    """Track an ANSI C12.22 communication session."""

    client_ip: str
    server_ip: str
    calling_ap_titles: Set[str] = field(default_factory=set)
    called_ap_titles: Set[str] = field(default_factory=set)
    services_seen: Set[str] = field(default_factory=set)
    tables_accessed: Set[int] = field(default_factory=set)
    read_count: int = 0
    write_count: int = 0
    logon_count: int = 0
    security_count: int = 0
    registration_count: int = 0
    user_ids_seen: Set[int] = field(default_factory=set)
    # Association-level authentication: the C12.22 calling authentication value
    # (and any LOGON password) is presented once per association at ACSE setup,
    # not on every EPSEM data PDU.  Once observed, later data PDUs of the same
    # association are authenticated even though they carry no per-PDU auth value.
    authenticated: bool = False
    first_seen: str = ""
    last_seen: str = ""


class C1222PassiveListener(PySharkListenerBase):
    """Passive ANSI C12.22 smart metering traffic listener (PyShark-based).

    Monitors AMI (Advanced Metering Infrastructure) traffic to:
    - Identify meters and head-end systems by ApTitle
    - Track ACSE service usage (READ, WRITE, LOGON, etc.)
    - Monitor table access patterns for sensitive table reads/writes
    - Detect authentication attempts and credential exposure
    - Alert on WRITE services (meter configuration changes)
    - Alert on unauthenticated access and sensitive table operations

    Usage:
        listener = C1222PassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

    Data stored in device.c1222_passive_data:
        {
            "role": "meter" | "head_end",
            "ap_titles": ["2.16.124.113620.1.22"],
            "services_seen": ["READ", "LOGON"],
            "tables_accessed": [0, 7, 64],
            "write_operations": 3,
            "logon_attempts": 1,
            "protocol": "C12.22/TCP",
        }
    """

    PROTOCOL_NAME = "c1222"
    DISPLAY_FILTER = "c1222"
    REQUIRED_LAYERS = ("c1222",)
    PROTOCOL_COLUMNS = ("service", "table", "offset", "count", "aptitle", "detail")
    SERVER_PORTS = (1153,)

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize C12.22 passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], C1222Session] = {}
        self._alerts: List[Dict[str, str]] = []
        # Credentials extracted from LOGON services, surfaced to the scanner.
        self.credentials: List[C1222Credential] = []
        self._seen_creds: Set[Tuple[str, str, str, str]] = set()

    def process_packet(self, packet) -> None:
        """Process an ANSI C12.22 packet using PyShark dissection."""
        if not hasattr(packet, "c1222"):
            return

        c1222_layer = packet.c1222

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        now = datetime.now().isoformat()

        # Extract ACSE fields
        # ANSI C12.22 abbreviations keep "AP" upper-case (c1222.calling_AP_title);
        # EK mode does no case-normalisation, so the lower-case names return None.
        calling_ap = str(
            self.get_field_any(c1222_layer, "calling_AP_title", "calling_ap_title") or ""
        )
        called_ap = str(self.get_field_any(c1222_layer, "called_AP_title", "called_ap_title") or "")
        calling_inv_id = self.get_field_any(
            c1222_layer, "calling_AP_invocation_id", "calling_ap_invocation_id"
        )
        called_inv_id = self.get_field_any(
            c1222_layer, "called_AP_invocation_id", "called_ap_invocation_id"
        )

        # Extract service code
        cmd_raw = self.get_field(c1222_layer, "cmd")
        cmd_code = self._parse_int(cmd_raw, None)

        # Extract table access fields. The Wireshark dissector splits these
        # by service: c1222.read.table / c1222.write.table (-> read_table /
        # write_table after the layer prefix is stripped and dots become
        # underscores), likewise for offset. READ uses c1222.read.count;
        # WRITE uses c1222.write.size for the byte count.
        table_raw = self.get_field_any(c1222_layer, "read_table", "write_table")
        table_num = self._parse_int(table_raw, None)
        offset_raw = self.get_field_any(c1222_layer, "read_offset", "write_offset")
        offset = self._parse_int(offset_raw, None)
        count_raw = self.get_field_any(c1222_layer, "read_count", "write_size")
        count = self._parse_int(count_raw, None)

        # Extract authentication fields. LOGON exposes c1222.logon.id (numeric
        # user ID) and c1222.logon.user (username string); the password lives
        # under the SECURITY service as c1222.security.password. The calling
        # authentication value bytes are c1222.calling_authentication_value_-
        # octet_aligned (FT_BYTES); the container *_element fields are FT_NONE
        # and carry no value.
        user_id_raw = self.get_field(c1222_layer, "logon_id")
        user_id = self._parse_int(user_id_raw, None)
        username = str(self.get_field(c1222_layer, "logon_user") or "")
        password = str(self.get_field(c1222_layer, "security_password") or "")
        auth_value = str(
            self.get_field(c1222_layer, "calling_authentication_value_octet_aligned") or ""
        )

        # Extract procedure fields (c1222.procedure.num)
        procedure_num = self.get_field(c1222_layer, "procedure_num")

        # Determine service name and direction
        svc_name = (
            C1222_SERVICES.get(cmd_code, f"CMD 0x{cmd_code:02x}")
            if cmd_code is not None
            else "Unknown"
        )

        # Classify request vs response from the C12.22 command code. Response
        # PDUs carry an OK/error status code (0x00-0x12); service *requests*
        # use codes >= 0x20. Anything else (absent command code) is ambiguous.
        is_response = cmd_code is not None and cmd_code <= MAX_RESPONSE_CODE

        # Native request/response signal for resolve_direction(): True=request,
        # False=response, None=ambiguous (unknown/absent command code). Be
        # conservative -- only assert direction when the command code is one we
        # recognise: OK/error status codes are responses, known service codes
        # (>= 0x20) are requests.
        native: Optional[bool]
        if cmd_code is None:
            native = None
        elif cmd_code <= MAX_RESPONSE_CODE:
            native = False
        elif cmd_code in C1222_SERVICES:
            native = True
        else:
            native = None

        # Resolve client/server roles and direction. Tier 1 uses the native
        # command-code signal above; tier 2 falls back to the canonical server
        # port (1153, in SERVER_PORTS) plus any user --decode-as / OVERRIDE_PREFS
        # overrides; tier 3 is the lower-port / first-seen heuristic. On the
        # standard port with a recognised command code this reproduces the old
        # "client sends to 1153" behaviour exactly, while also handling
        # non-standard ports and ambiguous command codes robustly.
        d = self.resolve_direction(
            packet,
            native=native,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        is_request = d.is_request
        client_ip, server_ip = d.client_ip, d.server_ip
        direction = d.direction
        src_mac, dst_mac = self.get_mac_info(packet)
        client_mac, server_mac = (src_mac, dst_mac) if is_request else (dst_mac, src_mac)

        # Build details
        details: Dict[str, Any] = {
            "service_code": cmd_code,
            "service_name": svc_name,
        }
        if calling_ap:
            details["calling_ap_title"] = calling_ap
        if called_ap:
            details["called_ap_title"] = called_ap
        if calling_inv_id is not None:
            details["calling_inv_id"] = str(calling_inv_id)
        if called_inv_id is not None:
            details["called_inv_id"] = str(called_inv_id)
        if table_num is not None:
            details["table"] = table_num
            sensitive = SENSITIVE_TABLES.get(table_num)
            if sensitive:
                details["table_name"] = sensitive
        if offset is not None:
            details["offset"] = offset
        if count is not None:
            details["count"] = count
        if user_id is not None:
            details["user_id"] = user_id
        if username:
            details["username"] = username
        if password:
            details["has_password"] = True
        if auth_value:
            details["has_auth_value"] = True
        if procedure_num is not None:
            details["procedure_num"] = str(procedure_num)

        # Build summary
        summary = self._build_summary(
            svc_name, table_num, offset, count, calling_ap, user_id, is_response
        )

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            svc_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Update session
        session_key = (client_ip, server_ip)
        self._update_session(
            session_key,
            calling_ap,
            called_ap,
            cmd_code,
            svc_name,
            table_num,
            user_id,
            now,
        )

        # Remember association-level authentication.  A calling authentication
        # value or LOGON password seen on any PDU authenticates the whole
        # association, so subsequent data PDUs carrying no per-PDU auth value
        # must not each be flagged as unauthenticated.
        if auth_value or password:
            self.sessions[session_key].authenticated = True

        # Generate security alerts
        self._check_security(
            cmd_code,
            svc_name,
            table_num,
            src_ip,
            dst_ip,
            auth_value,
            password,
            username,
            user_id,
            is_response,
            self.sessions[session_key].authenticated,
        )

        # Surface LOGON credentials to the scanner credential table.
        # Only requests carry credentials; dedup per (client, server, user, pw).
        if cmd_code == 0x50 and not is_response and (username or user_id is not None or password):
            cred_key = (
                client_ip,
                server_ip,
                username or (f"uid={user_id}" if user_id is not None else "?"),
                password,
            )
            if cred_key not in self._seen_creds:
                self._seen_creds.add(cred_key)
                self.credentials.append(
                    C1222Credential(
                        source_ip=client_ip,
                        dest_ip=server_ip,
                        user=username,
                        user_id_value=user_id,
                        password_value=password,
                    )
                )
                if not username and user_id is None and password:
                    self.logger.debug(
                        f"C12.22 LOGON credential with password but no user "
                        f"from {client_ip} -> {server_ip}"
                    )

        # Update devices
        self._update_devices(client_ip, server_ip, session_key, client_mac, server_mac)

    # ------------------------------------------------------------------
    # Session tracking
    # ------------------------------------------------------------------

    def _update_session(
        self,
        session_key: Tuple[str, str],
        calling_ap: str,
        called_ap: str,
        cmd_code: Optional[int],
        svc_name: str,
        table_num: Optional[int],
        user_id: Optional[int],
        now: str,
    ) -> None:
        """Update session statistics."""
        if session_key not in self.sessions:
            self.sessions[session_key] = C1222Session(
                client_ip=session_key[0],
                server_ip=session_key[1],
                first_seen=now,
                last_seen=now,
            )

        session = self.sessions[session_key]
        session.last_seen = now

        if calling_ap:
            session.calling_ap_titles.add(calling_ap)
        if called_ap:
            session.called_ap_titles.add(called_ap)

        session.services_seen.add(svc_name)

        if table_num is not None:
            session.tables_accessed.add(table_num)

        if user_id is not None:
            session.user_ids_seen.add(user_id)

        if cmd_code is not None:
            if cmd_code in READ_SERVICES:
                session.read_count += 1
            elif cmd_code in WRITE_SERVICES:
                session.write_count += 1
            elif cmd_code == 0x50:  # LOGON
                session.logon_count += 1
            elif cmd_code == 0x51:  # SECURITY
                session.security_count += 1
            elif cmd_code == 0x27:  # REGISTRATION
                session.registration_count += 1

    # ------------------------------------------------------------------
    # Security checks
    # ------------------------------------------------------------------

    def _check_security(
        self,
        cmd_code: Optional[int],
        svc_name: str,
        table_num: Optional[int],
        src_ip: str,
        dst_ip: str,
        auth_value: str,
        password: str,
        username: str,
        user_id: Optional[int],
        is_response: bool,
        session_authenticated: bool = False,
    ) -> None:
        """Generate security alerts for suspicious activity."""
        if cmd_code is None or is_response:
            return

        # WRITE service -- meter configuration change
        if cmd_code in WRITE_SERVICES:
            table_info = ""
            if table_num is not None:
                table_info = SENSITIVE_TABLES.get(table_num, f"table {table_num}")
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "c1222_write",
                    "message": (
                        f"C12.22 WRITE: {src_ip} -> {dst_ip} "
                        f"{table_info} (meter configuration change)"
                    ),
                }
            )

        # LOGON attempt
        if cmd_code == 0x50:
            user_info = f"user_id={user_id}" if user_id is not None else ""
            if username:
                user_info = f"user={username}"
            self._alerts.append(
                {
                    "level": "highlight",
                    "category": "c1222_logon",
                    "message": (f"C12.22 LOGON: {src_ip} -> {dst_ip} {user_info}"),
                }
            )
            if password:
                self._alerts.append(
                    {
                        "level": "fail",
                        "category": "c1222_cleartext_password",
                        "message": (
                            f"C12.22 CLEARTEXT PASSWORD: {src_ip} -> {dst_ip} "
                            f"{user_info} (password visible in traffic)"
                        ),
                    }
                )

        # SECURITY service
        if cmd_code == 0x51:
            self._alerts.append(
                {
                    "level": "highlight",
                    "category": "c1222_security_service",
                    "message": (
                        f"C12.22 SECURITY SERVICE: {src_ip} -> {dst_ip} "
                        f"(authentication/key exchange request)"
                    ),
                }
            )

        # REGISTRATION service -- re-association
        if cmd_code == 0x27:
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "c1222_registration",
                    "message": (
                        f"C12.22 REGISTRATION: {src_ip} -> {dst_ip} "
                        f"(meter registration/re-association)"
                    ),
                }
            )

        # Sensitive table access
        if table_num is not None and table_num in SENSITIVE_TABLES:
            table_info = SENSITIVE_TABLES[table_num]
            if cmd_code in READ_SERVICES:  # READ on sensitive table
                self._alerts.append(
                    {
                        "level": "highlight",
                        "category": "c1222_sensitive_table",
                        "message": (
                            f"C12.22 SENSITIVE TABLE READ: {src_ip} -> {dst_ip} {table_info}"
                        ),
                    }
                )

        # Unauthenticated request (no auth_value and no password).  Auth is
        # carried once at association setup, so only flag when the association
        # itself has never presented an authentication value or password.
        if (
            not auth_value
            and not password
            and not session_authenticated
            and cmd_code in (READ_SERVICES | WRITE_SERVICES)
        ):
            self._alerts.append(
                {
                    "level": "highlight",
                    "category": "c1222_no_auth",
                    "message": (
                        f"C12.22 NO AUTH: {src_ip} -> {dst_ip} {svc_name} without authentication"
                    ),
                }
            )

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_devices(
        self,
        client_ip: str,
        server_ip: str,
        session_key: Tuple[str, str],
        client_mac: str = "",
        server_mac: str = "",
    ) -> None:
        """Update device entries for C12.22 endpoints."""
        session = self.sessions[session_key]

        # Server (meter)
        if is_valid_discovered_ip(server_ip):
            device_key = f"c1222-meter:{server_ip}"
            device, is_new = self._ensure_device(
                device_key,
                server_ip,
                mac=server_mac,
                device_type="Smart Meter (C12.22)",
            )
            device.c1222_passive_data = self._build_device_data("meter", session)
            if is_new:
                self.logger.debug(
                    f"C12.22: Meter {server_ip} tables={sorted(session.tables_accessed)}"
                )

        # Client (head-end / AMI system)
        if is_valid_discovered_ip(client_ip):
            device_key = f"c1222-headend:{client_ip}"
            device, is_new = self._ensure_device(
                device_key,
                client_ip,
                mac=client_mac,
                device_type="AMI Head-End (C12.22)",
            )
            device.c1222_passive_data = self._build_device_data("head_end", session)

    def _build_device_data(self, role: str, session: C1222Session) -> Dict[str, Any]:
        """Build c1222_passive_data dict from session."""
        all_ap_titles = sorted(session.calling_ap_titles | session.called_ap_titles)
        return {
            "role": role,
            "ap_titles": all_ap_titles,
            "services_seen": sorted(session.services_seen),
            "tables_accessed": sorted(session.tables_accessed),
            "read_operations": session.read_count,
            "write_operations": session.write_count,
            "logon_attempts": session.logon_count,
            "security_requests": session.security_count,
            "registrations": session.registration_count,
            "user_ids": sorted(session.user_ids_seen),
            "protocol": "C12.22/TCP",
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
        }

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        service = d.get("service_name", "")
        table = d.get("table", "")
        offset = d.get("offset", "")
        count = d.get("count", "")

        # Show ApTitle -- prefer calling for requests, called for responses
        if ix.direction == "request":
            aptitle = d.get("calling_ap_title", "")
        else:
            aptitle = d.get("called_ap_title", "")

        # Build detail string
        detail_parts: List[str] = []
        if d.get("table_name"):
            detail_parts.append(d["table_name"])
        if d.get("user_id") is not None:
            detail_parts.append(f"uid={d['user_id']}")
        if d.get("username"):
            detail_parts.append(f"user={d['username']}")
        if d.get("has_password"):
            detail_parts.append("[PASSWORD]")
        if d.get("has_auth_value"):
            detail_parts.append("[AUTH]")
        if d.get("procedure_num"):
            detail_parts.append(f"proc={d['procedure_num']}")
        detail = " ".join(detail_parts)

        return [service, table, offset, count, aptitle, detail]

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        svc_name: str,
        table_num: Optional[int],
        offset: Optional[int],
        count: Optional[int],
        calling_ap: str,
        user_id: Optional[int],
        is_response: bool,
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts: List[str] = [svc_name]

        if table_num is not None:
            table_desc = SENSITIVE_TABLES.get(table_num, f"T{table_num}")
            parts.append(table_desc)

        if offset is not None and count is not None:
            parts.append(f"@{offset}+{count}")
        elif offset is not None:
            parts.append(f"@{offset}")

        if user_id is not None:
            parts.append(f"uid={user_id}")

        if calling_ap:
            # Truncate long OIDs for display
            short_ap = calling_ap if len(calling_ap) <= 30 else calling_ap[:27] + "..."
            parts.append(f"AP={short_ap}")

        return " ".join(parts)

    # ------------------------------------------------------------------
    # Harvest
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with C12.22-specific security alerts."""
        result = super().harvest()
        if not result and not self._alerts:
            return {}
        if not result:
            result = {"tables": [], "alerts": []}
        if self._alerts:
            result.setdefault("alerts", []).extend(self._alerts)
        return result

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Return LOGON credentials in scanner-compatible dict form.

        Keys match the base-class ``_collect_credentials()`` builder so the
        data lands in the correct columns without fallback chains.
        """
        return [
            {
                "credential_type": c.credential_type,
                "auth_method": c.auth_method,
                "username": c.username,
                "password": c.password,
                "server_ip": c.server_ip,
                "client_ip": c.client_ip,
                "protocol": self.PROTOCOL_NAME.upper(),
            }
            for c in self.credentials
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed C12.22 sessions."""
        return [
            {
                "client": s.client_ip,
                "server": s.server_ip,
                "calling_ap_titles": sorted(s.calling_ap_titles),
                "called_ap_titles": sorted(s.called_ap_titles),
                "services": sorted(s.services_seen),
                "tables": sorted(s.tables_accessed),
                "read_count": s.read_count,
                "write_count": s.write_count,
                "logon_count": s.logon_count,
                "user_ids": sorted(s.user_ids_seen),
            }
            for s in self.sessions.values()
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write operations."""
        return [
            {
                "client": s.client_ip,
                "server": s.server_ip,
                "write_count": s.write_count,
                "tables": sorted(s.tables_accessed),
            }
            for s in self.sessions.values()
            if s.write_count > 0
        ]
