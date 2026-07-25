"""
CoAP (Constrained Application Protocol) Passive Listener (PyShark-based).

Passively monitors CoAP traffic -- the lightweight REST-like protocol for
constrained IoT devices defined in RFC 7252. CoAP uses UDP transport
(port 5683 for plain, port 5684 for DTLS-secured) and supports GET, PUT,
POST, DELETE methods with observe notifications for pub/sub patterns.

CoAP is widely used in:
- IoT sensor networks (temperature, humidity, motion sensors)
- Smart building automation (lighting, HVAC)
- Industrial IoT (IIoT) edge devices
- LWM2M device management

Protocol format:
- Version (2 bits): Always 1
- Type (2 bits): CON (0), NON (1), ACK (2), RST (3)
- Token Length (4 bits)
- Code (8 bits): class.detail format (e.g. 0.01=GET, 2.05=Content)
- Message ID (16 bits): For CON/ACK matching
- Token (0-8 bytes): Request/response correlation
- Options: Uri-Path, Content-Format, Observe, Block1/Block2, etc.
- Payload (after 0xFF marker)

tshark fields used:
- coap.version: Protocol version (FT_UINT8)
- coap.type: Message type -- CON(0), NON(1), ACK(2), RST(3) (FT_UINT8)
- coap.token_len: Token length (FT_UINT8)
- coap.token: Token bytes (FT_BYTES)
- coap.mid: Message ID (FT_UINT16)
- coap.code: Method/response code (FT_UINT8)
- coap.payload: Payload content (FT_STRING)
- coap.payload_desc: Payload description (FT_STRING)
- coap.payload_length: Payload length (FT_UINT32)
- coap.opt.uri_path: URI path component (FT_STRING)
- coap.opt.uri_path_recon: Full reconstructed URI path (FT_STRING)
- coap.opt.uri_query: URI query string (FT_STRING)
- coap.opt.ctype: Content-Format option (FT_STRING)
- coap.opt.accept: Accept option (FT_STRING)
- coap.opt.max_age: Max-Age option (FT_UINT32)
- coap.opt.proxy_uri: Proxy-URI option (FT_STRING)
- coap.opt.observe: Observe option value (FT_UINT32)
- coap.opt.block_number: Block number (FT_UINT32)
- coap.opt.block_mflag: Block more flag (FT_UINT8)
- coap.opt.block_size: Block size (FT_UINT8)
- coap.opt.if_match: If-Match option (FT_BYTES)
- coap.opt.hop_limit: Hop Limit option (FT_UINT8)
- coap.opt.object_security_kid: OSCORE Key ID (FT_BYTES)
- coap.opt.object_security_piv: OSCORE Partial IV (FT_BYTES)
- coap.length: Full frame length (FT_UINT32)

Security notes:
- CoAP on port 5683 is unencrypted -- all data visible in cleartext
- PUT/POST/DELETE operations are write operations (actuation, configuration)
- DTLS (port 5684) provides encryption but may use weak configurations
- Observe notifications may leak continuous sensor data
- Proxy-URI option may indicate open relay / SSRF risk
- OSCORE (Object Security for CoAP) provides end-to-end security
  but is rarely deployed in practice
- No built-in authentication -- access control is application-layer

References:
- RFC 7252: The Constrained Application Protocol (CoAP)
- RFC 7641: Observing Resources in CoAP
- RFC 7959: Block-Wise Transfers in CoAP
- RFC 8613: Object Security for CoAP (OSCORE)
- RFC 6347: Datagram Transport Layer Security (DTLS) version 1.2
- Wireshark dissector: packet-coap.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip

# CoAP message types
COAP_TYPES = {
    "0": "CON",
    "1": "NON",
    "2": "ACK",
    "3": "RST",
}

# CoAP method/response codes (code field = class * 32 + detail)
# Class 0: Methods
# Class 2: Success responses
# Class 4: Client error responses
# Class 5: Server error responses
COAP_CODES = {
    0: "Empty",
    1: "GET",
    2: "POST",
    3: "PUT",
    4: "DELETE",
    5: "FETCH",
    6: "PATCH",
    7: "iPATCH",
    # 2.xx Success
    65: "2.01 Created",
    66: "2.02 Deleted",
    67: "2.03 Valid",
    68: "2.04 Changed",
    69: "2.05 Content",
    95: "2.31 Continue",
    # 4.xx Client Error
    128: "4.00 Bad Request",
    129: "4.01 Unauthorized",
    130: "4.02 Bad Option",
    131: "4.03 Forbidden",
    132: "4.04 Not Found",
    133: "4.05 Method Not Allowed",
    134: "4.06 Not Acceptable",
    136: "4.08 Request Entity Incomplete",
    137: "4.09 Conflict",
    140: "4.12 Precondition Failed",
    141: "4.13 Request Entity Too Large",
    143: "4.15 Unsupported Content-Format",
    150: "4.22 Unprocessable Entity",
    157: "4.29 Too Many Requests",
    # 5.xx Server Error
    160: "5.00 Internal Server Error",
    161: "5.01 Not Implemented",
    162: "5.02 Bad Gateway",
    163: "5.03 Service Unavailable",
    164: "5.04 Gateway Timeout",
    165: "5.05 Proxying Not Supported",
}

# Write/actuation methods (security-relevant)
COAP_WRITE_METHODS = {2, 3, 4, 6, 7}  # POST, PUT, DELETE, PATCH, iPATCH

# Content-Format values (common subset)
COAP_CONTENT_FORMATS = {
    "0": "text/plain",
    "40": "application/link-format",
    "41": "application/xml",
    "42": "application/octet-stream",
    "47": "application/exi",
    "50": "application/json",
    "60": "application/cbor",
    "11542": "application/vnd.oma.lwm2m+tlv",
    "11543": "application/vnd.oma.lwm2m+json",
}


@dataclass
class CoAPSession:
    """Track CoAP session statistics."""

    client_ip: str
    server_ip: str
    methods: Set[str] = field(default_factory=set)
    uri_paths: Set[str] = field(default_factory=set)
    content_formats: Set[str] = field(default_factory=set)
    observe_count: int = 0
    write_count: int = 0
    read_count: int = 0
    error_count: int = 0
    unencrypted: bool = False
    has_oscore: bool = False
    first_seen: str = ""
    last_seen: str = ""


class CoAPPassiveListener(PySharkListenerBase):
    """Passive CoAP traffic listener for IoT/IIoT analysis.

    Captures CoAP traffic to extract:
    - Request methods (GET, PUT, POST, DELETE) and URI paths
    - Response codes and content formats
    - Observe notifications (pub/sub sensor data)
    - Block-wise transfer tracking
    - OSCORE (Object Security) presence
    - Security analysis: unencrypted traffic, write operations, proxy usage

    CoAP uses UDP on port 5683 (plain) or 5684 (DTLS-secured).

    Usage:
        listener = CoAPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "coap"
    DISPLAY_FILTER = "coap"
    REQUIRED_LAYERS = ("coap",)
    PROTOCOL_COLUMNS = ("method", "uri_path", "type", "content_format", "observe", "detail")

    # Standard CoAP ports
    COAPS_PORT = 5684

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], CoAPSession] = {}
        self._alerts: List[Dict[str, str]] = []
        self._seen_alert_keys: Set[str] = set()  # Deduplicate alerts

    def process_packet(self, packet) -> None:
        """Process CoAP packet and extract method, URI, and security info."""
        if not hasattr(packet, "coap"):
            return

        coap = packet.coap
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        now = datetime.now().isoformat()

        # -- Core fields --
        msg_type_raw = str(self.get_field(coap, "type", "") or "")
        msg_type = COAP_TYPES.get(msg_type_raw, f"T{msg_type_raw}")

        code_raw = self.get_field(coap, "code", None)
        code_val = self._parse_int(code_raw, -1) if code_raw is not None else -1
        code_name = COAP_CODES.get(code_val, "")
        if not code_name and code_val >= 0:
            code_class = code_val >> 5
            code_detail = code_val & 0x1F
            code_name = f"{code_class}.{code_detail:02d}"

        mid = str(self.get_field(coap, "mid", "") or "")
        token = str(self.get_field(coap, "token", "") or "")

        # -- URI path --
        uri_path = str(self.get_field(coap, "opt_uri_path_recon", "") or "")
        if not uri_path:
            uri_path = str(self.get_field(coap, "opt_uri_path", "") or "")
        uri_query = str(self.get_field(coap, "opt_uri_query", "") or "")

        # -- Content format --
        content_format_raw = str(self.get_field(coap, "opt_ctype", "") or "")
        content_format = COAP_CONTENT_FORMATS.get(content_format_raw, content_format_raw)

        # -- Observe option --
        observe_raw = self.get_field(coap, "opt_observe", None)
        observe_val = self._parse_int(observe_raw, -1) if observe_raw is not None else -1
        is_observe = observe_val >= 0

        # -- Block options --
        block_number = self.get_field(coap, "opt_block_number", None)
        block_mflag = self.get_field(coap, "opt_block_mflag", None)
        block_size = self.get_field(coap, "opt_block_size", None)

        # -- Payload --
        payload_len = self._parse_int(self.get_field(coap, "payload_length"), 0)
        payload_desc = str(self.get_field(coap, "payload_desc", "") or "")

        # -- Proxy-URI (security concern) --
        proxy_uri = str(self.get_field(coap, "opt_proxy_uri", "") or "")

        # -- OSCORE (Object Security) --
        oscore_kid = self.get_field(coap, "opt_object_security_kid", None)
        oscore_piv = self.get_field(coap, "opt_object_security_piv", None)
        has_oscore = oscore_kid is not None or oscore_piv is not None

        # -- Max-Age --
        max_age = self.get_field(coap, "opt_max_age", None)

        # -- Accept --
        accept = str(self.get_field(coap, "opt_accept", "") or "")

        # -- If-Match --
        if_match = self.get_field(coap, "opt_if_match", None)

        # -- Hop Limit --
        hop_limit = self.get_field(coap, "opt_hop_limit", None)

        # Determine direction and operation. Code 0 is the empty message
        # (ACK/RST with no method/response code) and must NOT be treated as
        # a request -- it's excluded from the request range so is_empty gets
        # a chance to set direction from msg_type instead.
        is_request = 1 <= code_val <= 7
        is_response = code_val >= 64
        is_empty = code_val == 0

        if is_request:
            direction = "request"
            method = code_name or f"Method({code_val})"
        elif is_response:
            direction = "response"
            method = code_name
        elif is_empty:
            # Empty messages: ACK/RST with code 0
            direction = "response" if msg_type in ("ACK", "RST") else "request"
            method = msg_type
        else:
            direction = "request"
            method = code_name or f"Code({code_val})"

        # Detect encryption from port
        is_encrypted = dst_port == self.COAPS_PORT or src_port == self.COAPS_PORT

        # Build interaction details
        details: Dict[str, Any] = {
            "method": method,
            "msg_type": msg_type,
            "code": code_val,
            "mid": mid,
        }
        if uri_path:
            details["uri_path"] = uri_path
        if uri_query:
            details["uri_query"] = uri_query
        if content_format:
            details["content_format"] = content_format
        if is_observe:
            details["observe"] = observe_val
        if block_number is not None:
            details["block_number"] = str(block_number)
            if block_mflag is not None:
                details["block_more"] = str(block_mflag)
            if block_size is not None:
                details["block_size"] = str(block_size)
        if payload_len:
            details["payload_length"] = payload_len
        if payload_desc:
            details["payload_desc"] = payload_desc
        if proxy_uri:
            details["proxy_uri"] = proxy_uri
        if has_oscore:
            details["oscore"] = True
        if token:
            details["token"] = token
        if max_age is not None:
            details["max_age"] = str(max_age)
        if accept:
            details["accept"] = accept
        if if_match is not None:
            details["if_match"] = str(if_match)
        if hop_limit is not None:
            details["hop_limit"] = str(hop_limit)
        details["encrypted"] = is_encrypted

        # Build summary
        summary = self._build_summary(
            method,
            uri_path,
            msg_type,
            is_observe,
            observe_val,
            content_format,
            payload_len,
            is_encrypted,
        )

        operation = method
        if is_observe and is_request and observe_val == 0:
            operation = "OBSERVE Register"
        elif is_observe and is_request and observe_val == 1:
            operation = "OBSERVE Deregister"
        elif is_observe and is_response:
            operation = "OBSERVE Notification"

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
            stream_id=stream_id,
        )

        # Update session tracking
        if is_request:
            session = self._get_session(src_ip, dst_ip, now)
        else:
            session = self._get_session(dst_ip, src_ip, now)

        if is_request:
            session.methods.add(method)
            if uri_path:
                session.uri_paths.add(uri_path)
            if code_val in COAP_WRITE_METHODS:
                session.write_count += 1
            elif code_val == 1:  # GET
                session.read_count += 1
            if is_observe:
                session.observe_count += 1
        elif is_response and code_val >= 128:  # 4.xx or 5.xx
            session.error_count += 1

        if content_format:
            session.content_formats.add(content_format)
        if not is_encrypted:
            session.unencrypted = True
        if has_oscore:
            session.has_oscore = True

        # Security alerts
        self._check_security(
            src_ip,
            dst_ip,
            is_request,
            code_val,
            method,
            uri_path,
            is_encrypted,
            proxy_uri,
            has_oscore,
        )

        # Update device entries
        self._update_devices(src_ip, dst_ip, is_request, uri_path, content_format)

    def _check_security(
        self,
        src_ip: str,
        dst_ip: str,
        is_request: bool,
        code_val: int,
        method: str,
        uri_path: str,
        is_encrypted: bool,
        proxy_uri: str,
        has_oscore: bool,
    ) -> None:
        """Check for security-relevant CoAP operations."""
        # Alert: write operations (PUT, POST, DELETE) -- actuation risk
        if is_request and code_val in COAP_WRITE_METHODS:
            alert_key = f"write:{src_ip}:{dst_ip}:{method}"
            if alert_key not in self._seen_alert_keys:
                self._seen_alert_keys.add(alert_key)
                path_str = f" path={uri_path}" if uri_path else ""
                self._alerts.append(
                    {
                        "level": "fail",
                        "category": "coap_write",
                        "message": (
                            f"CoAP WRITE: {src_ip} -> {dst_ip} "
                            f"{method}{path_str} "
                            f"(potential device actuation/configuration change)"
                        ),
                    }
                )

        # Alert: unencrypted CoAP traffic (port 5683)
        if not is_encrypted and not has_oscore:
            alert_key = f"unencrypted:{src_ip}:{dst_ip}"
            if alert_key not in self._seen_alert_keys:
                self._seen_alert_keys.add(alert_key)
                self._alerts.append(
                    {
                        "level": "highlight",
                        "category": "coap_unencrypted",
                        "message": (
                            f"CoAP UNENCRYPTED: {src_ip} <-> {dst_ip} "
                            f"traffic on port 5683 without DTLS or OSCORE "
                            f"(data and commands visible in cleartext)"
                        ),
                    }
                )

        # Alert: proxy-URI usage (potential SSRF)
        if proxy_uri:
            alert_key = f"proxy:{src_ip}:{dst_ip}"
            if alert_key not in self._seen_alert_keys:
                self._seen_alert_keys.add(alert_key)
                self._alerts.append(
                    {
                        "level": "fail",
                        "category": "coap_proxy",
                        "message": (
                            f"CoAP PROXY: {src_ip} -> {dst_ip} "
                            f"Proxy-URI={proxy_uri} "
                            f"(potential open relay / SSRF vector)"
                        ),
                    }
                )

        # Alert: unauthorized access (4.01 response)
        if not is_request and code_val == 129:  # 4.01 Unauthorized
            alert_key = f"unauth:{src_ip}:{dst_ip}"
            if alert_key not in self._seen_alert_keys:
                self._seen_alert_keys.add(alert_key)
                self._alerts.append(
                    {
                        "level": "fail",
                        "category": "coap_unauthorized",
                        "message": (
                            f"CoAP UNAUTHORIZED: {src_ip} -> {dst_ip} "
                            f"received 4.01 Unauthorized response "
                            f"(access control active, possible brute-force attempt)"
                        ),
                    }
                )

        # Alert: forbidden access (4.03 response)
        if not is_request and code_val == 131:  # 4.03 Forbidden
            alert_key = f"forbidden:{src_ip}:{dst_ip}"
            if alert_key not in self._seen_alert_keys:
                self._seen_alert_keys.add(alert_key)
                self._alerts.append(
                    {
                        "level": "fail",
                        "category": "coap_forbidden",
                        "message": (
                            f"CoAP FORBIDDEN: {src_ip} -> {dst_ip} received 4.03 Forbidden response"
                        ),
                    }
                )

    # ------------------------------------------------------------------
    # Session tracking
    # ------------------------------------------------------------------

    def _get_session(self, client_ip: str, server_ip: str, now: str) -> CoAPSession:
        """Get or create a session."""
        key = (client_ip, server_ip)
        if key not in self.sessions:
            self.sessions[key] = CoAPSession(
                client_ip=client_ip,
                server_ip=server_ip,
                first_seen=now,
                last_seen=now,
            )
        session = self.sessions[key]
        session.last_seen = now
        return session

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_devices(
        self,
        src_ip: str,
        dst_ip: str,
        is_request: bool,
        uri_path: str = "",
        content_format: str = "",
    ) -> None:
        """Update device entries for CoAP endpoints."""
        # Server is the destination of requests
        if is_request:
            server_ip, client_ip = dst_ip, src_ip
        else:
            server_ip, client_ip = src_ip, dst_ip

        if is_valid_discovered_ip(server_ip):
            server_key = f"coap-server:{server_ip}"
            device, is_new = self._ensure_device(
                server_key,
                server_ip,
                name=f"CoAP Server ({server_ip})",
                device_type="CoAP Server",
            )
            if is_new:
                device.coap_passive_data = {
                    "role": "server",
                    "protocol": "CoAP/UDP",
                }

        if is_valid_discovered_ip(client_ip):
            client_key = f"coap-client:{client_ip}"
            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                name=f"CoAP Client ({client_ip})",
                device_type="CoAP Client",
            )
            if is_new:
                device.coap_passive_data = {
                    "role": "client",
                    "protocol": "CoAP/UDP",
                }

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        method = d.get("method", "")
        uri_path = d.get("uri_path", "")
        msg_type = d.get("msg_type", "")
        content_format = d.get("content_format", "")
        observe = d.get("observe", "")
        if observe == -1:
            observe = ""
        elif isinstance(observe, int):
            if observe == 0:
                observe = "register"
            elif observe == 1:
                observe = "deregister"
            else:
                observe = f"seq={observe}"

        detail_parts: List[str] = []
        if d.get("uri_query"):
            detail_parts.append(f"?{d['uri_query']}")
        if d.get("payload_length"):
            detail_parts.append(f"len={d['payload_length']}")
        if d.get("proxy_uri"):
            detail_parts.append(f"proxy={d['proxy_uri']}")
        if d.get("oscore"):
            detail_parts.append("[OSCORE]")
        if d.get("block_number") is not None:
            blk = f"blk={d['block_number']}"
            if d.get("block_more"):
                blk += "+"
            detail_parts.append(blk)
        if not d.get("encrypted", True):
            detail_parts.append("[PLAIN]")

        return [
            method,
            uri_path,
            msg_type,
            content_format,
            str(observe) if observe else "",
            " ".join(detail_parts),
        ]

    # ------------------------------------------------------------------
    # Harvest
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with CoAP-specific alerts."""
        result = super().harvest()
        if not result and not self._alerts:
            return {}
        if not result:
            result = {"tables": [], "alerts": []}
        if self._alerts:
            result.setdefault("alerts", []).extend(self._alerts)

        # Build URI path discovery table
        uri_rows = []
        seen_paths: Set[str] = set()
        for ix in self.interactions:
            path = ix.details.get("uri_path", "")
            if path and path not in seen_paths:
                seen_paths.add(path)
                method = ix.details.get("method", "")
                cf = ix.details.get("content_format", "")
                uri_rows.append([ix.dst_ip, path, method, cf])
        if uri_rows:
            tables = result.setdefault("tables", [])
            tables.insert(
                0,
                {
                    "headers": ["Server", "URI Path", "Method", "Content-Format"],
                    "rows": uri_rows,
                    "title": f"CoAP Resources ({len(uri_rows)})",
                },
            )

        return result

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get interactions that are CoAP write operations."""
        writes: Dict[Tuple[str, str], int] = {}
        for ix in self.interactions:
            if ix.direction == "request":
                code = ix.details.get("code", -1)
                if code in COAP_WRITE_METHODS:
                    pair = (ix.src_ip, ix.dst_ip)
                    writes[pair] = writes.get(pair, 0) + 1
        return [
            {"client": client, "server": server, "write_count": count}
            for (client, server), count in writes.items()
            if count > 0
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed CoAP sessions."""
        return [
            {
                "client": s.client_ip,
                "server": s.server_ip,
                "methods": sorted(s.methods),
                "uri_paths": sorted(s.uri_paths),
                "content_formats": sorted(s.content_formats),
                "observe_count": s.observe_count,
                "write_count": s.write_count,
                "read_count": s.read_count,
                "error_count": s.error_count,
                "unencrypted": s.unencrypted,
                "has_oscore": s.has_oscore,
            }
            for s in self.sessions.values()
        ]

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        method: str,
        uri_path: str,
        msg_type: str,
        is_observe: bool,
        observe_val: int,
        content_format: str,
        payload_len: int,
        is_encrypted: bool,
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts: List[str] = []
        parts.append(method)

        if uri_path:
            parts.append(uri_path)

        if is_observe:
            if observe_val == 0:
                parts.append("[OBSERVE:register]")
            elif observe_val == 1:
                parts.append("[OBSERVE:deregister]")
            else:
                parts.append(f"[OBSERVE:seq={observe_val}]")

        if content_format:
            parts.append(f"({content_format})")

        if payload_len:
            parts.append(f"{payload_len}B")

        return " ".join(parts)
