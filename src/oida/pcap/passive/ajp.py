"""
AJP13 (Apache JServ Protocol) Passive Listener.

Passively captures AJP13 traffic between web servers and Tomcat/Java
application servers to extract:
- HTTP methods and URIs proxied through AJP
- Remote client addresses (real client behind reverse proxy)
- Server names and servlet engine info
- Response status codes (401/403 = auth issues)
- Sensitive paths (manager, admin, WEB-INF)

AJP13 runs on TCP port 8009 (default) and is used by Apache httpd
mod_jk / mod_proxy_ajp to forward requests to Tomcat.

Security value:
- Ghostcat (CVE-2020-1938): AJP connector file read/inclusion
- Exposed AJP ports allow direct servlet access bypassing WAF/auth
- Reveals internal Java web app structure and URLs

tshark fields used (requires decode_as tcp.port==8009,ajp13):
- ajp13.code: Packet type (2=ForwardRequest, 4=SendHeaders, 5=EndResponse)
- ajp13.method: HTTP method code (2=GET, 3=HEAD, 4=POST, ...)
- ajp13.uri: Request URI
- ajp13.raddr: Remote (client) address
- ajp13.rhost: Remote hostname
- ajp13.srv: Server name
- ajp13.port: Server port
- ajp13.sslp: Is SSL?
- ajp13.nhdr: Number of headers
- ajp13.host: Host header
- ajp13.user_agent: User-Agent header
- ajp13.content_type: Content-Type header
- ajp13.content_length: Content-Length header
- ajp13.servlet_engine: Servlet-Engine response header
- ajp13.www_authenticate: WWW-Authenticate response header
- ajp13.location: Location response header
- ajp13.status: Status response header
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# AJP13 packet type codes (ajp13.code)
AJP_FORWARD_REQUEST = "2"
AJP_SEND_HEADERS = "4"
AJP_END_RESPONSE = "5"
AJP_SEND_BODY_CHUNK = "3"
AJP_GET_BODY_CHUNK = "6"
AJP_SHUTDOWN = "7"
AJP_PING = "8"
AJP_CPONG = "9"
AJP_CPING = "10"

CODE_NAMES = {
    "2": "Forward Request",
    "3": "Send Body Chunk",
    "4": "Send Headers",
    "5": "End Response",
    "6": "Get Body Chunk",
    "7": "Shutdown",
    "8": "Ping",
    "9": "CPong",
    "10": "CPing",
}

# AJP13 HTTP method codes
METHOD_NAMES = {
    "1": "OPTIONS",
    "2": "GET",
    "3": "HEAD",
    "4": "POST",
    "5": "PUT",
    "6": "DELETE",
    "7": "TRACE",
    "8": "PROPFIND",
    "9": "PROPPATCH",
    "10": "MKCOL",
    "11": "COPY",
    "12": "MOVE",
    "13": "LOCK",
    "14": "UNLOCK",
    "15": "ACL",
    "16": "REPORT",
    "17": "VERSION-CONTROL",
    "18": "CHECKIN",
    "19": "CHECKOUT",
    "20": "UNCHECKOUT",
    "21": "SEARCH",
    "22": "MKWORKSPACE",
    "23": "UPDATE",
    "24": "LABEL",
    "25": "MERGE",
    "26": "BASELINE-CONTROL",
    "27": "MKACTIVITY",
}

# Sensitive URI patterns
SENSITIVE_PATHS = {
    "/manager",
    "/manager/html",
    "/manager/text",
    "/manager/status",
    "/host-manager",
    "/admin",
    "/WEB-INF",
    "/META-INF",
    "/status",
    "/jmxproxy",
    "/jolokia",
    "/console",
}


class AJPPassiveListener(PySharkListenerBase):
    """Passive AJP13 traffic listener.

    Captures AJP13 traffic between web servers (Apache httpd, nginx)
    and Java application servers (Tomcat) to extract:
    - HTTP methods and URIs being proxied
    - Remote client addresses (real source behind reverse proxy)
    - Servlet engine identification
    - Response status codes
    - Sensitive admin path access attempts
    """

    PROTOCOL_NAME = "ajp"
    DISPLAY_FILTER = "ajp13"
    REQUIRED_LAYERS = ("ajp13",)
    PROTOCOL_COLUMNS = ("type", "method", "uri", "status", "detail")

    # Decode-as hint needed because tshark doesn't auto-detect AJP13
    DECODE_AS = {"tcp.port==8009": "ajp13"}

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.servlet_engines: Dict[str, str] = {}  # server_ip -> engine version
        self.uri_paths: Dict[str, Set[str]] = {}  # server_ip -> set of URIs
        self._sensitive_access: List[Dict[str, str]] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format AJP interaction as protocol-specific table columns."""
        d = ix.details
        code_name = d.get("code_name", "")
        method = d.get("method_name", "")
        uri = d.get("uri", "")
        status = d.get("response_status", "")
        detail = d.get("detail", "")
        return [code_name, method, uri, status, detail]

    def process_packet(self, packet) -> None:
        """Process AJP13 packet."""
        if not hasattr(packet, "ajp13"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        ajp = packet.ajp13
        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        code_raw = str(self.get_field(ajp, "code", "") or "")
        code_name = CODE_NAMES.get(code_raw, f"Unknown({code_raw})")

        if code_raw == AJP_FORWARD_REQUEST:
            self._process_forward_request(
                ajp,
                src_ip,
                dst_ip,
                flow_id,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                packet,
            )
        elif code_raw == AJP_SEND_HEADERS:
            self._process_send_headers(
                ajp,
                src_ip,
                dst_ip,
                flow_id,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                packet,
            )
        elif code_raw == AJP_END_RESPONSE:
            now = datetime.now().isoformat()
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "AJP End Response",
                {"code": code_raw, "code_name": "End Response"},
                f"AJP End Response {src_ip} -> {dst_ip}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
        elif code_raw in (AJP_SHUTDOWN, AJP_PING, AJP_CPONG, AJP_CPING):
            now = datetime.now().isoformat()
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request" if code_raw in (AJP_SHUTDOWN, AJP_CPING) else "response",
                f"AJP {code_name}",
                {"code": code_raw, "code_name": code_name},
                f"AJP {code_name} {src_ip} -> {dst_ip}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
            if code_raw == AJP_SHUTDOWN:
                self.logger.warning(f"AJP SHUTDOWN command: {src_ip} -> {dst_ip}")

    def _process_forward_request(
        self,
        ajp,
        src_ip,
        dst_ip,
        flow_id,
        src_port,
        dst_port,
        src_mac,
        dst_mac,
        packet,
    ) -> None:
        """Process AJP13 Forward Request (type 2)."""
        method_raw = str(self.get_field(ajp, "method", "") or "")
        method_name = METHOD_NAMES.get(method_raw, f"METHOD_{method_raw}")

        uri = str(self.get_field(ajp, "uri", "") or "")
        raddr = str(self.get_field(ajp, "raddr", "") or "")
        rhost = str(self.get_field(ajp, "rhost", "") or "")
        server = str(self.get_field(ajp, "srv", "") or "")
        port = str(self.get_field(ajp, "port", "") or "")
        is_ssl = self.get_field(ajp, "sslp", "")
        nhdr = str(self.get_field(ajp, "nhdr", "") or "")

        # Extract useful headers
        host_hdr = str(self.get_field(ajp, "host", "") or "")
        user_agent = str(self.get_field(ajp, "user_agent", "") or "")
        content_type = str(self.get_field(ajp, "content_type", "") or "")

        # Build detail string
        detail_parts = []
        if server:
            detail_parts.append(f"srv={server}")
        if raddr and raddr != src_ip:
            detail_parts.append(f"client={raddr}")
        if user_agent:
            detail_parts.append(f"UA={user_agent}")
        detail = " ".join(detail_parts)

        # Track URIs per server
        if dst_ip not in self.uri_paths:
            self.uri_paths[dst_ip] = set()
        if uri:
            self.uri_paths[dst_ip].add(uri)

        # Check for sensitive paths
        if uri:
            uri_lower = uri.lower()
            for sensitive in SENSITIVE_PATHS:
                if uri_lower.startswith(sensitive.lower()):
                    self._sensitive_access.append(
                        {
                            "client": raddr or src_ip,
                            "server": dst_ip,
                            "uri": uri,
                            "method": method_name,
                        }
                    )
                    self.logger.warning(
                        f"AJP sensitive path: {method_name} {uri} "
                        f"(client={raddr or src_ip} -> {dst_ip})"
                    )
                    break

        details: Dict[str, Any] = {
            "code": AJP_FORWARD_REQUEST,
            "code_name": "Forward Request",
            "method": method_raw,
            "method_name": method_name,
            "uri": uri,
            "remote_addr": raddr,
            "remote_host": rhost,
            "server_name": server,
            "server_port": port,
            "is_ssl": str(is_ssl) if is_ssl else "",
            "num_headers": nhdr,
            "host": host_hdr,
            "user_agent": user_agent,
            "content_type": content_type,
            "detail": detail,
        }

        now = datetime.now().isoformat()
        summary = f"AJP {method_name} {uri}"
        if server:
            summary += f" (srv={server})"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"AJP {method_name}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Track devices -- the web server sends Forward Request TO Tomcat
        # src_ip = web server (Apache/nginx), dst_ip = Tomcat
        if is_valid_discovered_ip(dst_ip):
            vendor = lookup_mac_vendor(dst_mac) if dst_mac else ""
            device, is_new = self._ensure_device(
                f"ajp-server:{dst_ip}",
                dst_ip,
                mac=dst_mac or "",
                name=server or f"Tomcat ({dst_ip})",
                device_type="AJP Server (Tomcat)",
                manufacturer=vendor if vendor != "Unknown" else "",
            )
            if is_new:
                device.ajp_passive_data = {
                    "role": "server",
                    "protocol": "AJP13/TCP",
                    "server_name": server,
                }
            elif hasattr(device, "ajp_passive_data") and device.ajp_passive_data:
                if server and not device.ajp_passive_data.get("server_name"):
                    device.ajp_passive_data["server_name"] = server

        if is_valid_discovered_ip(src_ip):
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            self._ensure_device(
                f"ajp-proxy:{src_ip}",
                src_ip,
                mac=src_mac or "",
                name=f"AJP Proxy ({src_ip})",
                device_type="AJP Proxy (Web Server)",
                manufacturer=vendor if vendor != "Unknown" else "",
            )

    def _process_send_headers(
        self,
        ajp,
        src_ip,
        dst_ip,
        flow_id,
        src_port,
        dst_port,
        src_mac,
        dst_mac,
        packet,
    ) -> None:
        """Process AJP13 Send Headers response (type 4)."""
        # Note: In Send Headers, tshark uses different field names
        # Status is in ajp13.status but also accessible via ajp13.nhdr etc.
        nhdr = str(self.get_field(ajp, "nhdr", "") or "")
        content_type = str(self.get_field(ajp, "content_type", "") or "")
        content_length = str(self.get_field(ajp, "content_length", "") or "")
        servlet_engine = str(self.get_field(ajp, "servlet_engine", "") or "")
        www_auth = str(self.get_field(ajp, "www_authenticate", "") or "")
        location = str(self.get_field(ajp, "location", "") or "")

        # Track servlet engine for server fingerprinting
        if servlet_engine and src_ip:
            self.servlet_engines[src_ip] = servlet_engine
            # Update device data
            key = f"ajp-server:{src_ip}"
            if key in self.discovered_devices:
                dev = self.discovered_devices[key]
                if hasattr(dev, "ajp_passive_data") and dev.ajp_passive_data:
                    dev.ajp_passive_data["servlet_engine"] = servlet_engine

        # Build detail
        detail_parts = []
        if content_type:
            detail_parts.append(f"type={content_type}")
        if servlet_engine:
            detail_parts.append(f"engine={servlet_engine}")
        if location:
            detail_parts.append(f"location={location}")
        if www_auth:
            detail_parts.append(f"auth={www_auth}")
        detail = " ".join(detail_parts)

        # We don't have direct access to the status code in a simple field;
        # tshark shows it as RSTATUS but the field name isn't standard.
        # We rely on the overall stream context.
        response_status = ""

        details: Dict[str, Any] = {
            "code": AJP_SEND_HEADERS,
            "code_name": "Send Headers",
            "response_status": response_status,
            "num_headers": nhdr,
            "content_type": content_type,
            "content_length": content_length,
            "servlet_engine": servlet_engine,
            "www_authenticate": www_auth,
            "location": location,
            "detail": detail,
        }

        now = datetime.now().isoformat()
        summary = "AJP Send Headers"
        if servlet_engine:
            summary += f" (engine={servlet_engine})"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "AJP Response",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Tomcat is sending response back to proxy
        if is_valid_discovered_ip(src_ip):
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            device, is_new = self._ensure_device(
                f"ajp-server:{src_ip}",
                src_ip,
                mac=src_mac or "",
                name=servlet_engine or f"Tomcat ({src_ip})",
                device_type="AJP Server (Tomcat)",
                manufacturer=vendor if vendor != "Unknown" else "",
            )
            if is_new:
                device.ajp_passive_data = {
                    "role": "server",
                    "protocol": "AJP13/TCP",
                    "servlet_engine": servlet_engine,
                }

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data."""
        base = super().harvest()
        tables = base.get("tables", [])
        alerts = base.get("alerts", [])

        # Alert on sensitive path access
        for access in self._sensitive_access:
            alerts.append(
                {
                    "level": "fail",
                    "category": "sensitive_access",
                    "message": (
                        f"AJP sensitive path: {access['method']} {access['uri']} "
                        f"(client={access['client']} -> {access['server']})"
                    ),
                }
            )

        if not tables and not alerts:
            return {}
        return {"tables": tables, "alerts": alerts}
