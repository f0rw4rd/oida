"""
RTSP Passive Listener for surveillance and streaming infrastructure discovery.

Passively captures RTSP traffic to extract:
- Stream URIs and camera endpoints
- Methods (DESCRIBE, SETUP, PLAY, TEARDOWN)
- Session IDs and transport parameters
- Authentication credentials (Basic/Digest)
- Server and client user-agent strings
- Content types and SDP information

RTSP uses:
- TCP port: 554 (primary)
- TCP port: 8554 (alternate)
- Text-based protocol similar to HTTP/1.1

Request methods:
- OPTIONS: Query server capabilities
- DESCRIBE: Get media description (SDP)
- ANNOUNCE: Post description of media
- SETUP: Specify transport mechanism
- PLAY: Start media delivery
- PAUSE: Temporarily halt delivery
- TEARDOWN: Stop media delivery
- GET_PARAMETER: Get parameter value
- SET_PARAMETER: Set parameter value
- RECORD: Start recording

Security value for ICS:
- IP camera and surveillance system enumeration
- Stream access discovery (unauthorized viewing)
- Credential extraction from authentication headers
- Camera firmware/version fingerprinting

PyShark RTSP field reference (packet.rtsp.*):
- rtsp.method: Request method
- rtsp.url: Request URL
- rtsp.session: Session identifier
- rtsp.status: Response status code
- rtsp.content_type: Content-Type header
- rtsp.transport: Transport header parameters
- rtsp.authorization: Authorization header
- rtsp.server: Server header
- rtsp.user_agent: User-Agent header
"""

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# RTSP constants
RTSP_PORT = 554
RTSP_ALT_PORT = 8554


@dataclass
class RTSPCredential:
    """Extracted RTSP credential."""

    username: str
    password: str = ""
    auth_type: str = "Basic"  # "Basic" or "Digest"
    credential_type: str = "plaintext"
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    url: str = ""
    timestamp: str = ""

    @property
    def auth_method(self) -> str:
        """Scanner credential loop compatibility."""
        return f"RTSP-{self.auth_type}"


class RTSPPassiveListener(PySharkListenerBase):
    """Passive RTSP traffic listener for camera/streaming discovery.

    Captures RTSP traffic to discover:
    - IP cameras and surveillance systems
    - Stream URIs and endpoints
    - Authentication credentials (Basic/Digest)
    - Server software versions
    - Transport parameters

    Usage:
        listener = RTSPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for cred in listener.credentials:
            print(f"{cred.auth_type}: {cred.username} @ {cred.url}")
    """

    PROTOCOL_NAME = "rtsp"
    DISPLAY_FILTER = "rtsp"
    REQUIRED_LAYERS = ("rtsp",)
    SERVER_PORTS = (RTSP_PORT, RTSP_ALT_PORT)
    PROTOCOL_COLUMNS = (
        "method_status",
        "url",
        "session",
        "transport",
        "detail",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[RTSPCredential] = []
        self._seen_creds: Set[Tuple[str, str, str]] = set()

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format RTSP interaction as protocol-specific table columns."""
        d = ix.details
        method_status = d.get("method", "") or d.get("status", "") or "?"
        url = d.get("url", "") or "-"
        session = d.get("session", "") or "-"
        transport = d.get("transport", "") or "-"
        # Build detail from remaining fields
        detail_parts: List[str] = []
        if d.get("server"):
            detail_parts.append(f"srv={d['server']}")
        if d.get("user_agent"):
            detail_parts.append(f"ua={d['user_agent']}")
        if d.get("content_type"):
            detail_parts.append(f"ct={d['content_type']}")
        if d.get("cseq"):
            detail_parts.append(f"cseq={d['cseq']}")
        detail = " ".join(detail_parts) or "-"

        return [
            method_status,
            url,
            session,
            transport,
            detail,
        ]

    def process_packet(self, packet) -> None:
        """Process RTSP packet and extract stream/camera information."""
        if not hasattr(packet, "rtsp"):
            return

        rtsp = packet.rtsp
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        stream_id = self.get_stream_id(packet)

        # Determine if request or response.  RTSP is text-based like HTTP: a
        # request line carries a method (OPTIONS/DESCRIBE/SETUP/PLAY...), a
        # response line carries an "RTSP/1.0 <code>" status -- a clean,
        # port-independent QR signal we feed as the cascade's native tier.  When
        # a frame has neither (e.g. an interleaved/continuation segment), pass
        # native=None so resolve_direction() falls through to the known-server-
        # port tier (canonical 554/8554 plus user --decode-as / OVERRIDE_PREFS)
        # and then the lower-port heuristic.
        method = str(self.get_field(rtsp, "method", "") or "")
        status = str(self.get_field(rtsp, "status", "") or "")
        status_code = str(self.get_field(rtsp, "status_code", "") or "")

        has_status = bool(status) or bool(status_code)
        if method:
            native: Optional[bool] = True
        elif has_status:
            native = False
        else:
            native = None
        d = self.resolve_direction(
            packet,
            native=native,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        direction = d.direction

        # Extract RTSP fields from named layer attributes
        url = str(self.get_field(rtsp, "url", "") or "")
        session = str(self.get_field(rtsp, "session", "") or "")
        content_type = str(self.get_field(rtsp, "content_type", "") or "")
        transport = str(self.get_field(rtsp, "transport", "") or "")
        server = str(self.get_field(rtsp, "server", "") or "")
        user_agent = str(self.get_field(rtsp, "user_agent", "") or "")
        cseq = str(self.get_field(rtsp, "cseq", "") or "")
        authorization = str(self.get_field(rtsp, "authorization", "") or "")

        # tshark exposes Server/User-Agent/Authorization as unnamed fields
        # in the RTSP layer (empty key in _all_fields).  Parse them from
        # the raw header text when not already extracted.
        if not server or not user_agent or not authorization:
            raw_headers = self._extract_raw_headers(rtsp)
            if not server:
                server = raw_headers.get("server", "")
            if not user_agent:
                user_agent = raw_headers.get("user-agent", "")
            if not authorization:
                authorization = raw_headers.get("authorization", "")

        # Build operation name
        if method:
            operation = f"RTSP {method}"
        elif status_code:
            operation = f"RTSP {status_code}"
            if status:
                operation = f"RTSP {status}"
        else:
            operation = "RTSP"

        # Build detail
        details: Dict[str, Any] = {
            "method": method,
            "url": url,
            "session": session,
            "status": status,
            "status_code": status_code,
            "content_type": content_type,
            "transport": transport,
            "server": server,
            "user_agent": user_agent,
            "cseq": cseq,
        }

        now = datetime.now().isoformat()
        summary = f"RTSP {method or status} {src_ip}"
        if url:
            summary += f" {url}"

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

        # Extract credentials from Authorization header
        if authorization:
            self._extract_credentials(
                authorization,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                url,
                now,
            )

        # Update device tracking.  Roles come from the resolved direction: the
        # RTSP camera/server is d.server_ip, the viewer/client is d.client_ip.
        camera_mac = src_mac if not d.is_request else dst_mac
        client_mac = dst_mac if not d.is_request else src_mac
        self._update_devices(
            d.server_ip,
            d.client_ip,
            camera_mac,
            client_mac,
            url=url,
            server=server,
            user_agent=user_agent,
        )

    def _extract_raw_headers(self, rtsp_layer) -> Dict[str, str]:
        """Extract RTSP headers from raw request/response text and unnamed fields.

        tshark stores Server, User-Agent, Authorization, and other headers
        differently depending on dissection mode:
        - XML mode: unnamed (empty-key) fields in _all_fields
        - EK mode: only available in the raw ``request`` or ``response`` text

        This method parses both sources.
        """
        headers: Dict[str, str] = {}

        # Source 1: Parse raw request/response text (works in both modes)
        for field_name in ("request", "response"):
            raw = str(self.get_field(rtsp_layer, field_name, "") or "")
            if raw:
                self._parse_header_lines(raw, headers)

        # Source 2: Unnamed fields in XML mode _all_fields
        all_fields = self.get_all_fields(rtsp_layer)
        for key, val in all_fields.items():
            val_str = str(val).strip()
            if not key or key == "":
                self._parse_header_lines(val_str, headers)

        return headers

    @staticmethod
    def _parse_header_lines(text: str, headers: Dict[str, str]) -> None:
        """Parse RTSP header lines from raw text into headers dict."""
        # Split on \r\n (literal or escaped)
        lines = text.replace("\\r\\n", "\n").replace("\r\n", "\n").split("\n")
        for line in lines:
            line = line.strip()
            if ": " in line and not line.startswith(
                (
                    "RTSP/",
                    "OPTIONS ",
                    "DESCRIBE ",
                    "SETUP ",
                    "PLAY ",
                    "PAUSE ",
                    "TEARDOWN ",
                    "GET_PARAMETER ",
                    "SET_PARAMETER ",
                    "ANNOUNCE ",
                    "RECORD ",
                )
            ):
                hdr_name, _, hdr_val = line.partition(": ")
                headers[hdr_name.lower().strip()] = hdr_val.strip()

    def _extract_credentials(
        self,
        authorization: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        url: str,
        timestamp: str,
    ) -> None:
        """Extract credentials from RTSP Authorization header."""
        auth_str = authorization.strip()

        if auth_str.lower().startswith("basic "):
            b64_creds = auth_str[6:].strip()
            try:
                decoded = base64.b64decode(b64_creds).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
                    self._record_credential(
                        username,
                        password,
                        "Basic",
                        "plaintext",
                        src_ip,
                        dst_ip,
                        dst_port,
                        url,
                        timestamp,
                    )
            except Exception as e:
                self.logger.debug(f"Failed to get decoded: {e}")

        elif auth_str.lower().startswith("digest "):
            # Extract username from Digest auth header
            username = self._extract_digest_field(auth_str, "username")
            if username:
                self._record_credential(
                    username,
                    "",
                    "Digest",
                    "hash",
                    src_ip,
                    dst_ip,
                    dst_port,
                    url,
                    timestamp,
                )

    def _extract_digest_field(self, auth_header: str, field_name: str) -> str:
        """Extract a field value from a Digest authorization header."""
        import re

        pattern = rf'{field_name}="([^"]*)"'
        match = re.search(pattern, auth_header, re.IGNORECASE)
        if match:
            return match.group(1)
        # Try without quotes
        pattern = rf"{field_name}=([^,\s]*)"
        match = re.search(pattern, auth_header, re.IGNORECASE)
        if match:
            return match.group(1).strip('"')
        return ""

    def _record_credential(
        self,
        username: str,
        password: str,
        auth_type: str,
        credential_type: str,
        client_ip: str,
        server_ip: str,
        server_port: int,
        url: str,
        timestamp: str,
    ) -> None:
        """Record extracted RTSP credential."""
        cred_key = (username, client_ip, server_ip)
        if cred_key in self._seen_creds:
            return
        self._seen_creds.add(cred_key)

        cred = RTSPCredential(
            username=username,
            password=password,
            auth_type=auth_type,
            credential_type=credential_type,
            server_ip=server_ip,
            server_port=server_port,
            client_ip=client_ip,
            url=url,
            timestamp=timestamp,
        )
        self.credentials.append(cred)
        self.logger.info(f"RTSP {auth_type}: {username} @ {server_ip}:{server_port} ({url})")

    def _update_devices(
        self,
        camera_ip: str,
        client_ip: str,
        camera_mac: str = "",
        client_mac: str = "",
        url: str = "",
        server: str = "",
        user_agent: str = "",
    ) -> None:
        """Update device entries for RTSP participants.

        Roles are pre-resolved by the caller via ``resolve_direction()``: the
        camera/RTSP server is *camera_ip*, the viewer is *client_ip*.
        """
        if is_valid_discovered_ip(camera_ip):
            vendor = lookup_mac_vendor(camera_mac) if camera_mac else ""
            device, is_new = self._ensure_device(
                f"rtsp-camera:{camera_ip}",
                camera_ip,
                mac=camera_mac,
                name=server or "",
                device_type="IP Camera/RTSP Server",
                manufacturer=vendor if vendor != "Unknown" else "",
            )
            if is_new:
                device.rtsp_passive_data = {
                    "role": "server",
                    "protocol": "RTSP/TCP",
                    "server": server,
                    "streams": [],
                }
            else:
                data = getattr(device, "rtsp_passive_data", None)
                if data:
                    if server and not data.get("server"):
                        data["server"] = server
                    if url and url not in data.get("streams", []):
                        data.setdefault("streams", []).append(url)

        if is_valid_discovered_ip(client_ip):
            vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            device, is_new = self._ensure_device(
                f"rtsp-client:{client_ip}",
                client_ip,
                mac=client_mac,
                name="",
                device_type="RTSP Client",
                manufacturer=vendor if vendor != "Unknown" else "",
            )
            if is_new:
                device.rtsp_passive_data = {
                    "role": "client",
                    "protocol": "RTSP/TCP",
                    "user_agent": user_agent,
                }

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return [
            {
                "protocol": "RTSP",
                "credential_type": cred.credential_type,
                "auth_method": cred.auth_method,
                "username": cred.username,
                "password": cred.password,
                "server_ip": cred.server_ip,
                "server_port": cred.server_port,
                "client_ip": cred.client_ip,
                "url": cred.url,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]
