"""
SIP/RTP Passive Listener for VoIP call tracking.

Passively captures SIP/RTP traffic to track:
- VoIP call initiation and termination
- Caller and callee identification
- Call metadata (duration, codecs)
- RTP media streams

Based on BruteShark's VoipCallsModule approach.
Uses PyShark for packet dissection via tshark.

SIP Methods:
- INVITE: Call initiation
- ACK: Call acknowledgment
- CANCEL: Call cancellation
- BYE: Call termination

SIP Responses:
- 200 OK: Success (contains SDP with RTP port)
- 4xx: Client errors
- 5xx: Server errors
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
)


@dataclass
class SIPDigestCredential:
    """Extracted SIP Digest authentication credential."""

    username: str
    realm: str = ""
    nonce: str = ""
    uri: str = ""
    response: str = ""  # The digest hash
    qop: str = ""
    nc: str = ""
    cnonce: str = ""
    algorithm: str = "MD5"
    method: str = "REGISTER"
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    timestamp: str = ""

    @property
    def password(self) -> str:
        """No plaintext password for digest auth."""
        return ""

    @property
    def hash_value(self) -> str:
        """The digest response hash."""
        return self.response

    @property
    def hashcat_format(self) -> str:
        """Hashcat-compatible hash string (mode 11400)."""
        return (
            f"$sip$*{self.uri}*{self.realm}*{self.username}*"
            f"{self.nonce}*{self.nc}*{self.cnonce}*{self.qop}*"
            f"{self.method}*{self.response}"
        )

    @property
    def credential_type(self) -> str:
        return "hash"

    @property
    def auth_method(self) -> str:
        return f"SIP-Digest-{self.algorithm}"


class CallState(Enum):
    """VoIP call state."""

    INVITED = "invited"
    IN_CALL = "in_call"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"


@dataclass
class VoIPCall:
    """Tracked VoIP call."""

    call_id: str
    from_user: str
    from_host: str
    from_ip: str
    to_user: str
    to_host: str
    to_ip: str
    state: CallState
    rtp_port: int = 0
    rtp_media_type: str = ""
    start_time: str = ""
    end_time: str = ""
    rtp_packet_count: int = 0


class SIPPassiveListener(PySharkListenerBase):
    """Passive SIP/RTP traffic listener for VoIP call tracking.

    Captures SIP traffic to track:
    - Call setup (INVITE, 200 OK, ACK)
    - Call teardown (BYE, CANCEL)
    - Caller/callee information
    - RTP media ports and codecs

    Uses PyShark (tshark) for SIP protocol dissection.

    Usage:
        # Live capture
        listener = SIPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
        devices = listener.scan()

        # Access tracked calls
        for call in listener.calls.values():
            print(f"{call.from_user} -> {call.to_user} ({call.state.value})")

    Data structure stored in device.sip_passive_data:
        {
            "role": "caller" | "callee" | "server",
            "calls": [...],
            "protocol": "SIP/UDP",
        }
    """

    PROTOCOL_NAME = "sip"
    DISPLAY_FILTER = "sip"
    REQUIRED_LAYERS = ("sip",)
    PROTOCOL_COLUMNS = ("method", "from", "to", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize SIP passive listener."""
        super().__init__(interface, timeout, nxc_logger)

        # Track calls by Call-ID
        self.calls: Dict[str, VoIPCall] = {}

        # Extracted SIP Digest credentials
        self.credentials: List[SIPDigestCredential] = []

    def process_packet(self, packet) -> None:
        """Process SIP packet and track calls using PyShark dissection."""
        if not hasattr(packet, "sip"):
            return

        sip_layer = packet.sip
        src_ip, dst_ip = self.get_ip_info(packet)

        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        # Get SIP method (for requests) or status code (for responses)
        # Try EK-mode field name first (Method), then XML-mode (method)
        method = self.get_field_any(sip_layer, "Method", "method")
        status_code = self.get_field_any(sip_layer, "Status-Code", "status_code")

        # Extract common per-packet fields for interaction details
        call_id = self.get_field(sip_layer, "Call-ID", None) or self.get_field(
            sip_layer, "call_id", None
        )
        user_agent = self.get_field(sip_layer, "User-Agent", None)
        cseq_seq = self.get_field(sip_layer, "CSeq_seq", None)
        cseq_method = self.get_field(sip_layer, "CSeq_method", None)
        via_address = self.get_field(sip_layer, "Via_sent-by_address", None)
        from_user = self.get_field(sip_layer, "from_user", None)
        from_host = self.get_field(sip_layer, "from_host", None)
        from_port = self.get_field(sip_layer, "from_port", None)
        to_user = self.get_field(sip_layer, "to_user", None)
        to_host = self.get_field(sip_layer, "to_host", None)
        to_port = self.get_field(sip_layer, "to_port", None)
        contact_user = self.get_field(sip_layer, "contact_user", None)
        r_uri_user = self.get_field(sip_layer, "r-uri_user", None)
        response_time = self.get_field(sip_layer, "response-time", None)

        # Build interaction details dict with all available fields
        details: Dict[str, Any] = {}
        if call_id:
            details["call_id"] = str(call_id)
        if user_agent:
            details["user_agent"] = str(user_agent)
        if cseq_seq:
            details["cseq_seq"] = str(cseq_seq)
        if cseq_method:
            details["cseq_method"] = str(cseq_method)
        if via_address:
            details["via_address"] = str(via_address)
        if from_user:
            details["from_user"] = str(from_user)
        if from_host:
            details["from_host"] = str(from_host)
        if from_port:
            details["from_port"] = str(from_port)
        if to_user:
            details["to_user"] = str(to_user)
        if to_host:
            details["to_host"] = str(to_host)
        if to_port:
            details["to_port"] = str(to_port)
        if contact_user:
            details["contact_user"] = str(contact_user)
        if r_uri_user:
            details["r_uri_user"] = str(r_uri_user)
        if response_time:
            details["response_time"] = str(response_time)

        # Extract auth header fields (T1 coverage)
        self._extract_auth_header_fields(sip_layer, details)

        # Record interaction
        now = datetime.now().isoformat()
        src_port, dst_port = self.get_port_info(packet)
        if method:
            details["method"] = str(method)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                f"SIP {method}",
                details,
                f"SIP {method}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
        elif status_code:
            details["status_code"] = str(status_code)
            status_line = self.get_field(sip_layer, "Status-Line", None)
            if status_line:
                details["status_line"] = str(status_line)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                f"SIP {status_code}",
                details,
                f"SIP {status_code}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

        # Extract SIP Digest authentication from any packet with auth headers.
        # Prefer the CSeq method (reflects the request method the digest was
        # computed over), falling back to the request line method.
        digest_method = str(cseq_method or method or "REGISTER").strip() or "REGISTER"
        self._extract_digest_auth(sip_layer, src_ip, dst_ip, dst_port, digest_method)

        if method:
            # SIP request
            self._process_sip_request(str(method), sip_layer, packet, src_ip, dst_ip)
        elif status_code:
            # SIP response
            try:
                status_code_int = int(status_code)
                self._process_sip_response(status_code_int, sip_layer, packet, src_ip, dst_ip)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get status_code_int: {e}")

    def _extract_auth_header_fields(self, sip_layer, details: Dict[str, Any]) -> None:
        """Extract authentication header fields into interaction details."""
        # Full auth header values (Authorization, Proxy-*, WWW-Authenticate)
        authorization = self.get_field(sip_layer, "Authorization", None)
        if authorization:
            details["authorization"] = str(authorization)
        proxy_auth = self.get_field(sip_layer, "Proxy-Authenticate", None)
        if proxy_auth:
            details["proxy_authenticate"] = str(proxy_auth)
        proxy_authz = self.get_field(sip_layer, "Proxy-Authorization", None)
        if proxy_authz:
            details["proxy_authorization"] = str(proxy_authz)
        www_auth = self.get_field(sip_layer, "WWW-Authenticate", None)
        if www_auth:
            details["www_authenticate"] = str(www_auth)

        # Parsed auth sub-fields
        auth = self.get_field(sip_layer, "auth", None)
        if auth:
            details["auth"] = str(auth)
        auth_scheme = self.get_field(sip_layer, "auth_scheme", None)
        if auth_scheme:
            details["auth_scheme"] = str(auth_scheme)
        auth_opaque = self.get_field(sip_layer, "auth_opaque", None)
        if auth_opaque:
            details["auth_opaque"] = str(auth_opaque)
        auth_stale = self.get_field(sip_layer, "auth_stale", None)
        if auth_stale:
            details["auth_stale"] = str(auth_stale)

    def _parse_sip_address(self, address: str) -> tuple:
        """Parse SIP address into user and host.

        Args:
            address: SIP address like 'sip:user@host' or '"Name" <sip:user@host>'

        Returns:
            Tuple of (user, host)
        """
        if not address:
            return "", ""

        # Remove display name and angle brackets
        if "<" in address:
            address = address.split("<")[-1].split(">")[0]

        # Remove sip: prefix
        if address.startswith("sip:"):
            address = address[4:]
        elif address.startswith("sips:"):
            address = address[5:]

        # Split user@host
        if "@" in address:
            parts = address.split("@", 1)
            user = parts[0]
            # Remove port and parameters from host
            host = parts[1].split(":")[0].split(";")[0]
            return user, host

        return address, ""

    def _process_sip_request(
        self, method: str, sip_layer, packet, src_ip: str, dst_ip: str
    ) -> None:
        """Process SIP request using PyShark fields."""
        # Get Call-ID from PyShark (EK: Call-ID, XML: call_id)
        call_id = self.get_field(sip_layer, "Call-ID", None) or self.get_field(
            sip_layer, "call_id", None
        )
        if not call_id:
            return

        if method == "INVITE":
            self._handle_invite(call_id, sip_layer, packet, src_ip, dst_ip)
        elif method == "ACK":
            self._handle_ack(call_id)
        elif method == "BYE":
            self._handle_bye(call_id)
        elif method == "CANCEL":
            self._handle_cancel(call_id)

    def _process_sip_response(
        self, status_code: int, sip_layer, packet, src_ip: str, dst_ip: str
    ) -> None:
        """Process SIP response using PyShark fields."""
        call_id = self.get_field(sip_layer, "Call-ID", None) or self.get_field(
            sip_layer, "call_id", None
        )
        if not call_id:
            return

        if call_id not in self.calls:
            return

        call = self.calls[call_id]

        if status_code == 200:
            # 200 OK - Call answered, extract RTP info from SDP
            self._extract_sdp_info(call, packet)
            self.logger.debug(f"SIP: 200 OK for {call_id}, RTP port={call.rtp_port}")

        elif 400 <= status_code < 500:
            # Client error - call rejected
            call.state = CallState.REJECTED
            call.end_time = datetime.now().isoformat()
            self._finalize_call(call)
            self.logger.info(f"SIP: Call {call_id} rejected ({status_code})")

    def _extract_sdp_info(self, call: VoIPCall, packet) -> None:
        """Extract RTP port and media info from SDP in packet."""
        if not hasattr(packet, "sdp"):
            return

        sdp_layer = packet.sdp

        # Get media port (m=audio <port>)
        media_port = self.get_field(sdp_layer, "media_port", None)
        if media_port:
            try:
                call.rtp_port = int(media_port)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get call.rtp_port: {e}")

        # Get media type/codec from rtpmap
        media_format = self.get_field(sdp_layer, "media_format", None)
        if media_format:
            call.rtp_media_type = str(media_format)

        # Alternative: Get rtpmap encoding name
        encoding_name = self.get_field(sdp_layer, "rtpmap_encoding_name", None)
        if encoding_name and not call.rtp_media_type:
            call.rtp_media_type = str(encoding_name)

    def _handle_invite(
        self,
        call_id: str,
        sip_layer,
        packet,
        src_ip: str,
        dst_ip: str,
    ) -> None:
        """Handle INVITE request - new call initiation."""
        if call_id in self.calls:
            return  # Already tracking this call

        # Prefer tshark-dissected user/host fields (EK mode) over manual parsing
        from_user = self.get_field(sip_layer, "from_user", "") or ""
        from_host = self.get_field(sip_layer, "from_host", "") or ""
        to_user = self.get_field(sip_layer, "to_user", "") or ""
        to_host = self.get_field(sip_layer, "to_host", "") or ""

        # Fall back to manual address parsing if tshark fields are absent
        if not from_user and not from_host:
            from_addr = self.get_field_any(sip_layer, "from", "from_addr", default="")
            from_user, from_host = self._parse_sip_address(str(from_addr))
        if not to_user and not to_host:
            to_addr = self.get_field_any(sip_layer, "to", "to_addr", default="")
            to_user, to_host = self._parse_sip_address(str(to_addr))

        call = VoIPCall(
            call_id=call_id,
            from_user=from_user,
            from_host=from_host,
            from_ip=src_ip,
            to_user=to_user,
            to_host=to_host,
            to_ip=dst_ip,
            state=CallState.INVITED,
            start_time=datetime.now().isoformat(),
        )
        self.calls[call_id] = call

        self.logger.info(
            f"SIP: INVITE {call.from_user}@{call.from_host} -> {call.to_user}@{call.to_host}"
        )

        # Update devices
        self._update_devices(call)

    def _handle_ack(self, call_id: str) -> None:
        """Handle ACK - call established."""
        if call_id not in self.calls:
            return

        call = self.calls[call_id]
        call.state = CallState.IN_CALL

        self.logger.debug(f"SIP: ACK for {call_id} - call established")

    def _handle_bye(self, call_id: str) -> None:
        """Handle BYE - call terminated normally."""
        if call_id not in self.calls:
            return

        call = self.calls[call_id]
        call.state = CallState.COMPLETED
        call.end_time = datetime.now().isoformat()

        self._finalize_call(call)
        self.logger.info(f"SIP: BYE for {call_id} - call completed")

    def _handle_cancel(self, call_id: str) -> None:
        """Handle CANCEL - call cancelled before answer."""
        if call_id not in self.calls:
            return

        call = self.calls[call_id]
        call.state = CallState.CANCELLED
        call.end_time = datetime.now().isoformat()

        self._finalize_call(call)
        self.logger.info(f"SIP: CANCEL for {call_id} - call cancelled")

    def _finalize_call(self, call: VoIPCall) -> None:
        """Finalize call and update device records."""
        self._update_devices(call)

    def _update_devices(self, call: VoIPCall) -> None:
        """Update device entries with call information."""
        # Caller device
        caller_ip = call.from_ip
        callee_ip = call.to_ip

        call_info = {
            "call_id": call.call_id,
            "from": f"{call.from_user}@{call.from_host}",
            "to": f"{call.to_user}@{call.to_host}",
            "state": call.state.value,
            "rtp_port": call.rtp_port,
            "start_time": call.start_time,
            "end_time": call.end_time,
        }

        # Caller
        if is_valid_discovered_ip(caller_ip):
            caller_key = f"sip-caller:{caller_ip}"
            device, is_new = self._ensure_device(
                caller_key,
                caller_ip,
                name=f"VoIP Phone ({call.from_user})",
                device_type="VoIP Phone",
            )
            if is_new:
                device.sip_passive_data = {
                    "role": "caller",
                    "user": call.from_user,
                    "calls": [call_info],
                    "protocol": "SIP/UDP",
                }
            else:
                if device.sip_passive_data:
                    # Update call info
                    calls = device.sip_passive_data.get("calls", [])
                    # Update existing or add new
                    for i, c in enumerate(calls):
                        if c.get("call_id") == call.call_id:
                            calls[i] = call_info
                            break
                    else:
                        calls.append(call_info)
                    device.sip_passive_data["calls"] = calls
        # Callee
        if is_valid_discovered_ip(callee_ip):
            callee_key = f"sip-callee:{callee_ip}"
            device, is_new = self._ensure_device(
                callee_key,
                callee_ip,
                name=f"VoIP Phone ({call.to_user})",
                device_type="VoIP Phone",
            )
            if is_new:
                device.sip_passive_data = {
                    "role": "callee",
                    "user": call.to_user,
                    "calls": [call_info],
                    "protocol": "SIP/UDP",
                }

    def _extract_digest_auth(
        self,
        sip_layer,
        src_ip: str,
        dst_ip: str,
        dst_port: int = 0,
        method: str = "REGISTER",
    ) -> None:
        """Extract SIP Digest authentication credentials from Authorization header."""
        # Check for auth fields (from Authorization or Proxy-Authorization headers)
        username = str(self.get_field(sip_layer, "auth_username", "") or "").strip()
        if not username:
            return

        realm = str(self.get_field(sip_layer, "auth_realm", "") or "").strip()
        nonce = str(self.get_field(sip_layer, "auth_nonce", "") or "").strip()
        response = str(self.get_field(sip_layer, "auth_digest_response", "") or "").strip()
        uri = str(self.get_field(sip_layer, "auth_uri", "") or "").strip()
        qop = str(self.get_field(sip_layer, "auth_qop", "") or "").strip()
        nc = str(self.get_field(sip_layer, "auth_nc", "") or "").strip()
        cnonce = str(self.get_field(sip_layer, "auth_cnonce", "") or "").strip()
        algorithm = str(self.get_field(sip_layer, "auth_algorithm", "") or "").strip() or "MD5"

        if not response:
            return

        # Check for duplicate
        if self._is_duplicate_digest(username, response, src_ip, dst_ip):
            return

        cred = SIPDigestCredential(
            username=username,
            realm=realm,
            nonce=nonce,
            uri=uri,
            response=response,
            qop=qop,
            nc=nc,
            cnonce=cnonce,
            algorithm=algorithm,
            method=(method or "REGISTER").strip() or "REGISTER",
            server_ip=dst_ip,
            server_port=dst_port,
            client_ip=src_ip,
            timestamp=datetime.now().isoformat(),
        )
        self.credentials.append(cred)
        self.logger.info(f"SIP Digest Auth: {username} @ {dst_ip}:{dst_port} (realm={realm})")

    def _is_duplicate_digest(
        self, username: str, response: str, client_ip: str, server_ip: str
    ) -> bool:
        """Check if SIP digest credential is already recorded."""
        for cred in self.credentials:
            if (
                cred.username == username
                and cred.response == response
                and cred.client_ip == client_ip
                and cred.server_ip == server_ip
            ):
                return True
        return False

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format interaction as [Method, From, To, Detail]."""
        d = ix.details
        method = d.get("method", d.get("status_code", ""))
        from_addr = d.get("from_user", "")
        if from_addr and d.get("from_host"):
            from_addr = f"{from_addr}@{d['from_host']}"
        to_addr = d.get("to_user", "")
        if to_addr and d.get("to_host"):
            to_addr = f"{to_addr}@{d['to_host']}"
        detail = d.get("status_line", d.get("user_agent", ""))
        return [str(method), str(from_addr), str(to_addr), str(detail)]

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted SIP Digest credentials."""
        result = []
        for cred in self.credentials:
            result.append(
                {
                    "protocol": "SIP",
                    "credential_type": "hash",
                    "auth_method": f"SIP-Digest-{cred.algorithm}",
                    "username": cred.username,
                    "realm": cred.realm,
                    "nonce": cred.nonce,
                    "uri": cred.uri,
                    "response": cred.response,
                    "qop": cred.qop,
                    "nc": cred.nc,
                    "cnonce": cred.cnonce,
                    "algorithm": cred.algorithm,
                    "method": cred.method,
                    "server_ip": cred.server_ip,
                    "client_ip": cred.client_ip,
                    "timestamp": cred.timestamp,
                }
            )
        return result

    def get_hashcat_hashes(self) -> List[str]:
        """Get SIP Digest hashes in hashcat-compatible format.

        Hashcat mode 11400: SIP digest authentication (same as HTTP Digest).
        """
        result = []
        for cred in self.credentials:
            result.append(
                f"$sip$*{cred.uri}*{cred.realm}*{cred.username}*"
                f"{cred.nonce}*{cred.nc}*{cred.cnonce}*{cred.qop}*"
                f"{cred.method}*{cred.response}"
            )
        return result

    def get_calls_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all tracked calls."""
        return [
            {
                "call_id": call.call_id,
                "from_user": call.from_user,
                "from_host": call.from_host,
                "from_ip": call.from_ip,
                "to_user": call.to_user,
                "to_host": call.to_host,
                "to_ip": call.to_ip,
                "state": call.state.value,
                "rtp_port": call.rtp_port,
                "rtp_media_type": call.rtp_media_type,
                "start_time": call.start_time,
                "end_time": call.end_time,
            }
            for call in self.calls.values()
        ]
