"""
RADIUS Passive Listener for authentication extraction.

Passively captures RADIUS authentication to extract:
- Usernames from Access-Request packets
- NAS identifiers (network access servers)
- Realms and authentication types
- Authentication results (accept/reject/challenge)
- CHAP credentials (CHAP-Password, CHAP-Ident, CHAP challenge hash)
- Message-Authenticator (HMAC-MD5 integrity attribute)
- Filter-Id (access policy from Accept/Challenge responses)

RADIUS packet format:
- Code (1) + Identifier (1) + Length (2) + Authenticator (16) + Attributes

Note: User-Password is XOR'd with MD5(shared_secret + authenticator).
Without the shared secret, only username and metadata can be extracted.
CHAP-Password contains the CHAP identifier + MD5 response hash.

Reference: RFC 2865 (RADIUS), RFC 2866 (Accounting)
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip

# RADIUS codes
RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCOUNTING_REQUEST = 4
RADIUS_ACCOUNTING_RESPONSE = 5
RADIUS_ACCESS_CHALLENGE = 11

# Service types
SERVICE_TYPES = {
    1: "Login",
    2: "Framed",
    3: "Callback Login",
    4: "Callback Framed",
    5: "Outbound",
    6: "Administrative",
    7: "NAS Prompt",
    8: "Authenticate Only",
    9: "Callback NAS Prompt",
    10: "Call Check",
    11: "Callback Administrative",
}

# tshark field names used by this listener (for audit_listener_fields.py detection).
# The listener uses _get_radius_field() on get_all_fields() dicts rather than
# self.get_field(), so this constant registers the field names explicitly.
# get_field() references: radius.code, radius.id, radius.authenticator,
# radius.User_Name, radius.User_Password_encrypted, radius.CHAP_Password,
# radius.CHAP_Ident, radius.Service_Type, radius.Filter_Id,
# radius.Message_Authenticator, radius.NAS_IP_Address
_RADIUS_FIELDS = (
    "radius.code",
    "radius.id",
    "radius.authenticator",
    "radius.User_Name",
    "radius.User_Password_encrypted",
    "radius.CHAP_Password",
    "radius.CHAP_Ident",
    "radius.Service_Type",
    "radius.Filter_Id",
    "radius.Message_Authenticator",
)


@dataclass
class RADIUSCredential:
    """Extracted RADIUS authentication data."""

    username: str
    realm: str  # Part after @ in username
    nas_identifier: str
    nas_ip: str
    calling_station: str  # Client MAC or phone number
    service_type: str
    authenticator: str  # 16-byte authenticator (hex)
    encrypted_password: str  # User-Password attribute (hex, for cracking)
    client_ip: str  # RADIUS client (NAS)
    server_ip: str  # RADIUS server
    timestamp: str = ""
    auth_result: str = ""  # accept/reject/challenge
    credential_type: str = "hash"
    chap_password: str = ""  # CHAP-Password attribute (hex, ident + MD5 hash)
    chap_ident: str = ""  # CHAP identifier byte
    chap_challenge: str = ""  # CHAP-Challenge attribute (hex); falls back to authenticator
    message_authenticator: str = ""  # HMAC-MD5 Message-Authenticator (hex)
    filter_id: str = ""  # Filter-Id from Access-Accept/Challenge
    nas_port: str = ""  # NAS-Port attribute
    # MS-CHAPv2 (Microsoft VSA, vendor 311): hashcat 5500 (NetNTLMv1)
    mschap_challenge: str = ""  # MS-CHAP-Challenge (16-byte AuthenticatorChallenge, hex)
    mschap2_response: str = ""  # MS-CHAP2-Response (49 bytes: flags+PeerChal+resv+NTresp, hex)

    @property
    def password(self) -> str:
        """Alias for scanner credential loop compatibility."""
        return self.encrypted_password or self.chap_password

    @property
    def auth_method(self) -> str:
        """Return auth method distinguishing PAP vs CHAP vs MS-CHAPv2."""
        if self.mschap2_response:
            return "RADIUS-MSCHAPv2"
        if self.chap_password:
            return "RADIUS-CHAP"
        return "RADIUS-PAP"

    @property
    def hashcat_format(self) -> str:
        """Crackable hash line for RADIUS auth.

        - MS-CHAPv2 (MS-CHAP-Challenge + MS-CHAP2-Response) -> NetNTLMv1
          (hashcat 5500): ``user::::<NTresponse>:<8-byte challenge>`` where the
          8-byte challenge = SHA1(PeerChallenge ‖ AuthenticatorChallenge ‖
          username)[:8]. (asleap/chapcrack derivation.)
        - CHAP-Password -> generic CHAP-MD5 (hashcat 4800):
          ``<MD5 response>:<challenge>:<id>`` where the challenge is the
          CHAP-Challenge attribute, or the Request-Authenticator if absent.

        PAP (User-Password) is XOR-obfuscated and not crackable without the
        shared secret, so it yields "" (no fabricated hash).
        """
        if self.mschap2_response and self.mschap_challenge and self.username:
            resp = self.mschap2_response.replace(":", "").lower()
            authchal = self.mschap_challenge.replace(":", "").lower()
            # MS-CHAP2-Response value (RFC 2548, 50 bytes):
            #   Ident(1) Flags(1) PeerChallenge(16) Reserved(8) NT-Response(24)
            # -> peer_challenge = hex[4:36], nt_response = hex[52:100].
            if len(resp) >= 100 and len(authchal) >= 32:
                peer_challenge = bytes.fromhex(resp[4:36])
                nt_response = resp[52:100]
                challenge8 = hashlib.sha1(  # noqa: S324 - protocol-defined, not for security
                    peer_challenge + bytes.fromhex(authchal[:32]) + self.username.encode()
                ).digest()[:8]
                return f"{self.username}::::{nt_response}:{challenge8.hex()}"

        if self.chap_password and len(self.chap_password) >= 34:
            cid = self.chap_password[:2]
            response = self.chap_password[2:34]
            challenge = (self.chap_challenge or self.authenticator).replace(":", "").lower()
            if response and challenge:
                return f"{response}:{challenge}:{cid}"
        return ""

    @property
    def hash_value(self) -> str:
        """Raw captured auth material (display/forensics).

        For PAP: XOR-encrypted User-Password (requires shared secret).
        For CHAP: the CHAP-Password attribute. The crackable hashcat line is the
        separate ``hashcat_format`` property.
        """
        return self.encrypted_password or self.chap_password


class RADIUSPassiveListener(PySharkListenerBase):
    """Passive RADIUS traffic listener for auth extraction.

    Captures RADIUS authentication to extract:
    - Usernames and realms
    - NAS identifiers
    - Calling-Station-Id (usually client MAC)
    - Authentication results

    Uses PyShark (tshark) for packet dissection with Wireshark's
    RADIUS protocol dissector.

    Usage:
        listener = RADIUSPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for cred in listener.credentials:
            print(f"RADIUS: {cred.username} via {cred.nas_identifier}")
    """

    PROTOCOL_NAME = "radius"
    DISPLAY_FILTER = "radius"
    REQUIRED_LAYERS = ("radius",)
    PROTOCOL_COLUMNS = ("code", "username", "nas", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[RADIUSCredential] = []
        # Track requests by (client, server, identifier) for response correlation
        self._requests: Dict[tuple, RADIUSCredential] = {}

    @staticmethod
    def _get_radius_field(fields: Dict[str, str], field_name: str, default: str = "") -> str:
        """Case-insensitive field lookup for RADIUS.

        EK mode exposes field names like ``radius.User_Name`` while XML mode
        uses ``radius.user_name``.  This helper tries exact match first, then
        falls back to case-insensitive comparison so the listener works in
        both modes.
        """
        val = fields.get(field_name, "")
        if val:
            return val
        # Case-insensitive fallback
        lower = field_name.lower()
        for key, value in fields.items():
            if key.lower() == lower:
                return value
        return default

    def process_packet(self, packet) -> None:
        """Process RADIUS packet using PyShark dissection."""
        if not hasattr(packet, "radius"):
            return

        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)

        # Get RADIUS fields via PyShark
        radius_layer = packet.radius
        fields = self.get_all_fields(radius_layer)

        # Get RADIUS code
        code_str = self._get_radius_field(fields, "radius.code")
        try:
            code = int(code_str)
        except (ValueError, TypeError) as e:
            self.logger.debug(f"RADIUS: code field int parse failed: {e}")
            return

        # Get packet identifier for request/response correlation
        identifier_str = self._get_radius_field(fields, "radius.id", "0")
        try:
            identifier = int(identifier_str)
        except (ValueError, TypeError):
            identifier = 0

        # Get authenticator (hex)
        authenticator = self._get_radius_field(fields, "radius.authenticator")
        # Remove colons if present (PyShark often formats as hex with colons)
        if isinstance(authenticator, str):
            authenticator = authenticator.replace(":", "")

        # Extract Message-Authenticator (HMAC-MD5 integrity, RFC 3579)
        msg_auth = self._get_radius_field(fields, "radius.message_authenticator")
        if isinstance(msg_auth, str):
            msg_auth = msg_auth.replace(":", "")

        # Record interaction with enriched details
        now = datetime.now().isoformat()
        code_names = {
            RADIUS_ACCESS_REQUEST: "Access-Request",
            RADIUS_ACCESS_ACCEPT: "Access-Accept",
            RADIUS_ACCESS_REJECT: "Access-Reject",
            RADIUS_ACCESS_CHALLENGE: "Access-Challenge",
            RADIUS_ACCOUNTING_REQUEST: "Accounting-Request",
            RADIUS_ACCOUNTING_RESPONSE: "Accounting-Response",
        }
        code_name = code_names.get(code, f"Code-{code}")
        direction = (
            "request" if code in (RADIUS_ACCESS_REQUEST, RADIUS_ACCOUNTING_REQUEST) else "response"
        )
        username = self._get_radius_field(fields, "radius.user_name")
        interaction_details: Dict[str, Any] = {
            "code": code,
            "identifier": identifier,
            "username": username,
        }
        if msg_auth:
            interaction_details["message_authenticator"] = msg_auth
        if authenticator:
            interaction_details["authenticator"] = authenticator
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"RADIUS {code_name}",
            interaction_details,
            f"RADIUS {code_name} user={username}" if username else f"RADIUS {code_name}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        if code == RADIUS_ACCESS_REQUEST:
            self._process_access_request(
                fields, authenticator, identifier, src_ip, dst_ip, msg_auth
            )
        elif code in (
            RADIUS_ACCESS_ACCEPT,
            RADIUS_ACCESS_REJECT,
            RADIUS_ACCESS_CHALLENGE,
        ):
            self._process_access_response(code, identifier, src_ip, dst_ip, fields)

    def _process_access_request(
        self,
        fields: Dict[str, str],
        authenticator: str,
        identifier: int,
        client_ip: str,  # NAS
        server_ip: str,  # RADIUS server
        msg_auth: str = "",
    ) -> None:
        """Process RADIUS Access-Request packet."""
        # Extract username from PyShark fields
        # EK mode may expose User_Name (capital), XML mode radius.user_name
        username = self._get_radius_field(fields, "radius.user_name")
        if not username:
            return

        # Extract realm from username (user@realm)
        realm = ""
        if "@" in username:
            parts = username.rsplit("@", 1)
            username = parts[0]
            realm = parts[1]

        # Get NAS info
        nas_identifier = self._get_radius_field(fields, "radius.nas_identifier")
        nas_ip = self._get_radius_field(fields, "radius.nas_ip_address", client_ip)

        # Calling station ID (usually client MAC or phone number)
        calling_station = self._get_radius_field(fields, "radius.calling_station_id")

        # Service type (T1 field: radius.Service_Type)
        service_type_str = self._get_radius_field(fields, "radius.service_type")
        try:
            service_type_num = int(service_type_str)
            service_type = SERVICE_TYPES.get(service_type_num, f"Type-{service_type_num}")
        except (ValueError, TypeError):
            service_type = service_type_str if service_type_str else "Unknown"

        # NAS-Port (T2 field: radius.NAS_Port)
        nas_port = self._get_radius_field(fields, "radius.nas_port")

        # --- PAP: Encrypted password (for offline cracking) ---
        # EK mode uses User_Password_encrypted, XML mode radius.user_password
        encrypted_password = self._get_radius_field(fields, "radius.user_password")
        if not encrypted_password:
            encrypted_password = self._get_radius_field(fields, "radius.user_password_encrypted")
        if isinstance(encrypted_password, str):
            encrypted_password = encrypted_password.replace(":", "")

        # --- CHAP: CHAP-Password (T1 field: radius.CHAP_Password) ---
        # Contains 1-byte CHAP ident + 16-byte MD5 response hash
        chap_password = self._get_radius_field(fields, "radius.chap_password")
        if isinstance(chap_password, str):
            chap_password = chap_password.replace(":", "")

        # CHAP identifier (T2 field: radius.CHAP_Ident)
        chap_ident = self._get_radius_field(fields, "radius.chap_ident")

        # CHAP-Challenge attribute (type 60). When absent, RFC 2865 says the
        # Request-Authenticator IS the challenge -- the property falls back to it.
        chap_challenge = self._get_radius_field(fields, "radius.chap_challenge")
        if isinstance(chap_challenge, str):
            chap_challenge = chap_challenge.replace(":", "")

        # MS-CHAPv2 (Microsoft VSAs, vendor 311) -> hashcat 5500.
        mschap_challenge = self._get_radius_field(fields, "radius.ms_chap_challenge")
        if isinstance(mschap_challenge, str):
            mschap_challenge = mschap_challenge.replace(":", "")
        mschap2_response = self._get_radius_field(fields, "radius.ms_chap2_response")
        if isinstance(mschap2_response, str):
            mschap2_response = mschap2_response.replace(":", "")

        cred = RADIUSCredential(
            username=username,
            realm=realm,
            nas_identifier=nas_identifier,
            nas_ip=nas_ip if isinstance(nas_ip, str) else "",
            calling_station=calling_station,
            service_type=service_type,
            authenticator=authenticator,
            encrypted_password=encrypted_password,
            client_ip=client_ip,
            server_ip=server_ip,
            timestamp=datetime.now().isoformat(),
            chap_password=chap_password,
            chap_ident=chap_ident,
            chap_challenge=chap_challenge,
            message_authenticator=msg_auth,
            nas_port=nas_port,
            mschap_challenge=mschap_challenge,
            mschap2_response=mschap2_response,
        )

        # Store for response correlation
        req_key = (client_ip, server_ip, identifier)
        self._requests[req_key] = cred

        if not self._is_duplicate(cred):
            self.credentials.append(cred)
            self.logger.info(
                f"RADIUS: {username}{'@' + realm if realm else ''} "
                f"via {nas_identifier or client_ip}"
            )
            self._update_devices(cred)

    def _process_access_response(
        self,
        code: int,
        identifier: int,
        server_ip: str,
        client_ip: str,
        fields: Optional[Dict[str, str]] = None,
    ) -> None:
        """Process RADIUS Access-Accept/Reject/Challenge.

        Extracts Filter-Id (T1) and Service-Type from Accept/Challenge
        responses and updates the correlated credential.
        """
        # Find matching request
        req_key = (client_ip, server_ip, identifier)
        cred = self._requests.get(req_key)

        if cred:
            if code == RADIUS_ACCESS_ACCEPT:
                cred.auth_result = "accept"
            elif code == RADIUS_ACCESS_REJECT:
                cred.auth_result = "reject"
            elif code == RADIUS_ACCESS_CHALLENGE:
                cred.auth_result = "challenge"

            # Extract Filter-Id from response (T1: access policy indicator)
            if fields:
                filter_id = self._get_radius_field(fields, "radius.filter_id")
                if filter_id:
                    cred.filter_id = filter_id

                # Service-Type in response may provide info absent from request
                svc = self._get_radius_field(fields, "radius.service_type")
                if svc and (not cred.service_type or cred.service_type == "Unknown"):
                    try:
                        svc_num = int(svc)
                        cred.service_type = SERVICE_TYPES.get(svc_num, f"Type-{svc_num}")
                    except (ValueError, TypeError) as e:
                        self.logger.debug(f"Failed to get svc_num: {e}")

            self.logger.debug(f"RADIUS: {cred.username} -> {cred.auth_result}")

    def _is_duplicate(self, cred: RADIUSCredential) -> bool:
        """Check for duplicate credential."""
        for c in self.credentials:
            if (
                c.username == cred.username
                and c.realm == cred.realm
                and c.server_ip == cred.server_ip
                and c.authenticator == cred.authenticator
            ):
                return True
        return False

    def _update_devices(self, cred: RADIUSCredential) -> None:
        """Update device entries."""
        # RADIUS server
        if is_valid_discovered_ip(cred.server_ip):
            key = f"radius-server:{cred.server_ip}"

            device, is_new = self._ensure_device(
                key,
                cred.server_ip,
                name="RADIUS Server",
                device_type="RADIUS Server",
            )
            if is_new:
                device.radius_passive_data = {
                    "role": "server",
                    "realms": [cred.realm] if cred.realm else [],
                    "nas_clients": [cred.client_ip],
                    "auth_count": 1,
                    "protocol": "RADIUS/UDP",
                }
            else:
                if device.radius_passive_data:
                    if cred.realm and cred.realm not in device.radius_passive_data.get(
                        "realms", []
                    ):
                        device.radius_passive_data.setdefault("realms", []).append(cred.realm)
                    if cred.client_ip not in device.radius_passive_data.get("nas_clients", []):
                        device.radius_passive_data.setdefault("nas_clients", []).append(
                            cred.client_ip
                        )
                    device.radius_passive_data["auth_count"] = (
                        device.radius_passive_data.get("auth_count", 0) + 1
                    )
        # NAS (RADIUS client)
        if is_valid_discovered_ip(cred.client_ip):
            key = f"radius-nas:{cred.client_ip}"

            device, is_new = self._ensure_device(
                key,
                cred.client_ip,
                name=cred.nas_identifier or "Network Access Server",
                device_type="NAS/RADIUS Client",
            )
            if is_new:
                device.radius_passive_data = {
                    "role": "nas",
                    "nas_identifier": cred.nas_identifier,
                    "radius_server": cred.server_ip,
                    "protocol": "RADIUS/UDP",
                }

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format interaction for the operations table."""
        d = ix.details
        code_name = str(ix.operation).replace("RADIUS ", "") if ix.operation else ""
        username = str(d.get("username", ""))
        # NAS is the client: src for requests, dst for responses
        nas = str(ix.src_ip if ix.direction == "request" else ix.dst_ip)
        detail = str(ix.summary) if ix.summary else code_name
        return [code_name, username, nas, detail]

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of extracted credentials.

        Uses canonical key names for the base class harvest()
        credential table builder.
        """
        result = []
        for c in self.credentials:
            entry: Dict[str, Any] = {
                "protocol": "RADIUS",
                "credential_type": "hash",
                "auth_method": c.auth_method,
                "username": c.username,
                "server_ip": c.server_ip,
                "client_ip": c.client_ip,
                "realm": c.realm,
                "nas": c.nas_identifier or c.client_ip,
                "calling_station": c.calling_station,
                "service_type": c.service_type,
                "result": c.auth_result,
                "timestamp": c.timestamp,
            }
            if c.chap_password:
                entry["chap_password"] = c.chap_password
            if c.chap_ident:
                entry["chap_ident"] = c.chap_ident
            if c.message_authenticator:
                entry["message_authenticator"] = c.message_authenticator
            if c.filter_id:
                entry["filter_id"] = c.filter_id
            if c.nas_port:
                entry["nas_port"] = c.nas_port
            result.append(entry)
        return result

    def get_hashcat_hashes(self) -> List[str]:
        """Crackable RADIUS hashes: CHAP-Password (4800) and MS-CHAPv2 (5500).

        Delegates to the per-credential property. PAP (User-Password) is not
        crackable without the shared secret, so it yields "" and is skipped.
        """
        return [c.hashcat_format for c in self.credentials if c.hashcat_format]

    def get_users_by_realm(self) -> Dict[str, List[str]]:
        """Get users grouped by realm."""
        realms: Dict[str, List[str]] = {}
        for c in self.credentials:
            realm = c.realm or "(none)"
            if realm not in realms:
                realms[realm] = []
            if c.username not in realms[realm]:
                realms[realm].append(c.username)
        return realms
