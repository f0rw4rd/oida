"""
LDAP Passive Listener for credential and operations extraction.

Passively captures LDAP traffic to extract:
- Simple Bind credentials (username/password in plaintext)
- SASL authentication mechanism detection (GSSAPI, DIGEST-MD5, NTLM, etc.)
- Bind DN (Distinguished Name)
- Authentication result codes and error messages
- Search operations (base DN, scope, filter)
- Write operations (modify, add, delete, modDN) with alerts
- Password change operations (RFC 3062 extended operations)
- Unbind / session teardown

Uses PyShark (tshark) for LDAP dissection, providing access to Wireshark's
LDAP protocol dissector for clean field extraction.

Key PyShark LDAP fields:
- ldap.bindRequest_element: Present for Bind requests
- ldap.bindResponse_element: Present for Bind responses
- ldap.name: Bind DN (Distinguished Name)
- ldap.simple: Simple authentication password (plaintext)
- ldap.resultCode: Authentication result (0 = success)
- ldap.version: LDAP protocol version
- ldap.messageID: Message correlation ID
- ldap.mechanism: SASL mechanism name
- ldap.searchRequest_element: Present for Search requests
- ldap.baseObject: Search base DN
- ldap.scope: Search scope (0=base, 1=one, 2=sub)
- ldap.filter: Search filter expression
- ldap.modifyRequest_element: Present for Modify requests
- ldap.addRequest_element: Present for Add requests
- ldap.delRequest: DN of entry to delete
- ldap.modDNRequest_element: Present for ModifyDN requests
- ldap.errorMessage: Server error message
- ldap.oldPasswd / ldap.newPasswd: Password change data (RFC 3062)
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# LDAP ports
LDAP_PORT = 389
LDAPS_PORT = 636
LDAP_GC_PORT = 3268  # Global Catalog
LDAPS_GC_PORT = 3269  # Global Catalog over SSL

LDAP_PORTS = {LDAP_PORT, LDAPS_PORT, LDAP_GC_PORT, LDAPS_GC_PORT}

# LDAP result codes
LDAP_RESULT_CODES = {
    0: "success",
    1: "operationsError",
    2: "protocolError",
    3: "timeLimitExceeded",
    4: "sizeLimitExceeded",
    7: "authMethodNotSupported",
    8: "strongerAuthRequired",
    16: "noSuchAttribute",
    17: "undefinedAttributeType",
    32: "noSuchObject",
    34: "invalidDNSyntax",
    48: "inappropriateAuthentication",
    49: "invalidCredentials",
    50: "insufficientAccessRights",
    51: "busy",
    52: "unavailable",
    53: "unwillingToPerform",
    65: "objectClassViolation",
    68: "entryAlreadyExists",
    80: "other",
}
LDAP_SUCCESS = 0
LDAP_INVALID_CREDENTIALS = 49

# LDAP search scope values
LDAP_SCOPE_NAMES = {
    "0": "base",
    "1": "one",
    "2": "sub",
}

# LDAP write operation protocolOp values and element field names
LDAP_WRITE_OPS = {
    "ldap.modifyRequest_element": "Modify",
    "ldap.addRequest_element": "Add",
    "ldap.delRequest": "Delete",
    "ldap.modDNRequest_element": "ModifyDN",
}

# Password Modify Extended Operation OID (RFC 3062)
PASSWD_MODIFY_OID = "1.3.6.1.4.1.4203.1.11.1"

# StartTLS Extended Operation OID (RFC 4511)
STARTTLS_OID = "1.3.6.1.4.6.1.1"

# LDAP authentication choice values (ldap.authentication)
LDAP_AUTH_CHOICES = {
    "0": "simple",
    "3": "sasl",
    "10": "sicily_negotiate",
    "11": "sicily_initial",
    "12": "sicily_subsequent",
}

# T1 tshark fields that this listener extracts.
# Used by the audit tool to measure field coverage.
_T1_FIELDS = (
    "ldap.messageID",
    "ldap.errorMessage",
    "ldap.version",
    "ldap.name",
    "ldap.authentication",
    "ldap.bindResponse_resultCode",
    "ldap.resultCode",
    "ldap.credentials",
    "ldap.requestName",
    "ldap.extendedResponse_resultCode",
    "ldap.maxBytes",
)


@dataclass
class LDAPCredential:
    """Extracted LDAP credential."""

    username: str  # Bind DN (Distinguished Name)
    password: str  # Simple bind password (plaintext)
    server_ip: str
    client_ip: str
    success: Optional[bool] = None  # True if result code 0, False otherwise
    timestamp: str = ""
    server_port: int = LDAP_PORT
    ldap_version: int = 3
    credential_type: str = "plaintext"

    @property
    def auth_method(self) -> str:
        """Return auth method for scanner credential loop."""
        return "Simple Bind"


@dataclass
class LDAPSession:
    """Track LDAP session state for credential extraction."""

    client_ip: str
    server_ip: str
    server_port: int = LDAP_PORT
    bind_dn: str = ""
    password: str = ""
    ldap_version: int = 3
    message_id: int = 0
    state: str = "init"  # init, bind_sent, complete


class LDAPPassiveListener(PySharkListenerBase):
    """Passive LDAP traffic listener for credential and operations extraction.

    Captures LDAP traffic to extract:
    - Simple Bind credentials (plaintext password)
    - SASL authentication mechanism detection
    - Bind DN (Distinguished Name)
    - Authentication success/failure status
    - Search operations (base DN, scope, filter)
    - Write operations (modify, add, delete) with security alerts
    - Password change operations (RFC 3062)

    Uses PyShark (tshark) for LDAP protocol dissection.

    Usage:
        # Live capture
        listener = LDAPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access extracted credentials
        for cred in listener.credentials:
            print(f"{cred.username}:{cred.password} @ {cred.server_ip}")

    Data structure stored in device.ldap_passive_data:
        {
            "role": "server" | "client",
            "credentials": [...],
            "bind_count": 5,
            "search_count": 12,
            "write_count": 2,
            "sasl_mechanisms": ["GSSAPI"],
            "protocol": "LDAP/TCP",
        }
    """

    PROTOCOL_NAME = "ldap"
    DISPLAY_FILTER = "ldap"
    REQUIRED_LAYERS = ("ldap",)

    PROTOCOL_COLUMNS = ("op", "details", "result")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize LDAP passive listener.

        Args:
            interface: Network interface to capture on
            timeout: Capture timeout in seconds
            nxc_logger: Optional NXC-style logger
        """
        super().__init__(interface, timeout, nxc_logger)
        # Track LDAP sessions by (client_ip, server_ip, message_id) tuple
        self._sessions: Dict[Tuple[str, str, int], LDAPSession] = {}

        # Extracted credentials
        self.credentials: List[LDAPCredential] = []

        # Counters for server/client device enrichment
        self._server_stats: Dict[str, Dict[str, Any]] = {}  # server_ip -> stats
        self._client_stats: Dict[str, Dict[str, Any]] = {}  # client_ip -> stats

        # Write operations for alerting
        self._write_ops: List[Dict[str, Any]] = []

    def process_packet(self, packet) -> None:
        """Process LDAP packet and extract credentials using PyShark."""
        if not hasattr(packet, "ldap"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        src_port, dst_port = self.get_port_info(packet)
        stream_id = self.get_stream_id(packet)

        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        # Get MAC addresses for device enrichment
        src_mac, dst_mac = self.get_mac_info(packet)

        ldap_layer = packet.ldap

        # Handle multi-PDU TCP segments: EK mode returns _fields_dict as a
        # list when multiple LDAP messages are in one TCP segment.
        fd = getattr(ldap_layer, "_fields_dict", None)
        if isinstance(fd, list):
            for sub_fields_raw in fd:
                if not isinstance(sub_fields_raw, dict):
                    continue
                # Normalise keys: strip the "ldap_ldap_" EK prefix to match
                # the "ldap." convention used by get_all_fields().
                sub_fields: Dict[str, str] = {}
                for k, v in sub_fields_raw.items():
                    if k.startswith("ldap_ldap_"):
                        short = "ldap." + k[len("ldap_ldap_") :]
                    elif k == "text":
                        # 'text' key is used as-is
                        sub_fields[k] = v
                        continue
                    else:
                        short = k
                    sub_fields[short] = "" if v is None else str(v) if not isinstance(v, str) else v
                self._process_ldap_fields(
                    sub_fields,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    src_mac,
                    dst_mac,
                    flow_id,
                    stream_id,
                    ldap_layer,
                )
            return

        fields = self.get_all_fields(ldap_layer)

        self._process_ldap_fields(
            fields,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            src_mac,
            dst_mac,
            flow_id,
            stream_id,
            ldap_layer,
        )

    def _process_ldap_fields(
        self,
        fields: Dict[str, str],
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        stream_id: str,
        ldap_layer: Any,
    ) -> None:
        """Process a single set of LDAP fields (one LDAP message).

        Factored out of process_packet() to support multi-PDU segments
        where a single TCP segment contains multiple LDAP messages.
        """
        now = datetime.now().isoformat()

        # Determine message type from fields
        if self._is_bind_request(fields):
            self._handle_bind_request(
                now,
                src_ip,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                fields,
                flow_id,
                src_port=src_port,
                stream_id=stream_id,
            )
        elif self._is_bind_response(fields):
            self._handle_bind_response(
                now,
                src_ip,
                dst_ip,
                src_port,
                src_mac,
                dst_mac,
                fields,
                flow_id,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif self._is_search_request(fields):
            self._handle_search_request(
                now,
                src_ip,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                fields,
                flow_id,
                ldap_layer,
                src_port=src_port,
                stream_id=stream_id,
            )
        elif self._is_search_result(fields):
            self._handle_search_result(
                now,
                src_ip,
                dst_ip,
                src_port,
                fields,
                flow_id,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif self._is_write_operation(fields):
            self._handle_write_operation(
                now,
                src_ip,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                fields,
                flow_id,
                src_port=src_port,
                stream_id=stream_id,
            )
        elif self._is_write_response(fields):
            self._handle_write_response(
                now,
                src_ip,
                dst_ip,
                src_port,
                fields,
                flow_id,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif self._is_extended_request(fields):
            self._handle_extended_request(
                now,
                src_ip,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                fields,
                flow_id,
                src_port=src_port,
                stream_id=stream_id,
            )
        elif self._is_extended_response(fields):
            self._handle_extended_response(
                now,
                src_ip,
                dst_ip,
                src_port,
                fields,
                flow_id,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif "ldap.unbindRequest_element" in fields:
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "Unbind",
                {"message_id": fields.get("ldap.messageID", "?")},
                "LDAP Unbind",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

    # -------------------------------------------------------------------------
    # Message type detection
    # -------------------------------------------------------------------------

    def _is_bind_request(self, fields: Dict[str, str]) -> bool:
        if "ldap.bindRequest_element" in fields:
            return True
        if fields.get("ldap.protocolOp") == "0":
            return True
        return False

    def _is_bind_response(self, fields: Dict[str, str]) -> bool:
        if "ldap.bindResponse_element" in fields:
            return True
        if fields.get("ldap.protocolOp") == "1":
            return True
        return False

    def _is_search_request(self, fields: Dict[str, str]) -> bool:
        if "ldap.searchRequest_element" in fields:
            return True
        if fields.get("ldap.protocolOp") == "3":
            return True
        return False

    def _is_search_result(self, fields: Dict[str, str]) -> bool:
        return "ldap.searchResEntry_element" in fields or "ldap.searchResDone_element" in fields

    def _is_write_operation(self, fields: Dict[str, str]) -> bool:
        return any(key in fields for key in LDAP_WRITE_OPS)

    def _is_write_response(self, fields: Dict[str, str]) -> bool:
        return any(
            key in fields
            for key in (
                "ldap.modifyResponse_element",
                "ldap.addResponse_element",
                "ldap.delResponse_element",
                "ldap.modDNResponse_element",
            )
        )

    def _is_extended_request(self, fields: Dict[str, str]) -> bool:
        return "ldap.extendedReq_element" in fields

    def _is_extended_response(self, fields: Dict[str, str]) -> bool:
        return "ldap.extendedResp_element" in fields

    # -------------------------------------------------------------------------
    # Bind request/response handling
    # -------------------------------------------------------------------------

    def _handle_bind_request(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        fields: Dict[str, str],
        flow_id: str,
        *,
        src_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle LDAP Bind Request -- extract credentials and record interaction."""
        bind_dn = (
            fields.get("ldap.name")
            or fields.get("ldap.bindRequest.name")
            or fields.get("ldap.bindDN")
            or ""
        )
        if not bind_dn:
            bind_dn = "?"
            self.logger.debug(f"Missing bind DN in bind request from {src_ip} -> {dst_ip}")

        # Detect auth method
        sasl_mechanism = fields.get("ldap.mechanism", "")
        password = fields.get("ldap.simple") or fields.get("ldap.authentication.simple") or ""

        # Extract authentication choice enum (0=simple, 3=sasl, 10+=sicily)
        auth_choice_raw = fields.get("ldap.authentication", "")
        auth_choice_name = LDAP_AUTH_CHOICES.get(auth_choice_raw, auth_choice_raw)

        is_sasl = bool(
            "ldap.sasl_element" in fields
            or "ldap.sasl" in fields
            or "ldap.authentication.sasl" in fields
            or sasl_mechanism
        )

        # Extract SASL credentials bytes (present for GSSAPI/DIGEST-MD5/NTLM binds)
        sasl_creds = fields.get("ldap.credentials", "")

        # Build details for interaction
        msg_id = fields.get("ldap.messageID", "?")
        version_str = fields.get("ldap.version", "3")
        details: Dict[str, Any] = {
            "bind_dn": bind_dn,
            "message_id": msg_id,
            "version": version_str,
            "auth_choice": auth_choice_name or auth_choice_raw,
        }

        if is_sasl:
            mechanism = sasl_mechanism or "?"
            details["auth_type"] = f"SASL/{mechanism}"
            details["sasl_mechanism"] = mechanism
            if sasl_creds:
                details["sasl_credentials"] = "present"
            summary = f"Bind SASL/{mechanism} DN={bind_dn}"
            # Track SASL mechanism on server
            self._get_server_stats(dst_ip).setdefault("sasl_mechanisms", set()).add(mechanism)
            self.logger.debug(
                f"LDAP: SASL bind ({mechanism}) from {src_ip} to {dst_ip} DN={bind_dn}"
            )
        elif password:
            details["auth_type"] = "Simple"
            summary = f"Bind Simple DN={bind_dn}"
        else:
            details["auth_type"] = "Anonymous"
            summary = "Bind Anonymous"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "Bind",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Increment bind count on server
        stats = self._get_server_stats(dst_ip)
        stats["bind_count"] = stats.get("bind_count", 0) + 1

        # Only extract credentials for simple bind with password
        if password and not is_sasl:
            self._process_bind_request(src_ip, dst_ip, dst_port, src_mac, dst_mac, fields)
        else:
            # Still track devices even for SASL/anonymous binds
            self._update_client_device(src_ip, dst_ip, src_mac)
            self._update_server_device(dst_ip, dst_port, dst_mac)

    def _handle_bind_response(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        src_mac: str,
        dst_mac: str,
        fields: Dict[str, str],
        flow_id: str,
        *,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle LDAP Bind Response -- update credential success and record interaction."""
        result_code_str = fields.get("ldap.resultCode", "")
        if not result_code_str:
            result_code_str = fields.get("ldap.bindResponse_resultCode", "")
        result_code = self._parse_result_code(result_code_str)
        result_name = LDAP_RESULT_CODES.get(result_code, f"code={result_code}")

        error_msg = fields.get("ldap.errorMessage", "")
        matched_dn = fields.get("ldap.matchedDN", "") or fields.get(
            "ldap.bindResponse_matchedDN", ""
        )

        details: Dict[str, Any] = {
            "result_code": result_code,
            "result_name": result_name,
            "message_id": fields.get("ldap.messageID", "?"),
        }
        if error_msg:
            details["error_message"] = error_msg
        if matched_dn:
            details["matched_dn"] = matched_dn

        # Check for SASL server credentials (server challenge/response)
        server_sasl = fields.get("ldap.serverSaslCreds", "")
        if server_sasl:
            details["server_sasl_creds"] = "present"

        summary = f"Bind Response {result_name}"
        if error_msg:
            summary += f" ({error_msg})"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "Bind Response",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Update credential success (server -> client, so client=dst, server=src)
        self._process_bind_response(dst_ip, src_ip, src_port, fields)

    # -------------------------------------------------------------------------
    # Search request/result handling
    # -------------------------------------------------------------------------

    def _handle_search_request(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        fields: Dict[str, str],
        flow_id: str,
        ldap_layer: Any = None,
        *,
        src_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle LDAP Search Request -- record who searches what."""
        base_dn = fields.get("ldap.baseObject", "")
        if not base_dn:
            base_dn = "?"
            self.logger.debug(f"Missing baseObject in search from {src_ip} -> {dst_ip}")

        scope_raw = fields.get("ldap.scope", "?")
        scope_name = LDAP_SCOPE_NAMES.get(scope_raw, scope_raw)

        # Extract human-readable filter from the layer's text attribute
        # (tshark puts "Filter: (...)" in the text field)
        search_filter = ""
        if ldap_layer is not None:
            text_val = getattr(ldap_layer, "text", None)
            if text_val:
                texts = text_val if isinstance(text_val, list) else [text_val]
                for t in texts:
                    t = str(t)
                    if t.startswith("Filter: ") and "(" in t:
                        search_filter = t[8:]  # strip "Filter: " prefix
                        break
        if not search_filter:
            # Fall back to component fields
            present = fields.get("ldap.present", "")
            attr_desc = fields.get("ldap.attributeDesc", "")
            assert_val = fields.get("ldap.assertionValue", "")
            if present:
                search_filter = f"({present}=*)"
            elif attr_desc and assert_val:
                search_filter = f"({attr_desc}={assert_val})"
            else:
                search_filter = fields.get("ldap.filter", "?")
        if not search_filter:
            search_filter = "?"
            self.logger.debug(f"Missing filter in search from {src_ip} -> {dst_ip}")

        size_limit = fields.get("ldap.sizeLimit", "")
        time_limit = fields.get("ldap.timeLimit", "")

        # Requested attributes
        attrs = fields.get("ldap.AttributeDescription", "")

        # DirSync control maxBytes (ldap.maxBytes) -- present when
        # Active Directory DirSync replication control is used
        max_bytes = fields.get("ldap.maxBytes", "")

        details: Dict[str, Any] = {
            "base_dn": base_dn,
            "scope": scope_name,
            "filter": search_filter,
            "message_id": fields.get("ldap.messageID", "?"),
        }
        if size_limit:
            details["size_limit"] = size_limit
        if time_limit:
            details["time_limit"] = time_limit
        if attrs:
            details["attributes"] = attrs
        if max_bytes:
            details["max_bytes"] = max_bytes

        summary = f"Search base={base_dn} scope={scope_name} filter={search_filter}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "Search",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Increment search count on server
        stats = self._get_server_stats(dst_ip)
        stats["search_count"] = stats.get("search_count", 0) + 1

        # Track devices
        self._update_client_device(src_ip, dst_ip, src_mac)
        self._update_server_device(dst_ip, dst_port, dst_mac)

    def _handle_search_result(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        fields: Dict[str, str],
        flow_id: str,
        *,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle LDAP Search Result Entry / Done."""
        if "ldap.searchResDone_element" in fields:
            result_code_str = fields.get("ldap.resultCode", "?")
            result_code = self._parse_result_code(result_code_str)
            result_name = LDAP_RESULT_CODES.get(result_code, f"code={result_code}")
            error_msg = fields.get("ldap.errorMessage", "")

            details: Dict[str, Any] = {
                "result_code": result_code,
                "result_name": result_name,
                "message_id": fields.get("ldap.messageID", "?"),
            }
            if error_msg:
                details["error_message"] = error_msg

            summary = f"Search Done {result_name}"
            if error_msg:
                summary += f" ({error_msg})"

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "Search Done",
                details,
                summary,
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif "ldap.searchResEntry_element" in fields:
            object_name = fields.get("ldap.objectName", "?")
            details = {
                "object_name": object_name,
                "message_id": fields.get("ldap.messageID", "?"),
            }
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "Search Entry",
                details,
                f"Search Entry: {object_name}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

    # -------------------------------------------------------------------------
    # Write operation handling (modify, add, delete, modDN)
    # -------------------------------------------------------------------------

    def _handle_write_operation(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        fields: Dict[str, str],
        flow_id: str,
        *,
        src_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle LDAP write operations -- record and alert."""
        op_name = "?"
        target_dn = "?"
        for field_key, name in LDAP_WRITE_OPS.items():
            if field_key in fields:
                op_name = name
                break

        if op_name == "Delete":
            target_dn = fields.get("ldap.delRequest", "?")
        elif op_name == "Modify":
            target_dn = fields.get("ldap.object", "") or fields.get("ldap.entry", "") or "?"
        elif op_name == "Add":
            target_dn = fields.get("ldap.entry", "") or fields.get("ldap.object", "") or "?"
        elif op_name == "ModifyDN":
            target_dn = fields.get("ldap.entry", "") or "?"
            new_rdn = fields.get("ldap.newrdn", "")
            if new_rdn:
                target_dn = f"{target_dn} -> {new_rdn}"

        if target_dn == "?":
            self.logger.debug(f"Missing target DN in LDAP {op_name} from {src_ip} -> {dst_ip}")

        details: Dict[str, Any] = {
            "operation": op_name,
            "target_dn": target_dn,
            "message_id": fields.get("ldap.messageID", "?"),
        }

        summary = f"{op_name} {target_dn}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            op_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track write operation for alerts
        self._write_ops.append(
            {
                "client": src_ip,
                "server": dst_ip,
                "operation": op_name,
                "target_dn": target_dn,
                "timestamp": now,
            }
        )

        # Increment write count on server
        stats = self._get_server_stats(dst_ip)
        stats["write_count"] = stats.get("write_count", 0) + 1

        # Track devices
        self._update_client_device(src_ip, dst_ip, src_mac)
        self._update_server_device(dst_ip, dst_port, dst_mac)

    def _handle_write_response(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        fields: Dict[str, str],
        flow_id: str,
        *,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle LDAP write response (modify/add/delete/modDN response)."""
        # Determine which response type
        op_name = "Write"
        for key, name in {
            "ldap.modifyResponse_element": "Modify",
            "ldap.addResponse_element": "Add",
            "ldap.delResponse_element": "Delete",
            "ldap.modDNResponse_element": "ModifyDN",
        }.items():
            if key in fields:
                op_name = name
                break

        result_code_str = fields.get("ldap.resultCode", "?")
        result_code = self._parse_result_code(result_code_str)
        result_name = LDAP_RESULT_CODES.get(result_code, f"code={result_code}")
        error_msg = fields.get("ldap.errorMessage", "")

        details: Dict[str, Any] = {
            "result_code": result_code,
            "result_name": result_name,
            "message_id": fields.get("ldap.messageID", "?"),
        }
        if error_msg:
            details["error_message"] = error_msg

        summary = f"{op_name} Response {result_name}"
        if error_msg:
            summary += f" ({error_msg})"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            f"{op_name} Response",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    # -------------------------------------------------------------------------
    # Extended operation handling (password change, etc.)
    # -------------------------------------------------------------------------

    def _handle_extended_request(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        fields: Dict[str, str],
        flow_id: str,
        *,
        src_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle LDAP Extended Request (e.g., password change)."""
        request_name = fields.get("ldap.requestName", "?")
        if not request_name or request_name == "?":
            self.logger.debug(f"Missing requestName in extended request from {src_ip} -> {dst_ip}")

        details: Dict[str, Any] = {
            "request_oid": request_name,
            "message_id": fields.get("ldap.messageID", "?"),
        }

        # Check for Password Modify Extended Operation (RFC 3062)
        if request_name == PASSWD_MODIFY_OID:
            old_passwd = fields.get("ldap.oldPasswd", "")
            new_passwd = fields.get("ldap.newPasswd", "")
            user_identity = fields.get("ldap.userIdentity", "")
            details["operation"] = "PasswordModify"
            if user_identity:
                details["user_identity"] = user_identity
            if old_passwd:
                details["old_password"] = "present"
            if new_passwd:
                details["new_password"] = "present"
            summary = "ExtendedOp: Password Modify"
            if user_identity:
                summary += f" user={user_identity}"

            # This is also a write operation
            self._write_ops.append(
                {
                    "client": src_ip,
                    "server": dst_ip,
                    "operation": "PasswordModify",
                    "target_dn": user_identity or "?",
                    "timestamp": now,
                }
            )
            stats = self._get_server_stats(dst_ip)
            stats["write_count"] = stats.get("write_count", 0) + 1
        else:
            summary = f"ExtendedOp OID={request_name}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "Extended",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track devices
        self._update_client_device(src_ip, dst_ip, src_mac)
        self._update_server_device(dst_ip, dst_port, dst_mac)

    def _handle_extended_response(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        fields: Dict[str, str],
        flow_id: str,
        *,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle LDAP Extended Response (e.g., StartTLS result)."""
        # Use extendedResponse_resultCode (specific) before generic resultCode
        result_code_str = fields.get("ldap.extendedResponse_resultCode", "")
        if not result_code_str:
            result_code_str = fields.get("ldap.resultCode", "?")
        result_code = self._parse_result_code(result_code_str)
        result_name = LDAP_RESULT_CODES.get(result_code, f"code={result_code}")

        error_msg = fields.get("ldap.errorMessage", "")
        response_name = fields.get("ldap.responseName", "")

        details: Dict[str, Any] = {
            "result_code": result_code,
            "result_name": result_name,
            "message_id": fields.get("ldap.messageID", "?"),
        }
        if error_msg:
            details["error_message"] = error_msg
        if response_name:
            details["response_oid"] = response_name

        summary = f"Extended Response {result_name}"
        if error_msg:
            summary += f" ({error_msg})"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "Extended Response",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    # -------------------------------------------------------------------------
    # Credential extraction (simple bind only)
    # -------------------------------------------------------------------------

    def _process_bind_request(
        self,
        client_ip: str,
        server_ip: str,
        server_port: int,
        client_mac: str,
        server_mac: str,
        fields: Dict[str, str],
    ) -> None:
        """Process LDAP Bind Request and extract credentials."""
        message_id_str = fields.get("ldap.messageID", "0")
        try:
            message_id = int(message_id_str)
        except (ValueError, TypeError):
            message_id = 0

        bind_dn = (
            fields.get("ldap.name")
            or fields.get("ldap.bindRequest.name")
            or fields.get("ldap.bindDN")
            or ""
        )
        if not bind_dn:
            bind_dn = "?"
            self.logger.debug(f"Missing bind DN in credential extraction from {client_ip}")

        password = fields.get("ldap.simple") or fields.get("ldap.authentication.simple") or ""

        # Skip if no password
        if not password:
            self.logger.debug(f"LDAP: No simple auth password in bind request from {client_ip}")
            return

        version_str = fields.get("ldap.version", "3")
        try:
            ldap_version = int(version_str)
        except (ValueError, TypeError):
            ldap_version = 3

        # Create/update session
        session = self._get_session(client_ip, server_ip, message_id, server_port)
        session.bind_dn = bind_dn
        session.password = password
        session.ldap_version = ldap_version
        session.state = "bind_sent"

        self.logger.debug(
            f"LDAP: Bind request from {client_ip} to {server_ip}:{server_port} DN={session.bind_dn}"
        )

        # Record credential immediately (success will be updated by response)
        self._record_credential(session, success=None)

        # Update device tracking
        self._update_client_device(client_ip, server_ip, client_mac)
        self._update_server_device(server_ip, server_port, server_mac)

    def _process_bind_response(
        self, client_ip: str, server_ip: str, server_port: int, fields: Dict[str, str]
    ) -> None:
        """Process LDAP Bind Response to update credential success status."""
        message_id_str = fields.get("ldap.messageID", "0")
        try:
            message_id = int(message_id_str)
        except (ValueError, TypeError):
            message_id = 0

        result_code_str = fields.get("ldap.resultCode", "")
        if not result_code_str:
            result_code_str = fields.get("ldap.bindResponse_resultCode", "")
        result_code = self._parse_result_code(result_code_str)

        # Find matching session
        key = (client_ip, server_ip, message_id)
        if key not in self._sessions:
            return

        session = self._sessions[key]
        success = result_code == LDAP_SUCCESS

        self.logger.debug(
            f"LDAP: Bind response from {server_ip}:{server_port} to {client_ip} "
            f"result_code={result_code} (success={success})"
        )

        # Update credential with success status
        self._update_credential_success(session, success)
        session.state = "complete"

    # -------------------------------------------------------------------------
    # Interaction table formatting
    # -------------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format a single LDAP interaction as protocol-specific table columns.

        Columns: Op, Details, Result
        """
        d = ix.details
        op = ix.operation

        # Build details string based on operation type
        if op == "Bind":
            auth_type = d.get("auth_type", "?")
            bind_dn = d.get("bind_dn", "?")
            detail = f"{auth_type} DN={bind_dn}"
        elif op == "Bind Response":
            detail = d.get("result_name", "?")
            err = d.get("error_message", "")
            if err:
                detail += f" ({err})"
        elif op == "Search":
            base = d.get("base_dn", "?")
            scope = d.get("scope", "?")
            filt = d.get("filter", "?")
            detail = f"base={base} scope={scope} filter={filt}"
        elif op == "Search Done":
            detail = d.get("result_name", "?")
            err = d.get("error_message", "")
            if err:
                detail += f" ({err})"
        elif op == "Search Entry":
            detail = d.get("object_name", "?")
        elif op in ("Modify", "Add", "Delete", "ModifyDN"):
            target = d.get("target_dn", "?")
            detail = target
        elif op.endswith(" Response"):
            detail = d.get("result_name", "?")
            err = d.get("error_message", "")
            if err:
                detail += f" ({err})"
        elif op == "Extended":
            oid = d.get("request_oid", "?")
            ext_op = d.get("operation", "")
            detail = ext_op if ext_op else f"OID={oid}"
        elif op == "Unbind":
            detail = ""
        else:
            detail = ix.summary or "?"

        # Result column: show result code for responses, empty for requests
        result = ""
        if ix.direction == "response":
            rc = d.get("result_code")
            rn = d.get("result_name", "")
            if rc is not None:
                result = rn if rn else str(rc)
            err = d.get("error_message", "")
            if err and not rn:
                result = err

        return [op, detail, result]

    # -------------------------------------------------------------------------
    # Helper methods
    # -------------------------------------------------------------------------

    def _parse_result_code(self, result_code_str: str) -> int:
        """Parse LDAP result code from tshark string."""
        if not result_code_str:
            return -1
        try:
            return int(result_code_str)
        except (ValueError, TypeError):
            # tshark may show enum strings like "success (0)"
            lower = result_code_str.lower()
            if "success" in lower:
                return LDAP_SUCCESS
            elif "invalidcredentials" in lower:
                return LDAP_INVALID_CREDENTIALS
            elif "nosuchobject" in lower:
                return 32
            elif "insufficientaccessrights" in lower:
                return 50
            return -1

    def _get_server_stats(self, server_ip: str) -> Dict[str, Any]:
        """Get or create stats dict for a server IP."""
        if server_ip not in self._server_stats:
            self._server_stats[server_ip] = {
                "bind_count": 0,
                "search_count": 0,
                "write_count": 0,
                "sasl_mechanisms": set(),
            }
        return self._server_stats[server_ip]

    def _get_session(
        self,
        client_ip: str,
        server_ip: str,
        message_id: int,
        server_port: int = LDAP_PORT,
    ) -> LDAPSession:
        """Get or create LDAP session tracker."""
        key = (client_ip, server_ip, message_id)
        if key not in self._sessions:
            self._sessions[key] = LDAPSession(
                client_ip=client_ip,
                server_ip=server_ip,
                server_port=server_port,
                message_id=message_id,
            )
        return self._sessions[key]

    def _record_credential(self, session: LDAPSession, success: Optional[bool]) -> None:
        """Record extracted LDAP credential."""
        if not session.bind_dn and not session.password:
            return

        # Check if we already have this credential
        for cred in self.credentials:
            if (
                cred.server_ip == session.server_ip
                and cred.client_ip == session.client_ip
                and cred.username == session.bind_dn
                and cred.password == session.password
            ):
                # Update success status if we now know it
                if success is not None and cred.success is None:
                    cred.success = success
                return

        cred = LDAPCredential(
            username=session.bind_dn,
            password=session.password,
            server_ip=session.server_ip,
            client_ip=session.client_ip,
            server_port=session.server_port,
            ldap_version=session.ldap_version,
            timestamp=datetime.now().isoformat(),
            success=success,
        )
        self.credentials.append(cred)

        self.logger.info(
            f"LDAP Credential: {session.bind_dn}:{session.password} "
            f"@ {session.server_ip}:{session.server_port} (success={success})"
        )

        # Update device with credential info
        self._update_device_credentials(session, success)

    def _update_credential_success(self, session: LDAPSession, success: bool) -> None:
        """Update existing credential with success status."""
        for cred in self.credentials:
            if (
                cred.server_ip == session.server_ip
                and cred.client_ip == session.client_ip
                and cred.username == session.bind_dn
                and cred.password == session.password
                and cred.success is None
            ):
                cred.success = success
                self.logger.info(
                    f"LDAP Credential updated: {session.bind_dn}:{session.password} "
                    f"@ {session.server_ip}:{session.server_port} (success={success})"
                )
                break

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _update_server_device(self, server_ip: str, server_port: int, server_mac: str = "") -> None:
        """Update or create LDAP server device entry."""
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"ldap-server:{server_ip}"
        manufacturer = lookup_mac_vendor(server_mac) if server_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            mac=server_mac,
            name=f"LDAP Server ({server_ip})",
            device_type="LDAP Server",
            manufacturer=manufacturer if manufacturer != "Unknown" else "",
        )

        # Build/update protocol data from stats
        stats = self._get_server_stats(server_ip)
        sasl_mechs = sorted(stats.get("sasl_mechanisms", set()))
        device.ldap_passive_data = {
            "role": "server",
            "port": server_port,
            "bind_count": stats.get("bind_count", 0),
            "search_count": stats.get("search_count", 0),
            "write_count": stats.get("write_count", 0),
            "sasl_mechanisms": sasl_mechs,
            "credentials": [],
            "protocol": "LDAP/TCP",
        }

    def _update_client_device(self, client_ip: str, server_ip: str, client_mac: str = "") -> None:
        """Update or create LDAP client device entry."""
        if not is_valid_discovered_ip(client_ip):
            return

        device_key = f"ldap-client:{client_ip}"
        manufacturer = lookup_mac_vendor(client_mac) if client_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            mac=client_mac,
            name=f"LDAP Client ({client_ip})",
            device_type="LDAP Client",
            manufacturer=manufacturer if manufacturer != "Unknown" else "",
        )
        if is_new:
            device.ldap_passive_data = {
                "role": "client",
                "credentials": [],
                "servers_accessed": [server_ip],
                "protocol": "LDAP/TCP",
            }
        else:
            if device.ldap_passive_data:
                servers = device.ldap_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.ldap_passive_data["servers_accessed"] = servers

    def _update_device_credentials(self, session: LDAPSession, success: Optional[bool]) -> None:
        """Update device entries with credential information."""
        server_key = f"ldap-server:{session.server_ip}"
        client_key = f"ldap-client:{session.client_ip}"

        cred_entry = {
            "username": session.bind_dn,
            "password": session.password,
            "client_ip": session.client_ip,
            "success": success,
            "timestamp": datetime.now().isoformat(),
        }

        with self._lock:
            # Update server
            if server_key in self.discovered_devices:
                device = self.discovered_devices[server_key]
                if device.ldap_passive_data:
                    creds = device.ldap_passive_data.get("credentials", [])
                    if not any(
                        c.get("username") == session.bind_dn
                        and c.get("password") == session.password
                        for c in creds
                    ):
                        creds.append(cred_entry)
                        device.ldap_passive_data["credentials"] = creds

            # Update client
            if client_key in self.discovered_devices:
                device = self.discovered_devices[client_key]
                if device.ldap_passive_data:
                    creds = device.ldap_passive_data.get("credentials", [])
                    client_cred = {
                        "username": session.bind_dn,
                        "password": session.password,
                        "server_ip": session.server_ip,
                        "success": success,
                        "timestamp": datetime.now().isoformat(),
                    }
                    if not any(
                        c.get("username") == session.bind_dn
                        and c.get("server_ip") == session.server_ip
                        for c in creds
                    ):
                        creds.append(client_cred)
                        device.ldap_passive_data["credentials"] = creds

    # -------------------------------------------------------------------------
    # harvest() and get_* methods
    # -------------------------------------------------------------------------

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials.

        Returns list of credential dicts with canonical keys for the base class
        harvest() credential table builder.
        """
        return [
            {
                "protocol": "LDAP",
                "credential_type": "plaintext",
                "auth_method": "Simple Bind",
                "username": cred.username,
                "password": cred.password,
                "server_ip": cred.server_ip,
                "server_port": cred.server_port,
                "client_ip": cred.client_ip,
                "ldap_version": cred.ldap_version,
                "success": cred.success,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get LDAP write operations for alert generation.

        Returns list of write operation dicts for the base class harvest()
        write alert builder.
        """
        if not self._write_ops:
            return []

        # Aggregate by client -> server pair
        pairs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for op in self._write_ops:
            key = (op["client"], op["server"])
            if key not in pairs:
                pairs[key] = {
                    "client": op["client"],
                    "server": op["server"],
                    "write_count": 0,
                    "operations": [],
                }
            pairs[key]["write_count"] += 1
            pairs[key]["operations"].append(f"{op['operation']}({op['target_dn']})")

        return list(pairs.values())
