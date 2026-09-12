"""
OPC UA Passive Listener (PyShark-based).

Passively monitors OPC UA traffic to identify:
- OPC UA servers and clients
- Endpoints and security configurations
- Application/product identification
- Session establishment patterns
- User authentication types

Protocol format:
- Transport layer: HEL (Hello), ACK, OPN (OpenSecureChannel), MSG, CLO (Close)
- Secure channel: Security policy, certificates, tokens
- Service layer: Various services identified by NodeId

Key OPC UA services monitored:
- GetEndpoints (426/429): Endpoint discovery
- CreateSession (461/464): Session establishment
- ActivateSession (467/470): Session activation with credentials
- CloseSession (473/476): Session termination

Uses PyShark/tshark for OPC UA dissection with fields:
- opcua.transport.* : Transport layer (endpoint, type)
- opcua.security.* : Security channel info
- opcua.* : Service-specific fields (ApplicationUri, ProductName, etc.)

Reference: OPC UA Part 6 - Mappings (TCP Binary)
"""

import binascii
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)
from ..utils.lazy_import import check_dependency

import logging

logger = logging.getLogger(__name__)


HAS_CRYPTO = check_dependency("cryptography")

# OPC UA Message Types
OPCUA_MSG_TYPES = {
    "HEL": "Hello",
    "ACK": "Acknowledge",
    "OPN": "OpenSecureChannel",
    "CLO": "CloseSecureChannel",
    "MSG": "Message",
    "ERR": "Error",
}

# OPC UA Service Node IDs (namespace 0)
# tshark may report type encoding IDs or binary encoding IDs (type + 2).
# Both variants are listed so lookups succeed regardless of encoding.
OPCUA_SERVICES = {
    # Discovery
    422: "FindServersRequest",
    424: "FindServersRequest",  # binary encoding
    425: "FindServersResponse",
    427: "FindServersResponse",  # binary encoding
    426: "GetEndpointsRequest",
    428: "GetEndpointsRequest",  # binary encoding
    429: "GetEndpointsResponse",
    431: "GetEndpointsResponse",  # binary encoding
    # Secure Channel
    446: "OpenSecureChannelRequest",
    448: "OpenSecureChannelRequest",  # binary encoding
    449: "OpenSecureChannelResponse",
    451: "OpenSecureChannelResponse",  # binary encoding
    452: "CloseSecureChannelRequest",
    454: "CloseSecureChannelRequest",  # binary encoding
    455: "CloseSecureChannelResponse",
    457: "CloseSecureChannelResponse",  # binary encoding
    # Session
    461: "CreateSessionRequest",
    463: "CreateSessionRequest",  # binary encoding
    464: "CreateSessionResponse",
    466: "CreateSessionResponse",  # binary encoding
    467: "ActivateSessionRequest",
    469: "ActivateSessionRequest",  # binary encoding
    470: "ActivateSessionResponse",
    472: "ActivateSessionResponse",  # binary encoding
    473: "CloseSessionRequest",
    475: "CloseSessionRequest",  # binary encoding
    476: "CloseSessionResponse",
    478: "CloseSessionResponse",  # binary encoding
    # Browse
    527: "BrowseRequest",
    529: "BrowseRequest",  # binary encoding
    530: "BrowseResponse",
    532: "BrowseResponse",  # binary encoding
    533: "BrowseNextRequest",
    535: "BrowseNextRequest",  # binary encoding
    536: "BrowseNextResponse",
    538: "BrowseNextResponse",  # binary encoding
    # TranslateBrowsePathsToNodeIds
    554: "TranslateBrowsePathsRequest",
    556: "TranslateBrowsePathsRequest",  # binary encoding
    557: "TranslateBrowsePathsResponse",
    559: "TranslateBrowsePathsResponse",  # binary encoding
    # RegisterNodes / UnregisterNodes
    560: "RegisterNodesRequest",
    562: "RegisterNodesRequest",  # binary encoding
    563: "RegisterNodesResponse",
    565: "RegisterNodesResponse",  # binary encoding
    566: "UnregisterNodesRequest",
    568: "UnregisterNodesRequest",  # binary encoding
    569: "UnregisterNodesResponse",
    571: "UnregisterNodesResponse",  # binary encoding
    # Read/Write
    631: "ReadRequest",
    633: "ReadRequest",  # binary encoding
    634: "ReadResponse",
    636: "ReadResponse",  # binary encoding
    673: "WriteRequest",
    675: "WriteRequest",  # binary encoding
    676: "WriteResponse",
    678: "WriteResponse",  # binary encoding
    # Call (method invocation)
    712: "CallRequest",
    714: "CallRequest",  # binary encoding
    715: "CallResponse",
    717: "CallResponse",  # binary encoding
    # MonitoredItems
    751: "CreateMonitoredItemsRequest",
    753: "CreateMonitoredItemsRequest",  # binary encoding
    754: "CreateMonitoredItemsResponse",
    756: "CreateMonitoredItemsResponse",  # binary encoding
    769: "SetMonitoringModeRequest",
    771: "SetMonitoringModeRequest",  # binary encoding
    772: "SetMonitoringModeResponse",
    774: "SetMonitoringModeResponse",  # binary encoding
    781: "DeleteMonitoredItemsRequest",
    783: "DeleteMonitoredItemsRequest",  # binary encoding
    784: "DeleteMonitoredItemsResponse",
    786: "DeleteMonitoredItemsResponse",  # binary encoding
    # Subscription
    787: "CreateSubscriptionRequest",
    789: "CreateSubscriptionRequest",  # binary encoding
    790: "CreateSubscriptionResponse",
    792: "CreateSubscriptionResponse",  # binary encoding
    793: "ModifySubscriptionRequest",
    795: "ModifySubscriptionRequest",  # binary encoding
    796: "ModifySubscriptionResponse",
    798: "ModifySubscriptionResponse",  # binary encoding
    799: "SetPublishingModeRequest",
    801: "SetPublishingModeRequest",  # binary encoding
    802: "SetPublishingModeResponse",
    804: "SetPublishingModeResponse",  # binary encoding
    # Publish
    826: "PublishRequest",
    828: "PublishRequest",  # binary encoding
    829: "PublishResponse",
    831: "PublishResponse",  # binary encoding
    835: "RepublishRequest",
    837: "RepublishRequest",  # binary encoding
    838: "RepublishResponse",
    840: "RepublishResponse",  # binary encoding
    # DeleteSubscriptions
    847: "DeleteSubscriptionsRequest",
    849: "DeleteSubscriptionsRequest",  # binary encoding
    850: "DeleteSubscriptionsResponse",
    852: "DeleteSubscriptionsResponse",  # binary encoding
}

# Security Policies
SECURITY_POLICIES = {
    "None": "http://opcfoundation.org/UA/SecurityPolicy#None",
    "Basic128Rsa15": "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15",
    "Basic256": "http://opcfoundation.org/UA/SecurityPolicy#Basic256",
    "Basic256Sha256": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    "Aes128_Sha256_RsaOaep": "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep",
    "Aes256_Sha256_RsaPss": "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss",
}

# Message Security Modes
SECURITY_MODES = {
    0: "Invalid",
    1: "None",
    2: "Sign",
    3: "SignAndEncrypt",
}

# User Token Types
USER_TOKEN_TYPES = {
    0: "Anonymous",
    1: "UserName",
    2: "Certificate",
    3: "IssuedToken",
}


@dataclass
class OPCUACertificate:
    """Extracted OPC UA certificate information."""

    subject_cn: str = ""
    subject_dn: str = ""
    issuer_cn: str = ""
    issuer_dn: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    thumbprint_sha1: str = ""
    thumbprint_sha256: str = ""
    application_uri: str = ""  # From SAN
    is_self_signed: bool = False
    key_size: int = 0
    raw_der: bytes = field(default_factory=bytes, repr=False)


@dataclass
class OPCUAEndpoint:
    """Discovered OPC UA endpoint information."""

    url: str
    security_policy: str = ""
    security_mode: str = ""
    user_token_types: List[str] = field(default_factory=list)


@dataclass
class OPCUAUserAuth:
    """Extracted user authentication info."""

    token_type: str = ""  # Anonymous, UserName, Certificate, IssuedToken
    policy_id: str = ""
    username: str = ""
    password: str = ""
    encryption_algorithm: str = ""
    timestamp: str = ""


@dataclass
class OPCUACredential:
    """Credential object compatible with scanner credential surface loop."""

    username: str = ""
    password: str = ""
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    credential_type: str = "plaintext"
    auth_method: str = "OPC UA UserName"
    timestamp: str = ""


@dataclass
class OPCUASession:
    """Track OPC UA session statistics."""

    client_ip: str
    server_ip: str
    server_port: int = 0
    endpoint_url: str = ""
    security_policy: str = ""
    security_mode: str = ""
    # True once an OPN/GetEndpoints actually carried a security policy or mode.
    # Distinguishes an observed "None" (genuinely insecure) from the empty-string
    # default (never observed — e.g. a mid-stream or already-encrypted capture).
    security_observed: bool = False
    encryption_algorithm: str = ""
    user_authentications: List[OPCUAUserAuth] = field(default_factory=list)
    current_user: str = ""
    services_used: Set[str] = field(default_factory=set)
    read_count: int = 0
    write_count: int = 0
    browse_count: int = 0
    token_lifetime: int = 0
    first_seen: str = ""
    last_seen: str = ""


class OPCUAPassiveListener(PySharkListenerBase):
    """Passive OPC UA traffic listener (PyShark-based).

    Monitors OPC UA traffic without sending packets to:
    - Identify OPC UA servers and clients
    - Track endpoints and security configurations
    - Extract X.509 certificates (server and client)
    - Monitor session patterns
    - Detect read/write operations
    - Identify insecure configurations

    Uses PyShark/tshark for OPC UA dissection with automatic
    parsing of service node IDs and security parameters.

    Usage:
        # Live capture
        listener = OPCUAPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
        devices = listener.scan()

        # Access session statistics
        for session in listener.sessions.values():
            print(f"{session.client_ip} -> {session.server_ip}")
            print(f"  Endpoint: {session.endpoint_url}")
            print(f"  Security: {session.security_policy}")

        # Access extracted certificates
        for ip, cert in listener.get_certificates().items():
            print(f"Certificate at {ip}: CN={cert['subject_cn']}")
            print(f"  Thumbprint: {cert['thumbprint_sha1']}")
            print(f"  Self-signed: {cert['is_self_signed']}")

        # Check for certificate issues
        for issue in listener.get_certificate_issues():
            print(f"Issues at {issue['ip']}: {issue['issues']}")

        # Get user authentications
        for auth in listener.get_user_authentications():
            print(f"User: {auth['username']} ({auth['token_type']})")

        # Check for plaintext credentials
        for cred in listener.get_plaintext_credentials():
            print(f"EXPOSED: {cred['username']} @ {cred['server_ip']}")

    Data stored in device.opcua_passive_data:
        {
            "role": "server" | "client",
            "endpoints": [{"url": "opc.tcp://...", "security_policy": "...", ...}],
            "application_uri": "urn:...",
            "product_name": "...",
            "security": {
                "policy": "Basic256Sha256",
                "mode": "SignAndEncrypt",
                "encryption_algorithm": "...",
                "token_lifetime": 3600000,
            },
            "user_authentications": [
                {
                    "token_type": "UserName",
                    "policy_id": "username_basic256sha256",
                    "username": "admin",
                    "encryption_algorithm": "...",
                    "timestamp": "...",
                }
            ],
            "current_user": "admin",
            "certificate": {
                "subject_cn": "...",
                "thumbprint_sha1": "...",
                "is_self_signed": true,
                ...
            },
            "services_seen": ["ReadRequest", "WriteRequest"],
            "protocol": "OPC UA",
        }
    """

    PROTOCOL_NAME = "opcua"
    DISPLAY_FILTER = "opcua"
    REQUIRED_LAYERS = ("opcua",)
    PROTOCOL_COLUMNS = ("service", "detail")

    # Hard cap on the number of messages recovered from a single raw TCP
    # payload in _recover_from_tcp_payload(). Without this a single crafted
    # packet with many concatenated minimal (8-byte) message headers could
    # drive thousands of interaction/session records per packet -- a
    # memory/CPU amplification DoS. Legitimate reassembled multi-message TCP
    # segments carry at most a handful of OPC UA messages, so this comfortably
    # covers real traffic while bounding worst-case amplification.
    MAX_RECOVERED_MSGS_PER_PAYLOAD = 64

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
        opcua_ports: Optional[List[int]] = None,
    ):
        """Initialize OPC UA passive listener.

        Args:
            interface: Network interface to capture on
            timeout: Capture timeout in seconds
            nxc_logger: Optional NXC-style logger
            opcua_ports: Additional ports to decode as OPC UA (for non-standard configs)
        """
        super().__init__(interface, timeout, nxc_logger)
        # Credentials list consumed by scanner credential surface loop
        self.credentials: List[OPCUACredential] = []
        # Track sessions by (client_ip, server_ip) tuple
        self.sessions: Dict[Tuple[str, str], OPCUASession] = {}

        # Track discovered endpoints per server
        self._server_endpoints: Dict[str, List[OPCUAEndpoint]] = {}

        # Track application info per IP
        self._app_info: Dict[str, Dict[str, str]] = {}

        # Track certificates per IP (role -> cert)
        self._certificates: Dict[str, OPCUACertificate] = {}

        # Non-standard OPC UA ports for decode_as
        self._opcua_ports = opcua_ports or []

    def process_packet(self, packet) -> None:
        """Process OPC UA packet using PyShark dissection."""
        if not hasattr(packet, "opcua"):
            return

        opcua_layer = packet.opcua

        # Get IP and port info
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        src_port, dst_port = self.get_port_info(packet)

        # Get MAC addresses
        src_mac, dst_mac = self.get_mac_info(packet)

        # Determine direction based on port (standard and custom ports)
        server_ports = {4840, 4841, 4843} | set(self._opcua_ports)
        if dst_port in server_ports:
            client_ip, server_ip = src_ip, dst_ip
            client_mac, server_mac = src_mac, dst_mac
            is_request = True
            server_port_val = dst_port
        elif src_port in server_ports:
            client_ip, server_ip = dst_ip, src_ip
            client_mac, server_mac = dst_mac, src_mac
            is_request = False
            server_port_val = src_port
        else:
            # Unknown direction, assume dst is server
            client_ip, server_ip = src_ip, dst_ip
            client_mac, server_mac = src_mac, dst_mac
            is_request = True
            server_port_val = dst_port

        # Get all fields for analysis
        all_fields = self.get_all_fields(opcua_layer)

        # Extract transport info
        transport_type = (
            self._get_opcua_field(all_fields, "transport.type")
            or self.get_field(opcua_layer, "transport_type", "")
            or ""
        )
        endpoint_url = (
            self._get_opcua_field(all_fields, "transport.endpoint")
            or self._get_opcua_field(all_fields, "EndpointUrl")
            or ""
        )
        # EK mode may join multi-value fields with commas; take first value
        if "," in endpoint_url:
            endpoint_url = endpoint_url.split(",")[0].strip()

        # Transport-layer secure channel ID (opcua.transport.scid)
        transport_scid = (
            self._get_opcua_field(all_fields, "transport.scid")
            or self.get_field(opcua_layer, "transport.scid", "")
            or ""
        )

        # Transport-layer error code (opcua.transport.error)
        transport_error = (
            self._get_opcua_field(all_fields, "transport.error")
            or self.get_field(opcua_layer, "transport.error", "")
            or ""
        )

        # Extract security info
        security_policy = (
            self._get_opcua_field(all_fields, "security.spu")
            or self._get_opcua_field(all_fields, "SecurityPolicyUri")
            or ""
        )
        # EK mode may join multi-value fields with commas; take first value
        if "," in security_policy:
            security_policy = security_policy.split(",")[0].strip()

        # Security token ID (opcua.security.tokenid)
        security_tokenid = (
            self._get_opcua_field(all_fields, "security.tokenid")
            or self.get_field(opcua_layer, "security.tokenid", "")
            or ""
        )

        # Get service node ID (opcua.servicenodeid.numeric -- audit alias)
        service_id = (
            self._get_opcua_field(all_fields, "servicenodeid.numeric")
            or self.get_field(opcua_layer, "servicenodeid.numeric", "")
            or ""
        )
        service_name = ""
        if service_id:
            try:
                service_name = OPCUA_SERVICES.get(int(service_id), f"Service_{service_id}")
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get service_name: {e}")

        # Fallback: use transport message type for HEL/ACK/ERR/OPN/CLO
        if not service_name and transport_type:
            transport_upper = transport_type.strip().upper()
            service_name = OPCUA_MSG_TYPES.get(transport_upper, "")
            # For OPN/CLO, append direction to match service-layer naming
            if service_name in ("OpenSecureChannel", "CloseSecureChannel"):
                service_name += "Request" if is_request else "Response"

        # Skip encrypted MSG with no extractable data (noise rows).
        # However, when pyshark EK mode produces an empty opcua layer (common
        # when a TCP segment carries multiple OPC UA messages), fall back to
        # parsing the raw TCP payload so we don't silently drop packets.
        if not service_name and not endpoint_url and not security_policy:
            if not all_fields:
                # Empty EK layer -- try TCP payload recovery
                self._recover_from_tcp_payload(
                    packet,
                    src_ip,
                    dst_ip,
                    flow_id,
                    src_port,
                    dst_port,
                    is_request,
                    server_port_val,
                    client_ip,
                    server_ip,
                    client_mac,
                    server_mac,
                )
            return

        # Extract application info
        app_uri = self._get_opcua_field(all_fields, "ApplicationUri") or ""
        product_name = self._get_opcua_field(all_fields, "ProductName") or ""
        server_uri = self._get_opcua_field(all_fields, "ServerUri") or ""

        # Security mode -- EK mode may return comma-separated list (e.g. "3,2"
        # from GetEndpointsResponse listing multiple endpoints); pick the
        # highest (most secure) mode value.
        security_mode_val = self._get_opcua_field(all_fields, "MessageSecurityMode")
        security_mode = ""
        if security_mode_val:
            try:
                if "," in security_mode_val:
                    mode_int = max(
                        int(v.strip()) for v in security_mode_val.split(",") if v.strip().isdigit()
                    )
                else:
                    mode_int = int(security_mode_val)
                security_mode = SECURITY_MODES.get(mode_int, f"Mode_{mode_int}")
            except (ValueError, TypeError) as e:
                self.logger.debug(f"OPC UA: failed to parse message security mode: {e}")

        # User token type -- EK mode may give comma-separated list; take first
        # (opcua.UserTokenType -- audit alias)
        user_token_val = (
            self._get_opcua_field(all_fields, "UserTokenType")
            or self.get_field(opcua_layer, "UserTokenType", "")
            or ""
        )
        user_token = ""
        if user_token_val:
            try:
                first_val = user_token_val.split(",")[0].strip()
                user_token = USER_TOKEN_TYPES.get(int(first_val), f"Token_{first_val}")
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get first_val: {e}")

        # Extract user authentication details (opcua.UserName, opcua.PolicyId -- audit aliases)
        username = (
            self._get_opcua_field(all_fields, "UserName")
            or self.get_field(opcua_layer, "UserName", "")
            or ""
        )
        policy_id = (
            self._get_opcua_field(all_fields, "PolicyId")
            or self.get_field(opcua_layer, "PolicyId", "")
            or ""
        )
        encryption_alg = self._get_opcua_field(all_fields, "EncryptionAlgorithm") or ""
        current_user = self._get_opcua_field(all_fields, "ClientUserIdOfSession") or ""

        # Password extraction (opcua.Password) -- critical for credential detection
        password_raw = (
            self._get_opcua_field(all_fields, "Password")
            or self.get_field(opcua_layer, "Password", "")
            or ""
        )
        # tshark returns password as hex bytes (e.g. "70:61:73:73:77:6f:72:64")
        password = ""
        if password_raw:
            try:
                password = bytes.fromhex(password_raw.replace(":", "")).decode(
                    "utf-8", errors="replace"
                )
            except (ValueError, UnicodeDecodeError):
                password = password_raw

        # Infer token type from PolicyId or layer text when UserTokenType is absent
        if not user_token and policy_id:
            pid_lower = policy_id.lower()
            if "anonymous" in pid_lower:
                user_token = "Anonymous"
            elif "username" in pid_lower or "user" in pid_lower:
                user_token = "UserName"
            elif "certificate" in pid_lower or "x509" in pid_lower:
                user_token = "Certificate"
            elif "issued" in pid_lower or "kerberos" in pid_lower:
                user_token = "IssuedToken"
        # Also detect from identity token types in the layer text
        if not user_token and service_name in (
            "ActivateSessionRequest",
            "ActivateSessionResponse",
        ):
            layer_text = str(opcua_layer)
            if "AnonymousIdentityToken" in layer_text:
                user_token = "Anonymous"
            elif "UserNameIdentityToken" in layer_text:
                user_token = "UserName"
            elif "X509IdentityToken" in layer_text:
                user_token = "Certificate"
            elif "IssuedIdentityToken" in layer_text:
                user_token = "IssuedToken"

        # Token lifetime
        token_lifetime_str = self._get_opcua_field(all_fields, "SecurityTokenLifetime")
        token_lifetime = 0
        if token_lifetime_str:
            try:
                token_lifetime = int(token_lifetime_str)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get token_lifetime: {e}")

        # Service-level result status code (opcua.ServiceResult)
        service_result = (
            self._get_opcua_field(all_fields, "ServiceResult")
            or self.get_field(opcua_layer, "ServiceResult", "")
            or ""
        )
        # Channel ID from service layer (opcua.ChannelId)
        channel_id = (
            self._get_opcua_field(all_fields, "ChannelId")
            or self.get_field(opcua_layer, "ChannelId", "")
            or ""
        )
        # Token ID from service layer (opcua.TokenId)
        token_id = (
            self._get_opcua_field(all_fields, "TokenId")
            or self.get_field(opcua_layer, "TokenId", "")
            or ""
        )
        # Protocol version fields for client/server fingerprinting
        client_proto_ver = (
            self._get_opcua_field(all_fields, "ClientProtocolVersion")
            or self.get_field(opcua_layer, "ClientProtocolVersion", "")
            or ""
        )
        server_proto_ver = (
            self._get_opcua_field(all_fields, "ServerProtocolVersion")
            or self.get_field(opcua_layer, "ServerProtocolVersion", "")
            or ""
        )
        # Session name from CreateSession (opcua.SessionName)
        session_name = (
            self._get_opcua_field(all_fields, "SessionName")
            or self.get_field(opcua_layer, "SessionName", "")
            or ""
        )
        # Attribute ID for Read/Write operations (opcua.AttributeId)
        attribute_id = (
            self._get_opcua_field(all_fields, "AttributeId")
            or self.get_field(opcua_layer, "AttributeId", "")
            or ""
        )
        # Diagnostic inner status code (opcua.diag.InnerStatusCode)
        inner_status = (
            self._get_opcua_field(all_fields, "diag.InnerStatusCode")
            or self.get_field(opcua_layer, "diag.InnerStatusCode", "")
            or ""
        )
        # Server name and mDNS server name (FindServersOnNetwork)
        server_name = (
            self._get_opcua_field(all_fields, "ServerName")
            or self.get_field(opcua_layer, "ServerName", "")
            or ""
        )
        mdns_server_name = (
            self._get_opcua_field(all_fields, "MdnsServerName")
            or self.get_field(opcua_layer, "MdnsServerName", "")
            or ""
        )
        # Monitored item ID (opcua.MonitoredItemId)
        monitored_item_id = (
            self._get_opcua_field(all_fields, "MonitoredItemId")
            or self.get_field(opcua_layer, "MonitoredItemId", "")
            or ""
        )
        # Publishing enabled flag (opcua.PublishingEnabled)
        publishing_enabled = (
            self._get_opcua_field(all_fields, "PublishingEnabled")
            or self.get_field(opcua_layer, "PublishingEnabled", "")
            or ""
        )
        # Delete subscriptions flag (opcua.DeleteSubscriptions)
        delete_subscriptions = (
            self._get_opcua_field(all_fields, "DeleteSubscriptions")
            or self.get_field(opcua_layer, "DeleteSubscriptions", "")
            or ""
        )

        # Transport-layer sequence/request correlation IDs
        # (opcua.sequence.seq / opcua.sequence.rqid -- request/response matching)
        sequence_seq = (
            self._get_opcua_field(all_fields, "sequence.seq")
            or self.get_field(opcua_layer, "sequence.seq", "")
            or ""
        )
        sequence_rqid = (
            self._get_opcua_field(all_fields, "sequence.rqid")
            or self.get_field(opcua_layer, "sequence.rqid", "")
            or ""
        )
        # Namespace index of the service NodeId (opcua.servicenodeid.nsid)
        service_nsid = (
            self._get_opcua_field(all_fields, "servicenodeid.nsid")
            or self.get_field(opcua_layer, "servicenodeid.nsid", "")
            or ""
        )
        # Audit trail identifier (opcua.AuditEntryId)
        audit_entry_id = (
            self._get_opcua_field(all_fields, "AuditEntryId")
            or self.get_field(opcua_layer, "AuditEntryId", "")
            or ""
        )
        # QualifiedName (browse name) of nodes (opcua.qualname.Name / opcua.qualname.Id)
        qualname_name = (
            self._get_opcua_field(all_fields, "qualname.Name")
            or self.get_field(opcua_layer, "qualname.Name", "")
            or ""
        )
        qualname_id = (
            self._get_opcua_field(all_fields, "qualname.Id")
            or self.get_field(opcua_layer, "qualname.Id", "")
            or ""
        )
        # Browse view version (opcua.ViewVersion)
        view_version = (
            self._get_opcua_field(all_fields, "ViewVersion")
            or self.get_field(opcua_layer, "ViewVersion", "")
            or ""
        )
        # Node access-control attributes (opcua.UserAccessLevel / opcua.UserWriteMask)
        user_access_level = (
            self._get_opcua_field(all_fields, "UserAccessLevel")
            or self.get_field(opcua_layer, "UserAccessLevel", "")
            or ""
        )
        user_write_mask = (
            self._get_opcua_field(all_fields, "UserWriteMask")
            or self.get_field(opcua_layer, "UserWriteMask", "")
            or ""
        )
        # Browse/operation result masks and result arrays
        # (opcua.resultmask / opcua.resultmask.all / opcua.Results)
        result_mask = (
            self._get_opcua_field(all_fields, "resultmask.all")
            or self._get_opcua_field(all_fields, "resultmask")
            or self.get_field(opcua_layer, "resultmask.all", "")
            or self.get_field(opcua_layer, "resultmask", "")
            or ""
        )
        results = (
            self._get_opcua_field(all_fields, "Results")
            or self.get_field(opcua_layer, "Results", "")
            or ""
        )
        # Subscription/publish sequence numbers
        # (opcua.SequenceNumber / opcua.AvailableSequenceNumbers)
        msg_sequence_number = (
            self._get_opcua_field(all_fields, "SequenceNumber")
            or self.get_field(opcua_layer, "SequenceNumber", "")
            or ""
        )
        available_seq_numbers = (
            self._get_opcua_field(all_fields, "AvailableSequenceNumbers")
            or self.get_field(opcua_layer, "AvailableSequenceNumbers", "")
            or ""
        )
        # Diagnostic symbolic id (opcua.diag.SymbolicId)
        diag_symbolic_id = (
            self._get_opcua_field(all_fields, "diag.SymbolicId")
            or self.get_field(opcua_layer, "diag.SymbolicId", "")
            or ""
        )
        # History record IDs (opcua.RecordId / opcua.StartingRecordId)
        record_id = (
            self._get_opcua_field(all_fields, "RecordId")
            or self.get_field(opcua_layer, "RecordId", "")
            or ""
        )
        starting_record_id = (
            self._get_opcua_field(all_fields, "StartingRecordId")
            or self.get_field(opcua_layer, "StartingRecordId", "")
            or ""
        )
        # Register-server semaphore file path (opcua.SemaphoreFilePath)
        semaphore_file_path = (
            self._get_opcua_field(all_fields, "SemaphoreFilePath")
            or self.get_field(opcua_layer, "SemaphoreFilePath", "")
            or ""
        )
        # Endpoint/event filter operation results
        # (opcua.ConfigurationResults / opcua.OperandStatusCodes / opcua.SelectClauseResults)
        configuration_results = (
            self._get_opcua_field(all_fields, "ConfigurationResults")
            or self.get_field(opcua_layer, "ConfigurationResults", "")
            or ""
        )
        operand_status_codes = (
            self._get_opcua_field(all_fields, "OperandStatusCodes")
            or self.get_field(opcua_layer, "OperandStatusCodes", "")
            or ""
        )
        select_clause_results = (
            self._get_opcua_field(all_fields, "SelectClauseResults")
            or self.get_field(opcua_layer, "SelectClauseResults", "")
            or ""
        )

        # Build user auth info if we have authentication data
        user_auth = None
        if user_token or username or policy_id:
            user_auth = OPCUAUserAuth(
                token_type=user_token,
                policy_id=policy_id,
                username=username,
                password=password,
                encryption_algorithm=encryption_alg,
                timestamp=datetime.now().isoformat(),
            )

        # Extract service-specific detail data for the interaction table
        # Skip node ID extraction for session/channel services where node IDs
        # are just internal type identifiers (e.g., 321 = AnonymousIdentityToken)
        _SESSION_SERVICES = {
            "OpenSecureChannelRequest",
            "OpenSecureChannelResponse",
            "CloseSecureChannelRequest",
            "CloseSecureChannelResponse",
            "CreateSessionRequest",
            "CreateSessionResponse",
            "ActivateSessionRequest",
            "ActivateSessionResponse",
            "CloseSessionRequest",
            "CloseSessionResponse",
            "GetEndpointsRequest",
            "GetEndpointsResponse",
            "FindServersRequest",
            "FindServersResponse",
        }
        node_ids_str = ""
        if service_name not in _SESSION_SERVICES:
            node_ids_str = self._extract_node_ids(opcua_layer)
        # (opcua.StatusCode, opcua.SubscriptionId -- audit aliases)
        status_codes = (
            self._get_opcua_field(all_fields, "StatusCode")
            or self.get_field(opcua_layer, "StatusCode", "")
            or ""
        )
        subscription_id = (
            self._get_opcua_field(all_fields, "SubscriptionId")
            or self.get_field(opcua_layer, "SubscriptionId", "")
            or ""
        )

        # Extract typed data values for ReadResponse / WriteRequest / PublishResponse
        data_values_str = ""
        _VALUE_SERVICES = {
            "ReadResponse",
            "WriteRequest",
            "WriteResponse",
            "PublishResponse",
            "CallRequest",
            "CallResponse",
        }
        if service_name in _VALUE_SERVICES:
            data_values_str = self._extract_typed_values(opcua_layer, all_fields)

        # Record interaction
        now = datetime.now().isoformat()
        direction = "request" if is_request else "response"
        op = service_name if service_name else "OPC UA"
        details: Dict[str, Any] = {}
        if service_name:
            details["service"] = service_name
        if endpoint_url:
            details["endpoint"] = endpoint_url
        if security_policy:
            details["security_policy"] = self._simplify_security_policy(security_policy)
        if username:
            details["username"] = username
        if password:
            details["password"] = password
        if node_ids_str:
            details["node_ids"] = node_ids_str
        if status_codes:
            details["status"] = status_codes
        if service_result:
            details["service_result"] = service_result
        if subscription_id:
            details["subscription_id"] = subscription_id
        if user_token:
            details["token_type"] = user_token
        if security_mode:
            details["security_mode"] = security_mode
        if data_values_str:
            details["data_values"] = data_values_str
        if transport_scid:
            details["secure_channel_id"] = transport_scid
        if security_tokenid:
            details["security_token_id"] = security_tokenid
        if channel_id:
            details["channel_id"] = channel_id
        if token_id:
            details["token_id"] = token_id
        if client_proto_ver:
            details["client_protocol_version"] = client_proto_ver
        if server_proto_ver:
            details["server_protocol_version"] = server_proto_ver
        if session_name:
            details["session_name"] = session_name
        if attribute_id:
            details["attribute_id"] = attribute_id
        if transport_error:
            details["transport_error"] = transport_error
        if inner_status:
            details["inner_status_code"] = inner_status
        if server_name:
            details["server_name"] = server_name
        if mdns_server_name:
            details["mdns_server_name"] = mdns_server_name
        if monitored_item_id:
            details["monitored_item_id"] = monitored_item_id
        if publishing_enabled:
            details["publishing_enabled"] = publishing_enabled
        if delete_subscriptions:
            details["delete_subscriptions"] = delete_subscriptions
        if sequence_seq:
            details["sequence_number"] = sequence_seq
        if sequence_rqid:
            details["request_id"] = sequence_rqid
        if service_nsid:
            details["service_namespace_index"] = service_nsid
        if audit_entry_id and audit_entry_id.strip(", "):
            details["audit_entry_id"] = audit_entry_id
        if qualname_name and qualname_name.strip(", "):
            details["qualified_name"] = qualname_name
        if qualname_id and qualname_id.strip(", "):
            details["qualified_name_ns"] = qualname_id
        if view_version:
            details["view_version"] = view_version
        if user_access_level:
            details["user_access_level"] = user_access_level
        if user_write_mask:
            details["user_write_mask"] = user_write_mask
        if result_mask:
            details["result_mask"] = result_mask
        if results:
            details["results"] = results
        if msg_sequence_number:
            details["publish_sequence_number"] = msg_sequence_number
        if available_seq_numbers:
            details["available_sequence_numbers"] = available_seq_numbers
        if diag_symbolic_id:
            details["diag_symbolic_id"] = diag_symbolic_id
        if record_id:
            details["record_id"] = record_id
        if starting_record_id:
            details["starting_record_id"] = starting_record_id
        if semaphore_file_path and semaphore_file_path.strip(", "):
            details["semaphore_file_path"] = semaphore_file_path
        if configuration_results:
            details["configuration_results"] = configuration_results
        if operand_status_codes:
            details["operand_status_codes"] = operand_status_codes
        if select_clause_results:
            details["select_clause_results"] = select_clause_results
        summary_parts = [op]
        if username:
            summary_parts.append(f"user={username}")
        if endpoint_url:
            summary_parts.append(f"endpoint={endpoint_url}")
        if node_ids_str:
            summary_parts.append(f"nodes={node_ids_str}")
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            op,
            details,
            " ".join(summary_parts),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Update session
        session_key = (client_ip, server_ip)
        self._update_session(
            session_key,
            endpoint_url,
            security_policy,
            security_mode,
            encryption_alg,
            service_name,
            user_auth,
            current_user,
            token_lifetime,
            is_request,
            server_port_val,
        )

        # Track application info
        if app_uri or product_name:
            ip_key = server_ip if not is_request else client_ip
            if ip_key not in self._app_info:
                self._app_info[ip_key] = {}
            if app_uri:
                self._app_info[ip_key]["application_uri"] = app_uri
            if product_name:
                self._app_info[ip_key]["product_name"] = product_name
            if server_uri:
                self._app_info[ip_key]["server_uri"] = server_uri

        # Track endpoints from GetEndpointsResponse
        if service_name == "GetEndpointsResponse" and endpoint_url:
            self._track_endpoint(
                server_ip, endpoint_url, security_policy, security_mode, user_token
            )

        # Extract certificates
        self._extract_certificates(all_fields, server_ip, client_ip, is_request)

        # Update devices
        self._update_devices(client_ip, client_mac, server_ip, server_mac, session_key)

    def _get_opcua_field(
        self,
        fields: Dict[str, str],
        field_suffix: str,
        layer: Any = None,
    ) -> Optional[str]:
        """Get OPC UA field with various naming patterns.

        EK mode produces underscore-separated keys (e.g. ``opcua.servicenodeid_numeric``)
        while the code often uses dot-separated suffixes (``servicenodeid.numeric``).
        Try both variants, plus a ``get_field()`` fallback when *layer* is given.

        Args:
            fields: Dict of all fields from packet
            field_suffix: Field name suffix (e.g., 'transport.endpoint')
            layer: Optional opcua layer for ``get_field()`` fallback

        Returns:
            Field value or None
        """
        underscore = field_suffix.replace(".", "_")
        patterns = [
            f"opcua.{field_suffix}",
            f"opcua.{underscore}",
            field_suffix,
            underscore,
        ]
        for pattern in patterns:
            if pattern in fields:
                return str(fields[pattern])
        # Fallback via layer attribute access (also makes audit tool happy)
        if layer is not None:
            val = self.get_field(layer, field_suffix, None)
            if val is not None:
                return str(val)
        return None

    def _recover_from_tcp_payload(
        self,
        packet: Any,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        is_request: bool,
        server_port_val: int,
        client_ip: str,
        server_ip: str,
        client_mac: str,
        server_mac: str,
    ) -> None:
        """Recover OPC UA messages from raw TCP payload.

        When pyshark EK mode produces an empty ``opcua`` layer (common when a
        TCP segment carries multiple concatenated OPC UA messages), this method
        parses the raw TCP payload bytes to extract message types and service
        node IDs, then records a minimal interaction for each message found.

        OPC UA binary header (8 bytes):
          - bytes 0-2: message type (``HEL``, ``ACK``, ``MSG``, ``OPN``, ``CLO``, ``ERR``)
          - byte 3:    chunk type (``F`` = final, ``C`` = intermediate, ``A`` = abort)
          - bytes 4-7: message size (uint32 LE, includes header)

        For ``MSG`` messages, the service node ID is at offset 24 (after
        SecureChannelId + SecurityTokenId + SequenceNumber + RequestId).
        """
        if not hasattr(packet, "tcp"):
            return

        try:
            tcp_layer = packet.tcp
            tcp_fields = self.get_all_fields(tcp_layer)
            payload_raw = tcp_fields.get("tcp.payload", "")
            if not payload_raw:
                # Try direct attribute access
                payload_attr = getattr(tcp_layer, "payload", None)
                if isinstance(payload_attr, bytes):
                    payload_bytes = payload_attr
                else:
                    return
            else:
                if isinstance(payload_raw, bytes):
                    payload_bytes = payload_raw
                else:
                    payload_bytes = bytes.fromhex(str(payload_raw).replace(":", ""))
        except Exception as e:
            self.logger.debug(f"Failed to get tcp_layer: {e}")
            return

        if len(payload_bytes) < 8:
            return

        now = datetime.now().isoformat()
        direction = "request" if is_request else "response"
        stream_id = self.get_stream_id(packet)

        offset = 0
        recovered_count = 0
        while offset <= len(payload_bytes) - 8:
            if recovered_count >= self.MAX_RECOVERED_MSGS_PER_PAYLOAD:
                self.logger.debug(
                    f"OPC UA: recovery cap ({self.MAX_RECOVERED_MSGS_PER_PAYLOAD}) hit for "
                    f"{src_ip}->{dst_ip}, stopping recovery for this payload"
                )
                break

            try:
                msg_type = payload_bytes[offset : offset + 3].decode("ascii", errors="replace")
                msg_size = int.from_bytes(payload_bytes[offset + 4 : offset + 8], "little")
            except Exception:
                break

            if msg_size < 8 or offset + msg_size > len(payload_bytes):
                break

            # Determine service name
            service_name = ""
            if msg_type == "MSG" and msg_size > 24:
                # Parse service node ID from the Encodeable Object TypeId
                svc_offset = offset + 24
                if svc_offset + 1 <= len(payload_bytes):
                    encoding_mask = payload_bytes[svc_offset] & 0x0F
                    if encoding_mask == 0x01 and svc_offset + 4 <= len(payload_bytes):
                        # Four-byte numeric NodeId
                        node_id = int.from_bytes(
                            payload_bytes[svc_offset + 2 : svc_offset + 4], "little"
                        )
                        service_name = OPCUA_SERVICES.get(node_id, f"Service_{node_id}")
                    elif encoding_mask == 0x00 and svc_offset + 2 <= len(payload_bytes):
                        # Two-byte numeric NodeId
                        node_id = payload_bytes[svc_offset + 1]
                        service_name = OPCUA_SERVICES.get(node_id, f"Service_{node_id}")

            if not service_name:
                service_name = OPCUA_MSG_TYPES.get(msg_type, msg_type)
                if service_name in ("OpenSecureChannel", "CloseSecureChannel"):
                    service_name += "Request" if is_request else "Response"

            details: Dict[str, Any] = {"service": service_name, "recovered": True}
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                service_name or "OPC UA",
                details,
                f"{service_name} (recovered from multi-message TCP segment)",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

            # Update session with the recovered service name
            session_key = (client_ip, server_ip)
            self._update_session(
                session_key,
                "",
                "",
                "",
                "",
                service_name,
                None,
                "",
                0,
                is_request,
                server_port_val,
            )

            recovered_count += 1
            offset += msg_size

    def _extract_certificates(
        self,
        fields: Dict[str, str],
        server_ip: str,
        client_ip: str,
        is_request: bool,
    ) -> None:
        """Extract certificates from OPC UA packet fields.

        Args:
            fields: All fields from packet
            server_ip: Server IP address
            client_ip: Client IP address
            is_request: True if packet is a request
        """
        # Server certificate — from CreateSession/GetEndpoints response
        # (ServerCertificate field) or OPN response (security.scert).
        # For OPN responses (!is_request), security.scert holds the server cert.
        server_cert_hex = self._get_opcua_field(fields, "ServerCertificate")
        if not server_cert_hex and not is_request:
            server_cert_hex = self._get_opcua_field(fields, "security.scert")
        if server_cert_hex and server_ip not in self._certificates:
            # EK mode may return multiple certs comma-separated (list fields)
            for cert_part in server_cert_hex.split(","):
                cert_part = cert_part.strip()
                if not cert_part:
                    continue
                cert = self._parse_certificate(cert_part, "server")
                if cert:
                    self._certificates[server_ip] = cert
                    self.logger.debug(
                        f"OPC UA: Server certificate extracted from {server_ip}: "
                        f"CN={cert.subject_cn}, thumbprint={cert.thumbprint_sha1}"
                    )
                    break

        # Client certificate — from ActivateSession/CreateSession request
        # (ClientCertificate field) or OPN request (security.scert holds the
        # sender cert, which is the client cert for requests).
        client_cert_hex = self._get_opcua_field(fields, "ClientCertificate")
        if not client_cert_hex and is_request:
            client_cert_hex = self._get_opcua_field(fields, "security.scert")
        if client_cert_hex and client_ip not in self._certificates:
            for cert_part in client_cert_hex.split(","):
                cert_part = cert_part.strip()
                if not cert_part:
                    continue
                cert = self._parse_certificate(cert_part, "client")
                if cert:
                    self._certificates[client_ip] = cert
                    self.logger.debug(
                        f"OPC UA: Client certificate extracted from {client_ip}: "
                        f"CN={cert.subject_cn}"
                    )
                    break

    def _parse_certificate(self, cert_hex: str, _cert_type: str) -> Optional[OPCUACertificate]:
        """Parse X.509 certificate from hex string.

        Uses the central display_cert_info for X.509 parsing and security
        checks, with additional OPC UA-specific SAN extraction for
        application_uri.

        Args:
            cert_hex: Certificate in hex format (from tshark)
            _cert_type: "server" or "client" (unused, kept for API compat)

        Returns:
            OPCUACertificate or None if parsing fails
        """
        if not cert_hex:
            return None

        try:
            # Clean hex string (remove colons, spaces)
            cert_hex_clean = cert_hex.replace(":", "").replace(" ", "")

            # Reject OPC UA null certificate sentinel (ffffffff = -1 int32)
            # and any hex too short to be a real DER certificate
            if len(cert_hex_clean) < 64 or set(cert_hex_clean) <= {"f", "F", "0"}:
                return None

            cert_der = binascii.unhexlify(cert_hex_clean)

            # Central cert parsing + security checks (when --x509 is on)
            info = self._display_cert_info(cert_der, protocol="opcua")
            if info and "error" in info:
                return None

            # Calculate thumbprints
            sha1_thumb = hashlib.sha1(cert_der, usedforsecurity=False).hexdigest().upper()  # nosec B324
            sha256_thumb = hashlib.sha256(cert_der).hexdigest().upper()

            # When _x509 is off, _display_cert_info returns None — fall
            # back to lightweight parsing so OPC UA cert tracking still
            # works (thumbprints, subject/issuer CN, self-signed check).
            if not info:
                info = self._lightweight_cert_parse(cert_der)
                if not info:
                    return None

            cert_info = OPCUACertificate(
                thumbprint_sha1=sha1_thumb,
                thumbprint_sha256=sha256_thumb,
                raw_der=cert_der,
                subject_dn=info.get("subject", ""),
                issuer_dn=info.get("issuer", ""),
                not_before=info.get("not_before", ""),
                not_after=info.get("not_after", ""),
                is_self_signed=info.get("self_signed", False),
                key_size=info.get("key_size", 0),
                serial_number=str(info.get("serial", "")),
            )

            # Extract CN from subject DN
            for part in cert_info.subject_dn.split(","):
                if part.strip().upper().startswith("CN="):
                    cert_info.subject_cn = part.strip()[3:]
                    break

            # Extract CN from issuer DN
            for part in cert_info.issuer_dn.split(","):
                if part.strip().upper().startswith("CN="):
                    cert_info.issuer_cn = part.strip()[3:]
                    break

            # OPC UA-specific: extract Application URI from SAN extension
            extensions = info.get("extensions", {})
            san = extensions.get("san", {})
            if san and not cert_info.application_uri:
                for name in san.get("value", []):
                    if name.startswith("URI:urn:"):
                        cert_info.application_uri = name[4:]  # strip "URI:" prefix
                        break

            return cert_info

        except (binascii.Error, ValueError) as e:
            self.logger.debug(f"Failed to decode certificate hex: {e}")
            return None

    @staticmethod
    def _lightweight_cert_parse(cert_der: bytes) -> Optional[Dict[str, Any]]:
        """Minimal X.509 parse for cert tracking when --x509 is off.

        Extracts subject, issuer, validity, key size, and self-signed flag
        using the cryptography library directly (no security-check logging).
        """
        if not HAS_CRYPTO:
            return None
        try:
            from cryptography import x509 as x509_mod
            from cryptography.hazmat.primitives.asymmetric import ec, rsa

            cert = x509_mod.load_der_x509_certificate(cert_der)
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            key_size = 0
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                key_size = pub.key_size
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                key_size = pub.key_size

            # SAN extraction for application_uri
            extensions: Dict[str, Any] = {}
            try:
                san_ext = cert.extensions.get_extension_for_class(x509_mod.SubjectAlternativeName)
                san_values = []
                for name in san_ext.value:
                    # Cryptography returns typed objects; prefix with type
                    if hasattr(name, "value"):
                        val = name.value
                        type_name = type(name).__name__
                        if type_name == "UniformResourceIdentifier":
                            san_values.append(f"URI:{val}")
                        elif type_name == "DNSName":
                            san_values.append(f"DNS:{val}")
                        else:
                            san_values.append(str(val))
                    else:
                        san_values.append(str(name))
                extensions["san"] = {"value": san_values}
            except x509_mod.ExtensionNotFound as e:
                logger.debug(f"Failed to get san_ext: {e}")

            return {
                "subject": subject,
                "issuer": issuer,
                "serial": str(cert.serial_number),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "self_signed": subject == issuer,
                "key_size": key_size,
                "extensions": extensions,
            }
        except Exception as e:
            logger.debug(f"Operation failed: {e}")
            return None

    def _update_session(
        self,
        session_key: Tuple[str, str],
        endpoint_url: str,
        security_policy: str,
        security_mode: str,
        encryption_algorithm: str,
        service_name: str,
        user_auth: Optional[OPCUAUserAuth],
        current_user: str,
        token_lifetime: int,
        is_request: bool,
        server_port: int = 0,
    ) -> None:
        """Update session statistics."""
        now = datetime.now().isoformat()

        if session_key not in self.sessions:
            self.sessions[session_key] = OPCUASession(
                client_ip=session_key[0],
                server_ip=session_key[1],
                server_port=server_port,
                first_seen=now,
                last_seen=now,
            )

        session = self.sessions[session_key]
        session.last_seen = now
        if server_port and not session.server_port:
            session.server_port = server_port

        if endpoint_url and not session.endpoint_url:
            # EK mode may join multi-value fields with commas; take first value
            if "," in endpoint_url:
                endpoint_url = endpoint_url.split(",")[0].strip()
            session.endpoint_url = endpoint_url
        if security_policy or security_mode:
            # A security policy/mode field was actually present on the wire.
            session.security_observed = True
        if security_policy:
            simplified = self._simplify_security_policy(security_policy)
            if simplified and simplified != "None":
                # Real policy always overwrites (including initial "None")
                session.security_policy = simplified
            elif simplified and not session.security_policy:
                # Only set "None" if nothing was set yet
                session.security_policy = simplified
        if security_mode:
            if security_mode not in ("None", "Invalid"):
                session.security_mode = security_mode
            elif not session.security_mode:
                session.security_mode = security_mode
        if encryption_algorithm and not session.encryption_algorithm:
            session.encryption_algorithm = encryption_algorithm
        if current_user:
            session.current_user = current_user
        if token_lifetime > 0:
            session.token_lifetime = token_lifetime

        # Track user authentications
        if user_auth and user_auth.username:
            # Check for duplicate
            is_dup = any(
                ua.username == user_auth.username and ua.token_type == user_auth.token_type
                for ua in session.user_authentications
            )
            if not is_dup:
                session.user_authentications.append(user_auth)
                pw_msg = f" pass={user_auth.password}" if user_auth.password else ""
                self.logger.info(
                    f"OPC UA: User auth detected - {user_auth.token_type} "
                    f"user={user_auth.username}{pw_msg} @ {session.server_ip}:{session.server_port}"
                )
                # Surface to scanner credential loop
                if user_auth.token_type == "UserName":
                    self.credentials.append(
                        OPCUACredential(
                            username=user_auth.username,
                            password=user_auth.password,
                            server_ip=session.server_ip,
                            server_port=session.server_port,
                            client_ip=session.client_ip,
                            timestamp=user_auth.timestamp,
                        )
                    )

        if service_name:
            session.services_used.add(service_name)

            # Track operation counts
            if is_request:
                if "Read" in service_name:
                    session.read_count += 1
                elif "Write" in service_name:
                    session.write_count += 1
                elif "Browse" in service_name:
                    session.browse_count += 1

    def _track_endpoint(
        self,
        server_ip: str,
        endpoint_url: str,
        security_policy: str,
        security_mode: str,
        user_token: str,
    ) -> None:
        """Track discovered endpoint for a server."""
        if server_ip not in self._server_endpoints:
            self._server_endpoints[server_ip] = []

        # Check for duplicate
        for ep in self._server_endpoints[server_ip]:
            if ep.url == endpoint_url and ep.security_policy == security_policy:
                if user_token and user_token not in ep.user_token_types:
                    ep.user_token_types.append(user_token)
                return

        ep = OPCUAEndpoint(
            url=endpoint_url,
            security_policy=self._simplify_security_policy(security_policy),
            security_mode=security_mode,
            user_token_types=[user_token] if user_token else [],
        )
        self._server_endpoints[server_ip].append(ep)
        self.logger.debug(f"OPC UA: Endpoint discovered at {server_ip}: {endpoint_url}")

    def _simplify_security_policy(self, policy_uri: str) -> str:
        """Simplify security policy URI to short name."""
        for name, uri in SECURITY_POLICIES.items():
            if uri == policy_uri or policy_uri.endswith(f"#{name}"):
                return name
        return policy_uri.split("#")[-1] if "#" in policy_uri else policy_uri

    def _update_devices(
        self,
        client_ip: str,
        client_mac: str,
        server_ip: str,
        server_mac: str,
        session_key: Tuple[str, str],
    ) -> None:
        """Update device entries for client and server."""
        session = self.sessions[session_key]

        # Server device
        if is_valid_discovered_ip(server_ip):
            server_key = f"opcua-server:{server_ip}"
            app_info = self._app_info.get(server_ip, {})
            vendor = lookup_mac_vendor(server_mac) if server_mac else ""

            device, is_new = self._ensure_device(
                server_key,
                server_ip,
                mac=server_mac,
                name=app_info.get("product_name", ""),
                device_type="OPC UA Server",
                manufacturer=vendor,
            )
            device.opcua_passive_data = self._build_server_data(server_ip, session)
            if is_new:
                self.logger.debug(f"OPC UA: Server {server_ip} endpoint={session.endpoint_url}")

        # Client device
        if is_valid_discovered_ip(client_ip):
            client_key = f"opcua-client:{client_ip}"
            app_info = self._app_info.get(client_ip, {})
            vendor = lookup_mac_vendor(client_mac) if client_mac else ""

            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                mac=client_mac,
                name=app_info.get("product_name", ""),
                device_type="OPC UA Client (HMI/SCADA)",
                manufacturer=vendor,
            )
            device.opcua_passive_data = self._build_client_data(session)

    def _build_server_data(self, server_ip: str, session: OPCUASession) -> Dict[str, Any]:
        """Build opcua_passive_data dict for server."""
        app_info = self._app_info.get(server_ip, {})
        endpoints = self._server_endpoints.get(server_ip, [])
        cert = self._certificates.get(server_ip)

        data = {
            "role": "server",
            "endpoints": [
                {
                    "url": ep.url,
                    "security_policy": ep.security_policy,
                    "security_mode": ep.security_mode,
                    "user_token_types": ep.user_token_types,
                }
                for ep in endpoints
            ],
            "application_uri": app_info.get("application_uri", ""),
            "product_name": app_info.get("product_name", ""),
            "server_uri": app_info.get("server_uri", ""),
            "security": {
                "policy": session.security_policy,
                "mode": session.security_mode,
                "encryption_algorithm": session.encryption_algorithm,
                "token_lifetime": session.token_lifetime,
            },
            "user_authentications": [
                {
                    "token_type": ua.token_type,
                    "policy_id": ua.policy_id,
                    "username": ua.username,
                    "encryption_algorithm": ua.encryption_algorithm,
                    "timestamp": ua.timestamp,
                }
                for ua in session.user_authentications
            ],
            "current_user": session.current_user,
            "services_seen": sorted(list(session.services_used)),
            "read_operations": session.read_count,
            "write_operations": session.write_count,
            "browse_operations": session.browse_count,
            "protocol": "OPC UA",
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
        }

        # Add certificate info if available
        if cert:
            data["certificate"] = self._cert_to_dict(cert)

        return data

    def _build_client_data(self, session: OPCUASession) -> Dict[str, Any]:
        """Build opcua_passive_data dict for client."""
        app_info = self._app_info.get(session.client_ip, {})
        cert = self._certificates.get(session.client_ip)

        data = {
            "role": "client",
            "connected_server": session.server_ip,
            "endpoint_url": session.endpoint_url,
            "application_uri": app_info.get("application_uri", ""),
            "product_name": app_info.get("product_name", ""),
            "security": {
                "policy": session.security_policy,
                "mode": session.security_mode,
                "encryption_algorithm": session.encryption_algorithm,
                "token_lifetime": session.token_lifetime,
            },
            "user_authentications": [
                {
                    "token_type": ua.token_type,
                    "policy_id": ua.policy_id,
                    "username": ua.username,
                    "encryption_algorithm": ua.encryption_algorithm,
                    "timestamp": ua.timestamp,
                }
                for ua in session.user_authentications
            ],
            "current_user": session.current_user,
            "services_used": sorted(list(session.services_used)),
            "read_operations": session.read_count,
            "write_operations": session.write_count,
            "browse_operations": session.browse_count,
            "protocol": "OPC UA",
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
        }

        # Add certificate info if available
        if cert:
            data["certificate"] = self._cert_to_dict(cert)

        return data

    def _cert_to_dict(self, cert: OPCUACertificate) -> Dict[str, Any]:
        """Convert OPCUACertificate to serializable dict."""
        return {
            "subject_cn": cert.subject_cn,
            "subject_dn": cert.subject_dn,
            "issuer_cn": cert.issuer_cn,
            "issuer_dn": cert.issuer_dn,
            "serial_number": cert.serial_number,
            "not_before": cert.not_before,
            "not_after": cert.not_after,
            "thumbprint_sha1": cert.thumbprint_sha1,
            "thumbprint_sha256": cert.thumbprint_sha256,
            "application_uri": cert.application_uri,
            "is_self_signed": cert.is_self_signed,
            "key_size": cert.key_size,
        }

    def _extract_typed_values(self, opcua_layer: Any, all_fields: Dict[str, str]) -> str:
        """Extract typed data values from OPC UA ReadResponse/WriteRequest.

        Tries typed value fields from tshark's opcua dissector:
        - opcua.Boolean, opcua.Float, opcua.Double
        - opcua.Int16, opcua.Int32, opcua.Int64
        - opcua.UInt16, opcua.UInt32, opcua.UInt64
        - opcua.String, opcua.Value
        - opcua.Byte, opcua.SByte

        Returns a compact value summary or "" if no values found.
        """
        # Priority order: specific typed fields first, then generic Value
        _VALUE_FIELDS = [
            "opcua.Boolean",
            "opcua.Float",
            "opcua.Double",
            "opcua.Int16",
            "opcua.Int32",
            "opcua.Int64",
            "opcua.UInt16",
            "opcua.UInt32",
            "opcua.UInt64",
            "opcua.String",
            "opcua.Byte",
            "opcua.SByte",
            "opcua.Value",
        ]

        values: List[str] = []
        for field_name in _VALUE_FIELDS:
            raw = all_fields.get(field_name)
            if raw is not None and str(raw).strip():
                val = str(raw).strip()
                # Tag the type for clarity
                short_type = field_name.split(".")[-1]
                values.append(f"{short_type}={val}")

        if not values:
            # Try layer attribute access for fields not in all_fields
            for attr_name, type_label in [
                ("Boolean", "Bool"),
                ("Float", "Float"),
                ("Double", "Dbl"),
                ("Int32", "Int32"),
                ("UInt32", "UInt32"),
                ("String", "Str"),
                ("Value", "Val"),
            ]:
                raw = self.get_field(opcua_layer, attr_name, None)
                if raw is not None:
                    # Try to get multiple values via all_fields
                    try:
                        for f in getattr(opcua_layer, attr_name).all_fields:
                            values.append(f"{type_label}={f.show}")
                    except Exception:
                        values.append(f"{type_label}={raw}")
                    if values:
                        break

        if not values:
            return ""

        return ", ".join(values)

    def _extract_node_ids(self, opcua_layer: Any) -> str:
        """Extract node IDs from OPC UA layer.

        Formats as standard OPC UA NodeId: ``ns=1;s=Boolean.Variable``
        or ``ns=0;i=85``.  Omits ``ns=`` prefix when namespace is 0.

        Supports both PDML mode (parses "Identifier String:" lines) and
        EK mode (reads ``nodeid_string`` / ``nodeid_numeric`` attributes).
        """
        string_ids: List[str] = []
        numeric_ids: List[str] = []

        # EK mode namespace indices (parallel array to nodeid_string/numeric)
        raw_ns = getattr(opcua_layer, "nodeid_nsindex", None)
        ns_vals: List[int] = []
        if raw_ns:
            ns_list = raw_ns if isinstance(raw_ns, list) else [raw_ns]
            for v in ns_list:
                try:
                    ns_vals.append(int(v))
                except (ValueError, TypeError):
                    ns_vals.append(0)

        # EK mode: getattr returns the values directly (str or list)
        raw_str = getattr(opcua_layer, "nodeid_string", None)
        if raw_str:
            vals = raw_str if isinstance(raw_str, list) else [raw_str]
            for idx, v in enumerate(vals):
                s = str(v).strip()
                if s and s != "[OpcUa Null String]":
                    ns = ns_vals[idx] if idx < len(ns_vals) else 0
                    if ns:
                        string_ids.append(f"ns={ns};s={s}")
                    else:
                        string_ids.append(s)

        raw_num = getattr(opcua_layer, "nodeid_numeric", None)
        if raw_num and not string_ids:
            vals = raw_num if isinstance(raw_num, list) else [raw_num]
            for idx, v in enumerate(vals):
                s = str(v).strip()
                if s and s != "0" and "(" not in s:
                    ns = ns_vals[idx] if idx < len(ns_vals) else 0
                    if ns:
                        numeric_ids.append(f"ns={ns};i={s}")
                    else:
                        numeric_ids.append(f"i={s}")

        # PDML fallback: parse layer text representation
        if not string_ids and not numeric_ids:
            try:
                layer_text = str(opcua_layer)
            except Exception as e:
                self.logger.debug(f"Failed to get layer_text: {e}")
                return ""
            for line in layer_text.split("\n"):
                stripped = line.strip()
                if stripped.startswith("Identifier String:"):
                    val = stripped.split(":", 1)[1].strip()
                    if val and val != "[OpcUa Null String]":
                        string_ids.append(val)
                elif stripped.startswith("Identifier Numeric:"):
                    val = stripped.split(":", 1)[1].strip()
                    if "(" not in val and val != "0":
                        numeric_ids.append(f"i={val}")

        # Prefer string IDs
        if string_ids:
            if len(string_ids) == 1:
                return string_ids[0]
            if len(string_ids) <= 2:
                return ", ".join(string_ids)
            return f"{string_ids[0]} (+{len(string_ids) - 1} nodes)"

        # Fall back to numeric IDs
        if numeric_ids:
            if len(numeric_ids) == 1:
                return numeric_ids[0]
            if len(numeric_ids) <= 2:
                return ", ".join(numeric_ids)
            return f"{numeric_ids[0]} (+{len(numeric_ids) - 1} nodes)"

        return ""

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        service = d.get("service", "")

        # Build context-dependent data column
        data_parts: List[str] = []
        if d.get("endpoint"):
            data_parts.append(d["endpoint"])
        if d.get("security_policy"):
            data_parts.append(f"sec={d['security_policy']}")
        if d.get("security_mode"):
            data_parts.append(f"mode={d['security_mode']}")
        # Show sender certificate CN on OPN rows (looked up at display time)
        if service in (
            "OpenSecureChannel",
            "OpenSecureChannelRequest",
            "OpenSecureChannelResponse",
        ):
            sender_cert = self._certificates.get(ix.src_ip)
            if sender_cert and sender_cert.subject_cn:
                data_parts.append(f"cert={sender_cert.subject_cn}")
        if d.get("username"):
            data_parts.append(f"user={d['username']}")
        if d.get("password"):
            data_parts.append(f"pass={d['password']}")
        if d.get("token_type"):
            data_parts.append(f"token={d['token_type']}")
        if d.get("node_ids"):
            data_parts.append(d["node_ids"])
        if d.get("data_values"):
            data_parts.append(d["data_values"])
        if d.get("subscription_id"):
            data_parts.append(f"sub={d['subscription_id']}")
        if d.get("status"):
            data_parts.append(f"status={d['status']}")

        return [service, " | ".join(data_parts)]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed OPC UA sessions.

        Returns flat dicts (no nested dicts) so the base-class table
        renderer can display every value directly.
        """
        summaries = []
        for session in self.sessions.values():
            server_cert = self._certificates.get(session.server_ip)
            client_cert = self._certificates.get(session.client_ip)
            row: Dict[str, Any] = {
                "client": session.client_ip,
                "server": session.server_ip,
                "server_port": session.server_port,
                "endpoint": session.endpoint_url,
                "security_policy": session.security_policy,
                "security_mode": session.security_mode,
                "server_cert": server_cert.subject_cn if server_cert else "",
                "client_cert": client_cert.subject_cn if client_cert else "",
                "services": sorted(list(session.services_used)),
                "read_count": session.read_count,
                "write_count": session.write_count,
                "browse_count": session.browse_count,
                "first_seen": session.first_seen,
                "last_seen": session.last_seen,
            }
            summaries.append(row)
        return summaries

    def get_user_authentications(self) -> List[Dict[str, Any]]:
        """Get all observed user authentications.

        Returns:
            List of dicts with authentication details
        """
        auths = []
        for session in self.sessions.values():
            for ua in session.user_authentications:
                auths.append(
                    {
                        "client_ip": session.client_ip,
                        "server_ip": session.server_ip,
                        "token_type": ua.token_type,
                        "policy_id": ua.policy_id,
                        "username": ua.username,
                        "password": ua.password,
                        "encryption_algorithm": ua.encryption_algorithm,
                        "timestamp": ua.timestamp,
                    }
                )
        return auths

    def get_plaintext_credentials(self) -> List[Dict[str, Any]]:
        """Get sessions where credentials may be exposed.

        Returns sessions using UserName token without encryption.
        """
        exposed = []
        for session in self.sessions.values():
            for ua in session.user_authentications:
                if ua.token_type == "UserName":
                    # Check if encryption is weak or missing
                    is_exposed = (
                        not ua.encryption_algorithm
                        or session.security_policy in ("None", "")
                        or session.security_mode in ("None", "Invalid", "")
                    )
                    if is_exposed:
                        exposed.append(
                            {
                                "client_ip": session.client_ip,
                                "server_ip": session.server_ip,
                                "username": ua.username,
                                "password": ua.password,
                                "security_policy": session.security_policy,
                                "security_mode": session.security_mode,
                                "encryption_algorithm": ua.encryption_algorithm or "None",
                                "risk": "Username authentication without encryption",
                            }
                        )
        return exposed

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write operations (potentially dangerous)."""
        return [
            {
                "client": session.client_ip,
                "server": session.server_ip,
                "server_port": session.server_port,
                "endpoint": session.endpoint_url,
                "write_count": session.write_count,
                "security_policy": session.security_policy,
            }
            for session in self.sessions.values()
            if session.write_count > 0
        ]

    def get_insecure_connections(self) -> List[Dict[str, Any]]:
        """Get sessions using insecure configurations."""
        insecure = []
        for session in self.sessions.values():
            # Only judge sessions whose security config was actually observed.
            # An empty-string default means no OPN/GetEndpoints was captured
            # (mid-stream / already-encrypted flow) — "not observed" is not
            # evidence of "insecure", so don't emit a false-unsafe verdict.
            if not session.security_observed:
                continue
            issues = []
            if session.security_policy in ("None", ""):
                issues.append("No security policy")
            if session.security_mode in ("None", "Invalid", ""):
                issues.append("No message security")
            if issues:
                insecure.append(
                    {
                        "client": session.client_ip,
                        "server": session.server_ip,
                        "server_port": session.server_port,
                        "endpoint": session.endpoint_url,
                        "issues": issues,
                    }
                )
        return insecure

    def get_discovered_endpoints(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all discovered endpoints by server."""
        return {
            server_ip: [
                {
                    "url": ep.url,
                    "security_policy": ep.security_policy,
                    "security_mode": ep.security_mode,
                    "user_token_types": ep.user_token_types,
                }
                for ep in endpoints
            ]
            for server_ip, endpoints in self._server_endpoints.items()
        }

    def get_certificates(self) -> Dict[str, Dict[str, Any]]:
        """Get all extracted certificates by IP address.

        Returns:
            Dict mapping IP addresses to certificate information
        """
        return {ip: self._cert_to_dict(cert) for ip, cert in self._certificates.items()}

    def get_certificate_issues(self) -> List[Dict[str, Any]]:
        """Get certificates with potential security issues.

        Checks for:
        - Self-signed certificates
        - Expired certificates
        - Weak key sizes (< 2048 bits)
        - Missing application URI

        Returns:
            List of dicts with IP and issue descriptions
        """
        issues = []
        now = datetime.now()

        for ip, cert in self._certificates.items():
            cert_issues = []

            if cert.is_self_signed:
                cert_issues.append("Self-signed certificate")

            if cert.not_after:
                try:
                    expiry = datetime.fromisoformat(cert.not_after.replace("Z", "+00:00"))
                    if expiry.replace(tzinfo=None) < now:
                        cert_issues.append("Certificate expired")
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get expiry: {e}")

            if cert.key_size and cert.key_size < 2048:
                cert_issues.append(f"Weak key size: {cert.key_size} bits")

            if not cert.application_uri:
                cert_issues.append("Missing OPC UA Application URI in SAN")

            if cert_issues:
                issues.append(
                    {
                        "ip": ip,
                        "subject_cn": cert.subject_cn,
                        "thumbprint": cert.thumbprint_sha1,
                        "issues": cert_issues,
                    }
                )

        return issues

    def harvest(self) -> Dict[str, Any]:
        """Return OPC UA tables, results, and alerts for the scanner pipeline.

        Calls ``super().harvest()`` to get auto-generated tables (sessions,
        write alerts, interaction operations table) and then adds OPC UA-specific
        output: endpoints table, certificate results, and security alerts.
        """
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": [], "results": {}}

        tables = result.setdefault("tables", [])
        alerts = result.setdefault("alerts", [])
        results = result.setdefault("results", {})

        # Merge OPC UA certificates into unified TLS results format
        opcua_certs = self.get_certificates()
        if opcua_certs:
            tls_certs: Dict[str, Dict[str, Any]] = {}
            for ip, cert_dict in opcua_certs.items():
                thumb = cert_dict.get("thumbprint_sha256", ip)
                tls_certs[thumb] = {
                    "common_name": cert_dict.get("subject_cn", ""),
                    "subject": cert_dict.get("subject_dn", ""),
                    "issuer": cert_dict.get("issuer_dn", ""),
                    "thumbprint": thumb,
                    "self_signed": cert_dict.get("is_self_signed", False),
                    "not_before": cert_dict.get("not_before", ""),
                    "not_after": cert_dict.get("not_after", ""),
                    "key_size": cert_dict.get("key_size", 0),
                    "source": "opcua",
                }
            results["tls_certificates_merge"] = tls_certs

        # OPC UA Endpoints table (prepend before operations table)
        endpoints = self.get_discovered_endpoints()
        if endpoints:
            results.setdefault("opcua", {})["endpoints"] = endpoints
            ep_headers = ["Server", "Endpoint URL", "Security Policy", "Mode", "Token Types"]
            ep_rows = []
            for server_ip, eps in endpoints.items():
                for ep in eps:
                    ep_rows.append(
                        [
                            server_ip,
                            ep["url"],
                            ep.get("security_policy", ""),
                            ep.get("security_mode", ""),
                            ", ".join(ep.get("user_token_types", [])),
                        ]
                    )
            if ep_rows:
                tables.insert(
                    0,
                    {
                        "headers": ep_headers,
                        "rows": ep_rows,
                        "title": f"OPC UA Endpoints ({len(ep_rows)})",
                    },
                )

        # OPC UA certificate summary table (gated behind -X / --x509)
        if opcua_certs and getattr(self, "_x509", False):
            cert_headers = [
                "IP",
                "CN",
                "Issuer CN",
                "Key",
                "Self-Signed",
                "Valid Until",
                "Thumbprint (SHA1)",
            ]
            cert_rows = []
            for ip, cd in opcua_certs.items():
                cert_rows.append(
                    [
                        ip,
                        cd.get("subject_cn", ""),
                        cd.get("issuer_cn", ""),
                        f"{cd.get('key_size', '?')}b",
                        "Yes" if cd.get("is_self_signed") else "No",
                        cd.get("not_after", ""),
                        cd.get("thumbprint_sha1", ""),
                    ]
                )
            tables.append(
                {
                    "headers": cert_headers,
                    "rows": cert_rows,
                    "title": f"OPC UA Certificates ({len(cert_rows)})",
                }
            )

            # Certificate security alerts
            for issue in self.get_certificate_issues():
                for desc in issue.get("issues", []):
                    alerts.append(
                        {
                            "level": "warning",
                            "message": (
                                f"OPC UA CERT: {issue['ip']} CN={issue['subject_cn']} — {desc}"
                            ),
                        }
                    )

        # OPC UA-specific security alerts
        insecure = self.get_insecure_connections()
        for conn in insecure:
            issues = ", ".join(conn.get("issues", []))
            server_str = conn["server"]
            if conn.get("server_port"):
                server_str = f"{server_str}:{conn['server_port']}"
            alerts.append(
                {
                    "level": "fail",
                    "message": (f"OPC UA INSECURE: {conn['client']} -> {server_str} [{issues}]"),
                }
            )

        plaintext = self.get_plaintext_credentials()
        for cred in plaintext:
            alerts.append(
                {
                    "level": "fail",
                    "message": (
                        f"OPC UA EXPOSED: user={cred['username']}"
                        f"{' pass=' + cred['password'] if cred.get('password') else ''}"
                        f" @ {cred['server_ip']}"
                        f" policy={cred['security_policy']} mode={cred['security_mode']}"
                    ),
                }
            )

        return result
