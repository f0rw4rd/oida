"""OPC UA Protocol Fuzzer"""

from typing import List

from asyncua import ua
from asyncua.ua.ua_binary import nodeid_to_binary
from boofuzz import Block, Byte, DWord, Group, QWord, RandomData, Request, Size, Static, Word

from ..core.base_fuzzer import BaseFuzzer, CommonState, RequestInfo
from ..core.session.sequence import SequenceConfig, SequenceDirection
from ..core.session.state_context import StateContext
from ..core.session.state_machine import ProtocolState, StateMachine, StateType
from ..primitives.dynamic import DynamicBytes, DynamicDWord, SmartString
from ..primitives.smart_string import StringContext
from .opcua_constants import (
    OPCUAMessageTypes,
    OPCUASecurityPolicies,
    OPCUANodeIdTypes,
    OPCUAServiceIds,
    OPCUASecurityTokenRequestType,
    OPCUAMessageSecurityMode,
    OPCUATimestampsToReturn,
)


class OPCUAFuzzer(BaseFuzzer):
    """Comprehensive OPC UA protocol fuzzer"""

    # Hello/Acknowledge + session handshake: replies gate progress.
    STATEFUL = True

    # Default monitor for OPC UA protocol
    # Uses Hello/Acknowledge handshake for health checking
    DEFAULT_MONITORS = "opcua"

    PROTOCOL_OPTIONS = {
        "security_policy": {
            "type": str,
            "default": "None",
            "description": "Security policy (None, Basic256Sha256)",
            "choices": ["None", "Basic256Sha256"],
        },
        "security_mode": {
            "type": str,
            "default": "None",
            "description": "Security mode (None, Sign, SignAndEncrypt)",
            "choices": ["None", "Sign", "SignAndEncrypt"],
        },
        "endpoint_url": {
            "type": str,
            "default": "",
            "description": "OPC UA endpoint URL (default: opc.tcp://host:port)",
        },
        "application_uri": {
            "type": str,
            "default": "urn:oida:opcua:fuzzer",
            "description": "Application URI for client identification",
        },
        "product_uri": {
            "type": str,
            "default": "urn:oida:opcua:fuzzer",
            "description": "Product URI for client identification",
        },
        "application_name": {
            "type": str,
            "default": "OIDA OPC UA Fuzzer",
            "description": "Application name for client identification",
        },
        "receive_buffer_size": {
            "type": int,
            "default": 65535,
            "description": "Receive buffer size in bytes",
        },
        "send_buffer_size": {
            "type": int,
            "default": 65535,
            "description": "Send buffer size in bytes",
        },
        "max_message_size": {
            "type": int,
            "default": 0,
            "description": "Maximum message size (0 = unlimited)",
        },
        "max_chunk_count": {
            "type": int,
            "default": 0,
            "description": "Maximum chunk count (0 = unlimited)",
        },
        "use_session": {
            "type": bool,
            "default": False,
            "description": "Establish full session before fuzzing (HEL→OPN→Session)",
        },
        "opcua_username": {
            "type": str,
            "default": None,
            "description": "OPC UA username for authentication (None = anonymous)",
        },
        "opcua_password": {
            "type": str,
            "default": None,
            "description": "OPC UA password for authentication (None = anonymous)",
        },
    }

    def __init__(self, config, connection_factory=None):
        # State tracking attributes for state machine
        self.secure_channel_id = 0
        self.token_id = 0
        self.auth_token = None

        # StateContext for carrying state between transitions
        self._state_context = StateContext()

        # Sequence managers for SequenceNumber and RequestId tracking
        seq_mgr = self._state_context.get_sequence_manager("opcua")
        seq_mgr.add_sequence(
            SequenceConfig(
                name="sequence_number",
                initial=1,
                max_value=0xFFFFFFFF,
                increment=1,
                direction=SequenceDirection.SEND,
                wrap_behavior="modulo",
                fuzzable=True,
            )
        )
        seq_mgr.add_sequence(
            SequenceConfig(
                name="request_id",
                initial=1,
                max_value=0xFFFFFFFF,
                increment=1,
                direction=SequenceDirection.SEND,
                wrap_behavior="modulo",
                fuzzable=True,
            )
        )

        # Session mode
        self.use_session = config.get_option("use_session", False)

        # Authentication credentials
        self.opcua_username = config.get_option("opcua_username", None)
        self.opcua_password = config.get_option("opcua_password", None)

        super().__init__(config, connection_factory)

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Quick Coverage - touches all operations once
            RequestInfo(
                "OPCUA_Quick_Coverage",
                "Fast sweep of all OPC UA operations",
                "quick",
                requires_state="CONNECTED",
            ),
            # Baseline - pre-channel Hello/Acknowledge
            RequestInfo(
                "OPCUA_Baseline",
                "Hello/Acknowledge baseline test",
                "baseline",
                requires_state="CONNECTED",
            ),
            # Discovery (safe, read-only) - needs channel only
            RequestInfo(
                "OPCUA_Discovery",
                "Discovery services (GetEndpoints, FindServers)",
                "discovery",
                requires_state="SECURE_CHANNEL",
            ),
            # Secure Channel
            RequestInfo(
                "OPCUA_SecureChannel",
                "Secure channel establishment (OPN)",
                "channel",
                requires_state="HELLO_COMPLETE",
            ),
            # Session Management
            RequestInfo(
                "OPCUA_Session",
                "Session services (Create, Activate, Close)",
                "session",
                requires_state="SECURE_CHANNEL",
            ),
            # Authentication Fuzzing
            RequestInfo(
                "OPCUA_Auth",
                "Authentication fuzzing (Username/Password token attacks)",
                "auth",
                requires_state="SECURE_CHANNEL",
            ),
            # Read Operations (safe) - needs active session
            RequestInfo(
                "OPCUA_Read", "Attribute read operations", "read", requires_state="SESSION_ACTIVE"
            ),
            RequestInfo(
                "OPCUA_Browse",
                "Browse and navigation operations",
                "read",
                requires_state="SESSION_ACTIVE",
            ),
            # OPCUA_Query removed in 1.0: was advertised by --list-requests but
            # no corresponding Request("OPCUA_Query") definition existed in the
            # fuzzer's session graph. Re-add once a real Query implementation
            # lands.
            RequestInfo(
                "OPCUA_History_Read",
                "Historical data read",
                "read",
                requires_state="SESSION_ACTIVE",
            ),
            # Subscription (resource intensive) - needs active session
            RequestInfo(
                "OPCUA_Subscription",
                "Subscription management",
                "subscription",
                requires_state="SESSION_ACTIVE",
            ),
            RequestInfo(
                "OPCUA_MonitoredItems",
                "Monitored items management",
                "subscription",
                requires_state="SESSION_ACTIVE",
            ),
            RequestInfo(
                "OPCUA_Publish",
                "Publish/republish operations",
                "subscription",
                requires_state="SESSION_ACTIVE",
            ),
            # Write Operations (dangerous) - needs active session
            RequestInfo(
                "OPCUA_Write",
                "Attribute write operations",
                "write",
                requires_state="SESSION_ACTIVE",
            ),
            RequestInfo(
                "OPCUA_History_Update",
                "Historical data update",
                "write",
                requires_state="SESSION_ACTIVE",
            ),
            RequestInfo(
                "OPCUA_Call", "Method call invocation", "write", requires_state="SESSION_ACTIVE"
            ),
            RequestInfo(
                "OPCUA_NodeManagement",
                "Node/reference add/delete",
                "write",
                requires_state="SESSION_ACTIVE",
            ),
            # Attack Patterns - any state
            RequestInfo(
                "OPCUA_Boundary",
                "Message size and field boundary testing",
                "attack",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "OPCUA_ChunkFlood",
                "Incomplete chunk flooding (DoS)",
                "attack",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "OPCUA_NestedMessage",
                "Deeply nested message attack",
                "attack",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "OPCUA_Malformed",
                "Malformed message testing",
                "attack",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "OPCUA_CertAttack",
                "Certificate chain attack (CVE-2022-37013)",
                "attack",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "OPCUA_ExtensionObject",
                "ExtensionObject TypeId fuzzing (vendor-reserved 0x6XXX range)",
                "attack",
                requires_state="SESSION_ACTIVE",
            ),
            # Three new in §4 sweep (2026-06-03):
            RequestInfo(
                "OPCUA_NodeIdEncodingOverflow",
                "NodeId encoding byte out of spec range (reserved 6-15, ext flags)",
                "attack",
                requires_state="SESSION_ACTIVE",
            ),
            RequestInfo(
                "OPCUA_MalformedCert",
                "OpenSecureChannel with truncated/oversized/wrong-tag certificate",
                "attack",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "OPCUA_State_Confusion",
                "Session-required services issued pre-session (state-machine attack)",
                "attack",
                requires_state="SECURE_CHANNEL",
            ),
        ]

    def _create_socket(self):
        """Create TCP socket for OPC UA"""
        from boofuzz import TCPSocketConnection

        return TCPSocketConnection(
            self.config.target_ip,
            self.config.target_port or 4840,
            **self._timeout_overrides(),
        )

    def _get_endpoint_url(self) -> str:
        """Get OPC UA endpoint URL"""
        custom_url = self.config.get_option("endpoint_url", "")
        if custom_url:
            return custom_url
        return f"opc.tcp://{self.config.target_ip}:{self.config.target_port or 4840}"

    def _auth_token_bytes(self) -> bytes:
        """Return the authentication token as a binary NodeId.

        Handles both ua.NodeId (from asyncua Client) and raw bytes.
        Falls back to null NodeId if no session is active.
        """
        if (
            self.auth_token
            and isinstance(self.auth_token, ua.NodeId)
            and self.auth_token != ua.NodeId()
        ):
            return nodeid_to_binary(self.auth_token)
        if (
            self.auth_token
            and isinstance(self.auth_token, bytes)
            and self.auth_token != b"\x00" * len(self.auth_token)
        ):
            return self.auth_token
        return bytes([OPCUANodeIdTypes.TWO_BYTE, 0])  # null NodeId

    def _next_sequence_number(self) -> int:
        """Get current sequence number and increment for next use."""
        seq_mgr = self._state_context.get_sequence_manager("opcua")
        return seq_mgr.get_and_increment("sequence_number")

    def _next_request_id(self) -> int:
        """Get current request ID and increment for next use."""
        seq_mgr = self._state_context.get_sequence_manager("opcua")
        return seq_mgr.get_and_increment("request_id")

    def _create_msg_header(self, service_id, authenticated=False):
        """Create the common MSG body prefix: security header + sequence + TypeId + RequestHeader.

        Returns a tuple of boofuzz children to be unpacked with * inside a Block.
        Uses DynamicDWord for SecureChannelId/TokenId and SequenceNumber/RequestId
        so live state values propagate into fuzzed messages.
        """
        return (
            DynamicDWord("SecureChannelId", lambda: self.secure_channel_id, endian="<"),
            DynamicDWord("TokenId", lambda: self.token_id, endian="<"),
            DynamicDWord("SequenceNumber", lambda: self._next_sequence_number(), endian="<"),
            DynamicDWord("RequestId", lambda: self._next_request_id(), endian="<"),
            Static("TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
            Byte("TypeId_Namespace", 0x00),
            Word("TypeId_Identifier", service_id, endian="<"),
            self._create_request_header(authenticated=authenticated),
        )

    def _create_request_header(self, authenticated=False) -> Block:
        """Create OPC UA RequestHeader structure.

        Args:
            authenticated: When True, use DynamicBytes for the auth token
                so the live session token is injected at render time.
        """
        if authenticated:
            auth_children = (DynamicBytes("AuthToken", self._auth_token_bytes),)
        else:
            auth_children = (
                # Null NodeId (TwoByte with id=0)
                Static("AuthToken_Type", bytes([OPCUANodeIdTypes.TWO_BYTE])),
                Byte("AuthToken_Id", 0x00),
            )
        return Block(
            "RequestHeader",
            children=(
                *auth_children,
                # Timestamp - fixed Windows FILETIME (100ns since 1601)
                QWord("Timestamp", 132500000000000000, endian="<"),
                # RequestHandle
                DWord("RequestHandle", 1, endian="<"),
                # ReturnDiagnostics
                DWord("ReturnDiagnostics", 0, endian="<"),
                # AuditEntryId - null string
                DWord("AuditEntryId_Length", 0xFFFFFFFF, endian="<"),
                # TimeoutHint
                DWord("TimeoutHint", 10000, endian="<"),
                # AdditionalHeader - null ExtensionObject
                Static("AdditionalHeader_TypeId", bytes([OPCUANodeIdTypes.TWO_BYTE, 0])),
                Byte("AdditionalHeader_Encoding", 0x00),
            ),
        )

    def _create_user_identity_token(self, fuzzable: bool = False) -> tuple:
        """Create OPC UA UserIdentityToken structure.

        Returns a tuple of boofuzz children for either:
        - AnonymousIdentityToken (TypeId 321) when no credentials configured
        - UsernameIdentityToken (TypeId 322) when username/password are set

        Args:
            fuzzable: When True, use SmartString with CREDENTIAL context for
                username/password fields to enable auth fuzzing.

        OPC UA UsernameIdentityToken structure (Part 4, Section 7.36.4):
            TypeId: NodeId (322 for binary encoding)
            Encoding: Byte (0x01 = has body)
            Body:
                PolicyId: String (references UserTokenPolicy from CreateSession)
                UserName: String
                Password: ByteString
                EncryptionAlgorithm: String (null for no encryption)
        """
        if self.opcua_username is None:
            # Anonymous authentication - TypeId 321
            return (
                # TypeId for AnonymousIdentityToken (321)
                Static("UserIdentityToken_TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                Byte("UserIdentityToken_TypeId_Namespace", 0x00),
                Word("UserIdentityToken_TypeId_Identifier", 321, endian="<"),
                # Encoding (has body)
                Byte("UserIdentityToken_Encoding", 0x01),
                # Body length (AnonymousIdentityToken has only PolicyId which we leave null)
                DWord("UserIdentityToken_Body_Length", 4, endian="<"),
                # PolicyId - null string (server picks default anonymous policy)
                DWord("PolicyId_Length", 0xFFFFFFFF, endian="<"),
            )
        else:
            # Username/Password authentication - TypeId 322
            username = self.opcua_username or ""
            password = self.opcua_password or ""

            if fuzzable:
                # Fuzzable version with SmartString CREDENTIAL context
                return (
                    # TypeId for UsernameIdentityToken (322)
                    Static(
                        "UserIdentityToken_TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])
                    ),
                    Byte("UserIdentityToken_TypeId_Namespace", 0x00),
                    Word("UserIdentityToken_TypeId_Identifier", 322, endian="<"),
                    # Encoding (has body)
                    Byte("UserIdentityToken_Encoding", 0x01),
                    # Body length - calculated by Size primitive
                    Size(
                        "UserIdentityToken_Body_Length",
                        block_name="UserIdentityToken_Body",
                        length=4,
                        endian="<",
                        inclusive=False,
                    ),
                    Block(
                        "UserIdentityToken_Body",
                        children=(
                            # PolicyId - null string (server uses default username policy)
                            DWord("PolicyId_Length", 0xFFFFFFFF, endian="<"),
                            # UserName - length-prefixed string with CREDENTIAL fuzzing
                            Size(
                                "UserName_Length",
                                block_name="UserName_Data",
                                length=4,
                                endian="<",
                                inclusive=False,
                            ),
                            Block(
                                "UserName_Data",
                                children=(
                                    SmartString(
                                        "UserName",
                                        username,
                                        max_len=256,
                                        context=StringContext.CREDENTIAL,
                                    ),
                                ),
                            ),
                            # Password - length-prefixed ByteString with CREDENTIAL fuzzing
                            Size(
                                "Password_Length",
                                block_name="Password_Data",
                                length=4,
                                endian="<",
                                inclusive=False,
                            ),
                            Block(
                                "Password_Data",
                                children=(
                                    SmartString(
                                        "Password",
                                        password,
                                        max_len=256,
                                        context=StringContext.CREDENTIAL,
                                    ),
                                ),
                            ),
                            # EncryptionAlgorithm - null (no encryption for Policy None)
                            DWord("EncryptionAlgorithm_Length", 0xFFFFFFFF, endian="<"),
                        ),
                    ),
                )
            else:
                # Non-fuzzable baseline version
                username_bytes = username.encode("utf-8")
                password_bytes = password.encode("utf-8")
                # Calculate body length: PolicyId(4) + UserName(4+len) + Password(4+len) + EncAlgo(4)
                body_length = 4 + 4 + len(username_bytes) + 4 + len(password_bytes) + 4
                return (
                    # TypeId for UsernameIdentityToken (322)
                    Static(
                        "UserIdentityToken_TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])
                    ),
                    Byte("UserIdentityToken_TypeId_Namespace", 0x00),
                    Word("UserIdentityToken_TypeId_Identifier", 322, endian="<"),
                    # Encoding (has body)
                    Byte("UserIdentityToken_Encoding", 0x01),
                    # Body length
                    DWord("UserIdentityToken_Body_Length", body_length, endian="<"),
                    # PolicyId - null string
                    DWord("PolicyId_Length", 0xFFFFFFFF, endian="<"),
                    # UserName
                    DWord("UserName_Length", len(username_bytes), endian="<"),
                    Static("UserName", username_bytes),
                    # Password
                    DWord("Password_Length", len(password_bytes), endian="<"),
                    Static("Password", password_bytes),
                    # EncryptionAlgorithm - null
                    DWord("EncryptionAlgorithm_Length", 0xFFFFFFFF, endian="<"),
                )

    # ========================================================================
    # STATE MACHINE IMPLEMENTATION
    # ========================================================================

    def _define_state_machine(self) -> None:
        """OPC UA requires multi-stage connection setup: HEL→ACK→OPN→Session.

        Uses asyncua Client to perform the full handshake correctly, then
        extracts live protocol state (ChannelId, TokenId, AuthToken) for use
        in fuzzed messages.
        """
        if not self.use_session:
            return  # Skip state machine if not using sessions

        import asyncio
        from asyncua import Client

        async def _setup():
            url = self._get_endpoint_url()
            client = Client(url)
            client.session_timeout = 30000

            # Set credentials if configured
            if self.opcua_username is not None:
                client.set_user(self.opcua_username)
                client.set_password(self.opcua_password or "")

            try:
                await client.connect()
                # Extract live protocol state from client internals
                protocol = client.uaclient.protocol
                conn = protocol._connection
                self.secure_channel_id = conn.security_token.ChannelId
                self.token_id = conn.security_token.TokenId
                self.auth_token = protocol.authentication_token
                # Store state in context for cross-state access
                ctx = self._state_context
                ctx.set("secure_channel_id", self.secure_channel_id)
                ctx.set("token_id", self.token_id)
                ctx.set("auth_token", self.auth_token)

                # Use CryptoStateManager for nonce tracking. asyncua exposes the
                # peer nonce as SecureConnection.remote_nonce (the old
                # "server_nonce" attribute never existed, so the getattr default
                # silently stored empty bytes). It inits to int 0 before the
                # handshake completes, hence the isinstance guard.
                remote_nonce = getattr(conn, "remote_nonce", b"")
                ctx.crypto.set_nonce(
                    "server_nonce",
                    remote_nonce if isinstance(remote_nonce, bytes) else b"",
                )

                self.log.display(
                    f"Session established via asyncua - "
                    f"ChannelId: {self.secure_channel_id}, "
                    f"TokenId: {self.token_id}, "
                    f"AuthToken: {self.auth_token}"
                )
            finally:
                await client.disconnect()

        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(_setup())
            loop.close()
        except Exception as e:
            self.log.warning(f"Session setup failed (will fuzz with defaults): {e}")
            return

        connected = ProtocolState(
            name="CONNECTED",
            state_type=StateType.CONNECTION,
            description="TCP connection established",
        )

        hello_complete = ProtocolState(
            name="HELLO_COMPLETE", requires=["CONNECTED"], description="HEL/ACK handshake done"
        )

        secure_channel = ProtocolState(
            name="SECURE_CHANNEL",
            requires=["HELLO_COMPLETE"],
            description="SecureChannel established",
        )

        session_active = ProtocolState(
            name="SESSION_ACTIVE",
            requires=["SECURE_CHANNEL"],
            description="Session created and activated",
        )

        self.state_machine = StateMachine(
            initial_state=connected,
            states=[connected, hello_complete, secure_channel, session_active],
            context=self._state_context,
        )

        # All states are already satisfied by the asyncua handshake
        self.state_machine.transition_to("HELLO_COMPLETE")
        self.state_machine.transition_to("SECURE_CHANNEL")
        self.state_machine.transition_to("SESSION_ACTIVE")

        self.log.display(
            f"OPC UA state machine initialized - SecureChannelId: {self.secure_channel_id}, "
            f"TokenId: {self.token_id}"
        )

    def _define_protocol(self) -> None:
        """Define OPC UA protocol fuzzing structure"""

        endpoint_url = self._get_endpoint_url()
        receive_buffer = self.config.get_option("receive_buffer_size", 65535)
        send_buffer = self.config.get_option("send_buffer_size", 65535)
        max_message = self.config.get_option("max_message_size", 0)
        max_chunk = self.config.get_option("max_chunk_count", 0)

        # ============================================================
        # HELLO / ACKNOWLEDGE HANDSHAKE
        # ============================================================

        # 1. Baseline Hello - Simple connectivity test
        hello_baseline = Request(
            "OPCUA_Hello_Baseline",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.HELLO),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="HelloBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "HelloBody",
                    children=(
                        DWord("ProtocolVersion", 0, endian="<", fuzzable=False),
                        DWord("ReceiveBufferSize", receive_buffer, endian="<", fuzzable=False),
                        DWord("SendBufferSize", send_buffer, endian="<", fuzzable=False),
                        DWord("MaxMessageSize", max_message, endian="<", fuzzable=False),
                        DWord("MaxChunkCount", max_chunk, endian="<", fuzzable=False),
                        # EndpointUrl - length-prefixed string
                        Size(
                            "EndpointUrl_Length",
                            block_name="EndpointUrl_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        Block(
                            "EndpointUrl_Data",
                            children=(Static("EndpointUrl", endpoint_url.encode("utf-8")),),
                        ),
                    ),
                ),
            ),
        )

        # 2. Hello with fuzzable fields
        hello_fuzz = Request(
            "OPCUA_Hello_Fuzz",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.HELLO),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="HelloBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "HelloBody",
                    children=(
                        DWord("ProtocolVersion", 0, endian="<"),
                        DWord("ReceiveBufferSize", receive_buffer, endian="<"),
                        DWord("SendBufferSize", send_buffer, endian="<"),
                        DWord("MaxMessageSize", max_message, endian="<"),
                        DWord("MaxChunkCount", max_chunk, endian="<"),
                        Size(
                            "EndpointUrl_Length",
                            block_name="EndpointUrl_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "EndpointUrl_Data",
                            children=(SmartString("EndpointUrl", endpoint_url, max_len=4096),),
                        ),
                    ),
                ),
            ),
        )

        # 3. Hello boundary testing
        hello_boundary = Request(
            "OPCUA_Hello_Boundary",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.HELLO),
                        Static("IsFinal", b"F"),
                        Group(
                            "MessageSize_Boundary",
                            values=[
                                b"\x00\x00\x00\x00",  # Zero
                                b"\x08\x00\x00\x00",  # Minimum (header only)
                                b"\x1c\x00\x00\x00",  # Valid minimum Hello
                                b"\xff\xff\xff\x7f",  # Max signed int32
                                b"\xff\xff\xff\xff",  # Max uint32
                            ],
                        ),
                    ),
                ),
                Block(
                    "HelloBody",
                    children=(
                        Group(
                            "ProtocolVersion_Boundary",
                            values=[
                                b"\x00\x00\x00\x00",  # Version 0
                                b"\x01\x00\x00\x00",  # Version 1
                                b"\xff\xff\xff\xff",  # Max version
                            ],
                        ),
                        DWord("ReceiveBufferSize", receive_buffer, endian="<"),
                        DWord("SendBufferSize", send_buffer, endian="<"),
                        DWord("MaxMessageSize", max_message, endian="<"),
                        DWord("MaxChunkCount", max_chunk, endian="<"),
                        DWord("EndpointUrl_Length", 0, endian="<"),
                    ),
                ),
            ),
        )

        # 4. ReverseHello - Server-initiated connection
        reverse_hello = Request(
            "OPCUA_ReverseHello",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.REVERSE_HELLO),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="ReverseHelloBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "ReverseHelloBody",
                    children=(
                        Size(
                            "ServerUri_Length",
                            block_name="ServerUri_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ServerUri_Data",
                            children=(SmartString("ServerUri", "urn:test:server", max_len=4096),),
                        ),
                        Size(
                            "EndpointUrl_Length",
                            block_name="EndpointUrl_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "EndpointUrl_Data",
                            children=(SmartString("EndpointUrl", endpoint_url, max_len=4096),),
                        ),
                    ),
                ),
            ),
        )

        # ============================================================
        # OPEN SECURE CHANNEL (OPN)
        # ============================================================

        security_policy = OPCUASecurityPolicies.NONE

        # 5. OpenSecureChannel - Policy None (baseline)
        open_channel_baseline = Request(
            "OPCUA_OpenSecureChannel_Baseline",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.OPEN_SECURE_CHANNEL),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="OPNBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "OPNBody",
                    children=(
                        # SecureChannelId - 0 for new channel
                        DWord("SecureChannelId", 0, endian="<", fuzzable=False),
                        # SecurityPolicyUri - length-prefixed string
                        Size(
                            "SecurityPolicyUri_Length",
                            block_name="SecurityPolicyUri_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        Block(
                            "SecurityPolicyUri_Data",
                            children=(
                                Static("SecurityPolicyUri", security_policy.encode("utf-8")),
                            ),
                        ),
                        # SenderCertificate - null for Policy None
                        DWord("SenderCertificate_Length", 0xFFFFFFFF, endian="<", fuzzable=False),
                        # ReceiverCertificateThumbprint - null for Policy None
                        DWord("ReceiverThumbprint_Length", 0xFFFFFFFF, endian="<", fuzzable=False),
                        # SequenceHeader
                        DWord("SequenceNumber", 1, endian="<", fuzzable=False),
                        DWord("RequestId", 1, endian="<", fuzzable=False),
                        # OpenSecureChannelRequest body
                        # TypeId - FourByte NodeId for OpenSecureChannelRequest (446)
                        Static("TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("TypeId_Namespace", 0x00),
                        Word(
                            "TypeId_Identifier",
                            OPCUAServiceIds.OPEN_SECURE_CHANNEL_REQUEST,
                            endian="<",
                        ),
                        # RequestHeader
                        self._create_request_header(),
                        # ClientProtocolVersion
                        DWord("ClientProtocolVersion", 0, endian="<", fuzzable=False),
                        # RequestType (Issue=0, Renew=1)
                        DWord(
                            "RequestType",
                            OPCUASecurityTokenRequestType.ISSUE,
                            endian="<",
                            fuzzable=False,
                        ),
                        # SecurityMode (None=1, Sign=2, SignAndEncrypt=3)
                        DWord(
                            "SecurityMode",
                            OPCUAMessageSecurityMode.NONE,
                            endian="<",
                            fuzzable=False,
                        ),
                        # ClientNonce - null for Policy None
                        DWord("ClientNonce_Length", 0xFFFFFFFF, endian="<", fuzzable=False),
                        # RequestedLifetime in milliseconds
                        DWord("RequestedLifetime", 3600000, endian="<", fuzzable=False),
                    ),
                ),
            ),
        )

        # 6. OpenSecureChannel with fuzzable fields
        open_channel_fuzz = Request(
            "OPCUA_OpenSecureChannel_Fuzz",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.OPEN_SECURE_CHANNEL),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="OPNBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "OPNBody",
                    children=(
                        DWord("SecureChannelId", 0, endian="<"),
                        Size(
                            "SecurityPolicyUri_Length",
                            block_name="SecurityPolicyUri_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "SecurityPolicyUri_Data",
                            children=(
                                SmartString("SecurityPolicyUri", security_policy, max_len=4096),
                            ),
                        ),
                        DWord("SenderCertificate_Length", 0xFFFFFFFF, endian="<"),
                        DWord("ReceiverThumbprint_Length", 0xFFFFFFFF, endian="<"),
                        DWord("SequenceNumber", 1, endian="<"),
                        DWord("RequestId", 1, endian="<"),
                        Static("TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("TypeId_Namespace", 0x00),
                        Word(
                            "TypeId_Identifier",
                            OPCUAServiceIds.OPEN_SECURE_CHANNEL_REQUEST,
                            endian="<",
                        ),
                        self._create_request_header(),
                        DWord("ClientProtocolVersion", 0, endian="<"),
                        Group(
                            "RequestType",
                            values=[
                                b"\x00\x00\x00\x00",  # Issue
                                b"\x01\x00\x00\x00",  # Renew
                                b"\xff\xff\xff\xff",  # Invalid
                            ],
                        ),
                        Group(
                            "SecurityMode",
                            values=[
                                b"\x00\x00\x00\x00",  # Invalid
                                b"\x01\x00\x00\x00",  # None
                                b"\x02\x00\x00\x00",  # Sign
                                b"\x03\x00\x00\x00",  # SignAndEncrypt
                                b"\xff\xff\xff\xff",  # Invalid
                            ],
                        ),
                        DWord("ClientNonce_Length", 0xFFFFFFFF, endian="<"),
                        DWord("RequestedLifetime", 3600000, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # DISCOVERY SERVICES (no session required)
        # ============================================================

        # 7. GetEndpoints Request
        get_endpoints = Request(
            "OPCUA_GetEndpoints",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.GET_ENDPOINTS_REQUEST),
                        # EndpointUrl
                        Size(
                            "EndpointUrl_Length",
                            block_name="EndpointUrl_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "EndpointUrl_Data",
                            children=(SmartString("EndpointUrl", endpoint_url, max_len=4096),),
                        ),
                        # LocaleIds array - empty
                        DWord("LocaleIds_Length", 0xFFFFFFFF, endian="<"),
                        # ProfileUris array - empty
                        DWord("ProfileUris_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # 8. FindServers Request
        find_servers = Request(
            "OPCUA_FindServers",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.FIND_SERVERS_REQUEST),
                        # EndpointUrl
                        Size(
                            "EndpointUrl_Length",
                            block_name="EndpointUrl_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "EndpointUrl_Data",
                            children=(SmartString("EndpointUrl", endpoint_url, max_len=4096),),
                        ),
                        # LocaleIds array - empty
                        DWord("LocaleIds_Length", 0xFFFFFFFF, endian="<"),
                        # ServerUris array - empty
                        DWord("ServerUris_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # 9. FindServersOnNetwork Request
        find_servers_on_network = Request(
            "OPCUA_FindServersOnNetwork",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.FIND_SERVERS_ON_NETWORK_REQUEST),
                        # StartingRecordId
                        DWord("StartingRecordId", 0, endian="<"),
                        # MaxRecordsToReturn
                        DWord("MaxRecordsToReturn", 100, endian="<"),
                        # ServerCapabilityFilter array - empty
                        DWord("ServerCapabilityFilter_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # SESSION SERVICES
        # ============================================================

        app_uri = self.config.get_option("application_uri", "urn:oida:opcua:fuzzer")
        product_uri = self.config.get_option("product_uri", "urn:oida:opcua:fuzzer")
        app_name = self.config.get_option("application_name", "OIDA OPC UA Fuzzer")

        # 10. CreateSession Request
        create_session = Request(
            "OPCUA_CreateSession",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.CREATE_SESSION_REQUEST),
                        # ClientDescription (ApplicationDescription)
                        # ApplicationUri
                        Size(
                            "ApplicationUri_Length",
                            block_name="ApplicationUri_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ApplicationUri_Data",
                            children=(Static("ApplicationUri", app_uri.encode("utf-8")),),
                        ),
                        # ProductUri
                        Size(
                            "ProductUri_Length",
                            block_name="ProductUri_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ProductUri_Data",
                            children=(Static("ProductUri", product_uri.encode("utf-8")),),
                        ),
                        # ApplicationName (LocalizedText)
                        Byte("ApplicationName_EncodingMask", 0x03),  # Locale + Text
                        Size(
                            "ApplicationName_Locale_Length",
                            block_name="ApplicationName_Locale_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ApplicationName_Locale_Data",
                            children=(Static("ApplicationName_Locale", b"en"),),
                        ),
                        Size(
                            "ApplicationName_Text_Length",
                            block_name="ApplicationName_Text_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ApplicationName_Text_Data",
                            children=(Static("ApplicationName_Text", app_name.encode("utf-8")),),
                        ),
                        # ApplicationType (Client=0)
                        DWord("ApplicationType", 1, endian="<"),  # Client
                        # GatewayServerUri - null
                        DWord("GatewayServerUri_Length", 0xFFFFFFFF, endian="<"),
                        # DiscoveryProfileUri - null
                        DWord("DiscoveryProfileUri_Length", 0xFFFFFFFF, endian="<"),
                        # DiscoveryUrls - empty array
                        DWord("DiscoveryUrls_Length", 0xFFFFFFFF, endian="<"),
                        # ServerUri - null
                        DWord("ServerUri_Length", 0xFFFFFFFF, endian="<"),
                        # EndpointUrl
                        Size(
                            "EndpointUrl_Length",
                            block_name="EndpointUrl_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "EndpointUrl_Data",
                            children=(Static("EndpointUrl", endpoint_url.encode("utf-8")),),
                        ),
                        # SessionName
                        Size(
                            "SessionName_Length",
                            block_name="SessionName_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "SessionName_Data",
                            children=(
                                SmartString("SessionName", "OIDA Fuzzing Session", max_len=256),
                            ),
                        ),
                        # ClientNonce - 32 random bytes for security
                        DWord("ClientNonce_Length", 32, endian="<"),
                        Static("ClientNonce", bytes(32)),  # Zero nonce for simplicity
                        # ClientCertificate - null for Policy None
                        DWord("ClientCertificate_Length", 0xFFFFFFFF, endian="<"),
                        # RequestedSessionTimeout (ms) - OPC UA Duration is IEEE 754 double
                        # 0x41324f8000000000 is the uint64 bit pattern for 1200000.0 as a double
                        QWord(
                            "RequestedSessionTimeout", 0x41324F8000000000, endian="<"
                        ),  # 20 minutes (1200000.0ms) encoded as IEEE 754 double
                        # MaxResponseMessageSize
                        DWord("MaxResponseMessageSize", 0, endian="<"),  # Unlimited
                    ),
                ),
            ),
        )

        # 11. ActivateSession Request (baseline - uses configured auth or anonymous)
        activate_session = Request(
            "OPCUA_ActivateSession",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.ACTIVATE_SESSION_REQUEST, authenticated=True
                        ),
                        # ClientSignature (SignatureData) - null for Policy None
                        DWord("ClientSignature_Algorithm_Length", 0xFFFFFFFF, endian="<"),
                        DWord("ClientSignature_Signature_Length", 0xFFFFFFFF, endian="<"),
                        # ClientSoftwareCertificates - empty array
                        DWord("ClientSoftwareCertificates_Length", 0xFFFFFFFF, endian="<"),
                        # LocaleIds - array with one element
                        DWord("LocaleIds_Length", 1, endian="<"),
                        Size(
                            "LocaleId_0_Length",
                            block_name="LocaleId_0_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block("LocaleId_0_Data", children=(Static("LocaleId_0", b"en"),)),
                        # UserIdentityToken - Anonymous (321) or Username (322) based on config
                        *self._create_user_identity_token(fuzzable=False),
                        # UserTokenSignature - null for anonymous/Policy None
                        DWord("UserTokenSignature_Algorithm_Length", 0xFFFFFFFF, endian="<"),
                        DWord("UserTokenSignature_Signature_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # 11b. ActivateSession with fuzzable auth (for OPCUA_Auth category)
        # Uses SmartString with CREDENTIAL context for username/password fuzzing
        activate_session_auth_fuzz = Request(
            "OPCUA_ActivateSession_AuthFuzz",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.ACTIVATE_SESSION_REQUEST, authenticated=True
                        ),
                        # ClientSignature (SignatureData) - null for Policy None
                        DWord("ClientSignature_Algorithm_Length", 0xFFFFFFFF, endian="<"),
                        DWord("ClientSignature_Signature_Length", 0xFFFFFFFF, endian="<"),
                        # ClientSoftwareCertificates - empty array
                        DWord("ClientSoftwareCertificates_Length", 0xFFFFFFFF, endian="<"),
                        # LocaleIds - array with one element
                        DWord("LocaleIds_Length", 1, endian="<"),
                        Size(
                            "LocaleId_0_Length",
                            block_name="LocaleId_0_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block("LocaleId_0_Data", children=(Static("LocaleId_0", b"en"),)),
                        # UserIdentityToken with FUZZABLE credentials (SmartString CREDENTIAL context)
                        *self._create_user_identity_token(fuzzable=True),
                        # UserTokenSignature - null for Policy None
                        DWord("UserTokenSignature_Algorithm_Length", 0xFFFFFFFF, endian="<"),
                        DWord("UserTokenSignature_Signature_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # 12. CloseSession Request
        close_session = Request(
            "OPCUA_CloseSession",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.CLOSE_SESSION_REQUEST, authenticated=True
                        ),
                        # DeleteSubscriptions
                        Byte("DeleteSubscriptions", 0x01),  # True
                    ),
                ),
            ),
        )

        # ============================================================
        # READ OPERATIONS
        # ============================================================

        # 13. Read Request - read Server node attributes
        read_request = Request(
            "OPCUA_Read",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.READ_REQUEST, authenticated=True),
                        # MaxAge
                        QWord("MaxAge", 0, endian="<"),  # Read from cache or source
                        # TimestampsToReturn
                        Group(
                            "TimestampsToReturn",
                            values=[
                                b"\x00\x00\x00\x00",  # Source
                                b"\x01\x00\x00\x00",  # Server
                                b"\x02\x00\x00\x00",  # Both
                                b"\x03\x00\x00\x00",  # Neither
                            ],
                        ),
                        # NodesToRead array - read Server node DisplayName
                        DWord("NodesToRead_Length", 1, endian="<"),
                        # ReadValueId structure
                        # NodeId - Server node (i=2253)
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x00),
                        Word("NodeId_Identifier", 2253, endian="<"),  # Server node
                        # AttributeId (DisplayName=4)
                        Group(
                            "AttributeId",
                            values=[
                                b"\x01\x00\x00\x00",  # NodeId
                                b"\x02\x00\x00\x00",  # NodeClass
                                b"\x03\x00\x00\x00",  # BrowseName
                                b"\x04\x00\x00\x00",  # DisplayName
                                b"\x05\x00\x00\x00",  # Description
                                b"\x0d\x00\x00\x00",  # Value
                            ],
                        ),
                        # IndexRange - null
                        DWord("IndexRange_Length", 0xFFFFFFFF, endian="<"),
                        # DataEncoding - null QualifiedName
                        Word("DataEncoding_NamespaceIndex", 0x0000, endian="<"),
                        DWord("DataEncoding_Name_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # 14. Browse Request
        browse_request = Request(
            "OPCUA_Browse",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.BROWSE_REQUEST, authenticated=True
                        ),
                        # View (ViewDescription) - null
                        Static("View_ViewId_Encoding", bytes([OPCUANodeIdTypes.TWO_BYTE])),
                        Byte("View_ViewId", 0x00),
                        QWord("View_Timestamp", 0, endian="<"),
                        DWord("View_ViewVersion", 0, endian="<"),
                        # RequestedMaxReferencesPerNode
                        DWord("RequestedMaxReferencesPerNode", 100, endian="<"),
                        # NodesToBrowse array
                        DWord("NodesToBrowse_Length", 1, endian="<"),
                        # BrowseDescription structure
                        # NodeId - Root folder (i=84)
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x00),
                        Word("NodeId_Identifier", 84, endian="<"),  # Root folder
                        # BrowseDirection
                        Group(
                            "BrowseDirection",
                            values=[
                                b"\x00\x00\x00\x00",  # Forward
                                b"\x01\x00\x00\x00",  # Inverse
                                b"\x02\x00\x00\x00",  # Both
                            ],
                        ),
                        # ReferenceTypeId - null (all references)
                        Static("ReferenceTypeId_Encoding", bytes([OPCUANodeIdTypes.TWO_BYTE])),
                        Byte("ReferenceTypeId", 0x00),
                        # IncludeSubtypes
                        Byte("IncludeSubtypes", 0x01),
                        # NodeClassMask (all classes)
                        DWord("NodeClassMask", 0xFFFFFFFF, endian="<"),
                        # ResultMask
                        DWord("ResultMask", 0x3F, endian="<"),
                    ),
                ),
            ),
        )

        # 15. BrowseNext Request
        browse_next = Request(
            "OPCUA_BrowseNext",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.BROWSE_NEXT_REQUEST, authenticated=True
                        ),
                        # ReleaseContinuationPoints
                        Byte("ReleaseContinuationPoints", 0x00),
                        # ContinuationPoints array
                        DWord("ContinuationPoints_Length", 1, endian="<"),
                        # ByteString continuation point (fuzzable)
                        Size(
                            "ContinuationPoint_0_Length",
                            block_name="ContinuationPoint_0_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ContinuationPoint_0_Data",
                            children=(
                                SmartString("ContinuationPoint", "\x00\x00\x00\x00", max_len=1024),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 16. TranslateBrowsePathsToNodeIds Request
        translate_browse_paths = Request(
            "OPCUA_TranslateBrowsePaths",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.TRANSLATE_BROWSE_PATHS_REQUEST,
                            authenticated=True,
                        ),
                        # BrowsePaths array
                        DWord("BrowsePaths_Length", 1, endian="<"),
                        # BrowsePath structure
                        # StartingNode - Root folder (i=84)
                        Static("StartingNode_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("StartingNode_Namespace", 0x00),
                        Word("StartingNode_Identifier", 84, endian="<"),
                        # RelativePath
                        DWord("RelativePath_Elements_Length", 1, endian="<"),
                        # RelativePathElement
                        # ReferenceTypeId - Organizes (i=35)
                        Static("ReferenceTypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("ReferenceTypeId_Namespace", 0x00),
                        Word("ReferenceTypeId_Identifier", 35, endian="<"),
                        # IsInverse
                        Byte("IsInverse", 0x00),
                        # IncludeSubtypes
                        Byte("IncludeSubtypes", 0x01),
                        # TargetName (QualifiedName)
                        Word("TargetName_NamespaceIndex", 0x0000, endian="<"),
                        Size(
                            "TargetName_Name_Length",
                            block_name="TargetName_Name_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "TargetName_Name_Data",
                            children=(SmartString("TargetName", "Objects", max_len=512),),
                        ),
                    ),
                ),
            ),
        )

        # 17. HistoryRead Request
        history_read = Request(
            "OPCUA_HistoryRead",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.HISTORY_READ_REQUEST, authenticated=True
                        ),
                        # HistoryReadDetails (ReadRawModifiedDetails)
                        # TypeId for ReadRawModifiedDetails (641)
                        Static(
                            "HistoryReadDetails_TypeId_Encoding",
                            bytes([OPCUANodeIdTypes.FOUR_BYTE]),
                        ),
                        Byte("HistoryReadDetails_TypeId_Namespace", 0x00),
                        Word("HistoryReadDetails_TypeId_Identifier", 641, endian="<"),
                        Byte("HistoryReadDetails_Encoding", 0x01),
                        # Body length: IsReadModified(1) + StartTime(8) + EndTime(8) +
                        # NumValuesPerNode(4) + ReturnBounds(1) = 22
                        DWord("HistoryReadDetails_Body_Length", 22, endian="<"),
                        # IsReadModified
                        Byte("IsReadModified", 0x00),
                        # StartTime
                        QWord("StartTime", 0, endian="<"),
                        # EndTime
                        QWord("EndTime", 132500000000000000, endian="<"),
                        # NumValuesPerNode
                        DWord("NumValuesPerNode", 100, endian="<"),
                        # ReturnBounds
                        Byte("ReturnBounds", 0x00),
                        # TimestampsToReturn
                        DWord("TimestampsToReturn", OPCUATimestampsToReturn.BOTH, endian="<"),
                        # ReleaseContinuationPoints
                        Byte("ReleaseContinuationPoints", 0x00),
                        # NodesToRead array
                        DWord("NodesToRead_Length", 1, endian="<"),
                        # HistoryReadValueId
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x00),
                        Word("NodeId_Identifier", 2253, endian="<"),
                        DWord("IndexRange_Length", 0xFFFFFFFF, endian="<"),
                        Word("DataEncoding_NamespaceIndex", 0x0000, endian="<"),
                        DWord("DataEncoding_Name_Length", 0xFFFFFFFF, endian="<"),
                        DWord("ContinuationPoint_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # 18. RegisterNodes Request
        register_nodes = Request(
            "OPCUA_RegisterNodes",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.REGISTER_NODES_REQUEST, authenticated=True
                        ),
                        # NodesToRegister array
                        DWord("NodesToRegister_Length", 1, endian="<"),
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x00),
                        Word("NodeId_Identifier", 2253, endian="<"),
                    ),
                ),
            ),
        )

        # 19. UnregisterNodes Request
        unregister_nodes = Request(
            "OPCUA_UnregisterNodes",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.UNREGISTER_NODES_REQUEST, authenticated=True
                        ),
                        # NodesToUnregister array
                        DWord("NodesToUnregister_Length", 1, endian="<"),
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x00),
                        Word("NodeId_Identifier", 2253, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # SUBSCRIPTION SERVICES
        # ============================================================

        # 20. CreateSubscription Request
        create_subscription = Request(
            "OPCUA_CreateSubscription",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.CREATE_SUBSCRIPTION_REQUEST, authenticated=True
                        ),
                        # RequestedPublishingInterval (ms as double)
                        QWord(
                            "RequestedPublishingInterval", 0x408F400000000000, endian="<"
                        ),  # 1000.0
                        # RequestedLifetimeCount
                        DWord("RequestedLifetimeCount", 60, endian="<"),
                        # RequestedMaxKeepAliveCount
                        DWord("RequestedMaxKeepAliveCount", 10, endian="<"),
                        # MaxNotificationsPerPublish
                        DWord("MaxNotificationsPerPublish", 1000, endian="<"),
                        # PublishingEnabled
                        Byte("PublishingEnabled", 0x01),
                        # Priority
                        Byte("Priority", 0x00),
                    ),
                ),
            ),
        )

        # 21. ModifySubscription Request
        modify_subscription = Request(
            "OPCUA_ModifySubscription",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.MODIFY_SUBSCRIPTION_REQUEST, authenticated=True
                        ),
                        # SubscriptionId
                        DWord("SubscriptionId", 1, endian="<"),
                        # RequestedPublishingInterval
                        QWord(
                            "RequestedPublishingInterval", 0x4093480000000000, endian="<"
                        ),  # 2000.0
                        # RequestedLifetimeCount
                        DWord("RequestedLifetimeCount", 120, endian="<"),
                        # RequestedMaxKeepAliveCount
                        DWord("RequestedMaxKeepAliveCount", 20, endian="<"),
                        # MaxNotificationsPerPublish
                        DWord("MaxNotificationsPerPublish", 500, endian="<"),
                        # Priority
                        Byte("Priority", 0x01),
                    ),
                ),
            ),
        )

        # 22. DeleteSubscriptions Request
        delete_subscriptions = Request(
            "OPCUA_DeleteSubscriptions",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.DELETE_SUBSCRIPTIONS_REQUEST, authenticated=True
                        ),
                        # SubscriptionIds array
                        DWord("SubscriptionIds_Length", 1, endian="<"),
                        DWord("SubscriptionId_0", 1, endian="<"),
                    ),
                ),
            ),
        )

        # 23. CreateMonitoredItems Request
        create_monitored_items = Request(
            "OPCUA_CreateMonitoredItems",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.CREATE_MONITORED_ITEMS_REQUEST,
                            authenticated=True,
                        ),
                        # SubscriptionId
                        DWord("SubscriptionId", 1, endian="<"),
                        # TimestampsToReturn
                        DWord("TimestampsToReturn", OPCUATimestampsToReturn.BOTH, endian="<"),
                        # ItemsToCreate array
                        DWord("ItemsToCreate_Length", 1, endian="<"),
                        # MonitoredItemCreateRequest structure
                        # ItemToMonitor (ReadValueId)
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x00),
                        Word("NodeId_Identifier", 2253, endian="<"),
                        DWord("AttributeId", 13, endian="<"),  # Value attribute
                        DWord("IndexRange_Length", 0xFFFFFFFF, endian="<"),
                        Word("DataEncoding_NamespaceIndex", 0x0000, endian="<"),
                        DWord("DataEncoding_Name_Length", 0xFFFFFFFF, endian="<"),
                        # MonitoringMode
                        DWord("MonitoringMode", 2, endian="<"),  # Reporting
                        # RequestedParameters (MonitoringParameters)
                        DWord("ClientHandle", 1, endian="<"),
                        QWord("SamplingInterval", 0x408F400000000000, endian="<"),  # 1000.0
                        # Filter - null ExtensionObject
                        Static("Filter_TypeId", bytes([OPCUANodeIdTypes.TWO_BYTE, 0])),
                        Byte("Filter_Encoding", 0x00),
                        # QueueSize
                        DWord("QueueSize", 10, endian="<"),
                        # DiscardOldest
                        Byte("DiscardOldest", 0x01),
                    ),
                ),
            ),
        )

        # 24. Publish Request
        publish_request = Request(
            "OPCUA_Publish",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.PUBLISH_REQUEST, authenticated=True
                        ),
                        # SubscriptionAcknowledgements - empty array
                        DWord("SubscriptionAcknowledgements_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # WRITE OPERATIONS
        # ============================================================

        # 25. Write Request
        write_request = Request(
            "OPCUA_Write",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.WRITE_REQUEST, authenticated=True),
                        # NodesToWrite array
                        DWord("NodesToWrite_Length", 1, endian="<"),
                        # WriteValue structure
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x00),
                        Word("NodeId_Identifier", 2253, endian="<"),
                        DWord("AttributeId", 13, endian="<"),  # Value
                        DWord("IndexRange_Length", 0xFFFFFFFF, endian="<"),
                        # Value (DataValue)
                        Byte("DataValue_EncodingMask", 0x01),  # Has value
                        # Variant - Int32 value
                        Byte("Variant_EncodingMask", 0x06),  # Int32
                        DWord("Variant_Value", 42, endian="<"),
                    ),
                ),
            ),
        )

        # 26. Call Request (Method invocation)
        call_request = Request(
            "OPCUA_Call",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.CALL_REQUEST, authenticated=True),
                        # MethodsToCall array
                        DWord("MethodsToCall_Length", 1, endian="<"),
                        # CallMethodRequest structure
                        # ObjectId - Server node (i=2253)
                        Static("ObjectId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("ObjectId_Namespace", 0x00),
                        Word("ObjectId_Identifier", 2253, endian="<"),
                        # MethodId - GetMonitoredItems (i=11492)
                        Static("MethodId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("MethodId_Namespace", 0x00),
                        Word("MethodId_Identifier", 11492, endian="<"),
                        # InputArguments - empty array
                        DWord("InputArguments_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # 27. AddNodes Request
        add_nodes = Request(
            "OPCUA_AddNodes",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.ADD_NODES_REQUEST, authenticated=True
                        ),
                        # NodesToAdd array
                        DWord("NodesToAdd_Length", 1, endian="<"),
                        # AddNodesItem structure
                        # ParentNodeId - Objects folder (i=85)
                        Static("ParentNodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("ParentNodeId_Namespace", 0x00),
                        Word("ParentNodeId_Identifier", 85, endian="<"),
                        # ReferenceTypeId - Organizes (i=35)
                        Static("ReferenceTypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("ReferenceTypeId_Namespace", 0x00),
                        Word("ReferenceTypeId_Identifier", 35, endian="<"),
                        # RequestedNewNodeId - null (server assigns)
                        Static("RequestedNewNodeId_Encoding", bytes([OPCUANodeIdTypes.TWO_BYTE])),
                        Byte("RequestedNewNodeId_Id", 0x00),
                        # BrowseName
                        Word("BrowseName_NamespaceIndex", 0x0001, endian="<"),
                        Size(
                            "BrowseName_Name_Length",
                            block_name="BrowseName_Name_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "BrowseName_Name_Data",
                            children=(SmartString("BrowseName", "FuzzedNode", max_len=256),),
                        ),
                        # NodeClass (Object=1)
                        DWord("NodeClass", 1, endian="<"),
                        # NodeAttributes - null ExtensionObject
                        Static("NodeAttributes_TypeId", bytes([OPCUANodeIdTypes.TWO_BYTE, 0])),
                        Byte("NodeAttributes_Encoding", 0x00),
                        # TypeDefinition - BaseObjectType (i=58)
                        Static("TypeDefinition_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("TypeDefinition_Namespace", 0x00),
                        Word("TypeDefinition_Identifier", 58, endian="<"),
                    ),
                ),
            ),
        )

        # 28. DeleteNodes Request
        delete_nodes = Request(
            "OPCUA_DeleteNodes",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.DELETE_NODES_REQUEST, authenticated=True
                        ),
                        # NodesToDelete array
                        DWord("NodesToDelete_Length", 1, endian="<"),
                        # DeleteNodesItem
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x01),
                        Word("NodeId_Identifier", 1000, endian="<"),  # Fuzzed node ID
                        # DeleteTargetReferences
                        Byte("DeleteTargetReferences", 0x01),
                    ),
                ),
            ),
        )

        # ============================================================
        # ATTACK PATTERNS
        # ============================================================

        # 29. Chunk Flooding - Send incomplete chunks (DoS)
        chunk_flood = Request(
            "OPCUA_ChunkFlood",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"C"),  # Chunk - never final!
                        DWord("MessageSize", 64, endian="<"),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        DynamicDWord("SecureChannelId", lambda: self.secure_channel_id, endian="<"),
                        DynamicDWord("TokenId", lambda: self.token_id, endian="<"),
                        DWord("SequenceNumber", 99999, endian="<"),
                        DWord("RequestId", 99999, endian="<"),
                        # Minimal body to exhaust resources
                        RandomData("ChunkBody", min_length=32, max_length=32),
                    ),
                ),
            ),
        )

        # 30. Nested ExtensionObjects - Stack overflow attack
        nested_extension = Request(
            "OPCUA_NestedExtension",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.READ_REQUEST, authenticated=True),
                        # Deeply nested ExtensionObjects
                        # Each level: TypeId + Encoding + Length + Body
                        # Create 100 levels of nesting
                        Static(
                            "Nested_ExtObj_0",
                            bytes(
                                [
                                    0x01,
                                    0x00,
                                    0xFF,
                                    0x01,  # TypeId (FourByte, ns=0, id=511)
                                    0x01,  # Encoding (has body)
                                ]
                            )
                            * 50,
                        ),  # 50 nested objects
                        DWord("Final_Body_Length", 4, endian="<"),
                        DWord("Final_Value", 0xDEADBEEF, endian="<"),
                    ),
                ),
            ),
        )

        # 31. Malformed NodeId encodings
        malformed_nodeid = Request(
            "OPCUA_MalformedNodeId",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.READ_REQUEST, authenticated=True),
                        # MaxAge
                        QWord("MaxAge", 0, endian="<"),
                        DWord("TimestampsToReturn", 0, endian="<"),
                        # NodesToRead with malformed NodeId
                        DWord("NodesToRead_Length", 1, endian="<"),
                        # Malformed NodeId encoding byte
                        Group(
                            "NodeId_Encoding_Malformed",
                            values=[
                                b"\x06",  # Invalid type 6
                                b"\x07",  # Invalid type 7
                                b"\x0f",  # Invalid type 15
                                b"\xff",  # Invalid type 255
                                b"\x80",  # Namespace URI flag without valid type
                            ],
                        ),
                        # Garbage data that will be misinterpreted
                        SmartString("NodeId_Garbage", "\x00\x00\xff\xff", max_len=256),
                        DWord("AttributeId", 13, endian="<"),
                        DWord("IndexRange_Length", 0xFFFFFFFF, endian="<"),
                        Word("DataEncoding_NamespaceIndex", 0x0000, endian="<"),
                        DWord("DataEncoding_Name_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # 31b. ExtensionObject TypeId fuzzing - vendor parser bug discovery
        # Sends a Write whose value is an ExtensionObject whose TypeId is mutated
        # across common (0x0000/0x0001/0xFFFF) AND vendor-reserved (0x6000-0x6FFF)
        # ranges. Vendor-specific TypeIds in 0x6XXX trip dispatchers that fall
        # through to a vendor parser path which is rarely fuzz-tested.
        # See ref/opcua/cve_patterns.json#opcua-extension-object-typeid
        extension_object = Request(
            "OPCUA_ExtensionObject",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.WRITE_REQUEST, authenticated=True),
                        # NodesToWrite array - single WriteValue
                        DWord("NodesToWrite_Length", 1, endian="<"),
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x00),
                        Word("NodeId_Identifier", 2253, endian="<"),
                        DWord("AttributeId", 13, endian="<"),  # Value
                        DWord("IndexRange_Length", 0xFFFFFFFF, endian="<"),
                        # DataValue with ExtensionObject variant payload
                        Byte("DataValue_EncodingMask", 0x01),  # Has value
                        # Variant type code 22 = ExtensionObject
                        Byte("Variant_EncodingMask", 0x16),
                        # ExtensionObject.TypeId - FourByte NodeId
                        Static(
                            "ExtensionObject_TypeId_Encoding",
                            bytes([OPCUANodeIdTypes.FOUR_BYTE]),
                        ),
                        Byte("ExtensionObject_TypeId_Namespace", 0x00),
                        # TypeId identifier mutation: common + vendor-reserved 0x6XXX
                        # range. 0x6000-0x6FFF is the vendor-reserved band per the
                        # OPC UA NodeId convention; many stacks route these to
                        # plugin/extension handlers that lack input validation.
                        Group(
                            "ExtensionObject_TypeId_Identifier",
                            values=[
                                b"\x00\x00",  # 0x0000 - null
                                b"\x01\x00",  # 0x0001 - sentinel
                                b"\x00\x60",  # 0x6000 - vendor-reserved low
                                b"\x80\x60",  # 0x6080 - vendor-reserved mid
                                b"\xff\x6f",  # 0x6FFF - vendor-reserved high
                                b"\xff\xff",  # 0xFFFF - max
                            ],
                        ),
                        # Encoding: 0x01 = has ByteString body
                        Byte("ExtensionObject_Encoding", 0x01),
                        # Body length + minimal payload
                        DWord("ExtensionObject_Body_Length", 4, endian="<"),
                        DWord("ExtensionObject_Body", 0xDEADBEEF, endian="<"),
                    ),
                ),
            ),
        )

        # 32. Large array size attack
        large_array = Request(
            "OPCUA_LargeArray",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.READ_REQUEST, authenticated=True),
                        QWord("MaxAge", 0, endian="<"),
                        DWord("TimestampsToReturn", 0, endian="<"),
                        # Claim massive array size
                        Group(
                            "NodesToRead_Length_Attack",
                            values=[
                                b"\xff\xff\xff\x7f",  # Max signed int32 (2147483647)
                                b"\x00\x00\x00\x40",  # 1 billion
                                b"\x00\x00\x10\x00",  # 1 million
                            ],
                        ),
                        # Minimal actual data (will likely crash on allocation)
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x00),
                        Word("NodeId_Identifier", 2253, endian="<"),
                        DWord("AttributeId", 13, endian="<"),
                        DWord("IndexRange_Length", 0xFFFFFFFF, endian="<"),
                        Word("DataEncoding_NamespaceIndex", 0x0000, endian="<"),
                        DWord("DataEncoding_Name_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # 33. UTF-8 string fuzzing (CVE patterns)
        utf8_fuzz = Request(
            "OPCUA_UTF8Fuzz",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.BROWSE_REQUEST, authenticated=True
                        ),
                        # View
                        Static("View_ViewId_Encoding", bytes([OPCUANodeIdTypes.TWO_BYTE])),
                        Byte("View_ViewId", 0x00),
                        QWord("View_Timestamp", 0, endian="<"),
                        DWord("View_ViewVersion", 0, endian="<"),
                        DWord("RequestedMaxReferencesPerNode", 100, endian="<"),
                        DWord("NodesToBrowse_Length", 1, endian="<"),
                        # NodeId with string identifier (malformed UTF-8)
                        Static("NodeId_Encoding_String", bytes([OPCUANodeIdTypes.STRING])),
                        Word("NodeId_Namespace", 0x0000, endian="<"),
                        # Malformed UTF-8 string
                        Size(
                            "NodeId_String_Length",
                            block_name="NodeId_String_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "NodeId_String_Data",
                            children=(
                                Group(
                                    "MalformedUTF8",
                                    values=[
                                        b"\x80\x81\x82\x83",  # Invalid continuation bytes
                                        b"\xc0\xaf",  # Overlong encoding
                                        b"\xe0\x80\xaf",  # Overlong encoding
                                        b"\xf0\x80\x80\xaf",  # Overlong encoding
                                        b"\xed\xa0\x80",  # Surrogate half
                                        b"\xed\xbf\xbf",  # Surrogate half
                                        b"\xfe\xfe\xff\xff",  # Invalid bytes
                                        b"\xff" * 100,  # All invalid bytes
                                    ],
                                ),
                            ),
                        ),
                        DWord("BrowseDirection", 0, endian="<"),
                        Static("ReferenceTypeId_Encoding", bytes([OPCUANodeIdTypes.TWO_BYTE])),
                        Byte("ReferenceTypeId", 0x00),
                        Byte("IncludeSubtypes", 0x01),
                        DWord("NodeClassMask", 0xFFFFFFFF, endian="<"),
                        DWord("ResultMask", 0x3F, endian="<"),
                    ),
                ),
            ),
        )

        # 34. Close Secure Channel
        close_channel = Request(
            "OPCUA_CloseSecureChannel",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.CLOSE_SECURE_CHANNEL),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="CLOBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "CLOBody",
                    children=(
                        DynamicDWord("SecureChannelId", lambda: self.secure_channel_id, endian="<"),
                        DynamicDWord("TokenId", lambda: self.token_id, endian="<"),
                        DWord("SequenceNumber", 999, endian="<"),
                        DWord("RequestId", 999, endian="<"),
                        Static("TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("TypeId_Namespace", 0x00),
                        Word(
                            "TypeId_Identifier",
                            OPCUAServiceIds.CLOSE_SECURE_CHANNEL_REQUEST,
                            endian="<",
                        ),
                        self._create_request_header(authenticated=True),
                    ),
                ),
            ),
        )

        # ============================================================
        # DISCOVERY SERVICES (continued)
        # ============================================================

        # 36. RegisterServer Request - Discovery server poisoning
        register_server = Request(
            "OPCUA_RegisterServer",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.REGISTER_SERVER_REQUEST),
                        # RegisteredServer structure
                        # ServerUri
                        Size(
                            "ServerUri_Length",
                            block_name="ServerUri_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ServerUri_Data",
                            children=(
                                SmartString("ServerUri", "urn:fuzz:server:poisoned", max_len=4096),
                            ),
                        ),
                        # ProductUri
                        Size(
                            "ProductUri_Length",
                            block_name="ProductUri_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ProductUri_Data",
                            children=(
                                SmartString("ProductUri", "urn:fuzz:product:evil", max_len=4096),
                            ),
                        ),
                        # ServerNames array (LocalizedText)
                        DWord("ServerNames_Length", 1, endian="<"),
                        Byte("ServerName_EncodingMask", 0x03),
                        Size(
                            "ServerName_Locale_Length",
                            block_name="ServerName_Locale_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ServerName_Locale_Data", children=(Static("ServerName_Locale", b"en"),)
                        ),
                        Size(
                            "ServerName_Text_Length",
                            block_name="ServerName_Text_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ServerName_Text_Data",
                            children=(
                                SmartString("ServerName_Text", "Fuzzed Server", max_len=256),
                            ),
                        ),
                        # ServerType (0=Server, 1=Client, 2=ClientAndServer, 3=DiscoveryServer)
                        DWord("ServerType", 0, endian="<"),
                        # GatewayServerUri - null
                        DWord("GatewayServerUri_Length", 0xFFFFFFFF, endian="<"),
                        # DiscoveryUrls array
                        DWord("DiscoveryUrls_Length", 1, endian="<"),
                        Size(
                            "DiscoveryUrl_0_Length",
                            block_name="DiscoveryUrl_0_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "DiscoveryUrl_0_Data",
                            children=(SmartString("DiscoveryUrl_0", endpoint_url, max_len=4096),),
                        ),
                        # SemaphoreFilePath - null
                        DWord("SemaphoreFilePath_Length", 0xFFFFFFFF, endian="<"),
                        # IsOnline
                        Byte("IsOnline", 0x01),
                    ),
                ),
            ),
        )

        # 37. RegisterServer2 Request - Extended discovery config injection
        register_server2 = Request(
            "OPCUA_RegisterServer2",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(OPCUAServiceIds.REGISTER_SERVER2_REQUEST),
                        # RegisteredServer structure (same as RegisterServer)
                        Size(
                            "ServerUri_Length",
                            block_name="ServerUri_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ServerUri_Data",
                            children=(
                                SmartString("ServerUri", "urn:fuzz:server2:poisoned", max_len=4096),
                            ),
                        ),
                        Size(
                            "ProductUri_Length",
                            block_name="ProductUri_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ProductUri_Data",
                            children=(
                                SmartString("ProductUri", "urn:fuzz:product2:evil", max_len=4096),
                            ),
                        ),
                        DWord("ServerNames_Length", 1, endian="<"),
                        Byte("ServerName_EncodingMask", 0x03),
                        Size(
                            "ServerName_Locale_Length",
                            block_name="ServerName_Locale_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ServerName_Locale_Data", children=(Static("ServerName_Locale", b"en"),)
                        ),
                        Size(
                            "ServerName_Text_Length",
                            block_name="ServerName_Text_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "ServerName_Text_Data",
                            children=(
                                SmartString("ServerName_Text", "Fuzzed Server 2", max_len=256),
                            ),
                        ),
                        DWord("ServerType", 0, endian="<"),
                        DWord("GatewayServerUri_Length", 0xFFFFFFFF, endian="<"),
                        DWord("DiscoveryUrls_Length", 1, endian="<"),
                        Size(
                            "DiscoveryUrl_0_Length",
                            block_name="DiscoveryUrl_0_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "DiscoveryUrl_0_Data",
                            children=(SmartString("DiscoveryUrl_0", endpoint_url, max_len=4096),),
                        ),
                        DWord("SemaphoreFilePath_Length", 0xFFFFFFFF, endian="<"),
                        Byte("IsOnline", 0x01),
                        # DiscoveryConfiguration array (extension over RegisterServer)
                        DWord("DiscoveryConfiguration_Length", 1, endian="<"),
                        # ExtensionObject - MdnsDiscoveryConfiguration (12891)
                        Static(
                            "DiscoveryConfig_TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])
                        ),
                        Byte("DiscoveryConfig_TypeId_Namespace", 0x00),
                        Word("DiscoveryConfig_TypeId_Identifier", 12891, endian="<"),
                        Byte("DiscoveryConfig_Encoding", 0x01),  # Has body
                        # Body: MdnsServerName + ServerCapabilities
                        DWord("DiscoveryConfig_Body_Length", 12, endian="<"),
                        Size(
                            "MdnsServerName_Length",
                            block_name="MdnsServerName_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "MdnsServerName_Data",
                            children=(SmartString("MdnsServerName", "fuzz", max_len=256),),
                        ),
                        # ServerCapabilities - empty array
                        DWord("ServerCapabilities_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # SESSION SERVICES (continued)
        # ============================================================

        # 38. Cancel Request - Session state confusion
        cancel_request = Request(
            "OPCUA_Cancel",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.CANCEL_REQUEST, authenticated=True
                        ),
                        # RequestHandle - cancel a specific or invalid request
                        DWord("RequestHandle", 1, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # NODE MANAGEMENT (continued)
        # ============================================================

        # 39. AddReferences Request - Circular reference creation
        add_references = Request(
            "OPCUA_AddReferences",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.ADD_REFERENCES_REQUEST, authenticated=True
                        ),
                        # ReferencesToAdd array
                        DWord("ReferencesToAdd_Length", 1, endian="<"),
                        # AddReferencesItem structure
                        # SourceNodeId - Objects folder (i=85)
                        Static("SourceNodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("SourceNodeId_Namespace", 0x00),
                        Word("SourceNodeId_Identifier", 85, endian="<"),
                        # ReferenceTypeId - Organizes (i=35)
                        Static("ReferenceTypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("ReferenceTypeId_Namespace", 0x00),
                        Word("ReferenceTypeId_Identifier", 35, endian="<"),
                        # IsForward
                        Byte("IsForward", 0x01),
                        # TargetServerUri - null (local)
                        DWord("TargetServerUri_Length", 0xFFFFFFFF, endian="<"),
                        # TargetNodeId - ExpandedNodeId pointing back to Objects (circular)
                        Static("TargetNodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("TargetNodeId_Namespace", 0x00),
                        Word("TargetNodeId_Identifier", 85, endian="<"),
                        # TargetNodeClass (Object=1)
                        DWord("TargetNodeClass", 1, endian="<"),
                    ),
                ),
            ),
        )

        # 40. DeleteReferences Request - Orphan node creation
        delete_references = Request(
            "OPCUA_DeleteReferences",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.DELETE_REFERENCES_REQUEST, authenticated=True
                        ),
                        # ReferencesToDelete array
                        DWord("ReferencesToDelete_Length", 1, endian="<"),
                        # DeleteReferencesItem structure
                        # SourceNodeId - Objects folder (i=85)
                        Static("SourceNodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("SourceNodeId_Namespace", 0x00),
                        Word("SourceNodeId_Identifier", 85, endian="<"),
                        # ReferenceTypeId - Organizes (i=35)
                        Static("ReferenceTypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("ReferenceTypeId_Namespace", 0x00),
                        Word("ReferenceTypeId_Identifier", 35, endian="<"),
                        # IsForward
                        Byte("IsForward", 0x01),
                        # TargetNodeId - Root folder (i=84)
                        Static("TargetNodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("TargetNodeId_Namespace", 0x00),
                        Word("TargetNodeId_Identifier", 84, endian="<"),
                        # DeleteBidirectional
                        Byte("DeleteBidirectional", 0x01),
                    ),
                ),
            ),
        )

        # ============================================================
        # ATTRIBUTE SERVICES (continued)
        # ============================================================

        # 41. HistoryUpdate Request - Historical data tampering
        history_update = Request(
            "OPCUA_HistoryUpdate",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.HISTORY_UPDATE_REQUEST, authenticated=True
                        ),
                        # HistoryUpdateDetails array (ExtensionObject)
                        DWord("HistoryUpdateDetails_Length", 1, endian="<"),
                        # ExtensionObject - UpdateDataDetails (680)
                        Static(
                            "UpdateDetails_TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])
                        ),
                        Byte("UpdateDetails_TypeId_Namespace", 0x00),
                        Word("UpdateDetails_TypeId_Identifier", 680, endian="<"),
                        Byte("UpdateDetails_Encoding", 0x01),  # Has body
                        # Body: NodeId(4) + PerformInsertReplace(4) + ArrayLen(4) +
                        # EncodingMask(1) + VariantType(1) + Value(4) +
                        # SourceTimestamp(8) + ServerTimestamp(8) = 34
                        DWord("UpdateDetails_Body_Length", 34, endian="<"),
                        # NodeId (i=2253)
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x00),
                        Word("NodeId_Identifier", 2253, endian="<"),
                        # PerformInsertReplace (Insert=1, Replace=2, Update=3)
                        DWord("PerformInsertReplace", 1, endian="<"),
                        # UpdateValues array
                        DWord("UpdateValues_Length", 1, endian="<"),
                        # DataValue
                        Byte(
                            "DataValue_EncodingMask", 0x0D
                        ),  # Value + SourceTimestamp + ServerTimestamp
                        # Variant - Int32
                        Byte("Variant_EncodingMask", 0x06),
                        DWord("Variant_Value", 0xDEAD, endian="<"),
                        # SourceTimestamp
                        QWord("SourceTimestamp", 132500000000000000, endian="<"),
                        # ServerTimestamp
                        QWord("ServerTimestamp", 132500000000000000, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # MONITORED ITEM SERVICES (continued)
        # ============================================================

        # 42. ModifyMonitoredItems Request - Parameter escalation
        modify_monitored_items = Request(
            "OPCUA_ModifyMonitoredItems",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.MODIFY_MONITORED_ITEMS_REQUEST,
                            authenticated=True,
                        ),
                        # SubscriptionId
                        DWord("SubscriptionId", 1, endian="<"),
                        # TimestampsToReturn
                        DWord("TimestampsToReturn", OPCUATimestampsToReturn.BOTH, endian="<"),
                        # ItemsToModify array
                        DWord("ItemsToModify_Length", 1, endian="<"),
                        # MonitoredItemModifyRequest
                        DWord("MonitoredItemId", 1, endian="<"),
                        # RequestedParameters (MonitoringParameters)
                        DWord("ClientHandle", 1, endian="<"),
                        QWord("SamplingInterval", 0x0000000000000000, endian="<"),  # 0.0 = fastest
                        # Filter - null ExtensionObject
                        Static("Filter_TypeId", bytes([OPCUANodeIdTypes.TWO_BYTE, 0])),
                        Byte("Filter_Encoding", 0x00),
                        # QueueSize - abusive value
                        DWord("QueueSize", 0xFFFFFFFF, endian="<"),
                        # DiscardOldest
                        Byte("DiscardOldest", 0x01),
                    ),
                ),
            ),
        )

        # 43. SetMonitoringMode Request - State confusion
        set_monitoring_mode = Request(
            "OPCUA_SetMonitoringMode",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.SET_MONITORING_MODE_REQUEST, authenticated=True
                        ),
                        # SubscriptionId
                        DWord("SubscriptionId", 1, endian="<"),
                        # MonitoringMode (0=Disabled, 1=Sampling, 2=Reporting)
                        Group(
                            "MonitoringMode",
                            values=[
                                b"\x00\x00\x00\x00",  # Disabled
                                b"\x01\x00\x00\x00",  # Sampling
                                b"\x02\x00\x00\x00",  # Reporting
                                b"\xff\xff\xff\xff",  # Invalid
                            ],
                        ),
                        # MonitoredItemIds array
                        DWord("MonitoredItemIds_Length", 1, endian="<"),
                        DWord("MonitoredItemId_0", 1, endian="<"),
                    ),
                ),
            ),
        )

        # 44. SetTriggering Request - Circular triggering chains
        set_triggering = Request(
            "OPCUA_SetTriggering",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.SET_TRIGGERING_REQUEST, authenticated=True
                        ),
                        # SubscriptionId
                        DWord("SubscriptionId", 1, endian="<"),
                        # TriggeringItemId
                        DWord("TriggeringItemId", 1, endian="<"),
                        # LinksToAdd array - circular: item triggers itself
                        DWord("LinksToAdd_Length", 1, endian="<"),
                        DWord("LinkToAdd_0", 1, endian="<"),
                        # LinksToRemove array - empty
                        DWord("LinksToRemove_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # SUBSCRIPTION SERVICES (continued)
        # ============================================================

        # 45. SetPublishingMode Request - Boolean parsing test
        set_publishing_mode = Request(
            "OPCUA_SetPublishingMode",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.SET_PUBLISHING_MODE_REQUEST, authenticated=True
                        ),
                        # PublishingEnabled
                        Byte("PublishingEnabled", 0x01),
                        # SubscriptionIds array
                        DWord("SubscriptionIds_Length", 1, endian="<"),
                        DWord("SubscriptionId_0", 1, endian="<"),
                    ),
                ),
            ),
        )

        # 46. Republish Request - Sequence number manipulation
        republish_request = Request(
            "OPCUA_Republish",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.REPUBLISH_REQUEST, authenticated=True
                        ),
                        # SubscriptionId
                        DWord("SubscriptionId", 1, endian="<"),
                        # RetransmitSequenceNumber
                        DWord("RetransmitSequenceNumber", 1, endian="<"),
                    ),
                ),
            ),
        )

        # 47. TransferSubscriptions Request - Cross-session subscription theft
        transfer_subscriptions = Request(
            "OPCUA_TransferSubscriptions",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.TRANSFER_SUBSCRIPTIONS_REQUEST,
                            authenticated=True,
                        ),
                        # SubscriptionIds array
                        DWord("SubscriptionIds_Length", 1, endian="<"),
                        DWord("SubscriptionId_0", 1, endian="<"),
                        # SendInitialValues
                        Byte("SendInitialValues", 0x01),
                    ),
                ),
            ),
        )

        # ============================================================
        # CVE ATTACK PATTERNS
        # ============================================================

        # 48. CertChainLoop - CVE-2022-37013 pattern
        # OPN request with self-referencing certificate chain
        cert_chain_loop = Request(
            "OPCUA_CertChainLoop",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.OPEN_SECURE_CHANNEL),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="OPNBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "OPNBody",
                    children=(
                        # SecureChannelId - 0 for new channel
                        DWord("SecureChannelId", 0, endian="<"),
                        # SecurityPolicyUri - Basic256Sha256 (requires cert processing)
                        Size(
                            "SecurityPolicyUri_Length",
                            block_name="SecurityPolicyUri_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        Block(
                            "SecurityPolicyUri_Data",
                            children=(
                                Static(
                                    "SecurityPolicyUri",
                                    OPCUASecurityPolicies.BASIC256SHA256.encode("utf-8"),
                                ),
                            ),
                        ),
                        # SenderCertificate - self-referencing DER certificate chain
                        # Crafted X.509 cert where Issuer DN == Subject DN creating a loop
                        Size(
                            "SenderCertificate_Length",
                            block_name="SenderCertificate_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                        ),
                        Block(
                            "SenderCertificate_Data",
                            children=(
                                # Minimal self-signed DER cert structure with issuer == subject
                                # SEQUENCE { SEQUENCE { version, serial, algo, issuer, validity,
                                #   subject(==issuer), pubkey }, algo, signature }
                                Static(
                                    "CertPrefix",
                                    bytes(
                                        [
                                            0x30,
                                            0x82,
                                            0x01,
                                            0x00,  # SEQUENCE (256 bytes)
                                            0x30,
                                            0x81,
                                            0xAD,  # TBSCertificate SEQUENCE
                                            # Version v3
                                            0xA0,
                                            0x03,
                                            0x02,
                                            0x01,
                                            0x02,
                                            # SerialNumber
                                            0x02,
                                            0x01,
                                            0x01,
                                            # Signature Algorithm (SHA256WithRSA OID)
                                            0x30,
                                            0x0D,
                                            0x06,
                                            0x09,
                                            0x2A,
                                            0x86,
                                            0x48,
                                            0x86,
                                            0xF7,
                                            0x0D,
                                            0x01,
                                            0x01,
                                            0x0B,
                                            0x05,
                                            0x00,
                                        ]
                                    ),
                                ),
                                # Issuer and Subject identical (self-referencing)
                                Group(
                                    "LoopingIssuer",
                                    values=[
                                        # CN=Loop repeated to create chain depth issues
                                        b"\x30\x0f\x31\x0d\x30\x0b\x06\x03\x55\x04\x03"
                                        b"\x0c\x04Loop" * 3,
                                        # Very long CN to trigger buffer issues
                                        b"\x30\x82\x01\x00\x31\x81\xfd\x30\x81\xfa\x06\x03\x55\x04\x03"
                                        b"\x0c\x81\xf0" + b"A" * 240,
                                    ],
                                ),
                                # Padding to fill certificate structure
                                RandomData("CertPadding", min_length=64, max_length=128),
                            ),
                        ),
                        # ReceiverCertificateThumbprint - null
                        DWord("ReceiverThumbprint_Length", 0xFFFFFFFF, endian="<"),
                        # SequenceHeader
                        DWord("SequenceNumber", 1, endian="<"),
                        DWord("RequestId", 1, endian="<"),
                        # OpenSecureChannelRequest
                        Static("TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("TypeId_Namespace", 0x00),
                        Word(
                            "TypeId_Identifier",
                            OPCUAServiceIds.OPEN_SECURE_CHANNEL_REQUEST,
                            endian="<",
                        ),
                        self._create_request_header(),
                        DWord("ClientProtocolVersion", 0, endian="<"),
                        DWord("RequestType", OPCUASecurityTokenRequestType.ISSUE, endian="<"),
                        DWord("SecurityMode", OPCUAMessageSecurityMode.SIGN, endian="<"),
                        DWord("ClientNonce_Length", 32, endian="<"),
                        RandomData("ClientNonce", min_length=32, max_length=32),
                        DWord("RequestedLifetime", 3600000, endian="<"),
                    ),
                ),
            ),
        )

        # 49. BrowsePathDepth - CVE-2023-32172 pattern
        # TranslateBrowsePaths with deeply nested RelativePath elements
        # Build 200+ path elements to trigger stack overflow in path resolution
        path_elements = []
        for i in range(200):
            path_elements.extend(
                [
                    # RelativePathElement
                    Static(f"RefTypeId_{i}_Enc", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                    Byte(f"RefTypeId_{i}_NS", 0x00),
                    Word(f"RefTypeId_{i}_Id", 35, endian="<"),  # Organizes
                    Byte(f"IsInverse_{i}", 0x00),
                    Byte(f"IncSubtypes_{i}", 0x01),
                    # TargetName (QualifiedName) - short name to keep message manageable
                    Word(f"TargetNS_{i}", 0x0000, endian="<"),
                    DWord(f"TargetLen_{i}", 1, endian="<"),
                    Static(f"TargetVal_{i}", b"X"),
                ]
            )

        browse_path_depth = Request(
            "OPCUA_BrowsePathDepth",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.TRANSLATE_BROWSE_PATHS_REQUEST,
                            authenticated=True,
                        ),
                        # BrowsePaths array - single path with 200 elements
                        DWord("BrowsePaths_Length", 1, endian="<"),
                        # StartingNode - Root folder (i=84)
                        Static("StartingNode_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("StartingNode_Namespace", 0x00),
                        Word("StartingNode_Identifier", 84, endian="<"),
                        # RelativePath with 200 elements
                        DWord("RelativePath_Elements_Length", 200, endian="<"),
                        *path_elements,
                    ),
                ),
            ),
        )

        # 50. SecurityTokenConfusion - CVE-2023-31048 pattern
        # MSG with deliberately mismatched security token values
        security_token_confusion = Request(
            "OPCUA_SecurityTokenConfusion",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        # Deliberately mismatched SecureChannelId
                        Group(
                            "SecureChannelId_Confused",
                            values=[
                                b"\x00\x00\x00\x00",  # Zero (invalid)
                                b"\xff\xff\xff\xff",  # Max uint32
                                b"\x01\x00\x00\x00",  # Wrong channel (1)
                                b"\xef\xbe\xad\xde",  # Recognizable garbage
                            ],
                        ),
                        # Deliberately mismatched TokenId
                        Group(
                            "TokenId_Confused",
                            values=[
                                b"\x00\x00\x00\x00",  # Zero (expired/invalid)
                                b"\xff\xff\xff\xff",  # Max uint32
                                b"\x01\x00\x00\x00",  # Potentially expired token
                                b"\xfe\xca\x0d\xf0",  # Recognizable garbage
                            ],
                        ),
                        DWord("SequenceNumber", 47, endian="<"),
                        DWord("RequestId", 47, endian="<"),
                        # Read request with confused tokens
                        Static("TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("TypeId_Namespace", 0x00),
                        Word("TypeId_Identifier", OPCUAServiceIds.READ_REQUEST, endian="<"),
                        self._create_request_header(authenticated=True),
                        # Minimal read body
                        QWord("MaxAge", 0, endian="<"),
                        DWord("TimestampsToReturn", 0, endian="<"),
                        DWord("NodesToRead_Length", 1, endian="<"),
                        Static("NodeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("NodeId_Namespace", 0x00),
                        Word("NodeId_Identifier", 2253, endian="<"),
                        DWord("AttributeId", 13, endian="<"),
                        DWord("IndexRange_Length", 0xFFFFFFFF, endian="<"),
                        Word("DataEncoding_NamespaceIndex", 0x0000, endian="<"),
                        DWord("DataEncoding_Name_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # 51. DeleteMonitoredItems Request
        delete_monitored_items = Request(
            "OPCUA_DeleteMonitoredItems",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.DELETE_MONITORED_ITEMS_REQUEST,
                            authenticated=True,
                        ),
                        # SubscriptionId
                        DWord("SubscriptionId", 1, endian="<"),
                        # MonitoredItemIds array
                        DWord("MonitoredItemIds_Length", 1, endian="<"),
                        DWord("MonitoredItemId_0", 1, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # NodeId encoding overflow: an OPC UA NodeId starts with a single
        # encoding byte that selects TwoByte/FourByte/Numeric/String/
        # Guid/ByteString (0-5 in spec). Sending the reserved values 6-15
        # (Group) and 16-31 (extended ServerIndex bit) historically
        # crashed asyncua / open62541 / S2OPC stacks because the decoder
        # used a switch with no default. Pair with oversized identifier
        # lengths to exercise the length-prefix path.
        # ============================================================
        nodeid_encoding_overflow = Request(
            "OPCUA_NodeIdEncodingOverflow",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        *self._create_msg_header(
                            OPCUAServiceIds.READ_REQUEST,
                            authenticated=True,
                        ),
                        # ReadRequest body — MaxAge, TimestampsToReturn
                        QWord("MaxAge", 0, endian="<"),
                        DWord(
                            "TimestampsToReturn",
                            OPCUATimestampsToReturn.NEITHER,
                            endian="<",
                        ),
                        # NodesToRead array (1 element)
                        DWord("NodesToRead_Length", 1, endian="<"),
                        # Reserved / extended encoding bytes — should be
                        # rejected; many stacks index a jump table without
                        # range-checking.
                        Group(
                            "NodeId_Encoding",
                            values=[
                                bytes([0x06]),  # reserved
                                bytes([0x07]),
                                bytes([0x0F]),  # high nibble = ServerIndex flag set
                                bytes([0x40]),  # NamespaceUri flag with no NodeId tag
                                bytes([0x80]),  # ServerIndex flag alone
                                bytes([0xC0]),  # Both flags, no encoding tag
                                bytes([0xFF]),
                            ],
                        ),
                        # Oversized identifier length to test bound checks.
                        DWord("NodeId_Identifier_Length", 0xFFFFFFFF, endian="<"),
                        # Payload bytes (limited size; the length field is the attack).
                        RandomData(
                            "NodeId_Identifier",
                            default_value=b"\x00" * 16,
                            min_length=0,
                            max_length=64,
                        ),
                        DWord("AttributeId", 13, endian="<"),  # Value
                        # IndexRange (null string)
                        DWord("IndexRange_Length", 0xFFFFFFFF, endian="<"),
                        # DataEncoding QualifiedName (null)
                        Word("DataEncoding_Namespace", 0, endian="<"),
                        DWord("DataEncoding_Name_Length", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # Malformed certificate body: OPCUA_CertChainLoop covers the
        # self-referencing-issuer path; this request goes after the other
        # cert-parse failure modes — truncated DER, oversized cert length
        # mismatched against payload, wrong outer tag, embedded null
        # within the BIT STRING. Targets pyasn1 / cryptography errors
        # surfaced through asyncua's certificate validator.
        # ============================================================
        malformed_cert = Request(
            "OPCUA_MalformedCert",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.OPEN_SECURE_CHANNEL),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="OPNBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "OPNBody",
                    children=(
                        DWord("SecureChannelId", 0, endian="<"),
                        Size(
                            "SecurityPolicyUri_Length",
                            block_name="SecurityPolicyUri_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        Block(
                            "SecurityPolicyUri_Data",
                            children=(
                                Static(
                                    "SecurityPolicyUri",
                                    OPCUASecurityPolicies.BASIC256SHA256.encode("utf-8"),
                                ),
                            ),
                        ),
                        # SenderCertificate length is the FIRST attack
                        # surface: declare 64 KiB but supply nothing,
                        # supply 4 bytes that look like a DER tag but
                        # truncate, or set length to -1 (0xFFFFFFFF).
                        Group(
                            "SenderCertificate_Length",
                            values=[
                                # Declared 65535 bytes, supply 0 — read-past-end
                                bytes([0xFF, 0xFF, 0x00, 0x00]),
                                # Declared INT_MAX — integer overflow path
                                bytes([0xFF, 0xFF, 0xFF, 0x7F]),
                                # Declared -1 (UINT max) — null-cert sentinel ambiguity
                                bytes([0xFF, 0xFF, 0xFF, 0xFF]),
                                # Declared 4 — supply garbage 4-byte DER prefix
                                bytes([0x04, 0x00, 0x00, 0x00]),
                            ],
                        ),
                        Group(
                            "SenderCertificate_Body",
                            values=[
                                b"",  # absent (matches length=0xFFFF/FFFFFFFF cases)
                                bytes([0x30, 0x82, 0xFF, 0xFF]),  # SEQUENCE with bogus length
                                bytes([0xFF, 0xFF, 0xFF, 0xFF]),  # wrong outer tag
                                bytes([0x30, 0x00]),  # empty SEQUENCE
                            ],
                        ),
                        # ReceiverCertificateThumbprint — null sentinel
                        DWord("ReceiverCertThumbprint_Length", 0xFFFFFFFF, endian="<"),
                        # SequenceHeader
                        DWord("SequenceNumber", self._next_sequence_number(), endian="<"),
                        DWord("RequestId", self._next_request_id(), endian="<"),
                        # Body — minimal OpenSecureChannelRequest with
                        # default fuzz fields so the cert-parse failure
                        # is reached BEFORE the body processor.
                        Static("TypeId_Encoding", bytes([OPCUANodeIdTypes.FOUR_BYTE])),
                        Byte("TypeId_Namespace", 0x00),
                        Word("TypeId_Identifier", 446, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # State confusion: send Read before OpenSecureChannel completes,
        # send CloseSession with an inactive token, send ActivateSession
        # before CreateSession. The boofuzz session graph below explicitly
        # wires this Request to fire at state SECURE_CHANNEL (post-OPN,
        # pre-session) so the target receives a session-required service
        # without a session — exposing state-machine assumptions.
        # ============================================================
        state_confusion_read = Request(
            "OPCUA_State_Confusion",
            children=(
                Block(
                    "Header",
                    children=(
                        Static("MessageType", OPCUAMessageTypes.MESSAGE),
                        Static("IsFinal", b"F"),
                        Size(
                            "MessageSize",
                            block_name="MSGBody",
                            length=4,
                            endian="<",
                            inclusive=False,
                            offset=8,
                            fuzzable=False,
                        ),
                    ),
                ),
                Block(
                    "MSGBody",
                    children=(
                        # Service ID rotated through the
                        # session-required catalog. Each one issued
                        # WITHOUT an authenticated session in the boofuzz
                        # session graph below.
                        Group(
                            "Service_Id",
                            values=[
                                # 631 = ReadRequest (needs session)
                                bytes([OPCUANodeIdTypes.FOUR_BYTE, 0x00, 0x77, 0x02]),
                                # 525 = BrowseRequest
                                bytes([OPCUANodeIdTypes.FOUR_BYTE, 0x00, 0x0D, 0x02]),
                                # 671 = WriteRequest
                                bytes([OPCUANodeIdTypes.FOUR_BYTE, 0x00, 0x9F, 0x02]),
                                # 712 = CallRequest
                                bytes([OPCUANodeIdTypes.FOUR_BYTE, 0x00, 0xC8, 0x02]),
                                # 793 = CreateSubscriptionRequest
                                bytes([OPCUANodeIdTypes.FOUR_BYTE, 0x00, 0x19, 0x03]),
                                # 473 = CloseSessionRequest (with no session)
                                bytes([OPCUANodeIdTypes.FOUR_BYTE, 0x00, 0xD9, 0x01]),
                            ],
                        ),
                        # Request header with null AuthenticationToken
                        # (proves the no-session attack vs auth-token-fuzz)
                        Static("AuthenticationToken", bytes([OPCUANodeIdTypes.TWO_BYTE, 0])),
                        QWord("Timestamp", 0, endian="<"),
                        DWord("RequestHandle", 1, endian="<"),
                        DWord("ReturnDiagnostics", 0, endian="<"),
                        Size(
                            "AuditEntryId_Length",
                            block_name="AuditEntryId_Data",
                            length=4,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        Block("AuditEntryId_Data", children=(Static("AuditEntryId", b""),)),
                        DWord("TimeoutHint", 1000, endian="<"),
                        # AdditionalHeader null ExtensionObject
                        Static("AdditionalHeader_TypeId", bytes([OPCUANodeIdTypes.TWO_BYTE, 0])),
                        Byte("AdditionalHeader_Encoding", 0x00),
                        # Minimal payload — empty arrays
                        DWord("Empty_Array_1", 0xFFFFFFFF, endian="<"),
                        DWord("Empty_Array_2", 0xFFFFFFFF, endian="<"),
                    ),
                ),
            ),
        )

        # ============================================================
        # 35. QUICK COVERAGE REQUEST
        # Touches all major OPC UA service categories in a single sweep
        # Non-fuzzable fields for fast execution (~30 seconds total)
        # Service IDs tested: Hello, OpenSecureChannel, GetEndpoints,
        # FindServers, CreateSession, Read, Browse, Write, Call,
        # CreateSubscription, CreateMonitoredItems, AddNodes
        # ============================================================
        quick_coverage = Request(
            "OPCUA_Quick_Coverage",
            children=(
                # Part 1: Hello message (connection layer)
                Block(
                    "HelloPart",
                    children=(
                        Static("HelloMsgType", OPCUAMessageTypes.HELLO),
                        Static("HelloIsFinal", b"F"),
                        DWord("HelloMsgSize", 56, endian="<", fuzzable=False),
                        DWord("HelloProtocolVersion", 0, endian="<", fuzzable=False),
                        DWord("HelloReceiveBuffer", receive_buffer, endian="<", fuzzable=False),
                        DWord("HelloSendBuffer", send_buffer, endian="<", fuzzable=False),
                        DWord("HelloMaxMessage", max_message, endian="<", fuzzable=False),
                        DWord("HelloMaxChunk", max_chunk, endian="<", fuzzable=False),
                        DWord("HelloEndpointLen", len(endpoint_url), endian="<", fuzzable=False),
                        Static("HelloEndpoint", endpoint_url.encode("utf-8")),
                    ),
                ),
            ),
        )

        # ============================================================
        # OPTIMIZED REQUEST ORDERING FOR EARLY COVERAGE & CRASH DETECTION
        # ============================================================
        # Optimization strategy based on OPC UA CVE patterns:
        # - CVE-2024-42513: Resource exhaustion via large allocations
        # - CVE-2024-10085: DoS via excessive requests
        # - CVE-2025-1468: Buffer overflow in parsing
        # - CVE-2024-42512: Write operation vulnerabilities
        #
        # Phase 1 (0-30s): Quick feature sweep - all operations once
        # Phase 2 (30s-2m): High-crash tests - overflow, boundary, malformed
        # Phase 3 (2m-5m): CVE-targeted operations - write, allocation attacks
        # Phase 4 (5m-10m): Boundary attacks - field limits, type confusion
        # Phase 5 (10m+): Deep fuzzing - comprehensive coverage
        # ============================================================

        # ============================================================
        # PHASE 0: QUICK COVERAGE (single request, ~30 seconds)
        # Fast sweep of all OPC UA operations for immediate coverage
        # ============================================================
        if self.is_request_enabled("OPCUA_Quick_Coverage"):
            self.session.connect(quick_coverage)

        # ============================================================
        # PHASE 1: QUICK COVERAGE SWEEP (~30 seconds)
        # Touch all major operations once with minimal mutations
        # ============================================================

        # Baseline connectivity - validates target is reachable
        if self.is_request_enabled("OPCUA_Baseline"):
            self.session.connect(hello_baseline)

        # Secure channel baseline - required for most services
        if self.is_request_enabled("OPCUA_SecureChannel"):
            self.session.connect(open_channel_baseline)

        # Discovery - safe, fast, validates MSG handling
        if self.is_request_enabled("OPCUA_Discovery"):
            self.session.connect(get_endpoints)
            self.session.connect(find_servers)
            self.session.connect(register_server)

        # Session - validates session state machine
        if self.is_request_enabled("OPCUA_Session"):
            self.session.connect(create_session)
            self.session.connect(cancel_request)

        # Read - validates attribute service
        if self.is_request_enabled("OPCUA_Read"):
            self.session.connect(read_request)

        # Browse - validates view service
        if self.is_request_enabled("OPCUA_Browse"):
            self.session.connect(browse_request)

        # Write - validates write path (CVE-2024-42512 target)
        if self.is_request_enabled("OPCUA_Write"):
            self.session.connect(write_request)

        # History update - validates history write path
        if self.is_request_enabled("OPCUA_History_Update"):
            self.session.connect(history_update)

        # Call - validates method invocation
        if self.is_request_enabled("OPCUA_Call"):
            self.session.connect(call_request)

        # Subscription - validates subscription service
        if self.is_request_enabled("OPCUA_Subscription"):
            self.session.connect(create_subscription)

        # ============================================================
        # PHASE 2: HIGH-CRASH TESTS (~90 seconds)
        # Buffer overflow, memory corruption, resource exhaustion
        # These patterns match CVE-2024-42513, CVE-2024-10085
        # ============================================================

        # Large array allocation attack - CVE-2024-10085 pattern
        # Claims massive array size, triggers memory allocation bugs
        if self.is_request_enabled("OPCUA_Malformed"):
            self.session.connect(large_array)

        # Chunk flooding - resource exhaustion DoS
        # Sends incomplete chunks to exhaust server resources
        if self.is_request_enabled("OPCUA_ChunkFlood"):
            self.session.connect(chunk_flood)

        # Nested extension objects - stack overflow attack
        # Deeply nested structures crash recursive parsers
        if self.is_request_enabled("OPCUA_NestedMessage"):
            self.session.connect(nested_extension)

        # Malformed NodeId encoding - CVE-2025-1468 pattern
        # Invalid type bytes cause parser crashes
        if self.is_request_enabled("OPCUA_Malformed"):
            self.session.connect(malformed_nodeid)

        # ExtensionObject TypeId fuzzing - vendor-reserved 0x6XXX range
        # Targets vendor-specific extension parsers (see cve_patterns.json)
        if self.is_request_enabled("OPCUA_ExtensionObject"):
            self.session.connect(extension_object)

        # UTF-8 malformed strings - encoding vulnerabilities
        # Invalid UTF-8 sequences crash string handlers
        if self.is_request_enabled("OPCUA_Malformed"):
            self.session.connect(utf8_fuzz)

        # Hello boundary testing - message size/field limits
        # Tests boundary conditions in Hello/ACK exchange
        if self.is_request_enabled("OPCUA_Boundary"):
            self.session.connect(hello_boundary)
            self.session.connect(security_token_confusion)

        # CVE-targeted certificate attack - CVE-2022-37013
        if self.is_request_enabled("OPCUA_CertAttack"):
            self.session.connect(cert_chain_loop)

        # Deep browse path - CVE-2023-32172 stack overflow
        if self.is_request_enabled("OPCUA_Malformed"):
            self.session.connect(browse_path_depth)

        # ============================================================
        # PHASE 3: CVE-TARGETED OPERATIONS (~3 minutes)
        # Write operations and node management - high CVE density
        # ============================================================

        # Node management - AddNodes/DeleteNodes/References (write path)
        if self.is_request_enabled("OPCUA_NodeManagement"):
            self.session.connect(add_nodes)
            self.session.connect(delete_nodes)
            self.session.connect(add_references)
            self.session.connect(delete_references)

        # History read
        if self.is_request_enabled("OPCUA_History_Read"):
            self.session.connect(history_read)

        # Monitored items - resource allocation attacks
        # CVE pattern: Flooding with monitored items causes DoS
        if self.is_request_enabled("OPCUA_MonitoredItems"):
            self.session.connect(create_monitored_items)
            self.session.connect(modify_monitored_items)
            self.session.connect(set_triggering)

        # ============================================================
        # PHASE 4: BOUNDARY ATTACKS (~5 minutes)
        # Field boundary testing, type confusion, protocol violations
        # ============================================================

        # OpenSecureChannel with fuzzable fields
        if self.is_request_enabled("OPCUA_SecureChannel"):
            self.session.connect(open_channel_fuzz)

        # Hello with fuzzable fields (after baseline)
        if self.is_request_enabled("OPCUA_Discovery"):
            self.session.connect(hello_fuzz)
            self.session.connect(reverse_hello)
            self.session.connect(find_servers_on_network)

        # ============================================================
        # PHASE 5: COMPREHENSIVE COVERAGE (~remaining time)
        # Complete protocol coverage, all remaining operations
        # ============================================================

        # Session management completion
        if self.is_request_enabled("OPCUA_Session"):
            self.session.connect(activate_session)
            self.session.connect(close_session)

        # Authentication fuzzing - username/password token attacks
        # Uses SmartString with CREDENTIAL context for targeted credential fuzzing
        if self.is_request_enabled("OPCUA_Auth"):
            self.session.connect(activate_session_auth_fuzz)

        # Discovery completion
        if self.is_request_enabled("OPCUA_Discovery"):
            self.session.connect(register_server2)

        # Browse operations completion
        if self.is_request_enabled("OPCUA_Browse"):
            self.session.connect(browse_next)
            self.session.connect(translate_browse_paths)
            self.session.connect(register_nodes)
            self.session.connect(unregister_nodes)

        # Subscription operations completion
        if self.is_request_enabled("OPCUA_Subscription"):
            self.session.connect(modify_subscription)
            self.session.connect(delete_subscriptions)
            self.session.connect(set_publishing_mode)
            self.session.connect(transfer_subscriptions)

        if self.is_request_enabled("OPCUA_Publish"):
            self.session.connect(publish_request)
            self.session.connect(republish_request)

        # MonitoredItems completion
        if self.is_request_enabled("OPCUA_MonitoredItems"):
            self.session.connect(set_monitoring_mode)
            self.session.connect(delete_monitored_items)

        # Channel cleanup
        if self.is_request_enabled("OPCUA_SecureChannel"):
            self.session.connect(close_channel)

        # Three new request groups from §4 sweep (2026-06-03):
        if self.is_request_enabled("OPCUA_NodeIdEncodingOverflow"):
            self.session.connect(nodeid_encoding_overflow)
        if self.is_request_enabled("OPCUA_MalformedCert"):
            self.session.connect(malformed_cert)
        if self.is_request_enabled("OPCUA_State_Confusion"):
            self.session.connect(state_confusion_read)

        return self.session
