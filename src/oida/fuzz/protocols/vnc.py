"""VNC Protocol Fuzzer with State Machine Support

The fuzzer drives the RFB handshake (version exchange -> security negotiation
-> authentication) through a StateMachine, then fuzzes pre-auth or post-auth
client messages. A shared StateContext is created in __init__ and passed to the
state machine; the challenge nonce is stashed in its crypto store so the
challenge-response step can recover it.
"""

from typing import List

from boofuzz import Block, Delim, Group, Request, Static

from ..core.base_fuzzer import BaseFuzzer, CommonState, RequestInfo
from ..core.config import FuzzerConfig
from ..core.session.state_machine import ProtocolState, StateMachine, StateType
from ..core.session import StateContext
from ..monitors import SocketHealthMonitor
from ..primitives.dynamic import SmartBytes, SmartString
from ..primitives.smart_string import StringContext


class VNCSecurityTypes:
    """VNC security type constants"""

    INVALID = 0
    NONE = 1
    VNC_AUTH = 2
    RA2 = 5
    RA2NE = 6
    TIGHT = 16
    ULTRA = 17
    TLS = 18
    VENCRYPT = 19
    SASL = 20
    MD5_HASH = 21
    XVP = 22


class VNCFuzzer(BaseFuzzer):
    """
    Unified VNC Protocol Fuzzer with state machine authentication support.

    Consolidates pre-auth, auth, and post-auth fuzzing into a single fuzzer.
    Use `use_auth=false` for pre-authentication phase fuzzing only.
    Use `use_auth=true` (default) for post-authentication fuzzing.

    State Machine (when use_auth=True):
        CONNECTED -> VERSION_EXCHANGED -> SECURITY_NEGOTIATED -> AUTHENTICATED
    """

    PROTOCOL_OPTIONS = {
        "use_auth": {
            "type": bool,
            "default": True,
            "description": "Enable VNC authentication and state validation (set false for pre-auth fuzzing)",
        },
        "vnc_password": {
            "type": str,
            "default": "password",
            "description": "VNC password for authentication",
        },
        "vnc_version": {
            "type": str,
            "default": "003.008",
            "description": "VNC protocol version to use",
            "example": "003.008",
        },
        "screen_width": {
            "type": int,
            "default": 1024,
            "description": "Screen width for framebuffer operations",
        },
        "screen_height": {
            "type": int,
            "default": 768,
            "description": "Screen height for framebuffer operations",
        },
        "timeout": {
            "type": float,
            "default": 5.0,
            "description": "Connection timeout in seconds",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests

        VNC Protocol States:
        - PRE_AUTH: Version handshake, security negotiation (before auth challenge)
        - AUTHENTICATING: VNC authentication challenge/response
        - AUTHENTICATED: Post-auth client operations

        Custom VNC states (for state machine):
        - VERSION_EXCHANGED: After RFB version exchange
        - SECURITY_NEGOTIATED: After security type selection
        """
        return [
            # Pre-auth requests (before authentication)
            RequestInfo(
                "StaticProtocolVersion",
                "Static RFB version baseline",
                "baseline",
                requires_state=CommonState.PRE_AUTH,
            ),
            RequestInfo(
                "ProtocolVersionDynVersion",
                "Version number fuzzing",
                "preauth",
                requires_state=CommonState.PRE_AUTH,
            ),
            RequestInfo(
                "ProtocolVersionDynAll",
                "Full version string fuzzing",
                "preauth",
                requires_state=CommonState.PRE_AUTH,
            ),
            RequestInfo(
                "SecurityTypeSelection",
                "Security type negotiation fuzzing",
                "preauth",
                requires_state="VERSION_EXCHANGED",
            ),  # After version exchange
            RequestInfo(
                "SecurityTypeResponse",
                "Security type response fuzzing",
                "preauth",
                requires_state="VERSION_EXCHANGED",
            ),
            RequestInfo(
                "MalformedMessages",
                "Malformed and oversized messages",
                "attacks",
                requires_state=CommonState.ANY,
            ),  # Can be sent any time
            # Auth requests (during authentication)
            RequestInfo(
                "VNCAuth",
                "VNC authentication challenge fuzzing",
                "auth",
                requires_state="SECURITY_NEGOTIATED",
            ),  # After security type selected
            # Post-auth requests (after successful authentication)
            RequestInfo(
                "ClientInit",
                "Client initialization fuzzing",
                "postauth",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "SetPixelFormat",
                "Pixel format configuration fuzzing",
                "postauth",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "SetEncodings",
                "Encoding type fuzzing",
                "postauth",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "FramebufferUpdateRequest",
                "Framebuffer update request fuzzing",
                "postauth",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "KeyEvent",
                "Keyboard event fuzzing",
                "postauth",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "PointerEvent",
                "Mouse/pointer event fuzzing",
                "postauth",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "VNC_Overflow",
                "Oversized framebuffer and encoding overflow",
                "overflow",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "VNC_Boundary",
                "Boundary values for pixel format and dimensions",
                "boundary",
                requires_state=CommonState.AUTHENTICATED,
            ),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        self.port = config.target_port or 5900

        # Get options from config
        self.use_auth = config.get_option("use_auth", True) if config else True
        self.password = config.get_option("vnc_password", "password") if config else "password"
        self.vnc_version = config.get_option("vnc_version", "003.008") if config else "003.008"
        self.screen_width = config.get_option("screen_width", 1024) if config else 1024
        self.screen_height = config.get_option("screen_height", 768) if config else 768
        self.timeout = config.get_option("timeout", 5.0) if config else 5.0

        # Track authentication state
        self.security_type = None

        # State Machine V2: Create shared StateContext for VNC protocol
        # This context carries data between state transitions (VERSION -> SECURITY -> AUTH)
        self._state_context = StateContext()

        super().__init__(config, connection_factory)

    def setup_custom_monitors(self) -> List:
        """Setup VNC-specific monitors"""
        return [
            SocketHealthMonitor(
                host=self.config.target_ip,
                port=self.port,
                retry_count=3,
                timeout=2,
            )
        ]

    def _define_state_machine(self) -> None:
        """
        Define VNC state machine for authentication.

        State Machine V2 Integration:
        - StateContext is created in __init__ and passed to state machine
        - Responses are stored in context for cross-state access
        - State callbacks can access context for logging and state setup

        States:
        - CONNECTED: TCP connection established
        - VERSION_EXCHANGED: RFB version handshake complete
        - SECURITY_NEGOTIATED: Security type selected
        - AUTHENTICATED: Authentication successful
        """
        if not self.use_auth:
            self.log.display("VNC authentication disabled (use_auth=false), skipping state machine")
            return

        # Create multi-state VNC state machine
        connected = ProtocolState(
            name="CONNECTED",
            state_type=StateType.CONNECTION,
            description="TCP connection established",
        )

        version_exchanged = ProtocolState(
            name="VERSION_EXCHANGED",
            state_type=StateType.SESSION,
            setup=self._exchange_version,
            requires=["CONNECTED"],
            description="RFB version handshake complete",
        )

        security_negotiated = ProtocolState(
            name="SECURITY_NEGOTIATED",
            state_type=StateType.SESSION,
            setup=self._negotiate_security,
            requires=["VERSION_EXCHANGED"],
            description="Security type selected",
        )

        authenticated = ProtocolState(
            name="AUTHENTICATED",
            state_type=StateType.AUTHENTICATION,
            setup=self._perform_vnc_auth,
            validation=self._validate_vnc_auth,
            requires=["SECURITY_NEGOTIATED"],
            description="VNC authentication successful",
        )

        # State Machine V2: Pass context for response data propagation
        self.state_machine = StateMachine(
            initial_state=connected,
            states=[connected, version_exchanged, security_negotiated, authenticated],
            allow_invalid_transitions=False,
            context=self._state_context,
        )

        # Auth is deferred until connection is established in fuzz_all()
        self.log.display("VNC state machine created (auth deferred until connection ready)")

    def _get_auth_socket(self):
        """
        Get or create socket for preflight authentication check.

        Creates a direct socket connection for VNC handshake validation,
        separate from boofuzz's session management. Used only to verify
        credentials are valid before starting the fuzz campaign.
        """
        if not hasattr(self, "_auth_sock") or self._auth_sock is None:
            import socket

            self._auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._auth_sock.settimeout(self.timeout)
            self._auth_sock.connect((self.config.target_ip, self.config.target_port))
        return self._auth_sock

    def _close_auth_socket(self):
        """Close the preflight authentication socket."""
        if hasattr(self, "_auth_sock") and self._auth_sock:
            try:
                self._auth_sock.close()
            except Exception as e:
                self.log.debug(f"Socket close error: {e}")
            self._auth_sock = None

    def _exchange_version(self) -> bool:
        """
        Exchange RFB version with server (state machine callback).
        CONNECTED -> VERSION_EXCHANGED

        Uses the preflight auth socket (state machine transitions use _get_auth_socket).
        """
        return self._do_exchange_version(self._get_auth_socket())

    def _negotiate_security(self) -> bool:
        """
        Negotiate security type with server (state machine callback).
        VERSION_EXCHANGED -> SECURITY_NEGOTIATED
        """
        return self._do_negotiate_security(self._get_auth_socket())

    def _perform_vnc_auth(self) -> bool:
        """
        Perform VNC authentication (state machine callback).
        SECURITY_NEGOTIATED -> AUTHENTICATED
        """
        return self._do_perform_auth(self._get_auth_socket())

    def _do_exchange_version(self, sock) -> bool:
        """
        Exchange RFB version with server on the given socket.

        Args:
            sock: Socket to perform the version exchange on
        """
        try:
            # Receive server version
            server_version = sock.recv(12)
            if not server_version.startswith(b"RFB "):
                self.log.fail(f"Invalid server version: {server_version}")
                return False

            self.log.debug(f"Server version: {server_version.strip()}")

            # Send client version
            client_version = f"RFB {self.vnc_version}\n".encode()
            sock.send(client_version)
            self.log.debug(f"Sent client version: {self.vnc_version}")

            return True

        except Exception as e:
            self.log.fail(f"Version exchange failed: {e}")
            return False

    def _do_negotiate_security(self, sock) -> bool:
        """
        Negotiate security type with server on the given socket.

        Args:
            sock: Socket to perform security negotiation on
        """
        try:
            # Receive number of security types
            types_count_byte = sock.recv(1)
            if len(types_count_byte) != 1:
                self.log.fail("Failed to receive security type count")
                return False

            types_count = ord(types_count_byte)

            if types_count == 0:
                # Error case - read error message
                error_len_bytes = sock.recv(4)
                if len(error_len_bytes) == 4:
                    error_len = int.from_bytes(error_len_bytes, "big")
                    error_msg = sock.recv(error_len)
                    self.log.fail(f"Security negotiation error: {error_msg}")
                return False

            # Receive security types
            security_types = sock.recv(types_count)
            self.log.debug(f"Available security types: {list(security_types)}")

            # Select security type (prefer NONE, then VNC_AUTH)
            if VNCSecurityTypes.NONE in security_types:
                selected = VNCSecurityTypes.NONE
                self.security_type = "NONE"
            elif VNCSecurityTypes.VNC_AUTH in security_types:
                selected = VNCSecurityTypes.VNC_AUTH
                self.security_type = "VNC_AUTH"
            else:
                self.log.fail(f"No supported security types in: {list(security_types)}")
                return False

            # Send selected type
            sock.send(bytes([selected]))
            self.log.display(f"Selected security type: {self.security_type}")

            return True

        except Exception as e:
            self.log.fail(f"Security negotiation failed: {e}")
            return False

    def _do_perform_auth(self, sock) -> bool:
        """
        Perform VNC authentication on the given socket.

        Args:
            sock: Socket to perform authentication on
        """
        try:
            if self.security_type == "NONE":
                self.log.display("No authentication required (security type: NONE)")
                # For RFB 3.8, even with NONE we get a SecurityResult
                result = sock.recv(4)
                if result == b"\x00\x00\x00\x00":
                    return True
                else:
                    self.log.fail(f"Security result failed: {result.hex()}")
                    return False

            # Receive 16-byte challenge
            challenge = sock.recv(16)
            if len(challenge) != 16:
                self.log.fail(f"Invalid challenge length: {len(challenge)}")
                return False

            self.log.debug(f"Received challenge: {challenge.hex()}")

            # Store challenge in crypto state for cross-state access
            self._state_context.crypto.set_nonce("vnc_challenge", challenge)

            # Process challenge with VNC DES (bit-reversed key, ECB mode)
            response = self._process_challenge(challenge, self.password.encode())

            sock.send(response)

            # Receive security result
            result = sock.recv(4)
            if result == b"\x00\x00\x00\x00":
                self.log.display("VNC authentication successful")
                return True
            else:
                self.log.fail(f"VNC authentication failed: result={result.hex()}")
                return False

        except Exception as e:
            self.log.fail(f"VNC authentication exception: {e}")
            return False

    def _handshake_on_socket(self, sock) -> bool:
        """
        Perform the complete VNC handshake (version + security + auth) on a socket.

        Used by the pre_send callback to authenticate each boofuzz connection
        before fuzz payloads are sent.

        Args:
            sock: Raw socket to perform the handshake on

        Returns:
            True if handshake completed successfully
        """
        if not self._do_exchange_version(sock):
            return False
        if not self._do_negotiate_security(sock):
            return False
        if not self._do_perform_auth(sock):
            return False
        return True

    def _process_challenge(self, challenge: bytes, password: bytes) -> bytes:
        """
        Process VNC DES challenge-response authentication.

        VNC authentication uses a modified DES cipher where each byte of the
        password key has its bits reversed (mirrored) before encryption. The
        16-byte server challenge is then encrypted in two 8-byte blocks using
        DES-ECB mode.

        Args:
            challenge: 16-byte challenge from VNC server
            password: Password bytes (truncated/padded to 8 bytes per VNC spec)

        Returns:
            16-byte encrypted response
        """
        # Retrieve challenge from crypto state if available
        stored_challenge = self._state_context.crypto.get_nonce("vnc_challenge")
        if stored_challenge is not None:
            challenge = stored_challenge

        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, modes

            # TripleDES moved to decrepit module in cryptography >= 43.0
            try:
                from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            except ImportError:
                from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
        except ImportError:
            self.log.warning(
                "cryptography library not installed -- VNC auth will fail. "
                "Install with: pip install oida-ics[fuzz]"
            )
            return b"\x00" * 16

        # Pad or truncate password to exactly 8 bytes (VNC spec)
        key = (password[:8]).ljust(8, b"\x00")

        # VNC reverses the bits in each byte of the key
        reversed_key = bytes(sum(((b >> i) & 1) << (7 - i) for i in range(8)) for b in key)

        # Encrypt each 8-byte half of the challenge with DES-ECB
        # Use TripleDES with the key repeated to get single-DES behavior,
        # since cryptography library requires 16 or 24 byte keys for DES.
        des_key = reversed_key + reversed_key + reversed_key  # 24 bytes for TripleDES
        # VNC's authentication protocol (RFC 6143 §7.2.2) mandates DES-ECB;
        # we emit it via TripleDES with a tripled key (TripleDES with the same
        # key three times == single DES) because the cryptography library
        # dropped raw DES. The "weak cipher" warning here is intrinsic to the
        # VNC spec, not a fuzzer flaw.
        cipher = Cipher(TripleDES(des_key), modes.ECB())  # nosec B304 B305
        encryptor = cipher.encryptor()
        return encryptor.update(challenge[:16]) + encryptor.finalize()

    def _validate_vnc_auth(self) -> bool:
        """
        Validate VNC connection is still authenticated.

        For VNC, once authenticated, the connection stays authenticated
        until closed. We can't easily validate without affecting state.
        """
        # VNC doesn't have a simple ping - just assume valid if we got here
        return True

    def _define_protocol(self) -> None:
        """Define VNC protocol messages for fuzzing."""

        if not self.use_auth:
            # Pre-auth mode: Fuzz version handshake and security negotiation
            self._define_preauth_protocol()
        else:
            # Post-auth mode: Fuzz client messages after authentication
            self._define_postauth_protocol()

    def _define_preauth_protocol(self) -> None:
        """Define pre-authentication VNC protocol messages."""

        # Protocol Version Requests
        version_static = Request(
            "StaticProtocolVersion",
            children=(
                Block(
                    "Version",
                    children=(
                        Static("header", "RFB"),
                        Static("space", " "),
                        Static("version_bytes", "003.008"),
                        Static("terminator", "\n"),
                    ),
                )
            ),
        )

        version_dyn_version = Request(
            "ProtocolVersionDynVersion",
            children=(
                Block(
                    "Version",
                    children=(
                        Static("header", "RFB"),
                        Static("space", " "),
                        SmartString("version_bytes", "003.008"),
                        Static("terminator", "\n"),
                    ),
                )
            ),
        )

        version_dyn_all = Request(
            "ProtocolVersionDynAll",
            children=(
                Block(
                    "Version",
                    children=(
                        SmartString("header", "RFB "),
                        Delim("space", " "),
                        SmartString("version_bytes", "003.008"),
                        Delim("terminator", "\n"),
                    ),
                )
            ),
        )

        # Security Type Selection
        security = Request(
            "SecurityTypeSelection",
            children=(
                Block(
                    "SecurityHandshake",
                    children=(
                        SmartBytes("num_security_types", b"\x01"),
                        SmartBytes("security_types_list", b"\x01\x02"),
                        SmartBytes("padding", b"\x00\x00"),
                        Block(
                            "ErrorMessage",
                            children=(
                                SmartBytes("error_length", b"\x00\x00\x00\x04"),
                                SmartBytes("error_message", b"Error"),
                            ),
                        ),
                    ),
                )
            ),
        )

        # Security Type Response
        sec_response = Request(
            "SecurityTypeResponse",
            children=(
                Block(
                    "Response",
                    children=(
                        SmartBytes("selected_type", b"\x02"),
                        Block(
                            "Challenge",
                            children=(SmartBytes("challenge_bytes", b"\x00" * 16)),
                        ),
                        Block(
                            "SecurityData",
                            children=(SmartBytes("security_params", b"")),
                        ),
                    ),
                )
            ),
        )

        # VNC Authentication Challenge/Response
        vnc_auth = Request(
            "VNCAuth",
            children=(
                Block(
                    "Auth",
                    children=(
                        SmartBytes("challenge_response", b"\x00" * 16),
                        SmartBytes("password_hash", b"\x00" * 8, max_len=16),
                    ),
                )
            ),
        )

        # Malformed Messages
        malformed = Request(
            "MalformedMessages",
            children=(
                Block(
                    "Malformed",
                    children=(
                        SmartBytes("random_data", b"\x00"),
                        Block(
                            "PartialValid",
                            children=(
                                Static("rfb_prefix", "RFB "),
                                SmartBytes(
                                    "corrupt_version",
                                    b"003.008\n",
                                    max_len=32,
                                    fuzzable=True,
                                ),
                            ),
                        ),
                        Block(
                            "Oversized",
                            children=(
                                SmartBytes(
                                    "large_message",
                                    b"\x00" * 64,
                                    max_len=4096,
                                    fuzzable=True,
                                )
                            ),
                        ),
                    ),
                )
            ),
        )

        # Connect requests in fuzzing flow, honoring --enable/--disable filters.
        # version_dyn_all / version_dyn_version are independent roots; the rest
        # form a chain rooted at version_static:
        #   version_static -> security -> {sec_response -> vnc_auth, malformed}
        # When a downstream request is enabled its prerequisite path nodes are
        # also connected so boofuzz can reach it.
        if self.is_request_enabled("ProtocolVersionDynAll"):
            self.session.connect(version_dyn_all)
        if self.is_request_enabled("ProtocolVersionDynVersion"):
            self.session.connect(version_dyn_version)

        static_enabled = self.is_request_enabled("StaticProtocolVersion")
        security_enabled = self.is_request_enabled("SecurityTypeSelection")
        sec_response_enabled = self.is_request_enabled("SecurityTypeResponse")
        vnc_auth_enabled = self.is_request_enabled("VNCAuth")
        malformed_enabled = self.is_request_enabled("MalformedMessages")

        need_security = (
            security_enabled or sec_response_enabled or vnc_auth_enabled or malformed_enabled
        )
        if need_security:
            # version_static is the chain root and is reached as a side effect.
            self.session.connect(version_static, security)
        elif static_enabled:
            self.session.connect(version_static)
        if sec_response_enabled or vnc_auth_enabled:
            self.session.connect(security, sec_response)
        if vnc_auth_enabled:
            self.session.connect(sec_response, vnc_auth)
        if malformed_enabled:
            self.session.connect(security, malformed)

    def _define_postauth_protocol(self) -> None:
        """Define post-authentication VNC protocol messages."""

        # Client Init
        client_init = Request(
            "ClientInit",
            children=(Block("Init", children=(Group("shared_flag", values=[b"\x00", b"\x01"])))),
        )

        # SetPixelFormat (message type 0)
        pixel_format = Request(
            "SetPixelFormat",
            children=(
                Block(
                    "Format",
                    children=(
                        Static("message_type", b"\x00"),
                        Static("padding", b"\x00\x00\x00"),
                        SmartString(
                            "bits_per_pixel",
                            "32",
                            max_len=2,
                            context=StringContext.NUMERIC,
                        ),
                        SmartString("depth", "24", max_len=2, context=StringContext.NUMERIC),
                        Group("big_endian", values=[b"\x00", b"\x01"]),
                        Group("true_color", values=[b"\x00", b"\x01"]),
                        SmartString("red_max", "255", max_len=4, context=StringContext.NUMERIC),
                        SmartString("green_max", "255", max_len=4, context=StringContext.NUMERIC),
                        SmartString("blue_max", "255", max_len=4, context=StringContext.NUMERIC),
                        SmartString("red_shift", "16", max_len=2, context=StringContext.NUMERIC),
                        SmartString("green_shift", "8", max_len=2, context=StringContext.NUMERIC),
                        SmartString("blue_shift", "0", max_len=2, context=StringContext.NUMERIC),
                        Static("padding2", b"\x00\x00\x00"),
                    ),
                )
            ),
        )

        # SetEncodings (message type 2)
        encodings = Request(
            "SetEncodings",
            children=(
                Block(
                    "EncodingTypes",
                    children=(
                        Static("message_type", b"\x02"),
                        Static("padding", b"\x00"),
                        SmartString(
                            "num_encodings",
                            "4",
                            max_len=4,
                            context=StringContext.NUMERIC,
                        ),
                        Group(
                            "encoding_types",
                            values=[
                                b"\x00\x00\x00\x00",  # Raw
                                b"\x00\x00\x00\x01",  # CopyRect
                                b"\x00\x00\x00\x02",  # RRE
                                b"\x00\x00\x00\x05",  # Hextile
                                b"\xff\xff\xff\xff",  # Invalid
                            ],
                        ),
                    ),
                )
            ),
        )

        # FramebufferUpdateRequest (message type 3)
        fb_update = Request(
            "FramebufferUpdateRequest",
            children=(
                Block(
                    "UpdateReq",
                    children=(
                        Static("message_type", b"\x03"),
                        Group("incremental", values=[b"\x00", b"\x01"]),
                        SmartString("x_pos", "0", max_len=4, context=StringContext.NUMERIC),
                        SmartString("y_pos", "0", max_len=4, context=StringContext.NUMERIC),
                        SmartString(
                            "width",
                            str(self.screen_width),
                            max_len=4,
                            context=StringContext.NUMERIC,
                        ),
                        SmartString(
                            "height",
                            str(self.screen_height),
                            max_len=4,
                            context=StringContext.NUMERIC,
                        ),
                    ),
                )
            ),
        )

        # KeyEvent (message type 4)
        key_event = Request(
            "KeyEvent",
            children=(
                Block(
                    "Key",
                    children=(
                        Static("message_type", b"\x04"),
                        Group("down_flag", values=[b"\x00", b"\x01"]),
                        Static("padding", b"\x00\x00"),
                        SmartString("key", "a", max_len=4),
                    ),
                )
            ),
        )

        # PointerEvent (message type 5)
        pointer_event = Request(
            "PointerEvent",
            children=(
                Block(
                    "Pointer",
                    children=(
                        Static("message_type", b"\x05"),
                        SmartString("button_mask", "0", max_len=1, context=StringContext.NUMERIC),
                        SmartString("x_pos", "0", max_len=2, context=StringContext.NUMERIC),
                        SmartString("y_pos", "0", max_len=2, context=StringContext.NUMERIC),
                    ),
                )
            ),
        )

        # Overflow: oversized framebuffer request dimensions
        overflow_test = Request(
            "VNC_Overflow",
            children=(
                Block(
                    "OverflowReq",
                    children=(
                        # FramebufferUpdateRequest with max dimensions
                        Static("message_type", b"\x03"),
                        Static("incremental", b"\x00"),
                        Static("x_pos", b"\xff\xff"),
                        Static("y_pos", b"\xff\xff"),
                        Static("width", b"\xff\xff"),
                        Static("height", b"\xff\xff"),
                    ),
                ),
            ),
        )

        # Boundary: edge values for pixel format fields
        boundary_test = Request(
            "VNC_Boundary",
            children=(
                Block(
                    "BoundaryReq",
                    children=(
                        # SetPixelFormat with boundary values
                        Static("message_type", b"\x00"),
                        Static("padding", b"\x00\x00\x00"),
                        # bits-per-pixel = 0 (invalid boundary)
                        SmartString("bpp", "0", max_len=1, context=StringContext.NUMERIC),
                        # depth = 0
                        SmartString("depth", "0", max_len=1, context=StringContext.NUMERIC),
                        # big-endian flag
                        Group("big_endian", values=[b"\x00", b"\x01", b"\xff"]),
                        # true-colour flag
                        Group("true_colour", values=[b"\x00", b"\x01", b"\xff"]),
                        Static("rest", b"\x00" * 12),
                    ),
                ),
            ),
        )

        # Connect requests in fuzzing flow, honoring --enable/--disable filters.
        # The post-auth messages form a chain rooted at ClientInit:
        #   client_init -> pixel_format -> encodings -> {leaf messages}
        # boofuzz can only reach a node through a connected parent, so when a
        # downstream request is enabled its prerequisite path nodes are also
        # connected (the same pattern smtp.py uses for its HELO prerequisite).
        client_init_enabled = self.is_request_enabled("ClientInit")
        pixel_format_enabled = self.is_request_enabled("SetPixelFormat")
        encodings_enabled = self.is_request_enabled("SetEncodings")
        fb_update_enabled = self.is_request_enabled("FramebufferUpdateRequest")
        key_event_enabled = self.is_request_enabled("KeyEvent")
        pointer_event_enabled = self.is_request_enabled("PointerEvent")
        overflow_enabled = self.is_request_enabled("VNC_Overflow")
        boundary_enabled = self.is_request_enabled("VNC_Boundary")
        any_leaf_enabled = (
            fb_update_enabled
            or key_event_enabled
            or pointer_event_enabled
            or overflow_enabled
            or boundary_enabled
        )
        # encodings is a prerequisite for every leaf; pixel_format for encodings;
        # client_init for everything.
        need_encodings = encodings_enabled or any_leaf_enabled
        need_pixel_format = pixel_format_enabled or need_encodings
        need_client_init = client_init_enabled or need_pixel_format

        if need_client_init:
            self.session.connect(client_init)
        if need_pixel_format:
            self.session.connect(client_init, pixel_format)
        if need_encodings:
            self.session.connect(pixel_format, encodings)
        if fb_update_enabled:
            self.session.connect(encodings, fb_update)
        if key_event_enabled:
            self.session.connect(encodings, key_event)
        if pointer_event_enabled:
            self.session.connect(encodings, pointer_event)
        if overflow_enabled:
            self.session.connect(encodings, overflow_test)
        if boundary_enabled:
            self.session.connect(encodings, boundary_test)

    def _preflight_auth_check(self):
        """
        Preflight check: verify VNC credentials are valid before starting fuzz campaign.

        Opens a temporary socket, performs the full VNC handshake, and closes it.
        This validates that the password is correct before wasting time on fuzzing.
        The actual per-test-case authentication is handled by the pre_send callback.
        """
        if not self.use_auth or not self.state_machine:
            return

        current_state = self.state_machine.get_current_state_name()

        if current_state != "AUTHENTICATED":
            self.log.display(f"VNC preflight auth check (current state: {current_state})...")
            try:
                self.state_machine.transition_to("VERSION_EXCHANGED")
                self.state_machine.transition_to("SECURITY_NEGOTIATED")
                self.state_machine.transition_to("AUTHENTICATED")
                self.log.display("VNC preflight auth check passed")
                # Close preflight socket -- boofuzz manages its own connections
                self._close_auth_socket()
            except Exception as e:
                self._close_auth_socket()
                self.log.fail(f"VNC authentication failed: {e}")
                self.log.fail("Check your credentials (--option vnc_password=<password>)")
                self.log.fail("Or use --option use_auth=false to fuzz without authentication")
                raise

    def fuzz_all(self) -> None:
        """
        Override fuzz_all to add VNC authentication before fuzzing.

        VNC requires completing the RFB handshake (version exchange, security
        negotiation, authentication) before sending client messages. Each new
        boofuzz connection needs its own handshake.

        Flow:
        1. Preflight check validates credentials on a temporary socket
        2. pre_send callback performs handshake on each boofuzz connection
        3. Fuzz payloads are sent on the authenticated connection
        """
        # Access session to trigger lazy initialization
        _ = self.session

        if self.use_auth and self.state_machine:
            self.log.display("VNC fuzzing with authentication enabled")

            # Preflight: verify credentials are valid
            self._preflight_auth_check()

            # Track which boofuzz connection has been authenticated to avoid
            # re-authenticating the same connection on every test case
            self._vnc_authenticated_conn_id = None
            self._vnc_auth_failed = False

            def vnc_auth_pre_send(target, fuzz_data_logger, session, sock):
                """Pre-send callback: perform VNC handshake on each new connection."""
                if self._vnc_auth_failed:
                    raise ConnectionError("VNC authentication failed; aborting fuzz session")

                conn = target._target_connection
                generation = getattr(conn, "_connection_generation", 0)
                current_identity = (id(conn), generation)

                # Skip if this connection generation is already authenticated
                if current_identity == self._vnc_authenticated_conn_id:
                    return

                # Get the raw socket from the boofuzz connection
                raw_sock = getattr(conn, "_sock", None)
                if raw_sock is None:
                    self.log.fail("Cannot access boofuzz connection socket for VNC handshake")
                    self._vnc_auth_failed = True
                    return

                self.log.debug(f"VNC handshake on connection gen {generation}")

                # Reset state machine for the new connection
                self.state_machine.reset_to_initial()

                if self._handshake_on_socket(raw_sock):
                    # The handshake on raw_sock genuinely walked through version
                    # exchange, security negotiation, and authentication. Reflect
                    # each real step in the state machine history (the setup
                    # callbacks already ran on raw_sock, so use set_state_no_setup
                    # to record the transitions without re-running them).
                    self.state_machine.set_state_no_setup("VERSION_EXCHANGED")
                    self.state_machine.set_state_no_setup("SECURITY_NEGOTIATED")
                    self.state_machine.set_state_no_setup("AUTHENTICATED")
                    self._vnc_authenticated_conn_id = current_identity
                    self.log.debug("VNC handshake successful on boofuzz connection")
                else:
                    self.log.fail("VNC handshake failed on boofuzz connection")
                    self._vnc_auth_failed = True

            self.session._callback_monitor.on_pre_send.append(vnc_auth_pre_send)

        # Run normal fuzzing (skip StatefulFuzzer's auth since we handle it)
        super().fuzz_all()
