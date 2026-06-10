"""FTP Protocol Fuzzer

Refactored to use the StatefulFuzzer framework with:
- FTPConnection: Stateful connection with banner consumption
- FTPSConnection: FTP + TLS upgrade (AUTH TLS, PBSZ, PROT P)
- FTPAuthenticator: USER/PASS authentication

State Machine V2 Integration:
- StateContext: Carries response data between state transitions
- Response storage: Stores banner, AUTH responses for cross-state access
- Context-aware callbacks: State callbacks can access shared context

Integration Pattern Example:
    This fuzzer demonstrates the StateContext integration pattern:

    1. Create StateContext in __init__:
        self._state_context = StateContext()

    2. Store responses for cross-state data access:
        ctx.set_response("BANNER", ResponseData(raw=banner, parsed={"server": server_name}))
        ctx.set_response("AUTH", ResponseData(raw=response, parsed={"code": 230}))

    3. Access previous responses in later states:
        banner_resp = ctx.get_response("BANNER")
        if banner_resp:
            print(f"Server: {banner_resp.parsed.get('server')}")
"""

import ssl
import sys
from typing import List, Optional

from boofuzz import Block, Delim, Group, Request, Static

from ..core.base_fuzzer import CommonState, RequestInfo
from ..core.config import FuzzerConfig
from ..core.connections.stateful import StatefulConnection, TLSHandler
from ..core.session.state_machine import create_auth_state_machine
from ..core.session import StateContext, ResponseData
from ..core.stateful_fuzzer import StatefulFuzzer
from ..core.auth import UsernamePasswordAuth, ProtocolAuthenticator
from ..primitives.dynamic import SmartString
from ..primitives.smart_string import StringContext


# =============================================================================
# FTP Connection Classes (using StatefulConnection framework)
# =============================================================================


class FTPConnection(StatefulConnection):
    """FTP connection that consumes the 220 banner on connect.

    FTP servers send a 220 greeting immediately after TCP connect.
    This must be consumed before sending commands, otherwise it mixes
    with command responses causing timing issues.
    """

    def __init__(
        self,
        host: str,
        port: int = 21,
        send_timeout: float = 5.0,
        recv_timeout: float = 5.0,
        protocol_name: str = "FTP",
    ):
        super().__init__(host, port, send_timeout, recv_timeout, protocol_name)

    def _perform_handshake(self) -> None:
        """Consume FTP 220 banner."""
        banner = self._consume_banner(b"220")
        self.server_info["banner"] = banner.decode("utf-8", errors="ignore").strip()
        self._log.debug(f"Server: {self.server_info['banner'][:60]}")


class FTPSConnection(FTPConnection):
    """FTPS connection - FTP with TLS upgrade (AUTH TLS, PBSZ, PROT P).

    Uses composition (TLSHandler) instead of multiple inheritance for
    cleaner architecture and simpler MRO.

    Performs the complete FTPS upgrade sequence:
    1. Consume 220 banner
    2. Send AUTH TLS, wait for 234
    3. Wrap socket with TLS
    4. Send PBSZ 0, wait for 200
    5. Send PROT P, wait for 200
    """

    def __init__(
        self,
        host: str,
        port: int = 21,
        send_timeout: float = 5.0,
        recv_timeout: float = 5.0,
        sslcontext: Optional[ssl.SSLContext] = None,
        server_hostname: str = None,
        protocol_name: str = "FTPS",
    ):
        # Use composition for TLS functionality
        self.tls_handler = TLSHandler(sslcontext=sslcontext)
        self.server_hostname = server_hostname or host
        # Initialize FTP connection
        super().__init__(host, port, send_timeout, recv_timeout, protocol_name)

    @property
    def is_secure(self) -> bool:
        """Whether TLS is active (delegates to TLSHandler)."""
        return self.tls_handler.is_secure

    def _perform_handshake(self) -> None:
        """Consume banner and upgrade to TLS."""
        # First consume the banner
        super()._perform_handshake()

        # Then upgrade to TLS using the handler
        self._log.debug("Upgrading to FTPS")
        self.tls_handler.upgrade_connection(
            self,
            starttls_cmd=b"AUTH TLS\r\n",
            expected_code=234,
            server_hostname=self.server_hostname,
        )

        # Send PBSZ 0 and PROT P over TLS
        self._send_command(b"PBSZ 0\r\n", [200])
        self._send_command(b"PROT P\r\n", [200])
        self._log.display("FTPS upgrade complete (AUTH TLS + PBSZ + PROT P)")

    def send(self, data):
        """Send data over TLS connection."""
        if len(data) == 0:
            return 0
        try:
            return self._sock.send(data)
        except ssl.SSLError as e:
            raise Exception(f"TLS send error: {e}")

    def recv(self, max_bytes):
        """Receive data over TLS connection."""
        try:
            return self._sock.recv(max_bytes)
        except ssl.SSLError as e:
            raise Exception(f"TLS recv error: {e}")

    def get_tls_info(self) -> dict:
        """Get TLS connection information (delegates to TLSHandler)."""
        return self.tls_handler.get_tls_info()


# Legacy aliases for backwards compatibility
FTPSocketConnection = FTPConnection
FTPSSocketConnection = FTPSConnection


# =============================================================================
# FTP Authenticator (using ProtocolAuthenticator framework)
# =============================================================================


class FTPAuthenticator(UsernamePasswordAuth):
    """FTP USER/PASS authentication.

    Handles standard FTP authentication with:
    - USER command (expects 331)
    - PASS command (expects 230)
    - PWD validation (expects 257)
    """

    def __init__(
        self,
        username: str = "anonymous",
        password: str = "anonymous@example.com",
        protocol_name: str = "FTP",
    ):
        super().__init__(
            username=username,
            password=password,
            user_cmd_fmt="USER {}\r\n",
            pass_cmd_fmt="PASS {}\r\n",
            user_ok_codes=[331],
            pass_ok_codes=[230],
            protocol_name=protocol_name,
        )

    def validate(self, conn) -> bool:
        """Validate authentication with PWD command.

        Args:
            conn: Connection with _send_command method

        Returns:
            True if PWD returns 257
        """
        self._log.debug("Validating auth with PWD")
        try:
            code, _ = conn._send_command(b"PWD\r\n")
            return code == 257
        except Exception as e:
            self._log.fail(f"PWD validation failed: {e}")
            return False


class FTPFuzzer(StatefulFuzzer):
    """FTP Fuzzer implementation using StatefulFuzzer framework.

    Uses:
    - FTPConnection/FTPSConnection for protocol handshakes
    - FTPAuthenticator for USER/PASS authentication
    - State machine for FTPS upgrade sequence
    """

    # StatefulFuzzer configuration
    PROTOCOL_NAME = "ftp"
    CONNECTION_CLASS = FTPConnection  # Will be overridden in _create_socket if use_tls=True
    AUTHENTICATOR_CLASS = FTPAuthenticator

    # Protocol-specific monitor: FTP PWD check every 50 tests
    DEFAULT_MONITORS = "ftp:50"

    PROTOCOL_OPTIONS = {
        "ftp_username": {
            "type": str,
            "default": "anonymous",
            "description": "FTP username for authentication",
            "example": "testuser",
        },
        "ftp_password": {
            "type": str,
            "default": "anonymous@example.com",
            "description": "FTP password for authentication",
            "example": "password123",
        },
        "use_auth": {
            "type": bool,
            "default": True,
            "description": "Enable authentication and state validation",
        },
        "use_tls": {
            "type": bool,
            "default": False,
            "description": "Use FTPS (FTP over TLS) with AUTH TLS command",
        },
        "use_capability_detection": {
            "type": bool,
            "default": True,
            "description": "Parse FEAT response to skip unsupported commands (30-50% faster)",
        },
        "datachannel_attacks": {
            "type": bool,
            "default": False,
            "description": "Enable data channel attack patterns (overflow, path traversal, format strings)",
        },
    }

    def __init__(
        self,
        config: FuzzerConfig,
        username: str = None,
        password: str = None,
        use_auth: bool = None,
        connection_factory=None,
    ):
        # Authentication credentials - use options if not provided
        self.username = username or config.get_option("ftp_username", "anonymous")
        self.password = password or config.get_option("ftp_password", "anonymous@example.com")
        self.use_auth = use_auth if use_auth is not None else config.get_option("use_auth", True)

        # Capability detection - stores supported features from FEAT command
        self.supported_features = set()
        self.use_capability_detection = config.get_option("use_capability_detection", True)
        self.server_banner = None  # Store server banner for logging

        # State Machine V2: Create shared StateContext for FTP protocol
        # This context carries data between state transitions (CONNECTED -> AUTH -> TLS -> etc.)
        self._state_context = StateContext()

        # Detect capabilities BEFORE super().__init__ calls _define_protocol
        # Respect both use_capability_detection option AND enumerate config
        if self.use_capability_detection and self.use_auth and config.enumerate:
            self._early_capability_detection(config)

        super().__init__(config, connection_factory)

    @property
    def context(self) -> StateContext:
        """Get the StateContext for data propagation.

        State Machine V2 Pattern:
        Protocols can use this to access shared state:
            ctx = fuzzer.context
            banner = ctx.get_response("BANNER")
            auth_result = ctx.get_response("AUTH")
        """
        return self._state_context

    def store_banner_response(self, banner: str) -> None:
        """Store FTP banner response for later reference.

        State Machine V2 Pattern:
        Store the 220 banner from connection for cross-state access.

        Args:
            banner: Server banner text (e.g., "220 vsFTPd 3.0.3 ready.")
        """
        self._state_context.set_response(
            "BANNER",
            ResponseData(
                raw=banner.encode("utf-8") if isinstance(banner, str) else banner,
                parsed={"server": banner.strip() if banner else ""},
                response_code=220,
            ),
        )
        self._state_context.set("server_banner", banner)

    def store_auth_response(self, response: str, code: int, success: bool) -> None:
        """Store FTP authentication response.

        State Machine V2 Pattern:
        Store USER/PASS response for cross-state access.

        Args:
            response: Response text from server
            code: FTP response code (230=success, 530=failed)
            success: Whether authentication succeeded
        """
        self._state_context.set_response(
            "AUTH",
            ResponseData(
                raw=response.encode("utf-8") if isinstance(response, str) else response,
                parsed={"code": code, "success": success, "message": response.strip()},
                response_code=code,
            ),
        )
        self._state_context.set("authenticated", success)

    def get_ftp_state_info(self) -> dict:
        """Get current FTP state information.

        State Machine V2 Pattern:
        Use this for debugging and logging state.

        Returns:
            Dictionary with context keys and responses
        """
        return {
            "authenticated": self._state_context.get("authenticated", False),
            "server_banner": self._state_context.get("server_banner"),
            "context_keys": self._state_context.keys(),
            "responses_stored": self._state_context.response_keys(),
        }

    def _create_authenticator(self, config: FuzzerConfig) -> Optional[ProtocolAuthenticator]:
        """Create FTP authenticator from config options."""
        if not self.use_auth:
            return None

        return FTPAuthenticator(username=self.username, password=self.password, protocol_name="FTP")

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests

        Ordering optimized for early boundary/crash detection:
        - Phase 1: Auth fuzzing (PRE_AUTH for true pre-auth testing)
        - Phase 2: Critical path commands (AUTHENTICATED)
        - Phase 3+: Other categories in risk order

        State Requirements:
        - PRE_AUTH: Runs before authentication (USER/PASS fuzzing)
        - AUTHENTICATED: Runs after login (most commands)
        - ANY: Can run in any state (generic fuzzing)
        """
        return [
            # PHASE 1: AUTH FUZZING (USER/PASS - requires PRE_AUTH state)
            # Use -O use_auth=false for true pre-auth mode where no login happens
            RequestInfo(
                "FTP_Auth_Fuzz",
                "USER/PASS fuzzing (use -O use_auth=false for pre-auth)",
                "auth",
                requires_state=CommonState.PRE_AUTH,
            ),
            # PHASE 2: CRITICAL PATH COMMANDS (highest crash potential, requires login)
            RequestInfo(
                "FTP_Critical_Path",
                "CWD/MKD path fuzzing (SmartString boundaries)",
                "critical",
                requires_state=CommonState.AUTHENTICATED,
            ),
            # PHASE 3: BASELINE & SAFE INFO COMMANDS (requires login)
            RequestInfo(
                "FTP_Baseline",
                "Safe info commands (NOOP, PWD, SYST, FEAT, STAT, HELP)",
                "baseline",
                requires_state=CommonState.AUTHENTICATED,
            ),
            # PHASE 4: DIRECTORY READ COMMANDS (requires login)
            RequestInfo(
                "FTP_Directory_Read",
                "Directory listing (NLST, MLST, MLSD, SIZE, MDTM)",
                "read",
                requires_state=CommonState.AUTHENTICATED,
            ),
            # PHASE 5: NAVIGATION (requires login)
            RequestInfo(
                "FTP_Navigation",
                "Directory navigation (CDUP)",
                "navigation",
                requires_state=CommonState.AUTHENTICATED,
            ),
            # PHASE 6: DATA TRANSFER SETUP (requires login)
            RequestInfo(
                "FTP_Transfer_Setup",
                "Transfer configuration (PASV, EPSV, EPRT, TYPE, MODE, STRU)",
                "transfer",
                requires_state=CommonState.AUTHENTICATED,
            ),
            # PHASE 7: WRITE OPERATIONS (requires login)
            RequestInfo(
                "FTP_File_Write",
                "File write operations (APPE, ALLO, REST)",
                "write",
                requires_state=CommonState.AUTHENTICATED,
            ),
            # PHASE 8: DANGEROUS OPERATIONS (requires login)
            RequestInfo(
                "FTP_Dangerous",
                "Destructive operations (DELE, RMD, RNFR, RNTO, MFMT, MFCT)",
                "dangerous",
                requires_state=CommonState.AUTHENTICATED,
            ),
            # PHASE 9: SECURITY & TLS (can run pre-auth - AUTH TLS comes before login)
            RequestInfo(
                "FTP_Security",
                "Security/TLS commands (AUTH, PBSZ, PROT, CCC)",
                "security",
                requires_state=CommonState.PRE_AUTH,
            ),
            # PHASE 10: EXOTIC/RARE COMMANDS (requires login)
            RequestInfo(
                "FTP_Extended",
                "Extended features (HASH, AVBL, DSIZ, LANG, CSID, CLNT, HOST, ACCT, ABOR)",
                "extended",
                requires_state=CommonState.AUTHENTICATED,
            ),
            # PHASE 11: GENERIC FUZZER (can run in any state)
            RequestInfo(
                "FTP_Generic",
                "Generic command fuzzer",
                "generic",
                requires_state=CommonState.ANY,
            ),
            # NO-AUTH MODE COMMANDS (for testing without authentication)
            RequestInfo(
                "FTP_NoAuth_Basic",
                "Basic no-auth commands (CWD, LIST, PORT, OPTS, MKD, SITE, REST, QUIT)",
                "no_auth",
                requires_state=CommonState.PRE_AUTH,
            ),
            RequestInfo(
                "FTP_NoAuth_Transfer",
                "No-auth file transfer (STOR, RETR)",
                "no_auth",
                requires_state=CommonState.PRE_AUTH,
            ),
            # DATA CHANNEL ATTACKS (enabled via -O datachannel_attacks=true, requires login)
            RequestInfo(
                "FTP_DC_Overflow",
                "Buffer overflow on paths/filenames",
                "datachannel",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "FTP_DC_Path_Traversal",
                "Path traversal attacks ../",
                "datachannel",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "FTP_DC_Format_String",
                "Format string injection (%s, %n, %x)",
                "datachannel",
                requires_state=CommonState.AUTHENTICATED,
            ),
        ]

    def _early_capability_detection(self, config: FuzzerConfig) -> None:
        """Detect server capabilities before building session graph.

        Note: Creates a temporary ICSLogger since self.log isn't available yet.
        """
        import socket
        from oida.utils.ics_logger import get_logger

        # Create temporary logger for early detection
        log = get_logger("FUZZ-FTP", config.target_ip, config.target_port)
        log.display("Probing FTP server capabilities...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((config.target_ip, config.target_port))

            # Read banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            # Extract server name from banner (e.g., "220 vsFTPd 3.0.3 ready.")
            if banner.startswith("220"):
                self.server_banner = banner[4:].strip() if len(banner) > 4 else banner
            else:
                self.server_banner = banner[:60]
            log.display(f"Server: {self.server_banner[:60]}")

            # Login
            sock.send(f"USER {self.username}\r\n".encode())
            resp = sock.recv(1024).decode("utf-8", errors="ignore")
            if not resp.startswith("331"):
                log.display("Login failed at USER, assuming all commands supported")
                sock.close()
                self.supported_features = set(["*"])
                return

            sock.send(f"PASS {self.password}\r\n".encode())
            resp = sock.recv(1024).decode("utf-8", errors="ignore")
            if not resp.startswith("230"):
                log.display("Login failed at PASS, assuming all commands supported")
                sock.close()
                self.supported_features = set(["*"])
                return

            # Send FEAT
            sock.send(b"FEAT\r\n")
            response = b""
            while True:
                chunk = sock.recv(4096)
                response += chunk
                text = response.decode("utf-8", errors="ignore")
                if "211 " in text or "500 " in text or "502 " in text or not chunk:
                    break

            text = response.decode("utf-8", errors="ignore")
            if text.startswith("211"):
                for line in text.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("211"):
                        continue
                    parts = line.split()
                    if parts:
                        self.supported_features.add(parts[0].upper())
                log.display(f"Supported features: {', '.join(sorted(self.supported_features))}")
            else:
                log.display("FEAT not supported, fuzzing all commands")
                self.supported_features = set(["*"])

            sock.send(b"QUIT\r\n")
            sock.close()

        except Exception as e:
            log.warning(f"Capability detection failed ({e}), fuzzing all commands")
            self.supported_features = set(["*"])

    def _create_socket(self):
        """Create FTP connection (consumes 220 banner on connect)."""
        use_tls = self.config.get_option("use_tls", False)
        if use_tls:
            return FTPSSocketConnection(
                self.config.target_ip,
                self.config.target_port,
                **self._timeout_overrides(),
            )
        return FTPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            **self._timeout_overrides(),
        )

    def _log_capabilities(self) -> None:
        """Log probed FTP server capabilities."""
        if not self.use_capability_detection or not self.config.enumerate:
            return

        fuzz_log = self._get_fuzz_logger()

        # Display summary
        if self.server_banner:
            fuzz_log.display(f"Server: {self.server_banner}")

        if self.supported_features and "*" not in self.supported_features:
            fuzz_log.display(f"Supported: {', '.join(sorted(self.supported_features))}")

            # Show unsupported exotic commands that will be skipped
            exotic_commands = {
                "HASH",
                "AVBL",
                "DSIZ",
                "LANG",
                "CSID",
                "CLNT",
                "HOST",
                "ACCT",
                "MLST",
                "MLSD",
                "MDTM",
                "EPSV",
                "EPRT",
                "MFMT",
                "MFCT",
            }
            unsupported = exotic_commands - self.supported_features
            if unsupported:
                fuzz_log.display(f"Unsupported: {', '.join(sorted(unsupported))} (will be skipped)")
                fuzz_log.display("Tip: Use --no-enumerate to fuzz all commands anyway")
        elif "*" in self.supported_features:
            fuzz_log.display("Features: unknown (fuzzing all commands)")

    def _define_protocol(self) -> None:
        """Define FTP protocol requests

        CAPABILITY DETECTION IMPLEMENTED:
        - Sends FEAT command after successful authentication (RFC 2389)
        - Parses response to detect supported server features
        - Conditionally skips unsupported commands during fuzzing
        - Provides 30-50% speedup by avoiding rarely-supported commands

        Features commonly skipped on basic servers:
        - AVBL, DSIZ (space/size queries)
        - HASH, MFMT, MFCT (file metadata)
        - CSID, CLNT, HOST (client/host identification)
        - MLST, MLSD (machine-readable listings)

        Enable/disable with protocol option:
            --option use_capability_detection=true  (default)
            --option use_capability_detection=false (test all commands)
        """

        # Static authentication sequence
        Request(
            "auth_user",
            children=(
                Static("cmd_user", "USER"),
                Static(" ", " "),
                Static("username", self.username),
                Static("CRLF", "\r\n"),
            ),
        )

        Request(
            "auth_psw",
            children=(
                Static("cmd_pass", "PASS"),
                Static(" ", " "),
                Static("password", self.password),
                Static("CRLF", "\r\n"),
            ),
        )

        cmd_user = Request(
            "USER",
            children=(
                Static("cmd", "USER"),
                Delim(" ", " "),
                SmartString(
                    "username",
                    self.username,
                    max_len=512,
                    context=StringContext.CREDENTIAL,
                ),
                Static("CRLF", "\r\n"),
            ),
        )

        cmd_pass = Request(
            "PASS",
            children=(
                Static("cmd", "PASS"),
                Delim(" ", " "),
                SmartString(
                    "password",
                    self.password,
                    max_len=512,
                    context=StringContext.CREDENTIAL,
                ),
                Static("CRLF", "\r\n"),
            ),
        )

        # Fuzzable commands after authentication
        cmd_cwd = Request(
            "CWD",
            children=(
                Block(
                    "CWD_Cmd",
                    children=(
                        Static("cmd", "CWD"),
                        Delim(" ", " "),
                        SmartString("path", "/", max_len=2048, context=StringContext.PATH),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_list = Request(
            "LIST",
            children=(
                Block(
                    "LIST_Cmd",
                    children=(
                        Static("cmd", "LIST"),
                        Group("space_opt", values=[" ", ""]),
                        SmartString("path_opt", "", max_len=2048, context=StringContext.PATH),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_port = Request(
            "PORT",
            children=(
                Block(
                    "PORT_Cmd",
                    children=(
                        Static("cmd", "PORT"),
                        Delim(" ", " "),
                        SmartString(
                            "host_port",
                            "127,0,0,1,4,0",
                            max_len=128,
                            context=StringContext.IP_ADDRESS,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_stor = Request(
            "STOR",
            children=(
                Block(
                    "STOR_Cmd",
                    children=(
                        Static("cmd", "STOR"),
                        Delim(" ", " "),
                        SmartString(
                            "filename",
                            "test.txt",
                            max_len=512,
                            context=StringContext.FILENAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_retr = Request(
            "RETR",
            children=(
                Block(
                    "RETR_Cmd",
                    children=(
                        Static("cmd", "RETR"),
                        Delim(" ", " "),
                        SmartString(
                            "filename",
                            "test.txt",
                            max_len=512,
                            context=StringContext.FILENAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_rest = Request(
            "REST",
            children=(
                Block(
                    "REST_Cmd",
                    children=(
                        Static("cmd", "REST"),
                        Delim(" ", " "),
                        SmartString("offset", "0", max_len=32, context=StringContext.NUMERIC),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # Special format commands
        cmd_opts = Request(
            "OPTS",
            children=(
                Block(
                    "OPTS_Cmd",
                    children=(
                        Static("cmd", "OPTS"),
                        Delim(" ", " "),
                        Group("option", values=["UTF8", "MLST", "MLSD", "REST", "LANG"]),
                        Group("space_opt", values=[" ", ""]),
                        SmartString("value", "ON", max_len=32, context=StringContext.GENERIC),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_mkd = Request(
            "MKD",
            children=(
                Block(
                    "MKD_Cmd",
                    children=(
                        Static("cmd", "MKD"),
                        Delim(" ", " "),
                        SmartString("dirname", "test", max_len=512, context=StringContext.PATH),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_site = Request(
            "SITE",
            children=(
                Block(
                    "SITE_Cmd",
                    children=(
                        Static("cmd", "SITE"),
                        Delim(" ", " "),
                        Group(
                            "command",
                            values=["CHMOD", "HELP", "UMASK", "GROUP", "IDLE", "TIME"],
                        ),
                        Group("space_opt", values=[" ", ""]),
                        SmartString(
                            "arguments",
                            "644 test.txt",
                            max_len=512,
                            context=StringContext.COMMAND,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_quit = Request(
            "QUIT",
            children=(Block("QUIT_Cmd", children=(Static("cmd", "QUIT"), Static("CRLF", "\r\n")))),
        )

        cmd_abor = Request(
            "ABOR",
            children=(Block("ABOR_Cmd", children=(Static("cmd", "ABOR"), Static("CRLF", "\r\n")))),
        )

        cmd_acct = Request(
            "ACCT",
            children=(
                Block(
                    "ACCT_Cmd",
                    children=(
                        Static("cmd", "ACCT"),
                        Delim(" ", " "),
                        SmartString(
                            "account",
                            "test",
                            max_len=512,
                            context=StringContext.CREDENTIAL,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_appe = Request(
            "APPE",
            children=(
                Block(
                    "APPE_Cmd",
                    children=(
                        Static("cmd", "APPE"),
                        Delim(" ", " "),
                        SmartString(
                            "filename",
                            "test.txt",
                            max_len=512,
                            context=StringContext.FILENAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_cdup = Request(
            "CDUP",
            children=(Block("CDUP_Cmd", children=(Static("cmd", "CDUP"), Static("CRLF", "\r\n")))),
        )

        cmd_dele = Request(
            "DELE",
            children=(
                Block(
                    "DELE_Cmd",
                    children=(
                        Static("cmd", "DELE"),
                        Delim(" ", " "),
                        SmartString(
                            "filename",
                            "test.txt",
                            max_len=512,
                            context=StringContext.FILENAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_eprt = Request(
            "EPRT",
            children=(
                Block(
                    "EPRT_Cmd",
                    children=(
                        Static("cmd", "EPRT"),
                        Delim(" ", " "),
                        SmartString(
                            "address",
                            "|1|132.235.1.2|6275|",
                            max_len=128,
                            context=StringContext.IP_ADDRESS,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_epsv = Request(
            "EPSV",
            children=(
                Block(
                    "EPSV_Cmd",
                    children=(
                        Static("cmd", "EPSV"),
                        Group("arg_opt", values=[" ALL", ""]),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_help = Request(
            "HELP",
            children=(
                Block(
                    "HELP_Cmd",
                    children=(
                        Static("cmd", "HELP"),
                        Group("space_opt", values=[" ", ""]),
                        SmartString("command", "", max_len=64, context=StringContext.COMMAND),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_mode = Request(
            "MODE",
            children=(
                Block(
                    "MODE_Cmd",
                    children=(
                        Static("cmd", "MODE"),
                        Delim(" ", " "),
                        Group("mode", values=["S", "B", "C"]),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_nlst = Request(
            "NLST",
            children=(
                Block(
                    "NLST_Cmd",
                    children=(
                        Static("cmd", "NLST"),
                        Group("space_opt", values=[" ", ""]),
                        SmartString("path", "", max_len=512, context=StringContext.PATH),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_noop = Request(
            "NOOP",
            children=(Block("NOOP_Cmd", children=(Static("cmd", "NOOP"), Static("CRLF", "\r\n")))),
        )

        cmd_pasv = Request(
            "PASV",
            children=(Block("PASV_Cmd", children=(Static("cmd", "PASV"), Static("CRLF", "\r\n")))),
        )

        cmd_pwd = Request(
            "PWD",
            children=(Block("PWD_Cmd", children=(Static("cmd", "PWD"), Static("CRLF", "\r\n")))),
        )

        cmd_rmd = Request(
            "RMD",
            children=(
                Block(
                    "RMD_Cmd",
                    children=(
                        Static("cmd", "RMD"),
                        Delim(" ", " "),
                        SmartString("dirname", "test", max_len=512, context=StringContext.PATH),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_rnfr = Request(
            "RNFR",
            children=(
                Block(
                    "RNFR_Cmd",
                    children=(
                        Static("cmd", "RNFR"),
                        Delim(" ", " "),
                        SmartString(
                            "filename",
                            "test.txt",
                            max_len=512,
                            context=StringContext.FILENAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_rnto = Request(
            "RNTO",
            children=(
                Block(
                    "RNTO_Cmd",
                    children=(
                        Static("cmd", "RNTO"),
                        Delim(" ", " "),
                        SmartString(
                            "filename",
                            "test2.txt",
                            max_len=512,
                            context=StringContext.FILENAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_stat = Request(
            "STAT",
            children=(
                Block(
                    "STAT_Cmd",
                    children=(
                        Static("cmd", "STAT"),
                        Group("space_opt", values=[" ", ""]),
                        SmartString("path", "", max_len=512, context=StringContext.PATH),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_stru = Request(
            "STRU",
            children=(
                Block(
                    "STRU_Cmd",
                    children=(
                        Static("cmd", "STRU"),
                        Delim(" ", " "),
                        Group("structure", values=["F", "R", "P"]),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_syst = Request(
            "SYST",
            children=(Block("SYST_Cmd", children=(Static("cmd", "SYST"), Static("CRLF", "\r\n")))),
        )

        cmd_type = Request(
            "TYPE",
            children=(
                Block(
                    "TYPE_Cmd",
                    children=(
                        Static("cmd", "TYPE"),
                        Delim(" ", " "),
                        Group("type", values=["A", "I", "E", "L"]),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_allo = Request(
            "ALLO",
            children=(
                Block(
                    "ALLO_Cmd",
                    children=(
                        Static("cmd", "ALLO"),
                        Delim(" ", " "),
                        SmartString("size", "1024", max_len=32, context=StringContext.NUMERIC),
                        Group("space_opt", values=[" ", ""]),
                        SmartString("record_size", "", max_len=32, context=StringContext.NUMERIC),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_size = Request(
            "SIZE",
            children=(
                Block(
                    "SIZE_Cmd",
                    children=(
                        Static("cmd", "SIZE"),
                        Delim(" ", " "),
                        SmartString(
                            "filename",
                            "test.txt",
                            max_len=512,
                            context=StringContext.FILENAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # Additional FTP Commands based on RFC standards

        # MLSD - Machine List Directory (RFC 3659)
        cmd_mlsd = Request(
            "MLSD",
            children=(
                Block(
                    "MLSD_Cmd",
                    children=(
                        Static("cmd", "MLSD"),
                        Group("space_opt", values=[" ", ""]),
                        SmartString("path", "", max_len=512, context=StringContext.PATH),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # MLST - Machine List (RFC 3659)
        cmd_mlst = Request(
            "MLST",
            children=(
                Block(
                    "MLST_Cmd",
                    children=(
                        Static("cmd", "MLST"),
                        Group("space_opt", values=[" ", ""]),
                        SmartString("path", "", max_len=512, context=StringContext.PATH),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # FEAT - Feature Negotiation (RFC 2389)
        cmd_feat = Request(
            "FEAT",
            children=(Block("FEAT_Cmd", children=(Static("cmd", "FEAT"), Static("CRLF", "\r\n")))),
        )

        # AUTH - Authentication/Security Mechanism (RFC 2228)
        cmd_auth = Request(
            "AUTH",
            children=(
                Block(
                    "AUTH_Cmd",
                    children=(
                        Static("cmd", "AUTH"),
                        Delim(" ", " "),
                        Group(
                            "mechanism",
                            values=["TLS", "SSL", "TLS-C", "TLS-P", "GSSAPI"],
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # PBSZ - Protection Buffer Size (RFC 2228)
        cmd_pbsz = Request(
            "PBSZ",
            children=(
                Block(
                    "PBSZ_Cmd",
                    children=(
                        Static("cmd", "PBSZ"),
                        Delim(" ", " "),
                        SmartString("size", "0", max_len=32, context=StringContext.NUMERIC),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # PROT - Data Channel Protection Level (RFC 2228)
        cmd_prot = Request(
            "PROT",
            children=(
                Block(
                    "PROT_Cmd",
                    children=(
                        Static("cmd", "PROT"),
                        Delim(" ", " "),
                        Group("level", values=["C", "S", "E", "P"]),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # LANG - Language Negotiation (RFC 2640)
        cmd_lang = Request(
            "LANG",
            children=(
                Block(
                    "LANG_Cmd",
                    children=(
                        Static("cmd", "LANG"),
                        Group("space_opt", values=[" ", ""]),
                        SmartString("language", "EN", max_len=32, context=StringContext.GENERIC),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # MFMT - Modify Fact: Modification Time (RFC 3659)
        cmd_mfmt = Request(
            "FTP_MFMT",
            children=(
                Block(
                    "FTP_MFMT_Block",
                    children=(
                        Static("cmd", "MFMT"),
                        Delim("sp1", " "),
                        SmartString(
                            "timestamp",
                            "20240101120000",
                            max_len=32,
                            context=StringContext.NUMERIC,
                        ),
                        Delim("sp2", " "),
                        SmartString(
                            "filename",
                            "test.txt",
                            max_len=512,
                            context=StringContext.FILENAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # MFCT - Modify Fact: Create Time (RFC 3659)
        cmd_mfct = Request(
            "FTP_MFCT",
            children=(
                Block(
                    "FTP_MFCT_Block",
                    children=(
                        Static("cmd", "MFCT"),
                        Delim("sp1", " "),
                        SmartString(
                            "timestamp",
                            "20240101120000",
                            max_len=32,
                            context=StringContext.NUMERIC,
                        ),
                        Delim("sp2", " "),
                        SmartString(
                            "filename",
                            "test.txt",
                            max_len=512,
                            context=StringContext.FILENAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # HASH - Cryptographic Hash (RFC draft)
        cmd_hash = Request(
            "HASH",
            children=(
                Block(
                    "HASH_Cmd",
                    children=(
                        Static("cmd", "HASH"),
                        Group("space_opt", values=[" ", ""]),
                        SmartString(
                            "algorithm",
                            "SHA-1",
                            max_len=32,
                            context=StringContext.GENERIC,
                        ),
                        Group("space_opt2", values=[" ", ""]),
                        SmartString(
                            "filename",
                            "test.txt",
                            max_len=512,
                            context=StringContext.FILENAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # CSID - Client/Server Identification
        cmd_csid = Request(
            "CSID",
            children=(
                Block(
                    "CSID_Cmd",
                    children=(
                        Static("cmd", "CSID"),
                        Group("space_opt", values=[" ", ""]),
                        SmartString(
                            "client_id",
                            "FTPClient/1.0",
                            max_len=256,
                            context=StringContext.GENERIC,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # CLNT - Client Identification
        cmd_clnt = Request(
            "CLNT",
            children=(
                Block(
                    "CLNT_Cmd",
                    children=(
                        Static("cmd", "CLNT"),
                        Delim(" ", " "),
                        SmartString(
                            "client_name",
                            "OIDA",
                            max_len=256,
                            context=StringContext.GENERIC,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # HOST - Virtual Host (RFC 7151)
        cmd_host = Request(
            "HOST",
            children=(
                Block(
                    "HOST_Cmd",
                    children=(
                        Static("cmd", "HOST"),
                        Delim(" ", " "),
                        SmartString(
                            "hostname",
                            "ftp.example.com",
                            max_len=256,
                            context=StringContext.HOSTNAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # AVBL - Available Space
        cmd_avbl = Request(
            "AVBL",
            children=(
                Block(
                    "AVBL_Cmd",
                    children=(
                        Static("cmd", "AVBL"),
                        Group("space_opt", values=[" ", ""]),
                        SmartString("path", "/", max_len=512, context=StringContext.PATH),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # DSIZ - Directory Size
        cmd_dsiz = Request(
            "DSIZ",
            children=(
                Block(
                    "DSIZ_Cmd",
                    children=(
                        Static("cmd", "DSIZ"),
                        Group("space_opt", values=[" ", ""]),
                        SmartString("path", "/", max_len=512, context=StringContext.PATH),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # MDTM - File Modification Time (RFC 3659)
        cmd_mdtm = Request(
            "MDTM",
            children=(
                Block(
                    "MDTM_Cmd",
                    children=(
                        Static("cmd", "MDTM"),
                        Delim(" ", " "),
                        SmartString(
                            "filename",
                            "test.txt",
                            max_len=512,
                            context=StringContext.FILENAME,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        cmd_ccc = Request(
            "CCC",
            children=(Block("CCC_Cmd", children=(Static("cmd", "CCC"), Static("CRLF", "\r\n")))),
        )

        cmd_generic = Request(
            "GENERIC",
            children=(
                Block(
                    "GENERIC_Cmd",
                    children=(
                        # The command itself will be fuzzed
                        SmartString(
                            "cmd",
                            "TEST",
                            max_len=32,  # Maximum command length
                            fuzzable=True,
                            context=StringContext.COMMAND,
                        ),
                        # Optional space - some servers might be sensitive to this
                        Group("space_opt", values=[" ", ""]),
                        # The parameter string that will be fuzzed
                        SmartString(
                            "parameter",
                            "/path/to/file",
                            max_len=2048,  # Large enough for path traversal testing
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                )
            ),
        )

        # ==================== DATA CHANNEL ATTACKS ====================
        # Buffer overflow attacks (CVE-2010-4221, CVE-2020-8597)
        dc_overflow_cwd = Request(
            "DC_Overflow_CWD",
            children=(
                Static("cmd", "CWD"),
                Delim(" ", " "),
                SmartString("path", "/" + "A" * 4096, max_len=8192, context=StringContext.PATH),
                Static("CRLF", "\r\n"),
            ),
        )

        dc_overflow_stor = Request(
            "DC_Overflow_STOR",
            children=(
                Static("cmd", "STOR"),
                Delim(" ", " "),
                SmartString(
                    "filename",
                    "A" * 4096 + ".txt",
                    max_len=8192,
                    context=StringContext.FILENAME,
                ),
                Static("CRLF", "\r\n"),
            ),
        )

        dc_overflow_list = Request(
            "DC_Overflow_LIST",
            children=(
                Static("cmd", "LIST"),
                Delim(" ", " "),
                SmartString("path", "/" + "B" * 4096, max_len=8192, context=StringContext.PATH),
                Static("CRLF", "\r\n"),
            ),
        )

        # Path traversal attacks (CVE-2015-3306)
        dc_traversal_cwd = Request(
            "DC_Traversal_CWD",
            children=(
                Static("cmd", "CWD"),
                Delim(" ", " "),
                SmartString(
                    "path",
                    "../" * 50 + "etc/passwd",
                    max_len=1024,
                    context=StringContext.PATH,
                ),
                Static("CRLF", "\r\n"),
            ),
        )

        dc_traversal_retr = Request(
            "DC_Traversal_RETR",
            children=(
                Static("cmd", "RETR"),
                Delim(" ", " "),
                SmartString(
                    "path",
                    "../" * 50 + "etc/passwd",
                    max_len=1024,
                    context=StringContext.PATH,
                ),
                Static("CRLF", "\r\n"),
            ),
        )

        dc_traversal_stor = Request(
            "DC_Traversal_STOR",
            children=(
                Static("cmd", "STOR"),
                Delim(" ", " "),
                SmartString(
                    "path",
                    "../" * 50 + "tmp/pwned.txt",
                    max_len=1024,
                    context=StringContext.PATH,
                ),
                Static("CRLF", "\r\n"),
            ),
        )

        # Format string attacks
        dc_format_cwd = Request(
            "DC_Format_CWD",
            children=(
                Static("cmd", "CWD"),
                Delim(" ", " "),
                SmartString(
                    "path",
                    "%s%s%s%s%s%s%s%s%n%n%n%n",
                    max_len=512,
                    context=StringContext.PATH,
                ),
                Static("CRLF", "\r\n"),
            ),
        )

        dc_format_mkd = Request(
            "DC_Format_MKD",
            children=(
                Static("cmd", "MKD"),
                Delim(" ", " "),
                SmartString("dirname", "%x" * 100, max_len=512, context=StringContext.PATH),
                Static("CRLF", "\r\n"),
            ),
        )

        if not self.use_auth:
            # No-auth mode: Basic FTP commands
            if self.is_request_enabled("FTP_NoAuth_Basic"):
                self._register_request_nodes(
                    "FTP_NoAuth_Basic",
                    "USER",
                    "PASS",
                    "CWD",
                    "LIST",
                    "PORT",
                    "OPTS",
                    "MKD",
                    "SITE",
                    "REST",
                    "QUIT",
                )
                self.session.connect(cmd_user)
                self.session.connect(cmd_user, cmd_pass)
                self.session.connect(cmd_pass, cmd_cwd)
                self.session.connect(cmd_pass, cmd_list)
                self.session.connect(cmd_pass, cmd_port)
                self.session.connect(cmd_pass, cmd_opts)
                self.session.connect(cmd_pass, cmd_mkd)
                self.session.connect(cmd_pass, cmd_site)
                self.session.connect(cmd_pass, cmd_rest)
                self.session.connect(cmd_pass, cmd_quit)

                # File transfer commands depend on PORT
                if self.is_request_enabled("FTP_NoAuth_Transfer"):
                    self._register_request_nodes("FTP_NoAuth_Transfer", "STOR", "RETR")
                    self.session.connect(cmd_port, cmd_stor)
                    self.session.connect(cmd_port, cmd_retr)

        else:
            # ==================== PHASED REQUEST ORDERING ====================
            # Optimized for early crash detection:
            # - Phase 1: Critical path commands (CWD, MKD) - highest crash potential
            # - Phase 2+: Other categories in order
            #
            # NOTE: Authentication is handled by state machine (_perform_ftp_login)
            # which validates response codes (331, 230, 530). Boofuzz prereqs
            # don't validate responses, causing timing issues.
            # The state machine login runs ONCE after connection opens.

            # PHASE 1: AUTH FUZZING (USER/PASS after auth completes)
            # For true pre-auth fuzzing, use -O use_auth=false
            if self.is_request_enabled("FTP_Auth_Fuzz"):
                self._register_request_nodes("FTP_Auth_Fuzz", "USER", "PASS")
                self.session.connect(cmd_user)  # USER with SmartString CREDENTIAL context
                self.session.connect(cmd_pass)  # PASS with SmartString CREDENTIAL context

            # PHASE 2: CRITICAL PATH COMMANDS (highest crash potential)
            # CWD and MKD with SmartString PATH context hit boundaries early
            if self.is_request_enabled("FTP_Critical_Path"):
                self._register_request_nodes("FTP_Critical_Path", "CWD", "MKD")
                self.session.connect(cmd_cwd)  # CWD with SmartString boundaries
                self.session.connect(cmd_mkd)  # MKD with SmartString boundaries

            # PHASE 3: BASELINE & SAFE INFO COMMANDS (Read-only, no side effects)
            if self.is_request_enabled("FTP_Baseline"):
                self._register_request_nodes(
                    "FTP_Baseline", "NOOP", "PWD", "SYST", "FEAT", "STAT", "HELP"
                )
                self.session.connect(cmd_noop)  # Baseline: no operation
                self.session.connect(cmd_pwd)  # Print working directory
                self.session.connect(cmd_syst)  # System type
                self.session.connect(cmd_feat)  # List features
                self.session.connect(cmd_stat)  # Status
                self.session.connect(cmd_help)  # Help text

            # PHASE 4: SAFE READ COMMANDS (List and query operations)
            if self.is_request_enabled("FTP_Directory_Read"):
                nodes = ["NLST", "SIZE"]
                if self._supports_feature("MLST"):
                    nodes.append("MLST")
                if self._supports_feature("MLSD"):
                    nodes.append("MLSD")
                if self._supports_feature("MDTM"):
                    nodes.append("MDTM")
                self._register_request_nodes("FTP_Directory_Read", *nodes)
                self.session.connect(cmd_nlst)  # Name list
                if self._supports_feature("MLST"):
                    self.session.connect(cmd_mlst)  # Machine list
                if self._supports_feature("MLSD"):
                    self.session.connect(cmd_mlsd)  # Machine list directory
                self.session.connect(cmd_size)  # File size
                if self._supports_feature("MDTM"):
                    self.session.connect(cmd_mdtm)  # Modification time

            # PHASE 4: NAVIGATION COMMANDS (Directory changes)
            if self.is_request_enabled("FTP_Navigation"):
                self._register_request_nodes("FTP_Navigation", "CDUP")
                self.session.connect(cmd_cdup)  # Change to parent directory

            # PHASE 5: DATA TRANSFER SETUP (Connection modes)
            if self.is_request_enabled("FTP_Transfer_Setup"):
                nodes = ["PASV", "TYPE", "MODE", "STRU"]
                if self._supports_feature("EPSV"):
                    nodes.append("EPSV")
                if self._supports_feature("EPRT"):
                    nodes.append("EPRT")
                self._register_request_nodes("FTP_Transfer_Setup", *nodes)
                self.session.connect(cmd_pasv)  # Passive mode
                if self._supports_feature("EPSV"):
                    self.session.connect(cmd_epsv)  # Extended passive mode
                if self._supports_feature("EPRT"):
                    self.session.connect(cmd_eprt)  # Extended active port
                self.session.connect(cmd_type)  # Transfer type (ASCII/Binary)
                self.session.connect(cmd_mode)  # Transfer mode
                self.session.connect(cmd_stru)  # File structure

            # PHASE 6: WRITE OPERATIONS (Modify filesystem)
            if self.is_request_enabled("FTP_File_Write"):
                self._register_request_nodes("FTP_File_Write", "APPE", "ALLO", "REST")
                self.session.connect(cmd_appe)  # Append to file
                self.session.connect(cmd_allo)  # Allocate space
                self.session.connect(cmd_rest)  # Restart transfer

            # PHASE 7: DANGEROUS OPERATIONS (Delete, rename, overwrite)
            if self.is_request_enabled("FTP_Dangerous"):
                nodes = ["DELE", "RMD", "RNFR", "RNTO"]
                if self._supports_feature("MFMT"):
                    nodes.append("MFMT")
                if self._supports_feature("MFCT"):
                    nodes.append("MFCT")
                self._register_request_nodes("FTP_Dangerous", *nodes)
                self.session.connect(cmd_dele)  # Delete file
                self.session.connect(cmd_rmd)  # Remove directory
                self.session.connect(cmd_rnfr)  # Rename from
                self.session.connect(cmd_rnto)  # Rename to
                if self._supports_feature("MFMT"):
                    self.session.connect(cmd_mfmt)  # Modify file time
                if self._supports_feature("MFCT"):
                    self.session.connect(cmd_mfct)  # Modify file creation time

            # PHASE 8: SECURITY & TLS COMMANDS
            if self.is_request_enabled("FTP_Security"):
                self._register_request_nodes("FTP_Security", "AUTH", "PBSZ", "PROT", "CCC")
                self.session.connect(cmd_auth)  # Authentication/Security
                self.session.connect(cmd_pbsz)  # Protection buffer size
                self.session.connect(cmd_prot)  # Data channel protection
                self.session.connect(cmd_ccc)  # Clear command channel

            # PHASE 9: EXOTIC/RARE COMMANDS (Rarely supported)
            if self.is_request_enabled("FTP_Extended"):
                nodes = ["ABOR"]
                if self._supports_feature("HASH"):
                    nodes.append("HASH")
                if self._supports_feature("AVBL"):
                    nodes.append("AVBL")
                if self._supports_feature("DSIZ"):
                    nodes.append("DSIZ")
                if self._supports_feature("LANG"):
                    nodes.append("LANG")
                if self._supports_feature("CSID"):
                    nodes.append("CSID")
                if self._supports_feature("CLNT"):
                    nodes.append("CLNT")
                if self._supports_feature("HOST"):
                    nodes.append("HOST")
                if self._supports_feature("ACCT"):
                    nodes.append("ACCT")
                self._register_request_nodes("FTP_Extended", *nodes)
                if self._supports_feature("HASH"):
                    self.session.connect(cmd_hash)  # Hash algorithm
                if self._supports_feature("AVBL"):
                    self.session.connect(cmd_avbl)  # Available space
                if self._supports_feature("DSIZ"):
                    self.session.connect(cmd_dsiz)  # Directory size
                if self._supports_feature("LANG"):
                    self.session.connect(cmd_lang)  # Language negotiation
                if self._supports_feature("CSID"):
                    self.session.connect(cmd_csid)  # Client/Server ID
                if self._supports_feature("CLNT"):
                    self.session.connect(cmd_clnt)  # Client name
                if self._supports_feature("HOST"):
                    self.session.connect(cmd_host)  # Virtual host
                if self._supports_feature("ACCT"):
                    self.session.connect(cmd_acct)  # Account information
                self.session.connect(cmd_abor)  # Abort transfer (core FTP, always test)

            # PHASE 10: GENERIC FUZZER (Unknown commands)
            if self.is_request_enabled("FTP_Generic"):
                self._register_request_nodes("FTP_Generic", "GENERIC")
                self.session.connect(cmd_generic)  # Generic command fuzzer

            # DATA CHANNEL ATTACKS (opt-in via -O datachannel_attacks=true)
            datachannel_enabled = self.config.get_option("datachannel_attacks", False)
            if datachannel_enabled or self.is_request_enabled("FTP_DC_Overflow"):
                self._register_request_nodes(
                    "FTP_DC_Overflow",
                    "DC_Overflow_CWD",
                    "DC_Overflow_STOR",
                    "DC_Overflow_LIST",
                )
                self.session.connect(dc_overflow_cwd)
                self.session.connect(dc_overflow_stor)
                self.session.connect(dc_overflow_list)

            if datachannel_enabled or self.is_request_enabled("FTP_DC_Path_Traversal"):
                self._register_request_nodes(
                    "FTP_DC_Path_Traversal",
                    "DC_Traversal_CWD",
                    "DC_Traversal_RETR",
                    "DC_Traversal_STOR",
                )
                self.session.connect(dc_traversal_cwd)
                self.session.connect(dc_traversal_retr)
                self.session.connect(dc_traversal_stor)

            if datachannel_enabled or self.is_request_enabled("FTP_DC_Format_String"):
                self._register_request_nodes(
                    "FTP_DC_Format_String", "DC_Format_CWD", "DC_Format_MKD"
                )
                self.session.connect(dc_format_cwd)
                self.session.connect(dc_format_mkd)

            # Log capability detection summary
            if (
                self.use_capability_detection
                and self.supported_features
                and "*" not in self.supported_features
            ):
                exotic_commands = [
                    "HASH",
                    "AVBL",
                    "DSIZ",
                    "LANG",
                    "CSID",
                    "CLNT",
                    "HOST",
                    "ACCT",
                    "MLST",
                    "MLSD",
                    "MDTM",
                    "EPSV",
                    "EPRT",
                    "MFMT",
                    "MFCT",
                ]
                skipped = [cmd for cmd in exotic_commands if not self._supports_feature(cmd)]
                if skipped:
                    self.log.display(
                        f"[FEAT] Skipped {len(skipped)} unsupported commands: {skipped}"
                    )

        return self.session

    def setup_custom_monitors(self) -> list:
        """
        Setup FTP-specific monitoring with PWD command comparison.

        Returns:
            List of monitor instances for FTP service health checking
        """
        from ..monitors import FTPCommandMonitor

        # Create FTP PWD monitor
        ftp_monitor = FTPCommandMonitor(
            host=self.config.target_ip,
            port=self.config.target_port,
            timeout=2,
            check_interval=3,  # Check every 3 test cases
        )

        return [ftp_monitor]

    def _define_state_machine(self) -> None:
        """
        Define FTP state machine for authentication validation

        State Machine V2 Integration:
        - StateContext is created in __init__ and passed to state machine
        - Responses are stored in context for cross-state access
        - State callbacks can access context for logging and state setup

        States (standard FTP):
        - CONNECTED: TCP connection established, banner received
        - AUTHENTICATED: USER/PASS successful, ready to fuzz commands

        States (FTPS with use_tls=True):
        - CONNECTED: TCP connection established, banner received
        - TLS_NEGOTIATION: AUTH TLS command sent
        - TLS_ESTABLISHED: SSL handshake complete
        - PBSZ_SET: Protection buffer size negotiated
        - PROT_SET: Protection level set to Private
        - AUTHENTICATED: USER/PASS successful over TLS
        """
        if not self.use_auth:
            self.log.display("FTP authentication disabled, skipping state machine setup")
            return

        use_tls = self.config.get_option("use_tls", False)

        if use_tls:
            # Create FTPS state machine with TLS upgrade states
            self._create_ftps_state_machine()
        else:
            # Create simple FTP auth state machine with StateContext
            # Note: Authentication is deferred - will be performed when fuzzer runs
            # and establishes actual connection, not during session initialization
            self.state_machine = create_auth_state_machine(
                login_callback=self._perform_ftp_login,
                validate_callback=self._validate_ftp_auth,
                connected_validation=None,  # Could check if socket is alive
                context=self._state_context,  # State Machine V2: Pass context
            )
            self.log.display(
                "FTP state machine created with StateContext (auth deferred until connection ready)"
            )

    def _create_ftps_state_machine(self) -> None:
        """
        Create FTPS state machine with TLS upgrade sequence

        This creates a detailed state machine that tracks the complete FTPS
        upgrade process including AUTH TLS, SSL handshake, PBSZ, and PROT.
        """
        from ..core.session.state_machine import (
            ProtocolState,
            StateMachine,
            StateType,
            TransitionRule,
        )

        # Define states
        connected = ProtocolState(
            name="CONNECTED",
            state_type=StateType.CONNECTION,
            description="TCP connection established, banner received",
        )

        tls_negotiation = ProtocolState(
            name="TLS_NEGOTIATION",
            state_type=StateType.SESSION,
            setup=self._send_auth_tls,
            requires=["CONNECTED"],
            timeout=5.0,
            timeout_callback=lambda: self.log.warning("AUTH TLS timeout"),
            description="AUTH TLS command sent, awaiting server response",
        )

        tls_established = ProtocolState(
            name="TLS_ESTABLISHED",
            state_type=StateType.SESSION,
            setup=self._perform_ssl_handshake,
            validation=self._validate_tls_connection,
            requires=["TLS_NEGOTIATION"],
            description="SSL/TLS handshake complete",
        )

        pbsz_set = ProtocolState(
            name="PBSZ_SET",
            state_type=StateType.SESSION,
            setup=self._send_pbsz,
            requires=["TLS_ESTABLISHED"],
            description="Protection buffer size set to 0",
        )

        prot_set = ProtocolState(
            name="PROT_SET",
            state_type=StateType.SESSION,
            setup=self._send_prot,
            requires=["PBSZ_SET"],
            description="Protection level set to Private",
        )

        authenticated = ProtocolState(
            name="AUTHENTICATED",
            state_type=StateType.AUTHENTICATION,
            setup=self._perform_ftp_login,
            validation=self._validate_ftp_auth,
            requires=["PROT_SET"],
            description="Authenticated over secure TLS channel",
        )

        # Define transition rules
        transitions = [
            TransitionRule(
                "CONNECTED",
                "TLS_NEGOTIATION",
                description="Initiate TLS upgrade with AUTH TLS",
            ),
            TransitionRule(
                "TLS_NEGOTIATION",
                "TLS_ESTABLISHED",
                description="Complete SSL handshake",
            ),
            TransitionRule("TLS_ESTABLISHED", "PBSZ_SET", description="Set protection buffer size"),
            TransitionRule("PBSZ_SET", "PROT_SET", description="Set data channel protection level"),
            TransitionRule("PROT_SET", "AUTHENTICATED", description="Authenticate over TLS"),
        ]

        # Create state machine with StateContext
        # State Machine V2: Pass context for response data propagation
        self.state_machine = StateMachine(
            initial_state=connected,
            states=[
                connected,
                tls_negotiation,
                tls_established,
                pbsz_set,
                prot_set,
                authenticated,
            ],
            transitions=transitions,
            allow_invalid_transitions=False,
            context=self._state_context,
        )

        # Execute FTPS upgrade sequence (deferred when using mock connections)
        from ..core.connections.base import MockConnectionFactory

        if isinstance(self.connection_factory, MockConnectionFactory):
            self.log.display("FTPS state machine created (execution deferred - mock connection)")
            return

        self.log.display("Starting FTPS upgrade sequence")
        try:
            self.state_machine.transition_to("TLS_NEGOTIATION")
            self.state_machine.transition_to("TLS_ESTABLISHED")
            self.state_machine.transition_to("PBSZ_SET")
            self.state_machine.transition_to("PROT_SET")
            self.state_machine.transition_to("AUTHENTICATED")
            self.log.display(f"FTPS authentication successful as {self.username}")
        except Exception as e:
            self.log.fail(f"FTPS upgrade or authentication failed: {e}")
            raise

    def _send_auth_tls(self) -> bool:
        """
        Send AUTH TLS command to initiate TLS upgrade

        Returns:
            True if server accepts TLS upgrade (234 response)
        """
        try:
            sock = self.session.targets[0]._target_connection
            self.log.debug("Sending: AUTH TLS")
            sock.send(b"AUTH TLS\r\n")

            response = sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"Response: {response.strip()}")

            # Check for 234 (Security data exchange complete)
            if response.startswith("234"):
                self.log.display("Server accepted TLS upgrade")
                return True
            else:
                self.log.fail(f"AUTH TLS failed: {response.strip()}")
                return False

        except Exception as e:
            self.log.fail(f"Exception sending AUTH TLS: {e}")
            return False

    def _perform_ssl_handshake(self) -> bool:
        """
        Perform SSL/TLS handshake to upgrade connection

        Returns:
            True if SSL handshake successful
        """
        try:
            sock = self.session.targets[0]._target_connection

            # Create SSL context if not exists
            if not hasattr(sock, "sslcontext"):
                sock.sslcontext = ssl.create_default_context()
                sock.sslcontext.check_hostname = False
                sock.sslcontext.verify_mode = ssl.CERT_NONE

            # Wrap the socket with SSL
            self.log.display("Performing SSL handshake")
            sock._sock = sock.sslcontext.wrap_socket(
                sock._sock, server_side=False, server_hostname=self.config.target_ip
            )

            # Mark connection as secure
            if hasattr(sock, "is_secure"):
                sock.is_secure = True

            self.log.display("SSL handshake successful")
            return True

        except ssl.SSLError as e:
            self.log.fail(f"SSL handshake failed: {e}")
            return False
        except Exception as e:
            self.log.fail(f"Exception during SSL handshake: {e}")
            return False

    def _send_pbsz(self) -> bool:
        """
        Send PBSZ 0 command to set protection buffer size

        PBSZ must be 0 for TLS as per RFC 4217.

        Returns:
            True if server accepts PBSZ (200 response)
        """
        try:
            sock = self.session.targets[0]._target_connection
            self.log.debug("Sending: PBSZ 0")
            sock.send(b"PBSZ 0\r\n")

            response = sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"Response: {response.strip()}")

            # Check for 200 (Command okay)
            if response.startswith("200"):
                self.log.display("PBSZ set successfully")
                return True
            else:
                self.log.fail(f"PBSZ failed: {response.strip()}")
                return False

        except Exception as e:
            self.log.fail(f"Exception sending PBSZ: {e}")
            return False

    def _send_prot(self) -> bool:
        """
        Send PROT P command to set protection level to Private

        PROT P means both command and data channels are protected.

        Returns:
            True if server accepts PROT P (200 response)
        """
        try:
            sock = self.session.targets[0]._target_connection
            self.log.debug("Sending: PROT P")
            sock.send(b"PROT P\r\n")

            response = sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"Response: {response.strip()}")

            # Check for 200 (Command okay)
            if response.startswith("200"):
                self.log.display("PROT P set successfully")
                return True
            else:
                self.log.fail(f"PROT P failed: {response.strip()}")
                return False

        except Exception as e:
            self.log.fail(f"Exception sending PROT P: {e}")
            return False

    def _validate_tls_connection(self) -> bool:
        """
        Validate that TLS connection is still active

        Returns:
            True if connection is still using TLS
        """
        try:
            sock = self.session.targets[0]._target_connection

            # Check if socket has SSL wrapper
            if hasattr(sock, "_sock") and hasattr(sock._sock, "version"):
                tls_version = sock._sock.version()
                self.log.debug(f"TLS version: {tls_version}")
                return tls_version is not None

            # Fallback: check is_secure flag
            if hasattr(sock, "is_secure"):
                return sock.is_secure

            # Cannot determine TLS state
            self.log.warning("Cannot validate TLS connection state")
            return True  # Assume valid if cannot check

        except Exception as e:
            self.log.fail(f"Exception validating TLS: {e}")
            return False

    def _perform_ftp_login(self) -> bool:
        """
        Execute FTP login sequence (USER + PASS)

        Returns:
            True if login successful, False otherwise
        """
        self.log.debug(f"FTP login: USER={self.username}")
        try:
            sock = self.session.targets[0]._target_connection

            # Send USER command
            user_cmd = f"USER {self.username}\r\n".encode()
            self.log.debug(f">>> USER {self.username}")
            sock.send(user_cmd)

            # Receive response
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"<<< {response.strip()}")

            # Check for 331 (User name okay, need password)
            if not response.startswith("331"):
                self.log.fail(f"USER failed: expected 331, got: {response.strip()[:50]}")
                return False

            # Send PASS command
            pass_cmd = f"PASS {self.password}\r\n".encode()
            self.log.debug(f">>> PASS {self.password}")
            sock.send(pass_cmd)

            # Receive response
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"<<< {response.strip()}")

            # Check for 230 (User logged in)
            if response.startswith("230"):
                self.log.debug("FTP login successful")
                return True
            else:
                self.log.fail(f"PASS failed: expected 230, got: {response.strip()[:50]}")
                return False

        except Exception as e:
            self.log.fail(f"FTP login exception: {e}")
            return False

    def _validate_ftp_auth(self) -> bool:
        """
        Validate that we're still authenticated

        Uses PWD command to check if session is still valid.

        Returns:
            True if still authenticated, False otherwise
        """
        try:
            sock = self.session.targets[0]._target_connection

            # Send PWD command (should work if authenticated)
            self.log.debug("Validating auth with PWD command")
            sock.send(b"PWD\r\n")

            # Receive response
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"PWD Response: {response.strip()}")

            # Check for 257 (pathname created)
            if response.startswith("257"):
                self.log.debug("Auth validation successful")
                return True
            else:
                self.log.warning(f"Auth validation failed: {response.strip()}")
                return False

        except Exception as e:
            self.log.fail(f"Exception during auth validation: {e}")
            return False

    def _supports_feature(self, feature: str) -> bool:
        """
        Check if server supports a specific FTP feature

        Args:
            feature: Feature name to check (case-insensitive)

        Returns:
            True if feature is supported or capability detection is disabled
            False if feature is known to be unsupported
        """
        # If capability detection disabled, assume all features supported
        if not self.use_capability_detection:
            return True

        # If no features detected yet, assume all supported
        if not self.supported_features:
            return True

        # Wildcard means all features supported (or FEAT failed)
        if "*" in self.supported_features:
            return True

        # Check if feature is in supported set (case-insensitive)
        return feature.upper() in self.supported_features

    def fuzz_all(self) -> None:
        """
        Override fuzz_all with FTP-specific authentication handling.

        Uses StatefulFuzzer's authentication callback framework, but
        also supports state machine-based authentication for FTPS.
        """
        # Access session first to trigger lazy initialization
        _ = self.session

        # For FTPS with state machine, use state machine authentication
        # Otherwise, use the StatefulFuzzer's authenticator-based approach
        use_tls = self.config.get_option("use_tls", False)

        if use_tls and self.state_machine and self.use_auth:
            # FTPS uses state machine for the TLS upgrade sequence
            self._auth_failed = False
            self._ftps_authenticated_conn_id = None  # Track authenticated connection

            def ftps_auth_pre_send(target, fuzz_data_logger, session, sock):
                """Pre-send callback for FTPS state machine authentication"""
                if self._auth_failed:
                    raise ConnectionError("FTPS authentication failed; aborting fuzz session")

                # Get the connection from target
                conn = target._target_connection

                # Build unique identity using connection generation counter
                # This is more reliable than socket fd which OS can reuse after close
                generation = getattr(conn, "_connection_generation", 0)
                current_identity = (id(conn), generation)

                # Skip if same connection generation already authenticated
                if current_identity == self._ftps_authenticated_conn_id:
                    self.log.debug(
                        f"Skipping FTPS auth: connection gen {generation} already authenticated"
                    )
                    return

                # Reset and re-authenticate on new/changed connection
                self.state_machine.reset_to_initial()
                self.log.debug(f"Authenticating via state machine (gen {generation})")
                try:
                    self.state_machine.require_state("AUTHENTICATED")
                    self.log.debug("FTP authenticated")
                    # Mark this connection generation as authenticated
                    self._ftps_authenticated_conn_id = current_identity
                except Exception as e:
                    self.log.fail(f"FTP auth failed: {e}")
                    self._handle_auth_failure()
                    sys.exit(1)

            self.session._callback_monitor.on_pre_send.append(ftps_auth_pre_send)
            # Skip StatefulFuzzer's auth setup since we're using state machine
            from ..core.base_fuzzer import BaseFuzzer

            BaseFuzzer.fuzz_all(self)
        else:
            # Use StatefulFuzzer's authenticator-based approach
            super().fuzz_all()

    def test_ftps_attack_patterns(self) -> None:
        """
        Test FTPS state confusion and downgrade attack patterns

        This method demonstrates how to use the state machine in attack mode
        to test for vulnerabilities in the FTPS upgrade sequence.

        Attack patterns tested:
        1. Sending commands before TLS upgrade (cleartext injection)
        2. Skipping PBSZ command
        3. Skipping PROT command
        4. TLS downgrade by jumping directly to authenticated
        5. Authentication before TLS establishment

        Example usage:
            fuzzer = FTPFuzzer(config)
            fuzzer.test_ftps_attack_patterns()
        """
        use_tls = self.config.get_option("use_tls", False)
        if not use_tls or not self.state_machine:
            self.log.warning("FTPS attack patterns require use_tls=True and state machine")
            return

        # Enable attack mode
        self.enable_invalid_state_testing()
        self.log.display("Testing FTPS state confusion vulnerabilities")

        attack_patterns = [
            (
                "Sending USER command before TLS upgrade (cleartext injection)",
                ["CONNECTED"],
                lambda: self._test_command_before_tls(),
            ),
            (
                "Skipping PBSZ after TLS establishment",
                ["CONNECTED", "TLS_NEGOTIATION", "TLS_ESTABLISHED", "PROT_SET"],
                lambda: self._test_skip_pbsz(),
            ),
            (
                "Skipping PROT after PBSZ",
                [
                    "CONNECTED",
                    "TLS_NEGOTIATION",
                    "TLS_ESTABLISHED",
                    "PBSZ_SET",
                    "AUTHENTICATED",
                ],
                lambda: self._test_skip_prot(),
            ),
            (
                "Jumping directly to authenticated without TLS",
                ["CONNECTED", "AUTHENTICATED"],
                lambda: self._test_no_tls_auth(),
            ),
            (
                "Authenticating before completing TLS setup",
                ["CONNECTED", "TLS_NEGOTIATION", "AUTHENTICATED"],
                lambda: self._test_early_auth(),
            ),
        ]

        for pattern_name, state_sequence, test_func in attack_patterns:
            self.log.display(f"\n{'=' * 60}")
            self.log.display(f"Attack Pattern: {pattern_name}")
            self.log.display(f"State Sequence: {' → '.join(state_sequence)}")
            self.log.display(f"{'=' * 60}")

            try:
                # Reset to initial state
                self.force_invalid_state_transition("CONNECTED")

                # Follow the attack pattern state sequence
                for state in state_sequence[1:]:  # Skip first (already in CONNECTED)
                    self.force_invalid_state_transition(state)
                    self.log.display(f"Forced transition to: {state}")

                # Execute pattern-specific test
                test_func()

                self.log.display(f"✓ Attack pattern completed: {pattern_name}")

            except Exception as e:
                self.log.fail(f"✗ Attack pattern failed: {pattern_name} - {e}")

        # Disable attack mode
        self.disable_invalid_state_testing()
        self.log.display("\nFTPS attack pattern testing completed")

    def _test_command_before_tls(self):
        """Test sending FTP commands before TLS upgrade"""
        sock = self.session.targets[0]._target_connection
        self.log.display("Attempting to send USER command in cleartext")
        sock.send(f"USER {self.username}\r\n".encode())
        response = sock.recv(1024).decode("utf-8", errors="ignore")
        self.log.display(f"Server response: {response.strip()}")

    def _test_skip_pbsz(self):
        """Test skipping PBSZ command after TLS"""
        sock = self.session.targets[0]._target_connection
        self.log.display("Attempting to send PROT without PBSZ")
        sock.send(b"PROT P\r\n")
        response = sock.recv(1024).decode("utf-8", errors="ignore")
        self.log.display(f"Server response: {response.strip()}")

    def _test_skip_prot(self):
        """Test skipping PROT command after PBSZ"""
        sock = self.session.targets[0]._target_connection
        self.log.display("Attempting authentication without PROT")
        sock.send(f"USER {self.username}\r\n".encode())
        response = sock.recv(1024).decode("utf-8", errors="ignore")
        self.log.display(f"Server response: {response.strip()}")

    def _test_no_tls_auth(self):
        """Test authentication without TLS upgrade"""
        sock = self.session.targets[0]._target_connection
        self.log.display("Attempting authentication without TLS")
        sock.send(f"USER {self.username}\r\n".encode())
        sock.recv(1024)
        sock.send(f"PASS {self.password}\r\n".encode())
        response = sock.recv(1024).decode("utf-8", errors="ignore")
        self.log.display(f"Server response: {response.strip()}")

    def _test_early_auth(self):
        """Test authentication before TLS handshake completes"""
        sock = self.session.targets[0]._target_connection
        self.log.display("Attempting authentication after AUTH TLS but before handshake")
        sock.send(f"USER {self.username}\r\n".encode())
        response = sock.recv(1024).decode("utf-8", errors="ignore")
        self.log.display(f"Server response: {response.strip()}")
