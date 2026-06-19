"""
PostgreSQL Passive Listener for credential and session extraction.

Passively captures PostgreSQL traffic to extract:
- Database credentials (username/password or MD5 hash)
- Database name being accessed
- Authentication type and salt
- Protocol version (major.minor from startup message)
- Message types and operation flow (Startup, Auth, Query, Ready, etc.)
- Server error/notice messages (severity, code, message, routine)
- Transaction status from ReadyForQuery messages
- Server parameters (server_version, client_encoding, etc.)

Uses the ``pgsql.frontend`` field for protocol-level direction detection
instead of hardcoded port checks, so non-standard ports work correctly.

Uses the base class interaction table system (PROTOCOL_COLUMNS +
GROUP_BY_STREAM) to produce per-stream operations tables automatically.

PostgreSQL authentication flow:
    Client: StartupMessage (length + version + key-value pairs: user, database)
    Server: AuthenticationRequest (type 0=ok, 3=cleartext, 5=md5 with salt)
    Client: PasswordMessage ('p' + length + password/hash)
    Server: AuthenticationOk (type 0)

MD5 hash format: md5(md5(password + user) + salt)

Key tshark pgsql fields extracted:
- pgsql.frontend:        direction indicator (True=client, False=server)
- pgsql.type:            message type string ("Startup message", "Authentication request", etc.)
- pgsql.version_major:   protocol version major (typically 3)
- pgsql.version_minor:   protocol version minor (typically 0)
- pgsql.parameter_name:  startup parameter names (list in EK mode)
- pgsql.parameter_value: startup parameter values (list in EK mode)
- pgsql.authtype:        authentication type (0=ok, 3=cleartext, 5=md5, 10=sasl)
- pgsql.salt:            4-byte MD5 salt
- pgsql.password:        password or MD5 hash from client
- pgsql.status:          transaction status from ReadyForQuery (73=I, 84=T, 69=E)
- pgsql.severity:        error/notice severity (ERROR, FATAL, WARNING, NOTICE, etc.)
- pgsql.code:            SQLState error code (e.g. 42P01)
- pgsql.message:         error/notice message text
- pgsql.file:            server source file where error originated
- pgsql.line:            server source line number
- pgsql.routine:         server routine that reported the error
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# PostgreSQL authentication types
AUTH_OK = 0
AUTH_CLEARTEXT = 3
AUTH_MD5 = 5
AUTH_SASL = 10

# PostgreSQL default ports (used as fallback when frontend field is absent)
PGSQL_PORTS = {5432, 5433}

# Transaction status byte values from ReadyForQuery
TRANSACTION_STATUS = {
    "73": "idle",  # 'I' = idle (not in a transaction)
    "84": "transaction",  # 'T' = in a transaction block
    "69": "failed",  # 'E' = in a failed transaction block
}


@dataclass
class PostgreSQLCredential:
    """Extracted PostgreSQL credential."""

    username: str
    database: str
    password_or_hash: str
    salt: Optional[str]  # 4-byte salt as hex for MD5 auth
    auth_type: str  # "cleartext", "md5", "none", "sasl"
    server_ip: str
    client_ip: str
    success: Optional[bool]  # True if auth succeeded, False if failed, None if unknown
    timestamp: str = ""

    @property
    def credential_type(self) -> str:
        """Return credential type for scanner loop compatibility."""
        if self.auth_type == "cleartext":
            return "plaintext"
        elif self.auth_type == "md5":
            return "hash"
        return "none"

    @property
    def password(self) -> str:
        """Alias for scanner credential loop compatibility."""
        return self.password_or_hash

    @property
    def hash_value(self) -> str:
        """Alias for scanner credential loop compatibility."""
        return self.password_or_hash if self.auth_type == "md5" else ""

    @property
    def hashcat_format(self) -> str:
        """Hashcat-compatible hash string."""
        # PostgreSQL MD5 cracking needs the server salt; without it (Type request
        # not captured) the hash is uncrackable, so return "" rather than a line
        # with an empty salt field.
        if self.auth_type == "md5" and self.password_or_hash and self.salt:
            return f"{self.username}:{self.password_or_hash}:{self.salt}"
        return ""

    @property
    def auth_method(self) -> str:
        """Return auth method for scanner loop."""
        return f"PostgreSQL/{self.auth_type}"


@dataclass
class PostgreSQLSession:
    """Track PostgreSQL session state for credential extraction."""

    client_ip: str
    server_ip: str
    username: str = ""
    database: str = ""
    auth_type: str = ""
    salt: str = ""  # 4-byte salt as hex
    password_or_hash: str = ""
    authenticated: Optional[bool] = None
    protocol_version: str = ""  # "3.0"
    server_params: Dict[str, str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.server_params is None:
            self.server_params = {}


class PostgreSQLPassiveListener(PySharkListenerBase):
    """Passive PostgreSQL traffic listener for credential and session extraction.

    Captures PostgreSQL traffic to extract:
    - Login credentials (cleartext password or MD5 hash)
    - Username and database name
    - Authentication type and salt
    - Protocol version, message types, server parameters
    - Error/notice messages with severity and SQLState codes
    - Transaction status from ReadyForQuery

    Uses the ``pgsql.frontend`` field for protocol-level direction detection
    instead of hardcoded port checks.

    Uses the base class interaction table system (PROTOCOL_COLUMNS +
    GROUP_BY_STREAM) to produce per-stream operations tables automatically.

    Usage:
        # Live capture
        listener = PostgreSQLPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access extracted credentials
        for cred in listener.credentials:
            print(f"{cred.username}@{cred.database}: {cred.password_or_hash}")

    Data structure stored in device.pgsql_passive_data:
        {
            "role": "server" | "client",
            "credentials": [...],
            "protocol": "PostgreSQL/TCP",
            "server_version": "14.2",
            "databases": ["mydb"],
        }
    """

    PROTOCOL_NAME = "pgsql"
    DISPLAY_FILTER = "pgsql"
    REQUIRED_LAYERS = ("pgsql",)

    PROTOCOL_COLUMNS = ("type", "operation", "details", "result")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize PostgreSQL passive listener.

        Args:
            interface: Network interface to capture on
            timeout: Capture timeout in seconds
            nxc_logger: Optional NXC-style logger
        """
        super().__init__(interface, timeout, nxc_logger)
        # Track sessions by (client_ip, server_ip, client_port) tuple
        self._sessions: Dict[Tuple[str, str, int], PostgreSQLSession] = {}

        # Extracted credentials
        self.credentials: List[PostgreSQLCredential] = []

        # Track known server IPs for direction fallback
        self._known_servers: Set[str] = set()

        # Server parameters collected from ParameterStatus messages
        self._server_params: Dict[str, Dict[str, str]] = {}  # server_ip -> {param: value}

        # Security alerts
        self._alerts: List[Dict[str, str]] = []

    # -------------------------------------------------------------------------
    # Direction detection
    # -------------------------------------------------------------------------

    def _detect_direction(
        self, pgsql_layer: Any, src_ip: str, dst_ip: str, src_port: int, dst_port: int
    ) -> Optional[bool]:
        """Detect packet direction using pgsql.frontend field.

        Returns True if client->server (frontend), False if server->client,
        None if direction cannot be determined.
        """
        frontend = self.get_field(pgsql_layer, "frontend", None)
        if frontend is not None:
            frontend_str = str(frontend)
            if frontend_str in ("True", "1", "true"):
                return True
            if frontend_str in ("False", "0", "false"):
                return False

        # Fallback: message type implies direction
        msg_type = self.get_field(pgsql_layer, "type", "")
        msg_type_str = str(msg_type) if msg_type else ""
        if msg_type_str in (
            "Startup message",
            "Password message",
            "Termination",
            "Simple query",
            "Parse",
            "Bind",
            "Execute",
            "Describe",
            "Sync",
            "Flush",
            "Close",
            "Copy data",
            "Copy done",
        ):
            return True  # Client -> Server
        if msg_type_str in (
            "Authentication request",
            "Ready for query",
            "Notice",
            "Error",
            "Parameter status",
            "Row description",
            "Data row",
            "Command completion",
            "Backend key data",
            "Parse completion",
            "Bind completion",
            "Close completion",
            "Empty query",
            "Portal suspended",
            "No data",
        ):
            return False  # Server -> Client

        # Fallback: known servers
        if src_ip in self._known_servers:
            return False  # Source is known server -> server->client
        if dst_ip in self._known_servers:
            return True  # Dest is known server -> client->server

        # Fallback: port heuristic
        if dst_port in PGSQL_PORTS:
            return True
        if src_port in PGSQL_PORTS:
            return False

        return None

    # -------------------------------------------------------------------------
    # Parameter list extraction (EK mode)
    # -------------------------------------------------------------------------

    def _extract_startup_params(self, pgsql_layer: Any) -> Dict[str, str]:
        """Extract parameter name/value pairs from startup message.

        In EK mode, parameter_name and parameter_value are lists.
        In XML mode, they may be single values or comma-separated.
        Returns a dict mapping parameter names to their values.
        """
        raw_names = getattr(pgsql_layer, "parameter_name", None)
        raw_values = getattr(pgsql_layer, "parameter_value", None)

        if raw_names is None or raw_values is None:
            return {}

        # Handle list (EK mode) vs single string (XML mode)
        if isinstance(raw_names, list) and isinstance(raw_values, list):
            names = [str(n) for n in raw_names]
            values = [str(v) for v in raw_values]
        else:
            # get_field joins lists with commas; split back
            names_str = str(self._resolve_value(raw_names, ""))
            values_str = str(self._resolve_value(raw_values, ""))
            names = names_str.split(",") if names_str else []
            values = values_str.split(",") if values_str else []

        params = {}
        for i, name in enumerate(names):
            val = values[i] if i < len(values) else ""
            params[name.strip()] = val.strip()

        return params

    # -------------------------------------------------------------------------
    # Empty-layer handler (EK mode multi-message segments)
    # -------------------------------------------------------------------------

    def _record_empty_layer_interaction(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Record a generic interaction for a pgsql packet whose EK layer is empty.

        In EK mode, TCP segments that carry multiple pgsql messages are
        sometimes represented as a single layer with no fields.  The regular
        tshark text output would show the individual messages, but the EK JSON
        representation loses them.  We still record an interaction so the
        packet is not silently dropped.

        Direction is inferred from known-server set and port heuristics.
        """
        # Direction from known servers / port heuristic
        if src_ip in self._known_servers:
            direction = "response"
            server_ip, server_port = src_ip, src_port
            client_ip, client_port = dst_ip, dst_port
        elif dst_ip in self._known_servers:
            direction = "request"
            server_ip, server_port = dst_ip, dst_port
            client_ip, client_port = src_ip, src_port
        elif dst_port in PGSQL_PORTS:
            direction = "request"
            server_ip, server_port = dst_ip, dst_port
            client_ip, client_port = src_ip, src_port
        elif src_port in PGSQL_PORTS:
            direction = "response"
            server_ip, server_port = src_ip, src_port
            client_ip, client_port = dst_ip, dst_port
        else:
            # Fallback: treat src as sender
            direction = "request"
            server_ip, server_port = dst_ip, dst_port
            client_ip, client_port = src_ip, src_port

        src_rec = client_ip if direction == "request" else server_ip
        dst_rec = server_ip if direction == "request" else client_ip
        src_p = client_port if direction == "request" else server_port
        dst_p = server_port if direction == "request" else client_port

        self._record_interaction(
            now,
            src_rec,
            dst_rec,
            direction,
            "Multi-message",
            {"msg_type": "Multi-message segment"},
            "PostgreSQL multi-message segment (EK collapsed)",
            flow_id=flow_id,
            src_port=src_p,
            dst_port=dst_p,
            stream_id=stream_id,
        )

    # -------------------------------------------------------------------------
    # Packet processing
    # -------------------------------------------------------------------------

    def process_packet(self, packet) -> None:
        """Process PostgreSQL packet and extract credentials/session data."""
        if not hasattr(packet, "pgsql"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        flow_id = self.get_flow_id(packet)
        pgsql_layer = packet.pgsql

        # Handle empty pgsql layers (EK mode collapses multi-message TCP
        # segments into a single layer with no fields).  Record a generic
        # interaction so every packet that matched the display filter produces
        # at least one interaction.
        all_fn = getattr(pgsql_layer, "all_field_names", None)
        if not all_fn:
            now = self._get_timestamp()
            stream_id = self.get_stream_id(packet)
            self._record_empty_layer_interaction(
                now,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                flow_id,
                stream_id,
            )
            return

        fields = self.get_all_fields(pgsql_layer)
        now = self._get_timestamp()
        stream_id = self.get_stream_id(packet)

        # Extract message type (T1 field: pgsql.type)
        msg_type = self.get_field(pgsql_layer, "type", "")
        if not msg_type:
            msg_type = "?"
            self.logger.debug(f"Missing pgsql.type field in packet {src_ip} -> {dst_ip}")

        # Determine direction using pgsql.frontend (T2 field, but critical for correctness)
        is_frontend = self._detect_direction(pgsql_layer, src_ip, dst_ip, src_port, dst_port)
        if is_frontend is None:
            # Cannot determine direction -- skip
            self.logger.debug(
                f"Cannot determine direction for pgsql packet {src_ip}:{src_port} -> "
                f"{dst_ip}:{dst_port} type={msg_type}"
            )
            return

        if is_frontend:
            # Client -> Server
            client_ip, client_port = src_ip, src_port
            server_ip, server_port = dst_ip, dst_port
            client_mac, server_mac = src_mac, dst_mac
        else:
            # Server -> Client
            server_ip, server_port = src_ip, src_port
            client_ip, client_port = dst_ip, dst_port
            server_mac, client_mac = src_mac, dst_mac
            self._known_servers.add(server_ip)

        msg_type_str = str(msg_type) if msg_type != "?" else "?"

        # Route to handler by message type
        if msg_type_str == "Startup message":
            self._handle_startup(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                client_mac,
                server_mac,
                pgsql_layer,
                fields,
                flow_id,
                stream_id=stream_id,
            )
        elif msg_type_str == "Authentication request":
            self._handle_auth_request_msg(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                server_mac,
                pgsql_layer,
                fields,
                flow_id,
                stream_id=stream_id,
            )
        elif msg_type_str == "Password message":
            self._handle_password(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                client_mac,
                pgsql_layer,
                flow_id,
                stream_id=stream_id,
            )
        elif msg_type_str == "Ready for query":
            self._handle_ready_for_query(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                pgsql_layer,
                flow_id,
                stream_id=stream_id,
            )
        elif msg_type_str in ("Error", "Notice"):
            self._handle_error_notice(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                server_mac,
                pgsql_layer,
                msg_type_str,
                flow_id,
                stream_id=stream_id,
            )
        elif msg_type_str == "Termination":
            self._handle_termination(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                flow_id,
                stream_id=stream_id,
            )
        elif msg_type_str == "Simple query":
            self._handle_simple_query(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                pgsql_layer,
                flow_id,
                stream_id=stream_id,
            )
        elif msg_type_str in ("Parameter status",):
            self._handle_parameter_status(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                pgsql_layer,
                flow_id,
                stream_id=stream_id,
            )
        else:
            # Other message types: record interaction for visibility
            direction = "request" if is_frontend else "response"
            src_p = client_port if is_frontend else server_port
            dst_p = server_port if is_frontend else client_port
            self._record_interaction(
                now,
                client_ip if is_frontend else server_ip,
                server_ip if is_frontend else client_ip,
                direction,
                msg_type_str,
                {"msg_type": msg_type_str},
                f"PostgreSQL {msg_type_str}",
                flow_id=flow_id,
                src_port=src_p,
                dst_port=dst_p,
                stream_id=stream_id,
            )

    # -------------------------------------------------------------------------
    # Startup message handler
    # -------------------------------------------------------------------------

    def _handle_startup(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        client_mac: str,
        server_mac: str,
        pgsql_layer: Any,
        fields: Dict[str, str],
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle PostgreSQL Startup message from client.

        Extracts: version_major, version_minor, parameter name/value pairs
        (user, database, client_encoding, etc.)
        """
        session = self._get_session(client_ip, server_ip, client_port)

        # Extract protocol version (T1 fields: pgsql.version_major, pgsql.version_minor)
        version_major = self.get_field(pgsql_layer, "version_major", "")
        version_minor = self.get_field(pgsql_layer, "version_minor", "")
        if version_major:
            session.protocol_version = f"{version_major}.{version_minor or '0'}"
        else:
            session.protocol_version = "?"
            self.logger.debug(f"Missing version_major in startup from {client_ip} -> {server_ip}")

        # Extract startup parameters (handles EK list mode)
        params = self._extract_startup_params(pgsql_layer)

        if "user" in params:
            session.username = params["user"]
        if "database" in params:
            session.database = params["database"]

        # If params didn't work, try direct field access (fallback for XML mode)
        if not session.username:
            user = self.get_field(pgsql_layer, "user", None)
            if user:
                session.username = str(user)

        if not session.database:
            database = self.get_field(pgsql_layer, "database", None)
            if database:
                session.database = str(database)

        if not session.username:
            session.username = "?"
            self.logger.debug(f"Missing username in startup from {client_ip} -> {server_ip}")

        # Build interaction details
        details: Dict[str, Any] = {
            "msg_type": "Startup message",
            "version_major": str(version_major) if version_major else "?",
            "version_minor": str(version_minor) if version_minor else "0",
            "username": session.username,
            "database": session.database or "?",
        }
        # Include other startup params of interest
        for key in ("client_encoding", "application_name"):
            if key in params:
                details[key] = params[key]

        detail_str = f"user={session.username}"
        if session.database:
            detail_str += f" db={session.database}"
        detail_str += f" v{session.protocol_version}"

        self._record_interaction(
            now,
            client_ip,
            server_ip,
            "request",
            "Startup",
            details,
            f"Startup {detail_str}",
            flow_id=flow_id,
            src_port=client_port,
            dst_port=server_port,
            stream_id=stream_id,
        )

        # Update devices
        manufacturer = lookup_mac_vendor(client_mac) if client_mac else ""
        self._update_client_device(
            client_ip,
            server_ip,
            client_mac,
            manufacturer=manufacturer,
        )
        self._update_server_device(server_ip, server_port, server_mac)

    # -------------------------------------------------------------------------
    # Authentication request handler
    # -------------------------------------------------------------------------

    def _handle_auth_request_msg(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        server_mac: str,
        pgsql_layer: Any,
        fields: Dict[str, str],
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle PostgreSQL AuthenticationRequest message from server."""
        session = self._get_session(client_ip, server_ip, client_port)

        authtype = self.get_field(pgsql_layer, "authtype", None)
        if authtype is None:
            authtype = "?"
            self.logger.debug(f"Missing authtype in auth request from {server_ip} -> {client_ip}")

        try:
            auth_type_int = int(authtype)
        except (ValueError, TypeError):
            # Try string-based auth type parsing
            authtype_str = str(authtype).lower()
            if "ok" in authtype_str:
                auth_type_int = AUTH_OK
            elif "md5" in authtype_str:
                auth_type_int = AUTH_MD5
            elif "cleartext" in authtype_str:
                auth_type_int = AUTH_CLEARTEXT
            elif "sasl" in authtype_str:
                auth_type_int = AUTH_SASL
            else:
                auth_type_int = -1

        auth_name = {
            AUTH_OK: "OK",
            AUTH_CLEARTEXT: "Cleartext",
            AUTH_MD5: "MD5",
            AUTH_SASL: "SASL",
        }.get(auth_type_int, f"Type({auth_type_int})")

        details: Dict[str, Any] = {
            "msg_type": "Authentication request",
            "authtype": str(authtype),
            "auth_name": auth_name,
        }

        if auth_type_int == AUTH_OK:
            session.authenticated = True
            session.auth_type = session.auth_type or "none"
            if session.username and session.username != "?":
                self._record_credential(session, success=True)
                self.logger.info(
                    f"PostgreSQL: Auth OK for {session.username}@{session.database} "
                    f"from {session.client_ip} (type={session.auth_type})"
                )
            details["result"] = "authenticated"

        elif auth_type_int == AUTH_CLEARTEXT:
            session.auth_type = "cleartext"
            details["result"] = "requesting cleartext password"
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "credential_alert",
                    "message": (
                        f"PGSQL CLEARTEXT: Server {server_ip} requests cleartext password "
                        f"from {client_ip} (user={session.username})"
                    ),
                }
            )

        elif auth_type_int == AUTH_MD5:
            session.auth_type = "md5"
            salt = self.get_field(pgsql_layer, "salt", None)
            if salt:
                session.salt = str(salt)
            else:
                # Check fields dict for salt variations
                for key, value in fields.items():
                    if "salt" in key.lower():
                        session.salt = str(value)
                        break
                if not session.salt:
                    session.salt = "?"
                    self.logger.debug(f"Missing salt in MD5 auth request from {server_ip}")
            details["salt"] = session.salt
            details["result"] = "requesting MD5 password"

        elif auth_type_int == AUTH_SASL:
            session.auth_type = "sasl"
            # Extract SASL mechanism if available
            sasl_mech = self.get_field(pgsql_layer, "auth_sasl_mech", "")
            if sasl_mech:
                details["sasl_mechanism"] = str(sasl_mech)
            details["result"] = "requesting SASL auth"

        self._record_interaction(
            now,
            server_ip,
            client_ip,
            "response",
            f"Auth ({auth_name})",
            details,
            f"Auth {auth_name} for {session.username}",
            flow_id=flow_id,
            src_port=server_port,
            dst_port=client_port,
            stream_id=stream_id,
        )

        self._update_server_device(server_ip, server_port, "")

    # -------------------------------------------------------------------------
    # Password message handler
    # -------------------------------------------------------------------------

    def _handle_password(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        client_mac: str,
        pgsql_layer: Any,
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle PostgreSQL PasswordMessage from client."""
        session = self._get_session(client_ip, server_ip, client_port)

        password = self.get_field(pgsql_layer, "password", None)
        if password:
            session.password_or_hash = str(password)
        else:
            session.password_or_hash = "?"
            self.logger.debug(
                f"Missing password field in PasswordMessage from {client_ip} -> {server_ip}"
            )

        # Determine if this is MD5 hash or cleartext
        is_md5 = session.password_or_hash.startswith("md5")
        cred_display = "MD5 hash" if is_md5 else "password"

        details: Dict[str, Any] = {
            "msg_type": "Password message",
            "username": session.username or "?",
            "is_md5": is_md5,
            "auth_type": session.auth_type or "?",
        }

        self._record_interaction(
            now,
            client_ip,
            server_ip,
            "request",
            "Password",
            details,
            f"Password ({cred_display}) for {session.username or '?'}",
            flow_id=flow_id,
            src_port=client_port,
            dst_port=server_port,
            stream_id=stream_id,
        )

        # Record credential on password receipt (success=None until AUTH_OK/ERR)
        if session.username and session.username != "?":
            self._record_credential(session, success=None)

        self.logger.debug(
            f"PostgreSQL: Client {client_ip} sent {cred_display} for user {session.username}"
        )

    # -------------------------------------------------------------------------
    # ReadyForQuery handler
    # -------------------------------------------------------------------------

    def _handle_ready_for_query(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        pgsql_layer: Any,
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle PostgreSQL ReadyForQuery message from server.

        Extracts pgsql.status: transaction status byte.
        """
        # T1 field: pgsql.status
        status_raw = self.get_field(pgsql_layer, "status", "")
        status_str = str(status_raw) if status_raw else "?"
        tx_status = TRANSACTION_STATUS.get(status_str, f"unknown({status_str})")

        details: Dict[str, Any] = {
            "msg_type": "Ready for query",
            "status": status_str,
            "transaction_status": tx_status,
        }

        if not status_raw:
            self.logger.debug(
                f"Missing pgsql.status in ReadyForQuery from {server_ip} -> {client_ip}"
            )

        self._record_interaction(
            now,
            server_ip,
            client_ip,
            "response",
            "Ready",
            details,
            f"Ready ({tx_status})",
            flow_id=flow_id,
            src_port=server_port,
            dst_port=client_port,
            stream_id=stream_id,
        )

    # -------------------------------------------------------------------------
    # Error / Notice handler
    # -------------------------------------------------------------------------

    def _handle_error_notice(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        server_mac: str,
        pgsql_layer: Any,
        msg_type_str: str,
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle PostgreSQL ErrorResponse or NoticeResponse.

        Extracts T1 fields: severity, code, message, file, line, routine.
        """
        session = self._get_session(client_ip, server_ip, client_port)

        # T1 fields: pgsql.severity, pgsql.code, pgsql.message
        severity = self.get_field(pgsql_layer, "severity", "")
        if not severity:
            severity = "?"
            self.logger.debug(f"Missing severity in {msg_type_str} from {server_ip}")

        code = self.get_field(pgsql_layer, "code", "")
        if not code:
            code = "?"
            self.logger.debug(f"Missing code in {msg_type_str} from {server_ip}")

        message = self.get_field(pgsql_layer, "message", "")
        if not message:
            message = "?"
            self.logger.debug(f"Missing message in {msg_type_str} from {server_ip}")

        # T1 fields: pgsql.file, pgsql.line, pgsql.routine
        file_name = self.get_field(pgsql_layer, "file", "")
        if not file_name:
            file_name = "?"
            self.logger.debug(f"Missing file in {msg_type_str} from {server_ip}")

        line_num = self.get_field(pgsql_layer, "line", "")
        if not line_num:
            line_num = "?"
            self.logger.debug(f"Missing line in {msg_type_str} from {server_ip}")

        routine = self.get_field(pgsql_layer, "routine", "")
        if not routine:
            routine = "?"
            self.logger.debug(f"Missing routine in {msg_type_str} from {server_ip}")

        details: Dict[str, Any] = {
            "msg_type": msg_type_str,
            "severity": str(severity),
            "code": str(code),
            "message": str(message),
            "file": str(file_name),
            "line": str(line_num),
            "routine": str(routine),
        }

        display_msg = str(message)

        self._record_interaction(
            now,
            server_ip,
            client_ip,
            "response",
            msg_type_str,
            details,
            f"{msg_type_str}: [{severity}] {code} {display_msg}",
            flow_id=flow_id,
            src_port=server_port,
            dst_port=client_port,
            stream_id=stream_id,
        )

        # For ErrorResponse: check if it's an auth failure
        if msg_type_str == "Error":
            severity_str = str(severity)
            if severity_str in ("FATAL", "ERROR") and session.password_or_hash:
                # Mark credential as failed
                for cred in self.credentials:
                    if (
                        cred.server_ip == session.server_ip
                        and cred.client_ip == session.client_ip
                        and cred.username == session.username
                        and cred.success is None
                    ):
                        cred.success = False
                        self.logger.debug(
                            f"PostgreSQL: Auth failed for {session.username}@{session.server_ip}: "
                            f"{code} {display_msg}"
                        )
                        break

        self._update_server_device(server_ip, server_port, "")

    # -------------------------------------------------------------------------
    # Termination handler
    # -------------------------------------------------------------------------

    def _handle_termination(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle PostgreSQL Terminate message from client."""
        session = self._get_session(client_ip, server_ip, client_port)

        details: Dict[str, Any] = {
            "msg_type": "Termination",
            "username": session.username or "?",
        }

        self._record_interaction(
            now,
            client_ip,
            server_ip,
            "request",
            "Termination",
            details,
            f"Terminate (user={session.username or '?'})",
            flow_id=flow_id,
            src_port=client_port,
            dst_port=server_port,
            stream_id=stream_id,
        )

    # -------------------------------------------------------------------------
    # Simple query handler
    # -------------------------------------------------------------------------

    def _handle_simple_query(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        pgsql_layer: Any,
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle PostgreSQL Simple Query message from client."""
        query = self.get_field(pgsql_layer, "query", "")
        if not query:
            query = "?"
            self.logger.debug(f"Missing query text in Simple query from {client_ip} -> {server_ip}")

        query_str = str(query)
        display_query = query_str

        details: Dict[str, Any] = {
            "msg_type": "Simple query",
            "query": query_str,
        }

        self._record_interaction(
            now,
            client_ip,
            server_ip,
            "request",
            "Query",
            details,
            f"Query: {display_query}",
            flow_id=flow_id,
            src_port=client_port,
            dst_port=server_port,
            stream_id=stream_id,
        )

    # -------------------------------------------------------------------------
    # Parameter status handler
    # -------------------------------------------------------------------------

    def _handle_parameter_status(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        pgsql_layer: Any,
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle PostgreSQL ParameterStatus message from server.

        These messages convey server parameters like server_version,
        client_encoding, TimeZone, etc.
        """
        params = self._extract_startup_params(pgsql_layer)
        if not params:
            # Single param via get_field
            pname = self.get_field(pgsql_layer, "parameter_name", "")
            pval = self.get_field(pgsql_layer, "parameter_value", "")
            if pname:
                params = {str(pname): str(pval) if pval else ""}

        if params:
            if server_ip not in self._server_params:
                self._server_params[server_ip] = {}
            self._server_params[server_ip].update(params)

            # Update session with server params
            session = self._get_session(client_ip, server_ip, client_port)
            session.server_params.update(params)

        details: Dict[str, Any] = {
            "msg_type": "Parameter status",
        }
        details.update(params)

        param_str = ", ".join(f"{k}={v}" for k, v in params.items())

        self._record_interaction(
            now,
            server_ip,
            client_ip,
            "response",
            "ParameterStatus",
            details,
            f"Params: {param_str}",
            flow_id=flow_id,
            src_port=server_port,
            dst_port=client_port,
            stream_id=stream_id,
        )

    # -------------------------------------------------------------------------
    # Session management
    # -------------------------------------------------------------------------

    def _get_session(self, client_ip: str, server_ip: str, client_port: int) -> PostgreSQLSession:
        """Get or create PostgreSQL session tracker."""
        key = (client_ip, server_ip, client_port)
        if key not in self._sessions:
            self._sessions[key] = PostgreSQLSession(
                client_ip=client_ip,
                server_ip=server_ip,
            )
        return self._sessions[key]

    # -------------------------------------------------------------------------
    # Credential recording
    # -------------------------------------------------------------------------

    def _record_credential(self, session: PostgreSQLSession, success: Optional[bool]) -> None:
        """Record extracted PostgreSQL credential."""
        # Check for duplicates
        for cred in self.credentials:
            if (
                cred.server_ip == session.server_ip
                and cred.client_ip == session.client_ip
                and cred.username == session.username
                and cred.database == session.database
                and cred.password_or_hash == session.password_or_hash
            ):
                # Update success status if we now know it
                if success is not None and cred.success is None:
                    cred.success = success
                return

        cred = PostgreSQLCredential(
            username=session.username,
            database=session.database,
            password_or_hash=session.password_or_hash,
            salt=session.salt if session.salt else None,
            auth_type=session.auth_type,
            server_ip=session.server_ip,
            client_ip=session.client_ip,
            success=success,
            timestamp=datetime.now().isoformat(),
        )
        self.credentials.append(cred)

        log_msg = f"PostgreSQL Credential: {session.username}@{session.database}"
        if session.auth_type == "md5":
            log_msg += f" (MD5 hash, salt={session.salt})"
        elif session.auth_type == "cleartext":
            log_msg += f" (cleartext: {session.password_or_hash})"
        elif session.auth_type == "none":
            log_msg += " (no password)"
        log_msg += f" @ {session.server_ip} (success={success})"
        self.logger.info(log_msg)

        # Update device with credential info
        self._update_device_credentials(session, cred)

    # -------------------------------------------------------------------------
    # Interaction table formatting
    # -------------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format a single PostgreSQL interaction as protocol-specific table columns.

        Columns: Type, Operation, Details, Result
        """
        d = ix.details
        op = ix.operation
        msg_type = d.get("msg_type", "")

        # Details column
        if op == "Startup":
            user = d.get("username", "?")
            db = d.get("database", "?")
            ver = f"{d.get('version_major', '?')}.{d.get('version_minor', '0')}"
            detail = f"user={user} db={db} v{ver}"
        elif op == "Password":
            user = d.get("username", "?")
            is_md5 = d.get("is_md5", False)
            detail = f"user={user} ({'MD5' if is_md5 else 'cleartext'})"
        elif op.startswith("Auth"):
            auth_name = d.get("auth_name", "?")
            salt = d.get("salt", "")
            detail = auth_name
            if salt:
                detail += f" salt={salt}"
        elif op == "Ready":
            tx = d.get("transaction_status", "?")
            detail = tx
        elif op in ("Error", "Notice"):
            sev = d.get("severity", "?")
            code = d.get("code", "?")
            msg = d.get("message", "?")
            detail = f"[{sev}] {code}: {msg}"
        elif op == "Termination":
            detail = d.get("username", "?")
        elif op == "Query":
            q = d.get("query", "?")
            detail = q
        elif op == "ParameterStatus":
            # Show params excluding msg_type
            params = {k: v for k, v in d.items() if k != "msg_type"}
            detail = ", ".join(f"{k}={v}" for k, v in params.items())
        else:
            detail = ix.summary or ""

        # Result column
        result = d.get("result", "")

        return [msg_type, op, detail, result]

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _update_server_device(
        self,
        server_ip: str,
        server_port: int = 5432,
        server_mac: str = "",
        *,
        server_version: str = "",
    ) -> None:
        """Update or create PostgreSQL server device entry."""
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"pgsql-server:{server_ip}"
        manufacturer = lookup_mac_vendor(server_mac) if server_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            mac=server_mac,
            name=f"PostgreSQL Server ({server_ip})",
            device_type="Database Server",
            manufacturer=manufacturer if manufacturer != "Unknown" else "",
        )
        if is_new:
            device.pgsql_passive_data = {
                "role": "server",
                "credentials": [],
                "databases": [],
                "protocol": "PostgreSQL/TCP",
                "port": server_port,
            }

        # Enrich with server params if available
        if server_ip in self._server_params and device.pgsql_passive_data:
            params = self._server_params[server_ip]
            sv = params.get("server_version", "")
            if sv:
                device.pgsql_passive_data["server_version"] = sv

    def _update_client_device(
        self,
        client_ip: str,
        server_ip: str,
        client_mac: str = "",
        *,
        manufacturer: str = "",
    ) -> None:
        """Update or create PostgreSQL client device entry."""
        if not is_valid_discovered_ip(client_ip):
            return

        device_key = f"pgsql-client:{client_ip}"
        if not manufacturer:
            manufacturer = lookup_mac_vendor(client_mac) if client_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            mac=client_mac,
            name=f"PostgreSQL Client ({client_ip})",
            device_type="Database Client",
            manufacturer=manufacturer if manufacturer != "Unknown" else "",
        )
        if is_new:
            device.pgsql_passive_data = {
                "role": "client",
                "credentials": [],
                "servers_accessed": [server_ip],
                "protocol": "PostgreSQL/TCP",
            }
        else:
            if device.pgsql_passive_data:
                servers = device.pgsql_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.pgsql_passive_data["servers_accessed"] = servers

    def _update_device_credentials(
        self, session: PostgreSQLSession, cred: PostgreSQLCredential
    ) -> None:
        """Update device entries with credential information."""
        server_key = f"pgsql-server:{session.server_ip}"
        client_key = f"pgsql-client:{session.client_ip}"

        cred_entry = {
            "username": cred.username,
            "database": cred.database,
            "auth_type": cred.auth_type,
            "client_ip": cred.client_ip,
            "timestamp": cred.timestamp,
            "success": cred.success,
        }

        # Add hash/password based on auth type
        if cred.auth_type == "md5":
            cred_entry["md5_hash"] = cred.password_or_hash
            cred_entry["salt"] = cred.salt
        elif cred.auth_type == "cleartext":
            cred_entry["password"] = cred.password_or_hash

        with self._lock:
            # Update server
            if server_key in self.discovered_devices:
                device = self.discovered_devices[server_key]
                if device.pgsql_passive_data:
                    creds = device.pgsql_passive_data.get("credentials", [])
                    # Avoid duplicates
                    if not any(
                        c.get("username") == cred.username
                        and c.get("database") == cred.database
                        and c.get("client_ip") == cred.client_ip
                        for c in creds
                    ):
                        creds.append(cred_entry)
                        device.pgsql_passive_data["credentials"] = creds

                    # Track databases
                    databases = device.pgsql_passive_data.get("databases", [])
                    if cred.database and cred.database not in databases:
                        databases.append(cred.database)
                        device.pgsql_passive_data["databases"] = databases

            # Update client
            if client_key in self.discovered_devices:
                device = self.discovered_devices[client_key]
                if device.pgsql_passive_data:
                    creds = device.pgsql_passive_data.get("credentials", [])
                    client_cred = {
                        "username": cred.username,
                        "database": cred.database,
                        "server_ip": cred.server_ip,
                        "auth_type": cred.auth_type,
                        "timestamp": cred.timestamp,
                        "success": cred.success,
                    }
                    if not any(
                        c.get("username") == cred.username and c.get("server_ip") == cred.server_ip
                        for c in creds
                    ):
                        creds.append(client_cred)
                        device.pgsql_passive_data["credentials"] = creds

    # -------------------------------------------------------------------------
    # harvest() and get_* methods
    # -------------------------------------------------------------------------

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials.

        Uses canonical key names for the base class harvest()
        credential table builder.
        """
        return [
            {
                "protocol": "PostgreSQL",
                "credential_type": (
                    "hash"
                    if cred.auth_type == "md5"
                    else "plaintext"
                    if cred.auth_type == "cleartext"
                    else "plaintext"
                ),
                "auth_method": f"PostgreSQL/{cred.auth_type}",
                "username": cred.username,
                "password": cred.password_or_hash,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "database": cred.database,
                "salt": cred.salt,
                "success": cred.success,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]

    def get_hashes_summary(self) -> List[Dict[str, Any]]:
        """Get summary of extracted hashes for base class harvest().

        Only includes MD5-authenticated credentials (not cleartext).

        Returns list of dicts with keys expected by base class harvest():
        protocol, hash_type, username, domain, server_ip, client_ip,
        hashcat_format.
        """
        hashcat_lines = self.get_hashcat_format()
        result = []
        hashcat_idx = 0
        for cred in self.credentials:
            if cred.auth_type != "md5" or not cred.password_or_hash:
                continue
            result.append(
                {
                    "protocol": "PostgreSQL",
                    "hash_type": "MD5",
                    "username": cred.username,
                    "domain": cred.database,
                    "server_ip": cred.server_ip,
                    "client_ip": cred.client_ip,
                    "hashcat_format": (
                        hashcat_lines[hashcat_idx] if hashcat_idx < len(hashcat_lines) else ""
                    ),
                }
            )
            hashcat_idx += 1
        return result

    def get_hashcat_format(self) -> List[str]:
        """Get MD5 credentials in hashcat-compatible format.

        PostgreSQL MD5 hash = "md5" + md5(md5(password + user) + salt)
        The wire value already includes the "md5" prefix.

        Hashcat mode 12 handles raw MD5 hashes; for PostgreSQL-specific
        cracking use ``dynamic_1034`` in John the Ripper or a custom rule.

        Returns:
            List of hash strings in format: username:hash:salt
        """
        hashes = []
        for cred in self.credentials:
            if cred.auth_type == "md5" and cred.password_or_hash:
                salt_hex = cred.salt or ""
                hashes.append(f"{cred.username}:{cred.password_or_hash}:{salt_hex}")
        return hashes

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data.

        Delegates to base class for:
        - Credentials table (via get_credentials_summary)
        - Hashes table (via get_hashes_summary)
        - Interaction tables (via PROTOCOL_COLUMNS + _format_protocol_columns)

        Appends custom security alerts (cleartext auth).
        """
        result = super().harvest()
        if not result:
            if self._alerts:
                result = {"tables": [], "alerts": []}
            else:
                return {}

        # Append custom alerts
        alerts = result.get("alerts", [])
        for alert in self._alerts:
            if alert not in alerts:
                alerts.append(alert)
        result["alerts"] = alerts

        return result
