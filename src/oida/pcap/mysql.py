"""
MySQL Passive Listener for credential and query extraction.

Passively captures MySQL traffic to extract:
- Server version, protocol version, connection ID, auth plugin
- Salt/scramble values for offline password cracking
- Client authentication credentials (username + password hash)
- SQL queries (SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, etc.)
- Query results (OK packet, Error packet, result set metadata)
- Authentication success/failure tracking

MySQL authentication flow:
    1. Server sends greeting with:
       - Protocol version (10 for MySQL 5.x/8.x)
       - Server version string
       - Connection ID (thread_id)
       - Salt (scramble) part 1 - 8 bytes
       - Server capabilities
       - Charset, status flags
       - Salt part 2 - 12 bytes
       - Auth plugin name (e.g., mysql_native_password)

    2. Client responds with:
       - Client capabilities
       - Max packet size
       - Charset
       - Username (null-terminated)
       - Password hash (scrambled with salt)
       - Database (optional)
       - Auth plugin name (optional, mysql.client_auth_plugin)

    3. Server sends OK (0x00) or ERR (0xff) packet

Password hash format for mysql_native_password:
    SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))
    - 20 bytes of scrambled password data
    - Can be cracked with hashcat mode 11200 (MySQL $mysqlna$)

Key PyShark MySQL fields (EK mode uses short names; get_all_fields
prefixes them with ``mysql.``):
- mysql.version: Server version string
- mysql.protocol: MySQL protocol version (10)
- mysql.thread_id: Server connection ID
- mysql.salt / mysql.salt2: Scramble bytes (raw ASCII in EK mode)
- mysql.auth_plugin: Server auth plugin (EkMultiField in EK mode)
- mysql.user: Login username
- mysql.passwd: Password hash (colon-separated hex)
- mysql.client_auth_plugin: Client-side auth plugin name
- mysql.schema: Database name
- mysql.command: MySQL command type (3=Query, 2=Init DB, 1=Quit)
- mysql.query: SQL query text
- mysql.response_code: 0x00=OK, 0xfe=EOF, 0xff=ERR
- mysql.affected_rows: Rows affected by statement
- mysql.error_code / mysql.error_string: Error details
- mysql.server_greeting: Present (as null) on greeting packets
- mysql.login_request: Present (as null) on login request packets
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

import logging

logger = logging.getLogger(__name__)


# MySQL ports
MYSQL_PORT = 3306
MYSQL_PORTS = {MYSQL_PORT, 3307, 33060}

# MySQL command constants
MYSQL_CMD_QUIT = 1
MYSQL_CMD_INIT_DB = 2
MYSQL_CMD_QUERY = 3
MYSQL_CMD_FIELD_LIST = 4
MYSQL_CMD_CREATE_DB = 5
MYSQL_CMD_DROP_DB = 6
MYSQL_CMD_REFRESH = 7
MYSQL_CMD_SHUTDOWN = 8
MYSQL_CMD_STATISTICS = 9
MYSQL_CMD_PROCESS_INFO = 10
MYSQL_CMD_PROCESS_KILL = 12
MYSQL_CMD_CHANGE_USER = 17
MYSQL_CMD_PING = 14
MYSQL_CMD_STMT_PREPARE = 22
MYSQL_CMD_STMT_EXECUTE = 23
MYSQL_CMD_STMT_CLOSE = 25
MYSQL_CMD_RESET_CONNECTION = 31

MYSQL_COMMAND_NAMES = {
    MYSQL_CMD_QUIT: "Quit",
    MYSQL_CMD_INIT_DB: "Init DB",
    MYSQL_CMD_QUERY: "Query",
    MYSQL_CMD_FIELD_LIST: "Field List",
    MYSQL_CMD_CREATE_DB: "Create DB",
    MYSQL_CMD_DROP_DB: "Drop DB",
    MYSQL_CMD_REFRESH: "Refresh",
    MYSQL_CMD_SHUTDOWN: "Shutdown",
    MYSQL_CMD_STATISTICS: "Statistics",
    MYSQL_CMD_PROCESS_INFO: "Process Info",
    MYSQL_CMD_PROCESS_KILL: "Process Kill",
    MYSQL_CMD_CHANGE_USER: "Change User",
    MYSQL_CMD_PING: "Ping",
    MYSQL_CMD_STMT_PREPARE: "Stmt Prepare",
    MYSQL_CMD_STMT_EXECUTE: "Stmt Execute",
    MYSQL_CMD_STMT_CLOSE: "Stmt Close",
    MYSQL_CMD_RESET_CONNECTION: "Reset Connection",
}

# Response code constants
MYSQL_RESP_OK = 0x00
MYSQL_RESP_EOF = 0xFE
MYSQL_RESP_ERR = 0xFF

# Server status flag bits (mysql.server_status bitmask)
_SERVER_STATUS_FLAGS = {
    0x0001: "IN_TRANS",
    0x0002: "AUTOCOMMIT",
    0x0008: "MORE_RESULTS",
    0x0010: "NO_GOOD_INDEX",
    0x0020: "NO_INDEX",
    0x0040: "CURSOR_EXISTS",
    0x0080: "LAST_ROW_SENT",
    0x0100: "DB_DROPPED",
    0x0200: "NO_BACKSLASH_ESCAPES",
    0x0400: "METADATA_CHANGED",
    0x0800: "QUERY_WAS_SLOW",
    0x1000: "PS_OUT_PARAMS",
    0x2000: "IN_TRANS_READONLY",
    0x4000: "SESSION_STATE_CHANGED",
}

# Weak/insecure auth plugins
WEAK_AUTH_PLUGINS = {
    "mysql_clear_password",
    "mysql_old_password",
    "authentication_pam",
}

# Dangerous SQL operations
DANGEROUS_SQL_PREFIXES = {
    "DROP",
    "DELETE",
    "TRUNCATE",
    "ALTER",
    "GRANT",
    "REVOKE",
    "CREATE USER",
    "DROP USER",
    "SET PASSWORD",
    "FLUSH PRIVILEGES",
    "SHUTDOWN",
    "LOAD DATA",
    "LOAD_FILE",
}

# Write SQL operations
WRITE_SQL_PREFIXES = {
    "INSERT",
    "UPDATE",
    "DELETE",
    "REPLACE",
    "CREATE",
    "DROP",
    "ALTER",
    "TRUNCATE",
    "GRANT",
    "REVOKE",
}


def _classify_query(query: str) -> str:
    """Classify a SQL query by its operation type."""
    upper = query.strip().upper()
    for prefix in sorted(WRITE_SQL_PREFIXES, key=len, reverse=True):
        if upper.startswith(prefix):
            return prefix.title()
    if upper.startswith("SELECT"):
        return "Select"
    if upper.startswith("SHOW"):
        return "Show"
    if upper.startswith("SET"):
        return "Set"
    if upper.startswith("USE"):
        return "Use"
    if upper.startswith("DESCRIBE") or upper.startswith("DESC"):
        return "Describe"
    if upper.startswith("EXPLAIN"):
        return "Explain"
    if upper.startswith("BEGIN") or upper.startswith("START TRANSACTION"):
        return "Begin"
    if upper.startswith("COMMIT"):
        return "Commit"
    if upper.startswith("ROLLBACK"):
        return "Rollback"
    return "Other"


def _is_dangerous_query(query: str) -> bool:
    """Check if a SQL query is security-relevant (destructive/privilege)."""
    upper = query.strip().upper()
    return any(upper.startswith(p) for p in DANGEROUS_SQL_PREFIXES)


def _decode_server_status(raw: str) -> str:
    """Decode mysql.server_status bitmask to human-readable flag names."""
    try:
        val = int(str(raw), 0) if raw else 0
    except (ValueError, TypeError):
        return str(raw)
    if val == 0:
        return ""
    flags = [name for bit, name in _SERVER_STATUS_FLAGS.items() if val & bit]
    return ",".join(flags) if flags else str(val)


def _salt_to_hex(salt_str: str) -> str:
    """Convert tshark salt value (raw ASCII or hex) to hex string.

    tshark returns MySQL salt as raw ASCII text (e.g. ``>~$4uth,``)
    in both XML and EK modes.  We encode the raw bytes to hex for
    consistent storage and hashcat formatting.

    If the value already looks like colon-separated hex, strip colons.
    """
    if not salt_str:
        return ""
    # If it looks like colon-separated hex (e.g. from passwd field)
    if ":" in salt_str and all(len(p) == 2 for p in salt_str.split(":")):
        return salt_str.replace(":", "")
    # Raw ASCII text -- encode each char to hex
    try:
        return salt_str.encode("latin-1").hex()
    except (UnicodeEncodeError, AttributeError):
        return salt_str.encode("utf-8", errors="replace").hex()


@dataclass
class MySQLCredential:
    """Extracted MySQL credential."""

    username: str
    password_hash: str  # Hex-encoded scrambled password
    salt: str  # Hex-encoded salt part 1 (8 bytes)
    salt2: str  # Hex-encoded salt part 2 (12 bytes)
    auth_plugin: str  # e.g., "mysql_native_password"
    server_version: str
    server_ip: str
    client_ip: str
    success: Optional[bool] = None  # True if OK, False if ERR, None if unknown
    timestamp: str = ""
    credential_type: str = "hash"

    @property
    def password(self) -> str:
        """Alias for scanner credential loop compatibility."""
        return self.password_hash

    @property
    def hash_value(self) -> str:
        """Alias for scanner credential loop compatibility."""
        return self.password_hash

    @property
    def hashcat_format(self) -> str:
        """Hashcat-compatible hash string.

        mysql_native_password -> hashcat mode 11200:
            $mysqlna$<salt_hex>*<hash_hex>
        """
        if self.password_hash and self.salt:
            full_salt = self.salt + self.salt2
            return f"$mysqlna${full_salt}*{self.password_hash}"
        return ""

    @property
    def auth_method(self) -> str:
        """Return auth method for scanner loop."""
        return self.auth_plugin or "mysql_native_password"


@dataclass
class MySQLSession:
    """Track MySQL session state for credential extraction."""

    client_ip: str
    server_ip: str
    server_version: str = ""
    protocol_version: str = ""
    thread_id: str = ""
    salt_hex: str = ""  # 8-byte salt as hex
    salt2_hex: str = ""  # 12-byte salt as hex
    auth_plugin: str = ""
    client_auth_plugin: str = ""
    username: str = ""
    password_hash_hex: str = ""  # Password hash as hex
    schema: str = ""
    state: str = "init"  # init, got_greeting, got_auth, complete
    client_port: int = 0
    server_port: int = 3306
    query_count: int = 0
    write_count: int = 0
    error_count: int = 0


class MySQLPassiveListener(PySharkListenerBase):
    """Passive MySQL traffic listener for credential and query extraction.

    Captures MySQL traffic to extract:
    - Server greeting (version, protocol, thread ID, salt values, auth plugin)
    - Client authentication (username, scrambled password, client auth plugin)
    - Login success/failure (OK/ERR packets)
    - SQL queries with classification (read/write/DDL/admin)
    - Query results (affected rows, error codes)
    - Security alerts for cleartext auth, weak plugins, dangerous queries

    Uses the base class interaction table system (PROTOCOL_COLUMNS +
    GROUP_BY_STREAM) to produce per-stream operations tables automatically.

    Usage:
        # Live capture
        listener = MySQLPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access extracted credentials
        for cred in listener.credentials:
            print(f"{cred.username}:{cred.password_hash} @ {cred.server_ip}")

    Hashcat cracking:
        For mysql_native_password hashes, use hashcat mode 11200:
        hashcat -m 11200 hash.txt wordlist.txt

        Hash format: $mysqlna$<salt_hex>*<hash_hex>
    """

    PROTOCOL_NAME = "mysql"
    DISPLAY_FILTER = "mysql"
    REQUIRED_LAYERS = ("mysql",)

    PROTOCOL_COLUMNS = ("operation", "details", "result")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track MySQL sessions by (client_ip, client_port, server_ip, server_port)
        self._sessions: Dict[Tuple[str, int, str, int], MySQLSession] = {}

        # Extracted credentials
        self.credentials: List[MySQLCredential] = []

        # Track server roles to determine direction without hardcoded ports.
        # An IP is a "server" once we see it send a server_greeting.
        self._known_servers: Set[str] = set()

        # Server stats for device enrichment
        self._server_stats: Dict[str, Dict[str, Any]] = {}

        # Security alerts
        self._alerts: List[Dict[str, str]] = []

        # Write operations for get_write_operations()
        self._write_ops: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # Direction detection
    # -------------------------------------------------------------------------

    def _is_server(self, ip: str, port: int) -> bool:
        """Check if (ip, port) is a known MySQL server."""
        return ip in self._known_servers or port in MYSQL_PORTS

    # -------------------------------------------------------------------------
    # Packet processing
    # -------------------------------------------------------------------------

    def process_packet(self, packet) -> None:
        """Process MySQL packet and extract credentials/queries."""
        if not hasattr(packet, "mysql"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        src_port, dst_port = self.get_port_info(packet)

        if not src_ip or not dst_ip:
            return

        # Get MAC addresses for device enrichment
        src_mac, dst_mac = self.get_mac_info(packet)

        flow_id = self.get_flow_id(packet)
        mysql_layer = packet.mysql

        now = self._get_timestamp()
        stream_id = self.get_stream_id(packet)

        # Multi-PDU TCP segments: EK mode stores _fields_dict as a list
        # of dicts instead of a single dict; all_field_names returns None.
        ek_dicts = self._get_ek_layer_dicts(mysql_layer)
        if ek_dicts is not None:
            self._handle_multi_pdu(
                now,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                ek_dicts,
                flow_id,
                stream_id=stream_id,
            )
            return

        # Single-PDU: verify field_names are accessible
        if not hasattr(mysql_layer, "all_field_names"):
            # Fallback: record as unknown MySQL message
            self._handle_unknown(now, src_ip, src_port, dst_ip, dst_port, flow_id, stream_id)
            return
        field_names = mysql_layer.all_field_names
        if field_names is None:
            self._handle_unknown(now, src_ip, src_port, dst_ip, dst_port, flow_id, stream_id)
            return

        fields = self.get_all_fields(mysql_layer)

        # Determine direction using protocol-level indicators:
        # 1. server_greeting field -> server packet (src is server)
        # 2. login_request or user field -> client packet (src is client)
        # 3. query or command field (non-response) -> client packet
        # 4. response_code field -> server packet
        # 5. Fall back to known_servers / port heuristic

        has_greeting = "mysql.server_greeting" in fields or "mysql.version" in fields
        has_login = "mysql.login_request" in fields or "mysql.user" in fields
        has_query = "mysql.query" in fields  # Only true when actual SQL text present
        has_command = "mysql.command" in fields and "mysql.response_code" not in fields
        has_response = "mysql.response_code" in fields and not has_greeting

        if has_greeting:
            # Server -> Client: greeting
            server_ip, server_port = src_ip, src_port
            client_ip, client_port = dst_ip, dst_port
            server_mac, client_mac = src_mac, dst_mac
            self._known_servers.add(server_ip)
            self._handle_server_greeting(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                server_mac,
                client_mac,
                mysql_layer,
                fields,
                flow_id,
                stream_id=stream_id,
            )
        elif has_login:
            # Client -> Server: login request
            client_ip, client_port = src_ip, src_port
            server_ip, server_port = dst_ip, dst_port
            client_mac, server_mac = src_mac, dst_mac
            self._handle_login_request(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                client_mac,
                server_mac,
                mysql_layer,
                fields,
                flow_id,
                stream_id=stream_id,
            )
        elif has_query:
            # Client -> Server: query/command
            client_ip, client_port = src_ip, src_port
            server_ip, server_port = dst_ip, dst_port
            client_mac, server_mac = src_mac, dst_mac
            self._handle_query(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                client_mac,
                server_mac,
                mysql_layer,
                fields,
                flow_id,
                stream_id=stream_id,
            )
        elif has_response:
            # Server -> Client: response (OK/ERR/EOF)
            server_ip, server_port = src_ip, src_port
            client_ip, client_port = dst_ip, dst_port
            server_mac, client_mac = src_mac, dst_mac
            self._handle_response(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                mysql_layer,
                fields,
                flow_id,
                stream_id=stream_id,
            )
        elif has_command:
            # Command without query (e.g., Init DB, Quit, Ping)
            client_ip, client_port = src_ip, src_port
            server_ip, server_port = dst_ip, dst_port
            client_mac, server_mac = src_mac, dst_mac
            self._handle_command(
                now,
                client_ip,
                client_port,
                server_ip,
                server_port,
                client_mac,
                server_mac,
                mysql_layer,
                fields,
                flow_id,
                stream_id=stream_id,
            )
        else:
            # Unrecognized single-PDU packet (e.g. bare result set
            # metadata, field list reply, etc.) -- record so no packet
            # is silently dropped.
            self._handle_unknown(now, src_ip, src_port, dst_ip, dst_port, flow_id, stream_id)

    # -------------------------------------------------------------------------
    # Server greeting
    # -------------------------------------------------------------------------

    def _handle_server_greeting(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        server_mac: str,
        client_mac: str,
        mysql_layer: Any,
        fields: Dict[str, str],
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle MySQL server greeting packet."""
        session = self._get_session(client_ip, client_port, server_ip, server_port)

        version = self.get_field(mysql_layer, "version", "")
        if not version:
            version = "?"
            self.logger.debug(f"Missing version in greeting from {server_ip}")

        protocol = self.get_field(mysql_layer, "protocol", "")
        thread_id = self.get_field(mysql_layer, "thread_id", "")

        # Salt values: tshark returns raw ASCII in both XML and EK modes
        salt_raw = self.get_field(mysql_layer, "salt", "")
        salt2_raw = self.get_field(mysql_layer, "salt2", "")
        salt_hex = _salt_to_hex(str(salt_raw)) if salt_raw else ""
        salt2_hex = _salt_to_hex(str(salt2_raw)) if salt2_raw else ""

        # Auth plugin: may be EkMultiField in EK mode, resolved by get_field
        auth_plugin = self.get_field(mysql_layer, "auth_plugin", "")
        if not auth_plugin:
            auth_plugin = ""

        # T1 field: mysql.auth_plugin.length -- length byte of auth plugin name
        auth_plugin_length = self.get_field(mysql_layer, "auth_plugin_length", "")
        if not auth_plugin_length and auth_plugin:
            auth_plugin_length = "?"
            self.logger.debug(f"Missing auth_plugin.length in greeting from {server_ip}")

        # T1 field: mysql.packet_number -- sequence ID for this packet
        packet_number = self.get_field(mysql_layer, "packet_number", "")
        if not packet_number and packet_number != "0" and packet_number != 0:
            packet_number = "?"
            self.logger.debug(f"Missing packet_number in greeting from {server_ip}")

        # T1 field: mysql.server_status -- server status flags
        server_status_raw = self.get_field(mysql_layer, "server_status", "")
        server_status_flags = _decode_server_status(server_status_raw) if server_status_raw else ""

        session.server_version = str(version)
        session.protocol_version = str(protocol) if protocol else ""
        session.thread_id = str(thread_id) if thread_id else ""
        session.salt_hex = salt_hex
        session.salt2_hex = salt2_hex
        session.auth_plugin = str(auth_plugin)
        session.state = "got_greeting"

        # Build interaction details
        details: Dict[str, Any] = {
            "version": session.server_version,
            "protocol": session.protocol_version,
            "thread_id": session.thread_id,
            "auth_plugin": session.auth_plugin or "?",
            "auth_plugin_length": str(auth_plugin_length) if auth_plugin_length else "",
            "salt_len": len(salt_hex) // 2 if salt_hex else 0,
            "packet_number": str(packet_number),
            "server_status": str(server_status_raw) if server_status_raw else "",
            "server_status_flags": server_status_flags,
        }
        detail_str = f"v{session.server_version}"
        if session.auth_plugin:
            detail_str += f" plugin={session.auth_plugin}"

        self._record_interaction(
            now,
            server_ip,
            client_ip,
            "response",
            "Greeting",
            details,
            f"Server Greeting {detail_str}",
            flow_id=flow_id,
            src_port=server_port,
            dst_port=client_port,
            stream_id=stream_id,
        )

        # Security alert for weak auth plugins
        if session.auth_plugin in WEAK_AUTH_PLUGINS:
            alert = {
                "level": "fail",
                "category": "write_alert",
                "message": (
                    f"MYSQL WEAK AUTH: Server {server_ip} uses weak auth plugin "
                    f"'{session.auth_plugin}' (cleartext or legacy)"
                ),
            }
            self._alerts.append(alert)

        # Update device
        self._update_server_device(
            server_ip,
            server_port,
            server_mac,
            version=session.server_version,
            auth_plugin=session.auth_plugin,
            protocol_version=session.protocol_version,
            thread_id=session.thread_id,
        )

        self.logger.debug(
            f"MySQL: Server {server_ip} v{session.server_version} "
            f"plugin={session.auth_plugin} thread={session.thread_id} "
            f"salt1_hex={salt_hex} salt2_hex={salt2_hex}"
        )

    # -------------------------------------------------------------------------
    # Login request
    # -------------------------------------------------------------------------

    def _handle_login_request(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        client_mac: str,
        server_mac: str,
        mysql_layer: Any,
        fields: Dict[str, str],
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle MySQL login request (client authentication)."""
        session = self._get_session(client_ip, client_port, server_ip, server_port)

        username = self.get_field(mysql_layer, "user", "")
        if not username:
            username = "?"
            self.logger.debug(f"Missing username in login request from {client_ip}")
        session.username = str(username)

        # Password hash: colon-separated hex in EK mode
        passwd_raw = self.get_field(mysql_layer, "passwd", "")
        if passwd_raw:
            passwd_hex = str(passwd_raw).replace(":", "")
            session.password_hash_hex = passwd_hex
        else:
            session.password_hash_hex = ""

        # Client auth plugin
        client_auth = self.get_field(mysql_layer, "client_auth_plugin", "")
        if client_auth:
            session.client_auth_plugin = str(client_auth)

        # Schema/database
        schema = self.get_field(mysql_layer, "schema", "")
        if schema:
            session.schema = str(schema)

        session.state = "got_auth"

        # Build interaction details
        has_hash = bool(session.password_hash_hex)
        auth_type = session.client_auth_plugin or session.auth_plugin or "?"
        details: Dict[str, Any] = {
            "username": session.username,
            "has_hash": has_hash,
            "hash_len": len(session.password_hash_hex) // 2 if has_hash else 0,
            "auth_plugin": auth_type,
        }
        if session.schema:
            details["schema"] = session.schema

        detail_str = f"user={session.username}"
        if session.schema:
            detail_str += f" db={session.schema}"
        detail_str += f" auth={auth_type}"

        self._record_interaction(
            now,
            client_ip,
            server_ip,
            "request",
            "Login",
            details,
            f"Login {detail_str}",
            flow_id=flow_id,
            src_port=client_port,
            dst_port=server_port,
            stream_id=stream_id,
        )

        # Security alert for cleartext auth
        effective_plugin = session.client_auth_plugin or session.auth_plugin
        if effective_plugin in WEAK_AUTH_PLUGINS:
            alert = {
                "level": "fail",
                "category": "write_alert",
                "message": (
                    f"MYSQL CLEARTEXT: {client_ip} authenticating to {server_ip} "
                    f"using '{effective_plugin}' (credentials sent in cleartext)"
                ),
            }
            self._alerts.append(alert)

        # Update devices
        self._update_client_device(client_ip, server_ip, client_mac)
        self._update_server_device(server_ip, server_port, server_mac)

        self.logger.debug(
            f"MySQL: Login from {client_ip} user={session.username} "
            f"hash_len={len(session.password_hash_hex) // 2} auth={auth_type}"
        )

    # -------------------------------------------------------------------------
    # Query handling
    # -------------------------------------------------------------------------

    def _handle_query(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        client_mac: str,
        server_mac: str,
        mysql_layer: Any,
        fields: Dict[str, str],
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle MySQL query packet."""
        session = self._get_session(client_ip, client_port, server_ip, server_port)

        query = self.get_field(mysql_layer, "query", "")
        if not query:
            query = "?"
            self.logger.debug(f"Missing query text in command from {client_ip}")

        query_str = str(query)
        query_type = _classify_query(query_str)
        session.query_count += 1

        display_query = query_str

        details: Dict[str, Any] = {
            "query": query_str,
            "query_type": query_type,
        }

        self._record_interaction(
            now,
            client_ip,
            server_ip,
            "request",
            f"Query ({query_type})",
            details,
            f"Query: {display_query}",
            flow_id=flow_id,
            src_port=client_port,
            dst_port=server_port,
            stream_id=stream_id,
        )

        # Track write operations
        if query_type in (
            "Insert",
            "Update",
            "Delete",
            "Replace",
            "Create",
            "Drop",
            "Alter",
            "Truncate",
            "Grant",
            "Revoke",
        ):
            session.write_count += 1
            self._write_ops.append(
                {
                    "client": client_ip,
                    "server": server_ip,
                    "write_count": 1,
                    "query": query_str,
                }
            )

        # Security alert for dangerous queries
        if _is_dangerous_query(query_str):
            alert = {
                "level": "fail",
                "category": "write_alert",
                "message": (f"MYSQL DANGEROUS QUERY: {client_ip} -> {server_ip}: {display_query}"),
            }
            self._alerts.append(alert)

        # Update devices
        self._update_client_device(client_ip, server_ip, client_mac)
        self._update_server_device(server_ip, server_port, server_mac)

    # -------------------------------------------------------------------------
    # Command handling (non-query commands: Init DB, Quit, Ping, etc.)
    # -------------------------------------------------------------------------

    def _handle_command(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        client_mac: str,
        server_mac: str,
        mysql_layer: Any,
        fields: Dict[str, str],
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle MySQL command packet (non-query)."""
        session = self._get_session(client_ip, client_port, server_ip, server_port)

        cmd_raw = self.get_field(mysql_layer, "command", "")
        try:
            cmd_num = int(cmd_raw) if cmd_raw else 0
        except (ValueError, TypeError):
            cmd_num = 0

        cmd_name = MYSQL_COMMAND_NAMES.get(cmd_num, f"Command({cmd_num})")

        detail_str = ""
        details: Dict[str, Any] = {"command": cmd_num, "command_name": cmd_name}

        # T1 field: mysql.table_name -- table name for Field List commands
        table_name = self.get_field(mysql_layer, "table_name", "")
        if table_name:
            details["table_name"] = str(table_name)

        if cmd_num == MYSQL_CMD_INIT_DB:
            schema = self.get_field(mysql_layer, "schema", "")
            if schema:
                session.schema = str(schema)
                detail_str = f"db={schema}"
                details["schema"] = str(schema)
        elif cmd_num == MYSQL_CMD_FIELD_LIST:
            detail_str = f"table={table_name}" if table_name else ""
        elif cmd_num == MYSQL_CMD_QUIT:
            detail_str = ""
        elif cmd_num == MYSQL_CMD_CHANGE_USER:
            detail_str = "change_user"
            session.state = "init"  # Reset for re-auth

        self._record_interaction(
            now,
            client_ip,
            server_ip,
            "request",
            cmd_name,
            details,
            f"{cmd_name} {detail_str}".strip(),
            flow_id=flow_id,
            src_port=client_port,
            dst_port=server_port,
            stream_id=stream_id,
        )

        # Track dangerous commands
        if cmd_num in (MYSQL_CMD_SHUTDOWN, MYSQL_CMD_DROP_DB):
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "control_alert",
                    "message": f"MYSQL CONTROL: {client_ip} -> {server_ip}: {cmd_name}",
                }
            )

    # -------------------------------------------------------------------------
    # Response handling (OK / ERR / EOF)
    # -------------------------------------------------------------------------

    def _handle_response(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        mysql_layer: Any,
        fields: Dict[str, str],
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle MySQL response packet (OK / ERR / EOF)."""
        session = self._get_session(client_ip, client_port, server_ip, server_port)

        resp_raw = self.get_field(mysql_layer, "response_code", "")
        try:
            # response_code can be "0", "254", "255" or "0x00", "0xfe", "0xff"
            resp_code = int(str(resp_raw), 0) if resp_raw else -1
        except (ValueError, TypeError):
            resp_code = -1

        # T1 field: mysql.packet_number -- sequence ID (present on all responses)
        packet_number = self.get_field(mysql_layer, "packet_number", "")

        # T1 field: mysql.server_status -- status flags (present on OK/EOF)
        server_status_raw = self.get_field(mysql_layer, "server_status", "")
        server_status_flags = _decode_server_status(server_status_raw) if server_status_raw else ""

        if resp_code == MYSQL_RESP_OK:
            affected = self.get_field(mysql_layer, "affected_rows", "")
            warnings = self.get_field(mysql_layer, "warnings", "")

            # T1 field: mysql.insert_id -- last auto-increment ID from INSERT
            insert_id = self.get_field(mysql_layer, "insert_id", "")

            detail_parts = ["OK"]
            if affected and str(affected) != "0":
                detail_parts.append(f"rows={affected}")
            if insert_id and str(insert_id) != "0":
                detail_parts.append(f"insert_id={insert_id}")
            if warnings and str(warnings) != "0":
                detail_parts.append(f"warn={warnings}")
            detail_str = " ".join(detail_parts)

            details: Dict[str, Any] = {
                "response": "OK",
                "affected_rows": str(affected) if affected else "0",
                "warnings": str(warnings) if warnings else "0",
                "insert_id": str(insert_id) if insert_id else "0",
                "packet_number": str(packet_number) if packet_number else "",
                "server_status": str(server_status_raw) if server_status_raw else "",
                "server_status_flags": server_status_flags,
            }

            # Handle auth result
            if session.state == "got_auth":
                self._handle_auth_result(session, success=True)

            self._record_interaction(
                now,
                server_ip,
                client_ip,
                "response",
                "Response",
                details,
                detail_str,
                flow_id=flow_id,
                src_port=server_port,
                dst_port=client_port,
                stream_id=stream_id,
            )

        elif resp_code == MYSQL_RESP_ERR:
            error_code = self.get_field(mysql_layer, "error_code", "")
            error_msg = self.get_field(mysql_layer, "error_string", "")
            detail_parts = ["ERR"]
            if error_code:
                detail_parts.append(f"#{error_code}")
            if error_msg:
                msg_str = str(error_msg)
                detail_parts.append(msg_str)
            detail_str = " ".join(detail_parts)

            details = {
                "response": "ERR",
                "error_code": str(error_code) if error_code else "?",
                "error_string": str(error_msg) if error_msg else "",
                "packet_number": str(packet_number) if packet_number else "",
            }
            session.error_count += 1

            # Handle auth failure
            if session.state == "got_auth":
                self._handle_auth_result(session, success=False)

            self._record_interaction(
                now,
                server_ip,
                client_ip,
                "response",
                "Error",
                details,
                detail_str,
                flow_id=flow_id,
                src_port=server_port,
                dst_port=client_port,
                stream_id=stream_id,
            )

        elif resp_code == MYSQL_RESP_EOF:
            # EOF packet (result set boundary) -- record but not prominent
            details = {
                "response": "EOF",
                "packet_number": str(packet_number) if packet_number else "",
                "server_status": str(server_status_raw) if server_status_raw else "",
                "server_status_flags": server_status_flags,
            }
            self._record_interaction(
                now,
                server_ip,
                client_ip,
                "response",
                "EOF",
                details,
                "EOF",
                flow_id=flow_id,
                src_port=server_port,
                dst_port=client_port,
                stream_id=stream_id,
            )

    # -------------------------------------------------------------------------
    # Multi-PDU / fallback handlers
    # -------------------------------------------------------------------------

    @staticmethod
    def _get_ek_layer_dicts(layer) -> Optional[List[dict]]:
        """Return the raw list of dicts when an EK layer wraps multiple PDUs.

        In PyShark's EK mode, multi-PDU TCP segments store ``_fields_dict``
        as a *list* of dicts instead of a single dict.  PyShark's EkLayer
        cannot parse these and ``all_field_names`` returns None.  This helper
        detects that case and returns the list, or ``None`` for normal
        single-PDU layers.
        """
        try:
            fd = object.__getattribute__(layer, "_fields_dict")
            if isinstance(fd, list):
                return fd
        except AttributeError as e:
            logger.debug(f"MySQL EK layer _fields_dict access failed: {e}")
        return None

    def _handle_multi_pdu(
        self,
        now: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        ek_dicts: List[dict],
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Handle multi-PDU TCP segments (result sets, field lists, etc.).

        These packets contain multiple MySQL PDUs packed into one TCP segment.
        Common patterns:
        - Result set: column count + column defs + EOF + rows + EOF
        - Field list reply: column defs + EOF

        We extract column names, row data, and row count to record a useful
        "Result Set" interaction.
        """
        # Determine direction: result set data flows server -> client
        if self._is_server(src_ip, src_port):
            server_ip, server_port = src_ip, src_port
            client_ip, client_port = dst_ip, dst_port
        elif self._is_server(dst_ip, dst_port):
            server_ip, server_port = dst_ip, dst_port
            client_ip, client_port = src_ip, src_port
        else:
            # Heuristic: multi-PDU result sets are always server -> client
            server_ip, server_port = src_ip, src_port
            client_ip, client_port = dst_ip, dst_port

        num_fields = 0
        field_names: List[str] = []
        row_count = 0
        row_texts: List[str] = []
        pdu_count = len(ek_dicts)

        for fd in ek_dicts:
            if not isinstance(fd, dict):
                continue

            # Column count PDU
            nf = fd.get("mysql_mysql_num_fields")
            if nf is not None:
                try:
                    num_fields = int(str(nf))
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get num_fields: {e}")

            # Column definition PDU: extract field name
            fname = fd.get("mysql_mysql_field_name")
            if fname:
                field_names.append(str(fname))

            # Row data PDU
            rt = fd.get("mysql_mysql_row_text")
            if rt is not None:
                row_count += 1
                rt_str = str(rt)
                if len(rt_str) > 100:
                    rt_str = rt_str[:100] + "..."
                row_texts.append(rt_str)

        # Build description
        detail_parts = []
        if num_fields:
            detail_parts.append(f"cols={num_fields}")
        if field_names:
            names_str = ",".join(field_names[:5])
            if len(field_names) > 5:
                names_str += f"...+{len(field_names) - 5}"
            detail_parts.append(f"fields=[{names_str}]")
        if row_count:
            detail_parts.append(f"rows={row_count}")
        detail_str = " ".join(detail_parts) if detail_parts else f"{pdu_count} PDUs"

        details: Dict[str, Any] = {
            "pdu_count": pdu_count,
            "num_fields": num_fields,
            "field_names": field_names,
            "row_count": row_count,
        }
        if row_texts:
            details["row_preview"] = row_texts[:3]

        self._record_interaction(
            now,
            server_ip,
            client_ip,
            "response",
            "Result Set",
            details,
            f"Result Set {detail_str}",
            flow_id=flow_id,
            src_port=server_port,
            dst_port=client_port,
            stream_id=stream_id,
        )

    def _handle_unknown(
        self,
        now: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        flow_id: str,
        stream_id: str = "",
    ) -> None:
        """Fallback handler for unrecognized MySQL packets.

        Ensures no packet matching the display filter is silently dropped.
        Records a minimal interaction with direction heuristic.
        """
        # Determine likely direction
        if self._is_server(src_ip, src_port):
            direction = "response"
        else:
            direction = "request"

        self.logger.debug(
            f"Unrecognized MySQL packet from {src_ip}:{src_port} -> "
            f"{dst_ip}:{dst_port}, recording as {direction}"
        )

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            "MySQL Data",
            {},
            "MySQL Data",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    # -------------------------------------------------------------------------
    # Auth result
    # -------------------------------------------------------------------------

    def _handle_auth_result(self, session: MySQLSession, success: bool) -> None:
        """Handle authentication result and record credential."""
        session.state = "complete"

        if session.username and session.username != "?" and session.password_hash_hex:
            self._record_credential(session, success)

    def _record_credential(self, session: MySQLSession, success: Optional[bool]) -> None:
        """Record extracted MySQL credential."""
        # Check for duplicates
        for cred in self.credentials:
            if (
                cred.server_ip == session.server_ip
                and cred.client_ip == session.client_ip
                and cred.username == session.username
                and cred.password_hash == session.password_hash_hex
            ):
                # Update success status if we now know it
                if success is not None and cred.success is None:
                    cred.success = success
                return

        cred = MySQLCredential(
            username=session.username,
            password_hash=session.password_hash_hex,
            salt=session.salt_hex,
            salt2=session.salt2_hex,
            auth_plugin=session.client_auth_plugin
            or session.auth_plugin
            or "mysql_native_password",
            server_version=session.server_version,
            server_ip=session.server_ip,
            client_ip=session.client_ip,
            success=success,
            timestamp=datetime.now().isoformat(),
        )
        self.credentials.append(cred)

        self.logger.info(
            f"MySQL Credential: {session.username}@{session.server_ip} "
            f"hash={session.password_hash_hex} (success={success})"
        )

        # Update device with credential info
        self._update_device_credentials(session, success)

    # -------------------------------------------------------------------------
    # Session management
    # -------------------------------------------------------------------------

    def _get_session(
        self, client_ip: str, client_port: int, server_ip: str, server_port: int
    ) -> MySQLSession:
        """Get or create MySQL session tracker."""
        key = (client_ip, client_port, server_ip, server_port)
        if key not in self._sessions:
            self._sessions[key] = MySQLSession(
                client_ip=client_ip,
                server_ip=server_ip,
                client_port=client_port,
                server_port=server_port,
            )
        return self._sessions[key]

    def _get_server_stats(self, server_ip: str) -> Dict[str, Any]:
        """Get or create stats dict for a server IP."""
        if server_ip not in self._server_stats:
            self._server_stats[server_ip] = {
                "version": "",
                "auth_plugin": "",
                "query_count": 0,
                "write_count": 0,
                "login_count": 0,
                "error_count": 0,
            }
        return self._server_stats[server_ip]

    # -------------------------------------------------------------------------
    # Interaction table formatting
    # -------------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format a single MySQL interaction as protocol-specific table columns.

        Columns: Operation, Details, Result
        """
        d = ix.details
        op = ix.operation

        if op == "Greeting":
            version = d.get("version", "?")
            plugin = d.get("auth_plugin", "?")
            detail = f"v{version} plugin={plugin}"
        elif op == "Login":
            user = d.get("username", "?")
            schema = d.get("schema", "")
            auth = d.get("auth_plugin", "?")
            detail = f"user={user}"
            if schema:
                detail += f" db={schema}"
            detail += f" auth={auth}"
        elif op.startswith("Query"):
            query = d.get("query", "?")
            detail = query
        elif op == "Response":
            affected = d.get("affected_rows", "0")
            warnings = d.get("warnings", "0")
            parts = []
            if affected != "0":
                parts.append(f"rows={affected}")
            if warnings != "0":
                parts.append(f"warn={warnings}")
            detail = " ".join(parts) if parts else ""
        elif op == "Error":
            code = d.get("error_code", "?")
            msg = d.get("error_string", "")
            detail = f"#{code}"
            if msg:
                detail += f" {msg}"
        elif op == "EOF":
            detail = ""
        elif op == "Result Set":
            parts = []
            nf = d.get("num_fields")
            if nf:
                parts.append(f"cols={nf}")
            fnames = d.get("field_names")
            if fnames:
                names_str = ",".join(fnames[:5])
                if len(fnames) > 5:
                    names_str += f"...+{len(fnames) - 5}"
                parts.append(f"[{names_str}]")
            rc = d.get("row_count")
            if rc:
                parts.append(f"rows={rc}")
            detail = " ".join(parts) if parts else f"{d.get('pdu_count', '?')} PDUs"
        elif op == "MySQL Data":
            detail = ""
        elif op in MYSQL_COMMAND_NAMES.values():
            schema = d.get("schema", "")
            detail = f"db={schema}" if schema else ""
        else:
            detail = ix.summary or ""

        # Result column
        result = ""
        if ix.direction == "response":
            resp = d.get("response", "")
            if resp:
                result = resp
            elif op == "Greeting":
                result = d.get("version", "")
            elif op == "Result Set":
                rc = d.get("row_count", 0)
                result = f"{rc} row{'s' if rc != 1 else ''}" if rc else "metadata"

        return [op, detail, result]

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _update_server_device(
        self,
        server_ip: str,
        server_port: int = MYSQL_PORT,
        server_mac: str = "",
        *,
        version: str = "",
        auth_plugin: str = "",
        protocol_version: str = "",
        thread_id: str = "",
    ) -> None:
        """Update or create MySQL server device entry."""
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"mysql-server:{server_ip}"
        manufacturer = lookup_mac_vendor(server_mac) if server_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            mac=server_mac,
            name=f"MySQL Server ({server_ip})",
            device_type="MySQL Server",
            manufacturer=manufacturer if manufacturer != "Unknown" else "",
        )

        stats = self._get_server_stats(server_ip)
        if version:
            stats["version"] = version
        if auth_plugin:
            stats["auth_plugin"] = auth_plugin

        device.mysql_passive_data = {
            "role": "server",
            "server_version": stats.get("version", ""),
            "auth_plugin": stats.get("auth_plugin", ""),
            "protocol_version": protocol_version,
            "thread_id": thread_id,
            "port": server_port,
            "query_count": stats.get("query_count", 0),
            "write_count": stats.get("write_count", 0),
            "login_count": stats.get("login_count", 0),
            "error_count": stats.get("error_count", 0),
            "credentials": [],
            "protocol": "MySQL/TCP",
        }

    def _update_client_device(self, client_ip: str, server_ip: str, client_mac: str = "") -> None:
        """Update or create MySQL client device entry."""
        if not is_valid_discovered_ip(client_ip):
            return

        device_key = f"mysql-client:{client_ip}"
        manufacturer = lookup_mac_vendor(client_mac) if client_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            mac=client_mac,
            name=f"MySQL Client ({client_ip})",
            device_type="MySQL Client",
            manufacturer=manufacturer if manufacturer != "Unknown" else "",
        )
        if is_new:
            device.mysql_passive_data = {
                "role": "client",
                "credentials": [],
                "servers_accessed": [server_ip],
                "protocol": "MySQL/TCP",
            }
        else:
            if device.mysql_passive_data:
                servers = device.mysql_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.mysql_passive_data["servers_accessed"] = servers

    def _update_device_credentials(self, session: MySQLSession, success: Optional[bool]) -> None:
        """Update device entries with credential information."""
        server_key = f"mysql-server:{session.server_ip}"
        client_key = f"mysql-client:{session.client_ip}"

        cred_entry = {
            "username": session.username,
            "password_hash": session.password_hash_hex,
            "salt": session.salt_hex,
            "salt2": session.salt2_hex,
            "success": success,
            "timestamp": datetime.now().isoformat(),
        }

        with self._lock:
            # Update server
            if server_key in self.discovered_devices:
                device = self.discovered_devices[server_key]
                if device.mysql_passive_data:
                    creds = device.mysql_passive_data.get("credentials", [])
                    if not any(
                        c.get("username") == session.username
                        and c.get("password_hash") == session.password_hash_hex
                        for c in creds
                    ):
                        creds.append(cred_entry)
                        device.mysql_passive_data["credentials"] = creds

            # Update client
            if client_key in self.discovered_devices:
                device = self.discovered_devices[client_key]
                if device.mysql_passive_data:
                    creds = device.mysql_passive_data.get("credentials", [])
                    client_cred = {
                        "username": session.username,
                        "password_hash": session.password_hash_hex,
                        "server_ip": session.server_ip,
                        "success": success,
                        "timestamp": datetime.now().isoformat(),
                    }
                    if not any(
                        c.get("username") == session.username
                        and c.get("server_ip") == session.server_ip
                        for c in creds
                    ):
                        creds.append(client_cred)
                        device.mysql_passive_data["credentials"] = creds

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
                "protocol": "MySQL",
                "credential_type": "hash",
                "auth_method": cred.auth_plugin or "mysql_native_password",
                "username": cred.username,
                "password": cred.password_hash,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "salt": cred.salt,
                "salt2": cred.salt2,
                "server_version": cred.server_version,
                "success": cred.success,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]

    def get_hashes_summary(self) -> List[Dict[str, Any]]:
        """Get summary of extracted hashes for base class harvest().

        Returns list of dicts with keys expected by base class harvest():
        protocol, hash_type, username, domain, server_ip, client_ip,
        hashcat_format.
        """
        result = []
        for cred in self.credentials:
            if not cred.password_hash:
                continue
            result.append(
                {
                    "protocol": "MySQL",
                    "hash_type": cred.auth_plugin or "mysql_native_password",
                    "username": cred.username,
                    "domain": "",
                    "server_ip": cred.server_ip,
                    "client_ip": cred.client_ip,
                    "hashcat_format": cred.hashcat_format,
                }
            )
        return result

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get MySQL write operations for alert generation."""
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
                }
            pairs[key]["write_count"] += op.get("write_count", 1)

        return list(pairs.values())

    def get_hashcat_format(self) -> List[str]:
        """Get credentials in hashcat-compatible format.

        Returns:
            List of hash strings for hashcat mode 11200:
            $mysqlna$<salt_hex>*<hash_hex>
        """
        hashes = []
        for cred in self.credentials:
            hc = cred.hashcat_format
            if hc:
                hashes.append(hc)
        return hashes

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data.

        Delegates to base class for:
        - Credentials table (via get_credentials_summary)
        - Hashes table (via get_hashes_summary)
        - Interaction tables (via PROTOCOL_COLUMNS + _format_protocol_columns)
        - Write alerts (via get_write_operations)

        Appends custom security alerts (cleartext auth, weak plugins).
        """
        result = super().harvest()
        if not result:
            # If super returned empty but we have alerts, create structure
            if self._alerts:
                result = {"tables": [], "alerts": []}
            else:
                return {}

        # Append custom alerts
        alerts = result.get("alerts", [])
        for alert in self._alerts:
            # Avoid duplicate alerts
            if alert not in alerts:
                alerts.append(alert)
        result["alerts"] = alerts

        return result
