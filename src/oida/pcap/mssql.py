"""
MSSQL/TDS Passive Listener for credential and SQL operations extraction.

Passively captures SQL Server TDS traffic to extract:
- SQL Server usernames and passwords from TDS7 Login packets
- NTLM/SSPI authentication attempts
- SQL batch queries (SELECT, INSERT, UPDATE, DELETE, EXEC, etc.)
- RPC calls (sp_executesql, sp_prepexec, stored procedures)
- Server version info (from LoginAck tokens)
- Database names (from Login7 and EnvChange tokens)
- Pre-login exchange details (encryption settings, version)
- Error/info messages from server responses

TDS Protocol (Tabular Data Stream):
- Default port 1433
- Login7 packet (type 0x10) contains username, password (XOR obfuscated)
- SQL Batch packet (type 0x01) contains query text
- RPC packet (type 0x03) contains procedure name/ID and parameters
- Response packet (type 0x04) contains tokens: LoginAck, Error, Info, Done
- Pre-Login packet (type 0x12) contains version, encryption negotiation
- SSPI packet (type 0x11) contains NTLM/Kerberos auth data

tshark automatically decrypts TDS passwords during dissection.

Key tshark TDS fields:
- tds.type: packet type (1=SQL batch, 3=RPC, 4=response, 16=login7, 18=prelogin)
- tds.query: SQL batch query text
- tds.rpc.proc_id: well-known stored procedure ID (13=sp_prepexec, etc.)
- tds.rpc.name: stored procedure name
- tds.7login.username/password/databasename/appname/servername/clientname
- tds.7login.version: TDS version negotiated
- tds.loginack.progname/progversion/tdsversion: server version info
- tds.prelogin.option.version/encryption: pre-login negotiation
- tds.error.msgtext/number/class: server error messages
- tds.info.msgtext/number: server info messages
- tds.envchange.type/newvalue_string: environment change notifications
- tds.sspi: SSPI/NTLM authentication data
- tds.done.status: done token status flags
- tds.type_varbyte.data_string: RPC parameter string values (contains SQL text)

Reference: MS-TDS specification
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# TDS packet types
TDS_SQL_BATCH = 1  # SQL batch (query text)
TDS_RPC = 3  # Remote Procedure Call
TDS_RESPONSE = 4  # Response (tokens: LoginAck, Error, Info, Done, etc.)
TDS_ATTENTION = 6  # Attention (cancel)
TDS_BULK_LOAD = 7  # Bulk load data
TDS_FEDERATED_AUTH = 8  # Federated authentication token
TDS_TRANS_MGR = 14  # Transaction manager request
TDS_LOGIN7 = 16  # TDS7 Login packet (0x10)
TDS_SSPI = 17  # SSPI authentication (0x11)
TDS_PRELOGIN = 18  # Pre-login (0x12)

# Well-known stored procedure IDs (from MS-TDS)
RPC_PROC_IDS = {
    "1": "sp_cursor",
    "2": "sp_cursoropen",
    "3": "sp_cursorprepare",
    "4": "sp_cursorexecute",
    "5": "sp_cursorprepexec",
    "6": "sp_cursorunprepare",
    "7": "sp_cursorfetch",
    "8": "sp_cursoroption",
    "9": "sp_cursorclose",
    "10": "sp_executesql",
    "11": "sp_prepare",
    "12": "sp_execute",
    "13": "sp_prepexec",
    "14": "sp_prepexecrpc",
    "15": "sp_unprepare",
}

# TDS prelogin encryption values
PRELOGIN_ENCRYPTION = {
    "0": "OFF",
    "1": "ON",
    "2": "NOT_SUP",
    "3": "REQ",
    "4": "LOGIN_ONLY",
}

# SQL statement types for categorisation
SQL_WRITE_KEYWORDS = {"INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE", "MERGE"}
SQL_EXEC_KEYWORDS = {"EXEC", "EXECUTE"}
SQL_READ_KEYWORDS = {"SELECT"}
SQL_TRANSACTION_KEYWORDS = {"BEGIN", "COMMIT", "ROLLBACK", "SAVE"}
SQL_SET_KEYWORDS = {"SET", "USE", "GRANT", "REVOKE", "DENY"}


@dataclass
class MSSQLCredential:
    """Extracted MSSQL credential."""

    username: str
    password: str  # Decrypted password (tshark handles XOR decryption)
    database: str
    server_name: str
    client_ip: str
    server_ip: str
    app_name: str = ""
    client_name: str = ""
    timestamp: str = ""
    credential_type: str = "plaintext"
    success: Optional[bool] = None  # Updated by LoginAck response

    @property
    def auth_method(self) -> str:
        """Return auth method for scanner credential loop."""
        return "SQL Auth"


class MSSQLPassiveListener(PySharkListenerBase):
    """Passive MSSQL/TDS traffic listener for credential and SQL operations extraction.

    Captures all TDS traffic to extract:
    - SQL Server authentication credentials (Login7 packets)
    - SSPI/NTLM authentication attempts
    - SQL batch queries with statement type classification
    - RPC calls (stored procedures, sp_executesql, sp_prepexec)
    - Server version and configuration (LoginAck, EnvChange)
    - Pre-login encryption negotiation
    - Server error and info messages
    - Database changes (EnvChange)

    Uses PyShark/tshark for TDS dissection which automatically handles
    password decryption (XOR 0xA5 + nibble swap).

    Usage:
        listener = MSSQLPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for cred in listener.credentials:
            print(f"MSSQL: {cred.username}:{cred.password}@{cred.database}")
    """

    PROTOCOL_NAME = "mssql"
    DISPLAY_FILTER = "tds"
    REQUIRED_LAYERS = ("tds",)

    PROTOCOL_COLUMNS = ("type", "operation", "details")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize MSSQL passive listener.

        Args:
            interface: Network interface to capture on
            timeout: Capture timeout in seconds
            nxc_logger: Optional NXC-style logger
        """
        super().__init__(interface, timeout, nxc_logger)

        # Extracted credentials
        self.credentials: List[MSSQLCredential] = []

        # Credential dedup: (username, server_ip, password) tuples
        self._seen_creds: Set[Tuple[str, str, str]] = set()

        # Server info gathered from LoginAck tokens
        self._server_info: Dict[str, Dict[str, Any]] = {}  # server_ip -> info

        # Per-server stats
        self._server_stats: Dict[str, Dict[str, Any]] = {}  # server_ip -> stats

        # Write operations for alerts
        self._write_ops: List[Dict[str, Any]] = []

        # Track which flows have seen a login (for direction detection)
        self._login_flows: Dict[str, Dict[str, str]] = {}  # flow_id -> {client, server}

    def process_packet(self, packet) -> None:
        """Process TDS packet and extract credentials, queries, and metadata.

        Dispatches to handlers based on TDS packet type:
        - Type 1: SQL Batch (query text)
        - Type 3: RPC (stored procedure calls)
        - Type 4: Response (LoginAck, Error, Info, Done tokens)
        - Type 16: Login7 (credentials)
        - Type 17: SSPI (NTLM/Kerberos auth)
        - Type 18: Pre-Login (version, encryption negotiation)
        """
        if not hasattr(packet, "tds"):
            return

        tds_layer = packet.tds
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        fields = self.get_all_fields(tds_layer)

        # Handle multi-PDU EK packets that may have no fields at all
        if not fields:
            self.logger.debug(
                f"TDS packet from {src_ip} -> {dst_ip} has no parseable fields (multi-PDU?)"
            )
            return

        now = self._get_timestamp()
        stream_id = self.get_stream_id(packet)

        # Determine packet type
        tds_type_str = fields.get("tds.type", "")
        if not tds_type_str:
            tds_type_str = self.get_field(tds_layer, "type", "")
        if not tds_type_str:
            # Try the layer text attribute for type info
            text_val = getattr(tds_layer, "text", None)
            if text_val:
                texts = text_val if isinstance(text_val, list) else [text_val]
                for t in texts:
                    t_lower = str(t).lower()
                    if "sql batch" in t_lower:
                        tds_type_str = "1"
                        break
                    elif "remote procedure call" in t_lower:
                        tds_type_str = "3"
                        break
                    elif "login" in t_lower and "7" in t_lower:
                        tds_type_str = "16"
                        break
                    elif "pre-login" in t_lower:
                        tds_type_str = "18"
                        break

        # In EK mode, multi-PDU packets may return comma-separated types like "1,3"
        # Use the first type value for dispatch
        first_type_str = tds_type_str.split(",")[0].strip() if tds_type_str else ""
        try:
            tds_type = int(first_type_str)
        except (ValueError, TypeError):
            self.logger.debug(
                f"Could not parse TDS type '{tds_type_str}' from {src_ip} -> {dst_ip}"
            )
            return

        # Extract packet-level status byte (tds.status)
        # This covers EOM, ignore, event notification, and reset flags.
        _tds_status = fields.get("tds.status", "") or self.get_field(tds_layer, "status", "")

        # Dispatch by packet type
        if tds_type == TDS_LOGIN7:
            self._handle_login7(
                now,
                src_ip,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                fields,
                flow_id,
                tds_layer,
                src_port=src_port,
                stream_id=stream_id,
            )
        elif tds_type == TDS_SQL_BATCH:
            self._handle_sql_batch(
                now,
                src_ip,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                fields,
                flow_id,
                tds_layer,
                src_port=src_port,
                stream_id=stream_id,
            )
        elif tds_type == TDS_RPC:
            self._handle_rpc(
                now,
                src_ip,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                fields,
                flow_id,
                tds_layer,
                src_port=src_port,
                stream_id=stream_id,
            )
        elif tds_type == TDS_RESPONSE:
            self._handle_response(
                now,
                src_ip,
                dst_ip,
                src_port,
                src_mac,
                dst_mac,
                fields,
                flow_id,
                tds_layer,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif tds_type == TDS_PRELOGIN:
            self._handle_prelogin(
                now,
                src_ip,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                fields,
                flow_id,
                tds_layer,
                src_port=src_port,
                stream_id=stream_id,
            )
        elif tds_type == TDS_SSPI:
            self._handle_sspi(
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
        elif tds_type == TDS_ATTENTION:
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "Attention",
                {"tds_type": tds_type},
                "TDS Attention (cancel)",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

    # -------------------------------------------------------------------------
    # Login7 handling (credentials)
    # -------------------------------------------------------------------------

    def _handle_login7(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        fields: Dict[str, str],
        flow_id: str,
        tds_layer: Any,
        src_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle TDS7 Login packet -- extract credentials."""
        # Extract login fields with explicit get_field() calls for audit visibility,
        # falling back to _get_login_field() for EK-mode name variations.
        username = (
            fields.get("tds.7login.username", "")
            or self.get_field(tds_layer, "7login_username", "")
            or self._get_login_field(fields, tds_layer, "username")
        )
        password = (
            fields.get("tds.7login.password", "")
            or self.get_field(tds_layer, "7login_password", "")
            or self._get_login_field(fields, tds_layer, "password")
        )
        client_name = (
            fields.get("tds.7login.clientname", "")
            or self.get_field(tds_layer, "7login_clientname", "")
            or self._get_login_field(fields, tds_layer, "clientname")
            or ""
        )
        app_name = (
            fields.get("tds.7login.appname", "")
            or self.get_field(tds_layer, "7login_appname", "")
            or self._get_login_field(fields, tds_layer, "appname")
            or ""
        )
        server_name = (
            fields.get("tds.7login.servername", "")
            or self.get_field(tds_layer, "7login_servername", "")
            or self._get_login_field(fields, tds_layer, "servername")
            or ""
        )
        database = (
            fields.get("tds.7login.databasename", "")
            or self.get_field(tds_layer, "7login_databasename", "")
            or self._get_login_field(fields, tds_layer, "databasename")
            or ""
        )
        library = (
            fields.get("tds.7login.libraryname", "")
            or self.get_field(tds_layer, "7login_libraryname", "")
            or self._get_login_field(fields, tds_layer, "libraryname")
            or ""
        )

        # TDS version from login
        tds_version = fields.get("tds.7login.version", "") or self.get_field(
            tds_layer, "7login_version", ""
        )

        # Additional login fields (client version, PID, connection ID)
        client_version = (
            fields.get("tds.7login.client_version", "")
            or self.get_field(tds_layer, "7login_client_version", "")
            or ""
        )
        client_pid = (
            fields.get("tds.7login.client_pid", "")
            or self.get_field(tds_layer, "7login_client_pid", "")
            or ""
        )
        connection_id = (
            fields.get("tds.7login.connection_id", "")
            or self.get_field(tds_layer, "7login_connection_id", "")
            or ""
        )

        if not username:
            username = "?"
            self.logger.debug(f"Missing username in Login7 from {src_ip} -> {dst_ip}")

        # Record the login flow direction
        self._login_flows[flow_id] = {"client": src_ip, "server": dst_ip}

        # Build interaction details
        details: Dict[str, Any] = {
            "username": username,
            "database": database,
            "app_name": app_name,
            "client_name": client_name,
            "server_name": server_name,
            "library": library,
            "tds_version": tds_version,
        }
        if client_version:
            details["client_version"] = client_version
        if client_pid:
            details["client_pid"] = client_pid
        if connection_id:
            details["connection_id"] = connection_id

        has_password = bool(password)
        summary = f"Login7 user={username}"
        if database:
            summary += f" db={database}"
        if app_name:
            summary += f" app={app_name}"
        if not has_password:
            summary += " (SSPI/integrated)"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "Login7",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Extract credential if password present (SQL auth, not integrated/SSPI)
        if has_password:
            cred_key = (username, dst_ip, password)
            if cred_key not in self._seen_creds:
                self._seen_creds.add(cred_key)
                cred = MSSQLCredential(
                    username=username,
                    password=password,
                    database=database,
                    server_name=server_name,
                    client_ip=src_ip,
                    server_ip=dst_ip,
                    app_name=app_name,
                    client_name=client_name,
                    timestamp=now,
                )
                self.credentials.append(cred)
                self.logger.info(
                    f"MSSQL credential: {username}:{password} db={database} ({src_ip} -> {dst_ip})"
                )

        # Track both endpoint devices
        self._update_client_device(src_ip, dst_ip, src_mac)
        self._update_server_device(dst_ip, dst_port, dst_mac, server_name=server_name)

    # Mapping of login field suffixes to get_field attribute names.
    # Listed explicitly so the audit tool can detect them as extracted fields.
    _LOGIN_FIELD_ATTRS = {
        "username": "7login_username",
        "password": "7login_password",
        "clientname": "7login_clientname",
        "appname": "7login_appname",
        "servername": "7login_servername",
        "databasename": "7login_databasename",
        "libraryname": "7login_libraryname",
        "client_version": "7login_client_version",
        "client_pid": "7login_client_pid",
        "connection_id": "7login_connection_id",
    }

    def _get_login_field(self, fields: Dict[str, str], tds_layer: Any, field_name: str) -> str:
        """Get TDS7 login field trying multiple naming conventions.

        Handles both XML-mode and EK-mode field names consistently.

        Args:
            fields: Dict from get_all_fields() with dotted keys like "tds.7login.username"
            tds_layer: PyShark TDS layer for direct attribute access
            field_name: Field name suffix (e.g., 'username', 'password')

        Returns:
            Field value or empty string
        """
        # Try dotted names from get_all_fields (both XML and EK mode)
        dotted_patterns = [
            f"tds.7login.{field_name}",
            f"tds.7login_{field_name}",
        ]
        for pattern in dotted_patterns:
            val = fields.get(pattern, "")
            if val:
                return str(val)

        # Try direct attribute access on the layer (pyshark normalises to underscores)
        attr_name = self._LOGIN_FIELD_ATTRS.get(field_name, f"7login_{field_name}")
        for pattern in (f"_{attr_name}", attr_name):
            val = self.get_field(tds_layer, pattern)
            if val:
                return str(val)

        # Search all fields for fuzzy match
        for key, value in fields.items():
            if field_name in key.lower() and "7login" in key.lower():
                return str(value)

        return ""

    @staticmethod
    def _normalize_sql(text: str) -> str:
        """Collapse whitespace in SQL text from tshark (newlines become spaces)."""
        return re.sub(r"\s+", " ", text).strip()

    # -------------------------------------------------------------------------
    # SQL Batch handling
    # -------------------------------------------------------------------------

    def _handle_sql_batch(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        fields: Dict[str, str],
        flow_id: str,
        tds_layer: Any,
        src_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle TDS SQL Batch packet -- extract query text."""
        query = fields.get("tds.query", "") or self.get_field(tds_layer, "query", "")
        if not query:
            query = "?"
            self.logger.debug(f"Missing query text in SQL Batch from {src_ip} -> {dst_ip}")
        else:
            query = self._normalize_sql(query)

        # Classify SQL statement type
        sql_type = self._classify_sql(query)

        # Transaction descriptor from ALL_HEADERS
        trans_descr = fields.get("tds.all_headers.header.trans_descr", "") or self.get_field(
            tds_layer, "all_headers_header_trans_descr", ""
        )

        details: Dict[str, Any] = {
            "query": query,
            "sql_type": sql_type,
        }
        if trans_descr:
            details["transaction_descriptor"] = trans_descr

        summary = f"SQL Batch: {query}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "SQL Batch",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Alert on write operations
        if sql_type in ("WRITE", "DDL"):
            self._write_ops.append(
                {
                    "client": src_ip,
                    "server": dst_ip,
                    "operation": f"SQL {sql_type}",
                    "query": query,
                    "timestamp": now,
                }
            )

        # Update stats
        stats = self._get_server_stats(dst_ip)
        stats["query_count"] = stats.get("query_count", 0) + 1
        stats.setdefault("sql_types", set()).add(sql_type)

        # Track devices
        self._update_client_device(src_ip, dst_ip, src_mac)
        self._update_server_device(dst_ip, dst_port, dst_mac)

    # -------------------------------------------------------------------------
    # RPC handling
    # -------------------------------------------------------------------------

    def _handle_rpc(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        fields: Dict[str, str],
        flow_id: str,
        tds_layer: Any,
        src_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle TDS RPC packet -- extract procedure name and parameters."""
        # Get procedure name (named or by well-known ID)
        proc_name = fields.get("tds.rpc.name", "") or self.get_field(tds_layer, "rpc_name", "")
        proc_id = fields.get("tds.rpc.proc_id", "") or self.get_field(tds_layer, "rpc_proc_id", "")
        rpc_name_length = fields.get("tds.rpc.name_length", "") or self.get_field(
            tds_layer, "rpc_name_length", ""
        )

        # Resolve well-known procedure ID to name
        if proc_id and not proc_name:
            proc_name = RPC_PROC_IDS.get(str(proc_id), f"proc_id={proc_id}")
        elif proc_id:
            well_known = RPC_PROC_IDS.get(str(proc_id), "")
            if well_known:
                proc_name = well_known

        if not proc_name:
            # Check if name_length is 0xFFFF which indicates well-known stored proc
            if rpc_name_length == "65535":
                proc_name = RPC_PROC_IDS.get(str(proc_id), f"unknown(id={proc_id})")
            else:
                proc_name = "?"
                self.logger.debug(f"Missing proc name in RPC from {src_ip} -> {dst_ip}")

        # Extract RPC parameter metadata
        param_name = fields.get("tds.rpc.parameter.name", "") or self.get_field(
            tds_layer, "rpc_parameter_name", ""
        )
        param_status = fields.get("tds.rpc.parameter.status", "") or self.get_field(
            tds_layer, "rpc_parameter_status", ""
        )

        # Collation LCID on the parameter type_info identifies the locale
        # (e.g. 1033 / 0x409 == en-US). It is a stable server-side attribute.
        collation_lcid = fields.get("tds.type_info.collation.lcid", "") or self.get_field(
            tds_layer, "type_info_collation_lcid", ""
        )

        # Extract parameter string values (contains SQL for sp_executesql/sp_prepexec).
        # get_all_fields / get_field join lists with ",", which destroys SQL
        # containing commas.  Read the raw EK attribute to preserve list structure.
        raw_params = getattr(tds_layer, "type_varbyte_data_string", None)
        if raw_params is not None:
            raw_params = self._resolve_value(raw_params, None)
        if not raw_params:
            raw_params = fields.get("tds.type_varbyte.data_string", "")

        # Extract embedded SQL from parameters
        embedded_sql = ""
        if raw_params:
            # EK mode returns a list of parameter values; legacy/flattened mode
            # returns a single string.  Use list elements directly to avoid
            # splitting on commas inside SQL text.
            if isinstance(raw_params, list):
                parts = [str(self._resolve_value(v, "")) for v in raw_params]
            else:
                parts = [str(raw_params)]
            for part in parts:
                part = part.strip()
                # Heuristic: SQL statements are longer and contain SQL keywords
                upper = part.upper().strip()
                if any(
                    upper.startswith(kw)
                    for kw in (
                        "SELECT",
                        "INSERT",
                        "UPDATE",
                        "DELETE",
                        "EXEC",
                        "CREATE",
                        "ALTER",
                        "DROP",
                        "BEGIN",
                        "DECLARE",
                        "WITH",
                    )
                ):
                    embedded_sql = self._normalize_sql(part)
                    break

        details: Dict[str, Any] = {
            "proc_name": proc_name,
            "proc_id": proc_id or "",
        }
        if param_name:
            details["parameter_name"] = param_name
        if param_status:
            details["parameter_status"] = param_status
        if collation_lcid:
            details["collation_lcid"] = collation_lcid
            # First LCID seen is a stable server locale attribute.
            server_info = self._get_server_info(dst_ip)
            if not server_info.get("collation_lcid"):
                server_info["collation_lcid"] = str(collation_lcid).split(",")[0].strip()
        if embedded_sql:
            details["embedded_sql"] = embedded_sql

        summary = f"RPC: {proc_name}"
        if embedded_sql:
            summary += f" ({embedded_sql})"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "RPC",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Check for write operations in embedded SQL
        if embedded_sql:
            sql_type = self._classify_sql(embedded_sql)
            if sql_type in ("WRITE", "DDL"):
                self._write_ops.append(
                    {
                        "client": src_ip,
                        "server": dst_ip,
                        "operation": f"RPC {proc_name} ({sql_type})",
                        "query": embedded_sql,
                        "timestamp": now,
                    }
                )

        # Update stats
        stats = self._get_server_stats(dst_ip)
        stats["rpc_count"] = stats.get("rpc_count", 0) + 1
        stats.setdefault("procedures", set()).add(proc_name)

        # Track devices
        self._update_client_device(src_ip, dst_ip, src_mac)
        self._update_server_device(dst_ip, dst_port, dst_mac)

    # -------------------------------------------------------------------------
    # Response handling (LoginAck, Error, Info, EnvChange, Done)
    # -------------------------------------------------------------------------

    def _handle_response(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        src_mac: str,
        dst_mac: str,
        fields: Dict[str, str],
        flow_id: str,
        tds_layer: Any,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle TDS Response packet -- extract LoginAck, errors, info, EnvChange."""
        # Check for LoginAck token (server version info)
        loginack_progname = fields.get("tds.loginack.progname", "") or self.get_field(
            tds_layer, "loginack_progname", ""
        )
        loginack_version = fields.get("tds.loginack.progversion", "") or self.get_field(
            tds_layer, "loginack_progversion", ""
        )
        loginack_tdsversion = fields.get("tds.loginack.tdsversion", "") or self.get_field(
            tds_layer, "loginack_tdsversion", ""
        )

        if loginack_progname or loginack_version:
            self._handle_loginack(
                now,
                src_ip,
                dst_ip,
                src_port,
                src_mac,
                dst_mac,
                loginack_progname,
                loginack_version,
                loginack_tdsversion,
                fields,
                flow_id,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Check for Error tokens
        error_msg = fields.get("tds.error.msgtext", "") or self.get_field(
            tds_layer, "error_msgtext", ""
        )
        error_number = fields.get("tds.error.number", "") or self.get_field(
            tds_layer, "error_number", ""
        )
        error_class = fields.get("tds.error.class", "") or self.get_field(
            tds_layer, "error_class", ""
        )

        if error_msg or error_number:
            details: Dict[str, Any] = {
                "error_number": error_number or "?",
                "severity": error_class or "?",
                "message": error_msg if error_msg else "?",
            }

            error_server = fields.get("tds.error.servername", "") or self.get_field(
                tds_layer, "error_servername", ""
            )
            if error_server:
                details["server_name"] = error_server

            summary = f"Error {error_number}: {error_msg}" if error_msg else f"Error {error_number}"

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "Error",
                details,
                summary,
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Check for Info tokens
        info_msg = fields.get("tds.info.msgtext", "") or self.get_field(
            tds_layer, "info_msgtext", ""
        )
        info_number = fields.get("tds.info.number", "") or self.get_field(
            tds_layer, "info_number", ""
        )

        if info_msg:
            details = {
                "info_number": info_number or "",
                "message": info_msg,
            }

            info_server = fields.get("tds.info.servername", "") or self.get_field(
                tds_layer, "info_servername", ""
            )
            if info_server:
                details["server_name"] = info_server
                # Store server name from info messages
                server_info = self._get_server_info(src_ip)
                if not server_info.get("server_name"):
                    server_info["server_name"] = info_server

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "Info",
                details,
                f"Info: {info_msg}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Check for EnvChange tokens (database change, language, etc.)
        envchange_type = fields.get("tds.envchange.type", "") or self.get_field(
            tds_layer, "envchange_type", ""
        )
        envchange_newval = fields.get("tds.envchange.newvalue_string", "") or self.get_field(
            tds_layer, "envchange_newvalue_string", ""
        )

        if envchange_type and envchange_newval:
            env_type_name = self._envchange_type_name(envchange_type)
            details = {
                "change_type": env_type_name,
                "new_value": envchange_newval,
            }
            oldval = fields.get("tds.envchange.oldvalue_string", "") or self.get_field(
                tds_layer, "envchange_oldvalue_string", ""
            )
            if oldval:
                details["old_value"] = oldval

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "EnvChange",
                details,
                f"EnvChange: {env_type_name}={envchange_newval}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

            # Track database name from EnvChange
            if envchange_type in ("1", "4"):  # Database or Language
                server_info = self._get_server_info(src_ip)
                if envchange_type == "1":
                    server_info["current_database"] = envchange_newval

        # Check for Done token status
        done_status = fields.get("tds.done.status", "") or self.get_field(
            tds_layer, "done_status", ""
        )
        doneproc_status = fields.get("tds.doneproc.status", "") or self.get_field(
            tds_layer, "doneproc_status", ""
        )
        doneinproc_status = fields.get("tds.doneinproc.status", "") or self.get_field(
            tds_layer, "doneinproc_status", ""
        )

        if done_status or doneproc_status or doneinproc_status:
            done_details: Dict[str, Any] = {}
            if done_status:
                done_details["done_status"] = done_status
            if doneproc_status:
                done_details["doneproc_status"] = doneproc_status
            if doneinproc_status:
                done_details["doneinproc_status"] = doneinproc_status

            # Only record Done interaction when no higher-level token already covered
            if not (
                loginack_progname
                or loginack_version
                or error_msg
                or error_number
                or info_msg
                or (envchange_type and envchange_newval)
            ):
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Done",
                    done_details,
                    f"Done status={done_status or doneproc_status or doneinproc_status}",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )

        # Check for ReturnStatus token (stored procedure return value)
        return_status = fields.get("tds.returnstatus.value", "") or self.get_field(
            tds_layer, "returnstatus_value", ""
        )
        if return_status:
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "ReturnStatus",
                {"return_value": return_status},
                f"ReturnStatus value={return_status}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Check for ColMetadata token (result set column names)
        col_names = fields.get("tds.colmetadata.colname", "") or self.get_field(
            tds_layer, "colmetadata_colname", ""
        )
        if col_names:
            col_details: Dict[str, Any] = {"column_names": col_names}

            # User-defined type tag per column (nonzero => UDT in use).
            usertype = fields.get("tds.colmetadata.usertype", "") or self.get_field(
                tds_layer, "colmetadata_usertype", ""
            )
            if usertype:
                col_details["usertype"] = usertype

            # Collation charset id on the column metadata (Windows/SQL collation byte).
            charset_id = fields.get("tds.colmetadata.collate_charset_id", "") or self.get_field(
                tds_layer, "colmetadata_collate_charset_id", ""
            )
            if charset_id:
                col_details["collate_charset_id"] = charset_id

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "ColMetadata",
                col_details,
                f"ColMetadata columns={col_names}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Track server device
        self._update_server_device(src_ip, src_port, src_mac)

    def _handle_loginack(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        src_mac: str,
        dst_mac: str,
        progname: str,
        progversion: str,
        tdsversion: str,
        fields: Dict[str, str],
        flow_id: str,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle LoginAck token -- extract server version and update credential status."""
        server_info = self._get_server_info(src_ip)
        server_info["program_name"] = progname
        server_info["program_version"] = progversion
        server_info["tds_version"] = tdsversion

        details: Dict[str, Any] = {
            "program_name": progname or "?",
            "program_version": progversion or "?",
            "tds_version": tdsversion or "?",
        }

        summary = f"LoginAck: {progname}"
        if progversion:
            summary += f" v{progversion}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "LoginAck",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Update credential success status (LoginAck means success)
        flow_info = self._login_flows.get(flow_id, {})
        if flow_info:
            client_ip = flow_info.get("client", "")
            for cred in self.credentials:
                if (
                    cred.server_ip == src_ip
                    and cred.client_ip == client_ip
                    and cred.success is None
                ):
                    cred.success = True
                    self.logger.debug(
                        f"MSSQL credential updated: {cred.username}@{src_ip} success=True"
                    )
                    break

        # Update server device with version info
        self._update_server_device(
            src_ip,
            src_port,
            src_mac,
            server_name=progname,
            version=progversion,
        )

    # -------------------------------------------------------------------------
    # Pre-Login handling
    # -------------------------------------------------------------------------

    def _handle_prelogin(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        fields: Dict[str, str],
        flow_id: str,
        tds_layer: Any = None,
        src_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle TDS Pre-Login packet -- extract version and encryption settings."""
        version = fields.get("tds.prelogin.option.version", "") or self.get_field(
            tds_layer, "prelogin_option_version", ""
        )
        encryption = fields.get("tds.prelogin.option.encryption", "") or self.get_field(
            tds_layer, "prelogin_option_encryption", ""
        )
        mars = fields.get("tds.prelogin.option.mars", "") or self.get_field(
            tds_layer, "prelogin_option_mars", ""
        )
        instopt = fields.get("tds.prelogin.option.instopt", "") or ""
        threadid = fields.get("tds.prelogin.option.threadid", "") or self.get_field(
            tds_layer, "prelogin_option_threadid", ""
        )

        encryption_name = PRELOGIN_ENCRYPTION.get(encryption, encryption) if encryption else ""

        details: Dict[str, Any] = {}
        if version:
            details["version"] = version
        if encryption_name:
            details["encryption"] = encryption_name
        if mars:
            details["mars"] = mars
        if instopt:
            details["instance"] = instopt
        if threadid:
            details["threadid"] = threadid

        summary_parts = []
        if version:
            summary_parts.append(f"v={version}")
        if encryption_name:
            summary_parts.append(f"encrypt={encryption_name}")
        if mars:
            mars_str = "ON" if mars == "1" else "OFF"
            summary_parts.append(f"MARS={mars_str}")

        summary = "Pre-Login " + " ".join(summary_parts) if summary_parts else "Pre-Login"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "Pre-Login",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track devices (prelogin goes client->server)
        self._update_client_device(src_ip, dst_ip, src_mac)
        self._update_server_device(dst_ip, dst_port, dst_mac)

        # Alert if encryption is OFF
        if encryption_name == "OFF":
            self.logger.debug(f"MSSQL Pre-Login: encryption OFF from {src_ip} -> {dst_ip}")

    # -------------------------------------------------------------------------
    # SSPI/NTLM handling
    # -------------------------------------------------------------------------

    def _handle_sspi(
        self,
        now: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        fields: Dict[str, str],
        flow_id: str,
        src_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle TDS SSPI packet -- detect NTLM/Kerberos authentication."""
        sspi_buffer = fields.get("tds.sspi.buffer", "") or ""

        # NTLM detection via co-present ntlmssp layer is handled by the NTLM
        # listener. Here we just record the SSPI interaction.
        details: Dict[str, Any] = {
            "auth_type": "SSPI",
        }
        if sspi_buffer:
            # First few bytes can identify the auth mechanism
            buf = sspi_buffer.replace(":", "").upper()
            if buf.startswith("4E544C4D53535000"):  # "NTLMSSP\0"
                details["auth_type"] = "SSPI/NTLM"
            elif buf.startswith("6082") or buf.startswith("6182"):
                details["auth_type"] = "SSPI/Kerberos"

        # Track the flow as a login flow
        self._login_flows[flow_id] = {"client": src_ip, "server": dst_ip}

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "SSPI",
            details,
            f"{details['auth_type']} Authentication",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track devices
        self._update_client_device(src_ip, dst_ip, src_mac)
        self._update_server_device(dst_ip, dst_port, dst_mac)

    # -------------------------------------------------------------------------
    # Interaction table formatting
    # -------------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format a single MSSQL interaction as protocol-specific table columns.

        Columns: Type, Operation, Details
        """
        d = ix.details
        op = ix.operation

        # Build details string based on operation type
        if op == "Login7":
            username = d.get("username", "?")
            database = d.get("database", "")
            app = d.get("app_name", "")
            detail = f"user={username}"
            if database:
                detail += f" db={database}"
            if app:
                detail += f" app={app}"
        elif op == "SQL Batch":
            query = d.get("query", "?")
            sql_type = d.get("sql_type", "")
            detail = f"[{sql_type}] {query}" if sql_type else query
        elif op == "RPC":
            proc = d.get("proc_name", "?")
            embedded = d.get("embedded_sql", "")
            detail = proc
            if embedded:
                detail += f": {embedded}"
        elif op == "LoginAck":
            prog = d.get("program_name", "?")
            ver = d.get("program_version", "")
            detail = f"{prog} v{ver}" if ver else prog
        elif op == "Error":
            err_num = d.get("error_number", "?")
            msg = d.get("message", "")
            sev = d.get("severity", "")
            detail = f"#{err_num}"
            if sev:
                detail += f" sev={sev}"
            if msg:
                detail += f" {msg}"
        elif op == "Info":
            msg = d.get("message", "")
            detail = msg if msg else "?"
        elif op == "EnvChange":
            change_type = d.get("change_type", "?")
            new_val = d.get("new_value", "?")
            detail = f"{change_type}={new_val}"
        elif op == "Pre-Login":
            parts = []
            if d.get("version"):
                parts.append(f"v={d['version']}")
            if d.get("encryption"):
                parts.append(f"encrypt={d['encryption']}")
            detail = " ".join(parts) if parts else "?"
        elif op == "SSPI":
            detail = d.get("auth_type", "SSPI")
        elif op == "Attention":
            detail = "Cancel query"
        elif op == "Done":
            status_val = (
                d.get("done_status") or d.get("doneproc_status") or d.get("doneinproc_status", "?")
            )
            detail = f"status={status_val}"
        elif op == "ReturnStatus":
            detail = f"value={d.get('return_value', '?')}"
        elif op == "ColMetadata":
            cols = d.get("column_names", "?")
            detail = str(cols)
        else:
            detail = ix.summary if ix.summary else "?"

        # The "Type" column shows the TDS packet type, the "Operation" column
        # shows the specific sub-operation within that type.
        pkt_type = op  # default: use operation name as type
        if op in ("SQL Batch",):
            pkt_type = "SQL Batch"
        elif op in ("RPC",):
            pkt_type = "RPC"
        elif op in ("Login7",):
            pkt_type = "Login7"
        elif op in (
            "LoginAck",
            "Error",
            "Info",
            "EnvChange",
            "Done",
            "ReturnStatus",
            "ColMetadata",
        ):
            pkt_type = "Response"
        elif op in ("Pre-Login",):
            pkt_type = "Pre-Login"
        elif op in ("SSPI",):
            pkt_type = "SSPI"
        elif op in ("Attention",):
            pkt_type = "Attention"

        return [pkt_type, op, detail]

    # -------------------------------------------------------------------------
    # SQL classification
    # -------------------------------------------------------------------------

    @staticmethod
    def _classify_sql(query: str) -> str:
        """Classify SQL statement type from query text.

        Returns one of: READ, WRITE, DDL, EXEC, TRANSACTION, SET, OTHER
        """
        stripped = query.strip()
        if not stripped:
            return "OTHER"

        # Get first keyword (skip leading whitespace and comments)
        first_word = ""
        for line in stripped.split("\n"):
            line = line.strip()
            if line.startswith("--") or not line:
                continue
            # Skip block comments
            if line.startswith("/*"):
                continue
            first_word = line.split()[0].upper().rstrip(";") if line.split() else ""
            break

        if not first_word:
            return "OTHER"

        if first_word in SQL_WRITE_KEYWORDS:
            return "WRITE" if first_word in {"INSERT", "UPDATE", "DELETE", "MERGE"} else "DDL"
        if first_word in SQL_EXEC_KEYWORDS:
            return "EXEC"
        if first_word in SQL_READ_KEYWORDS:
            return "READ"
        if first_word in SQL_TRANSACTION_KEYWORDS:
            return "TRANSACTION"
        if first_word in SQL_SET_KEYWORDS:
            return "SET"

        return "OTHER"

    # -------------------------------------------------------------------------
    # EnvChange type name resolution
    # -------------------------------------------------------------------------

    @staticmethod
    def _envchange_type_name(type_val: str) -> str:
        """Convert EnvChange type numeric value to descriptive name."""
        names = {
            "1": "Database",
            "2": "Language",
            "3": "CharacterSet",
            "4": "PacketSize",
            "5": "UnicodeSortLocal",
            "6": "UnicodeSortComparison",
            "7": "Collation",
            "8": "BeginTransaction",
            "9": "CommitTransaction",
            "10": "RollbackTransaction",
            "11": "EnlistDTCTransaction",
            "12": "DefectTransaction",
            "13": "RealTimeLogShipping",
            "15": "PromoteTransaction",
            "16": "TransactionManagerAddr",
            "17": "TransactionEnded",
            "18": "ResetCompletion",
            "19": "UserInstance",
            "20": "RoutingInfo",
        }
        return names.get(type_val, f"type={type_val}")

    # -------------------------------------------------------------------------
    # Helper methods
    # -------------------------------------------------------------------------

    def _get_server_info(self, server_ip: str) -> Dict[str, Any]:
        """Get or create server info dict."""
        if server_ip not in self._server_info:
            self._server_info[server_ip] = {}
        return self._server_info[server_ip]

    def _get_server_stats(self, server_ip: str) -> Dict[str, Any]:
        """Get or create stats dict for a server IP."""
        if server_ip not in self._server_stats:
            self._server_stats[server_ip] = {
                "query_count": 0,
                "rpc_count": 0,
                "sql_types": set(),
                "procedures": set(),
            }
        return self._server_stats[server_ip]

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _update_server_device(
        self,
        server_ip: str,
        server_port: int,
        server_mac: str = "",
        *,
        server_name: str = "",
        version: str = "",
    ) -> None:
        """Update or create MSSQL server device entry."""
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"mssql-server:{server_ip}"
        manufacturer = lookup_mac_vendor(server_mac) if server_mac else ""

        name = server_name or f"MSSQL Server ({server_ip})"
        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            mac=server_mac,
            name=name,
            device_type="SQL Server",
            manufacturer=manufacturer if manufacturer != "Unknown" else "",
        )

        # Build/update protocol data
        stats = self._get_server_stats(server_ip)
        info = self._server_info.get(server_ip, {})

        protocol_data: Dict[str, Any] = {
            "role": "server",
            "port": server_port,
            "query_count": stats.get("query_count", 0),
            "rpc_count": stats.get("rpc_count", 0),
            "sql_types": sorted(stats.get("sql_types", set())),
            "procedures": sorted(stats.get("procedures", set())),
            "protocol": "TDS/TCP",
        }
        if info.get("program_name"):
            protocol_data["program_name"] = info["program_name"]
        if info.get("program_version"):
            protocol_data["program_version"] = info["program_version"]
        if info.get("tds_version"):
            protocol_data["tds_version"] = info["tds_version"]
        if info.get("server_name"):
            protocol_data["server_name"] = info["server_name"]
        if info.get("current_database"):
            protocol_data["current_database"] = info["current_database"]
        if info.get("collation_lcid"):
            protocol_data["collation_lcid"] = info["collation_lcid"]
        if version:
            protocol_data["program_version"] = version

        device.mssql_passive_data = protocol_data

    def _update_client_device(self, client_ip: str, server_ip: str, client_mac: str = "") -> None:
        """Update or create MSSQL client device entry."""
        if not is_valid_discovered_ip(client_ip):
            return

        device_key = f"mssql-client:{client_ip}"
        manufacturer = lookup_mac_vendor(client_mac) if client_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            mac=client_mac,
            name=f"MSSQL Client ({client_ip})",
            device_type="SQL Client",
            manufacturer=manufacturer if manufacturer != "Unknown" else "",
        )

        if is_new:
            device.mssql_passive_data = {
                "role": "client",
                "servers_accessed": [server_ip],
                "protocol": "TDS/TCP",
            }
        else:
            if device.mssql_passive_data:
                servers = device.mssql_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.mssql_passive_data["servers_accessed"] = servers

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
                "protocol": "MSSQL",
                "credential_type": c.credential_type,
                "auth_method": c.auth_method,
                "username": c.username,
                "password": c.password,
                "server_ip": c.server_ip,
                "client_ip": c.client_ip,
                "database": c.database,
                "server_name": c.server_name,
                "client_name": c.client_name,
                "app": c.app_name,
                "success": c.success,
                "timestamp": c.timestamp,
            }
            for c in self.credentials
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get SQL write operations for alert generation.

        Returns list of write operation dicts aggregated by client->server pair.
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
            pairs[key]["operations"].append(op.get("operation", "SQL WRITE"))

        return list(pairs.values())

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data.

        Uses base class auto-generation for:
        - Credentials table (via get_credentials_summary)
        - Interaction tables (via PROTOCOL_COLUMNS + _format_protocol_columns)
        - Write alerts (via get_write_operations)

        Adds security alerts for plaintext credentials and unencrypted connections.
        """
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}

        alerts = result.setdefault("alerts", [])

        # Alert for plaintext SQL auth credentials
        for cred in self.credentials:
            if cred.credential_type == "plaintext" and cred.password:
                alerts.append(
                    {
                        "level": "fail",
                        "category": "credential_alert",
                        "message": (
                            f"MSSQL PLAINTEXT CREDENTIAL: {cred.username}:{cred.password} "
                            f"db={cred.database} ({cred.client_ip} -> {cred.server_ip})"
                        ),
                    }
                )

        # Alert for unencrypted pre-login negotiations
        for ix in self.interactions:
            if ix.operation == "Pre-Login" and ix.details.get("encryption") == "OFF":
                alerts.append(
                    {
                        "level": "fail",
                        "category": "encryption_alert",
                        "message": (
                            f"MSSQL UNENCRYPTED: Pre-Login encryption=OFF "
                            f"({ix.src_ip} -> {ix.dst_ip})"
                        ),
                    }
                )

        # Add server info table if we have version data
        tables = result.setdefault("tables", [])
        if self._server_info:
            server_rows = []
            for ip, info in self._server_info.items():
                prog = info.get("program_name", "?")
                ver = info.get("program_version", "?")
                tds_ver = info.get("tds_version", "?")
                db = info.get("current_database", "?")
                server_rows.append([ip, prog, ver, tds_ver, db])
            if server_rows:
                tables.append(
                    {
                        "headers": ["Server IP", "Program", "Version", "TDS Version", "Database"],
                        "rows": server_rows,
                        "title": f"MSSQL Servers ({len(server_rows)})",
                    }
                )

        return result
