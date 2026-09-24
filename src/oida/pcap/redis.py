"""
Redis Passive Listener for credential and command extraction.

Passively captures Redis traffic (RESP protocol) to extract:
- AUTH commands with passwords (plaintext credentials)
- Command types (GET, SET, DEL, CONFIG, etc.)
- Key names for cache/session enumeration
- Database selection (SELECT commands)
- Configuration extraction (CONFIG GET)
- Replication status (INFO replication)

Redis uses the RESP (REdis Serialization Protocol) which tshark dissects
as the "resp" protocol layer.

PyShark RESP field reference (EK mode short names):
- resp.bulk_string_value: Bulk string values (hex-encoded bytes)
- resp.bulk_string_length: Bulk string lengths
- resp.array_length: Array element count
- resp.string: Simple string value (e.g., "OK")
- resp.integer: Integer response value
- resp.error: Error message string

RESP command format: Array of bulk strings
  *3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n

The first bulk string is always the command name.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from oida.pcap._mongodb_redis_common import WriteOpsHarvestMixin
from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# Standard Redis port
REDIS_PORT = 6379
REDIS_PORTS = {REDIS_PORT, 6380, 16379, 26379}

# Security-relevant commands
ADMIN_COMMANDS = {
    "SHUTDOWN",
    "SLAVEOF",
    "REPLICAOF",
    "DEBUG",
    "MONITOR",
    "FLUSHALL",
    "FLUSHDB",
    "BGSAVE",
    "BGREWRITEAOF",
    "CLIENT",
    "CLUSTER",
    "SCRIPT",
    "MODULE",
}
WRITE_COMMANDS = {
    "SET",
    "DEL",
    "MSET",
    "HSET",
    "LPUSH",
    "RPUSH",
    "SADD",
    "ZADD",
    "SETEX",
    "PSETEX",
    "SETNX",
    "APPEND",
    "INCR",
    "DECR",
    "EXPIRE",
    "PERSIST",
    "RENAME",
}


# Matches a complete b'...'/b"..." bytes-repr literal (escapes included), used
# to split get_field's comma-joined bytes-list representation without
# breaking on a comma that appears *inside* a literal's own payload (e.g. a
# password containing a comma).
BYTES_LITERAL_REGEX = re.compile(r'''b'(?:[^'\\]|\\.)*'|b"(?:[^"\\]|\\.)*"''')


def _decode_resp_hex(hex_str: str) -> str:
    """Decode a colon-separated hex string from RESP bulk_string_value."""
    if not hex_str:
        return ""
    try:
        clean = str(hex_str).replace(":", "")
        decoded = bytes.fromhex(clean).decode("utf-8", errors="replace")
        return decoded
    except (ValueError, UnicodeDecodeError):
        return str(hex_str)


class RedisPassiveListener(WriteOpsHarvestMixin, PySharkListenerBase):
    """Passive Redis traffic listener for credential and command extraction.

    Captures Redis RESP protocol traffic to extract:
    - AUTH commands with plaintext passwords
    - Command patterns (read/write/admin/config)
    - Key names for cache enumeration
    - Database selection (SELECT)
    - CONFIG GET output for configuration extraction
    - Replication status

    Usage:
        listener = RedisPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for cred in listener.credentials:
            print(f"Redis password: {cred['password']}")
    """

    PROTOCOL_NAME = "redis"
    DISPLAY_FILTER = "resp"
    REQUIRED_LAYERS = ("resp",)
    SERVER_PORTS = tuple(sorted(REDIS_PORTS))
    PROTOCOL_COLUMNS = ("command", "key_args", "response")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)

        self._known_servers: Set[str] = set()
        self.credentials: List[Dict[str, Any]] = []
        self._seen_creds: Set[Tuple[str, str]] = set()
        self.commands_seen: Dict[str, int] = {}
        self.keys_seen: Set[str] = set()
        self._write_ops: List[Dict[str, Any]] = []
        self._alerts: List[Dict[str, str]] = []

    def _resolve_roles(
        self,
        packet,
        native: Optional[bool],
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        flow_id: str,
    ) -> Tuple[str, int, str, int]:
        """Resolve (server_ip, server_port, client_ip, client_port) via the cascade.

        The RESP message shape is an authoritative native direction signal
        (command array = request, any response value = response).  When that is
        ambiguous (native=None) the known-server-port tier (canonical Redis
        ports plus learned servers and user --decode-as / OVERRIDE_PREFS
        overrides) and the lower-port / first-seen heuristic decide -- the
        packet is never dropped.  Learns the resolved server into
        ``_known_servers``.
        """
        if native is None:
            if src_ip in self._known_servers:
                native = False
            elif dst_ip in self._known_servers:
                native = True
        d = self.resolve_direction(
            packet,
            native=native,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        self._known_servers.add(d.server_ip)
        return d.server_ip, d.server_port, d.client_ip, d.client_port

    def process_packet(self, packet) -> None:
        """Process Redis RESP packet."""
        if not hasattr(packet, "resp"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)

        resp = packet.resp
        now = self._get_timestamp()

        # Determine if this is a request (array of bulk strings) or response
        array_length = self.get_field(resp, "array_length", None)
        simple_string = self.get_field(resp, "string", None)
        error_msg = self.get_field(resp, "error", None)
        integer_val = self.get_field(resp, "integer", None)

        if array_length is not None:
            # This is an array -- could be request or array response
            bulk_values_raw = self._get_raw_field(resp, "bulk_string_value")

            # Parse bulk string values
            values = self._parse_bulk_values(bulk_values_raw)

            if values:
                command = values[0].upper() if values else ""
                args = values[1:] if len(values) > 1 else []

                # Determine direction. Payload shape alone (first element looks
                # like a bare alphabetic command word) is ambiguous: server
                # array replies from CONFIG GET / KEYS / LRANGE / HGETALL
                # often start with a short alpha token too (e.g. "maxmemory",
                # "dir", a hash field name) and would be misread as a client
                # command -- which then makes _resolve_roles() *learn* the
                # responding server's IP as a client, poisoning
                # ``_known_servers`` for every later packet on the flow. Role
                # (a known server IP or a known Redis port) is a stronger,
                # protocol-independent signal than shape, so check it first
                # and only fall back to the shape heuristic when role is
                # unknown for both sides.
                src_is_server = (
                    src_ip in self._known_servers or src_port in self._known_server_ports
                )
                dst_is_server = (
                    dst_ip in self._known_servers or dst_port in self._known_server_ports
                )
                if src_is_server and not dst_is_server:
                    is_request = False
                elif dst_is_server and not src_is_server:
                    is_request = True
                else:
                    is_request = command.isalpha() and len(command) <= 20
                if is_request:
                    # Client -> Server (native=True: a command array is an
                    # authoritative request signal, port-independent).
                    server_ip, server_port, client_ip, client_port = self._resolve_roles(
                        packet, True, src_ip, dst_ip, src_port, dst_port, flow_id
                    )
                    if client_ip == src_ip:
                        client_mac, server_mac = src_mac, dst_mac
                    else:
                        client_mac, server_mac = dst_mac, src_mac

                    self._process_command(
                        now,
                        client_ip,
                        client_port,
                        server_ip,
                        server_port,
                        client_mac,
                        server_mac,
                        command,
                        args,
                        flow_id,
                        stream_id,
                    )
                    return
                else:
                    # Array response (e.g., CONFIG GET result) -- native=False:
                    # a non-command array value is an authoritative response.
                    server_ip, server_port, client_ip, client_port = self._resolve_roles(
                        packet, False, src_ip, dst_ip, src_port, dst_port, flow_id
                    )

                    details: Dict[str, Any] = {
                        "response_type": "array",
                        "array_length": str(array_length),
                        "values": ",".join(values),
                    }
                    self._record_interaction(
                        now,
                        server_ip,
                        client_ip,
                        "response",
                        "Array Response",
                        details,
                        f"Redis array response ({array_length} elements)",
                        flow_id=flow_id,
                        src_port=server_port,
                        dst_port=client_port,
                        stream_id=stream_id,
                    )
                    return
            else:
                # Array with no parseable bulk string values (empty EK layer)
                self.logger.debug(
                    f"RESP array with no bulk values from "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                )
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Array Response",
                    {"response_type": "array", "array_length": str(array_length)},
                    f"Redis array({array_length})",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
                return

        # Simple string / error / integer response -- native=False (a typed
        # RESP response value is an authoritative response signal).
        if simple_string is not None or error_msg is not None or integer_val is not None:
            server_ip, server_port, client_ip, client_port = self._resolve_roles(
                packet, False, src_ip, dst_ip, src_port, dst_port, flow_id
            )

            if simple_string is not None:
                resp_str = str(simple_string)
                details = {"response_type": "simple_string", "value": resp_str}
                self._record_interaction(
                    now,
                    server_ip,
                    client_ip,
                    "response",
                    "Response",
                    details,
                    f"Redis +{resp_str}",
                    flow_id=flow_id,
                    src_port=server_port,
                    dst_port=client_port,
                    stream_id=stream_id,
                )
            elif error_msg is not None:
                err_str = str(error_msg)
                details = {"response_type": "error", "error": err_str}
                self._record_interaction(
                    now,
                    server_ip,
                    client_ip,
                    "response",
                    "Error",
                    details,
                    f"Redis -{err_str}",
                    flow_id=flow_id,
                    src_port=server_port,
                    dst_port=client_port,
                    stream_id=stream_id,
                )
            elif integer_val is not None:
                details = {"response_type": "integer", "value": str(integer_val)}
                self._record_interaction(
                    now,
                    server_ip,
                    client_ip,
                    "response",
                    "Response",
                    details,
                    f"Redis :{integer_val}",
                    flow_id=flow_id,
                    src_port=server_port,
                    dst_port=client_port,
                    stream_id=stream_id,
                )

            # Ensure devices
            self._ensure_server_device(
                server_ip, server_port, src_mac if server_ip == src_ip else dst_mac
            )
            self._ensure_client_device(
                client_ip, server_ip, dst_mac if client_ip == dst_ip else src_mac
            )
            return

        # Bulk string response (single value, not wrapped in an array)
        # e.g., GET response returning a value, INFO response returning a string
        bulk_string_value = self._get_raw_field(resp, "bulk_string_value")
        if bulk_string_value is not None:
            # A bare bulk string is a server response value -- native=False.
            server_ip, server_port, client_ip, client_port = self._resolve_roles(
                packet, False, src_ip, dst_ip, src_port, dst_port, flow_id
            )

            values = self._parse_bulk_values(bulk_string_value)
            preview = values[0][:60] if values else "?"
            details: Dict[str, Any] = {
                "response_type": "bulk_string",
                "value": preview,
            }
            self._record_interaction(
                now,
                server_ip,
                client_ip,
                "response",
                "Bulk Response",
                details,
                f"Redis ${preview}",
                flow_id=flow_id,
                src_port=server_port,
                dst_port=client_port,
                stream_id=stream_id,
            )
            self._ensure_server_device(
                server_ip, server_port, src_mac if server_ip == src_ip else dst_mac
            )
            self._ensure_client_device(
                client_ip, server_ip, dst_mac if client_ip == dst_ip else src_mac
            )
            return

        # Fallback: RESP packet with no recognized fields (e.g., empty EK layer
        # from multi-PDU TCP segments).  No native signal -- the cascade's
        # known-server-port tier (canonical Redis ports + learned servers + user
        # overrides) and heuristic decide; never dropped.
        self.logger.debug(
            f"Unrecognized RESP packet from {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        )
        d = self.resolve_direction(
            packet,
            native=None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            d.direction,
            "RESP",
            {"response_type": "unknown"},
            f"Redis RESP ({src_ip}:{src_port} -> {dst_ip}:{dst_port})",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _get_raw_field(self, layer, field_name, default=None):
        """Get a field value without get_field's list-to-string conversion.

        For RESP bulk_string_value, EK mode returns a list of bytes objects
        (e.g. [b'AUTH', b'pass']) which _parse_bulk_values handles natively.
        Using get_field would flatten the list to a comma-joined string,
        losing the bytes/list structure.
        """
        try:
            val = getattr(layer, field_name, default)
            if val is None or val is default:
                return default
            return val
        except Exception as e:
            self.logger.debug(f"Redis: raw getattr on RESP field failed: {e}")
            return default

    def _parse_bulk_values(self, raw) -> List[str]:
        """Parse bulk string values from RESP layer.

        In EK mode, bulk_string_value can be:
        - A list of bytes objects (e.g. [b'AUTH', b'pass'])
        - A list of hex-encoded strings
        - A single hex-encoded string
        - A comma-separated string of hex or b'...' representations
        """
        if raw is None:
            return []
        if isinstance(raw, list):
            result = []
            for v in raw:
                if isinstance(v, bytes):
                    result.append(v.decode("utf-8", errors="replace"))
                elif hasattr(v, "value"):
                    result.append(_decode_resp_hex(str(v.value)))
                else:
                    result.append(_decode_resp_hex(str(v)))
            return result
        if isinstance(raw, bytes):
            return [raw.decode("utf-8", errors="replace")]
        raw_str = str(raw)
        # Handle get_field comma-joined representation of bytes list
        # e.g. "b'AUTH',b'secretpassword123'". A naive split(",") breaks a
        # value that itself contains a comma (e.g. "b'AUTH',b'pass,word'"),
        # so match complete b'...'/b"..." literals instead of splitting on
        # every comma.
        if raw_str.startswith("b'") or raw_str.startswith('b"'):
            literals = BYTES_LITERAL_REGEX.findall(raw_str)
            if literals:
                return [literal[2:-1] for literal in literals]
            # Fallback for a malformed/unmatched literal -- best effort.
            parts = []
            for part in raw_str.split(","):
                part = part.strip()
                if (part.startswith("b'") and part.endswith("'")) or (
                    part.startswith('b"') and part.endswith('"')
                ):
                    parts.append(part[2:-1])
                else:
                    parts.append(_decode_resp_hex(part))
            return parts
        if "," in raw_str:
            return [_decode_resp_hex(v.strip()) for v in raw_str.split(",")]
        return [_decode_resp_hex(raw_str)]

    def _process_command(
        self,
        now: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        client_mac: str,
        server_mac: str,
        command: str,
        args: List[str],
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Process a Redis command."""
        # Track command counts
        self.commands_seen[command] = self.commands_seen.get(command, 0) + 1

        # Track key names (first arg for most commands)
        key_name = args[0] if args else ""
        if key_name and command not in {"AUTH", "SELECT", "PING", "INFO", "CONFIG", "QUIT"}:
            self.keys_seen.add(key_name)

        # Handle AUTH command -- credential extraction
        if command == "AUTH":
            password = args[0] if args else ""
            username = ""
            if len(args) >= 2:
                # Redis 6+ ACL: AUTH username password
                username = args[0]
                password = args[1]
            self._record_credential(client_ip, server_ip, server_port, username, password)

        # Handle CONFIG GET -- configuration extraction
        if command == "CONFIG" and args and args[0].upper() == "GET":
            config_key = args[1] if len(args) > 1 else ""
            if config_key.lower() in ("requirepass", "masterauth"):
                self._alerts.append(
                    {
                        "level": "fail",
                        "category": "write_alert",
                        "message": (
                            f"REDIS CONFIG: {client_ip} querying sensitive config "
                            f"'{config_key}' on {server_ip}"
                        ),
                    }
                )

        # Track write operations
        if command in WRITE_COMMANDS:
            self._write_ops.append(
                {
                    "client": client_ip,
                    "server": server_ip,
                    "write_count": 1,
                    "command": command,
                    "key": key_name,
                }
            )

        # Track admin commands
        if command in ADMIN_COMMANDS:
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "control_alert",
                    "message": f"REDIS ADMIN: {client_ip} -> {server_ip}: {command} {' '.join(args)}",
                }
            )

        # Build details
        details: Dict[str, Any] = {
            "command": command,
            "args": " ".join(args),
        }
        if key_name:
            details["key"] = key_name
        if command == "AUTH":
            details["auth_attempt"] = True
        if command == "SELECT" and args:
            details["db_index"] = args[0]

        args_str = " ".join(args)
        summary = f"Redis {command}"
        if args_str:
            summary += f" {args_str}"

        self._record_interaction(
            now,
            client_ip,
            server_ip,
            "request",
            command,
            details,
            summary,
            flow_id=flow_id,
            src_port=client_port,
            dst_port=server_port,
            stream_id=stream_id,
        )

        # Ensure devices
        self._ensure_server_device(server_ip, server_port, server_mac)
        self._ensure_client_device(client_ip, server_ip, client_mac)

    def _record_credential(
        self,
        client_ip: str,
        server_ip: str,
        server_port: int,
        username: str,
        password: str,
    ) -> None:
        """Record extracted Redis credential."""
        cred_key = (server_ip, password)
        if cred_key in self._seen_creds:
            return
        self._seen_creds.add(cred_key)

        cred = {
            "protocol": "Redis",
            "credential_type": "plaintext",
            "auth_method": "AUTH",
            "username": username,
            "password": password,
            "value": password,
            "server_ip": server_ip,
            "server_port": server_port,
            "client_ip": client_ip,
            "timestamp": datetime.now().isoformat(),
        }
        self.credentials.append(cred)
        self.logger.info(
            f"Redis credential: {client_ip} -> {server_ip}:{server_port} "
            f"user={username or '(default)'} pass={password}"
        )

    # -------------------------------------------------------------------------
    # Interaction table formatting
    # -------------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format Redis interaction as protocol-specific table columns."""
        d = ix.details
        command = d.get("command", ix.operation)
        key_args = d.get("args", "")
        response = ""

        if ix.direction == "response":
            resp_type = d.get("response_type", "")
            if resp_type == "error":
                response = d.get("error", "")
            elif resp_type == "simple_string":
                response = d.get("value", "")
            elif resp_type == "integer":
                response = f":{d.get('value', '')}"
            elif resp_type == "array":
                response = f"array({d.get('array_length', '')})"
            command = ix.operation

        return [command, key_args, response]

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _ensure_server_device(self, ip: str, port: int, mac: str = "") -> None:
        """Create or update Redis server device."""
        if not is_valid_discovered_ip(ip):
            return
        key = f"redis-server:{ip}"
        vendor = lookup_mac_vendor(mac) if mac else ""
        device, is_new = self._ensure_device(
            key,
            ip,
            mac=mac,
            name=f"Redis Server ({ip})",
            device_type="Redis Server",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.redis_passive_data = {
                "role": "server",
                "port": port,
                "commands_seen": dict(self.commands_seen),
                "protocol": "Redis/TCP",
            }
        else:
            if hasattr(device, "redis_passive_data") and device.redis_passive_data:
                device.redis_passive_data["commands_seen"] = dict(self.commands_seen)

    def _ensure_client_device(self, ip: str, server_ip: str, mac: str = "") -> None:
        """Create or update Redis client device."""
        if not is_valid_discovered_ip(ip):
            return
        key = f"redis-client:{ip}"
        vendor = lookup_mac_vendor(mac) if mac else ""
        device, is_new = self._ensure_device(
            key,
            ip,
            mac=mac,
            name=f"Redis Client ({ip})",
            device_type="Redis Client",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.redis_passive_data = {
                "role": "client",
                "servers_accessed": [server_ip],
                "protocol": "Redis/TCP",
            }
        else:
            if hasattr(device, "redis_passive_data") and device.redis_passive_data:
                servers = device.redis_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)

    # -------------------------------------------------------------------------
    # Harvest / credential summaries
    # -------------------------------------------------------------------------

    # get_credentials_summary / get_write_operations / harvest are provided
    # by WriteOpsHarvestMixin (shared with the MongoDB listener).
