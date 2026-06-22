"""
MongoDB Passive Listener for database activity and credential extraction.

Passively captures MongoDB wire protocol traffic to extract:
- Database and collection names from queries
- Operation types (Query, Insert, Update, Delete, OP_MSG)
- Replica set configuration
- Authentication attempts (SCRAM-SHA-1/256)
- Query patterns and data exfiltration indicators

MongoDB wire protocol opcodes:
- OP_REPLY (1): Server reply to client request
- OP_UPDATE (2001): Update document
- OP_INSERT (2002): Insert new document
- OP_QUERY (2004): Query a collection
- OP_GET_MORE (2005): Get more data from query cursor
- OP_DELETE (2006): Delete documents
- OP_MSG (2013): Extensible message format (MongoDB 3.6+)

PyShark MongoDB field reference (EK mode short names):
- mongo.opcode: Wire protocol opcode
- mongo.full_collection_name: Target collection (db.collection)
- mongo.database_name: Database name (extracted from full_collection_name)
- mongo.collection_name: Collection name
- mongo.number_to_return: Requested doc count
- mongo.number_to_skip: Skip count
- mongo.number_returned: Docs in reply
- mongo.cursor_id: Server cursor ID
- mongo.response_to: Request ID being replied to
- mongo.request_id: Client request identifier
- mongo.element_name: BSON element key names
- mongo.element_value_string: BSON string values
- mongo.element_value_int: BSON integer values
- mongo.reply_flags_queryfailure: Query failure flag
- mongo.reply_flags_cursornotfound: Cursor not found flag
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# Standard MongoDB port
MONGODB_PORT = 27017
MONGODB_PORTS = {MONGODB_PORT, 27018, 27019}

# Opcode mapping
OPCODE_NAMES = {
    "1": "OP_REPLY",
    "2001": "OP_UPDATE",
    "2002": "OP_INSERT",
    "2004": "OP_QUERY",
    "2005": "OP_GET_MORE",
    "2006": "OP_DELETE",
    "2013": "OP_MSG",
    1: "OP_REPLY",
    2001: "OP_UPDATE",
    2002: "OP_INSERT",
    2004: "OP_QUERY",
    2005: "OP_GET_MORE",
    2006: "OP_DELETE",
    2013: "OP_MSG",
}

# Operations that modify data (security-relevant)
WRITE_OPCODES = {"OP_UPDATE", "OP_INSERT", "OP_DELETE"}


class MongoDBPassiveListener(PySharkListenerBase):
    """Passive MongoDB traffic listener for database activity extraction.

    Captures MongoDB wire protocol traffic to extract:
    - Database and collection names from queries/inserts/updates
    - Operation types (Query, Insert, Update, Delete, OP_MSG)
    - Authentication attempts (saslStart/saslContinue)
    - Replica set discovery (isMaster/hello commands)
    - Data exfiltration indicators (large result sets)

    Usage:
        listener = MongoDBPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for db in listener.databases_seen:
            print(f"Database: {db}")
    """

    PROTOCOL_NAME = "mongodb"
    DISPLAY_FILTER = "mongo"
    REQUIRED_LAYERS = ("mongo",)
    SERVER_PORTS = tuple(sorted(MONGODB_PORTS))
    PROTOCOL_COLUMNS = ("operation", "database", "collection", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)

        # Track known servers to determine direction
        self._known_servers: Set[str] = set()

        # Extracted data
        self.databases_seen: Set[str] = set()
        self.collections_seen: Set[str] = set()  # "db.collection" format
        self.credentials: List[Dict[str, Any]] = []
        self._seen_creds: Set[Tuple[str, str, str]] = set()

        # Write operation tracking
        self._write_ops: List[Dict[str, Any]] = []

        # Security alerts
        self._alerts: List[Dict[str, str]] = []

    def process_packet(self, packet) -> None:
        """Process MongoDB packet and extract database activity."""
        if not hasattr(packet, "mongo"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)

        mongo = packet.mongo

        # Extract opcode
        opcode_raw = self.get_field(mongo, "opcode", "")
        opcode_name = OPCODE_NAMES.get(opcode_raw, OPCODE_NAMES.get(str(opcode_raw), "UNKNOWN"))

        # response_to is set on any reply (the request_id it answers). OP_REPLY
        # is legacy; in MongoDB 3.6+ OP_MSG carries both commands and responses,
        # and a server->client OP_MSG response has a non-zero response_to.
        response_to = self.get_field(mongo, "response_to", "")
        responds_to_request = bool(response_to) and str(response_to) != "0"

        # Determine direction via the shared cascade.  OP_REPLY and an OP_MSG
        # carrying a non-zero response_to are authoritative, port-independent
        # response signals (native=False).  A client OP_MSG command / OP_QUERY
        # etc. has no reply marker, so native=None falls through to the
        # known-server-port tier (canonical 27017-27019 plus learned servers and
        # any user --decode-as / OVERRIDE_PREFS override) and then the
        # lower-port / first-seen heuristic -- never dropping the packet.
        is_reply = opcode_name == "OP_REPLY" or (opcode_name == "OP_MSG" and responds_to_request)
        native = False if is_reply else None

        # Preserve the learned-server hint: when one endpoint is already known to
        # be a server, fold that into the native signal so it outranks the port
        # heuristic (matches the previous _known_servers behaviour).
        if native is None:
            if dst_ip in self._known_servers:
                native = True
            elif src_ip in self._known_servers:
                native = False

        d = self.resolve_direction(
            packet,
            native=native,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        direction = d.direction
        if d.is_request:
            client_ip, server_ip, server_port = d.client_ip, d.server_ip, d.server_port
            client_mac, server_mac = src_mac, dst_mac
        else:
            client_ip, server_ip, server_port = d.client_ip, d.server_ip, d.server_port
            server_mac, client_mac = src_mac, dst_mac
            self._known_servers.add(server_ip)

        # Extract collection/database info
        full_collection = str(self.get_field(mongo, "full_collection_name", "") or "")
        database_name = str(self.get_field(mongo, "database_name", "") or "")
        collection_name = str(self.get_field(mongo, "collection_name", "") or "")

        if database_name:
            self.databases_seen.add(database_name)
        if full_collection:
            self.collections_seen.add(full_collection)

        # Extract query/document details
        number_to_return = self.get_field(mongo, "number_to_return", "")
        number_returned = self.get_field(mongo, "number_returned", "")
        cursor_id = self.get_field(mongo, "cursor_id", "")
        request_id = self.get_field(mongo, "request_id", "")

        # Extract BSON element names and values
        element_names = self.get_field(mongo, "element_name", "")
        element_value_str = self.get_field(mongo, "element_value_string", "")

        # Check for authentication-related commands
        auth_detected = False
        if element_names:
            names_str = str(element_names)
            for cmd in ("saslStart", "saslContinue", "authenticate"):
                if cmd in names_str:
                    auth_detected = True
                    self._record_auth_attempt(
                        client_ip, server_ip, server_port, cmd, element_value_str or ""
                    )
                    break

        # Build interaction details
        now = self._get_timestamp()
        details: Dict[str, Any] = {
            "opcode": opcode_name,
            "database": database_name,
            "collection": collection_name,
            "full_collection": full_collection,
            "request_id": str(request_id) if request_id else "",
            "response_to": str(response_to) if response_to else "",
        }
        if number_to_return:
            details["number_to_return"] = str(number_to_return)
        if number_returned:
            details["number_returned"] = str(number_returned)
        if cursor_id and str(cursor_id) != "0":
            details["cursor_id"] = str(cursor_id)
        if element_names:
            details["element_names"] = str(element_names)
        if auth_detected:
            details["auth_attempt"] = True

        # Detect reply errors
        query_failure = self.get_field(mongo, "reply_flags_queryfailure", None)
        if query_failure and str(query_failure).lower() in ("1", "true"):
            details["query_failure"] = True

        summary = f"MongoDB {opcode_name} {client_ip}->{server_ip}"
        if full_collection:
            summary += f" {full_collection}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            opcode_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track write operations
        if opcode_name in WRITE_OPCODES:
            self._write_ops.append(
                {
                    "client": client_ip,
                    "server": server_ip,
                    "write_count": 1,
                    "operation": opcode_name,
                    "collection": full_collection,
                }
            )

        # Ensure both endpoint devices exist
        self._ensure_server_device(server_ip, server_port, server_mac)
        self._ensure_client_device(client_ip, server_ip, client_mac)

    def _record_auth_attempt(
        self, client_ip: str, server_ip: str, server_port: int, method: str, value: str
    ) -> None:
        """Record an authentication attempt."""
        cred_key = (client_ip, server_ip, method)
        if cred_key in self._seen_creds:
            return
        self._seen_creds.add(cred_key)

        cred = {
            "protocol": "MongoDB",
            "credential_type": "auth_attempt",
            "auth_method": method,
            "username": "",  # SCRAM auth data is binary, hard to extract username
            "value": value,
            "server_ip": server_ip,
            "server_port": server_port,
            "client_ip": client_ip,
            "timestamp": datetime.now().isoformat(),
        }
        self.credentials.append(cred)
        self.logger.info(f"MongoDB auth attempt: {client_ip} -> {server_ip} method={method}")

    # -------------------------------------------------------------------------
    # Interaction table formatting
    # -------------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format MongoDB interaction as protocol-specific table columns."""
        d = ix.details
        op = d.get("opcode", ix.operation)
        database = d.get("database", "")
        collection = d.get("collection", "")
        detail = ""

        if op == "OP_QUERY":
            n = d.get("number_to_return", "")
            detail = f"limit={n}" if n else ""
            if d.get("element_names"):
                detail += f" keys={d['element_names']}"
        elif op == "OP_REPLY":
            n = d.get("number_returned", "")
            detail = f"docs={n}" if n else ""
            if d.get("query_failure"):
                detail += " [FAILURE]"
        elif op == "OP_INSERT":
            detail = "insert"
        elif op in ("OP_UPDATE", "OP_DELETE"):
            detail = op.replace("OP_", "").lower()
        elif d.get("auth_attempt"):
            detail = f"auth={d.get('element_names', '')}"
        elif d.get("element_names"):
            detail = str(d["element_names"])

        return [op, database, collection, detail]

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _ensure_server_device(self, ip: str, port: int, mac: str = "") -> None:
        """Create or update MongoDB server device."""
        if not is_valid_discovered_ip(ip):
            return
        key = f"mongodb-server:{ip}"
        vendor = lookup_mac_vendor(mac) if mac else ""
        device, is_new = self._ensure_device(
            key,
            ip,
            mac=mac,
            name=f"MongoDB Server ({ip})",
            device_type="MongoDB Server",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.mongodb_passive_data = {
                "role": "server",
                "port": port,
                "databases": sorted(self.databases_seen),
                "collections": sorted(self.collections_seen),
                "protocol": "MongoDB/TCP",
            }
        else:
            if hasattr(device, "mongodb_passive_data") and device.mongodb_passive_data:
                device.mongodb_passive_data["databases"] = sorted(self.databases_seen)
                device.mongodb_passive_data["collections"] = sorted(self.collections_seen)

    def _ensure_client_device(self, ip: str, server_ip: str, mac: str = "") -> None:
        """Create or update MongoDB client device."""
        if not is_valid_discovered_ip(ip):
            return
        key = f"mongodb-client:{ip}"
        vendor = lookup_mac_vendor(mac) if mac else ""
        device, is_new = self._ensure_device(
            key,
            ip,
            mac=mac,
            name=f"MongoDB Client ({ip})",
            device_type="MongoDB Client",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.mongodb_passive_data = {
                "role": "client",
                "servers_accessed": [server_ip],
                "protocol": "MongoDB/TCP",
            }
        else:
            if hasattr(device, "mongodb_passive_data") and device.mongodb_passive_data:
                servers = device.mongodb_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.mongodb_passive_data["servers_accessed"] = servers

    # -------------------------------------------------------------------------
    # Harvest / credential summaries
    # -------------------------------------------------------------------------

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return list(self.credentials)

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get aggregated write operations."""
        if not self._write_ops:
            return []
        pairs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for op in self._write_ops:
            key = (op["client"], op["server"])
            if key not in pairs:
                pairs[key] = {"client": op["client"], "server": op["server"], "write_count": 0}
            pairs[key]["write_count"] += 1
        return list(pairs.values())

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data."""
        result = super().harvest()
        if self._alerts:
            if not result:
                result = {"tables": [], "alerts": []}
            alerts = result.get("alerts", [])
            for alert in self._alerts:
                if alert not in alerts:
                    alerts.append(alert)
            result["alerts"] = alerts
        return result
