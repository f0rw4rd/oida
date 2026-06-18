"""
Memcached Passive Listener for cache activity and security extraction.

Passively captures Memcached traffic to extract:
- Command types (get, set, stats, delete, flush_all)
- Key names for cache content enumeration
- Stats data (version, item counts, memory usage)
- UDP amplification attack detection
- Slab statistics and item metadata

Memcached supports both text and binary protocols.
tshark dissects both as "memcache" layer.

Text protocol commands:
- set/add/replace/append/prepend <key> <flags> <exptime> <bytes>
- get/gets <key> [<key> ...]
- delete <key>
- stats [<args>]
- incr/decr <key> <value>
- flush_all
- version

PyShark Memcached field reference (EK mode short names):
- memcache.command: Text protocol command name (e.g., "stats", "get")
- memcache.key: Key name from text protocol
- memcache.response: Text protocol response (e.g., "STORED", "END")
- memcache.name: Stat name from stats response
- memcache.name_value: Stat value from stats response
- memcache.opcode: Binary protocol opcode
- memcache.type: Request (0x80) or Response (0x81)
- memcache.extras_flags: Binary protocol flags
- memcache.status: Binary protocol response status
- memcache.value: Value data
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

import logging

logger = logging.getLogger(__name__)


# Standard Memcached port
MEMCACHED_PORT = 11211
MEMCACHED_PORTS = {MEMCACHED_PORT}

# Binary protocol opcodes
BIN_OPCODES = {
    "0": "Get",
    "1": "Set",
    "2": "Add",
    "3": "Replace",
    "4": "Delete",
    "5": "Increment",
    "6": "Decrement",
    "7": "Quit",
    "8": "Flush",
    "9": "GetQ",
    "10": "Noop",
    "11": "Version",
    "12": "GetK",
    "13": "GetKQ",
    "14": "Append",
    "15": "Prepend",
    "16": "Stat",
    0: "Get",
    1: "Set",
    2: "Add",
    3: "Replace",
    4: "Delete",
    5: "Increment",
    6: "Decrement",
    7: "Quit",
    8: "Flush",
    9: "GetQ",
    10: "Noop",
    11: "Version",
    12: "GetK",
    13: "GetKQ",
    14: "Append",
    15: "Prepend",
    16: "Stat",
}

# Text protocol write commands
WRITE_COMMANDS = {"set", "add", "replace", "append", "prepend", "cas", "delete", "incr", "decr"}

# Dangerous commands
DANGEROUS_COMMANDS = {"flush_all", "Flush"}


class MemcachedPassiveListener(PySharkListenerBase):
    """Passive Memcached traffic listener for cache activity extraction.

    Captures Memcached traffic to extract:
    - Command types and frequency (get/set/stats/delete)
    - Key names for cache enumeration
    - Stats output (version, memory, items)
    - UDP amplification attack indicators
    - Binary and text protocol operations

    Usage:
        listener = MemcachedPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for key in listener.keys_seen:
            print(f"Cache key: {key}")
    """

    PROTOCOL_NAME = "memcached"
    DISPLAY_FILTER = "memcache"
    REQUIRED_LAYERS = ("memcache",)
    PROTOCOL_COLUMNS = ("command", "key", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)

        self._known_servers: Set[str] = set()
        self.commands_seen: Dict[str, int] = {}
        self.keys_seen: Set[str] = set()
        self.server_stats: Dict[str, Dict[str, str]] = {}  # server_ip -> {stat_name: value}
        self._write_ops: List[Dict[str, Any]] = []
        self._alerts: List[Dict[str, str]] = []
        self._udp_requests_seen: int = 0

    def process_packet(self, packet) -> None:
        """Process Memcached packet.

        Handles:
        - Text protocol commands and responses
        - Binary protocol messages
        - Multi-PDU TCP segments (EK mode _fields_dict as list)
        - VALUE/version responses (key+value without command field)
        - UDP amplification packets (empty memcache layer)
        - ICMP-embedded memcache packets (no top-level memcache layer)
        """
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        now = self._get_timestamp()

        # Handle packets without a top-level memcache layer (e.g. ICMP with
        # embedded memcache payload).  The display filter matched them, so
        # record a minimal interaction.
        if not hasattr(packet, "memcache"):
            self.logger.debug(
                f"No memcache layer (embedded in ICMP?) from "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            )
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "Embedded",
                {"response_type": "embedded"},
                f"Memcached embedded ({src_ip} -> {dst_ip})",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
            return

        memcache = packet.memcache

        # Check if this is UDP (amplification detection)
        is_udp = hasattr(packet, "udp")
        if is_udp:
            if dst_port in MEMCACHED_PORTS:
                self._udp_requests_seen += 1
                if self._udp_requests_seen == 1:
                    self._alerts.append(
                        {
                            "level": "fail",
                            "category": "write_alert",
                            "message": (
                                f"MEMCACHED UDP: {src_ip} sending UDP to {dst_ip}:{dst_port} "
                                "- potential amplification attack vector"
                            ),
                        }
                    )

        # --- Multi-PDU handling (EK mode: _fields_dict is a list) ---------
        multi_dicts = self._get_ek_layer_dicts(memcache)
        if multi_dicts is not None:
            self._process_multi_pdu(
                multi_dicts,
                now,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                flow_id,
                stream_id,
                packet,
            )
            return

        # --- Single-PDU processing ----------------------------------------
        self._process_single_layer(
            memcache,
            now,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            src_mac,
            dst_mac,
            flow_id,
            stream_id,
        )

    # ------------------------------------------------------------------
    # EK multi-PDU helper
    # ------------------------------------------------------------------

    @staticmethod
    def _get_ek_layer_dicts(layer) -> Optional[List[dict]]:
        """Return the raw list of dicts when an EK layer wraps multiple PDUs.

        In PyShark's EK mode, multi-PDU TCP segments store ``_fields_dict``
        as a *list* of dicts instead of a single dict.  PyShark's ``EkLayer``
        cannot resolve field names in that case.  This helper detects the
        array case and returns the list, or ``None`` for normal single-PDU
        layers.
        """
        try:
            fd = object.__getattribute__(layer, "_fields_dict")
            if isinstance(fd, list):
                return fd
        except AttributeError as e:
            logger.debug(f"Memcached EK layer _fields_dict access failed: {e}")
        return None

    def _process_multi_pdu(
        self,
        dicts: List[dict],
        now: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        stream_id: str,
        packet,
    ) -> None:
        """Process multi-PDU TCP segments (EK _fields_dict is a list)."""
        from pyshark.packet.layers.ek_layer import EkLayer as _EkLayer

        layer_name = packet.memcache._layer_name
        for raw_dict in dicts:
            syn_layer = _EkLayer(layer_name, raw_dict)
            self._process_single_layer(
                syn_layer,
                now,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                flow_id,
                stream_id,
            )

    # ------------------------------------------------------------------
    # Single-layer processing (called once per PDU)
    # ------------------------------------------------------------------

    def _process_single_layer(
        self,
        memcache,
        now: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Process a single memcache layer (normal packet or synthetic EK layer)."""
        # Text protocol: check for command field
        command_raw = self.get_field(memcache, "command", None)
        response_raw = self.get_field(memcache, "response", None)
        stat_name = self.get_field(memcache, "name", None)

        # Binary protocol: check for opcode
        opcode_raw = self.get_field(memcache, "opcode", None)
        bin_type = self.get_field(memcache, "magic", None)

        if command_raw is not None:
            # Text protocol command
            command_str = str(command_raw).strip().lower()

            # Handle multiple commands in one packet (stats responses)
            if isinstance(command_raw, list) or "," in str(command_raw):
                self._process_stats_response(
                    now,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    src_mac,
                    dst_mac,
                    memcache,
                    flow_id,
                    stream_id,
                )
                return

            self._process_text_command(
                now,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                command_str,
                memcache,
                flow_id,
                stream_id,
            )

        elif stat_name is not None:
            # Stats response
            self._process_stats_response(
                now,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                memcache,
                flow_id,
                stream_id,
            )

        elif response_raw is not None:
            # Text protocol response (STORED, END, etc.)
            self._known_servers.add(src_ip)
            resp_str = str(response_raw)

            server_ip, server_port = src_ip, src_port
            client_ip, client_port = dst_ip, dst_port

            details: Dict[str, Any] = {
                "response": resp_str,
            }

            self._record_interaction(
                now,
                server_ip,
                client_ip,
                "response",
                resp_str,
                details,
                f"Memcached {resp_str}",
                flow_id=flow_id,
                src_port=server_port,
                dst_port=client_port,
                stream_id=stream_id,
            )

            self._ensure_server_device(server_ip, server_port, src_mac)
            self._ensure_client_device(client_ip, server_ip, dst_mac)

        elif opcode_raw is not None:
            # Binary protocol
            self._process_binary(
                now,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                opcode_raw,
                bin_type,
                memcache,
                flow_id,
                stream_id,
            )

        else:
            # Check for text protocol VALUE response (key + value without
            # command/response fields) or version response
            version_raw = self.get_field(memcache, "version", None)
            key_raw = self.get_field(memcache, "key", None)
            value_raw = self.get_field(memcache, "value", None)

            if version_raw is not None:
                # Version response
                self._known_servers.add(src_ip)
                server_ip, server_port = src_ip, src_port
                client_ip, client_port = dst_ip, dst_port

                details: Dict[str, Any] = {
                    "response_type": "version",
                    "version": str(version_raw),
                }
                self._record_interaction(
                    now,
                    server_ip,
                    client_ip,
                    "response",
                    "Version",
                    details,
                    f"Memcached version {version_raw}",
                    flow_id=flow_id,
                    src_port=server_port,
                    dst_port=client_port,
                    stream_id=stream_id,
                )
                self._ensure_server_device(server_ip, server_port, src_mac)
                self._ensure_client_device(client_ip, server_ip, dst_mac)

            elif key_raw is not None or value_raw is not None:
                # VALUE response (GET/GETS result data without a command tag)
                self._known_servers.add(src_ip)
                server_ip, server_port = src_ip, src_port
                client_ip, client_port = dst_ip, dst_port

                key_str = str(key_raw) if key_raw else "?"
                if key_str and key_str != "?":
                    self.keys_seen.add(key_str)

                details = {
                    "response_type": "value",
                    "key": key_str,
                }
                self._record_interaction(
                    now,
                    server_ip,
                    client_ip,
                    "response",
                    "VALUE",
                    details,
                    f"Memcached VALUE {key_str}",
                    flow_id=flow_id,
                    src_port=server_port,
                    dst_port=client_port,
                    stream_id=stream_id,
                )
                self._ensure_server_device(server_ip, server_port, src_mac)
                self._ensure_client_device(client_ip, server_ip, dst_mac)

            else:
                # Fallback: memcache layer with no recognized fields
                # (e.g., UDP amplification raw payload, empty EK layer)
                self.logger.debug(
                    f"Memcache packet with no recognized fields from "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                )
                # Determine direction from port
                if src_port in MEMCACHED_PORTS or src_ip in self._known_servers:
                    direction = "response"
                    self._known_servers.add(src_ip)
                elif dst_port in MEMCACHED_PORTS or dst_ip in self._known_servers:
                    direction = "request"
                else:
                    direction = "response"

                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    direction,
                    "Data",
                    {"response_type": "raw"},
                    f"Memcached data ({src_ip}:{src_port} -> {dst_ip}:{dst_port})",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )

    def _process_text_command(
        self,
        now: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        command: str,
        memcache: Any,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Process a text protocol command."""
        # Determine direction
        if dst_port in MEMCACHED_PORTS or dst_ip in self._known_servers:
            client_ip, _ = src_ip, src_port
            server_ip, server_port = dst_ip, dst_port
            client_mac, server_mac = src_mac, dst_mac
            direction = "request"
        elif src_port in MEMCACHED_PORTS or src_ip in self._known_servers:
            server_ip, server_port = src_ip, src_port
            client_ip, _ = dst_ip, dst_port
            server_mac, client_mac = src_mac, dst_mac
            direction = "response"
            self._known_servers.add(server_ip)
        else:
            client_ip, _ = src_ip, src_port
            server_ip, server_port = dst_ip, dst_port
            client_mac, server_mac = src_mac, dst_mac
            direction = "request"

        self.commands_seen[command] = self.commands_seen.get(command, 0) + 1

        # Extract key
        key = str(self.get_field(memcache, "key", "") or "")
        if key:
            self.keys_seen.add(key)

        details: Dict[str, Any] = {
            "command": command,
        }
        if key:
            details["key"] = key

        detail_str = ""
        if key:
            detail_str = f"key={key}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            command,
            details,
            f"Memcached {command} {detail_str}".strip(),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track writes
        if command in WRITE_COMMANDS:
            self._write_ops.append(
                {
                    "client": client_ip,
                    "server": server_ip,
                    "write_count": 1,
                    "command": command,
                }
            )

        # Track dangerous commands
        if command in DANGEROUS_COMMANDS:
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "control_alert",
                    "message": f"MEMCACHED FLUSH: {client_ip} -> {server_ip}: {command}",
                }
            )

        self._ensure_server_device(server_ip, server_port, server_mac)
        self._ensure_client_device(client_ip, server_ip, client_mac)

    def _process_stats_response(
        self,
        now: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        memcache: Any,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Process stats response from server."""
        self._known_servers.add(src_ip)

        server_ip, server_port = src_ip, src_port
        client_ip, client_port = dst_ip, dst_port

        # Extract stat names and values
        stat_names = self.get_field(memcache, "name", "")
        stat_values = self.get_field(memcache, "name_value", "")

        # Parse into pairs
        names_list = self._to_list(stat_names)
        values_list = self._to_list(stat_values)

        # Store stats
        if server_ip not in self.server_stats:
            self.server_stats[server_ip] = {}
        for name, value in zip(names_list, values_list):
            self.server_stats[server_ip][name] = value

        # Build summary
        version = ""
        for name, value in zip(names_list, values_list):
            if name == "version":
                version = value
                break

        stat_count = len(names_list)
        detail = f"{stat_count} stats"
        if version:
            detail += f" version={version}"

        details: Dict[str, Any] = {
            "command": "stats_response",
            "stat_count": stat_count,
        }
        if version:
            details["version"] = version

        self._record_interaction(
            now,
            server_ip,
            client_ip,
            "response",
            "Stats Response",
            details,
            f"Memcached stats ({detail})",
            flow_id=flow_id,
            src_port=server_port,
            dst_port=client_port,
            stream_id=stream_id,
        )

        self._ensure_server_device(server_ip, server_port, src_mac)
        self._ensure_client_device(client_ip, server_ip, dst_mac)

    def _process_binary(
        self,
        now: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        opcode_raw: Any,
        bin_type: Any,
        memcache: Any,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Process binary protocol packet."""
        opcode_name = BIN_OPCODES.get(opcode_raw, BIN_OPCODES.get(str(opcode_raw), "Unknown"))

        # Determine direction from binary magic byte or port.
        # magic=0x80 (128) = request, magic=0x81 (129) = response.
        is_response = str(bin_type) in ("0x81", "129", "81")
        if is_response:
            server_ip, server_port = src_ip, src_port
            client_ip, _ = dst_ip, dst_port
            direction = "response"
            self._known_servers.add(server_ip)
        elif dst_port in MEMCACHED_PORTS or dst_ip in self._known_servers:
            client_ip, _ = src_ip, src_port
            server_ip, server_port = dst_ip, dst_port
            direction = "request"
        else:
            client_ip, _ = src_ip, src_port
            server_ip, server_port = dst_ip, dst_port
            direction = "request"

        self.commands_seen[opcode_name] = self.commands_seen.get(opcode_name, 0) + 1

        key = str(self.get_field(memcache, "key", "") or "")
        if key:
            self.keys_seen.add(key)

        details: Dict[str, Any] = {
            "command": opcode_name,
            "protocol": "binary",
        }
        if key:
            details["key"] = key

        detail_str = f"bin:{opcode_name}"
        if key:
            detail_str += f" key={key}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            opcode_name,
            details,
            f"Memcached {detail_str}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        self._ensure_server_device(
            server_ip, server_port, src_mac if server_ip == src_ip else dst_mac
        )
        self._ensure_client_device(
            client_ip, server_ip, dst_mac if client_ip == dst_ip else src_mac
        )

    @staticmethod
    def _to_list(val) -> List[str]:
        """Convert a pyshark field value to a list of strings."""
        if val is None:
            return []
        if isinstance(val, list):
            return [str(v.value if hasattr(v, "value") else v) for v in val]
        s = str(val)
        if "," in s:
            return [v.strip() for v in s.split(",")]
        return [s]

    # -------------------------------------------------------------------------
    # Interaction table formatting
    # -------------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format Memcached interaction as protocol-specific table columns."""
        d = ix.details
        command = d.get("command", ix.operation)
        key = d.get("key", "")
        detail = ""

        if command == "stats_response":
            count = d.get("stat_count", "")
            version = d.get("version", "")
            detail = f"{count} stats"
            if version:
                detail += f" v{version}"
        elif d.get("protocol") == "binary":
            detail = "binary"
        elif d.get("response"):
            detail = d["response"]

        return [command, key, detail]

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _ensure_server_device(self, ip: str, port: int, mac: str = "") -> None:
        """Create or update Memcached server device."""
        if not is_valid_discovered_ip(ip):
            return
        key = f"memcached-server:{ip}"
        vendor = lookup_mac_vendor(mac) if mac else ""
        device, is_new = self._ensure_device(
            key,
            ip,
            mac=mac,
            name=f"Memcached Server ({ip})",
            device_type="Memcached Server",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        stats = self.server_stats.get(ip, {})
        device.memcached_passive_data = {
            "role": "server",
            "port": port,
            "version": stats.get("version", ""),
            "commands_seen": dict(self.commands_seen),
            "keys_seen_count": len(self.keys_seen),
            "protocol": "Memcached/TCP",
        }

    def _ensure_client_device(self, ip: str, server_ip: str, mac: str = "") -> None:
        """Create or update Memcached client device."""
        if not is_valid_discovered_ip(ip):
            return
        key = f"memcached-client:{ip}"
        vendor = lookup_mac_vendor(mac) if mac else ""
        device, is_new = self._ensure_device(
            key,
            ip,
            mac=mac,
            name=f"Memcached Client ({ip})",
            device_type="Memcached Client",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.memcached_passive_data = {
                "role": "client",
                "servers_accessed": [server_ip],
                "protocol": "Memcached/TCP",
            }
        else:
            if hasattr(device, "memcached_passive_data") and device.memcached_passive_data:
                servers = device.memcached_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)

    # -------------------------------------------------------------------------
    # Harvest
    # -------------------------------------------------------------------------

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get aggregated write operations."""
        if not self._write_ops:
            return []
        pairs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for op in self._write_ops:
            pkey = (op["client"], op["server"])
            if pkey not in pairs:
                pairs[pkey] = {"client": op["client"], "server": op["server"], "write_count": 0}
            pairs[pkey]["write_count"] += 1
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
