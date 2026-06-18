"""
PyShark-based passive listener base class.

Uses PyShark (tshark wrapper) for live packet capture and dissection.
Provides access to Wireshark's 500+ protocol dissectors for cleaner
field extraction compared to manual scapy parsing.

Example:
    class TLSListener(PySharkListenerBase):
        PROTOCOL_NAME = "tls"
        DISPLAY_FILTER = "tls.handshake"

        def process_packet(self, packet) -> None:
            if hasattr(packet, 'tls'):
                sni = getattr(packet.tls, 'handshake_extensions_server_name', None)
                # ...
"""

import threading
import time
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ...protocols.discovery.core import DiscoveredDevice

from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


@dataclass
class ProtocolInteraction:
    """A single observed protocol interaction."""

    timestamp: str
    src_ip: str
    dst_ip: str
    direction: str  # "request" or "response"
    operation: str  # human-readable
    details: Dict[str, Any] = dataclass_field(default_factory=dict)
    summary: str = ""
    flow_id: str = ""  # Transport-agnostic flow identifier
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""  # auto-set by _record_interaction
    stream_id: str = ""  # tcp.stream / udp.stream index from tshark

    @property
    def dir(self) -> str:
        """Short direction label for display: req / res."""
        return "req" if self.direction == "request" else "res"


class PySharkListenerBase(ABC):
    """Abstract base class for PyShark-based passive listeners.

    Provides common infrastructure for:
    - Live packet capture via pyshark.LiveCapture
    - Direct packet feeding for testing
    - Thread-safe device storage
    - Interaction tracking (protocol operations timeline)
    - Device creation helpers

    Subclasses must:
    - Set PROTOCOL_NAME class attribute (e.g. "modbus", "ftp")
    - Set DISPLAY_FILTER class attribute (Wireshark filter syntax)
    - Implement process_packet() method

    Usage:
        listener = MyListener(interface="eth0", timeout=30)
        devices = listener.scan()
    """

    # Class-level configuration - subclasses must override
    PROTOCOL_NAME: str = ""  # e.g., "tls", "modbus", "ftp"
    DISPLAY_FILTER: str = ""  # Wireshark display filter
    REQUIRED_LAYERS: Tuple[str, ...] = ()  # PyShark layer names; packet must have at least one

    # Interaction table columns.  Subclasses define only protocol-specific
    # columns; the common prefix (Dir, Src, Dst) is prepended automatically.
    PROTOCOL_COLUMNS: Tuple[str, ...] = ()  # subclass defines these

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        from ...protocols.discovery.core import validate_interface, validate_timeout

        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.nxc_logger = nxc_logger
        self.logger = nxc_logger or get_module_logger(
            f"oida.pcap.passive.{self.PROTOCOL_NAME}" if self.PROTOCOL_NAME else __name__
        )
        self.discovered_devices: Dict[str, "DiscoveredDevice"] = {}
        self._lock = threading.Lock()
        self._capture = None

        # Interaction tracking
        self.interactions: List["ProtocolInteraction"] = []

    def scan(self) -> Dict[str, "DiscoveredDevice"]:
        """Run live discovery scan."""
        return self._live_capture()

    def _check_pyshark(self) -> None:
        """Check pyshark availability."""
        try:
            import pyshark  # noqa: F401
        except ImportError:
            raise ImportError(
                f"{self.PROTOCOL_NAME} requires pyshark: pip install pyshark\n"
                "Also requires tshark (Wireshark CLI) to be installed."
            )

    def _live_capture(self) -> Dict[str, "DiscoveredDevice"]:
        """Capture packets from live interface using PyShark."""
        self._check_pyshark()
        import pyshark

        self.logger.debug(
            f"{self.PROTOCOL_NAME}: Listening on {self.interface} for {self.timeout}s "
            f"(filter: {self.DISPLAY_FILTER or 'none'})"
        )

        try:
            capture_args = {
                "interface": self.interface,
            }
            if self.DISPLAY_FILTER:
                capture_args["display_filter"] = self.DISPLAY_FILTER

            self._capture = pyshark.LiveCapture(**capture_args)

            start_time = time.time()
            for packet in self._capture.sniff_continuously():
                self._safe_process_packet(packet)
                if time.time() - start_time >= self.timeout:
                    break

        except Exception as e:
            self.logger.debug(f"{self.PROTOCOL_NAME} capture error: {e}")
        finally:
            if self._capture:
                self._capture.close()
                self._capture = None

        self.logger.debug(
            f"{self.PROTOCOL_NAME}: {len(self.discovered_devices)} devices discovered"
        )
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> bool:
        """Wrapper with error handling for packet processing."""
        try:
            if self.should_process_packet(packet):
                self.process_packet(packet)
                return True
            return False
        except Exception as e:
            self.logger.debug(f"{self.PROTOCOL_NAME} packet parse error: {e}")
            return False

    def should_process_packet(self, packet) -> bool:
        """Check if packet should be processed.

        When REQUIRED_LAYERS is set, the packet must contain at least one of
        the listed PyShark layers.  Subclasses may override for extra checks
        but should call ``super().should_process_packet(packet)`` first.
        """
        if self.REQUIRED_LAYERS:
            return any(hasattr(packet, layer) for layer in self.REQUIRED_LAYERS)
        return True

    @abstractmethod
    def process_packet(self, packet) -> None:
        """Process a single packet. Subclasses must implement."""

    # -------------------------------------------------------------------------
    # Interaction tracking
    # -------------------------------------------------------------------------

    def _record_interaction(
        self,
        timestamp: str,
        src_ip: str,
        dst_ip: str,
        direction: str,
        operation: str,
        details: Dict[str, Any],
        summary: str,
        flow_id: str = "",
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Record a protocol interaction."""
        self.interactions.append(
            ProtocolInteraction(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                direction=direction,
                operation=operation,
                details=details,
                summary=summary,
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                protocol=self.PROTOCOL_NAME.upper(),
                stream_id=stream_id,
            )
        )

    def get_interactions_summary(self) -> Dict[str, Any]:
        """Return a condensed view of all recorded interactions."""
        ops: Counter = Counter()
        targets: Set[Tuple[str, str]] = set()

        for interaction in self.interactions:
            ops[interaction.operation] += 1
            target_obj = ""
            for key in (
                "unit_id",
                "db_number",
                "ioa",
                "memory_area",
                "object_id",
                "variable",
                "point",
                "path",
            ):
                val = interaction.details.get(key)
                if val is not None:
                    target_obj = f"{key}={val}"
                    break
            targets.add((interaction.dst_ip, target_obj))

        return {
            "total_interactions": len(self.interactions),
            "operations": dict(ops),
            "unique_targets": [{"ip": ip, "object": obj} for ip, obj in sorted(targets)],
            "timeline": [i.summary for i in self.interactions],
        }

    # -------------------------------------------------------------------------
    # PyShark field access helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _resolve_value(val, default=None):
        """Unwrap EkMultiField values from pyshark EK mode.

        In EK mode, fields with subfields (e.g. ip.src) return EkMultiField
        objects instead of plain strings.  This extracts the .value attribute.
        """
        if val is None:
            return default
        if hasattr(val, "value") and hasattr(val, "_containing_layer"):
            return val.value if val.value is not None else default
        return val

    def get_field(self, layer, field_name: str, default: Any = None) -> Any:
        """Safely get field from PyShark layer.

        Normalises EK-mode typed values (int, bytes, list) back to strings
        so existing listeners work identically in both XML and EK modes.
        """
        try:
            val = getattr(layer, field_name, default)
            val = self._resolve_value(val, default)
            if val is None or val is default:
                return val
            # EK mode casts fields to native types; normalize back to str.
            if isinstance(val, bytes):
                return val.hex(":")
            if isinstance(val, bool):
                return str(val)
            if isinstance(val, (int, float)):
                return str(val)
            if isinstance(val, list):
                parts = [str(self._resolve_value(v, "")) for v in val]
                return ",".join(parts)
            return val
        except Exception as e:
            self.logger.debug(f"PyShark: layer value resolution failed: {e}")
            return default

    def get_all_fields(self, layer) -> Dict[str, str]:
        """Get all fields from PyShark layer as dict."""
        try:
            if hasattr(layer, "_all_fields"):
                return dict(layer._all_fields)
            # EK mode: use all_field_names property
            if hasattr(layer, "all_field_names"):
                result = {}
                # EK mode returns short names (e.g. "simple"); prefix with
                # layer name so keys match the XML-mode convention
                # (e.g. "ldap.simple") that all listeners expect.
                prefix = ""
                layer_name = getattr(layer, "layer_name", "")
                if layer_name:
                    prefix = f"{layer_name}."
                for name in layer.all_field_names:
                    key = f"{prefix}{name}"
                    val = layer.get_field(name)
                    resolved = self._resolve_value(val, "")
                    if resolved is None:
                        result[key] = ""
                    elif isinstance(resolved, list):
                        parts = [str(self._resolve_value(v, "")) for v in resolved]
                        result[key] = ",".join(parts)
                    elif isinstance(resolved, bytes):
                        result[key] = resolved.hex(":")
                    elif isinstance(resolved, (int, float, bool)):
                        result[key] = str(resolved)
                    else:
                        result[key] = str(resolved)
                return result
            return {}
        except Exception as e:
            self.logger.debug(f"Operation failed: {e}")
            return {}

    def get_ip_info(self, packet) -> tuple:
        """Extract (src_ip, dst_ip) from packet."""
        try:
            if hasattr(packet, "ip"):
                return (
                    str(self._resolve_value(packet.ip.src, "")),
                    str(self._resolve_value(packet.ip.dst, "")),
                )
            elif hasattr(packet, "ipv6"):
                return (
                    str(self._resolve_value(packet.ipv6.src, "")),
                    str(self._resolve_value(packet.ipv6.dst, "")),
                )
        except Exception as e:
            self.logger.debug(f"if hasattr(packet, ip):: {e}")
        return "", ""

    def get_port_info(self, packet) -> tuple:
        """Extract (src_port, dst_port) from packet.

        For ICMP error packets that quote the original TCP/UDP header,
        falls back to extracting embedded ports from the ICMP layer's
        internal fields dict (EK mode).
        """
        try:
            if hasattr(packet, "tcp"):
                return int(packet.tcp.srcport), int(packet.tcp.dstport)
            elif hasattr(packet, "udp"):
                return int(packet.udp.srcport), int(packet.udp.dstport)
            elif hasattr(packet, "icmp"):
                try:
                    fd = object.__getattribute__(packet.icmp, "_fields_dict")
                    if isinstance(fd, dict):
                        for proto in ("tcp", "udp"):
                            proto_dict = fd.get(proto)
                            if isinstance(proto_dict, dict):
                                src = int(proto_dict.get(f"{proto}_{proto}_srcport", 0))
                                dst = int(proto_dict.get(f"{proto}_{proto}_dstport", 0))
                                if src or dst:
                                    return src, dst
                except (AttributeError, TypeError, ValueError):
                    pass
        except Exception as e:
            self.logger.debug(f"if hasattr(packet, tcp):: {e}")
        return 0, 0

    def get_mac_info(self, packet) -> tuple:
        """Extract (src_mac, dst_mac) from packet, normalized to lowercase colon-separated."""
        try:
            if hasattr(packet, "eth"):
                from ...protocols.discovery.core import normalize_mac

                raw_src = str(self._resolve_value(packet.eth.src, ""))
                raw_dst = str(self._resolve_value(packet.eth.dst, ""))
                return (
                    normalize_mac(raw_src) if raw_src else "",
                    normalize_mac(raw_dst) if raw_dst else "",
                )
        except Exception as e:
            self.logger.debug(f"if hasattr(packet, eth):: {e}")
        return "", ""

    # -------------------------------------------------------------------------
    # Value parsing helpers (shared across listeners)
    # -------------------------------------------------------------------------

    @staticmethod
    def _parse_int(raw: Any, default: Any = 0, base: int = 10) -> Any:
        """Parse a PyShark field value to int, handling hex strings.

        Args:
            raw: Field value from PyShark (str, int, None, etc.)
            default: Value to return on failure (0, None, etc.)
            base: Forced base for parsing (10 or 16). Hex ``0x`` prefix
                  is always auto-detected regardless of *base*.
        """
        if raw is None:
            return default
        try:
            s = str(raw).strip()
            if s.startswith(("0x", "0X")):
                return int(s, 16)
            if base == 16:
                return int(s, 16)
            try:
                return int(s)
            except ValueError:
                # Bare hex without 0x prefix (e.g. "0A", "FF")
                return int(s, 16)
        except (ValueError, TypeError) as e:
            logger.debug(f"PyShark: int parse of field value failed: {e}")
            return default

    @staticmethod
    def _format_float(val: Any) -> str:
        """Format a float value for clean display (strip trailing zeros)."""
        try:
            fv = float(str(val))
            if fv == int(fv) and abs(fv) < 1e10:
                return str(int(fv))
            return f"{fv:g}"
        except (ValueError, TypeError):
            return str(val)

    @staticmethod
    def _parse_bool(raw: Any) -> bool:
        """Parse a PyShark field value as boolean."""
        if raw is None:
            return False
        return str(raw) in ("True", "1", "true")

    # -------------------------------------------------------------------------
    # Mail auth helpers (shared by SMTP, IMAP, POP3)
    # -------------------------------------------------------------------------

    @staticmethod
    def _decode_auth_plain(b64_creds: str) -> Tuple[str, str]:
        """Decode AUTH PLAIN Base64 credentials.

        RFC 2595 format: [authzid]\\x00authcid\\x00passwd
        Returns (username, password). Returns ("", "") on failure.
        """
        import base64

        try:
            cleaned = str(b64_creds).strip()
            if not cleaned:
                return ("", "")
            decoded = base64.b64decode(cleaned)
            parts = decoded.split(b"\x00")
            if len(parts) >= 3:
                authzid = parts[0].decode("utf-8", errors="ignore")
                authcid = parts[1].decode("utf-8", errors="ignore")
                passwd = parts[2].decode("utf-8", errors="ignore")
                return (authzid if authzid else authcid, passwd)
            elif len(parts) == 2:
                a = parts[0].decode("utf-8", errors="ignore")
                b = parts[1].decode("utf-8", errors="ignore")
                return (a, b) if a else (b, "")
        except Exception as e:
            logger.debug(f"Failed to get cleaned: {e}")
        return ("", "")

    @staticmethod
    def _extract_cram_md5_username(response_b64: str) -> str:
        """Extract username from CRAM-MD5 response (base64-encoded 'user digest')."""
        import base64

        try:
            decoded = base64.b64decode(response_b64).decode("ascii", errors="ignore")
            if " " in decoded:
                return decoded.rsplit(" ", 1)[0]
        except Exception as e:
            logger.debug(f"Failed to get decoded: {e}")
        return ""

    def get_flow_id(self, packet) -> str:
        """Build a canonical, direction-independent flow identifier.

        Endpoints are sorted so that both directions of the same TCP/UDP
        stream map to the same flow_id.  This ensures ``GROUP_BY_STREAM``
        produces a single merged table per stream instead of two.

        Returns:
            - TCP/UDP: ``"ip_a:port_a <-> ip_b:port_b"`` (sorted)
            - L2 (no IP layer): ``"mac_a <-> mac_b"`` (sorted)
            - Fallback: ``""``
        """
        try:
            if hasattr(packet, "tcp") or hasattr(packet, "udp"):
                src_ip, dst_ip = self.get_ip_info(packet)
                src_port, dst_port = self.get_port_info(packet)
                if src_ip and dst_ip:
                    a = f"{src_ip}:{src_port}"
                    b = f"{dst_ip}:{dst_port}"
                    if a > b:
                        a, b = b, a
                    return f"{a} <-> {b}"
            elif hasattr(packet, "eth"):
                src_mac, dst_mac = self.get_mac_info(packet)
                if src_mac and dst_mac:
                    a, b = sorted([src_mac, dst_mac])
                    return f"{a} <-> {b}"
        except Exception as e:
            self.logger.debug(f"if hasattr(packet, tcp) or hasattr(pa...: {e}")
        return ""

    def get_stream_id(self, packet) -> str:
        """Extract tcp.stream or udp.stream index from packet.

        These are numeric stream indices assigned by tshark (e.g. "0", "1").
        Returns empty string for L2 protocols or when unavailable.
        """
        try:
            if hasattr(packet, "tcp"):
                val = self.get_field(packet.tcp, "stream")
                if val is not None:
                    return str(val)
            elif hasattr(packet, "udp"):
                val = self.get_field(packet.udp, "stream")
                if val is not None:
                    return str(val)
        except Exception as e:
            self.logger.debug(f"if hasattr(packet, tcp):: {e}")
        return ""

    def _format_details_string(self, ix: ProtocolInteraction) -> str:
        """Build 'Col=val Col2=val2' from PROTOCOL_COLUMNS + _format_protocol_columns.

        Used by the scanner to build the Details column of the unified table.
        Falls back to ix.summary when PROTOCOL_COLUMNS is not set.
        """
        if not self.PROTOCOL_COLUMNS:
            return ix.summary or ""
        try:
            values = self._format_protocol_columns(ix)
        except NotImplementedError as e:
            self.logger.debug(f"Failed to get values: {e}")
            return ix.summary or ""
        # Column names that are too generic to add as "Col=" prefix
        _BARE_COLS = {"detail", "details", "info"}
        parts = []
        op = ix.operation
        for col, val in zip(self.PROTOCOL_COLUMNS, values):
            if val is not None and val != "":
                if col == "operation" or str(val) == op:
                    continue  # already shown in unified table's Operation column
                if col in _BARE_COLS:
                    parts.append(str(val))
                else:
                    parts.append(f"{col}={val}")
        return " ".join(parts)

    @staticmethod
    def _format_ip_port(ip: str, port: int) -> str:
        """Central ip:port formatter for unified table Src/Dst columns."""
        if port:
            return f"{ip}:{port}"
        return ip

    # -------------------------------------------------------------------------
    # Credential/hash collection for scanner
    # -------------------------------------------------------------------------

    def _collect_credentials(self) -> List[List[str]]:
        """Normalize raw cred dicts into rows: [protocol, type, username, server, client].

        Called by the scanner to build the unified credential table.
        """
        if not hasattr(self, "get_credentials_summary"):
            return []
        creds = self.get_credentials_summary()
        if not creds:
            return []
        proto = self.PROTOCOL_NAME.upper()
        rows = []
        for c in creds:
            cred_type = c.get("credential_type") or c.get("auth_method") or ""
            username = (
                c.get("username")
                or c.get("value")
                or c.get("password")
                or c.get("auth_string")
                or c.get("auth_data")
                or c.get("auth_value")
                or ""
            )
            server = (
                c.get("server_ip")
                or c.get("server")
                or c.get("dest_ip")
                or c.get("plc_ip")
                or c.get("router_ip")
                or c.get("peer_ip")
                or ""
            )
            port = c.get("server_port") or c.get("dest_port") or 0
            if server and port:
                server = f"{server}:{port}"
            client = (
                c.get("client_ip")
                or c.get("source_ip")
                or c.get("nas")
                or c.get("client")
                or c.get("local_ip")
                or ""
            )
            rows.append([c.get("protocol", proto), cred_type, username, server, client])
        return rows

    def _collect_hashes(self) -> List[List[str]]:
        """Normalize raw hash dicts into rows: [protocol, type, username, server, client].

        Called by the scanner to build the unified credential table.
        """
        if not hasattr(self, "get_hashes_summary"):
            return []
        hashes = self.get_hashes_summary()
        if not hashes:
            return []
        proto = self.PROTOCOL_NAME.upper()
        rows = []
        for h in hashes:
            hash_type = h.get("hash_type", "")
            username = h.get("username", "")
            domain = h.get("domain", "")
            if domain:
                username = f"{domain}\\{username}" if username else domain
            server = h.get("server_ip", "")
            client = h.get("client_ip", "")
            rows.append([h.get("protocol", proto), hash_type, username, server, client])
        return rows

    # -------------------------------------------------------------------------
    # Testing API
    # -------------------------------------------------------------------------

    def feed_packet(self, packet) -> None:
        """Feed a single PyShark packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets: Iterator) -> Dict[str, "DiscoveredDevice"]:
        """Feed multiple packets and return discovered devices."""
        for packet in packets:
            self._safe_process_packet(packet)
        return self.discovered_devices

    # -------------------------------------------------------------------------
    # Harvest API -- scanner calls this after packet processing
    # -------------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data for the scanner pipeline.

        The base implementation returns only write/control alerts.
        Interaction tables and credential tables are built centrally by the
        scanner (unified across all protocols).

        Subclasses may override to add custom info tables (PLC identity,
        OPC UA endpoints, etc.) and/or a results dict.

        Returns dict with optional keys:
            "tables": list of {"headers": list, "rows": list, "title": str}
            "results": dict of key->value to merge into scanner results
            "alerts": list of {"level": str, "message": str}
            "log_messages": list of {"level": str, "message": str}
        """
        tables: List[Dict[str, Any]] = []
        alerts: List[Dict[str, str]] = []
        proto = self.PROTOCOL_NAME.upper()

        # --- write / control operation alerts ------------------------------
        if hasattr(self, "get_write_operations"):
            writes = self.get_write_operations()
            for w in writes:
                client = w.get("client", "")
                server = self._format_endpoint_from_dict(w, "server")
                count = w.get("write_count", 0)
                alerts.append(
                    {
                        "level": "fail",
                        "category": "write_alert",
                        "message": (f"{proto} WRITE: {client} -> {server} ({count} writes)"),
                    }
                )

        if hasattr(self, "get_control_operations"):
            controls = self.get_control_operations()
            for ctrl in controls:
                controlling = ctrl.get("controlling", "")
                controlled = self._format_endpoint_from_dict(ctrl, "controlled")
                count = ctrl.get("control_count", 0)
                alerts.append(
                    {
                        "level": "fail",
                        "category": "control_alert",
                        "message": (
                            f"{proto} CONTROL: {controlling} -> {controlled}"
                            f" ({count} control commands)"
                        ),
                    }
                )

        if not tables and not alerts:
            return {}

        return {
            "tables": tables,
            "alerts": alerts,
        }

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Return protocol-specific cells.  Subclasses override this.

        Must return a list matching ``PROTOCOL_COLUMNS`` in length.
        Used by ``_format_details_string()`` to build the unified table.
        """
        raise NotImplementedError(
            f"{type(self).__name__} sets PROTOCOL_COLUMNS but does not "
            "override _format_protocol_columns()"
        )

    @staticmethod
    def _format_endpoint_from_dict(data: Dict[str, Any], ip_key: str = "server") -> str:
        """Format an IP address with port when available.

        Checks for ``server_port``, ``port``, or ``controlled_port`` in *data*
        and appends to the IP.  Returns e.g. ``"10.0.0.1:4840"`` or plain IP
        if no port is found.
        """
        ip = data.get(ip_key, "")
        port = data.get("server_port") or data.get(f"{ip_key}_port") or data.get("port") or 0
        if port:
            return f"{ip}:{port}"
        return ip

    # -------------------------------------------------------------------------
    # Device creation helpers
    # -------------------------------------------------------------------------

    def _add_device(
        self,
        key: str,
        device: "DiscoveredDevice",
    ) -> None:
        """Thread-safe device addition."""
        with self._lock:
            if key not in self.discovered_devices:
                self.discovered_devices[key] = device
            else:
                self.discovered_devices[key].last_seen = datetime.now().isoformat()

    def _ensure_device(
        self,
        key: str,
        ip: str,
        *,
        mac: str = "",
        name: str = "",
        device_type: str = "",
        manufacturer: str = "",
        data_attr: str = "",
        protocol_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple["DiscoveredDevice", bool]:
        """Thread-safe device creation or update.

        Returns:
            Tuple of (device, is_new). On existing devices, last_seen is
            updated automatically.
        """
        from ...protocols.discovery.core import DiscoveredDevice

        with self._lock:
            if key in self.discovered_devices:
                device = self.discovered_devices[key]
                device.last_seen = datetime.now().isoformat()
                return device, False

            now = datetime.now().isoformat()
            device = DiscoveredDevice(
                mac_address=mac,
                ip_addresses=[ip] if ip else [],
                name=name,
                manufacturer=manufacturer,
                device_type=device_type,
                discovered_by=[self.PROTOCOL_NAME],
                first_seen=now,
                last_seen=now,
            )
            if data_attr and protocol_data is not None:
                setattr(device, data_attr, protocol_data)
            self.discovered_devices[key] = device
            return device, True

    def _register_device(
        self,
        ip: str,
        mac: str = "",
        *,
        role: str = "",
        device_type: str = "",
        data_attr: str = "",
        protocol_data: Optional[Dict[str, Any]] = None,
        name: str = "",
        manufacturer: str = "",
    ) -> Tuple[Optional["DiscoveredDevice"], bool]:
        """High-level device registration with IP validation and MAC vendor lookup.

        Combines :meth:`is_valid_discovered_ip` validation,
        :func:`lookup_mac_vendor`, key generation, and :meth:`_ensure_device`
        into a single call.

        The device key is generated as ``{PROTOCOL_NAME}-{role}:{ip}`` when
        *role* is provided, or ``{PROTOCOL_NAME}:{ip}`` otherwise.

        Returns ``(None, False)`` when the IP is invalid (broadcast, loopback,
        multicast, etc.).
        """
        from ...protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

        if not is_valid_discovered_ip(ip):
            return None, False

        if mac and not manufacturer:
            vendor = lookup_mac_vendor(mac)
            if vendor and vendor != "Unknown":
                manufacturer = vendor

        if role:
            key = f"{self.PROTOCOL_NAME}-{role}:{ip}"
        else:
            key = f"{self.PROTOCOL_NAME}:{ip}"

        return self._ensure_device(
            key,
            ip,
            mac=mac,
            name=name,
            device_type=device_type,
            manufacturer=manufacturer,
            data_attr=data_attr,
            protocol_data=protocol_data,
        )

    def _display_cert_info(
        self,
        cert_der: bytes,
        protocol: str = "",
        target: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Parse and check a certificate via the central display_cert_info.

        Calls :func:`~oida.utils.security_findings.display_cert_info` which
        parses the DER certificate, logs it, and runs security checks.

        Gated by the ``_x509`` flag (set via ``--x509`` / ``-X``).
        Returns the cert info dict (with ``issues`` key) or *None*.
        """
        if not getattr(self, "_x509", False):
            return None
        try:
            from ...utils.security_findings import display_cert_info

            return display_cert_info(
                logger=self.logger,
                cert=cert_der,
                protocol=protocol or self.PROTOCOL_NAME,
                target=target,
            )
        except Exception as e:
            self.logger.debug(f"Certificate parse error: {e}")
            return None

    def _get_timestamp(self) -> str:
        """Get current ISO timestamp."""
        return datetime.now().isoformat()
