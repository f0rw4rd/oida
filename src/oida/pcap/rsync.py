"""
Rsync Passive Listener.

Passively captures Rsync traffic to extract:
- Protocol version from @RSYNCD greeting/handshake
- Module names requested by clients
- Module listings from servers
- Rsync command arguments (--server, --sender, etc.)
- Server MOTD/greeting text

Rsync runs on TCP port 873 (default rsync daemon port).

Security value:
- File synchronization infrastructure discovery
- Unauthenticated module access detection
- Exposed module enumeration (backups, configs, etc.)
- Data exfiltration paths via rsync modules

tshark fields used (requires decode_as tcp.port==873,rsync):
- rsync.hdr_magic: "@RSYNCD:" header magic
- rsync.hdr_version: Protocol version string
- rsync.query: Client query string (module name)
- rsync.motd: Server MOTD string
- rsync.module_list: Server module listing
- rsync.response: RSYNCD response string (OK, EXIT, etc.)
- rsync.command: Client command string (rsync arguments)
- rsync.data: Raw rsync data (module list, responses)
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor


class RsyncPassiveListener(PySharkListenerBase):
    """Passive Rsync traffic listener.

    Captures rsync daemon traffic to extract:
    - Protocol version negotiation
    - Module names and listings
    - Command arguments
    - Server identification

    Usage:
        listener = RsyncPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "rsync"
    DISPLAY_FILTER = "rsync"
    REQUIRED_LAYERS = ("rsync",)
    PROTOCOL_COLUMNS = ("operation", "module_version", "detail")
    SERVER_PORTS = (873,)

    # Decode-as hint needed because tshark doesn't auto-detect rsync
    DECODE_AS = {"tcp.port==873": "rsync"}

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.modules: Dict[str, Set[str]] = {}  # server_ip -> set of module names
        self.server_versions: Dict[str, str] = {}  # server_ip -> version string

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format Rsync interaction as protocol-specific table columns."""
        d = ix.details
        operation = d.get("operation_type", "")
        module_or_version = d.get("module", "") or d.get("version", "")
        detail = d.get("detail", "")
        return [operation, module_or_version, detail]

    def process_packet(self, packet) -> None:
        """Process Rsync packet."""
        if not hasattr(packet, "rsync"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        rsync = packet.rsync
        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        hdr_magic = str(self.get_field(rsync, "hdr_magic", "") or "")
        hdr_version = str(self.get_field(rsync, "hdr_version", "") or "")
        query = str(self.get_field(rsync, "query", "") or "")
        # Motd, module_list, response are parsed from raw_data instead
        command = str(self.get_field(rsync, "command", "") or "")
        raw_data = str(self.get_field(rsync, "data", "") or "")

        # Clean up escaped newlines from tshark
        hdr_version = hdr_version.replace("\\n", "").strip()
        query = query.replace("\\n", "").strip()

        if hdr_magic:
            # @RSYNCD: header -- version handshake
            self._process_version(
                src_ip,
                dst_ip,
                hdr_version,
                flow_id,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                packet,
            )
        elif query:
            # Client query (module name or #list)
            self._process_query(
                query,
                src_ip,
                dst_ip,
                flow_id,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                packet,
            )
        elif command:
            # Client command arguments
            self._process_command(
                command,
                src_ip,
                dst_ip,
                flow_id,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                packet,
            )
        elif raw_data:
            # Raw data (module list, @RSYNCD: OK/EXIT responses)
            self._process_raw_data(
                raw_data,
                src_ip,
                dst_ip,
                flow_id,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                packet,
            )
        else:
            # Fallback: packet matched rsync filter but no recognized fields
            # (e.g. empty command with trailing stray characters, bare frames)
            now = datetime.now().isoformat()
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "Rsync Data",
                {"operation_type": "Data", "module": "", "detail": "rsync frame"},
                f"Rsync data frame ({src_ip} -> {dst_ip})",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

    def _process_version(
        self,
        src_ip,
        dst_ip,
        version,
        flow_id,
        src_port,
        dst_port,
        src_mac,
        dst_mac,
        packet,
    ) -> None:
        """Process @RSYNCD version handshake."""
        # Determine direction via the shared cascade.  The @RSYNCD greeting has
        # no request/response bit, so resolve_direction() falls through to the
        # known-server-port tier (canonical 873 plus any user --decode-as /
        # OVERRIDE_PREFS override) and then the lower-port heuristic.  A version
        # frame whose source is the server is a response (server greets first).
        d = self.resolve_direction(
            packet,
            native=None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        # is_server == the src_ip is the server side (server -> client greeting).
        is_server = not d.is_request
        direction = "response" if is_server else "request"

        if is_server and version:
            self.server_versions[src_ip] = version

        details: Dict[str, Any] = {
            "operation_type": "Version",
            "version": version,
            "detail": f"@RSYNCD: {version}",
        }

        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            "Rsync Version",
            details,
            f"Rsync @RSYNCD: {version} ({src_ip} -> {dst_ip})",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Track devices
        if is_server:
            self._ensure_server(src_ip, src_mac, version)
            self._ensure_client(dst_ip, dst_mac)
        else:
            self._ensure_client(src_ip, src_mac)
            self._ensure_server(dst_ip, dst_mac)

    def _process_query(
        self,
        query,
        src_ip,
        dst_ip,
        flow_id,
        src_port,
        dst_port,
        src_mac,
        dst_mac,
        packet,
    ) -> None:
        """Process client module query."""
        is_list = query.startswith("#list")
        module_name = "" if is_list else query

        if module_name and dst_ip:
            if dst_ip not in self.modules:
                self.modules[dst_ip] = set()
            self.modules[dst_ip].add(module_name)

        operation = "Module List Request" if is_list else "Module Access"
        detail = "#list" if is_list else f"module={module_name}"

        details: Dict[str, Any] = {
            "operation_type": operation,
            "module": module_name,
            "is_list_request": is_list,
            "detail": detail,
        }

        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"Rsync {operation}",
            details,
            f"Rsync {operation} {detail} ({src_ip} -> {dst_ip})",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        self._ensure_client(src_ip, src_mac)
        self._ensure_server(dst_ip, dst_mac)

    def _process_command(
        self,
        command,
        src_ip,
        dst_ip,
        flow_id,
        src_port,
        dst_port,
        src_mac,
        dst_mac,
        packet,
    ) -> None:
        """Process rsync command arguments."""
        # Clean up command for display
        cmd_clean = command.replace("\\n", " ").strip()
        cmd_short = cmd_clean

        details: Dict[str, Any] = {
            "operation_type": "Command",
            "command": cmd_clean,
            "module": "",
            "detail": cmd_short,
        }

        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "Rsync Command",
            details,
            f"Rsync Command: {cmd_short} ({src_ip} -> {dst_ip})",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        self._ensure_client(src_ip, src_mac)
        self._ensure_server(dst_ip, dst_mac)

    def _process_raw_data(
        self,
        raw_data,
        src_ip,
        dst_ip,
        flow_id,
        src_port,
        dst_port,
        src_mac,
        dst_mac,
        packet,
    ) -> None:
        """Process raw rsync data (module list, responses, binary transfer data)."""
        # Try to decode hex data
        decoded = self._try_decode_hex_data(raw_data)
        if decoded is None and raw_data:
            self.logger.debug(
                f"Rsync: undecodable raw data frame from {src_ip} -> {dst_ip} "
                f"({len(raw_data)} chars)"
            )

        recorded = False

        if decoded:
            # Parse the decoded content
            lines = decoded.strip().split("\n")
            modules_found: List[str] = []
            rsyncd_response = ""

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("@RSYNCD:"):
                    rsyncd_response = line
                elif "\t" in line:
                    # Module listing: "module_name\tdescription"
                    parts = line.split("\t", 1)
                    if parts[0]:
                        modules_found.append(parts[0])

            if modules_found:
                # Server is sending module listing
                if src_ip not in self.modules:
                    self.modules[src_ip] = set()
                self.modules[src_ip].update(modules_found)

                detail = f"modules: {', '.join(modules_found)}"
                details: Dict[str, Any] = {
                    "operation_type": "Module List",
                    "modules": modules_found,
                    "module": ", ".join(modules_found),
                    "detail": detail,
                }

                now = datetime.now().isoformat()
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Rsync Module List",
                    details,
                    f"Rsync Module List: {detail} ({src_ip} -> {dst_ip})",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=self.get_stream_id(packet),
                )
                recorded = True

                self._ensure_server(src_ip, src_mac)

                # Update server device with modules
                key = f"rsync-server:{src_ip}"
                if key in self.discovered_devices:
                    dev = self.discovered_devices[key]
                    if hasattr(dev, "rsync_passive_data") and dev.rsync_passive_data:
                        dev.rsync_passive_data["modules"] = sorted(self.modules.get(src_ip, set()))

            if rsyncd_response:
                operation = "RSYNCD Response"
                detail = rsyncd_response
                if "OK" in rsyncd_response:
                    operation = "RSYNCD OK"
                elif "EXIT" in rsyncd_response:
                    operation = "RSYNCD EXIT"

                details_resp: Dict[str, Any] = {
                    "operation_type": operation,
                    "response": rsyncd_response,
                    "module": "",
                    "detail": detail,
                }

                now = datetime.now().isoformat()
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    f"Rsync {operation}",
                    details_resp,
                    f"Rsync {rsyncd_response} ({src_ip} -> {dst_ip})",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=self.get_stream_id(packet),
                )
                recorded = True

                self._ensure_server(src_ip, src_mac)

        # Fallback: record binary/unrecognized data as a transfer interaction
        if not recorded:
            data_len = (
                len(raw_data.replace(":", "")) // 2 if ":" in raw_data else len(raw_data) // 2
            )
            now = datetime.now().isoformat()
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "Rsync Data",
                {
                    "operation_type": "Data Transfer",
                    "module": "",
                    "detail": f"binary data ({data_len} bytes)",
                },
                f"Rsync data transfer ({data_len} bytes) ({src_ip} -> {dst_ip})",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

    def _try_decode_hex_data(self, hex_str: str) -> Optional[str]:
        """Try to decode hex string (colon-separated or continuous) to UTF-8."""
        try:
            if ":" in hex_str:
                raw = bytes.fromhex(hex_str.replace(":", ""))
            else:
                raw = bytes.fromhex(hex_str)
            decoded = raw.decode("utf-8", errors="replace")
            if decoded and any(c.isalpha() for c in decoded):
                return decoded
        except (ValueError, UnicodeDecodeError) as e:
            self.logger.debug(f"Rsync: hex data decode failed: {e}")
        return None

    def harvest(self) -> Dict[str, Any]:
        """Surface discovered rsync modules (exposed shares) as a table + alert."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        tables = result.setdefault("tables", [])
        alerts = result.setdefault("alerts", [])

        if self.modules:
            rows = []
            for server_ip, mods in sorted(self.modules.items()):
                mod_list = ", ".join(sorted(m for m in mods if m)) or "?"
                version = self.server_versions.get(server_ip, "")
                rows.append([server_ip, version or "?", mod_list])
                alerts.append(
                    {
                        "level": "warning",
                        "category": "exposure_alert",
                        "message": (
                            f"RSYNC MODULES: {server_ip} exposes module(s): {mod_list} "
                            f"-- potential unauthenticated data access"
                        ),
                    }
                )
            tables.append(
                {
                    "headers": ["Server", "Version", "Modules"],
                    "rows": rows,
                    "title": f"Rsync Modules ({len(rows)})",
                }
            )

        if not tables and not alerts:
            return {}
        return result

    def _ensure_server(self, ip: str, mac: str = "", version: str = "") -> None:
        """Create/update rsync server device."""
        if not is_valid_discovered_ip(ip):
            return
        vendor = lookup_mac_vendor(mac) if mac else ""
        device, is_new = self._ensure_device(
            f"rsync-server:{ip}",
            ip,
            mac=mac or "",
            name=f"Rsync Server ({ip})",
            device_type="Rsync Server",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.rsync_passive_data = {
                "role": "server",
                "protocol": "Rsync/TCP",
                "version": version or self.server_versions.get(ip, ""),
                "modules": sorted(self.modules.get(ip, set())),
            }
        elif hasattr(device, "rsync_passive_data") and device.rsync_passive_data:
            if version:
                device.rsync_passive_data["version"] = version
            device.rsync_passive_data["modules"] = sorted(self.modules.get(ip, set()))

    def _ensure_client(self, ip: str, mac: str = "") -> None:
        """Create/update rsync client device."""
        if not is_valid_discovered_ip(ip):
            return
        vendor = lookup_mac_vendor(mac) if mac else ""
        device, is_new = self._ensure_device(
            f"rsync-client:{ip}",
            ip,
            mac=mac or "",
            name=f"Rsync Client ({ip})",
            device_type="Rsync Client",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.rsync_passive_data = {
                "role": "client",
                "protocol": "Rsync/TCP",
            }
