"""
PJL (Printer Job Language) Passive Listener for printer enumeration.

Passively captures PJL traffic on port 9100 (JetDirect) to extract:
- Printer model identification (@PJL INFO ID)
- Firmware version information
- Environment variables and settings (@PJL INFO VARIABLES, @PJL SET)
- Filesystem access commands (@PJL FSDIRLIST, @PJL FSQUERY) -- security-critical
- Print job names and parameters (@PJL JOB)
- Printer status information (@PJL INFO STATUS)

PJL is a plaintext protocol that starts with ``@PJL`` prefix.
There is no tshark PJL dissector, so this listener uses
``tcp.port == 9100`` display filter and parses raw TCP payload.

PJL commands of interest:
- @PJL INFO ID: Returns printer model name
- @PJL INFO STATUS: Returns printer status
- @PJL INFO VARIABLES: Lists all environment variables
- @PJL INFO FILESYS: Lists filesystem volumes
- @PJL SET <var>=<val>: Set environment variable
- @PJL FSDIRLIST: List directory contents (filesystem access!)
- @PJL FSQUERY: Query file existence
- @PJL FSUPLOAD: Download file from printer
- @PJL FSDOWNLOAD: Upload file to printer
- @PJL FSMKDIR: Create directory
- @PJL FSDELETE: Delete file
- @PJL JOB NAME="...": Start print job
- @PJL EOJ: End of job

Security implications:
- PJL filesystem commands enable full read/write access to printer storage
- Environment variables can reveal configuration details
- No authentication in standard PJL
- PRET (Printer Exploitation Toolkit) uses PJL for attacks

Reference: HP PJL Technical Reference Manual
"""

import re
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# PJL command patterns
RE_PJL_COMMAND = re.compile(r"@PJL\s+(\S+)(.*?)(?:\r?\n|$)", re.IGNORECASE)
RE_PJL_INFO_ID_RESPONSE = re.compile(r'@PJL\s+INFO\s+ID\s*\r?\n\s*"?([^"\r\n]+)"?', re.IGNORECASE)
RE_PJL_STATUS_CODE = re.compile(r"CODE\s*=\s*(\d+)", re.IGNORECASE)
RE_PJL_STATUS_DISPLAY = re.compile(r'DISPLAY\s*=\s*"([^"]*)"', re.IGNORECASE)
RE_PJL_JOB_NAME = re.compile(r'NAME\s*=\s*"([^"]*)"', re.IGNORECASE)
RE_PJL_SET_VAR = re.compile(r"(\w+)\s*=\s*(\S+)", re.IGNORECASE)
RE_PJL_FSDIRLIST_NAME = re.compile(r'NAME\s*=\s*"([^"]*)"', re.IGNORECASE)
RE_UEL = re.compile(rb"\x1b%-12345X", re.IGNORECASE)

# PJL filesystem commands (security-sensitive)
PJL_FS_COMMANDS = {
    "FSDIRLIST",
    "FSQUERY",
    "FSUPLOAD",
    "FSDOWNLOAD",
    "FSMKDIR",
    "FSDELETE",
    "FSINIT",
    "FSAPPEND",
}

# PJL info commands
PJL_INFO_COMMANDS = {"INFO", "DINQUIRE", "INQUIRE", "ECHO"}

PJL_DEFAULT_PORT = 9100


class PJLPassiveListener(PySharkListenerBase):
    """Passive PJL traffic listener for printer enumeration and attack detection.

    Captures raw TCP traffic on port 9100 to extract PJL commands:
    - Printer model identification
    - Filesystem access attempts (security-critical)
    - Environment variable enumeration
    - Print job tracking
    - Configuration changes

    Security value:
    - Printer infrastructure mapping
    - Detection of PRET-style attacks (filesystem access)
    - Unauthorized configuration changes
    - Information disclosure via PJL INFO commands

    Usage:
        listener = PJLPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "pjl"
    DISPLAY_FILTER = "tcp.port == 9100"
    REQUIRED_LAYERS = ()  # No protocol-specific layer; we parse raw TCP
    PROTOCOL_COLUMNS = ("command", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track discovered printer identities
        self.printer_ids: Dict[str, str] = {}  # server_ip -> printer model
        # Track filesystem access attempts (security-critical)
        self.fs_access: List[Dict[str, Any]] = []
        # Track environment variables
        self.env_vars: Dict[str, Dict[str, str]] = {}  # server_ip -> {var: val}

    def should_process_packet(self, packet) -> bool:
        """Check if packet is on port 9100 and has TCP payload."""
        if not hasattr(packet, "tcp"):
            return False
        try:
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)
            if src_port != PJL_DEFAULT_PORT and dst_port != PJL_DEFAULT_PORT:
                return False
        except (AttributeError, ValueError) as e:
            self.logger.debug(f"Failed to get src_port: {e}")
            return False
        return True

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format PJL interaction as protocol-specific table columns."""
        d = ix.details
        command = d.get("command", "?")
        subcommand = d.get("subcommand", "")
        if subcommand:
            cmd_str = f"{command} {subcommand}"
        else:
            cmd_str = command

        # Flag filesystem commands
        if command in PJL_FS_COMMANDS:
            cmd_str = f"[!] {cmd_str}"

        # Build detail
        parts = []
        printer_id = d.get("printer_id", "")
        if printer_id:
            parts.append(f'id="{printer_id}"')
        job_name = d.get("job_name", "")
        if job_name:
            parts.append(f'job="{job_name}"')
        var_name = d.get("variable_name", "")
        var_val = d.get("variable_value", "")
        if var_name:
            parts.append(f"{var_name}={var_val}")
        fs_path = d.get("fs_path", "")
        if fs_path:
            parts.append(f'path="{fs_path}"')
        status = d.get("status_display", "")
        if status:
            parts.append(f'status="{status}"')
        detail = " ".join(parts)

        return [cmd_str, detail]

    def process_packet(self, packet) -> None:
        """Process PJL packet by parsing raw TCP payload."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        stream_id = self.get_stream_id(packet)
        now = self._get_timestamp()

        # Extract TCP payload
        payload = self._get_tcp_payload(packet)
        if not payload:
            return

        # Determine direction
        is_server = src_port == PJL_DEFAULT_PORT
        direction = "response" if is_server else "request"
        server_ip = src_ip if is_server else dst_ip
        client_ip = dst_ip if is_server else src_ip

        # Try to decode payload as text
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            text = payload.decode("latin-1", errors="ignore")

        # Strip UEL escape if present
        text = re.sub(r"\x1b%-12345X", "", text)

        if not text.strip():
            return

        # Find all @PJL commands in the payload
        commands_found = list(RE_PJL_COMMAND.finditer(text))
        if not commands_found:
            return

        for match in commands_found:
            command = match.group(1).upper()
            args = match.group(2).strip()

            details: Dict[str, Any] = {
                "command": command,
            }

            # Parse command-specific data
            if command == "INFO":
                subcommand = args.split()[0].upper() if args.split() else ""
                details["subcommand"] = subcommand
                if subcommand == "ID" and is_server:
                    # Look for printer ID in the response
                    id_match = RE_PJL_INFO_ID_RESPONSE.search(text)
                    if id_match:
                        printer_id = id_match.group(1).strip().strip('"')
                        details["printer_id"] = printer_id
                        self.printer_ids[server_ip] = printer_id
                elif subcommand == "STATUS" and is_server:
                    code_match = RE_PJL_STATUS_CODE.search(text)
                    if code_match:
                        details["status_code"] = code_match.group(1)
                    display_match = RE_PJL_STATUS_DISPLAY.search(text)
                    if display_match:
                        details["status_display"] = display_match.group(1)

            elif command == "SET":
                var_match = RE_PJL_SET_VAR.search(args)
                if var_match:
                    var_name = var_match.group(1)
                    var_value = var_match.group(2)
                    details["variable_name"] = var_name
                    details["variable_value"] = var_value
                    self.env_vars.setdefault(server_ip, {})[var_name] = var_value

            elif command == "JOB":
                name_match = RE_PJL_JOB_NAME.search(args)
                if name_match:
                    details["job_name"] = name_match.group(1)

            elif command in PJL_FS_COMMANDS:
                details["is_fs_command"] = True
                name_match = RE_PJL_FSDIRLIST_NAME.search(args)
                if name_match:
                    details["fs_path"] = name_match.group(1)
                elif args:
                    details["fs_args"] = args.strip()

                # Track filesystem access
                if not is_server:
                    self.fs_access.append(
                        {
                            "client": client_ip,
                            "server": server_ip,
                            "command": command,
                            "path": details.get("fs_path", args.strip()),
                            "timestamp": now,
                        }
                    )
                    self.logger.warning(
                        f"PJL filesystem access: {client_ip} -> {server_ip} "
                        f"{command} {details.get('fs_path', args.strip())}"
                    )

            elif command == "EOJ":
                details["subcommand"] = "EOJ"

            # Build summary
            summary = f"PJL {command}"
            if details.get("subcommand"):
                summary += f" {details['subcommand']}"
            if details.get("printer_id"):
                summary += f' id="{details["printer_id"]}"'
            if details.get("job_name"):
                summary += f' job="{details["job_name"]}"'
            if details.get("fs_path"):
                summary += f' path="{details["fs_path"]}"'

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                f"PJL {command}",
                details,
                summary,
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Track devices
        self._update_server_device(server_ip, PJL_DEFAULT_PORT, dst_mac if is_server else src_mac)
        if is_valid_discovered_ip(client_ip):
            self._update_client_device(client_ip, server_ip, src_mac if is_server else dst_mac)

    def _get_tcp_payload(self, packet) -> Optional[bytes]:
        """Extract raw TCP payload from packet."""
        try:
            # Try data layer first (tshark puts raw payload here)
            if hasattr(packet, "data"):
                raw = self.get_field(packet.data, "data", None)
                if raw:
                    raw_str = str(raw).replace(":", "")
                    return bytes.fromhex(raw_str)

            # Try tcp.payload
            if hasattr(packet, "tcp"):
                payload = self.get_field(packet.tcp, "payload", None)
                if payload:
                    payload_str = str(payload).replace(":", "")
                    return bytes.fromhex(payload_str)
        except (ValueError, AttributeError) as e:
            self.logger.debug(f"if hasattr(packet, data):: {e}")
        return None

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _update_server_device(self, server_ip: str, server_port: int, server_mac: str = "") -> None:
        """Update or create PJL printer device entry."""
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"pjl-server:{server_ip}"
        vendor = lookup_mac_vendor(server_mac) if server_mac else ""

        printer_id = self.printer_ids.get(server_ip, "")
        name = printer_id or f"PJL Printer ({server_ip})"

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            mac=server_mac,
            name=name,
            device_type="Network Printer",
            manufacturer=vendor if vendor != "Unknown" else "",
        )

        protocol_data: Dict[str, Any] = {
            "role": "server",
            "port": server_port,
            "protocol": "PJL/TCP",
        }
        if printer_id:
            protocol_data["printer_id"] = printer_id
        env = self.env_vars.get(server_ip, {})
        if env:
            protocol_data["environment_variables"] = dict(env)

        device.pjl_passive_data = protocol_data

    def _update_client_device(self, client_ip: str, server_ip: str, client_mac: str = "") -> None:
        """Update or create PJL client device entry."""
        if not is_valid_discovered_ip(client_ip):
            return

        device_key = f"pjl-client:{client_ip}"
        vendor = lookup_mac_vendor(client_mac) if client_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            mac=client_mac,
            name=f"PJL Client ({client_ip})",
            device_type="Print Client",
            manufacturer=vendor if vendor != "Unknown" else "",
        )

        if is_new:
            device.pjl_passive_data = {
                "role": "client",
                "servers_accessed": [server_ip],
                "protocol": "PJL/TCP",
            }
        else:
            if device.pjl_passive_data:
                servers = device.pjl_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.pjl_passive_data["servers_accessed"] = servers

    # -------------------------------------------------------------------------
    # Harvest
    # -------------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data with PJL-specific tables and alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}

        tables = result.setdefault("tables", [])
        alerts = result.setdefault("alerts", [])

        # Printer identity table
        if self.printer_ids:
            rows = []
            for ip, printer_id in sorted(self.printer_ids.items()):
                env_count = len(self.env_vars.get(ip, {}))
                rows.append([ip, printer_id, str(env_count)])
            if rows:
                tables.append(
                    {
                        "headers": ["Server", "Printer ID", "Env Vars"],
                        "rows": rows,
                        "title": f"PJL Printers ({len(rows)})",
                    }
                )

        # Alert for filesystem access
        for fs in self.fs_access:
            alerts.append(
                {
                    "level": "fail",
                    "category": "fs_access_alert",
                    "message": (
                        f"PJL FILESYSTEM ACCESS: {fs['client']} -> {fs['server']} "
                        f"{fs['command']} {fs.get('path', '')}"
                    ),
                }
            )

        return result
