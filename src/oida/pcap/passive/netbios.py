"""
NetBIOS Passive Listener for Windows network discovery.

Passively captures NetBIOS traffic to extract:
- Computer names from NBNS name queries and registrations
- Domain/workgroup names
- NetBIOS name types (workstation, server, domain controller, etc.)
- IP-to-name mappings from NBNS responses
- Session service connections (port 139)

Security value:
- Windows network discovery (enumerate hosts/domains)
- NBNS poisoning detection (conflicting name registrations)
- Legacy SMB/NetBIOS service mapping

tshark fields used:
- nbns.name: NetBIOS name (encoded)
- nbns.type: Query type (NB=0x0020, NBSTAT=0x0021)
- nbns.addr: IP address in NB record
- nbns.flags: NBNS flags (response, opcode, etc.)
- nbns.count.queries: Number of questions
- nbns.count.answers: Number of answer RRs
- nbss.type: Session service message type
- nbss.length: Session service message length
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# NetBIOS name suffixes (16th byte)
NETBIOS_SUFFIXES = {
    "00": "Workstation Service",
    "01": "Messenger Service",
    "03": "Messenger Service",
    "06": "RAS Server Service",
    "1b": "Domain Master Browser",
    "1c": "Domain Controller",
    "1d": "Local Master Browser",
    "1e": "Browser Service Elections",
    "1f": "NetDDE Service",
    "20": "File Server Service",
    "21": "RAS Client Service",
    "be": "Network Monitor Agent",
    "bf": "Network Monitor Application",
}

# NBSS message types (hex string keys for XML mode, int keys for EK mode)
NBSS_TYPES = {
    "0x00": "Session Message",
    "0x81": "Session Request",
    "0x82": "Positive Response",
    "0x83": "Negative Response",
    "0x84": "Retarget Response",
    "0x85": "Session Keepalive",
    "0": "Session Message",
    "129": "Session Request",
    "130": "Positive Response",
    "131": "Negative Response",
    "132": "Retarget Response",
    "133": "Session Keepalive",
}


# NetBIOS Frames (LLC-based) command codes
NETBIOS_FRAME_COMMANDS = {
    "0x00": "Add Group Name",
    "0x01": "Add Name",
    "0x02": "Delete Name",
    "0x03": "Find Name",
    "0x04": "Status",
    "0x08": "Datagram",
    "0x09": "Datagram Broadcast",
    "0x0a": "Name Recognized",
    "0x0d": "Status Query",
    "0x0e": "Name Query",
    "0x0f": "Status Response",
    "0x13": "Reset",
    "0x14": "Session Initialize",
    "0x15": "No Receive",
    "0x16": "Receive Outstanding",
    "0x17": "Session Confirm",
    "0x18": "Session End",
    "0x19": "Data Ack",
    "0x1a": "Data First Middle",
    "0x1b": "Data Only Last",
    "0x1c": "Session Alive",
    # EK-mode decimal string keys
    "0": "Add Group Name",
    "1": "Add Name",
    "2": "Delete Name",
    "3": "Find Name",
    "4": "Status",
    "8": "Datagram",
    "9": "Datagram Broadcast",
    "10": "Name Recognized",
    "13": "Status Query",
    "14": "Name Query",
    "15": "Status Response",
    "19": "Reset",
    "20": "Session Initialize",
    "21": "No Receive",
    "22": "Receive Outstanding",
    "23": "Session Confirm",
    "24": "Session End",
    "25": "Data Ack",
    "26": "Data First Middle",
    "27": "Data Only Last",
    "28": "Session Alive",
}


class NetBIOSPassiveListener(PySharkListenerBase):
    """Passive NetBIOS traffic listener for Windows network discovery.

    Captures NBNS, NBSS, and NetBIOS datagram traffic to identify:
    - Windows computer names and workgroups
    - File servers and domain controllers
    - Name registration conflicts (potential NBNS poisoning)

    Usage:
        listener = NetBIOSPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for name, info in listener.name_table.items():
            print(f"{name}: {info['ip']} ({info['suffix_name']})")
    """

    PROTOCOL_NAME = "netbios"
    DISPLAY_FILTER = "nbns || nbss || netbios"
    REQUIRED_LAYERS = ("nbns", "nbss", "netbios")
    PROTOCOL_COLUMNS = ("type", "name", "suffix", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track NetBIOS name table: name -> {ip, suffix, suffix_name, ...}
        self.name_table: Dict[str, Dict[str, Any]] = {}
        self._seen_names: set = set()

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format NetBIOS interaction as protocol-specific table columns."""
        d = ix.details
        return [
            d.get("msg_type", "?"),
            d.get("name", "?"),
            d.get("suffix_name", ""),
            d.get("detail", ""),
        ]

    def process_packet(self, packet) -> None:
        """Process NetBIOS packet and extract names and services."""
        src_ip, dst_ip = self.get_ip_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        # NetBIOS Frames (LLC-based) may not have an IP layer
        if not src_ip and not dst_ip:
            # Fall back to MACs for L2-only NetBIOS frames
            if not src_mac and not dst_mac:
                return
            src_ip = src_mac
            dst_ip = dst_mac

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)

        handled = False

        # Process NBNS (Name Service, port 137)
        if hasattr(packet, "nbns"):
            self._process_nbns(
                packet, src_ip, dst_ip, flow_id, src_port, dst_port, src_mac, dst_mac
            )
            handled = True

        # Process NBSS (Session Service, port 139)
        if hasattr(packet, "nbss"):
            self._process_nbss(
                packet, src_ip, dst_ip, flow_id, src_port, dst_port, src_mac, dst_mac
            )
            handled = True

        # Process NetBIOS Frames (LLC-based, no IP layer)
        if hasattr(packet, "netbios") and not handled:
            self._process_netbios_frame(
                packet, src_ip, dst_ip, flow_id, src_port, dst_port, src_mac, dst_mac
            )

    def _process_nbns(
        self,
        packet,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
    ) -> None:
        """Process NBNS name service packet."""
        nbns = packet.nbns

        # Extract name
        name_raw = self.get_field(nbns, "name", "")
        name = self._clean_netbios_name(str(name_raw)) if name_raw else ""

        # Extract flags to determine if this is a query or response
        flags_raw = self.get_field(nbns, "flags", "")
        flags_str = str(flags_raw)

        # Check answer count to determine direction
        answers = self.get_field(nbns, "count_answers", "0")

        is_response = False
        try:
            is_response = int(str(answers)) > 0
        except (ValueError, TypeError):
            # Try flag-based detection
            try:
                flags_int = int(flags_str, 0)
                is_response = bool(flags_int & 0x8000)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get flags_int: {e}")

        # Extract address from response
        addr = str(self.get_field(nbns, "addr", "") or "")

        # Determine operation type
        nb_type = str(self.get_field(nbns, "type", "") or "")

        if is_response:
            if addr:
                msg_type = "Name Response"
                detail = f"-> {addr}"
            else:
                msg_type = "Name Response"
                detail = ""
        else:
            try:
                flags_int = int(flags_str, 0)
                opcode = (flags_int >> 11) & 0xF
                if opcode == 5:
                    msg_type = "Name Registration"
                    detail = "registering"
                elif opcode == 0:
                    msg_type = "Name Query"
                    detail = "querying"
                else:
                    msg_type = "Name Query"
                    detail = ""
            except (ValueError, TypeError):
                msg_type = "Name Query"
                detail = ""

        # Parse name suffix
        suffix, suffix_name = self._parse_name_suffix(name)

        direction = "response" if is_response else "request"
        operation = f"NBNS {msg_type}"

        details: Dict[str, Any] = {
            "msg_type": msg_type,
            "name": name,
            "suffix": suffix,
            "suffix_name": suffix_name,
            "addr": addr,
            "nb_type": nb_type,
            "flags": flags_str,
            "detail": detail,
        }

        now = datetime.now().isoformat()
        summary = f"NBNS {msg_type} {name}"
        if addr:
            summary += f" -> {addr}"
        if suffix_name:
            summary += f" ({suffix_name})"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Record name-to-IP mapping
        if name:
            self._record_name(name, addr or src_ip, suffix, suffix_name, src_mac)

        # Track devices
        if is_valid_discovered_ip(src_ip):
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            device_name = self._strip_suffix(name) if name else ""
            self._ensure_device(
                f"netbios:{src_ip}",
                src_ip,
                mac=src_mac or "",
                name=device_name,
                device_type="NetBIOS Host",
                manufacturer=vendor if vendor != "Unknown" else "",
                data_attr="netbios_passive_data",
                protocol_data={
                    "role": "responder" if is_response else "requester",
                    "names": [name] if name else [],
                    "protocol": "NetBIOS/UDP",
                },
            )

        if is_valid_discovered_ip(dst_ip) and dst_ip != "255.255.255.255":
            dst_vendor = lookup_mac_vendor(dst_mac) if dst_mac else ""
            self._ensure_device(
                f"netbios:{dst_ip}",
                dst_ip,
                mac=dst_mac or "",
                device_type="NetBIOS Host",
                manufacturer=dst_vendor if dst_vendor != "Unknown" else "",
                data_attr="netbios_passive_data",
                protocol_data={
                    "role": "requester" if is_response else "responder",
                    "protocol": "NetBIOS/UDP",
                },
            )

    def _process_nbss(
        self,
        packet,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
    ) -> None:
        """Process NBSS session service packet."""
        nbss = packet.nbss

        msg_type_raw = self.get_field(nbss, "type", "")
        msg_type_str = str(msg_type_raw)
        msg_type_name = NBSS_TYPES.get(msg_type_str, f"type={msg_type_str}")

        length = str(self.get_field(nbss, "length", "0") or "0")

        is_request = msg_type_str in ("0x81", "129")
        direction = "request" if is_request else "response"
        operation = f"NBSS {msg_type_name}"

        details: Dict[str, Any] = {
            "msg_type": msg_type_name,
            "name": "",
            "suffix": "",
            "suffix_name": "",
            "detail": f"len={length}",
            "nbss_type": msg_type_str,
            "nbss_length": length,
        }

        now = datetime.now().isoformat()
        summary = f"NBSS {msg_type_name} {src_ip} -> {dst_ip} (len={length})"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Track session endpoints
        if is_valid_discovered_ip(src_ip):
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            self._ensure_device(
                f"netbios:{src_ip}",
                src_ip,
                mac=src_mac or "",
                device_type="NetBIOS Host",
                manufacturer=vendor if vendor != "Unknown" else "",
                data_attr="netbios_passive_data",
                protocol_data={
                    "role": "client" if is_request else "server",
                    "protocol": "NetBIOS/TCP",
                },
            )

        if is_valid_discovered_ip(dst_ip):
            dst_vendor = lookup_mac_vendor(dst_mac) if dst_mac else ""
            self._ensure_device(
                f"netbios:{dst_ip}",
                dst_ip,
                mac=dst_mac or "",
                device_type="NetBIOS Host",
                manufacturer=dst_vendor if dst_vendor != "Unknown" else "",
                data_attr="netbios_passive_data",
                protocol_data={
                    "role": "server" if is_request else "client",
                    "protocol": "NetBIOS/TCP",
                },
            )

    def _clean_netbios_name(self, raw_name: str) -> str:
        """Clean NetBIOS name from tshark output."""
        if not raw_name:
            return ""
        # Remove surrounding quotes
        name = raw_name.strip()
        if name.startswith('"') and name.endswith('"'):
            name = name[1:-1]
        # Remove trailing spaces in NetBIOS names
        return name.rstrip()

    def _strip_suffix(self, name: str) -> str:
        """Strip the NetBIOS suffix from a name like 'MYPC<20>'."""
        if "<" in name:
            return name.split("<")[0].strip()
        return name.strip()

    def _parse_name_suffix(self, name: str) -> tuple:
        """Parse NetBIOS name suffix (e.g. MYPC<20> -> ('20', 'File Server Service'))."""
        if "<" in name and ">" in name:
            try:
                suffix = name.split("<")[1].split(">")[0].lower()
                suffix_name = NETBIOS_SUFFIXES.get(suffix, "")
                return suffix, suffix_name
            except (IndexError, ValueError) as e:
                self.logger.debug(f"Failed to get suffix: {e}")
        return "", ""

    def _process_netbios_frame(
        self,
        packet,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
    ) -> None:
        """Process LLC-based NetBIOS frame (no IP layer, uses MAC addresses).

        These are NetBIOS Frames protocol packets (not NBNS/NBSS) carried
        over LLC (SAP 0xF0).  They contain name management and datagram
        commands identified by the ``netbios.command`` field.
        """
        nb = packet.netbios

        cmd_raw = str(self.get_field(nb, "command", "") or "")
        cmd_name = NETBIOS_FRAME_COMMANDS.get(cmd_raw, "")
        if not cmd_name:
            # Try hex-prefixed lookup for EK-mode decimal values
            try:
                cmd_hex = hex(int(cmd_raw))
                cmd_name = NETBIOS_FRAME_COMMANDS.get(cmd_hex, f"cmd={cmd_raw}")
            except (ValueError, TypeError):
                cmd_name = f"cmd={cmd_raw}" if cmd_raw else "Unknown"

        # Extract NetBIOS name(s) -- may be comma-separated in EK mode
        nb_name_raw = str(self.get_field(nb, "nb_name", "") or "")
        nb_name_type_raw = str(self.get_field(nb, "nb_name_type", "") or "")

        # Parse names and types (may be multi-valued for datagrams)
        names = [n.strip() for n in nb_name_raw.split(",") if n.strip()] if nb_name_raw else []
        types = (
            [t.strip() for t in nb_name_type_raw.split(",") if t.strip()]
            if nb_name_type_raw
            else []
        )

        # Build display name with suffix
        display_name = ""
        suffix = ""
        suffix_name = ""
        if names:
            display_name = names[0]
            if types:
                # Convert type to hex suffix for lookup
                try:
                    type_int = int(types[0], 0)
                    suffix = f"{type_int:02x}"
                    suffix_name = NETBIOS_SUFFIXES.get(suffix, "")
                    display_name = f"{names[0]}<{suffix}>"
                except (ValueError, TypeError):
                    suffix = types[0]

        direction = "request"
        operation = f"NetBIOS {cmd_name}"

        detail_parts = []
        if len(names) > 1:
            detail_parts.append(f"names={','.join(names)}")
        if suffix_name:
            detail_parts.append(suffix_name)
        detail = "; ".join(detail_parts) if detail_parts else ""

        details: Dict[str, Any] = {
            "msg_type": cmd_name,
            "name": display_name,
            "suffix": suffix,
            "suffix_name": suffix_name,
            "command": cmd_raw,
            "nb_names": names,
            "nb_name_types": types,
            "detail": detail,
        }

        now = datetime.now().isoformat()
        summary = f"NetBIOS {cmd_name}"
        if display_name:
            summary += f" {display_name}"
        if suffix_name:
            summary += f" ({suffix_name})"
        summary += f" {src_ip} -> {dst_ip}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Record name mappings
        for i, name in enumerate(names):
            name_type = types[i] if i < len(types) else ""
            try:
                type_int = int(name_type, 0)
                sfx = f"{type_int:02x}"
            except (ValueError, TypeError):
                sfx = name_type
            sfx_name = NETBIOS_SUFFIXES.get(sfx, "")
            full_name = f"{name}<{sfx}>" if sfx else name
            self._record_name(full_name, src_ip, sfx, sfx_name, src_mac)

        # Track source device (using MAC since these are L2-only)
        if src_mac:
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            device_name = names[0] if names else ""
            self._ensure_device(
                f"netbios:{src_ip}",
                src_ip,
                mac=src_mac or "",
                name=device_name,
                device_type="NetBIOS Host",
                manufacturer=vendor if vendor != "Unknown" else "",
                data_attr="netbios_passive_data",
                protocol_data={
                    "role": "requester",
                    "names": names,
                    "protocol": "NetBIOS/LLC",
                },
            )

    def _record_name(
        self,
        name: str,
        ip: str,
        suffix: str,
        suffix_name: str,
        mac: str,
    ) -> None:
        """Record a NetBIOS name mapping."""
        clean_name = self._strip_suffix(name)
        if not clean_name:
            return

        key = f"{clean_name}:{suffix}"
        if key in self._seen_names:
            return
        self._seen_names.add(key)

        self.name_table[key] = {
            "name": clean_name,
            "full_name": name,
            "ip": ip,
            "suffix": suffix,
            "suffix_name": suffix_name,
            "mac": mac,
            "timestamp": datetime.now().isoformat(),
        }

        self.logger.debug(f"NetBIOS name: {clean_name} ({suffix_name or suffix}) -> {ip}")
