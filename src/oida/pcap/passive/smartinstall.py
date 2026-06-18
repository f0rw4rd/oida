"""
Cisco Smart Install Passive Listener for network infrastructure discovery.

Passively captures Cisco Smart Install traffic to identify:
- Cisco switches using Smart Install protocol
- Smart Install Director (server) and Client (switch) roles
- Protocol version and operation types
- Potential CVE-2018-0171 exposure

Cisco Smart Install uses:
- TCP port: 4786
- Custom binary protocol

Message types (from Smart Install header):
- Type 1: Image list request/response
- Type 2: Copy/execute configuration operations

Smart Install header format (first 4 bytes):
- Version (4 bytes): Protocol version (usually 0x00000001)
- Length (4 bytes): Total message length
- Type (4 bytes): Operation type
- Data (variable): Operation-specific data

Security value for ICS:
- CVE-2018-0171: Remote code execution via Smart Install
- Network infrastructure enumeration
- Configuration extraction risk
- Switch identification and version fingerprinting

Note: tshark has limited Smart Install dissection. This listener
uses TCP port-based detection and parses the binary protocol header
directly from raw payload data when available.
"""

import struct
from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# Smart Install constants
SMART_INSTALL_PORT = 4786

# Smart Install operation types
SMI_TYPES = {
    1: "IMAGE_LIST",
    2: "COPY_CONFIG",
    3: "WRITE_FLASH",
    4: "READ_CONFIG",
}

# Smart Install magic bytes (first 4 bytes of protocol)
SMI_VERSION_V1 = 0x00000001


class SmartInstallPassiveListener(PySharkListenerBase):
    """Passive Cisco Smart Install traffic listener.

    Captures Smart Install traffic on TCP port 4786 to identify:
    - Cisco switches with Smart Install enabled
    - Director (server) and Client (switch) roles
    - Operation types (config copy, image list)
    - CVE-2018-0171 exposure indicators

    Usage:
        listener = SmartInstallPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "smartinstall"
    DISPLAY_FILTER = "tcp.port == 4786"
    REQUIRED_LAYERS = ("tcp",)
    PROTOCOL_COLUMNS = (
        "operation",
        "version",
        "length",
        "detail",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)

    def should_process_packet(self, packet) -> bool:
        """Check if packet is Smart Install traffic (TCP port 4786)."""
        if not hasattr(packet, "tcp"):
            return False
        try:
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)
            return src_port == SMART_INSTALL_PORT or dst_port == SMART_INSTALL_PORT
        except (ValueError, AttributeError) as e:
            self.logger.debug(f"Failed to get src_port: {e}")
            return False

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format Smart Install interaction as protocol-specific table columns."""
        d = ix.details
        operation = d.get("operation_name", "") or d.get("operation", "?")
        version = d.get("version", "?")
        length = d.get("length", "?")
        detail = d.get("detail", "") or "-"
        return [
            operation,
            version,
            length,
            detail,
        ]

    def process_packet(self, packet) -> None:
        """Process Smart Install packet and extract protocol information."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        stream_id = self.get_stream_id(packet)

        # Determine direction based on port
        is_from_server = src_port == SMART_INSTALL_PORT
        direction = "response" if is_from_server else "request"

        # Try to parse Smart Install header from raw payload
        smi_info = self._parse_smart_install_payload(packet)

        operation_name = "Connection"
        version_str = "?"
        length_str = "?"
        detail = ""

        if smi_info:
            version_str = str(smi_info.get("version", "?"))
            length_str = str(smi_info.get("length", "?"))
            op_type = smi_info.get("type", 0)
            operation_name = SMI_TYPES.get(op_type, f"Type-{op_type}")
            detail = smi_info.get("detail", "")
        else:
            # TCP SYN/ACK or data without parseable SMI header
            tcp_flags = str(self.get_field(packet.tcp, "flags", "") or "")
            if "0x002" in tcp_flags or "S" in tcp_flags.upper():
                operation_name = "SYN"
                detail = "TCP handshake"
            elif "0x012" in tcp_flags:
                operation_name = "SYN-ACK"
                detail = "TCP handshake"
                direction = "response"
            elif "0x010" in tcp_flags:
                operation_name = "ACK"
                detail = "TCP handshake"

        # Build interaction details
        details: Dict[str, Any] = {
            "operation": operation_name,
            "operation_name": operation_name,
            "version": version_str,
            "length": length_str,
            "detail": detail,
            "src_port": src_port,
            "dst_port": dst_port,
        }
        if smi_info:
            details["type_code"] = smi_info.get("type", 0)
            details["raw_version"] = smi_info.get("version", 0)

        now = datetime.now().isoformat()
        summary = f"SmartInstall {operation_name} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"SMI {operation_name}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Update device tracking
        self._update_devices(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            operation_name,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    def _parse_smart_install_payload(self, packet) -> Optional[Dict[str, Any]]:
        """Parse Smart Install protocol header from raw TCP payload.

        Smart Install header:
        - Bytes 0-3: Version (uint32, big-endian)
        - Bytes 4-7: Length (uint32, big-endian)
        - Bytes 8-11: Type (uint32, big-endian)

        Returns parsed fields or None if payload is not parseable.
        """
        try:
            # Try to get raw payload data
            payload = None
            if hasattr(packet, "data"):
                data_raw = self.get_field(packet.data, "data", None)
                if data_raw:
                    payload = bytes.fromhex(str(data_raw).replace(":", ""))
            if payload is None or len(payload) < 12:
                # Try TCP payload
                tcp_payload = self.get_field(packet.tcp, "payload", None)
                if tcp_payload:
                    payload = bytes.fromhex(str(tcp_payload).replace(":", ""))

            if payload is None or len(payload) < 12:
                return None

            version, length, msg_type = struct.unpack("!III", payload[:12])

            # Validate: version should be 1
            if version not in (0, 1, 2):
                return None

            result: Dict[str, Any] = {
                "version": version,
                "length": length,
                "type": msg_type,
            }

            # Add detail based on type
            if msg_type in SMI_TYPES:
                result["detail"] = f"op={SMI_TYPES[msg_type]}"
            else:
                result["detail"] = f"type={msg_type}"

            return result

        except Exception as e:
            self.logger.debug(f"Operation failed: {e}")
            return None

    def _update_devices(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        operation: str,
        src_mac: str = "",
        dst_mac: str = "",
    ) -> None:
        """Update device entries for Smart Install participants."""
        # The device sending TO port 4786 is the director/client
        # The device listening ON port 4786 is the switch/server
        if dst_port == SMART_INSTALL_PORT:
            director_ip = src_ip
            switch_ip = dst_ip
            director_mac = src_mac
            switch_mac = dst_mac
        else:
            director_ip = dst_ip
            switch_ip = src_ip
            director_mac = dst_mac
            switch_mac = src_mac

        if is_valid_discovered_ip(switch_ip):
            vendor = lookup_mac_vendor(switch_mac) if switch_mac else ""
            device, is_new = self._ensure_device(
                f"smi-switch:{switch_ip}",
                switch_ip,
                mac=switch_mac,
                name="",
                device_type="Cisco Switch (Smart Install)",
                manufacturer=vendor if vendor != "Unknown" else "Cisco",
            )
            if is_new:
                device.smartinstall_data = {
                    "role": "client",
                    "protocol": "SmartInstall/TCP",
                    "port": SMART_INSTALL_PORT,
                    "cve_2018_0171": True,
                }
                self.logger.warning(
                    f"Smart Install: Cisco switch at {switch_ip}:{SMART_INSTALL_PORT} "
                    f"(CVE-2018-0171 potential)"
                )

        if is_valid_discovered_ip(director_ip):
            vendor = lookup_mac_vendor(director_mac) if director_mac else ""
            device, is_new = self._ensure_device(
                f"smi-director:{director_ip}",
                director_ip,
                mac=director_mac,
                name="",
                device_type="Smart Install Director",
                manufacturer=vendor if vendor != "Unknown" else "",
            )
            if is_new:
                device.smartinstall_data = {
                    "role": "director",
                    "protocol": "SmartInstall/TCP",
                }
