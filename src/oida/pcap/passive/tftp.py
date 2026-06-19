"""
TFTP Passive Listener for file transfer tracking.

Passively captures TFTP traffic to extract:
- Read requests (RRQ) with filenames
- Write requests (WRQ) with filenames
- DATA blocks with block numbers
- ACK packets with block numbers
- ERROR packets with error codes and messages
- Transfer mode (octet/netascii)

TFTP (RFC 1350) uses UDP port 69 for initial requests.
No authentication -- only file operations are tracked.

tshark fields used:
- tftp.opcode: 1=RRQ, 2=WRQ, 3=DATA, 4=ACK, 5=ERROR
- tftp.source_file: filename in RRQ
- tftp.destination_file: filename in WRQ or DATA
- tftp.type: transfer mode
- tftp.blocknum: block number in DATA/ACK
- tftp.error_code: error code in ERROR
- tftp.error_string: error message in ERROR
"""

from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor


class TFTPPassiveListener(PySharkListenerBase):
    """Passive TFTP traffic listener for file transfer tracking.

    Captures TFTP read/write requests to identify what files are being
    transferred and between which hosts.

    Usage:
        listener = TFTPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for op in listener.get_file_operations():
            print(f"{op['operation']}: {op['filename']}")
    """

    PROTOCOL_NAME = "tftp"
    DISPLAY_FILTER = "tftp"
    REQUIRED_LAYERS = ("tftp",)
    PROTOCOL_COLUMNS = ("operation", "filename", "mode", "source", "dest")
    TFTP_RRQ = 1
    TFTP_WRQ = 2
    TFTP_DATA = 3
    TFTP_ACK = 4
    TFTP_ERROR = 5
    TFTP_OPCODES = {1: "RRQ", 2: "WRQ", 3: "DATA", 4: "ACK", 5: "ERROR"}

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.file_operations: List[Dict[str, str]] = []
        # Per-flow TFTP server IP, learned from the initial RRQ/WRQ (the
        # request destination is always the server). Used to attribute DATA
        # direction: RRQ download => server sends DATA; WRQ upload => client
        # sends DATA. Keyed by the direction-independent flow_id.
        self._flow_server_ip: Dict[str, str] = {}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format TFTP interaction as protocol-specific table columns."""
        d = ix.details
        operation = d.get("operation", "?")

        # Build a meaningful "filename" column depending on opcode type
        if operation in ("Download", "Upload"):
            filename = d.get("filename", "?")
        elif operation == "DATA":
            block = d.get("block", "?")
            fname = d.get("filename", "")
            filename = f"block {block}" + (f" ({fname})" if fname else "")
        elif operation == "ACK":
            filename = f"block {d.get('block', '?')}"
        elif operation == "ERROR":
            filename = f"code {d.get('error_code', '?')}: {d.get('error_message', '?')}"
        else:
            filename = "?"

        return [
            operation,
            filename,
            d.get("mode", ""),
            ix.src_ip,
            ix.dst_ip,
        ]

    def process_packet(self, packet) -> None:
        """Process TFTP packet and extract file operation info.

        Handles all 5 TFTP opcodes:
        - RRQ (1): Read request with filename
        - WRQ (2): Write request with filename
        - DATA (3): Data block with block number
        - ACK (4): Acknowledgement with block number
        - ERROR (5): Error with code and message
        """
        if not hasattr(packet, "tftp"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        tftp = packet.tftp
        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        opcode_raw = self.get_field(tftp, "opcode")
        if opcode_raw is None:
            return

        try:
            opcode = int(opcode_raw)
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to get opcode: {e}")
            return

        opcode_name = self.TFTP_OPCODES.get(opcode, f"UNKNOWN({opcode})")
        now = self._get_timestamp()

        ports = {"src_port": src_port, "dst_port": dst_port}
        if opcode == self.TFTP_RRQ:
            self._process_rrq(tftp, src_ip, dst_ip, src_mac, dst_mac, flow_id, now, **ports)
        elif opcode == self.TFTP_WRQ:
            self._process_wrq(tftp, src_ip, dst_ip, src_mac, dst_mac, flow_id, now, **ports)
        elif opcode == self.TFTP_DATA:
            self._process_data(tftp, src_ip, dst_ip, src_mac, dst_mac, flow_id, now, **ports)
        elif opcode == self.TFTP_ACK:
            self._process_ack(tftp, src_ip, dst_ip, src_mac, dst_mac, flow_id, now, **ports)
        elif opcode == self.TFTP_ERROR:
            self._process_error(tftp, src_ip, dst_ip, src_mac, dst_mac, flow_id, now, **ports)
        else:
            # Unknown opcode -- still record an interaction so no packet is dropped
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                f"TFTP {opcode_name}",
                {"opcode": opcode, "operation": opcode_name},
                f"TFTP unknown opcode {opcode}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
            )
            self.logger.debug(f"Unknown TFTP opcode {opcode} from {src_ip} -> {dst_ip}")

    def _process_rrq(
        self,
        tftp,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        now: str,
        src_port: int = 0,
        dst_port: int = 0,
    ) -> None:
        """Handle RRQ (opcode 1) -- client requests file download."""
        # The request destination is the TFTP server for this flow.
        if flow_id:
            self._flow_server_ip[flow_id] = dst_ip

        filename = self.get_field(tftp, "source_file", "")
        filename = str(filename).strip() if filename else ""
        if not filename:
            filename = "?"
            self.logger.debug(f"Missing filename in TFTP RRQ from {src_ip} -> {dst_ip}")

        mode = str(self.get_field(tftp, "type", "")).strip()
        if not mode:
            mode = "?"
            self.logger.debug(f"Missing transfer mode in TFTP RRQ from {src_ip} -> {dst_ip}")

        self.file_operations.append(
            {
                "operation": "Download",
                "filename": filename,
                "source_ip": src_ip,
                "dest_ip": dst_ip,
            }
        )

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "TFTP Download",
            {"filename": filename, "mode": mode, "operation": "Download"},
            f"TFTP Download {filename}" + (f" ({mode})" if mode != "?" else ""),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        self._track_devices(src_ip, dst_ip, src_mac, dst_mac)
        self.logger.debug(f"TFTP: Download {filename} ({src_ip} -> {dst_ip})")

    def _process_wrq(
        self,
        tftp,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        now: str,
        src_port: int = 0,
        dst_port: int = 0,
    ) -> None:
        """Handle WRQ (opcode 2) -- client requests file upload."""
        # The request destination is the TFTP server for this flow.
        if flow_id:
            self._flow_server_ip[flow_id] = dst_ip

        filename = self.get_field(tftp, "destination_file", "")
        filename = str(filename).strip() if filename else ""
        if not filename:
            filename = "?"
            self.logger.debug(f"Missing filename in TFTP WRQ from {src_ip} -> {dst_ip}")

        mode = str(self.get_field(tftp, "type", "")).strip()
        if not mode:
            mode = "?"
            self.logger.debug(f"Missing transfer mode in TFTP WRQ from {src_ip} -> {dst_ip}")

        self.file_operations.append(
            {
                "operation": "Upload",
                "filename": filename,
                "source_ip": src_ip,
                "dest_ip": dst_ip,
            }
        )

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "TFTP Upload",
            {"filename": filename, "mode": mode, "operation": "Upload"},
            f"TFTP Upload {filename}" + (f" ({mode})" if mode != "?" else ""),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        self._track_devices(src_ip, dst_ip, src_mac, dst_mac)
        self.logger.debug(f"TFTP: Upload {filename} ({src_ip} -> {dst_ip})")

    def _process_data(
        self,
        tftp,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        now: str,
        src_port: int = 0,
        dst_port: int = 0,
    ) -> None:
        """Handle DATA (opcode 3) -- data block (server->client on RRQ download,
        client->server on WRQ upload)."""
        # Determine DATA direction from the transfer learned at RRQ/WRQ time.
        # The TFTP server replies from an ephemeral TID port, so the DATA flow_id
        # need not match the request's; correlate by the server IP (the request
        # destination) instead. If either endpoint of this DATA packet is a known
        # server, the server is whichever endpoint matches; otherwise fall back to
        # the common RRQ-download case of server-as-source.
        known_servers = set(self._flow_server_ip.values())
        if src_ip in known_servers:
            server_is_src = True
        elif dst_ip in known_servers:
            server_is_src = False
        else:
            server_is_src = True

        block_raw = self.get_field(tftp, "blocknum", "")
        block = str(block_raw).strip() if block_raw else "?"
        if not block or block == "":
            block = "?"
            self.logger.debug(f"Missing block number in TFTP DATA from {src_ip} -> {dst_ip}")

        # tshark may provide the filename being transferred on DATA packets
        filename = self.get_field(tftp, "destination_file", "")
        filename = str(filename).strip() if filename else ""

        details: Dict[str, Any] = {
            "operation": "DATA",
            "block": block,
        }
        if filename:
            details["filename"] = filename

        summary = f"TFTP DATA block {block}"
        if filename:
            summary += f" ({filename})"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "TFTP DATA",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        self._track_devices(src_ip, dst_ip, src_mac, dst_mac, server_is_src=server_is_src)
        self.logger.debug(f"TFTP: DATA block {block} ({src_ip} -> {dst_ip})")

    def _process_ack(
        self,
        tftp,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        now: str,
        src_port: int = 0,
        dst_port: int = 0,
    ) -> None:
        """Handle ACK (opcode 4) -- receiver acknowledges data block."""
        block_raw = self.get_field(tftp, "blocknum", "")
        block = str(block_raw).strip() if block_raw else "?"
        if not block or block == "":
            block = "?"
            self.logger.debug(f"Missing block number in TFTP ACK from {src_ip} -> {dst_ip}")

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "TFTP ACK",
            {"operation": "ACK", "block": block},
            f"TFTP ACK block {block}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        self.logger.debug(f"TFTP: ACK block {block} ({src_ip} -> {dst_ip})")

    def _process_error(
        self,
        tftp,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        now: str,
        src_port: int = 0,
        dst_port: int = 0,
    ) -> None:
        """Handle ERROR (opcode 5) -- error response."""
        error_code_raw = self.get_field(tftp, "error_code", "")
        error_code = str(error_code_raw).strip() if error_code_raw else "?"
        if not error_code or error_code == "":
            error_code = "?"
            self.logger.debug(f"Missing error code in TFTP ERROR from {src_ip} -> {dst_ip}")

        error_msg = self.get_field(tftp, "error_string", "")
        error_msg = str(error_msg).strip() if error_msg else ""
        if not error_msg:
            error_msg = "?"
            self.logger.debug(f"Missing error message in TFTP ERROR from {src_ip} -> {dst_ip}")

        summary = f"TFTP ERROR {error_code}: {error_msg}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "TFTP ERROR",
            {
                "operation": "ERROR",
                "error_code": error_code,
                "error_message": error_msg,
            },
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        self._track_devices(src_ip, dst_ip, src_mac, dst_mac)
        self.logger.debug(f"TFTP: ERROR {error_code}: {error_msg} ({src_ip} -> {dst_ip})")

    def _track_devices(
        self,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        server_is_src: bool = False,
    ) -> None:
        """Track both client and server devices.

        For requests (RRQ/WRQ/ACK) the destination is the TFTP server. For
        server-originated traffic (DATA), pass ``server_is_src=True`` so the
        source is labelled the server.
        """
        if server_is_src:
            server_ip, server_mac = src_ip, src_mac
            client_ip, client_mac = dst_ip, dst_mac
        else:
            server_ip, server_mac = dst_ip, dst_mac
            client_ip, client_mac = src_ip, src_mac

        if is_valid_discovered_ip(server_ip):
            server_vendor = lookup_mac_vendor(server_mac) if server_mac else ""
            self._ensure_device(
                f"tftp-server:{server_ip}",
                server_ip,
                mac=server_mac or "",
                name=f"TFTP Server ({server_ip})",
                device_type="TFTP Server",
                manufacturer=server_vendor if server_vendor != "Unknown" else "",
            )
        if is_valid_discovered_ip(client_ip):
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            self._ensure_device(
                f"tftp-client:{client_ip}",
                client_ip,
                mac=client_mac or "",
                name=f"TFTP Client ({client_ip})",
                device_type="TFTP Client",
                manufacturer=client_vendor if client_vendor != "Unknown" else "",
            )

    def get_file_operations(self) -> List[Dict[str, str]]:
        """Get file operations extracted from TFTP requests."""
        return self.file_operations
