"""
iSCSI Passive Listener for storage area network discovery.

Passively captures iSCSI traffic to extract:
- Target IQN names (fully qualified target identifiers)
- Initiator IQN names
- LUN numbers being accessed
- Authentication methods (CHAP, None)
- Login phase parameters
- Data operations (SCSI READ/WRITE, Task Management)

iSCSI is security-relevant because:
- Target names reveal storage infrastructure
- Unauthenticated access allows data theft
- LUN enumeration reveals storage topology
- CHAP credentials may be weak or reused
- Data operations reveal what is being accessed

tshark fields used (packet.iscsi.*):
- iscsi.opcode: iSCSI opcode (login, text, SCSI command, etc.)
- iscsi.login.target_name: Target IQN (in login/text key-value data)
- iscsi.login.initiator_name: Initiator IQN
- iscsi.login.auth_method: Authentication method
- iscsi.login.session_type: Session type (Normal, Discovery)
- iscsi.login.status: Login response status
- iscsi.isid: Initiator Session ID
- iscsi.datasegmentlength: Data payload length
- iscsi.scsicommand.R / .W: Read/Write flags
- iscsi.scsicommand.expecteddatatransferlength: Transfer size
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# iSCSI opcode mapping.
# Values are the 6-bit opcode (BHS byte 0 masked with 0x3f), which is exactly
# what tshark exposes as iscsi.opcode (FT_UINT8, mask 0x3f, BASE_HEX).
# Verified against RFC 7143 and Linux iscsi_proto.h:
#   R2T = 0x31 (49), Asynchronous Message = 0x32 (50), Reject = 0x3f (63).
# Both decimal- and hex-keyed forms are kept so either tshark string form resolves.
OPCODES = {
    "0": "NOP-Out",
    "1": "SCSI Command",
    "2": "Task Management Request",
    "3": "Login Request",
    "4": "Text Request",
    "5": "Data-Out",
    "6": "Logout Request",
    "16": "SNACK Request",
    "32": "NOP-In",
    "33": "SCSI Response",
    "34": "Task Management Response",
    "35": "Login Response",
    "36": "Text Response",
    "37": "Data-In",
    "38": "Logout Response",
    "49": "R2T",
    "50": "Async Message",
    "63": "Reject",
    # Hex values commonly seen
    "0x00": "NOP-Out",
    "0x01": "SCSI Command",
    "0x02": "Task Management Request",
    "0x03": "Login Request",
    "0x04": "Text Request",
    "0x05": "Data-Out",
    "0x06": "Logout Request",
    "0x10": "SNACK Request",
    "0x20": "NOP-In",
    "0x21": "SCSI Response",
    "0x22": "Task Management Response",
    "0x23": "Login Response",
    "0x24": "Text Response",
    "0x25": "Data-In",
    "0x26": "Logout Response",
    "0x31": "R2T",
    "0x32": "Async Message",
    "0x3f": "Reject",
}

# Response opcodes (from target)
RESPONSE_OPCODES = {
    "32",
    "33",
    "34",
    "35",
    "36",
    "37",
    "38",
    "49",
    "50",
    "63",
    "0x20",
    "0x21",
    "0x22",
    "0x23",
    "0x24",
    "0x25",
    "0x26",
    "0x31",
    "0x32",
    "0x3f",
    "NOP-In",
    "SCSI Response",
    "Task Management Response",
    "Login Response",
    "Text Response",
    "Data-In",
    "Logout Response",
    "R2T",
    "Async Message",
    "Reject",
}

# Login status codes
LOGIN_STATUS = {
    "0": "Success",
    "0x0000": "Success",
    "0x0100": "Target moved temporarily",
    "0x0101": "Target moved permanently",
    "0x0200": "Initiator error",
    "0x0201": "Authentication failure",
    "0x0202": "Authorization failure",
    "0x0203": "Not found",
    "0x0204": "Target removed",
    "0x0205": "Unsupported version",
    "0x0206": "Too many connections",
    "0x0207": "Missing parameter",
    "0x0208": "Can't include in session",
    "0x0209": "Session type not supported",
    "0x020a": "Session does not exist",
    "0x020b": "Invalid during login",
    "0x0300": "Target error",
    "0x0301": "Service unavailable",
    "0x0302": "Out of resources",
}


class ISCSIPassiveListener(PySharkListenerBase):
    """Passive iSCSI traffic listener for storage area network discovery.

    Captures iSCSI traffic to extract:
    - Target and initiator IQN names
    - LUN numbers being accessed
    - Authentication methods
    - Login/logout sessions
    - SCSI command operations

    Usage:
        listener = ISCSIPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for ix in listener.interactions:
            print(f"{ix.operation}: {ix.details}")
    """

    PROTOCOL_NAME = "iscsi"
    DISPLAY_FILTER = "iscsi"
    REQUIRED_LAYERS = ("iscsi",)
    PROTOCOL_COLUMNS = ("opcode", "target_initiator", "lun", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track discovered target names
        self.target_names: Dict[str, set] = {}  # server_ip -> set of target IQNs
        self.initiator_names: Dict[str, set] = {}  # client_ip -> set of initiator IQNs
        # Track auth methods
        self.auth_methods: Dict[str, set] = {}  # server_ip -> set of auth methods

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format iSCSI interaction as protocol-specific table columns."""
        d = ix.details
        opcode = d.get("opcode_name", "?")
        # Show target or initiator name, whichever is available
        name = d.get("target_name", "") or d.get("initiator_name", "") or "-"
        if len(name) > 40:
            name = "..." + name[-37:]
        lun = d.get("lun", "") or "-"
        # Detail: auth method or login status
        detail = d.get("auth_method", "") or d.get("login_status_name", "") or "-"
        return [opcode, name, lun, detail]

    def process_packet(self, packet) -> None:
        """Process iSCSI packet and extract target, initiator, and session info."""
        if not hasattr(packet, "iscsi"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        iscsi = packet.iscsi
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        # Extract opcode
        opcode_raw = self.get_field(iscsi, "opcode", None)
        opcode_str = str(opcode_raw) if opcode_raw is not None else ""
        opcode_name = OPCODES.get(opcode_str, "")
        if not opcode_name:
            # Try parsing as int
            opcode_int = self._parse_int(opcode_raw, default=None)
            if opcode_int is not None:
                opcode_name = OPCODES.get(str(opcode_int), f"Unknown(0x{opcode_int:02x})")
            else:
                opcode_name = f"Unknown({opcode_str})"

        # Determine direction from opcode
        is_response = opcode_str in RESPONSE_OPCODES or opcode_name in RESPONSE_OPCODES
        direction = "response" if is_response else "request"

        # Extract target and initiator names from login/text key-value data
        # tshark exposes these as iscsi.login.target_name and iscsi.login.initiator_name
        target_name = str(self.get_field(iscsi, "login_target_name", "") or "")
        if not target_name:
            target_name = str(self.get_field(iscsi, "login.target_name", "") or "")
        initiator_name = str(self.get_field(iscsi, "login_initiator_name", "") or "")
        if not initiator_name:
            initiator_name = str(self.get_field(iscsi, "login.initiator_name", "") or "")

        # Extract LUN from SCSI command
        lun = self.get_field(iscsi, "lun", None)
        lun_str = str(lun) if lun is not None else ""

        # Extract session ID
        isid = self.get_field(iscsi, "isid", None)
        isid_str = str(isid) if isid is not None else ""

        # Authentication method from login key-value pairs
        auth_method = str(self.get_field(iscsi, "login_auth_method", "") or "")
        if not auth_method:
            auth_method = str(self.get_field(iscsi, "login.auth_method", "") or "")

        # Login status
        login_status = self.get_field(iscsi, "login_status", None)
        if login_status is None:
            login_status = self.get_field(iscsi, "login.status", None)
        login_status_str = str(login_status) if login_status is not None else ""
        login_status_name = LOGIN_STATUS.get(login_status_str, "")

        # Session type
        session_type = str(self.get_field(iscsi, "login_session_type", "") or "")
        if not session_type:
            session_type = str(self.get_field(iscsi, "login.session_type", "") or "")

        # Data segment length
        data_seg_len = self.get_field(iscsi, "datasegmentlength", None)
        data_seg_len_str = str(data_seg_len) if data_seg_len is not None else ""

        # SCSI command flags
        scsi_read = self.get_field(iscsi, "scsicommand_R", None)
        scsi_write = self.get_field(iscsi, "scsicommand_W", None)
        expected_len = self.get_field(iscsi, "scsicommand_expecteddatatransferlength", None)

        # Build details
        details: Dict[str, Any] = {
            "opcode": opcode_str,
            "opcode_name": opcode_name,
            "target_name": target_name,
            "initiator_name": initiator_name,
            "lun": lun_str,
            "isid": isid_str,
            "auth_method": auth_method,
            "session_type": session_type,
            "login_status": login_status_str,
            "login_status_name": login_status_name,
            "data_segment_length": data_seg_len_str,
        }
        if scsi_read is not None:
            details["scsi_read"] = str(scsi_read)
        if scsi_write is not None:
            details["scsi_write"] = str(scsi_write)
        if expected_len is not None:
            details["expected_transfer_length"] = str(expected_len)

        # Build operation and summary
        operation = f"iSCSI {opcode_name}"
        summary = operation
        if target_name:
            summary += f" target={target_name}"
        if initiator_name:
            summary += f" initiator={initiator_name}"
        if lun_str:
            summary += f" lun={lun_str}"
        if auth_method:
            summary += f" auth={auth_method}"
        if login_status_name:
            summary += f" status={login_status_name}"

        now = datetime.now().isoformat()
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
            stream_id=stream_id,
        )

        # Determine server/client
        if is_response:
            server_ip, client_ip = src_ip, dst_ip
            server_mac, client_mac = src_mac, dst_mac
        else:
            server_ip, client_ip = dst_ip, src_ip
            server_mac, client_mac = dst_mac, src_mac

        # Track target names per server
        if target_name:
            if server_ip not in self.target_names:
                self.target_names[server_ip] = set()
            self.target_names[server_ip].add(target_name)

        # Track initiator names per client
        if initiator_name:
            if client_ip not in self.initiator_names:
                self.initiator_names[client_ip] = set()
            self.initiator_names[client_ip].add(initiator_name)

        # Track auth methods per server
        if auth_method:
            if server_ip not in self.auth_methods:
                self.auth_methods[server_ip] = set()
            self.auth_methods[server_ip].add(auth_method)

        # Create device entries
        if is_valid_discovered_ip(server_ip):
            server_vendor = lookup_mac_vendor(server_mac) if server_mac else ""
            device, is_new = self._ensure_device(
                f"iscsi-target:{server_ip}",
                server_ip,
                mac=server_mac or "",
                device_type="iSCSI Target",
                manufacturer=server_vendor if server_vendor != "Unknown" else "",
            )
            if is_new:
                device.iscsi_passive_data = {
                    "role": "target",
                    "protocol": "iSCSI/TCP",
                    "target_names": [],
                    "auth_methods": [],
                }
            if hasattr(device, "iscsi_passive_data") and device.iscsi_passive_data:
                targets = device.iscsi_passive_data.get("target_names", [])
                if target_name and target_name not in targets:
                    targets.append(target_name)
                    device.iscsi_passive_data["target_names"] = targets
                auths = device.iscsi_passive_data.get("auth_methods", [])
                if auth_method and auth_method not in auths:
                    auths.append(auth_method)
                    device.iscsi_passive_data["auth_methods"] = auths

        if is_valid_discovered_ip(client_ip):
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            device, is_new = self._ensure_device(
                f"iscsi-initiator:{client_ip}",
                client_ip,
                mac=client_mac or "",
                device_type="iSCSI Initiator",
                manufacturer=client_vendor if client_vendor != "Unknown" else "",
            )
            if is_new:
                device.iscsi_passive_data = {
                    "role": "initiator",
                    "protocol": "iSCSI/TCP",
                    "initiator_names": [],
                }
            if hasattr(device, "iscsi_passive_data") and device.iscsi_passive_data:
                inits = device.iscsi_passive_data.get("initiator_names", [])
                if initiator_name and initiator_name not in inits:
                    inits.append(initiator_name)
                    device.iscsi_passive_data["initiator_names"] = inits

        self.logger.debug(
            f"iSCSI: {opcode_name} {src_ip} -> {dst_ip}"
            + (f" target={target_name}" if target_name else "")
        )

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data including target discovery tables."""
        base = super().harvest()
        tables = base.get("tables", [])

        # Add target discovery table
        target_rows = []
        for server_ip, targets in self.target_names.items():
            for tgt in sorted(targets):
                auths = sorted(self.auth_methods.get(server_ip, set())) or ["Unknown"]
                target_rows.append([server_ip, tgt, ", ".join(auths)])
        if target_rows:
            tables.append(
                {
                    "title": "iSCSI Targets Discovered",
                    "headers": ["Server", "Target IQN", "Auth Methods"],
                    "rows": target_rows,
                }
            )

        # Add initiator table
        init_rows = []
        for client_ip, inits in self.initiator_names.items():
            for ini in sorted(inits):
                init_rows.append([client_ip, ini])
        if init_rows:
            tables.append(
                {
                    "title": "iSCSI Initiators",
                    "headers": ["Client", "Initiator IQN"],
                    "rows": init_rows,
                }
            )

        if tables:
            base["tables"] = tables
        return base
