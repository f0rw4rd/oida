"""
S7comm Passive Listener for Siemens PLC traffic analysis (ICS).

Passively captures Siemens S7comm traffic to extract:
- PLC passwords from PI service calls (_N_NEWPWD, etc.)
- Read/Write operations to data blocks (DB number, offset, data type)
- PLC Control commands (start, stop, memory reset)
- Upload/Download of program blocks
- SZL (System Status List) reads
- CPU diagnostics

S7comm is used by Siemens SIMATIC PLCs (S7-300, S7-400, S7-1200, S7-1500).

tshark fields used:
- s7comm.header.rosctr: ROSCTR (1=Job, 2=Ack, 3=AckData, 7=Userdata)
- s7comm.param.func: Function code (0x04=Read, 0x05=Write, 0x1a=Setup,
  0x28=PI, 0x29=PLC Stop, etc.)
- s7comm.param.item.area: Memory area (0x81=DI, 0x82=DB, 0x83=M, 0x84=E, 0x85=A)
- s7comm.param.item.db: DB number
- s7comm.param.item.address.byte: Byte address within the area
- s7comm.param.item.length: Data length
- s7comm.param.userdata.funcgroup: Userdata function group
- s7comm.param.userdata.subfunc: Userdata subfunction
- s7comm.param.userdata.type: Userdata type (1=req, 8=resp)
- s7comm.param.pistart.servicename: PI service name (_INSE, _DELE, etc.)
- s7comm.param.pi.n_x.password: Password in PI service calls
- s7comm.data.blockcontrol.*: Block control fields (download/upload)
- s7comm.data.blockinfo.*: Block info fields (list blocks)
- s7comm.szl.001c.*: SZL 001C PLC identification fields

References:
- Wireshark dissector: packet-s7comm.c
- S7comm protocol reverse engineering documentation
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

import logging

logger = logging.getLogger(__name__)


# S7comm ROSCTR values
ROSCTR = {
    0x01: "Job",
    0x02: "Ack",
    0x03: "AckData",
    0x07: "Userdata",
}

# S7comm function codes
S7_FUNCTIONS = {
    0x00: "CPU Services",
    0x04: "Read Var",
    0x05: "Write Var",
    0x1A: "Request Download",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload",
    0x1E: "Upload",
    0x1F: "End Upload",
    0x28: "PI Service",
    0x29: "PLC Stop",
    0xF0: "Setup Communication",
}

# S7comm memory area codes
S7_AREAS = {
    0x03: "SysInfo",
    0x05: "SysFlags",
    0x06: "AnainS5",
    0x07: "AnaoutS5",
    0x80: "P",  # Direct peripheral access
    0x81: "Inputs",
    0x82: "Outputs",
    0x83: "Flags",  # M (Merker)
    0x84: "DB",  # Data Blocks
    0x85: "DI",  # Instance Data Blocks
    0x86: "Local",
    0x87: "V",  # Previous local data
    0x1C: "Counter",
    0x1D: "Timer",
}

# S7comm block types (blockcontrol / blockinfo)
S7_BLOCK_TYPES = {
    0x08: "OB",
    0x0A: "DB",
    0x0B: "SDB",
    0x0C: "FC",
    0x0D: "SFC",
    0x0E: "FB",
    0x0F: "SFB",
}

# S7comm block languages
S7_BLOCK_LANGS = {
    0x01: "AWL",
    0x02: "KOP",
    0x03: "FUP",
    0x04: "SCL",
    0x05: "DB",
    0x06: "GRAPH",
}

# S7comm userdata function groups
S7_USERDATA_FUNCGROUPS = {
    0x00: "Mode Transition",
    0x01: "Programmer Commands",
    0x02: "Cyclic Data",
    0x03: "Block Functions",
    0x04: "CPU Functions",
    0x05: "Security",
    0x06: "PBC BSEND/BRECV",
    0x07: "Time Functions",
}


@dataclass
class S7commCredential:
    """Extracted S7comm password."""

    password: str
    password_level: str = ""
    credential_type: str = "plaintext"
    plc_ip: str = ""
    client_ip: str = ""
    timestamp: str = ""

    @property
    def server_ip(self) -> str:
        """Canonical scanner field alias for plc_ip."""
        return self.plc_ip

    @property
    def username(self) -> str:
        """Canonical scanner field -- S7comm uses password-only auth."""
        return self.password

    @property
    def auth_method(self) -> str:
        """Canonical scanner field."""
        return (
            f"S7comm-PLC-Password (level={self.password_level})"
            if self.password_level
            else "S7comm-PLC-Password"
        )


def _first_int(raw) -> int:
    """Extract the first integer from a possibly comma-separated EK mode value.

    In EK mode, multi-item reads produce lists that get_field() joins into
    comma-separated strings like "131,129,130".  This returns the first value
    as an int (131), or 0 on failure.
    """
    if raw is None:
        return 0
    s = str(raw).strip()
    if "," in s:
        s = s.split(",", 1)[0].strip()
    try:
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        try:
            return int(s, 16)
        except (ValueError, TypeError) as e:
            logger.debug(f"Return value computation failed: {e}")
            return 0


def _count_csv(raw) -> int:
    """Count items in a comma-separated EK mode value.

    Returns 1 for scalar values, N for "v1,v2,...,vN".
    """
    if raw is None:
        return 0
    s = str(raw).strip()
    if not s:
        return 0
    return len(s.split(","))


class S7commPassiveListener(PySharkListenerBase):
    """Passive S7comm traffic listener for PLC interaction analysis.

    Captures Siemens S7comm protocol traffic to extract:
    - PLC passwords from PI service calls and block control operations
    - Read/Write operations (DB, M, I, Q areas)
    - PLC control (start, stop, download, upload)
    - CPU diagnostics and SZL reads
    """

    PROTOCOL_NAME = "s7comm"
    DISPLAY_FILTER = "s7comm"
    REQUIRED_LAYERS = ("s7comm",)
    PROTOCOL_COLUMNS = ("operation", "area", "db", "address", "size", "data")

    # S7comm write function codes (security-relevant)
    WRITE_FUNC_CODES = {0x05, 0x28, 0x29, 0x1A, 0x1B, 0x1C}

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[S7commCredential] = []
        # Track write operations per (client, plc) pair
        self._write_counts: Dict[Tuple[str, str], int] = {}
        # PLC identification from SZL 001C responses
        self._plc_identity: Dict[str, Dict[str, str]] = {}
        # Block transfer tracking: flow_id -> accumulated block metadata
        self._block_transfers: Dict[str, Dict[str, Any]] = {}
        # Completed block transfers for harvest table
        self._completed_blocks: List[Dict[str, Any]] = []

    def process_packet(self, packet) -> None:
        """Process S7comm packet and extract interactions + passwords."""
        if not hasattr(packet, "s7comm"):
            return

        s7comm = packet.s7comm
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            # Fuzz / malformed packets may lack an IP layer.  Use placeholders
            # so we still record an interaction (every s7comm-filtered packet
            # must produce at least one).
            src_ip = src_ip or "0.0.0.0"
            dst_ip = dst_ip or "0.0.0.0"
            self.logger.debug("S7comm packet missing IP layer — using placeholder addresses")

        flow_id = self.get_flow_id(packet)

        src_port, dst_port = self.get_port_info(packet)
        stream_id = self.get_stream_id(packet)

        # Get MAC addresses for vendor lookup
        src_mac, dst_mac = self.get_mac_info(packet)

        now = datetime.now().isoformat()

        # Extract protocol ID (always 0x32 for S7comm)
        protid_raw = self.get_field(s7comm, "header_protid", None)
        if protid_raw is None:
            protid_raw = self.get_field(s7comm, "header.protid", None)

        # Extract ROSCTR
        rosctr_raw = self.get_field(s7comm, "header_rosctr", None)
        if rosctr_raw is None:
            rosctr_raw = self.get_field(s7comm, "header.rosctr", None)
        rosctr = 0
        if rosctr_raw is not None:
            try:
                rosctr = int(rosctr_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get rosctr: {e}")

        # Redundancy ID (header.redid): reserved, should always be 0x0000.
        # A non-zero value is anomalous; capture it for visibility/alerting.
        redid_raw = self.get_field(s7comm, "header_redid", None)
        if redid_raw is None:
            redid_raw = self.get_field(s7comm, "header.redid", None)
        redid_str = str(redid_raw) if redid_raw is not None else ""

        # Determine client/PLC roles using port 102 (PLC always listens
        # on 102).  ROSCTR-only detection fails for Download/Upload where
        # the PLC sends Job (ROSCTR=1) to request block data from the
        # client, reversing the normal Job=client pattern.
        if dst_port == 102:
            client_ip, plc_ip = src_ip, dst_ip
            client_mac, plc_mac = src_mac, dst_mac
            is_request = True
        elif src_port == 102:
            client_ip, plc_ip = dst_ip, src_ip
            client_mac, plc_mac = dst_mac, src_mac
            is_request = False
        else:
            # Non-standard port — use ROSCTR as fallback
            if rosctr == 0x01:
                client_ip, plc_ip = src_ip, dst_ip
                client_mac, plc_mac = src_mac, dst_mac
                is_request = True
            elif rosctr in (0x02, 0x03):
                client_ip, plc_ip = dst_ip, src_ip
                client_mac, plc_mac = dst_mac, src_mac
                is_request = False
            else:
                # Best guess: treat src as client
                client_ip, plc_ip = src_ip, dst_ip
                client_mac, plc_mac = src_mac, dst_mac
                is_request = True

        direction = "request" if is_request else "response"

        # Extract function code
        func_raw = self.get_field(s7comm, "param_func", None)
        if func_raw is None:
            func_raw = self.get_field(s7comm, "param.func", None)
        func_code = 0
        if func_raw is not None:
            try:
                if isinstance(func_raw, str) and func_raw.startswith("0x"):
                    func_code = int(func_raw, 16)
                else:
                    func_code = int(func_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"if isinstance(func_raw, str) and func...: {e}")

        func_name = S7_FUNCTIONS.get(func_code, f"Func 0x{func_code:02x}")

        # Handle Read/Write Var (requests AND AckData responses)
        if func_code in (0x04, 0x05):
            if is_request or rosctr == 0x03:
                self._process_read_write(
                    s7comm,
                    src_ip,
                    dst_ip,
                    func_code,
                    func_name,
                    now,
                    flow_id,
                    is_request=is_request,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )

        # Handle Userdata (SZL, diagnostics, security)
        elif rosctr == 0x07:
            self._process_userdata(
                s7comm,
                src_ip,
                dst_ip,
                client_ip,
                plc_ip,
                direction,
                now,
                flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Handle PI Service (program invocation)
        elif func_code == 0x28:
            self._process_pi_service(
                s7comm,
                src_ip,
                dst_ip,
                client_ip,
                plc_ip,
                direction,
                now,
                flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Handle PLC Stop (both request and response/AckData)
        elif func_code == 0x29:
            stop_label = "PLC Stop" if is_request else "PLC Stop (response)"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                "PLC Stop",
                {"function": "PLC Stop"},
                stop_label,
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Handle Download/Upload
        elif func_code in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F):
            self._process_block_control(
                s7comm,
                src_ip,
                dst_ip,
                func_code,
                func_name,
                direction,
                now,
                flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Handle Setup Communication
        elif func_code == 0xF0:
            pdu_len_raw = self.get_field(s7comm, "param_pdu_length", None)
            if pdu_len_raw is None:
                pdu_len_raw = self.get_field(s7comm, "param.pdu_length", None)
            pdu_len = 0
            if pdu_len_raw:
                try:
                    pdu_len = int(pdu_len_raw)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get pdu_len: {e}")
            setup_details: Dict[str, Any] = {"pdu_length": pdu_len}
            if redid_str:
                setup_details["redundancy_id"] = redid_str
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                "Setup Communication",
                setup_details,
                f"Setup Communication (PDU={pdu_len})" if pdu_len else "Setup Communication",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        else:
            # Catch-all for packets not matching any specific handler:
            # bare Ack (ROSCTR=2) with no function code, unknown function
            # codes, or malformed/fuzz packets.  Every s7comm-filtered
            # packet must produce at least one interaction.
            rosctr_name = ROSCTR.get(rosctr, f"ROSCTR {rosctr}")
            if func_code:
                op_label = f"{rosctr_name}: {func_name}"
            else:
                op_label = rosctr_name
            catchall_details: Dict[str, Any] = {
                "rosctr": rosctr,
                "function_code": func_code,
            }
            if redid_str:
                catchall_details["redundancy_id"] = redid_str
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                op_label,
                catchall_details,
                op_label,
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Track write operations for alerting
        if func_code in self.WRITE_FUNC_CODES and is_request:
            pair = (client_ip, plc_ip)
            self._write_counts[pair] = self._write_counts.get(pair, 0) + 1

        # Extract password (preserve original credential extraction)
        self._extract_password(s7comm, src_ip, dst_ip)

        # Update devices
        self._update_devices(client_ip, plc_ip, client_mac, plc_mac)

    def _process_read_write(
        self,
        s7comm,
        src_ip: str,
        dst_ip: str,
        func_code: int,
        func_name: str,
        now: str,
        flow_id: str = "",
        is_request: bool = True,
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process Read Var / Write Var requests and responses."""
        direction = "request" if is_request else "response"

        details: Dict[str, Any] = {
            "function_code": func_code,
        }

        # Area/DB/address/length only present in requests.
        # In EK mode, multi-item reads return comma-separated lists
        # (e.g. "131,129,130" for 3 items).  Use first item for display
        # and store item_count for the table formatter.
        if is_request:
            area_raw = self.get_field(s7comm, "param_item_area", None)
            if area_raw is None:
                area_raw = self.get_field(s7comm, "param.item.area", None)
            db_raw = self.get_field(s7comm, "param_item_db", None)
            if db_raw is None:
                db_raw = self.get_field(s7comm, "param.item.db", None)
            addr_raw = self.get_field(s7comm, "param_item_address_byte", None)
            if addr_raw is None:
                addr_raw = self.get_field(s7comm, "param.item.address.byte", None)
            length_raw = self.get_field(s7comm, "param_item_length", None)
            if length_raw is None:
                length_raw = self.get_field(s7comm, "param.item.length", None)

            area_code = _first_int(area_raw)
            item_count = _count_csv(area_raw)

            area_name = S7_AREAS.get(area_code, f"Area 0x{area_code:02x}")
            db_num = _first_int(db_raw)
            byte_addr = _first_int(addr_raw)
            length = _first_int(length_raw)

            details["area"] = area_name
            details["db_number"] = db_num
            details["byte_address"] = byte_addr
            details["length"] = length
            if item_count > 1:
                details["item_count"] = item_count

            # Syntax ID: format type of the address specification
            # (0x10 = S7-Any, 0x12 = DB-block read, 0xb0 = NCK, etc.).
            # Identifies how the following address bytes are encoded.
            syntaxid_raw = self.get_field(s7comm, "param_item_syntaxid", None)
            if syntaxid_raw is None:
                syntaxid_raw = self.get_field(s7comm, "param.item.syntaxid", None)
            if syntaxid_raw is not None:
                details["syntax_id"] = str(syntaxid_raw)

        # Extract data values
        data_str = self._extract_data_values(s7comm)
        if data_str:
            details["data"] = data_str

        # Check return code for response status
        return_code_raw = self.get_field(s7comm, "data_returncode", None)
        if return_code_raw is None:
            return_code_raw = self.get_field(s7comm, "data.returncode", None)
        if return_code_raw is not None:
            try:
                rc = (
                    int(return_code_raw, 16)
                    if isinstance(return_code_raw, str) and return_code_raw.startswith("0x")
                    else int(return_code_raw)
                )
                if rc != 0xFF:  # 0xFF = success
                    details["return_code"] = rc
            except (ValueError, TypeError) as e:
                self.logger.debug(f"S7comm: return code int parse failed: {e}")

        # Build summary
        area_name = details.get("area", "")
        db_num = details.get("db_number", 0)
        byte_addr = details.get("byte_address", 0)
        length = details.get("length", 0)

        if is_request:
            item_count = details.get("item_count", 0)
            area_code_val = 0
            for code, name in S7_AREAS.items():
                if name == area_name:
                    area_code_val = code
                    break
            if area_code_val in (0x84, 0x85) and db_num:
                summary = f"{func_name} DB{db_num}.DBB{byte_addr} ({length} bytes)"
            else:
                summary = f"{func_name} {area_name} addr={byte_addr} ({length} bytes)"
            if item_count > 1:
                summary += f" [{item_count} items]"
        else:
            summary = f"{func_name} response"

        if data_str:
            summary += f" = [{data_str}]"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            func_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _process_block_control(
        self,
        s7comm,
        src_ip: str,
        dst_ip: str,
        func_code: int,
        func_name: str,
        direction: str,
        now: str,
        flow_id: str = "",
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process Download/Upload block control operations."""
        details: Dict[str, Any] = {
            "function_code": func_code,
            "function_name": func_name,
        }

        # Extract block type
        bt_raw = self.get_field(s7comm, "data_blockcontrol_block_type", None)
        if bt_raw is None:
            bt_raw = self.get_field(s7comm, "data.blockcontrol.block_type", None)
        if bt_raw is not None:
            bt = self._parse_int(bt_raw)
            details["block_type"] = S7_BLOCK_TYPES.get(bt, f"0x{bt:02x}") if bt else str(bt_raw)

        # Extract block number
        bn_raw = self.get_field(s7comm, "data_blockcontrol_block_number", None)
        if bn_raw is None:
            bn_raw = self.get_field(s7comm, "data.blockcontrol.block_number", None)
        if bn_raw is not None:
            try:
                details["block_number"] = int(bn_raw)
            except (ValueError, TypeError):
                details["block_number"] = str(bn_raw)

        # Extract load memory length
        lm_raw = self.get_field(s7comm, "data_blockcontrol_loadmem_len", None)
        if lm_raw is None:
            lm_raw = self.get_field(s7comm, "data.blockcontrol.loadmem_len", None)
        if lm_raw is not None:
            try:
                details["loadmem_len"] = int(lm_raw)
            except (ValueError, TypeError):
                details["loadmem_len"] = str(lm_raw)

        # Extract MC7 code length
        mc7_raw = self.get_field(s7comm, "data_blockcontrol_mc7code_len", None)
        if mc7_raw is None:
            mc7_raw = self.get_field(s7comm, "data.blockcontrol.mc7code_len", None)
        if mc7_raw is not None:
            try:
                details["mc7code_len"] = int(mc7_raw)
            except (ValueError, TypeError):
                details["mc7code_len"] = str(mc7_raw)

        # Extract file identifier ('_'=complete module, '$'=module header for upload)
        fi_raw = self.get_field(s7comm, "data_blockcontrol_file_identifier", None)
        if fi_raw is None:
            fi_raw = self.get_field(s7comm, "data.blockcontrol.file_identifier", None)
        if fi_raw is not None:
            fi_str = str(fi_raw).strip()
            if fi_str:
                details["file_identifier"] = fi_str

        # Extract upload ID (session identifier for upload operations)
        uid_raw = self.get_field(s7comm, "data_blockcontrol_uploadid", None)
        if uid_raw is None:
            uid_raw = self.get_field(s7comm, "data.blockcontrol.uploadid", None)
        if uid_raw is not None:
            details["upload_id"] = str(uid_raw).strip()

        # Extract function status (0=no error, 1=more data, 2=error)
        fs_raw = self.get_field(s7comm, "param_blockcontrol_functionstatus", None)
        if fs_raw is None:
            fs_raw = self.get_field(s7comm, "param.blockcontrol.functionstatus", None)
        if fs_raw is not None:
            fs_val = self._parse_int(fs_raw)
            fs_labels = {0: "ok", 1: "more_data", 2: "error"}
            details["function_status"] = fs_labels.get(fs_val, f"status_{fs_val}")

        # Extract upload length string (total upload block size in bytes)
        upl_len_raw = self.get_field(s7comm, "param_blockcontrol_upl_lenstring", None)
        if upl_len_raw is None:
            upl_len_raw = self.get_field(s7comm, "param.blockcontrol.upl_lenstring", None)
        if upl_len_raw is not None:
            details["upload_length"] = str(upl_len_raw).strip()

        # Extract filename
        fn_raw = self.get_field(s7comm, "param_blockcontrol_filename", None)
        if fn_raw is None:
            fn_raw = self.get_field(s7comm, "param.blockcontrol.filename", None)
        if fn_raw is not None:
            details["filename"] = str(fn_raw).strip()

        # Extract error code
        ec_raw = self.get_field(s7comm, "data_blockcontrol_errorcode", None)
        if ec_raw is None:
            ec_raw = self.get_field(s7comm, "data.blockcontrol.errorcode", None)
        if ec_raw is not None:
            try:
                ec = (
                    int(ec_raw, 16)
                    if isinstance(ec_raw, str) and ec_raw.startswith("0x")
                    else int(ec_raw)
                )
                if ec != 0:
                    details["error_code"] = f"0x{ec:04x}"
            except (ValueError, TypeError) as e:
                self.logger.debug(f"S7comm: block-control error code int parse failed: {e}")

        # Parse block payload data from Download Block / Upload responses
        if func_code in (0x1B, 0x1E):  # Download Block / Upload
            self._parse_block_payload(s7comm, src_ip, dst_ip, func_code, flow_id, details)

        # Finalize block transfer on Download Ended / End Upload
        if func_code in (0x1C, 0x1F):  # Download Ended / End Upload
            self._finalize_block_transfer(flow_id, src_ip, dst_ip, func_code, details)

        # Build summary
        bt_str = details.get("block_type", "")
        bn_str = details.get("block_number", "")
        block_label = f"{bt_str}{bn_str}" if bt_str and bn_str else (bt_str or "")
        summary = f"{func_name} {block_label}".strip() if block_label else func_name

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            func_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _parse_block_payload(
        self,
        s7comm,
        src_ip: str,
        dst_ip: str,
        func_code: int,
        flow_id: str,
        details: Dict[str, Any],
    ) -> None:
        """Parse S7 block header and interface data from Download/Upload payloads.

        S7 block header (36 bytes, starts with signature 0x7070):
          [0:2]   signature (0x7070 = uncompressed)
          [2]     version
          [3]     attribute
          [4]     language (05=DB, 07=SDB, etc.)
          [5]     block type (0x0A=DB, 0x0B=SDB, etc.)
          [6:8]   block number (big-endian)
          [8:12]  load memory length
          [12:16] block security/password
          [32:36] MC7 code length

        The interface/footer contains author (8B), family (8B), name (8B).
        SDB blocks contain station/PLC/project names as embedded strings.
        """
        raw = self.get_field(s7comm, "resp_data", None)
        if raw is None:
            raw = self.get_field(s7comm, "resp.data", None)
        if raw is None:
            return

        # Convert colon-separated hex or plain hex to bytes
        hex_str = str(raw).replace(":", "").strip()
        if not hex_str or len(hex_str) < 4:
            return
        try:
            payload = bytes.fromhex(hex_str)
        except ValueError as e:
            self.logger.debug(f"Failed to get payload: {e}")
            return

        # Initialize or get transfer state for this flow
        transfer_key = flow_id or f"{src_ip}-{dst_ip}"
        transfer = self._block_transfers.setdefault(
            transfer_key,
            {
                "segments": [],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "direction": "download" if func_code == 0x1B else "upload",
            },
        )
        transfer["segments"].append(payload)

        # Parse block header from first segment (starts with 0x7070)
        if len(payload) >= 36 and payload[0:2] == b"\x70\x70":
            block_type_byte = payload[5]
            block_num = int.from_bytes(payload[6:8], "big")
            load_len = int.from_bytes(payload[8:12], "big")
            security = int.from_bytes(payload[12:16], "big")
            mc7_len = int.from_bytes(payload[32:36], "big")
            lang_byte = payload[4]

            bt_name = S7_BLOCK_TYPES.get(block_type_byte, f"0x{block_type_byte:02x}")
            lang_name = S7_BLOCK_LANGS.get(lang_byte, f"0x{lang_byte:02x}")

            transfer["block_type"] = bt_name
            transfer["block_number"] = block_num
            transfer["load_len"] = load_len
            transfer["mc7_len"] = mc7_len
            transfer["language"] = lang_name
            transfer["security"] = security

            details.setdefault("block_type", bt_name)
            details.setdefault("block_number", block_num)

        # Try to extract author/family/name from each segment.
        # Skip the 36-byte block header (contains BCD timestamps that can
        # look like ASCII) when this is the first segment.
        search_start = 36 if payload[0:2] == b"\x70\x70" and len(payload) > 36 else 0
        self._extract_block_strings(payload, transfer, search_start)

    @staticmethod
    def _extract_block_strings(
        payload: bytes, transfer: Dict[str, Any], search_start: int = 0
    ) -> None:
        """Extract author/family/name and station strings from block payload."""
        import re

        search_area = payload[search_start:]

        # For SDB blocks, look for station/PLC/project strings (longer, variable position)
        if transfer.get("block_type") == "SDB" or (
            len(payload) >= 8 and payload[0:2] == b"\x70\x70" and payload[5] == 0x0B
        ):
            strings = [
                m.group().decode("ascii", errors="replace").strip()
                for m in re.finditer(rb"[\x20-\x7e]{4,}", search_area)
            ]
            for s in strings:
                if "/" in s and len(s) > 6:
                    # e.g. "S7300/ET200M station_1"
                    transfer.setdefault("station_name", s)
                elif s.startswith("STEP ") or s.startswith("TIA "):
                    transfer.setdefault("project_tool", s.strip())
                elif not transfer.get("station_name") and len(s) >= 3:
                    # PLC name candidate (short, after station)
                    if "station_name" in transfer and "plc_name" not in transfer:
                        transfer["plc_name"] = s
            return

        # For non-SDB blocks (DB, OB, FC, FB, etc.), look for author/family/name
        # in the interface block. These appear as three consecutive 8-byte
        # null-padded fields. Search for 3+ char printable strings.
        strings = []
        for m in re.finditer(rb"[\x20-\x7e]{3,}", search_area):
            s = m.group().decode("ascii", errors="replace").rstrip("\x00").strip()
            if s and len(s) <= 8:
                strings.append(s)

        if len(strings) >= 3:
            # Take the last 3 strings — they're typically author, family, name
            candidates = strings[-3:]
            transfer.setdefault("block_author", candidates[0])
            transfer.setdefault("block_family", candidates[1])
            transfer.setdefault("block_name", candidates[2])
        elif len(strings) >= 1:
            # Partial extraction — at least capture what we can
            for s in strings:
                if not transfer.get("block_name"):
                    transfer.setdefault("block_name", s)

    def _finalize_block_transfer(
        self,
        flow_id: str,
        src_ip: str,
        dst_ip: str,
        func_code: int,
        details: Dict[str, Any],
    ) -> None:
        """Finalize a block transfer and save to completed list."""
        transfer_key = flow_id or f"{src_ip}-{dst_ip}"
        transfer = self._block_transfers.pop(transfer_key, None)
        if not transfer:
            return

        # Copy extracted metadata into the current interaction details
        for key in (
            "block_author",
            "block_family",
            "block_name",
            "station_name",
            "plc_name",
            "project_tool",
        ):
            val = transfer.get(key)
            if val:
                details[key] = val

        # Build completed transfer record
        record: Dict[str, Any] = {
            "direction": transfer.get("direction", "unknown"),
            "block_type": transfer.get("block_type", details.get("block_type", "")),
            "block_number": transfer.get("block_number", details.get("block_number", "")),
            "load_len": transfer.get("load_len", 0),
            "mc7_len": transfer.get("mc7_len", 0),
            "language": transfer.get("language", ""),
            "security": transfer.get("security", 0),
            "segments": len(transfer.get("segments", [])),
            "src_ip": transfer.get("src_ip", src_ip),
            "dst_ip": transfer.get("dst_ip", dst_ip),
        }
        for key in (
            "block_author",
            "block_family",
            "block_name",
            "station_name",
            "plc_name",
            "project_tool",
        ):
            val = transfer.get(key)
            if val:
                record[key] = val

        self._completed_blocks.append(record)

    def _process_userdata(
        self,
        s7comm,
        src_ip: str,
        dst_ip: str,
        client_ip: str,
        plc_ip: str,
        direction: str,
        now: str,
        flow_id: str = "",
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process Userdata frames (SZL reads, diagnostics, security)."""
        funcgroup_raw = self.get_field(s7comm, "param_userdata_funcgroup", None)
        if funcgroup_raw is None:
            funcgroup_raw = self.get_field(s7comm, "param.userdata.funcgroup", None)
        subfunc_raw = self.get_field(s7comm, "param_userdata_subfunc", None)
        if subfunc_raw is None:
            subfunc_raw = self.get_field(s7comm, "param.userdata.subfunc", None)

        # Userdata type (1=request, 4=response, 8=push)
        ud_type_raw = self.get_field(s7comm, "param_userdata_type", None)
        if ud_type_raw is None:
            ud_type_raw = self.get_field(s7comm, "param.userdata.type", None)

        funcgroup = 0
        subfunc = 0
        ud_type = 0
        if funcgroup_raw:
            try:
                funcgroup = int(funcgroup_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get funcgroup: {e}")
        if subfunc_raw:
            try:
                subfunc = int(subfunc_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get subfunc: {e}")
        if ud_type_raw:
            try:
                ud_type = int(ud_type_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get ud_type: {e}")

        group_name = S7_USERDATA_FUNCGROUPS.get(funcgroup, f"Group {funcgroup}")

        # Build operation name based on group
        if funcgroup == 0x04:
            # CPU functions - subfunc 1 = Read SZL
            if subfunc == 0x01:
                operation = "Read SZL"
            elif subfunc == 0x02:
                operation = "Message Service"
            else:
                operation = f"CPU Function (subfunc={subfunc})"
        elif funcgroup == 0x05:
            # Security - subfunc 1 = PLC password
            if subfunc == 0x01:
                operation = "PLC Password"
            else:
                operation = f"Security (subfunc={subfunc})"
        elif funcgroup == 0x03:
            # Block functions
            if subfunc == 0x01:
                operation = "List Blocks"
            elif subfunc == 0x02:
                operation = "List Blocks of Type"
            elif subfunc == 0x03:
                operation = "Get Block Info"
            else:
                operation = f"Block Function (subfunc={subfunc})"
        else:
            operation = f"{group_name} (subfunc={subfunc})"

        details: Dict[str, Any] = {
            "function_group": funcgroup,
            "function_group_name": group_name,
            "subfunction": subfunc,
        }
        if ud_type:
            details["userdata_type"] = ud_type

        # Userdata sequence number: correlates a request with its response
        # and identifies multi-frame (fragmented) userdata transfers.
        seq_num_raw = self.get_field(s7comm, "param_userdata_seq_num", None)
        if seq_num_raw is None:
            seq_num_raw = self.get_field(s7comm, "param.userdata.seq_num", None)
        if seq_num_raw is not None:
            details["seq_num"] = str(seq_num_raw)

        # Data unit reference: nonzero when the userdata PDU is fragmented.
        dataunitref_raw = self.get_field(s7comm, "param_userdata_dataunitref", None)
        if dataunitref_raw is None:
            dataunitref_raw = self.get_field(s7comm, "param.userdata.dataunitref", None)
        if dataunitref_raw is not None:
            details["data_unit_ref"] = str(dataunitref_raw)

        # Last data unit flag: 0x00 = more fragments follow, else final unit.
        lastdataunit_raw = self.get_field(s7comm, "param_userdata_lastdataunit", None)
        if lastdataunit_raw is None:
            lastdataunit_raw = self.get_field(s7comm, "param.userdata.lastdataunit", None)
        if lastdataunit_raw is not None:
            details["last_data_unit"] = str(lastdataunit_raw)

        # Extract SZL data (s7comm.data.userdata.szl.id in EK mode)
        if funcgroup == 0x04 and subfunc == 0x01:
            szl_id_raw = self.get_field(s7comm, "data_userdata_szl_id", None)
            if szl_id_raw is None:
                szl_id_raw = self.get_field(s7comm, "data.userdata.szl.id", None)
            if szl_id_raw is None:
                szl_id_raw = self.get_field(s7comm, "szl_id", None)
            if szl_id_raw is not None:
                szl_id = self._parse_int(szl_id_raw)
                if szl_id:
                    details["szl_id"] = f"0x{szl_id:04x}"
                else:
                    details["szl_id"] = str(szl_id_raw)
                operation = f"Read SZL (ID={details['szl_id']})"

            # SZL index (sub-index within the SZL ID)
            szl_index_raw = self.get_field(s7comm, "data_userdata_szl_index", None)
            if szl_index_raw is None:
                szl_index_raw = self.get_field(s7comm, "data.userdata.szl_index", None)
            if szl_index_raw is not None:
                szl_index = self._parse_int(szl_index_raw)
                details["szl_index"] = f"0x{szl_index:04x}" if szl_index else str(szl_index_raw)

            # Parse SZL response fields
            if direction == "response":
                self._extract_szl_response(s7comm, plc_ip, details)

        # Extract CPU message fields (username, result)
        if funcgroup == 0x04:
            cpu_user_raw = self.get_field(s7comm, "cpu_msg_username", None)
            if cpu_user_raw is None:
                cpu_user_raw = self.get_field(s7comm, "cpu.msg.username", None)
            if cpu_user_raw is not None:
                cpu_user = str(cpu_user_raw).strip()
                if cpu_user:
                    details["cpu_msg_username"] = cpu_user

            cpu_result_raw = self.get_field(s7comm, "cpu_msg_res_result", None)
            if cpu_result_raw is None:
                cpu_result_raw = self.get_field(s7comm, "cpu.msg.res_result", None)
            if cpu_result_raw is not None:
                details["cpu_msg_result"] = str(cpu_result_raw).strip()

            # CPU diagnostic message event ID
            diag_eventid_raw = self.get_field(s7comm, "cpu_diag_msg_eventid", None)
            if diag_eventid_raw is None:
                diag_eventid_raw = self.get_field(s7comm, "cpu.diag_msg.eventid", None)
            if diag_eventid_raw is not None:
                diag_eventid = self._parse_int(diag_eventid_raw)
                if diag_eventid:
                    details["diag_event_id"] = f"0x{diag_eventid:04x}"

        # Extract TIS (Test and Installation) job function
        tis_func_raw = self.get_field(s7comm, "tis_job_function", None)
        if tis_func_raw is None:
            tis_func_raw = self.get_field(s7comm, "tis.job.function", None)
        if tis_func_raw is not None:
            details["tis_job_function"] = self._parse_int(tis_func_raw)

        # Extract alarm function and event ID
        alarm_func_raw = self.get_field(s7comm, "alarm_function", None)
        if alarm_func_raw is None:
            alarm_func_raw = self.get_field(s7comm, "alarm.function", None)
        if alarm_func_raw is not None:
            details["alarm_function"] = self._parse_int(alarm_func_raw)

        alarm_event_raw = self.get_field(s7comm, "alarm_event_id", None)
        if alarm_event_raw is None:
            alarm_event_raw = self.get_field(s7comm, "alarm.event_id", None)
        if alarm_event_raw is not None:
            alarm_eid = self._parse_int(alarm_event_raw)
            if alarm_eid:
                details["alarm_event_id"] = f"0x{alarm_eid:04x}"

        # Extract cyclic data function and job ID
        cyclic_func_raw = self.get_field(s7comm, "cyclic_function", None)
        if cyclic_func_raw is None:
            cyclic_func_raw = self.get_field(s7comm, "cyclic.function", None)
        if cyclic_func_raw is not None:
            details["cyclic_function"] = self._parse_int(cyclic_func_raw)

        cyclic_job_raw = self.get_field(s7comm, "cyclic_job_id", None)
        if cyclic_job_raw is None:
            cyclic_job_raw = self.get_field(s7comm, "cyclic.job_id", None)
        if cyclic_job_raw is not None:
            details["cyclic_job_id"] = self._parse_int(cyclic_job_raw)

        # Extract block info fields for funcgroup=3 (both requests and responses)
        if funcgroup == 0x03:
            self._extract_block_info(s7comm, subfunc, direction, details)

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            operation,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _extract_szl_response(
        self,
        s7comm,
        plc_ip: str,
        details: Dict[str, Any],
    ) -> None:
        """Extract useful fields from SZL responses based on SZL ID."""
        szl_id_str = details.get("szl_id", "")
        szl_id = self._parse_int(szl_id_str) if szl_id_str else 0

        if szl_id == 0x001C:
            self._extract_szl_001c(s7comm, plc_ip, details)
        elif szl_id == 0x0011:
            self._extract_szl_0011(s7comm, plc_ip, details)
        elif szl_id == 0x0132:
            self._extract_szl_0132(s7comm, details)
        elif szl_id == 0x0424:
            self._extract_szl_0424(s7comm, details)

    def _extract_szl_001c(
        self,
        s7comm,
        plc_ip: str,
        details: Dict[str, Any],
    ) -> None:
        """Extract SZL 001C PLC identification fields."""
        # Component name (index 0x0001)
        component = self.get_field(s7comm, "szl_001c_0001_name", None)
        if component is None:
            component = self.get_field(s7comm, "szl.001c.0001.name", None)
        if component is not None:
            details["component"] = str(component).strip()

        # Module / order number (index 0x0002)
        module = self.get_field(s7comm, "szl_001c_0002_name", None)
        if module is None:
            module = self.get_field(s7comm, "szl.001c.0002.name", None)
        if module is not None:
            details["module_name"] = str(module).strip()

        # Serial number (index 0x0005)
        serial = self.get_field(s7comm, "szl_001c_0005_serialn", None)
        if serial is None:
            serial = self.get_field(s7comm, "szl.001c.0005.serialn", None)
        if serial is not None:
            details["serial_number"] = str(serial).strip()

        # CPU type name (index 0x0007)
        cpu_type = self.get_field(s7comm, "szl_001c_0007_cputypname", None)
        if cpu_type is None:
            cpu_type = self.get_field(s7comm, "szl.001c.0007.cputypname", None)
        if cpu_type is not None:
            details["cpu_type"] = str(cpu_type).strip()

        # Manufacturer ID (PROFIBUS/PROFINET I&M, index 0x0009)
        mfr_id_raw = self.get_field(s7comm, "szl_001c_0009_manufacturer_id", None)
        if mfr_id_raw is None:
            mfr_id_raw = self.get_field(s7comm, "szl.001c.0009.manufacturer_id", None)
        if mfr_id_raw is not None:
            details["manufacturer_id"] = str(mfr_id_raw).strip()

        # OEM ID (index 0x000a)
        oem_id_raw = self.get_field(s7comm, "szl_001c_000a_oem_id", None)
        if oem_id_raw is None:
            oem_id_raw = self.get_field(s7comm, "szl.001c.000a.oem_id", None)
        if oem_id_raw is not None:
            details["oem_id"] = str(oem_id_raw).strip()

        # Location ID (index 0x000b)
        loc_id_raw = self.get_field(s7comm, "szl_001c_000b_loc_id", None)
        if loc_id_raw is None:
            loc_id_raw = self.get_field(s7comm, "szl.001c.000b.loc_id", None)
        if loc_id_raw is not None:
            details["location_id"] = str(loc_id_raw).strip()

        # Store identity data for device enrichment and harvest table
        identity: Dict[str, str] = {}
        for key in ("component", "module_name", "serial_number", "cpu_type"):
            val = details.get(key)
            if val:
                identity[key] = val
        if identity and plc_ip:
            self._plc_identity[plc_ip] = identity

    def _extract_szl_0011(
        self,
        s7comm,
        plc_ip: str,
        details: Dict[str, Any],
    ) -> None:
        """Extract SZL 0011 Module Identification (order number + FW version)."""
        # Order number (anz field — may be comma-separated list from array)
        anz_raw = self.get_field(s7comm, "szl_xy11_0001_anz", None)
        if anz_raw is None:
            anz_raw = self.get_field(s7comm, "szl.xy11.0001.anz", None)
        if anz_raw is not None:
            anz_str = str(anz_raw).strip()
            # Take first entry if comma-separated (first = CPU module)
            if "," in anz_str:
                order_num = anz_str.split(",")[0].strip()
            else:
                order_num = anz_str.strip()
            if order_num:
                details["order_number"] = order_num

        # Firmware version: ausbg (major) / ausbe (minor)
        ausbg_raw = self.get_field(s7comm, "szl_xy11_0001_ausbg", None)
        if ausbg_raw is None:
            ausbg_raw = self.get_field(s7comm, "szl.xy11.0001.ausbg", None)
        ausbe_raw = self.get_field(s7comm, "szl_xy11_0001_ausbe", None)
        if ausbe_raw is None:
            ausbe_raw = self.get_field(s7comm, "szl.xy11.0001.ausbe", None)
        if ausbg_raw is not None and ausbe_raw is not None:
            # Take first entry (CPU module)
            major_str = str(ausbg_raw).split(",")[0].strip()
            minor_str = str(ausbe_raw).split(",")[0].strip()
            major = self._parse_int(major_str)
            minor = self._parse_int(minor_str)
            if major or minor:
                details["firmware_version"] = f"V{major}.{minor}"

        # Update PLC identity with order number
        if plc_ip and details.get("order_number"):
            identity = self._plc_identity.setdefault(plc_ip, {})
            identity["order_number"] = details["order_number"]
            if details.get("firmware_version"):
                identity["firmware_version"] = details["firmware_version"]

    def _extract_szl_0132(
        self,
        s7comm,
        details: Dict[str, Any],
    ) -> None:
        """Extract SZL 0132 Communication Parameters (protection level)."""
        # Protection level (key field)
        key_raw = self.get_field(s7comm, "szl_0132_0004_key", None)
        if key_raw is None:
            key_raw = self.get_field(s7comm, "szl.0132.0004.key", None)
        if key_raw is not None:
            key_val = self._parse_int(key_raw)
            protection_levels = {
                0: "No protection",
                1: "Write protection",
                2: "Read/Write protection",
                3: "Full protection",
            }
            details["protection_level"] = protection_levels.get(key_val, f"Level {key_val}")

        # Assigned protection level param (0=no password, 1-3=protection levels)
        param_raw = self.get_field(s7comm, "szl_0132_0004_param", None)
        if param_raw is None:
            param_raw = self.get_field(s7comm, "szl.0132.0004.param", None)
        if param_raw is not None:
            param_val = self._parse_int(param_raw)
            details["assigned_protection"] = param_val

    def _extract_szl_0424(
        self,
        s7comm,
        details: Dict[str, Any],
    ) -> None:
        """Extract SZL 0424 Diagnostic Buffer (event ID)."""
        ereig_raw = self.get_field(s7comm, "szl_0424_0000_ereig", None)
        if ereig_raw is None:
            ereig_raw = self.get_field(s7comm, "szl.0424.0000.ereig", None)
        if ereig_raw is not None:
            ereig_val = self._parse_int(ereig_raw)
            if ereig_val:
                details["diag_event_id"] = f"0x{ereig_val:04x}"

    def _extract_block_info(
        self,
        s7comm,
        subfunc: int,
        direction: str,
        details: Dict[str, Any],
    ) -> None:
        """Extract block info fields for funcgroup=3 (requests and responses).

        tshark EK returns arrays for List Blocks responses, e.g.:
          blockinfo_blocktype = ['08', '0E', '0C', '0A', ...]
          blockinfo_block_count = ['1', '0', '0', '0', ...]
        Single values for List Blocks of Type / Get Block Info requests.
        """
        # Block type (may be a comma-separated list for List Blocks response;
        # single value for List Blocks of Type / Get Block Info requests)
        bi_type_raw = self.get_field(s7comm, "blockinfo_blocktype", None)
        if bi_type_raw is None:
            bi_type_raw = self.get_field(s7comm, "blockinfo.blocktype", None)
        # Block count (List Blocks response only)
        bi_count_raw = self.get_field(s7comm, "blockinfo_block_count", None)
        if bi_count_raw is None:
            bi_count_raw = self.get_field(s7comm, "blockinfo.block_count", None)

        # Handle array case: zip block types with counts for List Blocks
        type_parts = str(bi_type_raw).split(",") if bi_type_raw and "," in str(bi_type_raw) else []
        count_parts = (
            str(bi_count_raw).split(",") if bi_count_raw and "," in str(bi_count_raw) else []
        )
        if type_parts and count_parts:
            pairs = []
            for bt_val, bc_val in zip(type_parts, count_parts):
                bt_int = self._parse_int(bt_val.strip())
                bt_name = S7_BLOCK_TYPES.get(bt_int, f"0x{bt_int:02x}")
                bc_int = self._parse_int(bc_val.strip())
                if bc_int > 0:
                    pairs.append(f"{bt_name}:{bc_int}")
            if pairs:
                details["block_summary"] = " ".join(pairs)
        elif bi_type_raw is not None:
            # Single value — request specifying which type to list/query
            bt = self._parse_int(bi_type_raw)
            details["block_type"] = (
                S7_BLOCK_TYPES.get(bt, f"0x{bt:02x}") if bt else str(bi_type_raw)
            )
            if bi_count_raw is not None:
                details["block_count"] = self._parse_int(bi_count_raw)

        # Block number (may be comma-separated list in response,
        # or in data_blockinfo_block_number for Get Block Info request)
        bi_num_raw = self.get_field(s7comm, "blockinfo_block_num", None)
        if bi_num_raw is None:
            bi_num_raw = self.get_field(s7comm, "blockinfo.block_num", None)
        if bi_num_raw is None:
            # Get Block Info request uses data_blockinfo_block_number
            bi_num_raw = self.get_field(s7comm, "data_blockinfo_block_number", None)
            if bi_num_raw is None:
                bi_num_raw = self.get_field(s7comm, "data.blockinfo.block_number", None)
        if bi_num_raw is not None:
            num_str = str(bi_num_raw)
            if "," in num_str:
                nums = [
                    str(self._parse_int(v.strip()))
                    for v in num_str.split(",")
                    if self._parse_int(v.strip())
                ]
                if nums:
                    details["block_number"] = ", ".join(nums)
            else:
                details["block_number"] = self._parse_int(bi_num_raw)

        # Block language (List Blocks of Type response)
        bi_lang_raw = self.get_field(s7comm, "blockinfo_block_lang", None)
        if bi_lang_raw is None:
            bi_lang_raw = self.get_field(s7comm, "blockinfo.block_lang", None)
        if bi_lang_raw is not None:
            lang_int = self._parse_int(bi_lang_raw)
            # Lang 0 = not applicable (system blocks), suppress it
            if lang_int:
                details["block_lang"] = S7_BLOCK_LANGS.get(lang_int, f"Lang {lang_int}")

        # Filesystem (Get Block Info request)
        filesys_raw = self.get_field(s7comm, "data_blockinfo_filesys", None)
        if filesys_raw is None:
            filesys_raw = self.get_field(s7comm, "data.blockinfo.filesys", None)
        if filesys_raw is not None:
            details["block_filesys"] = str(filesys_raw).strip()

        # Author, family, name (Get Block Info response, subfunc=3)
        if subfunc == 0x03:
            for field, key in [
                ("blockinfo_author", "block_author"),
                ("blockinfo_family", "block_family"),
                ("blockinfo_headername", "block_name"),
                ("blockinfo_mc7_len", "mc7_len"),
                ("blockinfo_blocksecurity", "block_security"),
            ]:
                val = self.get_field(s7comm, f"data_{field}", None)
                if val is None:
                    val = self.get_field(s7comm, f"data.{field}", None)
                if val is not None:
                    val_str = str(val).strip()
                    if val_str:
                        details[key] = val_str

            # Direct tshark dissector fields (without data. prefix)
            # s7comm.blockinfo.author, .headername, .headerversion, .checksum
            if not details.get("block_author"):
                val = self.get_field(s7comm, "blockinfo_author", None)
                if val is None:
                    val = self.get_field(s7comm, "blockinfo.author", None)
                if val is not None:
                    val_str = str(val).strip()
                    if val_str:
                        details["block_author"] = val_str

            if not details.get("block_name"):
                val = self.get_field(s7comm, "blockinfo_headername", None)
                if val is None:
                    val = self.get_field(s7comm, "blockinfo.headername", None)
                if val is not None:
                    val_str = str(val).strip()
                    if val_str:
                        details["block_name"] = val_str

            bi_version = self.get_field(s7comm, "blockinfo_headerversion", None)
            if bi_version is None:
                bi_version = self.get_field(s7comm, "blockinfo.headerversion", None)
            if bi_version is not None:
                val_str = str(bi_version).strip()
                if val_str:
                    details["block_header_version"] = val_str

            bi_checksum = self.get_field(s7comm, "blockinfo_checksum", None)
            if bi_checksum is None:
                bi_checksum = self.get_field(s7comm, "blockinfo.checksum", None)
            if bi_checksum is not None:
                val_str = str(bi_checksum).strip()
                if val_str:
                    details["block_checksum"] = val_str

    def _process_pi_service(
        self,
        s7comm,
        src_ip: str,
        dst_ip: str,
        client_ip: str,
        plc_ip: str,
        direction: str,
        now: str,
        flow_id: str = "",
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process PI (Program Invocation) service calls."""
        service_name = str(self.get_field(s7comm, "param_pistart_servicename", "") or "").strip()
        if not service_name:
            service_name = str(
                self.get_field(s7comm, "param.pistart.servicename", "") or ""
            ).strip()

        if not service_name:
            service_name = "PI Service"

        # Common PI services: _INSE (insert), _DELE (delete), _MODU (start),
        # _GARB (compress), _N_LOGIN_ (login)
        pi_operations = {
            "_INSE": "Insert Block",
            "_DELE": "Delete Block",
            "_MODU": "Start Module",
            "_GARB": "Compress Memory",
            "_N_LOGIN_": "Login",
            "_N_LOGOUT": "Logout",
            "_N_NEWPWD": "Change Password",
        }

        operation = pi_operations.get(service_name, f"PI: {service_name}")

        details: Dict[str, Any] = {"pi_service": service_name}

        # Extract PI argument
        pi_arg = self.get_field(s7comm, "param_pistart_argument", None)
        if pi_arg is None:
            pi_arg = self.get_field(s7comm, "param.pistart.argument", None)
        if pi_arg is not None:
            details["pi_argument"] = str(pi_arg).strip()

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            f"PI Service: {service_name}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _extract_data_values(self, s7comm) -> str:
        """Extract data payload from S7comm Read Var response or Write Var request.

        Tries s7comm.resp.data (FT_BYTES) which contains the raw register/bit
        values transferred.  Returns a compact hex representation, or "" if
        no data payload is present.

        In EK mode, multi-item reads may return comma-separated hex strings
        for each item (e.g. "00:09,00:18") which we compact to "0009,0018".
        """
        raw = self.get_field(s7comm, "resp_data", None)
        if raw is None:
            raw = self.get_field(s7comm, "resp.data", None)
        if raw is not None:
            val = str(raw).strip()
            if val:
                # Compact colon-hex to plain hex (00:09:00:18 → 00090018)
                return val.replace(":", "")

        # Fallback: s7comm.data.userdata for userdata payloads
        raw = self.get_field(s7comm, "data_userdata", None)
        if raw is None:
            raw = self.get_field(s7comm, "data.userdata", None)
        if raw is not None:
            val = str(raw).strip()
            if val:
                return val.replace(":", "")

        return ""

    def _extract_password(self, s7comm, src_ip: str, dst_ip: str) -> None:
        """Extract password from PI service calls (original credential logic)."""
        password = str(self.get_field(s7comm, "param_pi_n_x_password", "") or "").strip()
        if not password:
            password = str(self.get_field(s7comm, "param.pi.n_x.password", "") or "").strip()

        password_level = str(self.get_field(s7comm, "param_pi_n_x_passwordlevel", "") or "").strip()
        if not password_level:
            password_level = str(
                self.get_field(s7comm, "param.pi.n_x.passwordlevel", "") or ""
            ).strip()

        if not password and not password_level:
            return

        if password and not self._is_duplicate(password, src_ip, dst_ip):
            cred = S7commCredential(
                password=password,
                password_level=password_level,
                credential_type="plaintext",
                plc_ip=dst_ip,
                client_ip=src_ip,
                timestamp=datetime.now().isoformat(),
            )
            self.credentials.append(cred)
            self.logger.info(f"S7comm: PLC password extracted from {src_ip} to {dst_ip}")

    def _is_duplicate(self, password: str, client_ip: str, plc_ip: str) -> bool:
        """Check if credential is already recorded."""
        for cred in self.credentials:
            if cred.password == password and cred.client_ip == client_ip and cred.plc_ip == plc_ip:
                return True
        return False

    def _update_devices(
        self,
        client_ip: str,
        plc_ip: str,
        client_mac: str = "",
        plc_mac: str = "",
    ) -> None:
        """Update device entries, enriching with SZL 001C identity when available."""
        if is_valid_discovered_ip(plc_ip):
            plc_vendor = lookup_mac_vendor(plc_mac) if plc_mac else ""
            plc_name = f"Siemens PLC ({plc_ip})"
            protocol_data: Dict[str, Any] = {"role": "plc", "protocol": "S7comm/TCP"}

            # Enrich with SZL 001C identity if available
            identity = self._plc_identity.get(plc_ip)
            if identity:
                module = identity.get("module_name", "")
                cpu = identity.get("cpu_type", "")
                serial = identity.get("serial_number", "")
                plc_name = module or cpu or plc_name
                if module:
                    protocol_data["model"] = module
                if serial:
                    protocol_data["serial_number"] = serial
                if cpu:
                    protocol_data["cpu_type"] = cpu

            device, is_new = self._ensure_device(
                f"s7comm-plc:{plc_ip}",
                plc_ip,
                mac=plc_mac,
                name=plc_name,
                manufacturer=plc_vendor or "Siemens",
                device_type="PLC",
                data_attr="s7comm_passive_data",
                protocol_data=protocol_data,
            )

            # Update existing devices with identity data when it arrives
            if not is_new and identity:
                module = identity.get("module_name", "")
                cpu = identity.get("cpu_type", "")
                if module or cpu:
                    device.name = module or cpu or device.name
                for attr_key in ("model", "serial_number", "cpu_type"):
                    val = identity.get(attr_key) or identity.get(
                        {"model": "module_name"}.get(attr_key, attr_key), ""
                    )
                    if val:
                        pdata = getattr(device, "s7comm_passive_data", {})
                        if isinstance(pdata, dict):
                            pdata[attr_key] = val

        if is_valid_discovered_ip(client_ip):
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            self._ensure_device(
                f"s7comm-client:{client_ip}",
                client_ip,
                mac=client_mac,
                name=f"S7comm Client ({client_ip})",
                manufacturer=client_vendor if client_vendor else "",
                device_type="Engineering Workstation",
                data_attr="s7comm_passive_data",
                protocol_data={"role": "client", "protocol": "S7comm/TCP"},
            )

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        op = ix.operation
        area = ""
        db = ""
        addr = ""
        size = ""
        data = ""

        # Read/Write Var
        if op in ("Read Var", "Write Var"):
            if ix.direction == "request":
                area = d.get("area", "")
                item_count = d.get("item_count", 0)
                if item_count > 1:
                    area = f"{area} (+{item_count - 1})"
                db = d.get("db_number", "")
                addr = d.get("byte_address", "")
                size = d.get("length", "")
                data = d.get("data", "")
            else:
                # Response — show data or error, no area/db/addr
                data = d.get("data", "")
                rc = d.get("return_code")
                if rc is not None and rc != 0xFF:
                    data = f"ERR 0x{rc:02x}" + (f" {data}" if data else "")

        # Download/Upload block control
        elif op in (
            "Request Download",
            "Download Block",
            "Download Ended",
            "Start Upload",
            "Upload",
            "End Upload",
        ):
            area = d.get("block_type", "")
            db = d.get("block_number", "")
            size = d.get("loadmem_len", "")
            # Show block metadata (author/family/name) when available,
            # fall back to filename
            meta_parts = []
            labels = {
                "block_author": "Author",
                "block_family": "Family",
                "block_name": "Name",
                "station_name": "Station",
                "plc_name": "PLC",
                "project_tool": "Tool",
            }
            for key in ("block_author", "block_family", "block_name"):
                val = d.get(key)
                if val:
                    meta_parts.append(f"{labels[key]}: {val}")
            if not meta_parts:
                for key in ("station_name", "plc_name", "project_tool"):
                    val = d.get(key)
                    if val:
                        meta_parts.append(f"{labels[key]}: {val}")
            if meta_parts:
                data = ", ".join(meta_parts)
            else:
                data = d.get("filename", "")

        # Read SZL
        elif op.startswith("Read SZL"):
            area = d.get("szl_id", "")
            # Show extracted SZL data in Data column
            parts = []
            for key in (
                "module_name",
                "cpu_type",
                "serial_number",
                "order_number",
                "firmware_version",
                "protection_level",
            ):
                val = d.get(key)
                if val:
                    parts.append(str(val))
            if parts:
                data = " | ".join(parts)

        # List Blocks
        elif op == "List Blocks":
            # Array summary (e.g., "OB:1 DB:12 FC:0 ...") or single type:count
            bs = d.get("block_summary", "")
            if bs:
                data = bs
            else:
                bt = d.get("block_type", "")
                bc = d.get("block_count", "")
                if bt and bc:
                    data = f"{bt}:{bc}"
                elif bt:
                    data = bt

        # List Blocks of Type
        elif op == "List Blocks of Type":
            area = d.get("block_type", "")
            db = d.get("block_number", "")
            lang = d.get("block_lang", "")
            if lang:
                data = lang

        # Get Block Info
        elif op == "Get Block Info":
            area = d.get("block_type", "")
            db = d.get("block_number", "")
            fs = d.get("block_filesys", "")
            if fs:
                addr = fs
            parts = []
            for key in ("block_name", "block_author", "block_family"):
                val = d.get(key)
                if val:
                    parts.append(str(val))
            if parts:
                data = " | ".join(parts)

        # Setup Communication
        elif op == "Setup Communication":
            size = d.get("pdu_length", "")

        # PI Service
        elif "PI" in op or op in (
            "Insert Block",
            "Delete Block",
            "Start Module",
            "Compress Memory",
            "Login",
            "Logout",
            "Change Password",
        ):
            area = d.get("pi_service", "")
            data = d.get("pi_argument", "")

        return [
            ix.operation,
            area,
            db if db else "",
            addr if addr else "",
            size if size else "",
            data,
        ]

    def harvest(self) -> Dict[str, Any]:
        """Add PLC identification table before the auto-generated operations table."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}

        # Build PLC identification table from SZL data
        identity_rows = []
        for plc_ip, identity in self._plc_identity.items():
            identity_rows.append(
                [
                    plc_ip,
                    identity.get("module_name", ""),
                    identity.get("cpu_type", ""),
                    identity.get("order_number", ""),
                    identity.get("firmware_version", ""),
                    identity.get("serial_number", ""),
                ]
            )
        if identity_rows:
            identity_table = {
                "headers": ["IP", "Module", "CPU Type", "Order Number", "Firmware", "Serial"],
                "rows": identity_rows,
                "title": f"S7comm PLC Identification ({len(identity_rows)})",
            }
            tables = result.setdefault("tables", [])
            tables.insert(0, identity_table)

        # Build block transfers table
        # Include any incomplete transfers that never got a "Download Ended"
        all_blocks = list(self._completed_blocks)
        for _key, transfer in self._block_transfers.items():
            if transfer.get("block_type") or transfer.get("segments"):
                record: Dict[str, Any] = {
                    "direction": transfer.get("direction", "unknown"),
                    "block_type": transfer.get("block_type", ""),
                    "block_number": transfer.get("block_number", ""),
                    "load_len": transfer.get("load_len", 0),
                    "src_ip": transfer.get("src_ip", ""),
                    "dst_ip": transfer.get("dst_ip", ""),
                }
                for key in (
                    "block_author",
                    "block_family",
                    "block_name",
                    "station_name",
                    "plc_name",
                    "project_tool",
                ):
                    val = transfer.get(key)
                    if val:
                        record[key] = val
                all_blocks.append(record)

        if all_blocks:
            block_rows = []
            for blk in all_blocks:
                direction = blk.get("direction", "")
                bt = blk.get("block_type", "")
                bn = blk.get("block_number", "")
                block_id = f"{bt}{bn}" if bt and bn else (bt or str(bn))
                size = blk.get("load_len", "")
                # Metadata column
                meta_parts = []
                labels = {
                    "block_author": "Author",
                    "block_family": "Family",
                    "block_name": "Name",
                    "station_name": "Station",
                    "plc_name": "PLC",
                    "project_tool": "Tool",
                }
                for key in ("block_author", "block_family", "block_name"):
                    val = blk.get(key)
                    if val:
                        meta_parts.append(f"{labels[key]}: {val}")
                for key in ("station_name", "plc_name", "project_tool"):
                    val = blk.get(key)
                    if val:
                        meta_parts.append(f"{labels[key]}: {val}")
                meta = ", ".join(meta_parts) if meta_parts else ""
                src = blk.get("src_ip", "")
                dst = blk.get("dst_ip", "")
                block_rows.append([direction, block_id, size, meta, src, dst])

            block_table = {
                "headers": ["Dir", "Block", "Size", "Metadata", "From", "To"],
                "rows": block_rows,
                "title": f"S7comm Block Transfers ({len(block_rows)})",
            }
            tables = result.setdefault("tables", [])
            # Insert after identity table, before interaction tables
            insert_pos = 1 if identity_rows else 0
            tables.insert(insert_pos, block_table)

        return result

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write/control operations."""
        return [
            {
                "client": client,
                "server": plc,
                "write_count": count,
            }
            for (client, plc), count in self._write_counts.items()
            if count > 0
        ]

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return [
            {
                "protocol": "S7comm",
                "credential_type": cred.credential_type,
                "username": cred.password,  # canonical key for harvest() builder
                "auth_method": cred.auth_method,
                "server_ip": cred.plc_ip,  # canonical key for harvest() builder
                "client_ip": cred.client_ip,
                "password_level": cred.password_level,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]
