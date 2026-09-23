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

tshark fields used (packet.iscsi.* unless noted):
- iscsi.opcode: iSCSI opcode (login, text, SCSI command, etc.)
- iscsi.keyvalue: login/text ``key=value`` pairs (RFC 7143 text). The
  dissector has NO dedicated iscsi.login.target_name / initiator_name /
  auth_method / session_type fields -- TargetName, InitiatorName,
  AuthMethod and SessionType are parsed out of these keyvalue pairs.
- iscsi.login.status: Login response status
- iscsi.isid: Initiator Session ID
- scsi.lun: LUN being accessed -- lives on the SCSI layer, NOT iscsi.lun
- iscsi.datasegmentlength: Data payload length
- iscsi.scsicommand.R / .W: Read/Write flags
- iscsi.scsicommand.expecteddatatransferlength: Transfer size
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from ._iscsi_msrpc_common import RecordInteractionMixin
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

# Login status codes.
# iscsi.login.status is FT_UINT16/BASE_HEX: XML mode renders it as a hex
# string ("0x0201"), EK mode renders the raw decimal integer as a string
# ("513"). Both forms are keyed here (mirrors OPCODES above) so lookups hit
# regardless of pyshark mode.
LOGIN_STATUS = {
    "0": "Success",
    "0x0000": "Success",
    "256": "Target moved temporarily",
    "0x0100": "Target moved temporarily",
    "257": "Target moved permanently",
    "0x0101": "Target moved permanently",
    "512": "Initiator error",
    "0x0200": "Initiator error",
    "513": "Authentication failure",
    "0x0201": "Authentication failure",
    "514": "Authorization failure",
    "0x0202": "Authorization failure",
    "515": "Not found",
    "0x0203": "Not found",
    "516": "Target removed",
    "0x0204": "Target removed",
    "517": "Unsupported version",
    "0x0205": "Unsupported version",
    "518": "Too many connections",
    "0x0206": "Too many connections",
    "519": "Missing parameter",
    "0x0207": "Missing parameter",
    "520": "Can't include in session",
    "0x0208": "Can't include in session",
    "521": "Session type not supported",
    "0x0209": "Session type not supported",
    "522": "Session does not exist",
    "0x020a": "Session does not exist",
    "523": "Invalid during login",
    "0x020b": "Invalid during login",
    "768": "Target error",
    "0x0300": "Target error",
    "769": "Service unavailable",
    "0x0301": "Service unavailable",
    "770": "Out of resources",
    "0x0302": "Out of resources",
}

# Login status codes that indicate an authentication/authorization failure --
# surfaced as alerts so failed CHAP/login attempts are visible. Both hex
# (XML mode) and decimal (EK mode) forms, matching LOGIN_STATUS above.
LOGIN_FAILURE_STATUS = {"0x0201", "0x0202", "0x0203", "513", "514", "515"}

# CHAP login text key=value pairs. iSCSI carries CHAP over the login/text data
# segment as RFC 7143 key=value text (CHAP_A/I/C/N/R), which Wireshark exposes
# via the generic login keyvalue field rather than dedicated iscsi.chap.* fields.
#   CHAP_A = algorithm (5 = MD5)
#   CHAP_I = identifier (the "id" byte, used as hashcat salt position)
#   CHAP_C = challenge (target -> initiator)
#   CHAP_N = name (the CHAP username)
#   CHAP_R = response (initiator -> target; the MD5 digest = the crackable hash)
# Value is printable ASCII excluding the '=' separator and the RFC 7143 pair
# delimiter ',' (plus whitespace/NUL) so a greedy match cannot swallow the
# next key=value pair.  CHAP values themselves never contain '=' or ','.
_CHAP_KV_RE = re.compile(rb"CHAP_([AICNR])=([\x21-\x2b\x2d-\x3c\x3e-\x7e]+)")


@dataclass
class ISCSICredential:
    """Extracted iSCSI CHAP credential.

    The CHAP response (CHAP_R) is an MD5 digest of (id || secret || challenge),
    crackable offline with hashcat mode 4800 once the challenge and id are known.
    """

    username: str = ""  # CHAP_N
    chap_id: str = ""  # CHAP_I
    challenge: str = ""  # CHAP_C (hex)
    response: str = ""  # CHAP_R (hex digest)
    algorithm: str = ""  # CHAP_A (5 = MD5)
    server_ip: str = ""  # target
    server_port: int = 0
    client_ip: str = ""  # initiator
    timestamp: str = ""
    credential_type: str = "hash"
    auth_method: str = "CHAP"

    @property
    def hash_value(self) -> str:
        """Canonical credential field: the CHAP MD5 response digest."""
        return self.response

    @property
    def hashcat_format(self) -> str:
        """hashcat mode 4800 line: ``response:challenge:id``.

        Empty when the captured material is incomplete (no response, or no
        challenge/id to anchor the hash) -- the scanner treats an empty
        hashcat_format as "not crackable" and skips the bare-value line.
        """
        resp = self._strip_hex(self.response)
        chal = self._strip_hex(self.challenge)
        cid = self.chap_id
        if not (resp and chal and cid):
            return ""
        # CHAP_I is decimal in the text protocol; hashcat 4800 expects the id
        # as a two-hex-digit value.
        try:
            id_hex = f"{int(cid, 0) & 0xFF:02x}"
        except (ValueError, TypeError):
            id_hex = cid
        return f"{resp}:{chal}:{id_hex}"

    @staticmethod
    def _strip_hex(val: str) -> str:
        """Normalise a CHAP hex value (drop ``0x`` prefix and colons)."""
        return str(val).strip().lower().removeprefix("0x").replace(":", "")


class ISCSIPassiveListener(RecordInteractionMixin, PySharkListenerBase):
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
        # Extracted CHAP credentials/hashes (consumed by the scanner cred loop)
        self.credentials: List[ISCSICredential] = []
        self._seen_creds: Set[Tuple[str, str, str]] = set()  # (user, server, response)
        # Per-flow CHAP accumulator -- challenge (CHAP_C) and response (CHAP_R)
        # arrive in separate PDUs, so correlate them by flow_id.
        self._chap_state: Dict[str, Dict[str, str]] = {}
        # Security alerts (login/auth failures)
        self._alerts: List[Dict[str, str]] = []

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

        # Target/initiator IQN, auth method and session type are carried as
        # RFC 7143 login/text ``key=value`` text, which Wireshark exposes as
        # repeated ``iscsi.keyvalue`` fields -- there are NO dedicated
        # iscsi.login.target_name / initiator_name / auth_method / session_type
        # fields, so we parse them out of the keyvalue pairs.
        login_kv = self._parse_login_keyvalues(self._collect_keyvalues(iscsi))
        target_name = login_kv.get("TargetName", "")
        initiator_name = login_kv.get("InitiatorName", "")
        auth_method = login_kv.get("AuthMethod", "")
        session_type = login_kv.get("SessionType", "")

        # LUN is carried on the SCSI layer as scsi.lun (there is no iscsi.lun).
        lun_str = ""
        if hasattr(packet, "scsi"):
            lun = self.get_field(packet.scsi, "lun", None)
            lun_str = str(lun) if lun is not None else ""

        # Extract session ID
        isid = self.get_field(iscsi, "isid", None)
        isid_str = str(isid) if isid is not None else ""

        # Login status
        login_status = self.get_field(iscsi, "login_status", None)
        if login_status is None:
            login_status = self.get_field(iscsi, "login.status", None)
        login_status_str = str(login_status) if login_status is not None else ""
        login_status_name = LOGIN_STATUS.get(login_status_str, "")

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
        server_ip, client_ip, server_mac, client_mac = self._record_and_resolve_endpoints(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_mac=src_mac,
            dst_mac=dst_mac,
            direction=direction,
            operation=operation,
            details=details,
            summary=summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
            is_response=is_response,
            now=now,
        )

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

        # CHAP credential / hash extraction from login text segment.
        server_port = dst_port if not is_response else src_port
        self._extract_chap(iscsi, flow_id, client_ip, server_ip, server_port, now, opcode_name)

        # Surface login/authentication failures as alerts.
        if login_status_str in LOGIN_FAILURE_STATUS:
            self._alerts.append(
                {
                    "level": "warning",
                    "category": "control_alert",
                    "message": (
                        f"iSCSI LOGIN FAILURE: {client_ip} -> {server_ip} "
                        f"[{login_status_name or login_status_str}]"
                    ),
                }
            )

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

    # -------------------------------------------------------------------------
    # Login/text key=value parsing
    # -------------------------------------------------------------------------

    def _collect_keyvalues(self, iscsi: Any) -> List[str]:
        """Return every ``iscsi.keyvalue`` login/text pair as a string.

        Wireshark emits one ``iscsi.keyvalue`` field per RFC 7143 ``key=value``
        login/text pair.  EK mode delivers repeats as a Python list; XML mode
        exposes them via ``.all_fields``.  Both are flattened to a list of plain
        ``"Key=Value"`` strings.  Read via raw ``getattr`` (not ``get_field``)
        so multi-value pairs stay separate rather than being comma-joined --
        an ``AuthMethod=CHAP,None`` value would otherwise be indistinguishable
        from two separate pairs.
        """
        raw = getattr(iscsi, "keyvalue", None)
        if raw is None:
            return []
        pairs: List[str] = []
        if isinstance(raw, list):
            for item in raw:
                item = self._resolve_value(item, "")
                if item not in (None, ""):
                    pairs.append(str(item))
            return pairs
        # XML mode: repeated same-named fields are reachable via .all_fields.
        try:
            for fld in raw.all_fields:
                val = str(getattr(fld, "show", "") or "")
                if val:
                    pairs.append(val)
        except Exception:
            val = self._resolve_value(raw, "")
            if val not in (None, ""):
                pairs.append(str(val))
        return pairs

    @staticmethod
    def _parse_login_keyvalues(pairs: List[str]) -> Dict[str, str]:
        """Split ``Key=Value`` login/text pairs into a dict (last value wins)."""
        out: Dict[str, str] = {}
        for kv in pairs:
            key, sep, value = kv.partition("=")
            if sep and key:
                out[key.strip()] = value.strip()
        return out

    # -------------------------------------------------------------------------
    # CHAP credential extraction
    # -------------------------------------------------------------------------

    def _extract_chap(
        self,
        iscsi: Any,
        flow_id: str,
        client_ip: str,
        server_ip: str,
        server_port: int,
        now: str,
        opcode_name: str,
    ) -> None:
        """Extract CHAP key=value pairs from the iSCSI login text segment.

        CHAP is carried as RFC 7143 text (``CHAP_A/I/C/N/R``) in the login/text
        data segment.  Wireshark surfaces these via the generic login keyvalue
        field rather than dedicated ``iscsi.chap.*`` fields, and the same
        ``CHAP_x=y`` text is also present in the raw data segment.  We probe both
        sources so extraction works regardless of which the active tshark build
        exposes.  Challenge (``CHAP_C``) and response (``CHAP_R``) arrive in
        separate PDUs, so we correlate them per ``flow_id``.
        """
        # Gather candidate text from named keyvalue fields and the data segment.
        # Field names verified via `tshark -G fields | grep -P '\tiscsi\.'`:
        # the login/text KeyValue field is always "iscsi.keyvalue" (there is
        # no separate login_keyvalue / text_keyvalue field), there is no
        # iscsi.data or iscsi.datasegment field at all, and the ping payload
        # field sanitizes to "pingdata" (not "ping_data"). The remaining
        # byte-content fields that could plausibly carry raw text in other
        # PDU types are "immediatedata" and "vendorspecificdata".
        candidates: List[str] = []
        for fname in (
            "keyvalue",
            "pingdata",
            "immediatedata",
            "vendorspecificdata",
        ):
            val = self.get_field(iscsi, fname, None)
            if val:
                candidates.append(str(val))

        pairs: Dict[str, str] = {}
        for text in candidates:
            # Match both raw text and tshark's colon-hex byte rendering.
            raw = text.encode("utf-8", errors="ignore")
            for m in _CHAP_KV_RE.finditer(raw):
                key = m.group(1).decode("ascii")
                pairs[key] = m.group(2).decode("ascii", errors="ignore")

        if not pairs:
            return

        if not flow_id:
            # Without a flow id we cannot correlate challenge/response across
            # PDUs; fall back to an endpoint-pair key so extraction still works.
            flow_id = f"{client_ip}<->{server_ip}"
        state = self._chap_state.setdefault(flow_id, {})
        for key in ("A", "I", "C", "N", "R"):
            if key in pairs and pairs[key]:
                state[key] = pairs[key]
        self.logger.debug(
            f"iSCSI CHAP fields {sorted(pairs)} on flow {flow_id} "
            f"({opcode_name}); accumulated {sorted(state)}"
        )

        # A response (CHAP_R) is the crackable material; record once we have it.
        if "R" not in state:
            return

        username = state.get("N", "")
        response = state.get("R", "")
        chap_id = state.get("I", "")
        challenge = state.get("C", "")
        algorithm = state.get("A", "")
        # Clear the per-flow accumulator now that a full challenge/response
        # exchange has been captured. Without this the dict grows unbounded
        # across a long capture with many flows, and -- since RFC 7143
        # permits more than one login phase on the same connection -- a
        # second CHAP exchange on the same flow that omits CHAP_N would
        # otherwise incorrectly pair the stale username from the first
        # exchange with the new CHAP_R.
        del self._chap_state[flow_id]

        dedup = (username, server_ip, response)
        if dedup in self._seen_creds:
            return
        self._seen_creds.add(dedup)

        cred = ISCSICredential(
            username=username,
            chap_id=chap_id,
            challenge=challenge,
            response=response,
            algorithm=algorithm,
            server_ip=server_ip,
            server_port=server_port,
            client_ip=client_ip,
            timestamp=now,
        )
        self.credentials.append(cred)
        if cred.hashcat_format:
            self.logger.info(
                f"iSCSI CHAP hash: user={username or '?'} @ {server_ip}:{server_port} "
                f"[hashcat 4800: {cred.hashcat_format}]"
            )
        else:
            self.logger.info(
                f"iSCSI CHAP (incomplete) user={username or '?'} @ {server_ip} "
                "-- missing challenge/id, not crackable"
            )

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Return CHAP credentials in scanner-compatible canonical-key form."""
        return [
            {
                "protocol": "iSCSI",
                "credential_type": cred.credential_type,
                "auth_method": cred.auth_method,
                "username": cred.username or "?",
                "hash_value": cred.response,
                "hashcat_format": cred.hashcat_format,
                "server_ip": cred.server_ip,
                "server_port": cred.server_port,
                "client_ip": cred.client_ip,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]

    def get_hashes_summary(self) -> List[Dict[str, Any]]:
        """Return CHAP hashes for the unified hashes table / hashcat export."""
        return [
            {
                "protocol": "iSCSI",
                "hash_type": "CHAP-MD5",
                "username": cred.username or "?",
                "hash_value": cred.response,
                "hashcat_format": cred.hashcat_format,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
            }
            for cred in self.credentials
        ]

    def get_hashcat_hashes(self) -> List[str]:
        """iSCSI CHAP hashes in hashcat mode-4800 format (``response:challenge:id``).

        Delegates to the per-credential property so incomplete pairs (missing
        challenge/response/id) are skipped rather than exported as bogus lines.
        """
        return [c.hashcat_format for c in self.credentials if c.hashcat_format]

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data including target discovery tables."""
        base = super().harvest()
        if not base:
            base = {"tables": [], "alerts": []}
        tables = base.get("tables", [])
        alerts = base.get("alerts", [])
        for alert in self._alerts:
            if alert not in alerts:
                alerts.append(alert)
        if alerts:
            base["alerts"] = alerts

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
