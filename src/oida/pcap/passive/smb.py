"""
SMB Passive Listener for Windows host discovery.

Extracts Windows host information from SMB/NTLM traffic:
- SMB dialect negotiation (version detection)
- NTLM authentication data (domain, username, workstation)

Based on BruteShark's NtlmsspHashParser approach for NTLM parsing.
Uses PyShark for cleaner SMB/SMB2 field extraction.

Contains:
- SMBPassiveListener: Passive SMB/NTLM traffic monitoring
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# SMB dialect strings (SMB1 negotiate)
SMB1_DIALECTS = {
    "PC NETWORK PROGRAM 1.0": "SMB1",
    "MICROSOFT NETWORKS 1.03": "SMB1",
    "MICROSOFT NETWORKS 3.0": "SMB1",
    "LANMAN1.0": "SMB1",
    "LM1.2X002": "SMB1",
    "DOS LANMAN2.1": "SMB1",
    "LANMAN2.1": "SMB1",
    "Samba": "SMB1",
    "NT LANMAN 1.0": "SMB1",
    "NT LM 0.12": "SMB1",
}

# SMB2/3 dialect codes
SMB2_DIALECTS = {
    0x0202: "SMB 2.002",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

SMB1_COMMANDS = {
    0x04: "Close",
    0x06: "Delete",
    0x07: "Rename",
    0x08: "QueryInfo",
    0x0D: "LockByteRange",
    0x10: "CheckDirectory",
    0x24: "LockingAndX",
    0x25: "Transaction",
    0x2B: "Echo",
    0x2D: "OpenAndX",
    0x2E: "ReadAndX",
    0x2F: "WriteAndX",
    0x32: "Transaction2",
    0x71: "TreeDisconnect",
    0x72: "Negotiate",
    0x73: "SessionSetup",
    0x74: "Logoff",
    0x75: "TreeConnect",
    0xA2: "NTCreate",
}

SMB2_COMMANDS = {
    0: "Negotiate",
    1: "SessionSetup",
    2: "Logoff",
    3: "TreeConnect",
    4: "TreeDisconnect",
    5: "Create",
    6: "Close",
    7: "Flush",
    8: "Read",
    9: "Write",
    10: "Lock",
    11: "Ioctl",
    12: "Cancel",
    13: "Echo",
    14: "QueryDirectory",
    15: "ChangeNotify",
    16: "QueryInfo",
    17: "SetInfo",
    18: "OplockBreak",
}

# Well-known NT Status codes for human-readable labels
NT_STATUS_CODES = {
    0x00000000: "STATUS_SUCCESS",
    0x00000103: "STATUS_PENDING",
    0x80000005: "STATUS_BUFFER_OVERFLOW",
    0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC000006D: "STATUS_LOGON_FAILURE",
    0xC000006E: "STATUS_ACCOUNT_RESTRICTION",
    0xC0000072: "STATUS_ACCOUNT_DISABLED",
    0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED",
    0xC0000064: "STATUS_NO_SUCH_USER",
    0xC000006A: "STATUS_WRONG_PASSWORD",
    0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
    0xC0000224: "STATUS_PASSWORD_MUST_CHANGE",
    0xC0000193: "STATUS_ACCOUNT_EXPIRED",
    0xC000005E: "STATUS_NO_LOGON_SERVERS",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
    0xC0000035: "STATUS_OBJECT_NAME_COLLISION",
    0xC00000BA: "STATUS_FILE_IS_A_DIRECTORY",
    0xC0000043: "STATUS_SHARING_VIOLATION",
    0xC0000008: "STATUS_INVALID_HANDLE",
    0xC0000120: "STATUS_CANCELLED",
    0xC0000128: "STATUS_FILE_CLOSED",
}

# SMB2 Create action disposition values
SMB2_CREATE_ACTIONS = {
    0: "FILE_SUPERSEDED",
    1: "FILE_OPENED",
    2: "FILE_CREATED",
    3: "FILE_OVERWRITTEN",
}

# SMB2 cipher IDs for negotiate context
SMB2_CIPHER_IDS = {
    1: "AES-128-CCM",
    2: "AES-128-GCM",
    3: "AES-256-CCM",
    4: "AES-256-GCM",
}


class SMBPassiveListener(PySharkListenerBase):
    """Passive SMB/NTLM traffic listener for Windows host discovery.

    Captures SMB traffic to identify:
    - Windows hosts via NTLM authentication
    - Domain/workgroup names
    - Usernames and workstation names
    - SMB protocol versions
    - Tree connect paths (shares)

    Usage:
        # Live capture
        listener = SMBPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
        devices = listener.scan()

        # Testing - feed packets directly
        listener = SMBPassiveListener(interface="eth0")
        listener.feed_packet(mock_smb_packet)

    Data structure stored in device.smb_passive_data:
        {
            "role": "server" | "client",
            "smb_version": "SMB1" | "SMB2" | "SMB3",
            "dialects": ["NT LM 0.12", "SMB 2.002"],
            "domain": "CONTOSO",
            "workstation": "WORKSTATION01",
            "username": "john.doe",
            "os_version": "Windows 10",
            "shares": ["\\\\SERVER\\SHARE"],
            "protocol": "SMB/TCP",
        }
    """

    PROTOCOL_NAME = "smb"
    DISPLAY_FILTER = "smb or smb2"
    REQUIRED_LAYERS = ("smb", "smb2", "ntlmssp")
    PROTOCOL_COLUMNS = ("version", "domain", "user", "share", "operation")

    SMB_PORTS = (445, 139)

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize SMB passive listener.

        Args:
            interface: Network interface to capture on
            timeout: Capture timeout in seconds
            nxc_logger: Optional NXC-style logger for user-visible output
        """
        super().__init__(
            interface=interface,
            timeout=timeout,
            nxc_logger=nxc_logger,
        )
        # Track SMB sessions by (src_ip, dst_ip) for correlation
        self._sessions: Dict[tuple, Dict[str, Any]] = {}
        # Track file operations: (operation, filename, client_ip, server_ip)
        self._file_ops: List[Tuple[str, str, str, str]] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format SMB interaction as protocol-specific table columns."""
        d = ix.details
        return [
            d.get("smb_version", "?"),
            d.get("domain", ""),
            d.get("username", ""),
            d.get("share", ""),
            ix.operation,
        ]

    def process_packet(self, packet) -> None:
        """Process SMB/NTLM packet and extract Windows host info.

        Uses PyShark's SMB/SMB2 dissector for cleaner field extraction.
        """
        if not (hasattr(packet, "smb") or hasattr(packet, "smb2") or hasattr(packet, "ntlmssp")):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        # Determine role based on port
        if dst_port in self.SMB_PORTS:
            # Traffic TO SMB port - sender is client
            client_ip = src_ip
            server_ip = dst_ip
            is_client_packet = True
        else:
            # Traffic FROM SMB port - sender is server
            client_ip = dst_ip
            server_ip = src_ip
            is_client_packet = False

        # Track session
        session_key = (client_ip, server_ip)
        if session_key not in self._sessions:
            self._sessions[session_key] = {
                "client_ip": client_ip,
                "server_ip": server_ip,
                "smb_version": None,
                "dialects": [],
                "domain": None,
                "username": None,
                "workstation": None,
                "os_version": None,
                "shares": [],
            }

        session = self._sessions[session_key]

        # Extract SMB data from PyShark layers
        self._extract_smb_data(packet, session)
        self._extract_smb2_data(packet, session)
        self._extract_ntlmssp_data(packet, session)

        # Record interaction
        now = datetime.now().isoformat()
        direction = "request" if is_client_packet else "response"
        details: Dict[str, Any] = {}
        smb_ver = session.get("smb_version") or "SMB"
        details["smb_version"] = smb_ver
        if session.get("domain"):
            details["domain"] = session["domain"]
        if session.get("username"):
            details["username"] = session["username"]
        shares = session.get("shares", [])
        if shares:
            details["share"] = shares[-1]

        # NT Status (consumed per-packet)
        nt_status_name = session.pop("_last_nt_status_name", None)
        if nt_status_name:
            details["nt_status"] = nt_status_name
        nt_status_val = session.pop("_last_nt_status", None)
        if nt_status_val is not None:
            details["nt_status_code"] = nt_status_val

        # DOS error class/code (SMB1)
        err_class = session.pop("_last_error_class", None)
        if err_class is not None:
            details["error_class"] = err_class
        err_code = session.pop("_last_error_code", None)
        if err_code is not None:
            details["error_code"] = err_code

        # Session ID
        sesid = session.pop("_last_sesid", None)
        if sesid is not None and sesid != "0":
            details["session_id"] = sesid

        # SMB1 header correlation IDs (consumed per-packet)
        for key, detail_key in (
            ("_last_smb_tid", "tid"),
            ("_last_smb_uid", "uid"),
            ("_last_smb_pid", "pid"),
            ("_last_smb_mid", "mid"),
        ):
            val = session.pop(key, None)
            if val is not None:
                details[detail_key] = val

        # SMB2 correlation IDs (consumed per-packet)
        msg_id = session.pop("_last_smb2_msg_id", None)
        if msg_id is not None:
            details["msg_id"] = msg_id
        tree_id = session.pop("_last_smb2_tid", None)
        if tree_id is not None:
            details["tree_id"] = tree_id

        # SMB1 password length / setup action (credential + logon-type indicators)
        pw_len = session.pop("_last_password_length", None)
        if pw_len is not None:
            details["password_length"] = pw_len
        setup_action = session.pop("_last_setup_action", None)
        if setup_action is not None:
            details["setup_action"] = setup_action
            if setup_action & 0x1:
                details["guest_logon"] = True

        # SMB3.1.1 pre-auth integrity hash
        if session.get("preauth_hash"):
            details["preauth_hash"] = session["preauth_hash"]

        # Server hostname
        if session.get("server_hostname"):
            details["server_hostname"] = session["server_hostname"]

        # Signing enabled
        if session.get("signing_enabled") is not None:
            details["signing_enabled"] = session["signing_enabled"]

        # Ciphers
        if session.get("ciphers"):
            details["ciphers"] = session["ciphers"]

        # Password blob indicator
        if session.pop("_has_password_blob", None):
            details["has_password_blob"] = True

        # Transaction name (SMB1)
        trans_name = session.pop("_last_trans_name", None)
        if trans_name:
            details["trans_name"] = trans_name

        # IOCTL function
        ioctl_fn = session.pop("_last_ioctl_function", None)
        if ioctl_fn:
            details["ioctl_function"] = ioctl_fn

        # Create action
        create_action = session.pop("_last_create_action", None)
        if create_action:
            details["create_action"] = create_action

        # Build operation from command + context
        cmd_name = session.pop("_last_cmd", "")
        last_file = session.pop("_last_file", "")
        if cmd_name:
            op = f"{smb_ver} {cmd_name}"
            if last_file:
                op += f" {last_file}"
        else:
            op = f"{smb_ver} {direction.title()}"
        share_str = f" share={shares[-1]}" if shares else ""
        user_str = f" user={session.get('username')}" if session.get("username") else ""
        domain_str = f" {session.get('domain')}" if session.get("domain") else ""
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            op,
            details,
            f"{smb_ver}{domain_str}{user_str}{share_str}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Update devices with session data
        self._update_device(
            ip=server_ip,
            mac=dst_mac if is_client_packet else src_mac,
            role="server",
            session=session,
        )

        # If we have NTLM Type 3 (client auth), also update client
        if session.get("workstation"):
            self._update_device(
                ip=client_ip,
                mac=src_mac if is_client_packet else dst_mac,
                role="client",
                session=session,
            )

    def _get_smb1_command(self, layer) -> str:
        """Get first meaningful SMB1 command name from cmd field.

        In EK mode, cmd may be a list (e.g. [115, 255] for AndX chains).
        Skip 0xFF (no further commands).

        Uses getattr directly instead of get_field() because get_field()
        normalizes lists to comma-separated strings, losing the list structure.
        """
        raw = self._resolve_value(getattr(layer, "cmd", None))
        if raw is None:
            return ""
        if isinstance(raw, list):
            for v in raw:
                try:
                    c = int(self._resolve_value(v, 0))
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"SMB1: command code int parse (list element) failed: {e}")
                    continue
                if c != 0xFF:
                    return SMB1_COMMANDS.get(c, f"Cmd{c:#x}")
            return ""
        try:
            c = int(self._resolve_value(raw, 0))
            return SMB1_COMMANDS.get(c, f"Cmd{c:#x}") if c != 0xFF else ""
        except (ValueError, TypeError) as e:
            self.logger.debug(f"SMB1: command code int parse (scalar) failed: {e}")
            return ""

    def _extract_smb_data(self, packet, session: Dict[str, Any]) -> None:
        """Extract SMB1 protocol data from PyShark packet."""
        if not hasattr(packet, "smb"):
            return

        smb = packet.smb

        if not session.get("smb_version"):
            session["smb_version"] = "SMB1"

        # Domain from primary_domain field (EK mode uses this name)
        for fname in ("primary_domain", "domain"):
            domain = self.get_field(smb, fname)
            if domain and str(domain) not in ("", "None"):
                domain = str(self._resolve_value(domain, ""))
                if domain and not session.get("domain"):
                    session["domain"] = domain
                break

        # Native OS from negotiate response
        native_os = self.get_field(smb, "native_os")
        if native_os:
            native_os = str(self._resolve_value(native_os, ""))
            if native_os and not session.get("os_version"):
                session["os_version"] = native_os

        # Dialect from negotiate (may be list in EK mode)
        for fname in ("dialect_name", "dialect"):
            dialect = self.get_field(smb, fname)
            if dialect is not None:
                if isinstance(dialect, list):
                    for d in dialect:
                        ds = str(self._resolve_value(d, ""))
                        if ds and ds not in session.get("dialects", []):
                            session.setdefault("dialects", []).append(ds)
                else:
                    ds = str(self._resolve_value(dialect, ""))
                    if ds and ds not in session.get("dialects", []):
                        session.setdefault("dialects", []).append(ds)
                break

        # Share path from SMB1 TreeConnect (path field)
        path = self.get_field(smb, "path")
        if path:
            path = str(self._resolve_value(path, ""))
            if path:
                shares = session.setdefault("shares", [])
                if path not in shares:
                    shares.append(path)

        # Service type (IPC, A:, LPT1:, etc.)
        service = self.get_field(smb, "service")
        if service:
            service = str(self._resolve_value(service, ""))
            if service:
                session["service"] = service

        # NT Status code (SMB1)
        nt_status_raw = self.get_field(smb, "nt_status")
        if nt_status_raw is not None:
            try:
                nt_val = int(nt_status_raw)
                session["_last_nt_status"] = nt_val
                session["_last_nt_status_name"] = NT_STATUS_CODES.get(nt_val, f"0x{nt_val:08X}")
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get nt_val: {e}")

        # DOS error class/code (SMB1 only, mutually exclusive with NT status)
        error_class = self.get_field(smb, "error_class")
        if error_class is not None:
            session["_last_error_class"] = str(error_class)
        error_code = self.get_field(smb, "error_code")
        if error_code is not None:
            session["_last_error_code"] = str(error_code)

        # SMB1 account field (plaintext auth username)
        account = self.get_field(smb, "account")
        if account:
            account = str(self._resolve_value(account, "")).strip()
            if account and not session.get("username"):
                session["username"] = account

        # SMB1 password blob presence (credential indicator)
        password = self.get_field(smb, "password")
        if password is not None:
            session["_has_password_blob"] = True

        # Transaction name (e.g. \PIPE\LANMAN, \MAILSLOT\BROWSE)
        trans_name = self.get_field(smb, "trans_name")
        if trans_name:
            trans_name = str(self._resolve_value(trans_name, "")).strip()
            if trans_name:
                session["_last_trans_name"] = trans_name

        # SMB1 header correlation IDs (TID/UID/PID/MID) for request/response matching
        for raw_field, key in (
            ("tid", "smb_tid"),
            ("uid", "smb_uid"),
            ("pid", "smb_pid"),
            ("mid", "smb_mid"),
        ):
            val = self.get_field(smb, raw_field)
            if val is not None:
                resolved = str(self._resolve_value(val, "")).strip()
                if resolved:
                    session[f"_last_{key}"] = resolved

        # SMB1 password length (credential indicator: non-zero => password supplied)
        pwlen = self.get_field(smb, "pwlen")
        if pwlen is not None:
            try:
                pw_val = int(self._resolve_value(pwlen, 0))
                if pw_val > 0:
                    session["_last_password_length"] = pw_val
            except (ValueError, TypeError) as e:
                self.logger.debug(f"SMB1: pwlen int parse failed: {e}")

        # SMB1 SessionSetup action flags (bit0 => guest logon)
        setup_action = self.get_field(smb, "setup.action")
        if setup_action is None:
            setup_action = self.get_field(smb, "setup_action")
        if setup_action is not None:
            try:
                act_val = int(str(self._resolve_value(setup_action, "0")), 0)
                session["_last_setup_action"] = act_val
            except (ValueError, TypeError) as e:
                self.logger.debug(f"SMB1: setup.action int parse failed: {e}")

        # SMB1 command name for operation tracking
        cmd_name = self._get_smb1_command(smb)
        if cmd_name:
            session["_last_cmd"] = cmd_name

        # SMB1 file/path tracking (file field may be EkMultiField)
        smb1_file = self.get_field(smb, "file")
        if smb1_file is not None:
            resolved = str(self._resolve_value(smb1_file, "")).strip()
            if resolved:
                session["_last_file"] = resolved
                op = cmd_name or "Access"
                entry = (
                    op,
                    resolved,
                    session.get("client_ip", ""),
                    session.get("server_ip", ""),
                )
                if entry not in self._file_ops:
                    self._file_ops.append(entry)

    def _extract_smb2_data(self, packet, session: Dict[str, Any]) -> None:
        """Extract SMB2/SMB3 protocol data from PyShark packet."""
        if not hasattr(packet, "smb2"):
            return

        smb2 = packet.smb2

        # Dialect revision (may be EkMultiField)
        dialect_rev = self.get_field(smb2, "dialect")
        if dialect_rev is not None:
            dialect_rev = self._resolve_value(dialect_rev)
            try:
                if isinstance(dialect_rev, str) and dialect_rev.startswith("0x"):
                    dialect_code = int(dialect_rev, 16)
                else:
                    dialect_code = int(dialect_rev)

                dialect_name = SMB2_DIALECTS.get(dialect_code, f"0x{dialect_code:04X}")

                if dialect_name not in session.get("dialects", []):
                    session.setdefault("dialects", []).append(dialect_name)

                if "3.1" in dialect_name or "3.0" in dialect_name:
                    session["smb_version"] = "SMB3"
                elif "2." in dialect_name:
                    session["smb_version"] = "SMB2"
            except (ValueError, TypeError) as e:
                self.logger.debug(f"if isinstance(dialect_rev, str) and d...: {e}")

        # NT Status code (SMB2)
        nt_status_raw = self.get_field(smb2, "nt_status")
        if nt_status_raw is not None:
            try:
                nt_val = int(nt_status_raw)
                session["_last_nt_status"] = nt_val
                session["_last_nt_status_name"] = NT_STATUS_CODES.get(nt_val, f"0x{nt_val:08X}")
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get nt_val: {e}")

        # Session ID (SMB2)
        sesid = self.get_field(smb2, "sesid")
        if sesid is not None:
            session["_last_sesid"] = str(self._resolve_value(sesid, ""))

        # SMB2 message ID (request/response correlation)
        msg_id = self.get_field(smb2, "msg_id")
        if msg_id is not None:
            resolved = str(self._resolve_value(msg_id, "")).strip()
            if resolved:
                session["_last_smb2_msg_id"] = resolved

        # SMB2 tree ID (share handle for the current request)
        tid = self.get_field(smb2, "tid")
        if tid is not None:
            resolved = str(self._resolve_value(tid, "")).strip()
            if resolved:
                session["_last_smb2_tid"] = resolved

        # SMB3.1.1 pre-authentication integrity hash (negotiation security artifact)
        preauth = self.get_field(smb2, "preauth_hash")
        if preauth is not None:
            resolved = str(self._resolve_value(preauth, "")).strip()
            if resolved:
                session["preauth_hash"] = resolved

        # Server host name from negotiate response
        host = self.get_field(smb2, "host")
        if host:
            host = str(self._resolve_value(host, "")).strip()
            if host:
                session["server_hostname"] = host

        # Signing enabled (security posture)
        sign_enabled = self.get_field(smb2, "sec_mode_sign_enabled")
        if sign_enabled is not None:
            session["signing_enabled"] = str(sign_enabled).lower() in ("true", "1")

        # Negotiate context cipher ID (encryption capability)
        cipher_raw = self.get_field(smb2, "negotiate_context_cipher_id")
        if cipher_raw is not None:
            cipher_raw = self._resolve_value(cipher_raw)
            ciphers = session.setdefault("ciphers", [])
            if isinstance(cipher_raw, list):
                for c in cipher_raw:
                    try:
                        cid = int(self._resolve_value(c, 0))
                        name = SMB2_CIPHER_IDS.get(cid, f"cipher_{cid}")
                        if name not in ciphers:
                            ciphers.append(name)
                    except (ValueError, TypeError) as e:
                        self.logger.debug(f"SMB2: cipher_id int parse (list element) failed: {e}")
            else:
                try:
                    cid = int(cipher_raw)
                    name = SMB2_CIPHER_IDS.get(cid, f"cipher_{cid}")
                    if name not in ciphers:
                        ciphers.append(name)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"SMB2: cipher_id int parse (scalar) failed: {e}")

        # Tree connect path (share name) — may be EkMultiField
        tree_path = self.get_field(smb2, "tree")
        if tree_path is not None:
            tree_path = str(self._resolve_value(tree_path, ""))
            if tree_path:
                shares = session.setdefault("shares", [])
                if tree_path not in shares:
                    shares.append(tree_path)

        # SMB2 command code (get_field returns str like "0", "1", etc.)
        cmd_raw = self.get_field(smb2, "cmd")
        if cmd_raw is not None:
            try:
                # Handle comma-separated list (unlikely for SMB2)
                cmd_str = str(cmd_raw).split(",")[0].strip()
                cmd_code = int(cmd_str)
                cmd_name = SMB2_COMMANDS.get(cmd_code, f"Cmd{cmd_code}")
                session["_last_cmd"] = cmd_name
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get cmd_str: {e}")
        elif self.get_field(smb2, "acct") is not None:
            # NTLMSSP auth sub-layer within SessionSetup (no cmd field)
            session["_last_cmd"] = "SessionSetup"

        # IOCTL function code
        ioctl_fn = self.get_field(smb2, "ioctl_function")
        if ioctl_fn is not None:
            try:
                session["_last_ioctl_function"] = str(int(self._resolve_value(ioctl_fn, 0)))
            except (ValueError, TypeError):
                session["_last_ioctl_function"] = str(self._resolve_value(ioctl_fn, ""))

        # Create action (file disposition result)
        create_action = self.get_field(smb2, "create_action")
        if create_action is not None:
            try:
                ca_val = int(self._resolve_value(create_action, 0))
                session["_last_create_action"] = SMB2_CREATE_ACTIONS.get(ca_val, f"action_{ca_val}")
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get ca_val: {e}")

        # Track file operations from SMB2 filename field
        filename = self.get_field(smb2, "filename")
        if filename is not None:
            filename = str(self._resolve_value(filename, "")).strip()
            if filename:
                session["_last_file"] = filename
                op = session.get("_last_cmd", "Access")
                entry = (op, filename, session.get("client_ip", ""), session.get("server_ip", ""))
                if entry not in self._file_ops:
                    self._file_ops.append(entry)

    def _extract_ntlmssp_data(self, packet, session: Dict[str, Any]) -> None:
        """Extract NTLMSSP authentication data from PyShark packet.

        NTLMSSP fields are embedded in the SMB/SMB2 layer with ntlmssp_ prefix:
        - ntlmssp_auth_domain: Domain name
        - ntlmssp_auth_username: Username
        - ntlmssp_auth_hostname: Client hostname/workstation
        """
        # Check for separate ntlmssp layer first
        if hasattr(packet, "ntlmssp"):
            ntlmssp = packet.ntlmssp
            self._parse_ntlmssp_layer(ntlmssp, session)
            return

        # NTLMSSP fields are embedded in SMB/SMB2 layer with ntlmssp_ prefix
        for layer_name in ["smb", "smb2"]:
            if hasattr(packet, layer_name):
                layer = getattr(packet, layer_name)

                # Access NTLMSSP auth fields using safe get_field helper
                domain = self.get_field(layer, "ntlmssp_auth_domain")
                if domain and str(domain) != "NULL" and not session.get("domain"):
                    session["domain"] = str(domain)

                username = self.get_field(layer, "ntlmssp_auth_username")
                if username and str(username) != "NULL" and not session.get("username"):
                    session["username"] = str(username)

                hostname = self.get_field(layer, "ntlmssp_auth_hostname")
                if hostname and str(hostname) != "NULL" and not session.get("workstation"):
                    session["workstation"] = str(hostname)

                # Also check for version info
                version = self.get_field(layer, "ntlmssp_version")
                if version and not session.get("os_version"):
                    session["os_version"] = str(version)

    def _parse_ntlmssp_layer(self, ntlmssp, session: Dict[str, Any]) -> None:
        """Parse NTLMSSP layer from PyShark."""
        # Domain name
        domain = (
            self.get_field(ntlmssp, "auth_domain")
            or self.get_field(ntlmssp, "ntlmserverchallenge_domainname")
            or self.get_field(ntlmssp, "challenge_domain")
        )
        if domain and not session.get("domain"):
            session["domain"] = domain

        # Username
        username = self.get_field(ntlmssp, "auth_username") or self.get_field(ntlmssp, "auth_user")
        if username and not session.get("username"):
            session["username"] = username

        # Workstation/hostname
        workstation = (
            self.get_field(ntlmssp, "auth_hostname")
            or self.get_field(ntlmssp, "auth_host")
            or self.get_field(ntlmssp, "ntlmserverchallenge_workstation")
        )
        if workstation and not session.get("workstation"):
            session["workstation"] = workstation

        # Target info - may contain OS version
        target_info = self.get_field(ntlmssp, "av_pairs_target_info") or self.get_field(
            ntlmssp, "target_info"
        )
        if target_info:
            self.logger.debug(f"NTLMSSP target_info: {target_info}")

    def _parse_ntlmssp_field(self, field: str, value: str, session: Dict[str, Any]) -> None:
        """Parse individual NTLMSSP field from dissector output."""
        field_lower = field.lower()

        if "domain" in field_lower and value:
            if not session.get("domain"):
                session["domain"] = value

        elif "username" in field_lower or "user" in field_lower:
            if value and not session.get("username"):
                session["username"] = value

        elif "hostname" in field_lower or "workstation" in field_lower or "host" in field_lower:
            if value and not session.get("workstation"):
                session["workstation"] = value

    def get_file_operations(self) -> List[Dict[str, str]]:
        """Get file operations extracted from SMB traffic."""
        return [
            {"operation": op, "filename": fn, "source_ip": src, "dest_ip": dst}
            for op, fn, src, dst in self._file_ops
        ]

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get credentials extracted from SMB/NTLM sessions using canonical key names."""
        creds = []
        for session in self._sessions.values():
            username = session.get("username")
            if not username:
                continue
            creds.append(
                {
                    "protocol": "SMB",
                    "credential_type": "NTLM",
                    "auth_method": "NTLM",
                    "username": username,
                    "server_ip": session.get("server_ip", ""),
                    "client_ip": session.get("client_ip", ""),
                    "domain": session.get("domain", ""),
                    "workstation": session.get("workstation", ""),
                }
            )
        return creds

    def _update_device(
        self,
        ip: str,
        mac: str,
        role: str,
        session: Dict[str, Any],
    ) -> None:
        """Update or create device entry with SMB data."""
        if not ip or not is_valid_discovered_ip(ip):
            return

        device_key = f"smb:{ip}"

        smb_data: Dict[str, Any] = {
            "role": role,
            "smb_version": session.get("smb_version"),
            "dialects": session.get("dialects", []),
            "domain": session.get("domain"),
            "workstation": session.get("workstation"),
            "username": session.get("username"),
            "os_version": session.get("os_version"),
            "shares": session.get("shares", []),
            "protocol": "SMB/TCP",
        }

        # Security posture fields
        if session.get("signing_enabled") is not None:
            smb_data["signing_enabled"] = session["signing_enabled"]
        if session.get("ciphers"):
            smb_data["ciphers"] = session["ciphers"]
        if session.get("server_hostname"):
            smb_data["server_hostname"] = session["server_hostname"]
        if session.get("preauth_hash"):
            smb_data["preauth_hash"] = session["preauth_hash"]

        # Clean None values
        smb_data = {k: v for k, v in smb_data.items() if v is not None}

        # Determine name - prefer workstation for clients, domain for servers
        if role == "client":
            name = session.get("workstation") or f"SMB Client ({ip})"
        else:
            name = session.get("domain") or f"SMB Server ({ip})"

        vendor = lookup_mac_vendor(mac) if mac else ""
        device, is_new = self._ensure_device(
            device_key,
            ip,
            mac=mac or "",
            name=name,
            device_type=f"Windows/{role.title()}",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.smb_passive_data = smb_data

            self.logger.debug(
                f"SMB: Discovered {role} {ip} "
                f"(domain={session.get('domain')}, user={session.get('username')})"
            )
        else:
            # Merge SMB data
            if device.smb_passive_data:
                # Update with new non-None values
                for k, v in smb_data.items():
                    if v and not device.smb_passive_data.get(k):
                        device.smb_passive_data[k] = v
                # Merge lists (dialects, shares)
                for list_key in ["dialects", "shares"]:
                    existing = device.smb_passive_data.get(list_key, [])
                    new_items = smb_data.get(list_key, [])
                    for item in new_items:
                        if item not in existing:
                            existing.append(item)
                    if existing:
                        device.smb_passive_data[list_key] = existing
            else:
                device.smb_passive_data = smb_data

            # Update name if better one found
            if session.get("workstation") and not device.name.startswith(session["workstation"]):
                device.name = session["workstation"]
            elif session.get("domain") and device.name.startswith("SMB"):
                device.name = f"{session['domain']} ({role})"
