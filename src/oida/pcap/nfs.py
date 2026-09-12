"""
NFS Passive Listener for file access and device extraction.

Passively captures NFS traffic to extract:
- NFS version (v3, v4)
- Procedure calls (READ, WRITE, LOOKUP, CREATE, REMOVE, etc.)
- File handles and filenames
- UID/GID mappings from file attributes
- File sizes and types from GETATTR responses
- Mount points and export paths

NFS is security-relevant because:
- UID/GID spoofing can be used for privilege escalation
- Exported paths reveal directory structure
- File operations reveal sensitive data access patterns
- No authentication in default NFSv3 (AUTH_SYS uses client-supplied UID/GID)

tshark fields used (packet.nfs.*):
- nfs.procedure_v3 / nfs.procedure_v4: Procedure number
- nfs.fhandle: File handle (opaque bytes)
- nfs.name: Filename in lookup/create/remove operations
- nfs.status / nfs.nfsstat3: NFS status code
- nfs.fattr3.uid / nfs.fattr3.gid: File owner UID/GID
- nfs.fattr3.size: File size
- nfs.fattr3.type: File type (regular, directory, etc.)
- nfs.fattr3.mode: Unix permissions
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# NFSv3 procedure names (RFC 1813)
NFS3_PROCEDURES = {
    "0": "NULL",
    "1": "GETATTR",
    "2": "SETATTR",
    "3": "LOOKUP",
    "4": "ACCESS",
    "5": "READLINK",
    "6": "READ",
    "7": "WRITE",
    "8": "CREATE",
    "9": "MKDIR",
    "10": "SYMLINK",
    "11": "MKNOD",
    "12": "REMOVE",
    "13": "RMDIR",
    "14": "RENAME",
    "15": "LINK",
    "16": "READDIR",
    "17": "READDIRPLUS",
    "18": "FSSTAT",
    "19": "FSINFO",
    "20": "PATHCONF",
    "21": "COMMIT",
}

# NFSv4 procedure names (RFC 7530) -- selected key operations
NFS4_PROCEDURES = {
    "0": "NULL",
    "1": "COMPOUND",
}

# NFSv4 operation codes inside COMPOUND requests
NFS4_OPS = {
    "3": "ACCESS",
    "4": "CLOSE",
    "5": "COMMIT",
    "6": "CREATE",
    "7": "DELEGPURGE",
    "8": "DELEGRETURN",
    "9": "GETATTR",
    "10": "GETFH",
    "11": "LINK",
    "12": "LOCK",
    "13": "LOCKT",
    "14": "LOCKU",
    "15": "LOOKUP",
    "16": "LOOKUPP",
    "17": "NVERIFY",
    "18": "OPEN",
    "19": "OPENATTR",
    "20": "OPEN_CONFIRM",
    "21": "OPEN_DOWNGRADE",
    "22": "PUTFH",
    "23": "PUTPUBFH",
    "24": "PUTROOTFH",
    "25": "READ",
    "26": "READDIR",
    "27": "READLINK",
    "28": "REMOVE",
    "29": "RENAME",
    "30": "RENEW",
    "31": "RESTOREFH",
    "32": "SAVEFH",
    "33": "SECINFO",
    "34": "SETATTR",
    "35": "SETCLIENTID",
    "36": "SETCLIENTID_CONFIRM",
    "37": "VERIFY",
    "38": "WRITE",
    "39": "RELEASE_LOCKOWNER",
}

# NFS status codes
NFS_STATUS = {
    "0": "OK",
    "1": "PERM",
    "2": "NOENT",
    "5": "IO",
    "6": "NXIO",
    "13": "ACCES",
    "17": "EXIST",
    "18": "XDEV",
    "19": "NODEV",
    "20": "NOTDIR",
    "21": "ISDIR",
    "22": "INVAL",
    "27": "FBIG",
    "28": "NOSPC",
    "30": "ROFS",
    "31": "MLINK",
    "63": "NAMETOOLONG",
    "66": "NOTEMPTY",
    "69": "DQUOT",
    "70": "STALE",
    "71": "REMOTE",
    "10001": "BADHANDLE",
    "10002": "NOT_SYNC",
    "10003": "BAD_COOKIE",
    "10004": "NOTSUPP",
    "10005": "TOOSMALL",
    "10006": "SERVERFAULT",
    "10007": "BADTYPE",
    "10008": "JUKEBOX",
}

# File type mapping from fattr3.type
FILE_TYPES = {
    "1": "REG",
    "2": "DIR",
    "3": "BLK",
    "4": "CHR",
    "5": "LNK",
    "6": "SOCK",
    "7": "FIFO",
}

# Security-sensitive procedures (writes, deletes, permission changes)
WRITE_PROCEDURES = {"WRITE", "CREATE", "MKDIR", "REMOVE", "RMDIR", "RENAME", "SETATTR", "LINK"}


class NFSPassiveListener(PySharkListenerBase):
    """Passive NFS traffic listener for file access and device extraction.

    Captures NFS traffic to extract:
    - NFS version and procedure calls
    - File handles and filenames
    - UID/GID mappings (useful for privilege escalation)
    - File operations (READ/WRITE/CREATE/REMOVE)
    - Export paths and mount point information

    Usage:
        listener = NFSPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for ix in listener.interactions:
            print(f"{ix.operation}: {ix.details}")
    """

    PROTOCOL_NAME = "nfs"
    DISPLAY_FILTER = "nfs"
    REQUIRED_LAYERS = ("nfs",)
    PROTOCOL_COLUMNS = ("version", "operation", "filename", "status", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track UID/GID mappings observed per server
        self.uid_gid_map: Dict[str, Dict[str, set]] = {}  # server_ip -> {uids: set, gids: set}
        # Track write operations for security alerting
        self._write_ops: List[Dict[str, Any]] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format NFS interaction as protocol-specific table columns."""
        d = ix.details
        version = d.get("version", "?")
        operation = d.get("procedure_name", "?")
        filename = d.get("filename", "") or "-"
        status = d.get("status_name", "") or "-"
        # Build detail string from interesting fields
        detail_parts = []
        uid = d.get("uid")
        gid = d.get("gid")
        if uid is not None and uid != "":
            detail_parts.append(f"uid={uid}")
        if gid is not None and gid != "":
            detail_parts.append(f"gid={gid}")
        fsize = d.get("file_size")
        if fsize is not None and fsize != "":
            detail_parts.append(f"size={fsize}")
        ftype = d.get("file_type_name")
        if ftype:
            detail_parts.append(f"type={ftype}")
        detail = " ".join(detail_parts) if detail_parts else "-"
        return [version, operation, filename, status, detail]

    def process_packet(self, packet) -> None:
        """Process NFS packet and extract procedure, file, and attribute info."""
        if not hasattr(packet, "nfs"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        nfs = packet.nfs
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        # Determine NFS version and procedure
        version, procedure_name = self._get_version_and_procedure(nfs)

        # Determine direction: request vs response. A status field is only
        # present on responses. The real tshark fields are nfs.nfsstat3 (v3),
        # nfs.nfsstat4 (v4) and the generic nfs.status; "nfs.status3" is not a
        # real field, so probing it first was a dead lookup that let v4
        # responses fall through to "request" and flip server/client attribution.
        status_raw = self.get_field_any(nfs, "nfsstat3", "nfsstat4", "status", default=None)

        # If we have a status code, this is likely a response
        is_response = status_raw is not None
        direction = "response" if is_response else "request"

        status_name = ""
        if status_raw is not None:
            status_name = NFS_STATUS.get(str(status_raw), str(status_raw))

        # Extract filename
        filename = str(self.get_field(nfs, "name", "") or "")

        # Extract file handle
        fhandle = str(self.get_field(nfs, "fhandle", "") or "")

        # Extract file attributes (from GETATTR responses)
        uid = self.get_field(nfs, "fattr3_uid", None)
        if uid is None:
            uid = self.get_field(nfs, "uid", None)
        gid = self.get_field(nfs, "fattr3_gid", None)
        if gid is None:
            gid = self.get_field(nfs, "gid", None)
        file_size = self.get_field(nfs, "fattr3_size", None)
        if file_size is None:
            file_size = self.get_field(nfs, "size", None)
        file_type_raw = self.get_field(nfs, "fattr3_type", None)
        if file_type_raw is None:
            file_type_raw = self.get_field(nfs, "type", None)
        file_type_name = FILE_TYPES.get(str(file_type_raw), "") if file_type_raw else ""

        mode = self.get_field(nfs, "mode3", None)
        if mode is None:
            mode = self.get_field(nfs, "fattr3_mode", None)
        if mode is None:
            mode = self.get_field(nfs, "mode", None)

        # Build details dict
        details: Dict[str, Any] = {
            "version": version,
            "procedure_name": procedure_name,
            "filename": filename,
            "fhandle": fhandle,
            "status": str(status_raw) if status_raw is not None else "",
            "status_name": status_name,
        }
        if uid is not None:
            details["uid"] = str(uid)
        if gid is not None:
            details["gid"] = str(gid)
        if file_size is not None:
            details["file_size"] = str(file_size)
        if file_type_name:
            details["file_type_name"] = file_type_name
        if mode is not None:
            details["mode"] = str(mode)

        # Record interaction
        now = datetime.now().isoformat()
        summary = f"NFS {version} {procedure_name}"
        if filename:
            summary += f" {filename}"
        if status_name and is_response:
            summary += f" -> {status_name}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"NFS {version} {procedure_name}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track UID/GID mappings for the server (response source)
        if is_response and uid is not None:
            self._track_uid_gid(src_ip, uid, gid)

        # Track write operations
        if procedure_name in WRITE_PROCEDURES and not is_response:
            self._write_ops.append(
                {
                    "client": src_ip,
                    "server": dst_ip,
                    "operation": procedure_name,
                    "filename": filename,
                    "timestamp": now,
                }
            )

        # Create device entries for both endpoints
        if is_response:
            server_ip, client_ip = src_ip, dst_ip
            server_mac, client_mac = src_mac, dst_mac
        else:
            server_ip, client_ip = dst_ip, src_ip
            server_mac, client_mac = dst_mac, src_mac

        if is_valid_discovered_ip(server_ip):
            server_vendor = lookup_mac_vendor(server_mac) if server_mac else ""
            device, is_new = self._ensure_device(
                f"nfs-server:{server_ip}",
                server_ip,
                mac=server_mac or "",
                device_type="NFS Server",
                manufacturer=server_vendor if server_vendor != "Unknown" else "",
            )
            if is_new:
                device.nfs_passive_data = {
                    "role": "server",
                    "version": version,
                    "protocol": "NFS/TCP",
                    "procedures_seen": [],
                }
            if hasattr(device, "nfs_passive_data") and device.nfs_passive_data:
                procs = device.nfs_passive_data.get("procedures_seen", [])
                if procedure_name and procedure_name not in procs:
                    procs.append(procedure_name)
                    device.nfs_passive_data["procedures_seen"] = procs

        if is_valid_discovered_ip(client_ip):
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            device, is_new = self._ensure_device(
                f"nfs-client:{client_ip}",
                client_ip,
                mac=client_mac or "",
                device_type="NFS Client",
                manufacturer=client_vendor if client_vendor != "Unknown" else "",
            )
            if is_new:
                device.nfs_passive_data = {
                    "role": "client",
                    "version": version,
                    "protocol": "NFS/TCP",
                    "procedures_seen": [],
                }

    def _get_version_and_procedure(self, nfs) -> Tuple[str, str]:
        """Extract NFS version and procedure name from packet."""
        # Try v3 first
        proc_v3 = self.get_field(nfs, "procedure_v3", None)
        if proc_v3 is not None:
            proc_name = NFS3_PROCEDURES.get(str(proc_v3), f"PROC_{proc_v3}")
            return "v3", proc_name

        # Try v4. procedure_v4 is almost always 1 (COMPOUND); the meaningful
        # operations are the opcodes carried INSIDE the COMPOUND. Resolve those
        # first so WRITE/REMOVE/SETATTR/etc. are visible and write-alerting fires
        # (returning "COMPOUND" here made the real per-op branch below dead and
        # write tracking miss every NFSv4 mutation).
        opcode = self.get_field(nfs, "opcode", None)
        if opcode is not None:
            # get_field comma-joins a multi-op COMPOUND's opcode list ("22,38,9").
            op_names = [
                NFS4_OPS.get(o.strip(), f"OP_{o.strip()}")
                for o in str(opcode).split(",")
                if o.strip() != ""
            ]
            if op_names:
                # Surface a write op if the COMPOUND contains one (drives the
                # write alert); otherwise the last op is the COMPOUND's primary
                # action (e.g. PUTFH+GETATTR -> GETATTR).
                write_op = next((n for n in op_names if n in WRITE_PROCEDURES), None)
                return "v4", write_op or op_names[-1]

        proc_v4 = self.get_field(nfs, "procedure_v4", None)
        if proc_v4 is not None:
            proc_name = NFS4_PROCEDURES.get(str(proc_v4), f"PROC_{proc_v4}")
            return "v4", proc_name

        # Fallback: try generic procedure field
        proc = self.get_field(nfs, "procedure", None)
        if proc is not None:
            return "?", f"PROC_{proc}"

        return "?", "UNKNOWN"

    def _track_uid_gid(self, server_ip: str, uid: Any, gid: Any) -> None:
        """Track UID/GID values observed from a server."""
        if server_ip not in self.uid_gid_map:
            self.uid_gid_map[server_ip] = {"uids": set(), "gids": set()}
        if uid is not None:
            self.uid_gid_map[server_ip]["uids"].add(str(uid))
        if gid is not None:
            self.uid_gid_map[server_ip]["gids"].add(str(gid))

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get write/modify operations for security alerting."""
        # Aggregate by client -> server pairs
        pair_counts: Dict[Tuple[str, str], int] = {}
        for w in self._write_ops:
            key = (w["client"], w["server"])
            pair_counts[key] = pair_counts.get(key, 0) + 1
        return [
            {"client": client, "server": server, "write_count": count}
            for (client, server), count in pair_counts.items()
        ]

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data including UID/GID tables."""
        base = super().harvest()
        tables = base.get("tables", [])

        # Add UID/GID mapping table if we found any
        uid_rows = []
        for server_ip, mapping in self.uid_gid_map.items():
            uids = sorted(mapping["uids"]) if mapping["uids"] else ["-"]
            gids = sorted(mapping["gids"]) if mapping["gids"] else ["-"]
            uid_rows.append([server_ip, ", ".join(uids), ", ".join(gids)])
        if uid_rows:
            tables.append(
                {
                    "title": "NFS UID/GID Mappings",
                    "headers": ["Server", "UIDs", "GIDs"],
                    "rows": uid_rows,
                }
            )

        if tables:
            base["tables"] = tables
        return base
