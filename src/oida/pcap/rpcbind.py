"""
RPCBind/Portmap Passive Listener for RPC service discovery.

Passively captures RPCBind/Portmap traffic to extract:
- RPC program mappings (program number, version, protocol, port)
- Service registrations and lookups
- DUMP responses listing all registered services

Security value:
- NFS/NIS service discovery
- Attack surface enumeration (which RPC services are exposed)
- Indirect call detection (CALLIT - potential for amplification)
- Service version fingerprinting

tshark fields used:
- rpc.msgtyp: Message type (0=Call, 1=Reply)
- rpc.program: RPC program number
- rpc.programversion: Program version
- rpc.procedure: Procedure number
- portmap.prog: Portmap program number
- portmap.version: Portmap program version
- portmap.proto: Transport protocol (6=TCP, 17=UDP)
- portmap.port: Port number
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# Well-known RPC program numbers
RPC_PROGRAMS = {
    100000: "portmapper",
    100001: "rstatd",
    100002: "rusersd",
    100003: "nfs",
    100004: "nlockmgr",
    100005: "mountd",
    100007: "ypbind",
    100008: "walld",
    100009: "yppasswdd",
    100011: "rquotad",
    100012: "sprayd",
    100017: "rexd",
    100021: "nlockmgr",
    100024: "status",
    100026: "bootparam",
    100028: "ypupdated",
    100029: "keyserv",
    100068: "cmsd",
    100083: "ttdbserver",
    100099: "autofsd",
    100227: "nfs_acl",
    100232: "sadmind",
    150001: "pcnfsd",
    300598: "dmispd",
    351455: "snmpXdmid",
    390109: "ypserv",
    391002: "sgi_fam",
    805306368: "ypserv",
}

# Portmap procedure names (version 2)
PORTMAP_PROCEDURES = {
    "0": "NULL",
    "1": "SET",
    "2": "UNSET",
    "3": "GETPORT",
    "4": "DUMP",
    "5": "CALLIT",
    0: "NULL",
    1: "SET",
    2: "UNSET",
    3: "GETPORT",
    4: "DUMP",
    5: "CALLIT",
}

# Transport protocol mapping
PROTO_NAMES = {
    "6": "TCP",
    "17": "UDP",
    6: "TCP",
    17: "UDP",
}


class RPCBindPassiveListener(PySharkListenerBase):
    """Passive RPCBind/Portmap traffic listener for RPC service discovery.

    Captures portmap/rpcbind traffic to identify:
    - RPC services registered on the network
    - Service lookups (which hosts need which services)
    - DUMP responses revealing full service maps
    - CALLIT indirect calls (amplification risk)

    Usage:
        listener = RPCBindPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for ip, services in listener.service_map.items():
            for svc in services:
                print(f"  {svc['program_name']}: port {svc['port']}")
    """

    PROTOCOL_NAME = "rpcbind"
    DISPLAY_FILTER = "portmap"
    REQUIRED_LAYERS = ("portmap", "rpc")
    PROTOCOL_COLUMNS = ("procedure", "program", "version", "port")

    # Portmapper RPC program number (RFC 1833). Used to distinguish genuine
    # portmap/rpcbind traffic from every other Sun-RPC service (NFS, mountd,
    # nlockmgr, status, ypserv...) that also carries an `rpc` layer.
    PORTMAPPER_PROGRAM = "100000"

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track RPC service map: server_ip -> [{"program", "version", "proto", "port"}, ...]
        self.service_map: Dict[str, List[Dict[str, Any]]] = {}

    def should_process_packet(self, packet) -> bool:
        """Only handle genuine portmap/rpcbind PDUs.

        The base guard admits any packet with an `rpc` layer, but `rpc` is
        present on EVERY Sun-RPC service (NFS, mountd, nlockmgr, status,
        ypserv...). During pcap replay (where DISPLAY_FILTER is NOT applied)
        that would mislabel innocuous NFS/mountd calls as Portmap operations,
        because they reuse procedure numbers 0-5 with different meanings.

        Require a real `portmap` layer; only fall back to a bare `rpc` layer
        when it is the portmapper itself (rpc.program == 100000).
        """
        if hasattr(packet, "portmap"):
            return True
        if hasattr(packet, "rpc"):
            return str(self.get_field(packet.rpc, "program", "") or "") == self.PORTMAPPER_PROGRAM
        return False

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format RPCBind interaction as protocol-specific table columns."""
        d = ix.details
        return [
            d.get("procedure_name", d.get("procedure", "?")),
            d.get("program_name", d.get("program", "?")),
            d.get("portmap_version", "?"),
            d.get("port", ""),
        ]

    def process_packet(self, packet) -> None:
        """Process RPCBind/Portmap packet and extract service mappings."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        # Extract RPC message type
        msg_type = ""
        procedure = ""
        procedure_name = ""
        rpc_program = ""
        rpc_version = ""

        if hasattr(packet, "rpc"):
            rpc = packet.rpc
            msg_type = str(self.get_field(rpc, "msgtyp", "") or "")
            procedure_raw = self.get_field(rpc, "procedure", "")
            procedure = str(procedure_raw) if procedure_raw is not None else ""
            procedure_name = PORTMAP_PROCEDURES.get(
                procedure, PORTMAP_PROCEDURES.get(procedure_raw, procedure)
            )
            rpc_program = str(self.get_field(rpc, "program", "") or "")
            rpc_version = str(self.get_field(rpc, "programversion", "") or "")

        is_reply = msg_type == "1"
        direction = "response" if is_reply else "request"

        # Extract portmap-specific fields
        pm_program = ""
        pm_program_name = ""
        pm_version = ""
        pm_proto = ""
        pm_proto_name = ""
        pm_port = ""

        if hasattr(packet, "portmap"):
            portmap = packet.portmap
            pm_program_raw = self.get_field(portmap, "prog", "")
            pm_version = str(self.get_field(portmap, "version", "") or "")
            pm_proto_raw = self.get_field(portmap, "proto", "")
            pm_port = str(self.get_field(portmap, "port", "") or "")

            # Handle comma-separated values from DUMP replies
            if pm_program_raw:
                pm_program = str(pm_program_raw)
                # Resolve first program number for display
                first_prog = pm_program.split(",")[0].strip()
                try:
                    pm_program_name = _resolve_program_name(int(first_prog))
                except (ValueError, TypeError):
                    pm_program_name = first_prog

            if pm_proto_raw:
                pm_proto = str(pm_proto_raw)
                first_proto = pm_proto.split(",")[0].strip()
                pm_proto_name = PROTO_NAMES.get(first_proto, first_proto)

        # Build operation
        if procedure_name:
            operation = f"Portmap {procedure_name}"
        else:
            operation = "Portmap" + (" Reply" if is_reply else " Call")

        # Build detail string
        detail = ""
        if pm_program_name:
            detail = pm_program_name
            if pm_version:
                first_ver = pm_version.split(",")[0].strip()
                detail += f" v{first_ver}"
            if pm_proto_name:
                detail += f"/{pm_proto_name}"
            if pm_port and pm_port != "0":
                first_port = pm_port.split(",")[0].strip()
                detail += f" port={first_port}"

        # Detect CALLIT (indirect call -- amplification risk)
        if procedure_name == "CALLIT":
            self.logger.warning(
                f"Portmap CALLIT from {src_ip} -> {dst_ip} "
                f"(program={pm_program_name or pm_program}) -- amplification risk"
            )

        details: Dict[str, Any] = {
            "msg_type": "reply" if is_reply else "call",
            "procedure": procedure,
            "procedure_name": procedure_name,
            "program": pm_program or rpc_program,
            "program_name": pm_program_name,
            "portmap_version": pm_version or rpc_version,
            "proto": pm_proto,
            "proto_name": pm_proto_name,
            "port": pm_port,
            "detail": detail,
        }

        now = datetime.now().isoformat()
        summary = f"Portmap {procedure_name} {src_ip} -> {dst_ip}"
        if detail:
            summary += f" ({detail})"

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

        # Record service mappings from DUMP replies or GETPORT replies
        if is_reply and pm_program:
            server_ip = src_ip  # The RPCBind server is the source of replies
            self._record_services(server_ip, pm_program, pm_version, pm_proto, pm_port)

        # Track devices
        if is_valid_discovered_ip(src_ip):
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            role = "server" if is_reply else "client"
            self._ensure_device(
                f"rpcbind-{role}:{src_ip}",
                src_ip,
                mac=src_mac or "",
                device_type=f"RPCBind {role.title()}",
                manufacturer=vendor if vendor != "Unknown" else "",
                data_attr="rpcbind_passive_data",
                protocol_data={
                    "role": role,
                    "protocol": "RPCBind/UDP" if hasattr(packet, "udp") else "RPCBind/TCP",
                },
            )

        if is_valid_discovered_ip(dst_ip):
            dst_vendor = lookup_mac_vendor(dst_mac) if dst_mac else ""
            peer_role = "client" if is_reply else "server"
            self._ensure_device(
                f"rpcbind-{peer_role}:{dst_ip}",
                dst_ip,
                mac=dst_mac or "",
                device_type=f"RPCBind {peer_role.title()}",
                manufacturer=dst_vendor if dst_vendor != "Unknown" else "",
                data_attr="rpcbind_passive_data",
                protocol_data={
                    "role": peer_role,
                    "protocol": "RPCBind/UDP" if hasattr(packet, "udp") else "RPCBind/TCP",
                },
            )

    def _record_services(
        self,
        server_ip: str,
        programs: str,
        versions: str,
        protos: str,
        ports: str,
    ) -> None:
        """Record RPC service mappings from a portmap reply.

        Handles comma-separated values from DUMP replies.
        """
        prog_list = [p.strip() for p in programs.split(",") if p.strip()]
        ver_list = [v.strip() for v in versions.split(",") if v.strip()]
        proto_list = [p.strip() for p in protos.split(",") if p.strip()]
        port_list = [p.strip() for p in ports.split(",") if p.strip()]

        if server_ip not in self.service_map:
            self.service_map[server_ip] = []

        max_entries = max(len(prog_list), 1)
        for i in range(max_entries):
            prog = prog_list[i] if i < len(prog_list) else ""
            ver = ver_list[i] if i < len(ver_list) else ""
            proto = proto_list[i] if i < len(proto_list) else ""
            port = port_list[i] if i < len(port_list) else ""

            if not prog:
                continue

            try:
                prog_num = int(prog)
                prog_name = _resolve_program_name(prog_num)
            except (ValueError, TypeError):
                prog_name = prog
                prog_num = 0

            proto_name = PROTO_NAMES.get(proto, proto)

            entry = {
                "program": prog_num,
                "program_name": prog_name,
                "version": ver,
                "proto": proto_name,
                "port": port,
            }

            # Avoid duplicate entries
            if entry not in self.service_map[server_ip]:
                self.service_map[server_ip].append(entry)
                self.logger.debug(
                    f"RPCBind: {server_ip} has {prog_name} v{ver} {proto_name} port={port}"
                )

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data including service map table."""
        base = super().harvest()
        tables = base.get("tables", [])
        alerts = base.get("alerts", [])

        # Build service map table if we have data
        if self.service_map:
            headers = ["Server", "Program", "Version", "Protocol", "Port"]
            rows = []
            for server_ip, services in sorted(self.service_map.items()):
                for svc in services:
                    rows.append(
                        [
                            server_ip,
                            svc.get("program_name", "?"),
                            str(svc.get("version", "?")),
                            svc.get("proto", "?"),
                            str(svc.get("port", "?")),
                        ]
                    )
            if rows:
                tables.append(
                    {
                        "title": "RPCBind Service Map",
                        "headers": headers,
                        "rows": rows,
                    }
                )

        if not tables and not alerts:
            return {}
        return {"tables": tables, "alerts": alerts}


def _resolve_program_name(program_num: int) -> str:
    """Resolve RPC program number to friendly name."""
    if program_num in RPC_PROGRAMS:
        return RPC_PROGRAMS[program_num]
    return str(program_num)
