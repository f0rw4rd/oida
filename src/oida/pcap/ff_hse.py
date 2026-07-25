"""
FOUNDATION Fieldbus HSE Passive Listener (PyShark-based).

Passively monitors FOUNDATION Fieldbus HSE (High Speed Ethernet) traffic
to identify:
- FDA (Fieldbus Device Access) sessions and operations
- SM (System Management) identification and tag resolution
- FMS (Fieldbus Message Specification) services
- LAN Redundancy diagnostic messages
- Device identity from SM Identify responses
- Configuration operations (FDA Open/Close/Idle sessions)
- Error responses with error class and code

FOUNDATION Fieldbus HSE (FF-HSE) is the Ethernet-based variant of FOUNDATION
Fieldbus, used in process automation (oil/gas, chemical, pharmaceutical).
It runs over standard IP/UDP networks and provides:
- FDA: Session management and device access (analogous to OPC UA sessions)
- SM: System Management for device identification and tag lookup
- FMS: Fieldbus Message Specification for data access (VFDs, OD, etc.)
- LR: LAN Redundancy for fault-tolerant networking

Key protocol layers:
- UDP port 1089-1091 (typical)
- FF message header: Version (1B) + FDA Address (4B) + Length (4B)
- Service header: Confirmed flag + Service ID
- FF message trailer: Message Number + Invoke ID + Timestamp

Key tshark fields:
- ff.hdr.ver: FDA message version (FT_UINT8)
- ff.hdr.fda_addr: FDA address (FT_UINT32)
- ff.hdr.len: Message length (FT_UINT32)
- ff.hdr_srv: Service byte (FT_UINT8)
- ff.hdr_srv.confirm_flag: Confirmed flag (FT_BOOLEAN)
- ff.hdr_srv.service_id: Service ID (FT_UINT8)
- ff.hdr_srv.fda.service_id.confirm: FDA confirmed service (FT_UINT8)
- ff.hdr_srv.fda.service_id.unconfirm: FDA unconfirmed service (FT_UINT8)
- ff.hdr_srv.sm.service_id.confirm: SM confirmed service (FT_UINT8)
- ff.hdr_srv.sm.service_id.unconfirm: SM unconfirmed service (FT_UINT8)
- ff.hdr_srv.fms.service_id.confirm: FMS confirmed service (FT_UINT8)
- ff.hdr_srv.fms.service_id.unconfirm: FMS unconfirmed service (FT_UINT8)
- ff.hdr.proto_id: Protocol ID (FT_UINT8)
- ff.hdr.confirm_msg_type: Confirmed message type (FT_UINT8)
- ff.trailer.msg_num: Message number (FT_UINT32)
- ff.trailer.invoke_id: Invoke ID (FT_UINT32)
- ff.fda.open_sess.req.pd_tag: PD Tag from session open (FT_STRING)
- ff.fda.open_sess.rsp.pd_tag: PD Tag from session response (FT_STRING)
- ff.fda.open_sess.err.err_class: Error class (FT_UINT8)
- ff.fda.open_sess.err.err_code: Error code (FT_UINT8)
- ff.sm.id.rsp.dev_id: Device ID from Identify (FT_STRING)
- ff.sm.id.rsp.pd_tag: PD Tag from Identify (FT_STRING)
- ff.sm.id.rsp.dev_idx: Device index (FT_UINT16)
- ff.sm.id.rsp.operational_ip_addr: Operational IP address (FT_IPv6)
- ff.sm.find_tag_query.req.tag: PD Tag or FB Tag query (FT_STRING)
- ff.sm.find_tag_reply.req.dev_id: Queried device ID (FT_STRING)
- ff.sm.find_tag_reply.req.pd_tag: Queried PD Tag (FT_STRING)

References:
- IEC 61158 Type 5 / IEC 61784-2 CPF 1 (FOUNDATION Fieldbus)
- Fieldbus Foundation specification FF-581, FF-588, FF-803
- Wireshark dissector: packet-ff.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# FDA confirmed service IDs
FDA_CONFIRMED_SERVICES = {
    1: "FDA_Open",
    2: "FDA_Close",
    3: "FDA_Read",
    4: "FDA_Write",
    6: "FDA_Idle",
    10: "FDA_ReadWithSubindex",
    11: "FDA_WriteWithSubindex",
    16: "FDA_GenericOpen",
}

# FDA unconfirmed service IDs
FDA_UNCONFIRMED_SERVICES = {
    1: "FDA_Identify",
}

# SM confirmed service IDs
SM_CONFIRMED_SERVICES = {
    1: "SM_Identify",
    2: "SM_FindTag",
    5: "SM_ClearAddress",
    6: "SM_SetAddress",
    15: "SM_DeviceAnnunciation",
}

# SM unconfirmed service IDs
SM_UNCONFIRMED_SERVICES = {
    1: "SM_FindTagQuery",
    2: "SM_FindTagReply",
    3: "SM_IdentifyRequest",
}

# FMS confirmed service IDs
FMS_CONFIRMED_SERVICES = {
    1: "FMS_Read",
    2: "FMS_Write",
    3: "FMS_DefineVFD",
    4: "FMS_DeleteVFD",
    6: "FMS_GetOD",
    8: "FMS_Status",
    9: "FMS_Identify",
    10: "FMS_GenericRead",
    11: "FMS_GenericWrite",
    16: "FMS_EventNotification",
    17: "FMS_AlterEventConditionMonitoring",
    20: "FMS_ReadWithSubindex",
    21: "FMS_WriteWithSubindex",
}

# FMS unconfirmed service IDs
FMS_UNCONFIRMED_SERVICES = {
    1: "FMS_InformationReport",
    2: "FMS_UnsolicedStatus",
    4: "FMS_EventNotificationUnconfirmed",
}

# LAN Redundancy service IDs
LAN_SERVICES = {
    1: "LR_PutInfo",
    2: "LR_GetInfo",
    3: "LR_GetStatistics",
    4: "LR_DiagnosticMsg",
}

# Write/control services (security-relevant)
FF_WRITE_SERVICES = {"FDA_Write", "FDA_WriteWithSubindex", "FMS_Write", "FMS_WriteWithSubindex"}

# Error classes (ff.*.err.err_class)
FF_ERROR_CLASSES = {
    0: "Other",
    1: "Object",
    2: "Resource",
    3: "Service",
    4: "Access",
    5: "FDA",
    6: "Application",
}


@dataclass
class FFSession:
    """Track a FOUNDATION Fieldbus HSE session."""

    client_ip: str
    server_ip: str
    pd_tag: str = ""
    device_id: str = ""
    services_seen: Set[str] = field(default_factory=set)
    write_count: int = 0
    read_count: int = 0
    error_count: int = 0
    first_seen: str = ""
    last_seen: str = ""


class FFHSEPassiveListener(PySharkListenerBase):
    """Passive FOUNDATION Fieldbus HSE traffic listener (PyShark-based).

    Monitors FF-HSE traffic to:
    - Identify field devices via SM Identify responses
    - Track FDA sessions (open, close, read, write)
    - Monitor FMS data access operations
    - Detect configuration/write operations
    - Extract device identity (PD Tag, Device ID)
    - Monitor LAN Redundancy diagnostics

    tshark layer: ff
    Transport: UDP (ports 1089-1091 typical)

    Usage:
        listener = FFHSEPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for session in listener.sessions.values():
            print(f"{session.client_ip} -> {session.server_ip} tag={session.pd_tag}")
    """

    PROTOCOL_NAME = "ff_hse"
    DISPLAY_FILTER = "ff"
    REQUIRED_LAYERS = ("ff",)
    PROTOCOL_COLUMNS = ("protocol", "service", "tag", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], FFSession] = {}
        self._device_info: Dict[str, Dict[str, Any]] = {}

    def process_packet(self, packet) -> None:
        """Process a FOUNDATION Fieldbus HSE packet."""
        if not hasattr(packet, "ff"):
            return

        ff = packet.ff
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_mac, dst_mac = self.get_mac_info(packet)
        src_port, dst_port = self.get_port_info(packet)
        flow_id = self.get_flow_id(packet)
        now = datetime.now().isoformat()

        # Parse FDA address
        fda_addr_raw = self.get_field(ff, "hdr_fda_addr")
        fda_addr = self._parse_int(fda_addr_raw, None, base=16)

        # Determine protocol and service
        proto_name, svc_name, is_confirmed, is_error = self._identify_service(ff)

        if not svc_name:
            svc_name = "Unknown"

        # Determine direction from the message-type field, NOT the
        # confirmed-service flag: ff.hdr_srv.confirm_flag (0x80) marks a
        # *confirmed service*, set on requests AND responses alike, so it can't
        # tell direction. ff.hdr.confirm_msg_type is 0=Request, 1=Response,
        # 2=Error (per `tshark -G values`).
        msg_type_raw = self.get_field(ff, "hdr_confirm_msg_type")
        msg_type_int = self._parse_int(msg_type_raw, 0)
        is_response = msg_type_int in (1, 2)  # 1=Response, 2=Error
        direction = "response" if is_response else "request"

        # Extract trailer info
        invoke_id_raw = self.get_field(ff, "trailer_invoke_id")
        invoke_id = self._parse_int(invoke_id_raw, None)

        msg_num_raw = self.get_field(ff, "trailer_msg_num")
        msg_num = self._parse_int(msg_num_raw, None)

        # Extract PD Tags and device info
        pd_tag = ""
        device_id = ""
        detail = ""
        rw = ""

        # FDA session operations
        if proto_name == "FDA":
            pd_tag, detail, rw = self._process_fda(ff, svc_name)

        # SM operations
        elif proto_name == "SM":
            device_id, pd_tag, detail = self._process_sm(ff, svc_name, src_ip)

        # FMS operations
        elif proto_name == "FMS":
            detail, rw = self._process_fms(ff, svc_name)

        # LAN Redundancy
        elif proto_name == "LAN":
            detail = self._process_lan(ff, svc_name)

        # Error handling
        if is_error:
            err_class_raw = None
            err_code_raw = None
            # Try various error field paths
            for prefix in (
                "fda_open_sess_err",
                "fda_idle_err",
                "sm_id_err",
                "sm_find_tag_err",
            ):
                ec = self.get_field(ff, f"{prefix}_err_class")
                if ec is not None:
                    err_class_raw = ec
                    err_code_raw = self.get_field(ff, f"{prefix}_err_code")
                    break

            if err_class_raw is not None:
                err_class = self._parse_int(err_class_raw, 0)
                err_code = self._parse_int(err_code_raw, 0)
                err_class_name = FF_ERROR_CLASSES.get(err_class, f"class-{err_class}")
                detail += f" Error: {err_class_name}/code-{err_code}"

        # Update session tracking
        if direction == "request":
            client_ip, server_ip = src_ip, dst_ip
        else:
            client_ip, server_ip = dst_ip, src_ip

        session = self._ensure_session(client_ip, server_ip, now)
        session.services_seen.add(svc_name)
        if pd_tag:
            session.pd_tag = pd_tag
        if device_id:
            session.device_id = device_id
        if svc_name in FF_WRITE_SERVICES:
            session.write_count += 1
            rw = "write"
        elif "Read" in svc_name or "Identify" in svc_name or "FindTag" in svc_name:
            session.read_count += 1
            if not rw:
                rw = "read"
        if is_error:
            session.error_count += 1

        # Build interaction details
        details: Dict[str, Any] = {
            "protocol": proto_name,
            "service": svc_name,
            "tag": pd_tag,
            "device_id": device_id,
            "detail": detail,
            "rw": rw,
        }
        if fda_addr is not None:
            details["fda_addr"] = f"0x{fda_addr:08x}"
        if invoke_id is not None:
            details["invoke_id"] = invoke_id
        if msg_num is not None:
            details["msg_num"] = msg_num

        summary = f"{proto_name} {svc_name}"
        if pd_tag:
            summary += f" tag={pd_tag}"
        if detail:
            summary += f" {detail}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            svc_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Update discovered devices
        self._update_devices(src_ip, dst_ip, src_mac, dst_mac, session)

    def _identify_service(self, ff) -> Tuple[str, str, bool, bool]:
        """Identify the FF protocol and service.

        Returns (proto_name, svc_name, is_confirmed, is_error).
        """
        # Try protocol-specific confirmed/unconfirmed service fields
        for proto, conf_map, unconf_map in (
            ("FDA", FDA_CONFIRMED_SERVICES, FDA_UNCONFIRMED_SERVICES),
            ("SM", SM_CONFIRMED_SERVICES, SM_UNCONFIRMED_SERVICES),
            ("FMS", FMS_CONFIRMED_SERVICES, FMS_UNCONFIRMED_SERVICES),
            ("LAN", LAN_SERVICES, {}),
        ):
            prefix = proto.lower()
            # Confirmed service
            svc_raw = self.get_field(ff, f"hdr_srv_{prefix}_service_id_confirm")
            if svc_raw is not None:
                svc_id = self._parse_int(svc_raw, None)
                if svc_id is not None:
                    svc_name = conf_map.get(svc_id, f"{proto}_Svc{svc_id}")
                    return proto, svc_name, True, False

            # Unconfirmed service
            svc_raw = self.get_field(ff, f"hdr_srv_{prefix}_service_id_unconfirm")
            if svc_raw is not None and unconf_map:
                svc_id = self._parse_int(svc_raw, None)
                if svc_id is not None:
                    svc_name = unconf_map.get(svc_id, f"{proto}_UnconfSvc{svc_id}")
                    return proto, svc_name, False, False

        # Check for error responses by looking for error markers
        for err_marker in (
            "fda_open_sess_err",
            "fda_idle_err",
            "sm_id_err",
            "sm_find_tag_err",
        ):
            if self.get_field(ff, err_marker) is not None:
                proto = err_marker.split("_")[0].upper()
                return proto, f"{proto}_Error", True, True

        # Fallback: generic service ID
        svc_id_raw = self.get_field(ff, "hdr_srv_service_id")
        if svc_id_raw is not None:
            svc_id = self._parse_int(svc_id_raw, 0)
            return "FF", f"Svc{svc_id}", False, False

        return "FF", "", False, False

    def _process_fda(self, ff, svc_name: str) -> Tuple[str, str, str]:
        """Process FDA service fields. Returns (pd_tag, detail, rw)."""
        pd_tag = ""
        detail = ""
        rw = ""

        # Open session request/response PD Tag
        for path in ("fda_open_sess_req_pd_tag", "fda_open_sess_rsp_pd_tag"):
            tag = self.get_field(ff, path)
            if tag:
                pd_tag = str(tag).strip()
                break

        # Session index
        for path in ("fda_open_sess_req_sess_idx", "fda_open_sess_rsp_sess_idx"):
            idx_raw = self.get_field(ff, path)
            if idx_raw is not None:
                idx = self._parse_int(idx_raw, None)
                if idx is not None:
                    detail = f"session={idx}"
                break

        # Max buffer / message sizes
        for path in ("fda_open_sess_req_max_buf_siz", "fda_open_sess_rsp_max_buf_siz"):
            buf_raw = self.get_field(ff, path)
            if buf_raw is not None:
                buf_size = self._parse_int(buf_raw, 0)
                detail += f" buf={buf_size}"
                break

        if "Write" in svc_name:
            rw = "write"
        elif "Read" in svc_name or "Open" in svc_name:
            rw = "read"

        return pd_tag, detail, rw

    def _process_sm(self, ff, svc_name: str, src_ip: str) -> Tuple[str, str, str]:
        """Process SM service fields. Returns (device_id, pd_tag, detail)."""
        device_id = ""
        pd_tag = ""
        detail = ""

        # SM Identify response
        dev_id = self.get_field(ff, "sm_id_rsp_dev_id")
        if dev_id:
            device_id = str(dev_id).strip()
            detail = f"device={device_id}"

        sm_pd_tag = self.get_field(ff, "sm_id_rsp_pd_tag")
        if sm_pd_tag:
            pd_tag = str(sm_pd_tag).strip()
            detail += f" tag={pd_tag}"

        dev_idx_raw = self.get_field(ff, "sm_id_rsp_dev_idx")
        if dev_idx_raw is not None:
            dev_idx = self._parse_int(dev_idx_raw, None)
            if dev_idx is not None:
                detail += f" idx={dev_idx}"

        op_ip = self.get_field(ff, "sm_id_rsp_operational_ip_addr")
        if op_ip:
            detail += f" ip={op_ip}"

        # SM Find Tag query
        find_tag = self.get_field(ff, "sm_find_tag_query_req_tag")
        if find_tag:
            pd_tag = str(find_tag).strip()
            detail = f"FindTag={pd_tag}"

        # SM Find Tag reply
        reply_dev = self.get_field(ff, "sm_find_tag_reply_req_dev_id")
        if reply_dev:
            device_id = str(reply_dev).strip()
            detail = f"TagReply device={device_id}"

        reply_tag = self.get_field(ff, "sm_find_tag_reply_req_pd_tag")
        if reply_tag:
            pd_tag = str(reply_tag).strip()
            detail += f" tag={pd_tag}"

        # Store device info
        if device_id and src_ip:
            self._device_info[src_ip] = {
                "device_id": device_id,
                "pd_tag": pd_tag,
            }

        return device_id, pd_tag, detail

    def _process_fms(self, ff, svc_name: str) -> Tuple[str, str]:
        """Process FMS service fields. Returns (detail, rw)."""
        rw = ""
        detail = ""

        if "Write" in svc_name:
            rw = "write"
        elif "Read" in svc_name:
            rw = "read"

        return detail, rw

    def _process_lan(self, ff, svc_name: str) -> str:
        """Process LAN Redundancy fields. Returns detail string."""
        detail = ""

        # Diagnostic message device index
        dev_idx_raw = self.get_field(ff, "lr_diagnostic_msg_req_dev_idx")
        if dev_idx_raw is not None:
            dev_idx = self._parse_int(dev_idx_raw, None)
            if dev_idx is not None:
                detail = f"diag idx={dev_idx}"

        pd_tag = self.get_field(ff, "lr_diagnostic_msg_req_pd_tag")
        if pd_tag:
            detail += f" tag={pd_tag}"

        return detail

    def _ensure_session(self, client_ip: str, server_ip: str, now: str) -> FFSession:
        """Ensure a session entry exists and return it."""
        key = (client_ip, server_ip)
        if key not in self.sessions:
            self.sessions[key] = FFSession(
                client_ip=client_ip,
                server_ip=server_ip,
                first_seen=now,
                last_seen=now,
            )
        session = self.sessions[key]
        session.last_seen = now
        return session

    def _update_devices(
        self,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        session: FFSession,
    ) -> None:
        """Update discovered device entries."""
        for ip, mac in ((src_ip, src_mac), (dst_ip, dst_mac)):
            if not is_valid_discovered_ip(ip):
                continue
            vendor = lookup_mac_vendor(mac) if mac else ""
            info = self._device_info.get(ip, {})
            dev_name = info.get("pd_tag", "") or info.get("device_id", "") or f"FF-HSE ({ip})"
            key = f"ff_hse:{ip}"

            device, is_new = self._ensure_device(
                key,
                ip,
                mac=mac,
                name=dev_name,
                device_type="FF-HSE Device",
                manufacturer=vendor if vendor else "",
            )
            device.ff_hse_passive_data = {
                "protocol": "FOUNDATION Fieldbus HSE",
                "services_seen": sorted(session.services_seen),
                "write_count": session.write_count,
                "read_count": session.read_count,
                "error_count": session.error_count,
                "pd_tag": session.pd_tag,
                "device_id": session.device_id,
                "first_seen": session.first_seen,
                "last_seen": session.last_seen,
            }
            if is_new:
                self.logger.debug(
                    f"FF-HSE: Device {ip}"
                    + (f" tag={session.pd_tag}" if session.pd_tag else "")
                    + (f" id={session.device_id}" if session.device_id else "")
                )

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format interaction as table row matching PROTOCOL_COLUMNS."""
        d = ix.details
        return [
            d.get("protocol", ""),
            d.get("service", ""),
            d.get("tag", ""),
            d.get("detail", ""),
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write operations."""
        return [
            {
                "client": session.client_ip,
                "server": session.server_ip,
                "write_count": session.write_count,
            }
            for session in self.sessions.values()
            if session.write_count > 0
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed FF-HSE sessions."""
        return [
            {
                "client": s.client_ip,
                "server": s.server_ip,
                "pd_tag": s.pd_tag,
                "device_id": s.device_id,
                "services": sorted(s.services_seen),
                "read_count": s.read_count,
                "write_count": s.write_count,
                "error_count": s.error_count,
            }
            for s in self.sessions.values()
        ]
