"""
Oracle TNS Passive Listener for database infrastructure enumeration.

Passively captures Oracle TNS (Transparent Network Substrate) traffic to extract:
- TNS packet types (Connect, Accept, Refuse, Data, Redirect, Resend)
- Connect data strings (SERVICE_NAME, SID, HOST, PORT, USER, PROGRAM)
- TNS version information from Connect/Accept packets
- Connection refusal reasons and error codes
- Service names and SID names from connect strings
- Client program and user identity from CID (Client Identifier)

TNS is the transport layer for Oracle Net Services (SQL*Net).
Default port: 1521/TCP.

Key tshark TNS fields:
- tns.type: Packet type (1=Connect, 2=Accept, 3=ACK, 4=Refuse, 5=Redirect, 6=Data)
- tns.version: TNS protocol version
- tns.compat_version: Compatible version
- tns.connect_data: Connect data string (contains SERVICE_NAME, SID, etc.)
- tns.accept_data: Accept data string
- tns.length: Packet length
- tns.sdu_size: Session Data Unit size
- tns.max_tdu_size: Maximum Transmission Data Unit size
- tns.connect_data_length: Length of connect data
- tns.data_oci.id: OCI call ID (in Data packets)
"""

import re
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

import logging

logger = logging.getLogger(__name__)


# TNS packet types
TNS_TYPE_NAMES = {
    "1": "Connect",
    "2": "Accept",
    "3": "ACK",
    "4": "Refuse",
    "5": "Redirect",
    "6": "Data",
    "7": "Null",
    "9": "Abort",
    "11": "Resend",
    "12": "Marker",
    "13": "Attention",
    "14": "Control",
}

# Regex patterns for parsing connect data strings
RE_SERVICE_NAME = re.compile(r"SERVICE_NAME\s*=\s*([^\)]+)", re.IGNORECASE)
RE_SID = re.compile(r"\bSID\s*=\s*([^\)]+)", re.IGNORECASE)
RE_HOST = re.compile(r"HOST\s*=\s*([^\)]+)", re.IGNORECASE)
RE_PORT = re.compile(r"PORT\s*=\s*(\d+)", re.IGNORECASE)
RE_USER = re.compile(r"USER\s*=\s*([^\)]+)", re.IGNORECASE)
RE_PROGRAM = re.compile(r"PROGRAM\s*=\s*([^\)]+)", re.IGNORECASE)
RE_CID_HOST = re.compile(r"CID\s*=\s*\([^)]*HOST\s*=\s*([^\)]+)", re.IGNORECASE)
RE_ERR_CODE = re.compile(r"ERR\s*=\s*(\d+)", re.IGNORECASE)
RE_ERROR_CODE = re.compile(r"CODE\s*=\s*(\d+)", re.IGNORECASE)
RE_VSNNUM = re.compile(r"VSNNUM\s*=\s*(\d+)", re.IGNORECASE)

TNS_DEFAULT_PORT = 1521


class TNSPassiveListener(PySharkListenerBase):
    """Passive Oracle TNS traffic listener for database infrastructure enumeration.

    Captures TNS traffic to extract:
    - Service names and SID names from connect strings
    - Client identity (program, user, host) from CID
    - TNS versions for fingerprinting
    - Connection refusals and error codes
    - Accept data with version info

    Security value:
    - Oracle database infrastructure mapping
    - Service/SID enumeration without active scanning
    - Client program and user identification
    - Version fingerprinting for vulnerability assessment

    Usage:
        listener = TNSPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "tns"
    DISPLAY_FILTER = "tns"
    REQUIRED_LAYERS = ("tns",)
    PROTOCOL_COLUMNS = ("type", "version", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track discovered service names and SIDs
        self.service_names: Dict[str, set] = {}  # server_ip -> {service_names}
        self.sids: Dict[str, set] = {}  # server_ip -> {sids}
        # Track TNS versions per server
        self.server_versions: Dict[str, Dict[str, Any]] = {}  # server_ip -> version info

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format TNS interaction as protocol-specific table columns."""
        d = ix.details
        pkt_type = d.get("packet_type_name", "?")
        version = d.get("version", "")
        compat = d.get("compat_version", "")
        ver_str = ""
        if version:
            ver_str = str(version)
            if compat:
                ver_str += f"/{compat}"

        # Build detail string based on packet type
        if pkt_type == "Connect":
            service = d.get("service_name", "")
            sid = d.get("sid", "")
            program = d.get("program", "")
            parts = []
            if service:
                parts.append(f"SVC={service}")
            if sid:
                parts.append(f"SID={sid}")
            if program:
                parts.append(f"prog={program}")
            detail = " ".join(parts) if parts else d.get("connect_data", "")
        elif pkt_type == "Refuse":
            err = d.get("error_code", "")
            detail = f"ERR={err}" if err else d.get("refuse_data", "")
        elif pkt_type == "Accept":
            detail = d.get("accept_data", "") or ""
        elif pkt_type == "Data":
            oci_id = d.get("oci_call_id", "")
            detail = f"OCI={oci_id}" if oci_id else ""
        elif pkt_type == "Redirect":
            detail = d.get("redirect_data", "") or ""
        else:
            detail = ""

        return [pkt_type, ver_str, detail]

    def process_packet(self, packet) -> None:
        """Process TNS packet and extract connection metadata.

        Handles multi-PDU TCP segments where tshark dissects multiple TNS
        messages in one frame.  In EK mode these produce ``_fields_dict`` as a
        list of dicts instead of a single dict -- PyShark's EkLayer cannot
        resolve field names in that case, so we iterate the raw dicts and
        create synthetic EkLayer objects for each PDU.
        """
        if not hasattr(packet, "tns"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        stream_id = self.get_stream_id(packet)

        # Detect multi-PDU EK mode: _fields_dict is a list of dicts
        tns_dicts = self._get_ek_layer_dicts(packet.tns)
        if tns_dicts is not None:
            from pyshark.packet.layers.ek_layer import EkLayer as _EkLayer

            for sub_dict in tns_dicts:
                syn_layer = _EkLayer(packet.tns._layer_name, sub_dict)
                self._process_single_tns(
                    syn_layer,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    src_mac,
                    dst_mac,
                    flow_id,
                    stream_id,
                )
        else:
            self._process_single_tns(
                packet.tns,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                flow_id,
                stream_id,
            )

    # ------------------------------------------------------------------
    # EK multi-PDU helper
    # ------------------------------------------------------------------

    @staticmethod
    def _get_ek_layer_dicts(layer) -> Optional[List[dict]]:
        """Return the raw list of dicts when an EK layer wraps multiple PDUs.

        In PyShark's EK mode, multi-PDU TCP segments store ``_fields_dict``
        as a *list* of dicts instead of a single dict.  PyShark's ``EkLayer``
        cannot resolve field names in that case.  This helper detects the
        array case and returns the list, or ``None`` for normal single-PDU
        layers.
        """
        try:
            fd = object.__getattribute__(layer, "_fields_dict")
            if isinstance(fd, list):
                return fd
        except AttributeError as e:
            logger.debug(f"TNS EK layer _fields_dict access failed: {e}")
        return None

    # ------------------------------------------------------------------
    # Per-PDU processing
    # ------------------------------------------------------------------

    def _process_single_tns(
        self,
        tns_layer,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Process a single TNS PDU.

        Called once for normal packets and N times for multi-PDU segments.
        """
        now = self._get_timestamp()

        # Get packet type
        pkt_type_raw = self.get_field(tns_layer, "type", "")
        if not pkt_type_raw:
            # Fallback: record as unknown TNS packet so it is never silently dropped
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "TNS Unknown",
                {"packet_type": "?", "packet_type_name": "Unknown"},
                f"TNS Unknown {src_ip} -> {dst_ip}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
            self.logger.debug(f"TNS: missing type field in packet from {src_ip} -> {dst_ip}")
            return
        pkt_type_str = str(pkt_type_raw)
        pkt_type_name = TNS_TYPE_NAMES.get(pkt_type_str, f"Unknown({pkt_type_str})")

        # Get version info
        version = self.get_field(tns_layer, "version", "")
        compat_version = self.get_field(tns_layer, "compat_version", "")
        sdu_size = self.get_field(tns_layer, "sdu_size", "")
        max_tdu_size = self.get_field(tns_layer, "max_tdu_size", "")

        # Determine direction based on packet type and port
        is_server = src_port == TNS_DEFAULT_PORT or pkt_type_str in ("2", "4")
        direction = "response" if is_server else "request"

        # Build base details
        details: Dict[str, Any] = {
            "packet_type": pkt_type_str,
            "packet_type_name": pkt_type_name,
        }
        if version:
            details["version"] = version
        if compat_version:
            details["compat_version"] = compat_version
        if sdu_size:
            details["sdu_size"] = sdu_size
        if max_tdu_size:
            details["max_tdu_size"] = max_tdu_size

        # Handle specific packet types
        if pkt_type_str == "1":  # Connect
            self._handle_connect(details, tns_layer, src_ip, dst_ip, dst_port, src_mac, dst_mac)
        elif pkt_type_str == "2":  # Accept
            self._handle_accept(details, tns_layer, src_ip, src_port, src_mac)
        elif pkt_type_str == "4":  # Refuse
            self._handle_refuse(details, tns_layer)
        elif pkt_type_str == "5":  # Redirect
            redirect_data = self.get_field(tns_layer, "redirect_data", "")
            if redirect_data:
                details["redirect_data"] = str(redirect_data)
        elif pkt_type_str == "6":  # Data
            oci_id = self.get_field(tns_layer, "data_oci_id", "")
            if oci_id:
                details["oci_call_id"] = str(oci_id)

        # Build summary
        summary = f"TNS {pkt_type_name}"
        service = details.get("service_name", "")
        sid = details.get("sid", "")
        if service:
            summary += f" SVC={service}"
        if sid:
            summary += f" SID={sid}"
        err = details.get("error_code", "")
        if err:
            summary += f" ERR={err}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"TNS {pkt_type_name}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track devices for both endpoints
        if is_server:
            self._update_server_device(src_ip, src_port, src_mac)
            if is_valid_discovered_ip(dst_ip):
                self._update_client_device(dst_ip, src_ip, dst_mac)
        else:
            server_ip = dst_ip
            server_port = dst_port
            self._update_server_device(server_ip, server_port, dst_mac)
            if is_valid_discovered_ip(src_ip):
                self._update_client_device(src_ip, server_ip, src_mac)

    def _handle_connect(
        self,
        details: Dict[str, Any],
        tns_layer: Any,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
    ) -> None:
        """Extract service name, SID, and client identity from TNS Connect packet."""
        connect_data = self.get_field(tns_layer, "connect_data", "")
        if connect_data:
            connect_data = str(connect_data)
            details["connect_data"] = connect_data

            # Extract service name
            m = RE_SERVICE_NAME.search(connect_data)
            if m:
                svc = m.group(1).strip()
                details["service_name"] = svc
                self.service_names.setdefault(dst_ip, set()).add(svc)

            # Extract SID
            m = RE_SID.search(connect_data)
            if m:
                sid = m.group(1).strip()
                details["sid"] = sid
                self.sids.setdefault(dst_ip, set()).add(sid)

            # Extract target host/port from connect data
            m = RE_HOST.search(connect_data)
            if m:
                details["target_host"] = m.group(1).strip()
            m = RE_PORT.search(connect_data)
            if m:
                details["target_port"] = m.group(1).strip()

            # Extract client identity from CID
            m = RE_USER.search(connect_data)
            if m:
                details["user"] = m.group(1).strip()
            m = RE_PROGRAM.search(connect_data)
            if m:
                details["program"] = m.group(1).strip()
            m = RE_CID_HOST.search(connect_data)
            if m:
                details["client_host"] = m.group(1).strip()

    def _handle_accept(
        self,
        details: Dict[str, Any],
        tns_layer: Any,
        server_ip: str,
        server_port: int,
        server_mac: str,
    ) -> None:
        """Extract version info and accept data from TNS Accept packet."""
        accept_data = self.get_field(tns_layer, "accept_data", "")
        if accept_data:
            accept_data = str(accept_data)
            details["accept_data"] = accept_data

            # Extract version number from VSNNUM
            m = RE_VSNNUM.search(accept_data)
            if m:
                details["vsnnum"] = m.group(1).strip()

        # Store server version info
        version = details.get("version", "")
        compat = details.get("compat_version", "")
        if version or compat:
            self.server_versions[server_ip] = {
                "version": version,
                "compat_version": compat,
                "vsnnum": details.get("vsnnum", ""),
            }

    def _handle_refuse(self, details: Dict[str, Any], tns_layer: Any) -> None:
        """Extract error info from TNS Refuse packet."""
        # tshark may put refuse reason in connect_data or raw payload
        refuse_data = self.get_field(tns_layer, "connect_data", "")
        if not refuse_data:
            refuse_data = self.get_field(tns_layer, "accept_data", "")
        if refuse_data:
            refuse_data = str(refuse_data)
            details["refuse_data"] = refuse_data

            # Extract error code
            m = RE_ERR_CODE.search(refuse_data)
            if m:
                details["error_code"] = m.group(1).strip()
            m = RE_ERROR_CODE.search(refuse_data)
            if m:
                if "error_code" not in details:
                    details["error_code"] = m.group(1).strip()

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _update_server_device(self, server_ip: str, server_port: int, server_mac: str = "") -> None:
        """Update or create Oracle server device entry."""
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"tns-server:{server_ip}"
        vendor = lookup_mac_vendor(server_mac) if server_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            mac=server_mac,
            name=f"Oracle Server ({server_ip})",
            device_type="Oracle Database",
            manufacturer=vendor if vendor != "Unknown" else "",
        )

        services = sorted(self.service_names.get(server_ip, set()))
        sids = sorted(self.sids.get(server_ip, set()))
        ver_info = self.server_versions.get(server_ip, {})

        protocol_data: Dict[str, Any] = {
            "role": "server",
            "port": server_port,
            "protocol": "TNS/TCP",
        }
        if services:
            protocol_data["service_names"] = services
        if sids:
            protocol_data["sids"] = sids
        if ver_info.get("version"):
            protocol_data["version"] = ver_info["version"]
        if ver_info.get("compat_version"):
            protocol_data["compat_version"] = ver_info["compat_version"]
        if ver_info.get("vsnnum"):
            protocol_data["vsnnum"] = ver_info["vsnnum"]

        device.tns_passive_data = protocol_data

    def _update_client_device(self, client_ip: str, server_ip: str, client_mac: str = "") -> None:
        """Update or create Oracle client device entry."""
        if not is_valid_discovered_ip(client_ip):
            return

        device_key = f"tns-client:{client_ip}"
        vendor = lookup_mac_vendor(client_mac) if client_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            mac=client_mac,
            name=f"Oracle Client ({client_ip})",
            device_type="Oracle Client",
            manufacturer=vendor if vendor != "Unknown" else "",
        )

        if is_new:
            device.tns_passive_data = {
                "role": "client",
                "servers_accessed": [server_ip],
                "protocol": "TNS/TCP",
            }
        else:
            if device.tns_passive_data:
                servers = device.tns_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.tns_passive_data["servers_accessed"] = servers

    # -------------------------------------------------------------------------
    # Harvest
    # -------------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data with Oracle-specific tables."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}

        tables = result.setdefault("tables", [])

        # Service/SID discovery table
        if self.service_names or self.sids:
            rows = []
            all_servers = set(self.service_names.keys()) | set(self.sids.keys())
            for ip in sorted(all_servers):
                services = ", ".join(sorted(self.service_names.get(ip, set()))) or "-"
                sids = ", ".join(sorted(self.sids.get(ip, set()))) or "-"
                ver = self.server_versions.get(ip, {})
                version = ver.get("version", "-")
                rows.append([ip, services, sids, version])
            if rows:
                tables.append(
                    {
                        "headers": ["Server", "Service Names", "SIDs", "Version"],
                        "rows": rows,
                        "title": f"Oracle TNS Services ({len(rows)})",
                    }
                )

        return result
