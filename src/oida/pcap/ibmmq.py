"""
IBM MQ (WebSphere MQ) Passive Listener for enterprise messaging enumeration.

Passively captures IBM MQ traffic to extract:
- Queue manager names from MQCONN and ID exchange
- Channel names from ID structures
- Queue names from MQOPEN operations
- Application names from MQCONN/MQPUT
- MQ API verbs (MQCONN, MQDISC, MQOPEN, MQCLOSE, MQPUT, MQGET, etc.)
- TSH segment types and control flags
- Connection and disconnection events
- Message sizes and counts

IBM MQ uses a proprietary binary protocol over TCP (default port 1414).
tshark recognizes it via the "TSH " (Transmission Segment Header) magic bytes
and dissects it as the ``mq`` protocol layer.

Key tshark MQ fields:
- mq.tsh.type: TSH segment type (0x01=INITIAL_DATA, 0x81=MQCONN, 0x82=MQDISC,
  0x83=MQOPEN, 0x85=MQGET, 0x86=MQPUT, 0x91=MQCONN_REPLY, etc.)
- mq.tsh.seglength: Segment length
- mq.tsh.cflags1: Control flags 1
- mq.tsh.cflags2: Control flags 2
- mq.tsh.encoding: Encoding
- mq.tsh.ccsid: Character set ID
- mq.id.channelname: Channel name from ID structure
- mq.id.qm: Queue manager name from ID structure
- mq.conn.qm: Queue manager from MQCONN
- mq.conn.appname: Application name from MQCONN
- mq.od.objname: Object (queue) name from Object Descriptor
- mq.od.objtype: Object type
- mq.od.objqmgrname: Object queue manager name
- mq.api.completioncode: API completion code (0=OK, 1=WARNING, 2=FAILED)
- mq.api.reasoncode: API reason code
- mq.api.hobj: Object handle

MQ segment types (authority: `tshark -G values | grep mq.tsh.type`, which
mirrors IBM's TSH_* constants -- the request codes are 0x81-0x8f and the XA
block 0xa1-0xaa; each reply is the request code + 0x10):
- 0x01-0x0f: channel-negotiation segments (INITIAL_DATA, SECURITY_DATA, ...)
- 0x81: MQCONN    0x82: MQDISC   0x83: MQOPEN   0x84: MQCLOSE  0x85: MQGET
- 0x86: MQPUT     0x87: MQPUT1   0x88: MQSET    0x89: MQINQ    0x8a: MQCMIT
- 0x8b: MQBACK    0x8c: SPI      0x8d: MQSTAT   0x8e: MQSUB    0x8f: MQSUBRQ
- 0x91-0x9f: the matching *_REPLY codes
- 0xa1-0xaa: XA_START..XA_COMPLETE; 0xb1-0xba: their replies

Reference: IBM MQ protocol specification
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)


# TSH segment type names -- verbatim from `tshark -G values` (field mq.tsh.type).
# The previous table was invented (0x86=MQOPEN, 0x91=MQPUT, 0x83=MQMSG, ...)
# and mislabelled every API verb *and* drove the handler dispatch below.
TSH_TYPE_NAMES = {
    "0x01": "INITIAL_DATA",
    "0x02": "RESYNC_DATA",
    "0x03": "RESET_DATA",
    "0x04": "MESSAGE_DATA",
    "0x05": "STATUS_DATA",
    "0x06": "SECURITY_DATA",
    "0x07": "PING_DATA",
    "0x08": "USERID_DATA",
    "0x09": "HEARTBEAT",
    "0x0a": "CONAUTH_INFO",
    "0x0b": "RENEGOTIATE_DATA",
    "0x0c": "SOCKET_ACTION",
    "0x0d": "ASYNC_MESSAGE",
    "0x0e": "REQUEST_MSGS",
    "0x0f": "NOTIFICATION",
    "0x81": "MQCONN",
    "0x82": "MQDISC",
    "0x83": "MQOPEN",
    "0x84": "MQCLOSE",
    "0x85": "MQGET",
    "0x86": "MQPUT",
    "0x87": "MQPUT1",
    "0x88": "MQSET",
    "0x89": "MQINQ",
    "0x8a": "MQCMIT",
    "0x8b": "MQBACK",
    "0x8c": "SPI",
    "0x8d": "MQSTAT",
    "0x8e": "MQSUB",
    "0x8f": "MQSUBRQ",
    "0x91": "MQCONN_REPLY",
    "0x92": "MQDISC_REPLY",
    "0x93": "MQOPEN_REPLY",
    "0x94": "MQCLOSE_REPLY",
    "0x95": "MQGET_REPLY",
    "0x96": "MQPUT_REPLY",
    "0x97": "MQPUT1_REPLY",
    "0x98": "MQSET_REPLY",
    "0x99": "MQINQ_REPLY",
    "0x9a": "MQCMIT_REPLY",
    "0x9b": "MQBACK_REPLY",
    "0x9c": "SPI_REPLY",
    "0x9d": "MQSTAT_REPLY",
    "0x9e": "MQSUB_REPLY",
    "0x9f": "MQSUBRQ_REPLY",
    "0xa1": "XA_START",
    "0xa2": "XA_END",
    "0xa3": "XA_OPEN",
    "0xa4": "XA_CLOSE",
    "0xa5": "XA_PREPARE",
    "0xa6": "XA_COMMIT",
    "0xa7": "XA_ROLLBACK",
    "0xa8": "XA_FORGET",
    "0xa9": "XA_RECOVER",
    "0xaa": "XA_COMPLETE",
    "0xb1": "XA_START_REPLY",
    "0xb2": "XA_END_REPLY",
    "0xb3": "XA_OPEN_REPLY",
    "0xb4": "XA_CLOSE_REPLY",
    "0xb5": "XA_PREPARE_REPLY",
    "0xb6": "XA_COMMIT_REPLY",
    "0xb7": "XA_ROLLBACK_REPLY",
    "0xb8": "XA_FORGET_REPLY",
    "0xb9": "XA_RECOVER_REPLY",
    "0xba": "XA_COMPLETE_REPLY",
}

# Completion codes
COMPLETION_CODES = {
    "0": "OK",
    "1": "WARNING",
    "2": "FAILED",
}

# Request segment types (client -> server): the 0x8x API verbs and the
# 0xax XA block. Replies are request+0x10 (0x9x / 0xbx) and the 0x0x
# negotiation segments flow in both directions, so they are not listed.
REQUEST_TYPES = {
    "0x81",  # MQCONN
    "0x82",  # MQDISC
    "0x83",  # MQOPEN
    "0x84",  # MQCLOSE
    "0x85",  # MQGET
    "0x86",  # MQPUT
    "0x87",  # MQPUT1
    "0x88",  # MQSET
    "0x89",  # MQINQ
    "0x8a",  # MQCMIT
    "0x8b",  # MQBACK
    "0x8c",  # SPI
    "0x8d",  # MQSTAT
    "0x8e",  # MQSUB
    "0x8f",  # MQSUBRQ
    "0xa1",  # XA_START
    "0xa2",  # XA_END
    "0xa3",  # XA_OPEN
    "0xa4",  # XA_CLOSE
    "0xa5",  # XA_PREPARE
    "0xa6",  # XA_COMMIT
    "0xa7",  # XA_ROLLBACK
    "0xa8",  # XA_FORGET
    "0xa9",  # XA_RECOVER
    "0xaa",  # XA_COMPLETE
}

MQ_DEFAULT_PORT = 1414


class IBMMQPassiveListener(PySharkListenerBase):
    """Passive IBM MQ traffic listener for enterprise messaging enumeration.

    Captures IBM MQ traffic to extract:
    - Queue manager names and channel configurations
    - Queue names from MQOPEN operations
    - Application identities from MQCONN
    - Message operations (PUT, GET, INQ, SET)
    - Connection/disconnection lifecycle

    Security value:
    - Enterprise messaging infrastructure mapping
    - Queue manager and channel discovery
    - Application identification in industrial environments
    - Message flow analysis for OT/IT convergence

    Usage:
        listener = IBMMQPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "ibmmq"
    DISPLAY_FILTER = "mq"
    REQUIRED_LAYERS = ("mq",)
    PROTOCOL_COLUMNS = ("type", "operation", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track queue managers
        self.queue_managers: Dict[str, str] = {}  # server_ip -> qm_name
        # Track channels
        self.channels: Dict[str, Set[str]] = {}  # server_ip -> {channel_names}
        # Track queues
        self.queues: Dict[str, Set[str]] = {}  # server_ip -> {queue_names}
        # Track applications
        self.applications: Dict[str, Set[str]] = {}  # server_ip -> {app_names}
        # Track write operations for alerts
        self._write_ops: List[Dict[str, Any]] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format IBM MQ interaction as protocol-specific table columns."""
        d = ix.details
        seg_type = d.get("segment_type_name", "?")
        operation = ix.operation

        # Build detail string
        parts = []
        qm = d.get("queue_manager", "")
        if qm:
            parts.append(f"QM={qm}")
        channel = d.get("channel_name", "")
        if channel:
            parts.append(f"Ch={channel}")
        queue = d.get("object_name", "")
        if queue:
            parts.append(f"Q={queue}")
        app = d.get("app_name", "")
        if app:
            parts.append(f"App={app}")
        cc = d.get("completion_name", "")
        if cc and cc != "OK":
            parts.append(f"CC={cc}")
        rc = d.get("reason_code", "")
        if rc and rc != "0":
            parts.append(f"RC={rc}")
        detail = " ".join(parts)

        return [seg_type, operation, detail]

    def process_packet(self, packet) -> None:
        """Process IBM MQ packet and extract messaging metadata.

        Handles two EK mode edge cases:
        1. Multi-PDU TCP segments where ``_fields_dict`` is a list of dicts.
        2. Nested dict where ``_fields_dict`` is ``{"mq": {actual_fields}}``
           instead of a flat dict -- PyShark's EkLayer cannot resolve field
           names in either case.
        """
        if not hasattr(packet, "mq"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        stream_id = self.get_stream_id(packet)

        mq_layer = packet.mq

        # Detect EK mode structural issues
        ek_dicts = self._get_ek_layer_dicts(mq_layer)
        if ek_dicts is not None:
            # Multi-PDU TCP segment or nested dict -- iterate each sub-dict
            from pyshark.packet.layers.ek_layer import EkLayer as _EkLayer

            for sub_dict in ek_dicts:
                syn_layer = _EkLayer(mq_layer._layer_name, sub_dict)
                self._process_single_mq(
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
            return

        self._process_single_mq(
            mq_layer,
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
    # EK multi-PDU / nested-dict helper
    # ------------------------------------------------------------------

    def _get_ek_layer_dicts(self, layer) -> Optional[List[dict]]:
        """Return a list of field dicts when EK mode wraps PDUs non-standardly.

        Detects two EK mode variants:
        1. ``_fields_dict`` is a *list* of dicts (multi-PDU TCP segment).
        2. ``_fields_dict`` is a dict with a single key matching the layer
           name, whose value is the actual field dict (nested wrapper).

        Returns a list of dicts (one per PDU) or ``None`` for normal layers.
        """
        try:
            fd = object.__getattribute__(layer, "_fields_dict")
            if isinstance(fd, list):
                return fd
            # Nested dict: {"mq": {actual_fields...}}
            if isinstance(fd, dict):
                layer_name = getattr(layer, "_layer_name", "")
                if layer_name and layer_name in fd and isinstance(fd[layer_name], dict):
                    return [fd[layer_name]]
        except AttributeError as e:
            self.logger.debug(f"IBM MQ EK layer _fields_dict access failed: {e}")
        return None

    # ------------------------------------------------------------------
    # Per-PDU processing
    # ------------------------------------------------------------------

    def _process_single_mq(
        self,
        mq_layer,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Process a single IBM MQ PDU.

        Called once for normal packets and N times for multi-PDU segments.
        """
        now = self._get_timestamp()

        # Get TSH segment type
        seg_type = self.get_field(mq_layer, "tsh_type", "")
        if not seg_type:
            # Fallback: record as unknown so packet is never silently dropped
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "MQ Unknown",
                {"segment_type": "?", "segment_type_name": "Unknown"},
                f"MQ Unknown {src_ip} -> {dst_ip}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
            self.logger.debug(f"IBM MQ: missing tsh_type in packet from {src_ip} -> {dst_ip}")
            return
        # tshark EK mode returns decimal strings (e.g. "1", "129", "134")
        # while XML mode may return hex ("0x01", "0x81"). Normalise to
        # zero-padded hex (e.g. "0x01", "0x81") for dict lookup.
        seg_type_str = str(seg_type).strip()
        if not seg_type_str.startswith("0x"):
            try:
                seg_type_str = f"0x{int(seg_type_str):02x}"
            except ValueError:
                seg_type_str = seg_type_str.lower()
        else:
            # Normalise existing hex to zero-padded lowercase
            try:
                seg_type_str = f"0x{int(seg_type_str, 16):02x}"
            except ValueError:
                seg_type_str = seg_type_str.lower()
        seg_type_name = TSH_TYPE_NAMES.get(seg_type_str, f"Unknown({seg_type})")

        # Determine direction
        is_request = seg_type_str in REQUEST_TYPES
        direction = "request" if is_request else "response"

        # Get TSH metadata
        seg_length = self.get_field(mq_layer, "tsh_seglength", "")
        encoding = self.get_field(mq_layer, "tsh_encoding", "")
        ccsid = self.get_field(mq_layer, "tsh_ccsid", "")
        details: Dict[str, Any] = {
            "segment_type": seg_type_str,
            "segment_type_name": seg_type_name,
        }
        if seg_length:
            details["segment_length"] = str(seg_length)
        if encoding:
            details["encoding"] = str(encoding)
        if ccsid:
            details["ccsid"] = str(ccsid)

        # Extract protocol-specific fields based on segment type
        if seg_type_str == "0x01":  # INITIAL_DATA (ID exchange)
            self._handle_initial_data(details, mq_layer, src_ip, dst_ip)
        elif seg_type_str in ("0x81", "0x91"):  # MQCONN / MQCONN_REPLY
            self._handle_conn(details, mq_layer, src_ip, dst_ip, is_request)
        elif seg_type_str in ("0x83", "0x93"):  # MQOPEN / MQOPEN_REPLY
            self._handle_open(details, mq_layer, src_ip, dst_ip, is_request)
        elif seg_type_str in ("0x86", "0x96", "0x87", "0x97"):
            # MQPUT / MQPUT_REPLY / MQPUT1 / MQPUT1_REPLY
            self._handle_put(details, mq_layer, src_ip, dst_ip, is_request, now)
        elif seg_type_str in ("0x85", "0x95"):  # MQGET / MQGET_REPLY
            self._handle_get(details, mq_layer)

        # Extract API header fields (common to most types)
        self._extract_api_fields(details, mq_layer)

        # Build summary
        summary = f"MQ {seg_type_name}"
        qm = details.get("queue_manager", "")
        if qm:
            summary += f" QM={qm}"
        channel = details.get("channel_name", "")
        if channel:
            summary += f" Ch={channel}"
        obj = details.get("object_name", "")
        if obj:
            summary += f" Q={obj}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"MQ {seg_type_name}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track devices
        server_ip = dst_ip if is_request else src_ip
        client_ip = src_ip if is_request else dst_ip
        server_port = dst_port if is_request else src_port
        server_mac = dst_mac if is_request else src_mac
        client_mac = src_mac if is_request else dst_mac

        self._update_server_device(server_ip, server_port, server_mac)
        if is_valid_discovered_ip(client_ip):
            self._update_client_device(client_ip, server_ip, client_mac)

    def _handle_initial_data(
        self,
        details: Dict[str, Any],
        mq_layer: Any,
        src_ip: str,
        dst_ip: str,
    ) -> None:
        """Extract channel name and QM name from INITIAL_DATA (ID exchange)."""
        channel = self.get_field(mq_layer, "id_channelname", "")
        if channel:
            channel = str(channel).strip().lstrip(",").strip()
            if channel:
                details["channel_name"] = channel
                # Track for both endpoints since ID exchange is bidirectional
                for ip in (src_ip, dst_ip):
                    self.channels.setdefault(ip, set()).add(channel)

        qm_name = self.get_field(mq_layer, "id_qm", "")
        if qm_name:
            qm_name = str(qm_name).strip()
            if qm_name:
                details["queue_manager"] = qm_name
                self.queue_managers[src_ip] = qm_name

    def _handle_conn(
        self,
        details: Dict[str, Any],
        mq_layer: Any,
        src_ip: str,
        dst_ip: str,
        is_request: bool,
    ) -> None:
        """Extract QM name and app name from MQCONN/MQCONN_REPLY."""
        qm = self.get_field(mq_layer, "conn_qm", "")
        if qm:
            qm = str(qm).strip()
            if qm:
                details["queue_manager"] = qm
                server_ip = dst_ip if is_request else src_ip
                self.queue_managers[server_ip] = qm

        app_name = self.get_field(mq_layer, "conn_appname", "")
        if app_name:
            app_name = str(app_name).strip()
            if app_name:
                details["app_name"] = app_name
                server_ip = dst_ip if is_request else src_ip
                self.applications.setdefault(server_ip, set()).add(app_name)

    def _handle_open(
        self,
        details: Dict[str, Any],
        mq_layer: Any,
        src_ip: str,
        dst_ip: str,
        is_request: bool,
    ) -> None:
        """Extract object (queue) name from MQOPEN/MQOPEN_REPLY."""
        obj_name = self.get_field(mq_layer, "od_objname", "")
        if obj_name:
            obj_name = str(obj_name).strip()
            if obj_name:
                details["object_name"] = obj_name
                server_ip = dst_ip if is_request else src_ip
                self.queues.setdefault(server_ip, set()).add(obj_name)

        obj_type = self.get_field(mq_layer, "od_objtype", "")
        if obj_type:
            details["object_type"] = str(obj_type)

        obj_qmgr = self.get_field(mq_layer, "od_objqmgrname", "")
        if obj_qmgr:
            obj_qmgr = str(obj_qmgr).strip()
            if obj_qmgr:
                details["object_qmgr"] = obj_qmgr

    def _handle_put(
        self,
        details: Dict[str, Any],
        mq_layer: Any,
        src_ip: str,
        dst_ip: str,
        is_request: bool,
        now: str,
    ) -> None:
        """Extract put application name and track write operations."""
        # md.applname is the real tshark field (md.putapplname does not
        # exist in the mq dissector); keep the old name as a fallback in
        # case a future tshark version reintroduces it.
        put_app = self.get_field_any(mq_layer, "md_applname", "md_putapplname", default="")
        if put_app:
            put_app = str(put_app).strip()
            if put_app:
                details["put_app_name"] = put_app
                server_ip = dst_ip if is_request else src_ip
                self.applications.setdefault(server_ip, set()).add(put_app)

        # Track write operations for alerting
        if is_request:
            self._write_ops.append(
                {
                    "client": src_ip,
                    "server": dst_ip,
                    "operation": "MQPUT",
                    "timestamp": now,
                }
            )

    def _handle_get(
        self,
        details: Dict[str, Any],
        mq_layer: Any,
    ) -> None:
        """Extract get-specific fields."""
        # Nothing additional for now; API fields are extracted separately
        pass

    def _extract_api_fields(self, details: Dict[str, Any], mq_layer: Any) -> None:
        """Extract common API header fields."""
        cc = self.get_field(mq_layer, "api_completioncode", "")
        if cc:
            details["completion_code"] = str(cc)
            details["completion_name"] = COMPLETION_CODES.get(str(cc), str(cc))

        rc = self.get_field(mq_layer, "api_reasoncode", "")
        if rc:
            details["reason_code"] = str(rc)

        hobj = self.get_field(mq_layer, "api_hobj", "")
        if hobj:
            details["object_handle"] = str(hobj)

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _update_server_device(self, server_ip: str, server_port: int, server_mac: str = "") -> None:
        """Update or create IBM MQ server (queue manager) device entry."""
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"ibmmq-server:{server_ip}"
        vendor = lookup_mac_vendor(server_mac) if server_mac else ""

        qm_name = self.queue_managers.get(server_ip, "")
        name = f"MQ QM {qm_name}" if qm_name else f"IBM MQ Server ({server_ip})"

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            mac=server_mac,
            name=name,
            device_type="MQ Queue Manager",
            manufacturer=vendor if vendor != "Unknown" else "",
        )

        protocol_data: Dict[str, Any] = {
            "role": "server",
            "port": server_port,
            "protocol": "MQ/TCP",
        }
        if qm_name:
            protocol_data["queue_manager"] = qm_name
        channels = sorted(self.channels.get(server_ip, set()))
        if channels:
            protocol_data["channels"] = channels
        queues = sorted(self.queues.get(server_ip, set()))
        if queues:
            protocol_data["queues"] = queues
        apps = sorted(self.applications.get(server_ip, set()))
        if apps:
            protocol_data["applications"] = apps

        device.ibmmq_passive_data = protocol_data

    def _update_client_device(self, client_ip: str, server_ip: str, client_mac: str = "") -> None:
        """Update or create IBM MQ client device entry."""
        if not is_valid_discovered_ip(client_ip):
            return

        device_key = f"ibmmq-client:{client_ip}"
        vendor = lookup_mac_vendor(client_mac) if client_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            mac=client_mac,
            name=f"MQ Client ({client_ip})",
            device_type="MQ Client",
            manufacturer=vendor if vendor != "Unknown" else "",
        )

        if is_new:
            device.ibmmq_passive_data = {
                "role": "client",
                "servers_accessed": [server_ip],
                "protocol": "MQ/TCP",
            }
        else:
            if device.ibmmq_passive_data:
                servers = device.ibmmq_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.ibmmq_passive_data["servers_accessed"] = servers

    # -------------------------------------------------------------------------
    # Harvest and write alerts
    # -------------------------------------------------------------------------

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get MQ write operations (MQPUT) for alert generation."""
        if not self._write_ops:
            return []

        pairs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for op in self._write_ops:
            key = (op["client"], op["server"])
            if key not in pairs:
                pairs[key] = {
                    "client": op["client"],
                    "server": op["server"],
                    "write_count": 0,
                }
            pairs[key]["write_count"] += 1

        return list(pairs.values())

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data with MQ-specific tables."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}

        tables = result.setdefault("tables", [])

        # Queue manager discovery table
        if self.queue_managers:
            rows = []
            for ip, qm in sorted(self.queue_managers.items()):
                channels = ", ".join(sorted(self.channels.get(ip, set()))) or "-"
                queues = ", ".join(sorted(self.queues.get(ip, set()))) or "-"
                apps = ", ".join(sorted(self.applications.get(ip, set()))) or "-"
                rows.append([ip, qm, channels, queues, apps])
            if rows:
                tables.append(
                    {
                        "headers": [
                            "Server",
                            "Queue Manager",
                            "Channels",
                            "Queues",
                            "Applications",
                        ],
                        "rows": rows,
                        "title": f"IBM MQ Queue Managers ({len(rows)})",
                    }
                )

        return result
