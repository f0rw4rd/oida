"""
Java RMI (Remote Method Invocation) Passive Listener.

Passively captures Java RMI traffic to extract:
- RMI protocol version and type (Stream, SingleOp, Multiplex)
- Endpoint hostnames and ports from server responses
- Call/Return message types
- Java serialization markers (potential deserialization attack vectors)

RMI runs on TCP port 1099 (default registry port).

Security value:
- Java application infrastructure discovery
- RMI deserialization attacks (ysoserial, etc.)
- JNDI injection vectors
- Remote class loading exploitation
- Registry enumeration for bound objects

tshark fields used (requires decode_as tcp.port==1099,rmi):
- rmi.magic: RMI header magic (0x4a524d49 = "JRMI")
- rmi.version: RMI protocol version
- rmi.protocol: Protocol type (0x4b=Stream, 0x4c=SingleOp, 0x4d=Multiplex)
- rmi.inputstream.message: Input stream message token
- rmi.outputstream.message: Output stream message token
- rmi.endpoint_id.hostname: Endpoint hostname
- rmi.endpoint_id.port: Endpoint port
- rmi.serialization_data: Serialized Java object data
- rmi.ser.magic: Java serialization magic (0xaced)
- rmi.ser.version: Java serialization version
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# RMI protocol types (hex and decimal for pyshark EK/XML modes)
PROTOCOL_TYPES = {
    "0x4b": "StreamProtocol",
    "0x4c": "SingleOpProtocol",
    "0x4d": "MultiplexProtocol",
    "75": "StreamProtocol",
    "76": "SingleOpProtocol",
    "77": "MultiplexProtocol",
}

# RMI output stream message tokens (client -> server)
OUTPUT_MESSAGES = {
    "0x50": "Call",
    "0x52": "Ping",
    "0x54": "DgcAck",
    "80": "Call",
    "82": "Ping",
    "84": "DgcAck",
}

# RMI input stream message tokens (server -> client)
INPUT_MESSAGES = {
    "0x4e": "ProtocolAck",
    "0x4f": "ProtocolNotSupported",
    "0x51": "ReturnData",
    "0x53": "PingAck",
    "78": "ProtocolAck",
    "79": "ProtocolNotSupported",
    "81": "ReturnData",
    "83": "PingAck",
}

# RMI magic values (hex and decimal)
RMI_MAGIC_VALUES = {"0x4a524d49", "1246907721"}


class RMIPassiveListener(PySharkListenerBase):
    """Passive Java RMI traffic listener.

    Captures RMI traffic to extract:
    - Protocol handshake details (version, protocol type)
    - Endpoint identifiers (hostname, port)
    - Call/Return message types
    - Java serialization markers

    Usage:
        listener = RMIPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "rmi"
    DISPLAY_FILTER = "rmi"
    REQUIRED_LAYERS = ("rmi",)
    PROTOCOL_COLUMNS = ("type", "protocol", "endpoint", "detail")
    SERVER_PORTS = (1099,)

    # Decode-as hint needed because tshark doesn't auto-detect RMI
    DECODE_AS = {"tcp.port==1099": "rmi"}

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.endpoints: Dict[str, Set[str]] = {}  # server_ip -> set of endpoint hostnames
        # Flows where Java serialized data was observed (deserialization attack
        # surface -- ysoserial / JNDI injection). Keyed (client_ip, server_ip).
        self.serialization_flows: Set[Tuple[str, str]] = set()

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format RMI interaction as protocol-specific table columns."""
        d = ix.details
        msg_type = d.get("message_type", "")
        protocol = d.get("protocol_name", "")
        endpoint = d.get("endpoint", "")
        detail = d.get("detail", "")
        return [msg_type, protocol, endpoint, detail]

    def process_packet(self, packet) -> None:
        """Process RMI packet."""
        if not hasattr(packet, "rmi"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            self.logger.debug(
                f"Dropping RMI packet with missing IP (src={src_ip!r} dst={dst_ip!r})"
            )
            return

        rmi = packet.rmi
        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        magic = str(self.get_field(rmi, "magic", "") or "")
        version = str(self.get_field(rmi, "version", "") or "")
        protocol_raw = str(self.get_field(rmi, "protocol", "") or "")
        input_msg = str(self.get_field(rmi, "inputstream_message", "") or "")
        output_msg = str(self.get_field(rmi, "outputstream_message", "") or "")
        endpoint_host = str(self.get_field(rmi, "endpoint_id_hostname", "") or "")
        endpoint_port = str(self.get_field(rmi, "endpoint_id_port", "") or "")
        ser_magic = str(self.get_field(rmi, "ser_magic", "") or "")
        ser_version = str(self.get_field(rmi, "ser_version", "") or "")

        # Determine message type and direction
        if magic.lower() in RMI_MAGIC_VALUES or magic in RMI_MAGIC_VALUES:
            # Client handshake: JRMI magic + version + protocol
            self._process_handshake(
                src_ip,
                dst_ip,
                version,
                protocol_raw,
                flow_id,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                packet,
            )
        elif input_msg:
            # Server -> Client message
            self._process_input_message(
                input_msg,
                src_ip,
                dst_ip,
                endpoint_host,
                endpoint_port,
                flow_id,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                packet,
            )
        elif output_msg:
            # Client -> Server message
            self._process_output_message(
                output_msg,
                src_ip,
                dst_ip,
                ser_magic,
                ser_version,
                flow_id,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                packet,
            )
        else:
            # No fresh stream token (magic / input / output). Typically a
            # serialization-data continuation segment -- the highest-value
            # signal here (ysoserial / JNDI deserialization surface). Don't
            # silently drop it: record a generic interaction so it leaves a
            # trace and a debug log explaining the skip.
            ser_data = str(self.get_field(rmi, "serialization_data", "") or "")
            self._process_data(
                src_ip,
                dst_ip,
                ser_magic,
                ser_version,
                ser_data,
                flow_id,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                packet,
            )

    def _process_handshake(
        self,
        src_ip,
        dst_ip,
        version,
        protocol_raw,
        flow_id,
        src_port,
        dst_port,
        src_mac,
        dst_mac,
        packet,
    ) -> None:
        """Process RMI handshake (JRMI header from client)."""
        protocol_name = PROTOCOL_TYPES.get(
            protocol_raw.lower() if protocol_raw else "",
            f"Unknown({protocol_raw})",
        )

        detail_parts = []
        if version:
            detail_parts.append(f"v{version}")
        detail_parts.append(protocol_name)
        detail = " ".join(detail_parts)

        details: Dict[str, Any] = {
            "message_type": "Handshake",
            "version": version,
            "protocol": protocol_raw,
            "protocol_name": protocol_name,
            "endpoint": "",
            "detail": detail,
        }

        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "RMI Handshake",
            details,
            f"RMI Handshake {protocol_name} v{version} {src_ip} -> {dst_ip}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Client is connecting to RMI registry/server
        self._update_devices(
            src_ip,
            dst_ip,
            src_mac,
            dst_mac,
        )

    def _process_input_message(
        self,
        input_msg,
        src_ip,
        dst_ip,
        endpoint_host,
        endpoint_port,
        flow_id,
        src_port,
        dst_port,
        src_mac,
        dst_mac,
        packet,
    ) -> None:
        """Process RMI input stream message (server -> client)."""
        msg_name = INPUT_MESSAGES.get(input_msg.lower(), f"Input({input_msg})")

        endpoint = ""
        if endpoint_host:
            endpoint = endpoint_host
            if endpoint_port:
                endpoint += f":{endpoint_port}"
            # Track discovered endpoints
            if src_ip not in self.endpoints:
                self.endpoints[src_ip] = set()
            self.endpoints[src_ip].add(endpoint)

        detail_parts = [msg_name]
        if endpoint:
            detail_parts.append(f"endpoint={endpoint}")
        detail = " ".join(detail_parts)

        details: Dict[str, Any] = {
            "message_type": msg_name,
            "input_message": input_msg,
            "endpoint_host": endpoint_host,
            "endpoint_port": endpoint_port,
            "endpoint": endpoint,
            "protocol_name": "",
            "detail": detail,
        }

        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            f"RMI {msg_name}",
            details,
            f"RMI {msg_name} {src_ip} -> {dst_ip}" + (f" endpoint={endpoint}" if endpoint else ""),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Server is sending response to client
        self._update_devices(
            dst_ip,
            src_ip,
            dst_mac,
            src_mac,
        )

    def _process_output_message(
        self,
        output_msg,
        src_ip,
        dst_ip,
        ser_magic,
        ser_version,
        flow_id,
        src_port,
        dst_port,
        src_mac,
        dst_mac,
        packet,
    ) -> None:
        """Process RMI output stream message (client -> server)."""
        msg_name = OUTPUT_MESSAGES.get(output_msg.lower(), f"Output({output_msg})")

        detail_parts = [msg_name]
        has_serialization = ser_magic.lower() in ("0xaced", "44269", "aced")
        if has_serialization:
            detail_parts.append(f"java-ser-v{ser_version}")
            # Output messages flow client -> server.
            self.serialization_flows.add((src_ip, dst_ip))
        detail = " ".join(detail_parts)

        details: Dict[str, Any] = {
            "message_type": msg_name,
            "output_message": output_msg,
            "has_serialization": has_serialization,
            "ser_version": ser_version if has_serialization else "",
            "endpoint": "",
            "protocol_name": "",
            "detail": detail,
        }

        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"RMI {msg_name}",
            details,
            f"RMI {msg_name} {src_ip} -> {dst_ip}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        self._update_devices(
            src_ip,
            dst_ip,
            src_mac,
            dst_mac,
        )

    def _process_data(
        self,
        src_ip,
        dst_ip,
        ser_magic,
        ser_version,
        ser_data,
        flow_id,
        src_port,
        dst_port,
        src_mac,
        dst_mac,
        packet,
    ) -> None:
        """Record an RMI packet that carries no fresh stream token.

        These are typically serialization-data continuation segments (the Java
        deserialization attack surface) or fragments/keepalives. We still record
        them so no packet matching the ``rmi`` display filter is silently
        dropped. ser_magic/ser_version are read here too -- serialized data can
        arrive without a leading output token, and that should still be flagged
        into ``serialization_flows``.
        """
        has_serialization = ser_magic.lower() in ("0xaced", "44269", "aced")
        # Direction via the shared cascade.  A serialization-data continuation
        # segment carries no stream token (magic / input / output), so there is
        # no native QR signal -- resolve_direction() falls through to the
        # known-server-port tier (canonical 1099 plus any user --decode-as /
        # OVERRIDE_PREFS override) and then the lower-port heuristic.
        d = self.resolve_direction(
            packet,
            native=None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        is_request_dir = d.is_request
        direction = "request" if is_request_dir else "response"

        detail_parts = ["Data"]
        if has_serialization:
            detail_parts.append(f"java-ser-v{ser_version}")
            # Output flows client -> server; record that direction as the flow.
            if is_request_dir:
                self.serialization_flows.add((src_ip, dst_ip))
            else:
                self.serialization_flows.add((dst_ip, src_ip))
        detail = " ".join(detail_parts)

        self.logger.debug(
            f"RMI data segment (no magic/input/output token) "
            f"from {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
            f"serialization={has_serialization}"
        )

        details: Dict[str, Any] = {
            "message_type": "Data",
            "has_serialization": has_serialization,
            "ser_version": ser_version if has_serialization else "",
            "endpoint": "",
            "protocol_name": "",
            "detail": detail,
        }

        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            "RMI Data",
            details,
            f"RMI Data {src_ip} -> {dst_ip}"
            + (" (java-serialization)" if has_serialization else ""),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        if is_request_dir:
            self._update_devices(src_ip, dst_ip, src_mac, dst_mac)
        else:
            self._update_devices(dst_ip, src_ip, dst_mac, src_mac)

    def _update_devices(
        self,
        client_ip,
        server_ip,
        client_mac,
        server_mac,
    ) -> None:
        """Create/update device entries for RMI participants."""
        if is_valid_discovered_ip(server_ip):
            vendor = lookup_mac_vendor(server_mac) if server_mac else ""
            device, is_new = self._ensure_device(
                f"rmi-server:{server_ip}",
                server_ip,
                mac=server_mac or "",
                name=f"RMI Server ({server_ip})",
                device_type="RMI Server",
                manufacturer=vendor if vendor != "Unknown" else "",
            )
            if is_new:
                device.rmi_passive_data = {
                    "role": "server",
                    "protocol": "RMI/TCP",
                    "endpoints": [],
                }
            if hasattr(device, "rmi_passive_data") and device.rmi_passive_data:
                eps = self.endpoints.get(server_ip, set())
                device.rmi_passive_data["endpoints"] = sorted(eps)

        if is_valid_discovered_ip(client_ip):
            vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            device, is_new = self._ensure_device(
                f"rmi-client:{client_ip}",
                client_ip,
                mac=client_mac or "",
                name=f"RMI Client ({client_ip})",
                device_type="RMI Client",
                manufacturer=vendor if vendor != "Unknown" else "",
            )
            if is_new:
                device.rmi_passive_data = {
                    "role": "client",
                    "protocol": "RMI/TCP",
                }

    # -------------------------------------------------------------------------
    # Harvest
    # -------------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Surface discovered RMI endpoints + Java deserialization surface.

        RMI endpoint hostnames (registry-bound objects) and observed Java
        serialized payloads are key attack-surface signals (ysoserial / JNDI
        injection) -- emit them as a structured table + alerts rather than
        leaving them buried in the interaction timeline.
        """
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        tables = result.setdefault("tables", [])
        alerts = result.setdefault("alerts", [])

        if self.endpoints:
            rows = []
            for server_ip, eps in sorted(self.endpoints.items()):
                ep_list = ", ".join(sorted(e for e in eps if e)) or "?"
                rows.append([server_ip, ep_list])
            if rows:
                tables.append(
                    {
                        "headers": ["Server", "Endpoints"],
                        "rows": rows,
                        "title": f"RMI Endpoints ({len(rows)})",
                    }
                )

        for client_ip, server_ip in sorted(self.serialization_flows):
            alerts.append(
                {
                    "level": "warning",
                    "category": "control_alert",
                    "message": (
                        f"RMI JAVA SERIALIZATION: {client_ip} -> {server_ip} "
                        f"-- deserialization attack surface (ysoserial / JNDI)"
                    ),
                }
            )

        if not tables and not alerts:
            return {}
        return result
