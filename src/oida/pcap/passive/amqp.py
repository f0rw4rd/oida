"""
AMQP Passive Listener for messaging infrastructure discovery.

Passively captures AMQP traffic to extract:
- Exchange and queue names
- Routing keys
- Broker connection properties
- SASL authentication mechanisms
- Connection metadata (virtual host, channel IDs)
- Message counts and delivery info

AMQP uses:
- TCP port: 5672 (plaintext)
- TCP port: 5671 (AMQP over TLS)

Frame types:
- Method: Protocol operations (connection, channel, exchange, queue, basic)
- Header: Content header with properties
- Body: Message body content
- Heartbeat: Connection keepalive

Class.Method operations of interest:
- Connection.Start / Start-Ok: Broker handshake, SASL mechanisms
- Connection.Tune / Tune-Ok: Channel/frame limits
- Connection.Open / Open-Ok: Virtual host selection
- Channel.Open / Close: Channel lifecycle
- Exchange.Declare: Exchange creation
- Queue.Declare / Bind: Queue creation and binding
- Basic.Publish / Consume / Deliver: Message operations
- Basic.Ack / Nack: Acknowledgments

Security value for ICS:
- Enterprise messaging infrastructure discovery
- ICS message bus enumeration (SCADA to MES)
- SASL auth mechanism identification
- Queue/exchange topology mapping

PyShark AMQP field reference (packet.amqp.*):
- amqp.method.method: Method ID
- amqp.method.class: Class ID
- amqp.method.arguments.exchange: Exchange name
- amqp.method.arguments.queue: Queue name
- amqp.method.arguments.routing_key: Routing key
- amqp.type: Frame type
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# AMQP constants
AMQP_PORT = 5672
AMQP_TLS_PORT = 5671

# AMQP class IDs
AMQP_CLASSES: Dict[str, str] = {
    "10": "Connection",
    "20": "Channel",
    "40": "Exchange",
    "50": "Queue",
    "60": "Basic",
    "85": "Confirm",
    "90": "Tx",
}

# AMQP method IDs (within each class)
AMQP_CONNECTION_METHODS: Dict[str, str] = {
    "10": "Start",
    "11": "Start-Ok",
    "20": "Secure",
    "21": "Secure-Ok",
    "30": "Tune",
    "31": "Tune-Ok",
    "40": "Open",
    "41": "Open-Ok",
    "50": "Close",
    "51": "Close-Ok",
}

AMQP_CHANNEL_METHODS: Dict[str, str] = {
    "10": "Open",
    "11": "Open-Ok",
    "20": "Flow",
    "21": "Flow-Ok",
    "40": "Close",
    "41": "Close-Ok",
}

AMQP_EXCHANGE_METHODS: Dict[str, str] = {
    "10": "Declare",
    "11": "Declare-Ok",
    "20": "Delete",
    "21": "Delete-Ok",
    "30": "Bind",
    "31": "Bind-Ok",
    "40": "Unbind",
    "51": "Unbind-Ok",
}

AMQP_QUEUE_METHODS: Dict[str, str] = {
    "10": "Declare",
    "11": "Declare-Ok",
    "20": "Bind",
    "21": "Bind-Ok",
    "30": "Purge",
    "31": "Purge-Ok",
    "40": "Delete",
    "41": "Delete-Ok",
    "50": "Unbind",
    "51": "Unbind-Ok",
}

AMQP_BASIC_METHODS: Dict[str, str] = {
    "10": "Qos",
    "11": "Qos-Ok",
    "20": "Consume",
    "21": "Consume-Ok",
    "30": "Cancel",
    "31": "Cancel-Ok",
    "40": "Publish",
    "50": "Return",
    "60": "Deliver",
    "70": "Get",
    "71": "Get-Ok",
    "72": "Get-Empty",
    "80": "Ack",
    "90": "Reject",
    "100": "Recover",
    "110": "Recover-Ok",
    "120": "Nack",
}

# Class -> method map
AMQP_METHOD_MAPS: Dict[str, Dict[str, str]] = {
    "10": AMQP_CONNECTION_METHODS,
    "20": AMQP_CHANNEL_METHODS,
    "40": AMQP_EXCHANGE_METHODS,
    "50": AMQP_QUEUE_METHODS,
    "60": AMQP_BASIC_METHODS,
}

# AMQP frame types
AMQP_FRAME_TYPES: Dict[str, str] = {
    "1": "Method",
    "2": "Header",
    "3": "Body",
    "8": "Heartbeat",
}


class AMQPPassiveListener(PySharkListenerBase):
    """Passive AMQP traffic listener for messaging infrastructure discovery.

    Captures AMQP traffic to extract:
    - Exchange and queue declarations
    - Routing keys and bindings
    - Broker properties and SASL mechanisms
    - Connection virtual hosts
    - Message publish/consume activity

    Usage:
        listener = AMQPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for ix in listener.interactions:
            print(f"{ix.operation}: {ix.details}")
    """

    PROTOCOL_NAME = "amqp"
    DISPLAY_FILTER = "amqp"
    REQUIRED_LAYERS = ("amqp",)
    PROTOCOL_COLUMNS = (
        "class_method",
        "exchange",
        "queue",
        "routing_key",
        "detail",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: list = []
        self._seen_creds: set = set()

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format AMQP interaction as protocol-specific table columns."""
        d = ix.details
        class_method = d.get("class_method", "?")
        exchange = d.get("exchange", "") or "-"
        queue = d.get("queue", "") or "-"
        routing_key = d.get("routing_key", "") or "-"
        detail = d.get("detail", "") or "-"
        return [
            class_method,
            exchange,
            queue,
            routing_key,
            detail,
        ]

    def process_packet(self, packet) -> None:
        """Process AMQP packet and extract messaging infrastructure info."""
        if not hasattr(packet, "amqp"):
            return

        amqp = packet.amqp
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        stream_id = self.get_stream_id(packet)

        # Get frame type
        frame_type_raw = str(self.get_field(amqp, "type", "") or "")
        frame_type = AMQP_FRAME_TYPES.get(frame_type_raw, "")

        # Get class and method IDs
        class_id = str(self.get_field(amqp, "method_class", "") or "")
        if not class_id:
            class_id = str(self.get_field(amqp, "method_method_class", "") or "")
        method_id = str(self.get_field(amqp, "method_method", "") or "")
        if not method_id:
            method_id = str(self.get_field(amqp, "method", "") or "")

        # Resolve class and method names
        class_name = AMQP_CLASSES.get(class_id, f"Class-{class_id}") if class_id else ""
        method_map = AMQP_METHOD_MAPS.get(class_id, {})
        method_name = method_map.get(method_id, f"Method-{method_id}") if method_id else ""

        class_method = f"{class_name}.{method_name}" if class_name and method_name else ""
        if not class_method:
            if frame_type == "Heartbeat":
                class_method = "Heartbeat"
            elif frame_type:
                class_method = frame_type
            else:
                class_method = "AMQP"

        # Determine direction
        is_response = method_name.endswith("-Ok") or method_name in (
            "Start",
            "Tune",
            "Deliver",
            "Return",
            "Get-Ok",
            "Get-Empty",
        )
        direction = "response" if is_response else "request"

        # Extract protocol-specific fields
        exchange = str(self.get_field(amqp, "method_arguments_exchange", "") or "")
        queue = str(self.get_field(amqp, "method_arguments_queue", "") or "")
        routing_key = str(self.get_field(amqp, "method_arguments_routing_key", "") or "")
        consumer_tag = str(self.get_field(amqp, "method_arguments_consumer_tag", "") or "")
        vhost = str(self.get_field(amqp, "method_arguments_virtual_host", "") or "")
        channel = str(self.get_field(amqp, "channel", "") or "")

        # Connection metadata
        mechanism = str(self.get_field(amqp, "method_arguments_mechanism", "") or "")
        mechanisms = str(self.get_field(amqp, "method_arguments_mechanisms", "") or "")
        # Locale field extracted but not currently used
        # locale = str(self.get_field(amqp, "method_arguments_locale", "") or "")
        reply_code = str(self.get_field(amqp, "method_arguments_reply_code", "") or "")
        reply_text = str(self.get_field(amqp, "method_arguments_reply_text", "") or "")

        # Build detail string
        detail_parts: List[str] = []
        if vhost:
            detail_parts.append(f"vhost={vhost}")
        if mechanism:
            detail_parts.append(f"mechanism={mechanism}")
        if mechanisms:
            detail_parts.append(f"mechanisms={mechanisms}")
        if consumer_tag:
            detail_parts.append(f"consumer={consumer_tag}")
        if channel and channel != "0":
            detail_parts.append(f"ch={channel}")
        if reply_code and reply_code != "0":
            detail_parts.append(f"reply={reply_code}")
        if reply_text:
            detail_parts.append(reply_text)

        details: Dict[str, Any] = {
            "class_method": class_method,
            "class_id": class_id,
            "method_id": method_id,
            "class_name": class_name,
            "method_name": method_name,
            "frame_type": frame_type,
            "exchange": exchange,
            "queue": queue,
            "routing_key": routing_key,
            "consumer_tag": consumer_tag,
            "vhost": vhost,
            "channel": channel,
            "mechanism": mechanism,
            "mechanisms": mechanisms,
            "reply_code": reply_code,
            "reply_text": reply_text,
            "detail": " ".join(detail_parts),
        }

        now = datetime.now().isoformat()
        summary = f"AMQP {class_method}"
        if exchange:
            summary += f" exchange={exchange}"
        if queue:
            summary += f" queue={queue}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"AMQP {class_method}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track SASL credentials
        if mechanism and class_method == "Connection.Start-Ok":
            response = str(self.get_field(amqp, "method_arguments_response", "") or "")
            if response:
                self._extract_sasl_credentials(
                    mechanism,
                    response,
                    src_ip,
                    dst_ip,
                    dst_port,
                    now,
                )

        # Update device tracking
        self._update_devices(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            class_method,
            src_mac=src_mac,
            dst_mac=dst_mac,
            vhost=vhost,
            mechanisms=mechanisms or mechanism,
        )

    def _extract_sasl_credentials(
        self,
        mechanism: str,
        response: str,
        client_ip: str,
        server_ip: str,
        server_port: int,
        timestamp: str,
    ) -> None:
        """Extract credentials from SASL authentication response."""
        if mechanism.upper() == "PLAIN":
            username, password = self._decode_auth_plain(response)
            if username:
                cred_key = (username, client_ip, server_ip)
                if cred_key not in self._seen_creds:
                    self._seen_creds.add(cred_key)
                    self.credentials.append(
                        {
                            "protocol": "AMQP",
                            "credential_type": "plaintext",
                            "auth_method": "SASL-PLAIN",
                            "username": username,
                            "password": password,
                            "server_ip": server_ip,
                            "server_port": server_port,
                            "client_ip": client_ip,
                            "timestamp": timestamp,
                        }
                    )
                    self.logger.info(f"AMQP SASL PLAIN: {username} @ {server_ip}:{server_port}")

    def _update_devices(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        class_method: str,
        src_mac: str = "",
        dst_mac: str = "",
        vhost: str = "",
        mechanisms: str = "",
    ) -> None:
        """Update device entries for AMQP participants."""
        # Broker is the side with port 5672
        if dst_port in (AMQP_PORT, AMQP_TLS_PORT):
            broker_ip = dst_ip
            client_ip = src_ip
            broker_mac = dst_mac
            client_mac = src_mac
        elif src_port in (AMQP_PORT, AMQP_TLS_PORT):
            broker_ip = src_ip
            client_ip = dst_ip
            broker_mac = src_mac
            client_mac = dst_mac
        else:
            return

        if is_valid_discovered_ip(broker_ip):
            vendor = lookup_mac_vendor(broker_mac) if broker_mac else ""
            device, is_new = self._ensure_device(
                f"amqp-broker:{broker_ip}",
                broker_ip,
                mac=broker_mac,
                name="",
                device_type="AMQP Broker",
                manufacturer=vendor if vendor != "Unknown" else "",
            )
            if is_new:
                device.amqp_passive_data = {
                    "role": "broker",
                    "protocol": "AMQP/TCP",
                    "vhost": vhost,
                    "mechanisms": mechanisms,
                }
            else:
                data = getattr(device, "amqp_passive_data", None)
                if data:
                    if vhost and not data.get("vhost"):
                        data["vhost"] = vhost
                    if mechanisms and not data.get("mechanisms"):
                        data["mechanisms"] = mechanisms

        if is_valid_discovered_ip(client_ip):
            vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            device, is_new = self._ensure_device(
                f"amqp-client:{client_ip}",
                client_ip,
                mac=client_mac,
                name="",
                device_type="AMQP Client",
                manufacturer=vendor if vendor != "Unknown" else "",
            )
            if is_new:
                device.amqp_passive_data = {
                    "role": "client",
                    "protocol": "AMQP/TCP",
                }

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return list(self.credentials)
