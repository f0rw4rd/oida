"""
MQTT-SN (MQTT for Sensor Networks) Passive Listener (PyShark-based).

Passively monitors MQTT-SN traffic to identify:
- Gateways (ADVERTISE / GWINFO) and the clients that connect to them
- Client IDs (CONNECT) and keep-alive/will configuration
- Registered/published topics and topic IDs (topic namespace mapping)
- Subscriptions and QoS levels

MQTT-SN is the UDP/non-TCP variant of MQTT aimed at low-power sensor nodes
(ISO/IEC 20922 companion spec).  Messages are compact and connectionless.

Message format (UDP 1883 by default; decode-as required, no auto-port):
- Length (1 byte; 0x01 => 3-byte extended length)
- MsgType (1 byte)
- Variable payload per message type

tshark fields used (mqttsn layer):
- mqttsn.msg.type       : message type (0x00 ADVERTISE .. 0x18 DISCONNECT)
- mqttsn.client.id      : client identifier (CONNECT / PINGREQ / WILL*)
- mqttsn.gw.id          : gateway id (ADVERTISE / GWINFO)
- mqttsn.topic.id       : numeric topic id (REGISTER / PUBLISH)
- mqttsn.topic          : topic name (REGISTER)
- mqttsn.topic.name.or.id : subscribe/unsubscribe topic
- mqttsn.pub.msg        : published payload
- mqttsn.qos            : QoS level
- mqttsn.radius         : broadcast radius (SEARCHGW)
- mqttsn.adv.interv     : advertise interval (ADVERTISE)
- mqttsn.keep.alive     : keep-alive duration (CONNECT)

Reference: MQTT-SN Protocol Specification v1.2 (OASIS).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# Message type -> (name, originator role).  "client" = sent by the sensor node,
# "gw" = sent by the gateway, "either" = symmetric.
MQTTSN_MSG = {
    "0x00": ("ADVERTISE", "gw"),
    "0x01": ("SEARCHGW", "client"),
    "0x02": ("GWINFO", "gw"),
    "0x04": ("CONNECT", "client"),
    "0x05": ("CONNACK", "gw"),
    "0x06": ("WILLTOPICREQ", "gw"),
    "0x07": ("WILLTOPIC", "client"),
    "0x08": ("WILLMSGREQ", "gw"),
    "0x09": ("WILLMSG", "client"),
    "0x0a": ("REGISTER", "client"),
    "0x0b": ("REGACK", "gw"),
    "0x0c": ("PUBLISH", "either"),
    "0x0d": ("PUBACK", "either"),
    "0x0e": ("PUBCOMP", "either"),
    "0x0f": ("PUBREC", "either"),
    "0x10": ("PUBREL", "either"),
    "0x12": ("SUBSCRIBE", "client"),
    "0x13": ("SUBACK", "gw"),
    "0x14": ("UNSUBSCRIBE", "client"),
    "0x15": ("UNSUBACK", "gw"),
    "0x16": ("PINGREQ", "client"),
    "0x17": ("PINGRESP", "gw"),
    "0x18": ("DISCONNECT", "either"),
    "0x1a": ("WILLTOPICUPD", "client"),
    "0x1b": ("WILLTOPICRESP", "gw"),
    "0x1c": ("WILLMSGUPD", "client"),
    "0x1d": ("WILLMSGRESP", "gw"),
}


class MQTTSNPassiveListener(PySharkListenerBase):
    """Passive MQTT-SN traffic listener (PyShark-based).

    Monitors MQTT-SN sensor traffic to:
    - Identify gateways (ADVERTISE/GWINFO) and clients (CONNECT)
    - Map the topic namespace (REGISTER/PUBLISH topic ids and names)
    - Track subscriptions and QoS usage

    Data stored in device.mqttsn_passive_data:
        {
            "role": "gateway" | "client",
            "client_id": "sensor-01",
            "gateway_id": "1",
            "topics": ["temp/room1"],
            "protocol": "MQTT-SN/UDP",
        }
    """

    PROTOCOL_NAME = "mqttsn"
    DISPLAY_FILTER = "mqttsn"
    REQUIRED_LAYERS = ("mqttsn",)
    SERVER_PORTS = (1883,)
    # MQTT-SN has no auto-registered port in tshark; bind the default so the
    # dissector fires under the same capture the listener sees at runtime.
    OVERRIDE_PREFS = {"mqttsn.udp.port": "1883"}
    PROTOCOL_COLUMNS = ("msg", "client_id", "gw_id", "topic", "qos")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # ip -> aggregated info (role, client_id, topics, ...)
        self.nodes: Dict[str, Dict[str, Any]] = {}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        return [
            d.get("msg_name", "?"),
            d.get("client_id", "") or "-",
            d.get("gateway_id", "") or "-",
            d.get("topic", "") or d.get("topic_id", "") or "-",
            d.get("qos", "") or "-",
        ]

    def process_packet(self, packet) -> None:
        """Process an MQTT-SN packet."""
        if not hasattr(packet, "mqttsn"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        sn = packet.mqttsn
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)

        msg_type_raw = self.get_field(sn, "msg_type", None)
        if msg_type_raw is None:
            self.logger.debug(f"MQTT-SN: missing msg.type from {src_ip}")
            return
        msg_type = self._norm_hex(msg_type_raw)
        msg_name, originator = MQTTSN_MSG.get(msg_type, (f"UNKNOWN({msg_type})", "either"))

        client_id = str(self.get_field(sn, "client_id", "") or "")
        gateway_id = str(self.get_field(sn, "gw_id", "") or "")
        topic = str(self.get_field_any(sn, "topic", "topic_name_or_id", default="") or "")
        topic_id = str(self.get_field(sn, "topic_id", "") or "")
        pub_msg = str(self.get_field(sn, "pub_msg", "") or "")
        qos = str(self.get_field(sn, "qos", "") or "")
        radius = str(self.get_field(sn, "radius", "") or "")
        keep_alive = str(self.get_field(sn, "keep_alive", "") or "")

        # Direction from the message originator role (native, port-independent).
        if originator == "gw":
            is_response = True
        elif originator == "client":
            is_response = False
        else:
            d = self.resolve_direction(
                packet,
                native=None,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                flow_id=flow_id,
            )
            is_response = not d.is_request
        direction = "response" if is_response else "request"

        details: Dict[str, Any] = {
            "msg_type": msg_type,
            "msg_name": msg_name,
            "client_id": client_id,
            "gateway_id": gateway_id,
            "topic": topic,
            "topic_id": topic_id,
            "pub_msg": pub_msg,
            "qos": qos,
            "radius": radius,
            "keep_alive": keep_alive,
        }

        now = datetime.now().isoformat()
        summary = f"MQTT-SN {msg_name} {src_ip}"
        if client_id:
            summary += f" client={client_id}"
        if topic or topic_id:
            summary += f" topic={topic or topic_id}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"MQTT-SN {msg_name}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Track the sender's role/identity.
        sender_role = (
            "gateway" if originator == "gw" else ("client" if originator == "client" else "")
        )
        self._track_node(src_ip, sender_role, client_id, gateway_id, topic or topic_id)

        if is_valid_discovered_ip(src_ip) and sender_role:
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            self._ensure_device(
                f"mqttsn-{sender_role}:{src_ip}",
                src_ip,
                mac=src_mac or "",
                device_type=f"MQTT-SN {sender_role.title()}",
                manufacturer=vendor if vendor and vendor != "Unknown" else "",
                data_attr="mqttsn_passive_data",
                protocol_data=self._node_data(src_ip, sender_role),
            )

    # ------------------------------------------------------------------
    def _track_node(self, ip: str, role: str, client_id: str, gateway_id: str, topic: str) -> None:
        info = self.nodes.setdefault(
            ip,
            {"role": role, "client_id": "", "gateway_id": "", "topics": set()},
        )
        if role:
            info["role"] = role
        if client_id:
            info["client_id"] = client_id
        if gateway_id:
            info["gateway_id"] = gateway_id
        if topic:
            info["topics"].add(topic)

    def _node_data(self, ip: str, role: str) -> Dict[str, Any]:
        info = self.nodes.get(ip, {})
        return {
            "role": role,
            "client_id": info.get("client_id", ""),
            "gateway_id": info.get("gateway_id", ""),
            "topics": sorted(info.get("topics", set())),
            "protocol": "MQTT-SN/UDP",
        }

    @staticmethod
    def _norm_hex(raw: Any) -> str:
        """Normalise a msg-type value to lowercase 0xNN form."""
        s = str(raw).strip().lower()
        if s.startswith("0x"):
            return s
        try:
            return f"0x{int(s):02x}"
        except (ValueError, TypeError):
            return s

    def harvest(self) -> Dict[str, Any]:
        """Add gateway/topic inventory tables to the base alerts."""
        result = super().harvest() or {}
        tables = result.setdefault("tables", [])

        gateways = [(ip, i) for ip, i in self.nodes.items() if i.get("role") == "gateway"]
        if gateways:
            tables.append(
                {
                    "title": "MQTT-SN Gateways",
                    "headers": ["Gateway IP", "Gateway ID"],
                    "rows": [[ip, i.get("gateway_id", "-") or "-"] for ip, i in sorted(gateways)],
                }
            )

        topics: Set[str] = set()
        for i in self.nodes.values():
            topics |= i.get("topics", set())
        if topics:
            tables.append(
                {
                    "title": "MQTT-SN Topics",
                    "headers": ["Topic"],
                    "rows": [[t] for t in sorted(topics)],
                }
            )
        return result if (result.get("tables") or result.get("alerts")) else {}
