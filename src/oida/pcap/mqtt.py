"""
MQTT Passive Listener for credential extraction and operations tracking.

Passively captures MQTT traffic to extract:
- Usernames and passwords from CONNECT packets
- Client IDs and protocol version
- Topics from PUBLISH and SUBSCRIBE packets
- CONNACK return codes (auth success/failure)
- Message IDs for QoS tracking

MQTT CONNECT packets transmit credentials in cleartext unless TLS is used.

tshark fields extracted:
- mqtt.username: Username (T1)
- mqtt.passwd: Password (T1)
- mqtt.clientid: Client identifier (T1)
- mqtt.protoname: Protocol name string (T1)
- mqtt.ver: MQTT protocol version (T1)
- mqtt.msgid: Message ID for QoS tracking (T1)
- mqtt.username_len: Username length (T1)
- mqtt.msgtype: Message type code (T2)
- mqtt.topic: Topic string (T2)
- mqtt.conack.val: CONNACK return code (T2)
- mqtt.kalive: Keep-alive interval (T2)
- mqtt.qos: QoS level (T2)
- mqtt.conflag.cleansess: Clean session flag (T2)

References:
- MQTT v3.1.1 (OASIS Standard)
- MQTT v5.0 (OASIS Standard)
- Wireshark dissector: packet-mqtt.c
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase

# MQTT message type codes
MQTT_MSG_TYPES: Dict[str, str] = {
    "1": "CONNECT",
    "2": "CONNACK",
    "3": "PUBLISH",
    "4": "PUBACK",
    "5": "PUBREC",
    "6": "PUBREL",
    "7": "PUBCOMP",
    "8": "SUBSCRIBE",
    "9": "SUBACK",
    "10": "UNSUBSCRIBE",
    "11": "UNSUBACK",
    "12": "PINGREQ",
    "13": "PINGRESP",
    "14": "DISCONNECT",
    "15": "AUTH",
}

# MQTT version mapping
MQTT_VERSIONS: Dict[str, str] = {
    "3": "3.1",
    "4": "3.1.1",
    "5": "5.0",
}

# CONNACK return codes (v3.1.1)
CONNACK_CODES: Dict[str, str] = {
    "0": "Accepted",
    "1": "Refused: Unacceptable Protocol",
    "2": "Refused: Identifier Rejected",
    "3": "Refused: Server Unavailable",
    "4": "Refused: Bad Credentials",
    "5": "Refused: Not Authorized",
}


@dataclass
class MQTTCredential:
    """Extracted MQTT credential."""

    username: str
    password: str = ""
    client_id: str = ""
    credential_type: str = "plaintext"
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    timestamp: str = ""

    @property
    def auth_method(self) -> str:
        """Scanner credential loop compatibility."""
        return "MQTT-CONNECT"


class MQTTPassiveListener(PySharkListenerBase):
    """Passive MQTT traffic listener for credential and operations extraction.

    Captures all MQTT message types to extract credentials, topic activity,
    connection metadata, and protocol version information.
    """

    PROTOCOL_NAME = "mqtt"
    DISPLAY_FILTER = "mqtt"
    REQUIRED_LAYERS = ("mqtt",)

    PROTOCOL_COLUMNS = ("type", "client_id", "topic", "msg_id", "qos", "details")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[MQTTCredential] = []
        self._seen_creds: Set[Tuple[str, str, str, str, str]] = set()
        self._alerts: List[Dict[str, str]] = []

    def process_packet(self, packet) -> None:
        """Process MQTT packet and extract credentials, topics, and metadata."""
        if not hasattr(packet, "mqtt"):
            return

        mqtt = packet.mqtt
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        stream_id = self.get_stream_id(packet)

        # -- T1 field: mqtt.msgtype --
        msgtype_raw = str(self.get_field(mqtt, "msgtype", "") or "")
        if not msgtype_raw:
            msgtype_raw = "?"
            self.logger.debug(f"Missing msgtype field in packet from {src_ip} -> {dst_ip}")
        msg_type_name = MQTT_MSG_TYPES.get(msgtype_raw, f"UNKNOWN({msgtype_raw})")

        # -- T1 field: mqtt.ver --
        ver_raw = str(self.get_field(mqtt, "ver", "") or "")
        ver_display = MQTT_VERSIONS.get(ver_raw, ver_raw) if ver_raw else ""

        # -- T1 field: mqtt.protoname --
        protoname = str(self.get_field(mqtt, "protoname", "") or "")

        # -- T1 field: mqtt.msgid --
        msgid = str(self.get_field(mqtt, "msgid", "") or "")

        # -- T1 field: mqtt.username_len --
        username_len = str(self.get_field(mqtt, "username_len", "") or "")

        # -- T1 field: mqtt.username --
        username = str(self.get_field(mqtt, "username", "") or "").strip()

        # -- T1 field: mqtt.passwd --
        password = str(self.get_field(mqtt, "passwd", "") or "").strip()

        # -- T1 field: mqtt.clientid --
        client_id = str(self.get_field(mqtt, "clientid", "") or "").strip()

        # -- T2 fields --
        topic = str(self.get_field(mqtt, "topic", "") or "")
        qos = str(self.get_field(mqtt, "qos", "") or "")
        kalive = str(self.get_field(mqtt, "kalive", "") or "")
        conack_val = str(self.get_field(mqtt, "conack_val", "") or "")
        clean_session = str(self.get_field(mqtt, "conflag_cleansess", "") or "")

        now = self._get_timestamp()

        # Dispatch by message type
        if msgtype_raw == "1":
            self._handle_connect(
                mqtt,
                src_ip,
                dst_ip,
                dst_port,
                flow_id,
                now,
                username,
                password,
                client_id,
                ver_raw,
                ver_display,
                protoname,
                kalive,
                clean_session,
                username_len,
                src_port=src_port,
                stream_id=stream_id,
            )
        elif msgtype_raw == "2":
            self._handle_connack(
                mqtt,
                src_ip,
                dst_ip,
                flow_id,
                now,
                conack_val,
                client_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif msgtype_raw == "3":
            self._handle_publish(
                mqtt,
                src_ip,
                dst_ip,
                flow_id,
                now,
                topic,
                msgid,
                qos,
                client_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif msgtype_raw == "8":
            self._handle_subscribe(
                mqtt,
                src_ip,
                dst_ip,
                flow_id,
                now,
                topic,
                msgid,
                qos,
                client_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif msgtype_raw == "9":
            self._handle_suback(
                mqtt,
                src_ip,
                dst_ip,
                flow_id,
                now,
                msgid,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif msgtype_raw == "14":
            self._handle_disconnect(
                src_ip,
                dst_ip,
                flow_id,
                now,
                client_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif msgtype_raw in ("12", "13"):
            # PINGREQ / PINGRESP -- record as interaction for flow tracking
            direction = "request" if msgtype_raw == "12" else "response"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                f"MQTT {msg_type_name}",
                {"msg_type": msg_type_name},
                f"{msg_type_name}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        else:
            # Other message types (PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK, AUTH)
            direction = "response" if msgtype_raw in ("4", "5", "7", "11") else "request"
            details: Dict[str, Any] = {"msg_type": msg_type_name}
            if msgid:
                details["msgid"] = msgid
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                f"MQTT {msg_type_name}",
                details,
                f"{msg_type_name}" + (f" msgid={msgid}" if msgid else ""),
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

    def _handle_connect(
        self,
        mqtt,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        flow_id: str,
        now: str,
        username: str,
        password: str,
        client_id: str,
        ver_raw: str,
        ver_display: str,
        protoname: str,
        kalive: str,
        clean_session: str,
        username_len: str,
        *,
        src_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle MQTT CONNECT message."""
        details: Dict[str, Any] = {
            "msg_type": "CONNECT",
            "username": username,
            "client_id": client_id,
            "protoname": protoname,
            "ver": ver_raw,
            "ver_display": ver_display,
            "kalive": kalive,
            "clean_session": clean_session,
            "username_len": username_len,
        }

        parts = [f"user={username}"] if username else []
        parts.append(f"client={client_id}")
        if ver_display:
            parts.append(f"v{ver_display}")
        if protoname:
            parts.append(f"proto={protoname}")

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "MQTT CONNECT",
            details,
            f"CONNECT {' '.join(parts)}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Device/interaction tracking happens for every CONNECT, credential
        # or not -- a client_id-only CONNECT is still useful telemetry.
        cred_key = (username, password, client_id, src_ip, dst_ip)
        if cred_key not in self._seen_creds:
            self._seen_creds.add(cred_key)
            self._update_devices(
                src_ip,
                dst_ip,
                client_id,
                ver_display=ver_display,
                protoname=protoname,
                kalive=kalive,
            )

            # Credential extraction: only record when actual credential
            # material (username or password) is present. client_id alone
            # is near-universal and is not a secret -- recording it as a
            # "username_only" credential pollutes the credential table.
            if username or password:
                cred = MQTTCredential(
                    username=username,
                    password=password,
                    client_id=client_id,
                    credential_type="plaintext" if password else "username_only",
                    server_ip=dst_ip,
                    server_port=dst_port,
                    client_ip=src_ip,
                    timestamp=now,
                )
                self.credentials.append(cred)

                if password:
                    self.logger.info(
                        f"MQTT: {username}:{password} client={client_id} @ {dst_ip}:{dst_port}"
                    )
                else:
                    self.logger.info(
                        f"MQTT: username={username} client={client_id} @ {dst_ip}:{dst_port}"
                    )

    def _handle_connack(
        self,
        mqtt,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        now: str,
        conack_val: str,
        client_id: str,
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle MQTT CONNACK message."""
        code_desc = CONNACK_CODES.get(conack_val, f"Unknown({conack_val})") if conack_val else "?"
        if not conack_val:
            conack_val = "?"
            self.logger.debug(f"Missing conack.val field in CONNACK from {src_ip} -> {dst_ip}")

        details: Dict[str, Any] = {
            "msg_type": "CONNACK",
            "conack_val": conack_val,
            "conack_desc": code_desc,
        }

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "MQTT CONNACK",
            details,
            f"CONNACK rc={conack_val} ({code_desc})",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Alert on auth failures
        if conack_val not in ("0", "?"):
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "auth_failure",
                    "message": f"MQTT CONNACK: {code_desc} from {src_ip} -> {dst_ip}",
                }
            )

    def _handle_publish(
        self,
        mqtt,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        now: str,
        topic: str,
        msgid: str,
        qos: str,
        client_id: str,
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle MQTT PUBLISH message."""
        if not topic:
            topic = "?"
            self.logger.debug(f"Missing topic field in PUBLISH from {src_ip} -> {dst_ip}")

        details: Dict[str, Any] = {
            "msg_type": "PUBLISH",
            "topic": topic,
            "qos": qos,
        }
        if msgid:
            details["msgid"] = msgid

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "MQTT PUBLISH",
            details,
            f"PUBLISH topic={topic}" + (f" qos={qos}" if qos else ""),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _handle_subscribe(
        self,
        mqtt,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        now: str,
        topic: str,
        msgid: str,
        qos: str,
        client_id: str,
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle MQTT SUBSCRIBE message."""
        sub_qos = str(self.get_field(mqtt, "sub_qos", "") or "") or qos
        if not topic:
            topic = "?"
            self.logger.debug(f"Missing topic field in SUBSCRIBE from {src_ip} -> {dst_ip}")

        details: Dict[str, Any] = {
            "msg_type": "SUBSCRIBE",
            "topic": topic,
            "qos": sub_qos,
        }
        if msgid:
            details["msgid"] = msgid

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "MQTT SUBSCRIBE",
            details,
            f"SUBSCRIBE topic={topic}" + (f" qos={sub_qos}" if sub_qos else ""),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _handle_suback(
        self,
        mqtt,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        now: str,
        msgid: str,
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle MQTT SUBACK message."""
        suback_qos = str(self.get_field(mqtt, "suback_qos", "") or "")

        details: Dict[str, Any] = {"msg_type": "SUBACK"}
        if msgid:
            details["msgid"] = msgid
        if suback_qos:
            details["suback_qos"] = suback_qos

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "MQTT SUBACK",
            details,
            "SUBACK" + (f" msgid={msgid}" if msgid else ""),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Alert on subscription rejection (QoS 0x80 / 128)
        if suback_qos and ("128" in suback_qos or "0x80" in suback_qos.lower()):
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "subscribe_rejected",
                    "message": f"MQTT SUBACK: subscription rejected (qos={suback_qos}) from {src_ip}",
                }
            )

    def _handle_disconnect(
        self,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        now: str,
        client_id: str,
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Handle MQTT DISCONNECT message."""
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "MQTT DISCONNECT",
            {"msg_type": "DISCONNECT"},
            "DISCONNECT",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _update_devices(
        self,
        client_ip: str,
        server_ip: str,
        client_id: str = "",
        ver_display: str = "",
        protoname: str = "",
        kalive: str = "",
    ) -> None:
        """Update device entries with protocol version info."""
        proto_str = "MQTT/TCP"
        if ver_display:
            proto_str = f"MQTT v{ver_display}/TCP"

        server_key = f"mqtt-server:{server_ip}"
        device, is_new = self._ensure_device(
            server_key,
            server_ip,
            name=f"MQTT Broker ({server_ip})",
            device_type="MQTT Broker",
        )
        broker_data = getattr(device, "mqtt_passive_data", None)
        if broker_data is None or is_new:
            device.mqtt_passive_data = {
                "role": "broker",
                "protocol": proto_str,
            }
        else:
            # Update protocol string if version was discovered later
            if ver_display and "v" not in broker_data.get("protocol", ""):
                broker_data["protocol"] = proto_str

        client_key = f"mqtt-client:{client_ip}"
        device, is_new = self._ensure_device(
            client_key,
            client_ip,
            name=f"MQTT Client ({client_id or client_ip})",
            device_type="MQTT Client",
        )
        client_data = getattr(device, "mqtt_passive_data", None)
        if client_data is None or is_new:
            device.mqtt_passive_data = {
                "role": "client",
                "client_id": client_id,
                "protocol": proto_str,
                "mqtt_version": ver_display,
                "protoname": protoname,
                "kalive": kalive,
            }
        else:
            # Enrich on subsequent connects
            if client_id and not client_data.get("client_id"):
                client_data["client_id"] = client_id
            if ver_display and not client_data.get("mqtt_version"):
                client_data["mqtt_version"] = ver_display
                client_data["protocol"] = proto_str

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format an interaction into a row matching PROTOCOL_COLUMNS."""
        d = ix.details
        msg_type = d.get("msg_type", "?")
        client_id = d.get("client_id", "")
        topic = d.get("topic", "")
        msgid = d.get("msgid", "")
        qos = d.get("qos", "")

        # Build details string from remaining interesting fields
        detail_parts: List[str] = []
        if d.get("username"):
            detail_parts.append(f"user={d['username']}")
        if d.get("ver_display"):
            detail_parts.append(f"v{d['ver_display']}")
        if d.get("protoname"):
            detail_parts.append(d["protoname"])
        if d.get("kalive"):
            detail_parts.append(f"ka={d['kalive']}s")
        if d.get("conack_val") is not None and d.get("conack_val") != "":
            desc = d.get("conack_desc", "")
            detail_parts.append(f"rc={d['conack_val']}" + (f" ({desc})" if desc else ""))
        if d.get("username_len"):
            detail_parts.append(f"ulen={d['username_len']}")
        if d.get("suback_qos"):
            detail_parts.append(f"suback_qos={d['suback_qos']}")

        return [
            msg_type,
            client_id,
            topic,
            msgid,
            qos,
            " ".join(detail_parts),
        ]

    def harvest(self) -> Dict[str, Any]:
        """Extend base harvest with MQTT-specific auth failure alerts."""
        result = super().harvest()
        if not result and not self._alerts:
            return {}
        if not result:
            result = {"tables": [], "alerts": []}
        if self._alerts:
            result.setdefault("alerts", []).extend(self._alerts)
        return result

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials using canonical key names."""
        return [
            {
                "protocol": "MQTT",
                "credential_type": cred.credential_type,
                "auth_method": "MQTT-CONNECT",
                "username": cred.username,
                "password": cred.password,
                "client_id": cred.client_id,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]
