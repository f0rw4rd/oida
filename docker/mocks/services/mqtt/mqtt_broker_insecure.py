#!/usr/bin/env python3
"""
Mock MQTT Broker - INSECURE Configuration
For testing OIDA MQTT scanner security detection

This broker intentionally has security vulnerabilities:
- Anonymous authentication allowed
- No TLS encryption
- Wildcard subscriptions allowed
- $SYS topics exposed
- No ACLs

Uses: paho-mqtt + asyncio
"""

import asyncio
import logging
import json
import time
import struct
from dataclasses import dataclass, field
from typing import Dict, Set, Optional
from enum import IntEnum

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger("mqtt-broker-insecure")


class MQTTPacketType(IntEnum):
    CONNECT = 1
    CONNACK = 2
    PUBLISH = 3
    PUBACK = 4
    PUBREC = 5
    PUBREL = 6
    PUBCOMP = 7
    SUBSCRIBE = 8
    SUBACK = 9
    UNSUBSCRIBE = 10
    UNSUBACK = 11
    PINGREQ = 12
    PINGRESP = 13
    DISCONNECT = 14


@dataclass
class MQTTClient:
    """Represents a connected MQTT client"""

    client_id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    subscriptions: Set[str] = field(default_factory=set)
    username: Optional[str] = None
    clean_session: bool = True
    keepalive: int = 60
    connected_at: float = field(default_factory=time.time)
    messages_received: int = 0
    messages_sent: int = 0


class MQTTBrokerInsecure:
    """
    Insecure MQTT Broker for security testing

    Vulnerabilities:
    - CVE-2017-7650 style: No authentication required
    - Wildcard subscriptions allowed (# and +)
    - $SYS topics fully readable
    - No topic ACLs
    - Plaintext only (no TLS)
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 1883):
        self.host = host
        self.port = port
        self.clients: Dict[str, MQTTClient] = {}
        self.retained_messages: Dict[str, tuple] = {}  # topic -> (payload, qos)
        self.topic_subscribers: Dict[str, Set[str]] = {}  # topic -> client_ids

        # Broker stats for $SYS topics
        self.stats = {
            "broker/version": "MockMQTT 1.0.0 (INSECURE)",
            "broker/uptime": 0,
            "broker/clients/connected": 0,
            "broker/clients/total": 0,
            "broker/messages/received": 0,
            "broker/messages/sent": 0,
            "broker/messages/stored": 0,
            "broker/subscriptions/count": 0,
            "broker/load/messages/received/1min": 0,
        }
        self.start_time = time.time()

        # ICS-style topics with sample data
        self.ics_topics = {
            "factory/plc1/temperature": "23.5",
            "factory/plc1/pressure": "101.3",
            "factory/plc1/status": json.dumps({"running": True, "mode": "auto"}),
            "factory/plc2/motor/speed": "1500",
            "factory/plc2/motor/current": "4.2",
            "scada/alarms": json.dumps({"level": "normal", "count": 0}),
            "scada/setpoints": json.dumps({"temp_max": 80, "pressure_max": 200}),
            "sensors/env/humidity": "45",
            "sensors/env/temperature": "22.1",
            "control/valve1/position": "75",
            "control/valve2/position": "50",
        }

    async def start(self):
        """Start the MQTT broker"""
        server = await asyncio.start_server(self._handle_client, self.host, self.port)

        log.info(f"INSECURE MQTT Broker started on {self.host}:{self.port}")
        log.warning("WARNING: This broker has NO authentication - for testing only!")

        # Start background tasks
        asyncio.create_task(self._update_sys_topics())
        asyncio.create_task(self._simulate_ics_data())

        async with server:
            await server.serve_forever()

    async def _update_sys_topics(self):
        """Update $SYS topics periodically"""
        while True:
            self.stats["broker/uptime"] = int(time.time() - self.start_time)
            self.stats["broker/clients/connected"] = len(self.clients)
            self.stats["broker/messages/stored"] = len(self.retained_messages)
            self.stats["broker/subscriptions/count"] = sum(
                len(subs) for subs in self.topic_subscribers.values()
            )
            await asyncio.sleep(5)

    async def _simulate_ics_data(self):
        """Simulate ICS data updates"""
        import random

        while True:
            # Update temperature
            temp = 22 + random.uniform(-2, 2)
            await self._publish_internal("factory/plc1/temperature", f"{temp:.1f}".encode())

            # Update pressure
            pressure = 101 + random.uniform(-1, 1)
            await self._publish_internal("factory/plc1/pressure", f"{pressure:.1f}".encode())

            # Update motor speed
            speed = 1500 + random.randint(-50, 50)
            await self._publish_internal("factory/plc2/motor/speed", str(speed).encode())

            await asyncio.sleep(2)

    async def _publish_internal(
        self, topic: str, payload: bytes, qos: int = 0, retain: bool = False
    ):
        """Internal publish to subscribers"""
        if retain:
            self.retained_messages[topic] = (payload, qos)

        # Find matching subscribers
        for pattern, client_ids in self.topic_subscribers.items():
            if self._topic_matches(pattern, topic):
                for client_id in client_ids:
                    if client_id in self.clients:
                        client = self.clients[client_id]
                        await self._send_publish(client, topic, payload, qos)

    def _topic_matches(self, pattern: str, topic: str) -> bool:
        """Check if topic matches subscription pattern (supports + and #)"""
        if pattern == "#":
            return True
        if pattern == topic:
            return True

        pattern_parts = pattern.split("/")
        topic_parts = topic.split("/")

        for i, p in enumerate(pattern_parts):
            if p == "#":
                return True
            if i >= len(topic_parts):
                return False
            if p == "+":
                continue
            if p != topic_parts[i]:
                return False

        return len(pattern_parts) == len(topic_parts)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a new client connection"""
        addr = writer.get_extra_info("peername")
        log.info(f"New connection from {addr}")

        client = None
        try:
            while True:
                # Read fixed header
                header = await reader.read(1)
                if not header:
                    break

                packet_type = (header[0] & 0xF0) >> 4
                flags = header[0] & 0x0F

                # Read remaining length (variable length encoding)
                remaining_length = await self._read_remaining_length(reader)

                # Read payload
                payload = (
                    await reader.readexactly(remaining_length) if remaining_length > 0 else b""
                )

                # Handle packet
                if packet_type == MQTTPacketType.CONNECT:
                    client = await self._handle_connect(reader, writer, payload)
                    if client:
                        self.stats["broker/clients/total"] += 1

                elif packet_type == MQTTPacketType.PUBLISH:
                    if client:
                        await self._handle_publish(client, flags, payload)

                elif packet_type == MQTTPacketType.SUBSCRIBE:
                    if client:
                        await self._handle_subscribe(client, payload)

                elif packet_type == MQTTPacketType.UNSUBSCRIBE:
                    if client:
                        await self._handle_unsubscribe(client, payload)

                elif packet_type == MQTTPacketType.PINGREQ:
                    await self._send_pingresp(writer)

                elif packet_type == MQTTPacketType.DISCONNECT:
                    log.info(f"Client {client.client_id if client else 'unknown'} disconnected")
                    break

        except asyncio.IncompleteReadError:
            log.debug(f"Client {addr} disconnected (incomplete read)")
        except Exception as e:
            log.error(f"Error handling client {addr}: {e}")
        finally:
            if client and client.client_id in self.clients:
                del self.clients[client.client_id]
                # Remove from subscriptions
                for topic_subs in self.topic_subscribers.values():
                    topic_subs.discard(client.client_id)
            writer.close()
            await writer.wait_closed()

    async def _read_remaining_length(self, reader: asyncio.StreamReader) -> int:
        """Read MQTT variable length integer"""
        multiplier = 1
        value = 0
        while True:
            byte = await reader.readexactly(1)
            value += (byte[0] & 0x7F) * multiplier
            if (byte[0] & 0x80) == 0:
                break
            multiplier *= 128
            if multiplier > 128 * 128 * 128:
                raise ValueError("Malformed remaining length")
        return value

    async def _handle_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, payload: bytes
    ) -> Optional[MQTTClient]:
        """Handle CONNECT packet - ALWAYS ACCEPTS (insecure!)"""
        try:
            offset = 0

            # Protocol name
            proto_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2
            protocol_name = payload[offset : offset + proto_len].decode()
            offset += proto_len

            # Protocol level
            protocol_level = payload[offset]
            offset += 1

            # Connect flags
            connect_flags = payload[offset]
            offset += 1

            clean_session = bool(connect_flags & 0x02)
            has_will = bool(connect_flags & 0x04)
            will_qos = (connect_flags & 0x18) >> 3
            will_retain = bool(connect_flags & 0x20)
            has_password = bool(connect_flags & 0x40)
            has_username = bool(connect_flags & 0x80)

            # Keep alive
            keepalive = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2

            # Client ID
            client_id_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2
            client_id = (
                payload[offset : offset + client_id_len].decode()
                if client_id_len > 0
                else f"auto_{id(writer)}"
            )
            offset += client_id_len

            # Skip will topic/message if present
            if has_will:
                will_topic_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2 + will_topic_len
                will_msg_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2 + will_msg_len

            # Username (optional)
            username = None
            if has_username:
                username_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2
                username = payload[offset : offset + username_len].decode()
                offset += username_len

            # Password (optional) - WE DON'T VALIDATE IT!
            password = None
            if has_password:
                password_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2
                password = payload[offset : offset + password_len].decode()
                offset += password_len

            # INSECURE: Always accept connection!
            log.warning(
                f"ACCEPTING connection from client '{client_id}' "
                f"(username={username}, has_password={has_password}) - NO VALIDATION!"
            )

            client = MQTTClient(
                client_id=client_id,
                reader=reader,
                writer=writer,
                username=username,
                clean_session=clean_session,
                keepalive=keepalive,
            )

            self.clients[client_id] = client

            # Send CONNACK (return code 0 = accepted)
            connack = bytes(
                [
                    0x20,  # CONNACK packet type
                    0x02,  # Remaining length
                    0x00,  # Session present flag
                    0x00,  # Return code: Connection Accepted
                ]
            )
            writer.write(connack)
            await writer.drain()

            self.stats["broker/messages/received"] += 1
            return client

        except Exception as e:
            log.error(f"Error parsing CONNECT: {e}")
            # Send CONNACK with error
            connack = bytes([0x20, 0x02, 0x00, 0x05])  # Not authorized (but we're insecure!)
            writer.write(connack)
            await writer.drain()
            return None

    async def _handle_publish(self, client: MQTTClient, flags: int, payload: bytes):
        """Handle PUBLISH packet"""
        try:
            qos = (flags & 0x06) >> 1
            retain = bool(flags & 0x01)

            offset = 0

            # Topic name
            topic_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2
            topic = payload[offset : offset + topic_len].decode()
            offset += topic_len

            # Packet ID (only for QoS > 0)
            packet_id = None
            if qos > 0:
                packet_id = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2

            # Message payload
            message = payload[offset:]

            log.info(
                f"PUBLISH from {client.client_id}: topic='{topic}', qos={qos}, "
                f"retain={retain}, payload={message[:50]}..."
            )

            client.messages_received += 1
            self.stats["broker/messages/received"] += 1

            # Store retained message
            if retain:
                self.retained_messages[topic] = (message, qos)

            # Forward to subscribers
            await self._publish_internal(topic, message, qos, retain)

            # Send acknowledgment for QoS > 0
            if qos == 1 and packet_id:
                puback = bytes([0x40, 0x02]) + struct.pack("!H", packet_id)
                client.writer.write(puback)
                await client.writer.drain()

        except Exception as e:
            log.error(f"Error handling PUBLISH: {e}")

    async def _handle_subscribe(self, client: MQTTClient, payload: bytes):
        """Handle SUBSCRIBE packet - ALLOWS ALL TOPICS (insecure!)"""
        try:
            offset = 0

            # Packet ID
            packet_id = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2

            granted_qos = []

            while offset < len(payload):
                # Topic filter
                topic_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2
                topic_filter = payload[offset : offset + topic_len].decode()
                offset += topic_len

                # Requested QoS
                requested_qos = payload[offset]
                offset += 1

                # INSECURE: Allow ALL subscriptions including $SYS and wildcards!
                log.warning(
                    f"ALLOWING subscription from {client.client_id} to '{topic_filter}' - NO ACL CHECK!"
                )

                client.subscriptions.add(topic_filter)

                if topic_filter not in self.topic_subscribers:
                    self.topic_subscribers[topic_filter] = set()
                self.topic_subscribers[topic_filter].add(client.client_id)

                granted_qos.append(min(requested_qos, 2))

                # Send retained messages for this subscription
                for topic, (msg, qos) in self.retained_messages.items():
                    if self._topic_matches(topic_filter, topic):
                        await self._send_publish(client, topic, msg, min(qos, requested_qos))

                # If subscribing to $SYS, send broker stats
                if topic_filter.startswith("$SYS") or topic_filter == "#":
                    for stat_name, stat_value in self.stats.items():
                        sys_topic = f"$SYS/{stat_name}"
                        if self._topic_matches(topic_filter, sys_topic):
                            await self._send_publish(client, sys_topic, str(stat_value).encode(), 0)

            # Send SUBACK
            suback = (
                bytes([0x90, len(granted_qos) + 2])
                + struct.pack("!H", packet_id)
                + bytes(granted_qos)
            )
            client.writer.write(suback)
            await client.writer.drain()

        except Exception as e:
            log.error(f"Error handling SUBSCRIBE: {e}")

    async def _handle_unsubscribe(self, client: MQTTClient, payload: bytes):
        """Handle UNSUBSCRIBE packet"""
        try:
            offset = 0

            # Packet ID
            packet_id = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2

            while offset < len(payload):
                topic_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2
                topic_filter = payload[offset : offset + topic_len].decode()
                offset += topic_len

                client.subscriptions.discard(topic_filter)
                if topic_filter in self.topic_subscribers:
                    self.topic_subscribers[topic_filter].discard(client.client_id)

            # Send UNSUBACK
            unsuback = bytes([0xB0, 0x02]) + struct.pack("!H", packet_id)
            client.writer.write(unsuback)
            await client.writer.drain()

        except Exception as e:
            log.error(f"Error handling UNSUBSCRIBE: {e}")

    async def _send_publish(self, client: MQTTClient, topic: str, payload: bytes, qos: int = 0):
        """Send PUBLISH to client"""
        try:
            topic_bytes = topic.encode()

            # Build packet
            remaining = 2 + len(topic_bytes) + len(payload)
            if qos > 0:
                remaining += 2  # Packet ID

            header = bytes([(MQTTPacketType.PUBLISH << 4) | (qos << 1)])

            # Encode remaining length
            remaining_bytes = self._encode_remaining_length(remaining)

            packet = header + remaining_bytes
            packet += struct.pack("!H", len(topic_bytes)) + topic_bytes

            if qos > 0:
                packet += struct.pack("!H", 1)  # Simple packet ID

            packet += payload

            client.writer.write(packet)
            await client.writer.drain()

            client.messages_sent += 1
            self.stats["broker/messages/sent"] += 1

        except Exception as e:
            log.error(f"Error sending PUBLISH to {client.client_id}: {e}")

    def _encode_remaining_length(self, length: int) -> bytes:
        """Encode remaining length as variable byte integer"""
        result = bytearray()
        while True:
            byte = length % 128
            length //= 128
            if length > 0:
                byte |= 0x80
            result.append(byte)
            if length == 0:
                break
        return bytes(result)

    async def _send_pingresp(self, writer: asyncio.StreamWriter):
        """Send PINGRESP"""
        writer.write(bytes([0xD0, 0x00]))
        await writer.drain()


async def main():
    """Start the insecure MQTT broker"""
    broker = MQTTBrokerInsecure(host="0.0.0.0", port=1883)
    await broker.start()


if __name__ == "__main__":
    asyncio.run(main())
