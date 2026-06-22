#!/usr/bin/env python3
"""
Mock MQTT Broker - WITH Authentication
For testing OIDA MQTT scanner credential testing

Security features:
- Username/password authentication required
- Weak default credentials for testing brute-force
- ACLs on some topics
- No TLS (for testing plaintext credential interception)

Default users:
- admin:admin (full access)
- user:password (limited access)
- operator:operator123 (read-only)
- guest:guest (very limited)
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
log = logging.getLogger("mqtt-broker-auth")


class MQTTPacketType(IntEnum):
    CONNECT = 1
    CONNACK = 2
    PUBLISH = 3
    PUBACK = 4
    SUBSCRIBE = 8
    SUBACK = 9
    UNSUBSCRIBE = 10
    UNSUBACK = 11
    PINGREQ = 12
    PINGRESP = 13
    DISCONNECT = 14


# Weak credentials for testing - intentionally insecure passwords
USERS = {
    "admin": {"password": "admin", "acl": "*"},
    "user": {"password": "password", "acl": "user/#"},
    "operator": {"password": "operator123", "acl": "factory/#,sensors/#"},
    "guest": {"password": "guest", "acl": "public/#"},
    "test": {"password": "test", "acl": "test/#"},
    "mqtt": {"password": "mqtt", "acl": "mqtt/#"},
    "ics": {"password": "ics123", "acl": "factory/#,scada/#"},
    "plc": {"password": "plc2024", "acl": "plc/#"},
}


@dataclass
class MQTTClient:
    client_id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    subscriptions: Set[str] = field(default_factory=set)
    username: Optional[str] = None
    acl: str = ""
    clean_session: bool = True
    keepalive: int = 60
    connected_at: float = field(default_factory=time.time)
    auth_failures: int = 0


class MQTTBrokerAuth:
    """
    MQTT Broker with Authentication

    For testing:
    - Credential brute-forcing
    - Weak password detection
    - ACL bypass attempts
    - Plaintext credential interception
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 1884):
        self.host = host
        self.port = port
        self.clients: Dict[str, MQTTClient] = {}
        self.retained_messages: Dict[str, tuple] = {}
        self.topic_subscribers: Dict[str, Set[str]] = {}
        self.failed_auth_attempts: Dict[str, int] = {}  # IP -> count

        self.stats = {
            "broker/version": "MockMQTT-Auth 1.0.0",
            "broker/uptime": 0,
            "broker/clients/connected": 0,
            "broker/auth/failures": 0,
            "broker/auth/successes": 0,
        }
        self.start_time = time.time()

        # Pre-populate some topics
        self.ics_topics = {
            "factory/plc1/status": json.dumps({"online": True}),
            "factory/plc2/status": json.dumps({"online": True}),
            "scada/alarms": json.dumps({"count": 0}),
            "public/info": "Welcome to MQTT broker",
            "user/data": "User private data",
        }

    async def start(self):
        server = await asyncio.start_server(self._handle_client, self.host, self.port)

        log.info(f"MQTT Broker (AUTH REQUIRED) started on {self.host}:{self.port}")
        log.info(f"Available users: {list(USERS.keys())}")

        asyncio.create_task(self._update_stats())
        asyncio.create_task(self._simulate_data())

        async with server:
            await server.serve_forever()

    async def _update_stats(self):
        while True:
            self.stats["broker/uptime"] = int(time.time() - self.start_time)
            self.stats["broker/clients/connected"] = len(self.clients)
            await asyncio.sleep(5)

    async def _simulate_data(self):
        import random

        while True:
            temp = 20 + random.uniform(-5, 5)
            await self._publish_internal("factory/plc1/temperature", f"{temp:.1f}".encode())
            await asyncio.sleep(3)

    async def _publish_internal(
        self, topic: str, payload: bytes, qos: int = 0, retain: bool = False
    ):
        if retain:
            self.retained_messages[topic] = (payload, qos)

        for pattern, client_ids in self.topic_subscribers.items():
            if self._topic_matches(pattern, topic):
                for client_id in list(client_ids):
                    if client_id in self.clients:
                        client = self.clients[client_id]
                        if self._check_acl(client, topic, "subscribe"):
                            await self._send_publish(client, topic, payload, qos)

    def _topic_matches(self, pattern: str, topic: str) -> bool:
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

    def _check_acl(self, client: MQTTClient, topic: str, action: str) -> bool:
        """Check if client has access to topic"""
        if client.acl == "*":
            return True

        # Parse ACL patterns
        acl_patterns = client.acl.split(",")
        for pattern in acl_patterns:
            if self._topic_matches(pattern.strip(), topic):
                return True

        # Block $SYS for non-admin
        if topic.startswith("$SYS") and client.acl != "*":
            return False

        return False

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        log.info(f"New connection from {addr}")

        client = None
        try:
            while True:
                header = await reader.read(1)
                if not header:
                    break

                packet_type = (header[0] & 0xF0) >> 4
                remaining_length = await self._read_remaining_length(reader)
                payload = (
                    await reader.readexactly(remaining_length) if remaining_length > 0 else b""
                )

                if packet_type == MQTTPacketType.CONNECT:
                    client = await self._handle_connect(reader, writer, payload, addr)

                elif packet_type == MQTTPacketType.PUBLISH:
                    if client:
                        await self._handle_publish(client, header[0] & 0x0F, payload)

                elif packet_type == MQTTPacketType.SUBSCRIBE:
                    if client:
                        await self._handle_subscribe(client, payload)

                elif packet_type == MQTTPacketType.UNSUBSCRIBE:
                    if client:
                        await self._handle_unsubscribe(client, payload)

                elif packet_type == MQTTPacketType.PINGREQ:
                    await self._send_pingresp(writer)

                elif packet_type == MQTTPacketType.DISCONNECT:
                    break

        except Exception as e:
            log.debug(f"Client {addr} error: {e}")
        finally:
            if client and client.client_id in self.clients:
                del self.clients[client.client_id]
                for topic_subs in self.topic_subscribers.values():
                    topic_subs.discard(client.client_id)
            writer.close()
            await writer.wait_closed()

    async def _read_remaining_length(self, reader: asyncio.StreamReader) -> int:
        multiplier = 1
        value = 0
        while True:
            byte = await reader.readexactly(1)
            value += (byte[0] & 0x7F) * multiplier
            if (byte[0] & 0x80) == 0:
                break
            multiplier *= 128
        return value

    async def _handle_connect(self, reader, writer, payload: bytes, addr) -> Optional[MQTTClient]:
        """Handle CONNECT with authentication check"""
        try:
            offset = 0

            # Protocol name
            proto_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2 + proto_len

            # Protocol level
            offset += 1

            # Connect flags
            connect_flags = payload[offset]
            offset += 1

            has_password = bool(connect_flags & 0x40)
            has_username = bool(connect_flags & 0x80)

            # Keep alive
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

            # Skip will
            if connect_flags & 0x04:
                will_topic_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2 + will_topic_len
                will_msg_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2 + will_msg_len

            # Get credentials
            username = None
            password = None

            if has_username:
                username_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2
                username = payload[offset : offset + username_len].decode()
                offset += username_len

            if has_password:
                password_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2
                password = payload[offset : offset + password_len].decode()
                offset += password_len

            # Authentication check
            if not has_username or not has_password:
                log.warning(f"Auth FAILED for {client_id} from {addr}: No credentials provided")
                self.stats["broker/auth/failures"] += 1
                connack = bytes([0x20, 0x02, 0x00, 0x05])  # Not authorized
                writer.write(connack)
                await writer.drain()
                return None

            if username not in USERS or USERS[username]["password"] != password:
                log.warning(
                    f"Auth FAILED for {client_id} from {addr}: Invalid credentials (user={username})"
                )
                self.stats["broker/auth/failures"] += 1

                # Track failed attempts per IP
                ip = addr[0]
                self.failed_auth_attempts[ip] = self.failed_auth_attempts.get(ip, 0) + 1

                connack = bytes([0x20, 0x02, 0x00, 0x05])  # Not authorized
                writer.write(connack)
                await writer.drain()
                return None

            # Success
            log.info(f"Auth SUCCESS for {client_id} from {addr} (user={username})")
            self.stats["broker/auth/successes"] += 1

            client = MQTTClient(
                client_id=client_id,
                reader=reader,
                writer=writer,
                username=username,
                acl=USERS[username]["acl"],
            )

            self.clients[client_id] = client

            connack = bytes([0x20, 0x02, 0x00, 0x00])  # Accepted
            writer.write(connack)
            await writer.drain()

            return client

        except Exception as e:
            log.error(f"Error in CONNECT: {e}")
            return None

    async def _handle_publish(self, client: MQTTClient, flags: int, payload: bytes):
        try:
            qos = (flags & 0x06) >> 1
            retain = bool(flags & 0x01)
            offset = 0

            topic_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2
            topic = payload[offset : offset + topic_len].decode()
            offset += topic_len

            if qos > 0:
                packet_id = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2
            else:
                packet_id = None

            message = payload[offset:]

            # ACL check for publish
            if not self._check_acl(client, topic, "publish"):
                log.warning(f"PUBLISH denied for {client.client_id} to '{topic}' - ACL violation")
                return

            log.info(f"PUBLISH from {client.client_id}: topic='{topic}'")
            await self._publish_internal(topic, message, qos, retain)

            if qos == 1 and packet_id:
                puback = bytes([0x40, 0x02]) + struct.pack("!H", packet_id)
                client.writer.write(puback)
                await client.writer.drain()

        except Exception as e:
            log.error(f"Error in PUBLISH: {e}")

    async def _handle_subscribe(self, client: MQTTClient, payload: bytes):
        try:
            offset = 0
            packet_id = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2

            granted_qos = []

            while offset < len(payload):
                topic_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2
                topic_filter = payload[offset : offset + topic_len].decode()
                offset += topic_len
                requested_qos = payload[offset]
                offset += 1

                # ACL check
                if self._check_acl(
                    client, topic_filter.replace("#", "test").replace("+", "test"), "subscribe"
                ):
                    log.info(f"SUBSCRIBE allowed for {client.client_id} to '{topic_filter}'")
                    client.subscriptions.add(topic_filter)

                    if topic_filter not in self.topic_subscribers:
                        self.topic_subscribers[topic_filter] = set()
                    self.topic_subscribers[topic_filter].add(client.client_id)

                    granted_qos.append(min(requested_qos, 2))

                    # Send retained
                    for topic, (msg, qos) in self.retained_messages.items():
                        if self._topic_matches(topic_filter, topic):
                            if self._check_acl(client, topic, "subscribe"):
                                await self._send_publish(
                                    client, topic, msg, min(qos, requested_qos)
                                )
                else:
                    log.warning(
                        f"SUBSCRIBE denied for {client.client_id} to '{topic_filter}' - ACL"
                    )
                    granted_qos.append(0x80)  # Failure

            suback = (
                bytes([0x90, len(granted_qos) + 2])
                + struct.pack("!H", packet_id)
                + bytes(granted_qos)
            )
            client.writer.write(suback)
            await client.writer.drain()

        except Exception as e:
            log.error(f"Error in SUBSCRIBE: {e}")

    async def _handle_unsubscribe(self, client: MQTTClient, payload: bytes):
        try:
            offset = 0
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

            unsuback = bytes([0xB0, 0x02]) + struct.pack("!H", packet_id)
            client.writer.write(unsuback)
            await client.writer.drain()

        except Exception as e:
            log.error(f"Error in UNSUBSCRIBE: {e}")

    async def _send_publish(self, client: MQTTClient, topic: str, payload: bytes, qos: int = 0):
        try:
            topic_bytes = topic.encode()
            remaining = 2 + len(topic_bytes) + len(payload)
            if qos > 0:
                remaining += 2

            header = bytes([(MQTTPacketType.PUBLISH << 4) | (qos << 1)])
            remaining_bytes = self._encode_remaining_length(remaining)

            packet = header + remaining_bytes
            packet += struct.pack("!H", len(topic_bytes)) + topic_bytes

            if qos > 0:
                packet += struct.pack("!H", 1)

            packet += payload

            client.writer.write(packet)
            await client.writer.drain()

        except Exception as e:
            log.error(f"Error sending PUBLISH: {e}")

    def _encode_remaining_length(self, length: int) -> bytes:
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

    async def _send_pingresp(self, writer):
        writer.write(bytes([0xD0, 0x00]))
        await writer.drain()


async def main():
    broker = MQTTBrokerAuth(host="0.0.0.0", port=1884)
    await broker.start()


if __name__ == "__main__":
    asyncio.run(main())
