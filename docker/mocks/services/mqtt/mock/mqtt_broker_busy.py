#!/usr/bin/env python3
"""
Mock MQTT Broker - High Activity, Strict Security
For testing OIDA MQTT scanner against busy brokers

Security features:
- Username/password authentication REQUIRED
- NO wildcard subscriptions allowed (# and + are rejected)
- Per-topic ACLs enforced
- Rate limiting on failed auth attempts

Activity features:
- 50+ topics with frequent updates (0.1s - 2s intervals)
- Simulates industrial environment with PLCs, sensors, HMIs
- High message throughput for stress testing

Default users:
- admin:admin123 (full access to all topics)
- scada:scada (access to scada/*, factory/*)
- operator:op3r4t0r (access to hmi/*, alarms/*)
- sensor:sensor (access to sensors/* only)
- readonly:readonly (can only subscribe, cannot publish)
"""

import asyncio
import logging
import json
import time
import struct
import random
from dataclasses import dataclass, field
from typing import Dict, Set, Optional, List, Tuple
from enum import IntEnum

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger("mqtt-broker-busy")


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


# User database with ACLs
# Format: {username: {password, subscribe_acl: [topics], publish_acl: [topics]}}
USERS = {
    "admin": {
        "password": "admin123",
        "subscribe_acl": ["*"],  # * means all topics
        "publish_acl": ["*"],
    },
    "scada": {
        "password": "scada",
        "subscribe_acl": ["scada/*", "factory/*", "plc/*", "rtu/*"],
        "publish_acl": ["scada/commands/*", "factory/setpoints/*"],
    },
    "operator": {
        "password": "op3r4t0r",
        "subscribe_acl": ["hmi/*", "alarms/*", "factory/status/*", "sensors/*"],
        "publish_acl": ["hmi/ack/*", "alarms/ack/*"],
    },
    "sensor": {
        "password": "sensor",
        "subscribe_acl": ["sensors/*"],
        "publish_acl": ["sensors/data/*"],
    },
    "readonly": {
        "password": "readonly",
        "subscribe_acl": ["factory/status/*", "sensors/temperature/*", "sensors/pressure/*"],
        "publish_acl": [],  # Cannot publish anything
    },
    "hmi": {
        "password": "hmi2024",
        "subscribe_acl": ["hmi/*", "factory/*", "alarms/*"],
        "publish_acl": ["hmi/input/*"],
    },
    "historian": {
        "password": "hist0ry",
        "subscribe_acl": ["factory/*", "sensors/*", "plc/*", "scada/*"],
        "publish_acl": [],  # Read-only for archiving
    },
}


@dataclass
class MQTTClient:
    client_id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    subscriptions: Set[str] = field(default_factory=set)
    username: Optional[str] = None
    subscribe_acl: List[str] = field(default_factory=list)
    publish_acl: List[str] = field(default_factory=list)
    clean_session: bool = True
    keepalive: int = 60
    connected_at: float = field(default_factory=time.time)
    messages_received: int = 0
    messages_sent: int = 0


class MQTTBrokerBusy:
    """
    MQTT Broker with High Activity and Strict Security

    Features:
    - NO wildcard subscriptions
    - Authentication required
    - High message throughput
    - Industrial simulation
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 1886):
        self.host = host
        self.port = port
        self.clients: Dict[str, MQTTClient] = {}
        self.retained_messages: Dict[str, Tuple[bytes, int]] = {}
        self.topic_subscribers: Dict[str, Set[str]] = {}
        self.failed_auth_attempts: Dict[str, List[float]] = {}  # IP -> timestamps

        self.stats = {
            "version": "MockMQTT-Busy 1.0.0",
            "uptime": 0,
            "clients_connected": 0,
            "auth_failures": 0,
            "auth_successes": 0,
            "messages_published": 0,
            "wildcard_rejections": 0,
            "acl_violations": 0,
        }
        self.start_time = time.time()

        # Simulation state
        self.simulation_data: Dict[str, any] = {}
        self._init_simulation_data()

    def _init_simulation_data(self):
        """Initialize simulation data for all topics"""
        # Factory PLCs
        for i in range(1, 6):
            self.simulation_data[f"plc_{i}"] = {
                "running": True,
                "mode": "auto",
                "scan_time": random.randint(10, 50),
                "io_count": random.randint(32, 256),
            }

        # Sensors (temperature, pressure, flow, level)
        for i in range(1, 21):
            self.simulation_data[f"temp_{i}"] = random.uniform(15.0, 85.0)
            self.simulation_data[f"pressure_{i}"] = random.uniform(0.5, 10.0)
            self.simulation_data[f"flow_{i}"] = random.uniform(0.0, 500.0)
            self.simulation_data[f"level_{i}"] = random.uniform(0.0, 100.0)

        # Motor drives
        for i in range(1, 11):
            self.simulation_data[f"drive_{i}"] = {
                "speed": random.uniform(0, 1800),
                "current": random.uniform(0, 50),
                "running": random.choice([True, False]),
                "fault": 0,
            }

        # Alarms
        self.simulation_data["alarm_count"] = 0
        self.simulation_data["alarm_list"] = []

    async def start(self):
        server = await asyncio.start_server(self._handle_client, self.host, self.port)

        log.info(f"MQTT Broker (BUSY/STRICT) started on {self.host}:{self.port}")
        log.info("Security: Authentication REQUIRED, Wildcards DENIED")
        log.info(f"Available users: {list(USERS.keys())}")

        # Start background tasks
        asyncio.create_task(self._update_stats())
        asyncio.create_task(self._simulate_fast_sensors())
        asyncio.create_task(self._simulate_medium_sensors())
        asyncio.create_task(self._simulate_slow_data())
        asyncio.create_task(self._simulate_plc_status())
        asyncio.create_task(self._simulate_drives())
        asyncio.create_task(self._simulate_alarms())
        asyncio.create_task(self._simulate_hmi_updates())
        asyncio.create_task(self._simulate_scada_data())

        async with server:
            await server.serve_forever()

    async def _update_stats(self):
        while True:
            self.stats["uptime"] = int(time.time() - self.start_time)
            self.stats["clients_connected"] = len(self.clients)
            await asyncio.sleep(5)

    # =========================================================================
    # HIGH-FREQUENCY SIMULATION TASKS
    # =========================================================================

    async def _simulate_fast_sensors(self):
        """Fast sensors: 100ms updates (10 topics)"""
        while True:
            await asyncio.sleep(0.1)

            # Temperature sensors (fast)
            for i in range(1, 6):
                temp = self.simulation_data[f"temp_{i}"]
                temp += random.uniform(-0.1, 0.1)
                temp = max(0, min(100, temp))
                self.simulation_data[f"temp_{i}"] = temp

                await self._publish_internal(
                    f"sensors/temperature/fast/{i}",
                    json.dumps({"value": round(temp, 2), "unit": "C", "ts": time.time()}).encode(),
                )

            # Pressure sensors (fast)
            for i in range(1, 6):
                pressure = self.simulation_data[f"pressure_{i}"]
                pressure += random.uniform(-0.05, 0.05)
                pressure = max(0, min(15, pressure))
                self.simulation_data[f"pressure_{i}"] = pressure

                await self._publish_internal(
                    f"sensors/pressure/fast/{i}",
                    json.dumps(
                        {"value": round(pressure, 3), "unit": "bar", "ts": time.time()}
                    ).encode(),
                )

    async def _simulate_medium_sensors(self):
        """Medium sensors: 500ms updates (20 topics)"""
        while True:
            await asyncio.sleep(0.5)

            # Flow sensors
            for i in range(1, 11):
                flow = self.simulation_data[f"flow_{i}"]
                flow += random.uniform(-5, 5)
                flow = max(0, min(600, flow))
                self.simulation_data[f"flow_{i}"] = flow

                await self._publish_internal(
                    f"sensors/flow/{i}",
                    json.dumps(
                        {"value": round(flow, 1), "unit": "L/min", "ts": time.time()}
                    ).encode(),
                )

            # Level sensors
            for i in range(1, 11):
                level = self.simulation_data[f"level_{i}"]
                level += random.uniform(-0.5, 0.5)
                level = max(0, min(100, level))
                self.simulation_data[f"level_{i}"] = level

                await self._publish_internal(
                    f"sensors/level/{i}",
                    json.dumps({"value": round(level, 1), "unit": "%", "ts": time.time()}).encode(),
                )

    async def _simulate_slow_data(self):
        """Slow sensors: 2s updates (temperature batch)"""
        while True:
            await asyncio.sleep(2)

            # Batch temperature reading
            temps = {}
            for i in range(1, 21):
                temps[f"sensor_{i}"] = round(self.simulation_data[f"temp_{i}"], 2)

            await self._publish_internal(
                "sensors/temperature/batch",
                json.dumps({"readings": temps, "ts": time.time()}).encode(),
            )

    async def _simulate_plc_status(self):
        """PLC status: 1s updates"""
        while True:
            await asyncio.sleep(1)

            for i in range(1, 6):
                plc = self.simulation_data[f"plc_{i}"]
                plc["scan_time"] = random.randint(10, 50)

                # Occasionally change mode
                if random.random() < 0.01:
                    plc["mode"] = random.choice(["auto", "manual", "maintenance"])

                await self._publish_internal(
                    f"plc/status/{i}",
                    json.dumps(
                        {
                            "id": i,
                            "running": plc["running"],
                            "mode": plc["mode"],
                            "scan_time_ms": plc["scan_time"],
                            "io_count": plc["io_count"],
                            "ts": time.time(),
                        }
                    ).encode(),
                )

                # PLC diagnostics
                await self._publish_internal(
                    f"plc/diagnostics/{i}",
                    json.dumps(
                        {
                            "cpu_load": random.randint(10, 80),
                            "memory_used": random.randint(20, 70),
                            "comm_errors": random.randint(0, 5),
                            "ts": time.time(),
                        }
                    ).encode(),
                )

    async def _simulate_drives(self):
        """Motor drive data: 200ms updates"""
        while True:
            await asyncio.sleep(0.2)

            for i in range(1, 11):
                drive = self.simulation_data[f"drive_{i}"]

                if drive["running"]:
                    drive["speed"] += random.uniform(-10, 10)
                    drive["speed"] = max(0, min(1800, drive["speed"]))
                    drive["current"] = drive["speed"] / 1800 * 40 + random.uniform(-2, 2)
                else:
                    drive["speed"] = max(0, drive["speed"] - 50)
                    drive["current"] = max(0, drive["current"] - 1)

                # Random start/stop
                if random.random() < 0.005:
                    drive["running"] = not drive["running"]

                await self._publish_internal(
                    f"factory/drives/{i}",
                    json.dumps(
                        {
                            "drive_id": i,
                            "speed_rpm": round(drive["speed"], 1),
                            "current_a": round(drive["current"], 2),
                            "running": drive["running"],
                            "fault_code": drive["fault"],
                            "ts": time.time(),
                        }
                    ).encode(),
                )

    async def _simulate_alarms(self):
        """Alarm simulation: random alarms every 5-30 seconds"""
        alarm_types = [
            ("HIGH_TEMP", "Temperature exceeded threshold", "warning"),
            ("LOW_PRESSURE", "Pressure below minimum", "warning"),
            ("DRIVE_FAULT", "Motor drive fault detected", "critical"),
            ("COMM_LOSS", "Communication lost with device", "critical"),
            ("LEVEL_HIGH", "Tank level high", "warning"),
            ("LEVEL_LOW", "Tank level low", "warning"),
            ("FLOW_DEVIATION", "Flow rate deviation detected", "info"),
            ("MAINTENANCE_DUE", "Scheduled maintenance required", "info"),
        ]

        while True:
            await asyncio.sleep(random.uniform(5, 30))

            # Generate random alarm
            alarm_type, desc, severity = random.choice(alarm_types)
            alarm = {
                "id": self.simulation_data["alarm_count"] + 1,
                "type": alarm_type,
                "description": desc,
                "severity": severity,
                "source": f"PLC-{random.randint(1, 5)}",
                "timestamp": time.time(),
                "acknowledged": False,
            }

            self.simulation_data["alarm_count"] += 1
            self.simulation_data["alarm_list"].append(alarm)

            # Keep only last 100 alarms
            if len(self.simulation_data["alarm_list"]) > 100:
                self.simulation_data["alarm_list"] = self.simulation_data["alarm_list"][-100:]

            await self._publish_internal(f"alarms/active/{alarm['id']}", json.dumps(alarm).encode())

            await self._publish_internal(
                "alarms/summary",
                json.dumps(
                    {
                        "total": self.simulation_data["alarm_count"],
                        "active": len(
                            [a for a in self.simulation_data["alarm_list"] if not a["acknowledged"]]
                        ),
                        "critical": len(
                            [
                                a
                                for a in self.simulation_data["alarm_list"]
                                if a["severity"] == "critical" and not a["acknowledged"]
                            ]
                        ),
                        "ts": time.time(),
                    }
                ).encode(),
            )

    async def _simulate_hmi_updates(self):
        """HMI display updates: 500ms"""
        while True:
            await asyncio.sleep(0.5)

            # Overview screen data
            await self._publish_internal(
                "hmi/screen/overview",
                json.dumps(
                    {
                        "plc_count_online": sum(
                            1 for i in range(1, 6) if self.simulation_data[f"plc_{i}"]["running"]
                        ),
                        "drives_running": sum(
                            1 for i in range(1, 11) if self.simulation_data[f"drive_{i}"]["running"]
                        ),
                        "alarm_count": len(
                            [a for a in self.simulation_data["alarm_list"] if not a["acknowledged"]]
                        ),
                        "production_rate": random.uniform(85, 99),
                        "ts": time.time(),
                    }
                ).encode(),
            )

            # Trend data
            await self._publish_internal(
                "hmi/trends/temperature",
                json.dumps(
                    {
                        "values": [
                            round(self.simulation_data[f"temp_{i}"], 2) for i in range(1, 6)
                        ],
                        "labels": [f"TT-{i:03d}" for i in range(1, 6)],
                        "ts": time.time(),
                    }
                ).encode(),
            )

    async def _simulate_scada_data(self):
        """SCADA system data: 1s updates"""
        while True:
            await asyncio.sleep(1)

            # RTU data
            for rtu in range(1, 4):
                await self._publish_internal(
                    f"scada/rtu/{rtu}/status",
                    json.dumps(
                        {
                            "rtu_id": rtu,
                            "online": True,
                            "comm_quality": random.randint(90, 100),
                            "last_poll": time.time(),
                            "points": random.randint(50, 200),
                        }
                    ).encode(),
                )

            # Master station status
            await self._publish_internal(
                "scada/master/status",
                json.dumps(
                    {
                        "rtus_online": 3,
                        "total_points": random.randint(200, 500),
                        "poll_rate_ms": 1000,
                        "redundancy": "primary",
                        "ts": time.time(),
                    }
                ).encode(),
            )

    # =========================================================================
    # MQTT PROTOCOL HANDLING
    # =========================================================================

    async def _publish_internal(
        self, topic: str, payload: bytes, qos: int = 0, retain: bool = False
    ):
        """Publish message to subscribers (internal use)"""
        self.stats["messages_published"] += 1

        if retain:
            self.retained_messages[topic] = (payload, qos)

        # Find exact topic matches only (no wildcard matching for subscribers since we don't allow wildcards)
        if topic in self.topic_subscribers:
            for client_id in list(self.topic_subscribers[topic]):
                if client_id in self.clients:
                    client = self.clients[client_id]
                    client.messages_sent += 1
                    await self._send_publish(client, topic, payload, qos)

    def _check_subscribe_acl(self, client: MQTTClient, topic: str) -> bool:
        """Check if client can subscribe to topic"""
        if "*" in client.subscribe_acl:
            return True

        for pattern in client.subscribe_acl:
            if pattern.endswith("/*"):
                prefix = pattern[:-2]
                if topic.startswith(prefix + "/") or topic == prefix:
                    return True
            elif pattern == topic:
                return True

        return False

    def _check_publish_acl(self, client: MQTTClient, topic: str) -> bool:
        """Check if client can publish to topic"""
        if "*" in client.publish_acl:
            return True

        for pattern in client.publish_acl:
            if pattern.endswith("/*"):
                prefix = pattern[:-2]
                if topic.startswith(prefix + "/") or topic == prefix:
                    return True
            elif pattern == topic:
                return True

        return False

    def _contains_wildcard(self, topic: str) -> bool:
        """Check if topic contains MQTT wildcards"""
        return "#" in topic or "+" in topic

    def _check_rate_limit(self, ip: str) -> bool:
        """Check if IP is rate limited (max 10 failures per minute)"""
        now = time.time()
        if ip not in self.failed_auth_attempts:
            return False

        # Clean old attempts
        self.failed_auth_attempts[ip] = [t for t in self.failed_auth_attempts[ip] if now - t < 60]

        return len(self.failed_auth_attempts[ip]) >= 10

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
                    if client is None:
                        break  # Connection rejected

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

        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            log.debug(f"Client {addr} error: {e}")
        finally:
            if client and client.client_id in self.clients:
                del self.clients[client.client_id]
                # Remove from all subscriptions
                for topic in list(client.subscriptions):
                    if topic in self.topic_subscribers:
                        self.topic_subscribers[topic].discard(client.client_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

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
        """Handle CONNECT with mandatory authentication"""
        ip = addr[0]

        # Check rate limiting
        if self._check_rate_limit(ip):
            log.warning(f"Rate limited: {ip}")
            connack = bytes([0x20, 0x02, 0x00, 0x05])  # Not authorized
            writer.write(connack)
            await writer.drain()
            return None

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

            # Skip will message if present
            if connect_flags & 0x04:
                will_topic_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2 + will_topic_len
                will_msg_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2 + will_msg_len

            # Get credentials
            username = None
            password = None

            if has_username and offset < len(payload):
                username_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2
                username = payload[offset : offset + username_len].decode()
                offset += username_len

            if has_password and offset < len(payload):
                password_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                offset += 2
                password = payload[offset : offset + password_len].decode()
                offset += password_len

            # REQUIRE authentication
            if not has_username or not has_password or not username or not password:
                log.warning(f"Auth FAILED for {client_id} from {addr}: Credentials required")
                self.stats["auth_failures"] += 1
                self._record_auth_failure(ip)
                connack = bytes([0x20, 0x02, 0x00, 0x04])  # Bad username or password
                writer.write(connack)
                await writer.drain()
                return None

            # Validate credentials
            if username not in USERS or USERS[username]["password"] != password:
                log.warning(
                    f"Auth FAILED for {client_id} from {addr}: Invalid credentials (user={username})"
                )
                self.stats["auth_failures"] += 1
                self._record_auth_failure(ip)
                connack = bytes([0x20, 0x02, 0x00, 0x05])  # Not authorized
                writer.write(connack)
                await writer.drain()
                return None

            # Success
            log.info(f"Auth SUCCESS for {client_id} from {addr} (user={username})")
            self.stats["auth_successes"] += 1

            user_config = USERS[username]
            client = MQTTClient(
                client_id=client_id,
                reader=reader,
                writer=writer,
                username=username,
                subscribe_acl=user_config["subscribe_acl"],
                publish_acl=user_config["publish_acl"],
            )

            self.clients[client_id] = client

            connack = bytes([0x20, 0x02, 0x00, 0x00])  # Accepted
            writer.write(connack)
            await writer.drain()

            return client

        except Exception as e:
            log.error(f"Error in CONNECT: {e}")
            return None

    def _record_auth_failure(self, ip: str):
        """Record authentication failure for rate limiting"""
        if ip not in self.failed_auth_attempts:
            self.failed_auth_attempts[ip] = []
        self.failed_auth_attempts[ip].append(time.time())

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
            if not self._check_publish_acl(client, topic):
                log.warning(f"PUBLISH denied for {client.client_id} to '{topic}' - ACL violation")
                self.stats["acl_violations"] += 1
                return

            client.messages_received += 1
            log.debug(f"PUBLISH from {client.client_id}: topic='{topic}'")
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

                # REJECT wildcards
                if self._contains_wildcard(topic_filter):
                    log.warning(
                        f"SUBSCRIBE denied for {client.client_id}: Wildcard '{topic_filter}' not allowed"
                    )
                    self.stats["wildcard_rejections"] += 1
                    granted_qos.append(0x80)  # Failure
                    continue

                # ACL check
                if not self._check_subscribe_acl(client, topic_filter):
                    log.warning(
                        f"SUBSCRIBE denied for {client.client_id} to '{topic_filter}' - ACL violation"
                    )
                    self.stats["acl_violations"] += 1
                    granted_qos.append(0x80)  # Failure
                    continue

                log.info(f"SUBSCRIBE allowed for {client.client_id} to '{topic_filter}'")
                client.subscriptions.add(topic_filter)

                if topic_filter not in self.topic_subscribers:
                    self.topic_subscribers[topic_filter] = set()
                self.topic_subscribers[topic_filter].add(client.client_id)

                granted_qos.append(min(requested_qos, 2))

                # Send retained message if exists
                if topic_filter in self.retained_messages:
                    msg, msg_qos = self.retained_messages[topic_filter]
                    await self._send_publish(client, topic_filter, msg, min(msg_qos, requested_qos))

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
            log.debug(f"Error sending PUBLISH: {e}")

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
    broker = MQTTBrokerBusy(host="0.0.0.0", port=1886)
    await broker.start()


if __name__ == "__main__":
    asyncio.run(main())
