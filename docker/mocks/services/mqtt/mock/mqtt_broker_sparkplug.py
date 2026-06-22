#!/usr/bin/env python3
"""
Mock MQTT Broker with Sparkplug B Simulation
For testing OIDA MQTT/Sparkplug scanner

Features:
- Full Sparkplug B namespace (spBv1.0/#)
- Simulated Edge Nodes and Devices
- Birth/Death certificates
- Metric updates
- ICS/SCADA style data

Sparkplug topic structure:
spBv1.0/{group_id}/{message_type}/{edge_node_id}/{device_id}

Message types: NBIRTH, NDEATH, DBIRTH, DDEATH, NDATA, DDATA, NCMD, DCMD, STATE
"""

import asyncio
import logging
import json
import time
import struct
import random
from dataclasses import dataclass, field
from typing import Dict, Set, Optional, List, Any
from enum import IntEnum

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger("mqtt-broker-sparkplug")


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


class SparkplugDataType(IntEnum):
    """Sparkplug B data types"""

    Unknown = 0
    Int8 = 1
    Int16 = 2
    Int32 = 3
    Int64 = 4
    UInt8 = 5
    UInt16 = 6
    UInt32 = 7
    UInt64 = 8
    Float = 9
    Double = 10
    Boolean = 11
    String = 12
    DateTime = 13
    Text = 14
    UUID = 15
    DataSet = 16
    Bytes = 17
    File = 18
    Template = 19


@dataclass
class SparkplugMetric:
    """Sparkplug metric definition"""

    name: str
    alias: int
    datatype: int
    value: Any
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    is_historical: bool = False
    is_transient: bool = False
    is_null: bool = False


@dataclass
class SparkplugDevice:
    """Simulated Sparkplug device"""

    device_id: str
    metrics: List[SparkplugMetric] = field(default_factory=list)
    online: bool = True
    seq: int = 0


@dataclass
class SparkplugEdgeNode:
    """Simulated Sparkplug edge node"""

    node_id: str
    group_id: str
    devices: Dict[str, SparkplugDevice] = field(default_factory=dict)
    metrics: List[SparkplugMetric] = field(default_factory=list)
    online: bool = True
    seq: int = 0
    bdseq: int = 0


@dataclass
class MQTTClient:
    client_id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    subscriptions: Set[str] = field(default_factory=set)
    username: Optional[str] = None


class SparkplugEncoder:
    """Simple Sparkplug B payload encoder (JSON-based for testing)"""

    @staticmethod
    def encode_birth(node: SparkplugEdgeNode, device: SparkplugDevice = None) -> bytes:
        """Encode birth certificate as JSON (simplified for testing)"""
        payload = {
            "timestamp": int(time.time() * 1000),
            "seq": node.seq if device is None else device.seq,
        }

        metrics = device.metrics if device else node.metrics
        payload["metrics"] = [
            {
                "name": m.name,
                "alias": m.alias,
                "timestamp": m.timestamp,
                "datatype": m.datatype,
                "value": m.value,
            }
            for m in metrics
        ]

        if device is None:
            payload["bdSeq"] = node.bdseq

        return json.dumps(payload).encode()

    @staticmethod
    def encode_data(metrics: List[SparkplugMetric], seq: int) -> bytes:
        """Encode data payload as JSON"""
        payload = {
            "timestamp": int(time.time() * 1000),
            "seq": seq,
            "metrics": [
                {
                    "name": m.name,
                    "alias": m.alias,
                    "timestamp": m.timestamp,
                    "datatype": m.datatype,
                    "value": m.value,
                }
                for m in metrics
            ],
        }
        return json.dumps(payload).encode()

    @staticmethod
    def encode_death(bdseq: int = 0) -> bytes:
        """Encode death certificate"""
        return json.dumps(
            {
                "timestamp": int(time.time() * 1000),
                "bdSeq": bdseq,
            }
        ).encode()


class MQTTBrokerSparkplug:
    """
    MQTT Broker with Sparkplug B Simulation

    Simulates:
    - Factory floor with PLCs
    - SCADA infrastructure
    - Building automation
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 1885):
        self.host = host
        self.port = port
        self.clients: Dict[str, MQTTClient] = {}
        self.retained_messages: Dict[str, tuple] = {}
        self.topic_subscribers: Dict[str, Set[str]] = {}
        self.encoder = SparkplugEncoder()

        # Sparkplug infrastructure
        self.edge_nodes: Dict[str, SparkplugEdgeNode] = {}
        self._setup_sparkplug_infrastructure()

        self.stats = {
            "broker/version": "MockMQTT-Sparkplug 1.0.0",
            "broker/uptime": 0,
            "broker/clients/connected": 0,
            "broker/sparkplug/nodes": 0,
            "broker/sparkplug/devices": 0,
        }
        self.start_time = time.time()

    def _setup_sparkplug_infrastructure(self):
        """Create simulated Sparkplug infrastructure"""

        # Factory floor group
        factory_plc1 = SparkplugEdgeNode(
            node_id="PLC-001",
            group_id="Factory-Floor",
            metrics=[
                SparkplugMetric("Node Control/Scan Rate", 1, SparkplugDataType.UInt32, 1000),
                SparkplugMetric("Node Control/Rebirth", 2, SparkplugDataType.Boolean, False),
                SparkplugMetric(
                    "Properties/Firmware Version", 3, SparkplugDataType.String, "2.1.4"
                ),
                SparkplugMetric("Properties/Hardware Make", 4, SparkplugDataType.String, "Siemens"),
                SparkplugMetric(
                    "Properties/Hardware Model", 5, SparkplugDataType.String, "S7-1500"
                ),
            ],
            devices={
                "Conveyor-1": SparkplugDevice(
                    device_id="Conveyor-1",
                    metrics=[
                        SparkplugMetric("Speed", 100, SparkplugDataType.Float, 1.5),
                        SparkplugMetric("Running", 101, SparkplugDataType.Boolean, True),
                        SparkplugMetric("Motor Current", 102, SparkplugDataType.Float, 4.2),
                        SparkplugMetric("Temperature", 103, SparkplugDataType.Float, 45.5),
                        SparkplugMetric("Fault Code", 104, SparkplugDataType.UInt16, 0),
                    ],
                ),
                "Sensor-Array-1": SparkplugDevice(
                    device_id="Sensor-Array-1",
                    metrics=[
                        SparkplugMetric("Proximity/1", 200, SparkplugDataType.Boolean, False),
                        SparkplugMetric("Proximity/2", 201, SparkplugDataType.Boolean, True),
                        SparkplugMetric("PhotoEye/1", 202, SparkplugDataType.Boolean, True),
                        SparkplugMetric("Counter", 203, SparkplugDataType.UInt32, 15432),
                    ],
                ),
            },
        )

        factory_plc2 = SparkplugEdgeNode(
            node_id="PLC-002",
            group_id="Factory-Floor",
            metrics=[
                SparkplugMetric("Node Control/Scan Rate", 1, SparkplugDataType.UInt32, 500),
                SparkplugMetric(
                    "Properties/Firmware Version", 3, SparkplugDataType.String, "3.0.1"
                ),
                SparkplugMetric(
                    "Properties/Hardware Make", 4, SparkplugDataType.String, "Allen-Bradley"
                ),
                SparkplugMetric(
                    "Properties/Hardware Model", 5, SparkplugDataType.String, "CompactLogix"
                ),
            ],
            devices={
                "Packaging-Line": SparkplugDevice(
                    device_id="Packaging-Line",
                    metrics=[
                        SparkplugMetric("PackagesPerMinute", 300, SparkplugDataType.UInt16, 42),
                        SparkplugMetric("TotalPackages", 301, SparkplugDataType.UInt64, 1523456),
                        SparkplugMetric("RejectCount", 302, SparkplugDataType.UInt32, 15),
                        SparkplugMetric("Running", 303, SparkplugDataType.Boolean, True),
                    ],
                ),
            },
        )

        # SCADA group
        scada_rtu = SparkplugEdgeNode(
            node_id="RTU-001",
            group_id="SCADA",
            metrics=[
                SparkplugMetric("Node Control/Scan Rate", 1, SparkplugDataType.UInt32, 5000),
                SparkplugMetric("Properties/Location", 6, SparkplugDataType.String, "Substation-A"),
            ],
            devices={
                "Power-Meter-1": SparkplugDevice(
                    device_id="Power-Meter-1",
                    metrics=[
                        SparkplugMetric("Voltage/L1", 400, SparkplugDataType.Float, 480.2),
                        SparkplugMetric("Voltage/L2", 401, SparkplugDataType.Float, 479.8),
                        SparkplugMetric("Voltage/L3", 402, SparkplugDataType.Float, 480.5),
                        SparkplugMetric("Current/L1", 403, SparkplugDataType.Float, 125.3),
                        SparkplugMetric("Current/L2", 404, SparkplugDataType.Float, 118.7),
                        SparkplugMetric("Current/L3", 405, SparkplugDataType.Float, 122.1),
                        SparkplugMetric("Power/Active", 406, SparkplugDataType.Float, 85.2),
                        SparkplugMetric("Power/Reactive", 407, SparkplugDataType.Float, 12.4),
                        SparkplugMetric("Energy/Total", 408, SparkplugDataType.Double, 1523456.78),
                    ],
                ),
                "Breaker-CB1": SparkplugDevice(
                    device_id="Breaker-CB1",
                    metrics=[
                        SparkplugMetric("Status", 500, SparkplugDataType.UInt8, 1),  # 1=closed
                        SparkplugMetric("Trip Count", 501, SparkplugDataType.UInt32, 3),
                        SparkplugMetric(
                            "Last Trip Time",
                            502,
                            SparkplugDataType.DateTime,
                            int(time.time() * 1000) - 86400000,
                        ),
                    ],
                ),
            },
        )

        # Building automation group
        bms_node = SparkplugEdgeNode(
            node_id="BMS-001",
            group_id="Building-Automation",
            metrics=[
                SparkplugMetric("Properties/Building", 6, SparkplugDataType.String, "Main-Office"),
                SparkplugMetric("Properties/Floor", 7, SparkplugDataType.UInt8, 1),
            ],
            devices={
                "HVAC-AHU1": SparkplugDevice(
                    device_id="HVAC-AHU1",
                    metrics=[
                        SparkplugMetric("Supply Air Temp", 600, SparkplugDataType.Float, 55.0),
                        SparkplugMetric("Return Air Temp", 601, SparkplugDataType.Float, 72.5),
                        SparkplugMetric("Fan Speed", 602, SparkplugDataType.UInt8, 75),
                        SparkplugMetric("Damper Position", 603, SparkplugDataType.UInt8, 50),
                        SparkplugMetric("Filter Status", 604, SparkplugDataType.String, "OK"),
                    ],
                ),
                "Lighting-Zone1": SparkplugDevice(
                    device_id="Lighting-Zone1",
                    metrics=[
                        SparkplugMetric("Level", 700, SparkplugDataType.UInt8, 80),
                        SparkplugMetric("Occupancy", 701, SparkplugDataType.Boolean, True),
                        SparkplugMetric("Daylight Level", 702, SparkplugDataType.UInt16, 450),
                    ],
                ),
            },
        )

        self.edge_nodes = {
            "Factory-Floor/PLC-001": factory_plc1,
            "Factory-Floor/PLC-002": factory_plc2,
            "SCADA/RTU-001": scada_rtu,
            "Building-Automation/BMS-001": bms_node,
        }

    async def start(self):
        server = await asyncio.start_server(self._handle_client, self.host, self.port)

        log.info(f"MQTT Broker (Sparkplug B) started on {self.host}:{self.port}")
        log.info("Sparkplug namespace: spBv1.0/#")
        log.info(f"Edge nodes: {len(self.edge_nodes)}")

        # Start background tasks
        asyncio.create_task(self._update_stats())
        asyncio.create_task(self._sparkplug_lifecycle())
        asyncio.create_task(self._simulate_sparkplug_data())

        async with server:
            await server.serve_forever()

    async def _update_stats(self):
        while True:
            self.stats["broker/uptime"] = int(time.time() - self.start_time)
            self.stats["broker/clients/connected"] = len(self.clients)
            self.stats["broker/sparkplug/nodes"] = len(self.edge_nodes)
            self.stats["broker/sparkplug/devices"] = sum(
                len(node.devices) for node in self.edge_nodes.values()
            )
            await asyncio.sleep(5)

    async def _sparkplug_lifecycle(self):
        """Send birth certificates for all nodes/devices"""
        await asyncio.sleep(2)  # Wait for broker to start

        for key, node in self.edge_nodes.items():
            # Send NBIRTH
            topic = f"spBv1.0/{node.group_id}/NBIRTH/{node.node_id}"
            payload = self.encoder.encode_birth(node)
            await self._publish_internal(topic, payload, qos=0, retain=True)
            log.info(f"Sent NBIRTH for {key}")

            # Send DBIRTH for each device
            for device_id, device in node.devices.items():
                topic = f"spBv1.0/{node.group_id}/DBIRTH/{node.node_id}/{device_id}"
                payload = self.encoder.encode_birth(node, device)
                await self._publish_internal(topic, payload, qos=0, retain=True)
                log.info(f"Sent DBIRTH for {key}/{device_id}")

            await asyncio.sleep(0.5)

    async def _simulate_sparkplug_data(self):
        """Simulate periodic Sparkplug data updates"""
        while True:
            await asyncio.sleep(3)

            for key, node in self.edge_nodes.items():
                node.seq = (node.seq + 1) % 256

                for device_id, device in node.devices.items():
                    device.seq = (device.seq + 1) % 256

                    # Update metrics with random variations
                    updated_metrics = []
                    for metric in device.metrics:
                        if metric.datatype == SparkplugDataType.Float:
                            metric.value = round(metric.value + random.uniform(-0.5, 0.5), 2)
                            metric.timestamp = int(time.time() * 1000)
                            updated_metrics.append(metric)
                        elif metric.datatype == SparkplugDataType.UInt32:
                            metric.value += random.randint(0, 5)
                            metric.timestamp = int(time.time() * 1000)
                            updated_metrics.append(metric)
                        elif metric.datatype == SparkplugDataType.UInt16:
                            metric.value = max(0, min(65535, metric.value + random.randint(-2, 2)))
                            metric.timestamp = int(time.time() * 1000)
                            updated_metrics.append(metric)

                    if updated_metrics:
                        topic = f"spBv1.0/{node.group_id}/DDATA/{node.node_id}/{device_id}"
                        payload = self.encoder.encode_data(updated_metrics, device.seq)
                        await self._publish_internal(topic, payload)

    async def _publish_internal(
        self, topic: str, payload: bytes, qos: int = 0, retain: bool = False
    ):
        if retain:
            self.retained_messages[topic] = (payload, qos)

        for pattern, client_ids in self.topic_subscribers.items():
            if self._topic_matches(pattern, topic):
                for client_id in list(client_ids):
                    if client_id in self.clients:
                        await self._send_publish(self.clients[client_id], topic, payload, qos)

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
                    client = await self._handle_connect(reader, writer, payload)

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
                    writer.write(bytes([0xD0, 0x00]))
                    await writer.drain()

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

    async def _handle_connect(self, reader, writer, payload: bytes) -> Optional[MQTTClient]:
        """Handle CONNECT - allows anonymous for Sparkplug testing"""
        try:
            offset = 0
            proto_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2 + proto_len + 1 + 1 + 2

            client_id_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2
            client_id = (
                payload[offset : offset + client_id_len].decode()
                if client_id_len > 0
                else f"auto_{id(writer)}"
            )

            log.info(f"CONNECT from {client_id}")

            client = MQTTClient(client_id=client_id, reader=reader, writer=writer)
            self.clients[client_id] = client

            connack = bytes([0x20, 0x02, 0x00, 0x00])
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

                log.info(f"SUBSCRIBE from {client.client_id} to '{topic_filter}'")

                client.subscriptions.add(topic_filter)
                if topic_filter not in self.topic_subscribers:
                    self.topic_subscribers[topic_filter] = set()
                self.topic_subscribers[topic_filter].add(client.client_id)

                granted_qos.append(min(requested_qos, 2))

                # Send retained messages
                for topic, (msg, qos) in self.retained_messages.items():
                    if self._topic_matches(topic_filter, topic):
                        await self._send_publish(client, topic, msg, min(qos, requested_qos))

                # Send $SYS topics if subscribed
                if topic_filter.startswith("$SYS") or topic_filter == "#":
                    for stat_name, stat_value in self.stats.items():
                        sys_topic = f"$SYS/{stat_name}"
                        if self._topic_matches(topic_filter, sys_topic):
                            await self._send_publish(client, sys_topic, str(stat_value).encode(), 0)

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

            # Encode remaining length
            remaining_bytes = bytearray()
            length = remaining
            while True:
                byte = length % 128
                length //= 128
                if length > 0:
                    byte |= 0x80
                remaining_bytes.append(byte)
                if length == 0:
                    break

            packet = header + bytes(remaining_bytes)
            packet += struct.pack("!H", len(topic_bytes)) + topic_bytes
            if qos > 0:
                packet += struct.pack("!H", 1)
            packet += payload

            client.writer.write(packet)
            await client.writer.drain()

        except Exception as e:
            log.error(f"Error sending PUBLISH: {e}")


async def main():
    broker = MQTTBrokerSparkplug(host="0.0.0.0", port=1885)
    await broker.start()


if __name__ == "__main__":
    asyncio.run(main())
