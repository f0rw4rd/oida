"""
MQTT Topic Discovery Mixin

Handles $SYS broker enumeration, wildcard topic enumeration,
Sparkplug B namespace discovery, and common topic bruteforce.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Set

from ..scanner import COMMON_TOPICS, MQTTMessage

import logging

logger = logging.getLogger(__name__)


class TopicDiscoveryMixin:
    """Mixin providing MQTT topic discovery operations."""

    def _enumerate_sys_topics(self, conn: Any) -> Dict[str, Any]:
        """Enumerate $SYS broker topics"""
        self.logger.display("Enumerating $SYS broker topics...")
        broker_info = {}
        sys_topics = {}

        def on_message(client, userdata, msg):
            topic = msg.topic
            try:
                value = msg.payload.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                value = msg.payload.hex()

            sys_topics[topic] = value

            # Parse specific broker info
            if topic == "$SYS/broker/version":
                broker_info["version"] = value
            elif topic == "$SYS/broker/uptime":
                broker_info["uptime"] = value
            elif topic == "$SYS/broker/clients/connected":
                broker_info["clients_connected"] = value

        conn.on_message = on_message
        conn.loop_start()
        conn.subscribe("$SYS/#")

        time.sleep(min(3, self.timeout))

        conn.unsubscribe("$SYS/#")
        conn.loop_stop()

        broker_info["sys_topics"] = sys_topics
        broker_info["sys_topic_count"] = len(sys_topics)

        if sys_topics:
            version = broker_info.get("version", "unknown")
            # Clean up version string (remove test markers like INSECURE)
            version = version.replace(" (INSECURE)", "").replace("(INSECURE)", "").strip()
            self.logger.display(
                f"$SYS enumeration complete: {len(sys_topics)} topics (broker: {version})"
            )
            self.logger.warning("$SYS topics accessible - broker info disclosure")
        else:
            self.logger.display("$SYS enumeration complete: not accessible")

        return broker_info

    def _enumerate_topics(self, conn: Any) -> List[Dict[str, Any]]:
        """Enumerate available topics"""
        self.logger.display(
            f"Enumerating topics (pattern: {self.topics_pattern}, timeout: {self.timeout}s)..."
        )
        topics_data = []
        messages_by_topic: Dict[str, List[MQTTMessage]] = {}

        def on_message(client, userdata, msg):
            self.topics_discovered.add(msg.topic)

            mqtt_msg = MQTTMessage(
                topic=msg.topic,
                payload=msg.payload,
                qos=msg.qos,
                retain=msg.retain,
            )
            self.messages.append(mqtt_msg)

            if msg.topic not in messages_by_topic:
                messages_by_topic[msg.topic] = []
            messages_by_topic[msg.topic].append(mqtt_msg)

        conn.on_message = on_message
        conn.loop_start()

        # Subscribe to main pattern
        conn.subscribe(self.topics_pattern)

        time.sleep(self.timeout)

        conn.unsubscribe(self.topics_pattern)
        conn.loop_stop()

        # Build topic summary
        for topic in sorted(self.topics_discovered):
            msgs = messages_by_topic.get(topic, [])
            topic_info = {
                "topic": topic,
                "message_count": len(msgs),
                "has_retained": any(m.retain for m in msgs),
                "qos_levels": list(set(m.qos for m in msgs)),
            }
            if msgs:
                topic_info["sample_payload"] = msgs[-1].payload_str()[:100]
            topics_data.append(topic_info)

        if self.topics_discovered:
            self.logger.display(
                f"Topic enumeration complete: {len(self.topics_discovered)} topics found"
            )
            # Print discovered topics
            for topic in sorted(self.topics_discovered):
                self.logger.display(f"  {topic}")
            # Warn if wildcard subscription worked (security issue)
            if self.topics_pattern == "#" and len(self.topics_discovered) > 0:
                self.logger.warning(
                    f"Wildcard subscription (#) allowed - {len(self.topics_discovered)} topics"
                )
        else:
            self.logger.display("Topic enumeration complete: no topics found")

        return topics_data

    def _enumerate_sparkplug(self, conn: Any) -> Dict[str, Any]:
        """Enumerate Sparkplug B namespace"""
        self.logger.display("Enumerating Sparkplug B namespace (spBv1.0/#)...")
        sparkplug = {
            "groups": set(),
            "nodes": {},
            "devices": [],
            "metrics": [],
        }

        def on_message(client, userdata, msg):
            topic = msg.topic
            if not topic.startswith("spBv1.0/"):
                return

            parts = topic.split("/")
            if len(parts) < 4:
                return

            group_id = parts[1]
            node_id = parts[3]
            device_id = parts[4] if len(parts) > 4 else None

            sparkplug["groups"].add(group_id)

            node_key = f"{group_id}/{node_id}"
            if node_key not in sparkplug["nodes"]:
                sparkplug["nodes"][node_key] = {
                    "group": group_id,
                    "node_id": node_id,
                    "devices": set(),
                    "metrics": [],
                }

            if device_id:
                sparkplug["nodes"][node_key]["devices"].add(device_id)

            # Parse payload (JSON for our mock, protobuf in real Sparkplug)
            try:
                payload = json.loads(msg.payload.decode("utf-8"))
                metrics = payload.get("metrics", [])
                for m in metrics:
                    metric_info = {
                        "name": m.get("name"),
                        "datatype": m.get("datatype"),
                        "value": m.get("value"),
                        "node": node_key,
                        "device": device_id,
                    }
                    sparkplug["metrics"].append(metric_info)

                    # Extract hardware info
                    if "Properties/Hardware" in m.get("name", "") or "Properties/Firmware" in m.get(
                        "name", ""
                    ):
                        sparkplug["nodes"][node_key]["hardware_info"] = {
                            m.get("name"): m.get("value")
                        }

            except Exception as e:
                logger.debug(f"Failed to get payload: {e}")

        conn.on_message = on_message
        conn.loop_start()
        conn.subscribe("spBv1.0/#")

        time.sleep(min(5, self.timeout))

        conn.unsubscribe("spBv1.0/#")
        conn.loop_stop()

        # Convert sets to lists for JSON serialization
        sparkplug["groups"] = list(sparkplug["groups"])
        for node_key in sparkplug["nodes"]:
            sparkplug["nodes"][node_key]["devices"] = list(sparkplug["nodes"][node_key]["devices"])

        if sparkplug["nodes"]:
            node_count = len(sparkplug["nodes"])
            device_count = sum(len(n["devices"]) for n in sparkplug["nodes"].values())
            self.logger.display(
                f"Sparkplug enumeration complete: {node_count} nodes, {device_count} devices"
            )
        else:
            self.logger.display("Sparkplug enumeration complete: no nodes detected")

        return sparkplug

    def _enumerate_common_topics(self, conn: Any) -> Dict[str, Any]:
        """Enumerate common ICS/IoT topics by bruteforce subscription

        Useful when wildcard subscriptions (#) are blocked by ACLs.
        Uses custom topic list file if provided, otherwise COMMON_TOPICS.
        """
        results = {
            "topics_tested": 0,
            "topics_found": [],
            "messages_received": 0,
            "accessible_patterns": [],
            "source": "builtin",
        }

        # Load topics from custom file or use builtin list
        topics_to_test = []
        if self.topic_list_file and Path(self.topic_list_file).exists():
            with open(self.topic_list_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        topics_to_test.append(line)
            results["source"] = f"file:{self.topic_list_file}"
            self.logger.display(
                f"Topic bruteforce: loaded {len(topics_to_test)} patterns from {self.topic_list_file}"
            )
        else:
            topics_to_test = list(COMMON_TOPICS)
            self.logger.display(
                f"Topic bruteforce: testing {len(topics_to_test)} common ICS/IoT patterns..."
            )

        found_topics: Set[str] = set()
        message_count = 0

        def on_message(client, userdata, msg):
            nonlocal message_count
            found_topics.add(msg.topic)
            message_count += 1
            self.topics_discovered.add(msg.topic)

            # Store message
            mqtt_msg = MQTTMessage(
                topic=msg.topic,
                payload=msg.payload,
                qos=msg.qos,
                retain=msg.retain,
            )
            self.messages.append(mqtt_msg)

        conn.on_message = on_message
        conn.loop_start()

        # Subscribe to all patterns at once for efficiency
        subscribed_patterns = []
        for topic_pattern in topics_to_test:
            # Skip if we already tested this via $SYS or sparkplug enumeration
            if topic_pattern.startswith("$SYS/") and self.enumerate_sys:
                continue
            if topic_pattern.startswith("spBv1.0/") and self.enumerate_sparkplug:
                continue

            results["topics_tested"] += 1
            conn.subscribe(topic_pattern)
            subscribed_patterns.append(topic_pattern)

        # Wait for messages (use timeout or min 2 seconds)
        wait_time = max(2, min(self.timeout, 10))
        time.sleep(wait_time)

        # Unsubscribe all
        for pattern in subscribed_patterns:
            conn.unsubscribe(pattern)

        conn.loop_stop()

        # Determine which patterns were accessible (had topics)
        for pattern in subscribed_patterns:
            matching = [t for t in found_topics if self._topic_matches_pattern(pattern, t)]
            if matching:
                results["accessible_patterns"].append(
                    {
                        "pattern": pattern,
                        "topics_found": len(matching),
                    }
                )

        # Build results
        results["topics_found"] = list(found_topics)
        results["messages_received"] = message_count

        if found_topics:
            self.logger.display(
                f"Topic bruteforce complete: {len(found_topics)} topics discovered ({len(results['accessible_patterns'])} patterns matched)"
            )
        else:
            self.logger.display(
                f"Topic bruteforce complete: no topics found ({results['topics_tested']} patterns tested)"
            )

        return results

    def _topic_matches_pattern(self, pattern: str, topic: str) -> bool:
        """Check if topic matches MQTT pattern with + and # wildcards"""
        if pattern == "#":
            return True
        if pattern == topic:
            return True

        pattern_parts = pattern.split("/")
        topic_parts = topic.split("/")

        for i, p in enumerate(pattern_parts):
            if p == "#":
                return True  # # matches rest of path
            if i >= len(topic_parts):
                return False
            if p == "+":
                continue  # + matches single level
            if p != topic_parts[i]:
                return False

        return len(pattern_parts) == len(topic_parts)
