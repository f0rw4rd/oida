"""
MQTT Messaging Mixin

Handles listen mode, publish, combined publish-and-listen,
and publish payload fuzzing.
"""

import json
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..scanner import ListenStats
from ....utils.export_utils import print_table
from ....utils.fuzzer import fuzz

# Cap publish fuzzing to the first N discovered topics
MAX_FUZZ_TOPICS = 10


class MessagingMixin:
    """Mixin providing MQTT messaging operations."""

    def _make_on_message(self, stats: ListenStats, output_fh, v5_state: dict):
        """Create the on_message callback used by listen and publish-and-listen.

        Args:
            stats: ListenStats accumulator.
            output_fh: Open file handle for JSON line output (or None).
            v5_state: Mutable dict with key ``'has_v5_props'`` (bool).

        Returns:
            Callback suitable for ``conn.on_message``.
        """

        def on_message(client, userdata, msg):
            is_new_topic = msg.topic not in stats.topics_seen

            stats.message_count += 1
            stats.topics_seen.add(msg.topic)
            stats.bytes_received += len(msg.payload)
            if msg.retain:
                stats.retained_count += 1

            try:
                payload_str = msg.payload.decode("utf-8")
            except Exception:
                payload_str = msg.payload.hex()

            props_dict = self._extract_message_properties(msg)
            if props_dict:
                v5_state["has_v5_props"] = True

            self.logger.debug(
                f"RECV #{stats.message_count}: '{msg.topic}' = {payload_str} (qos={msg.qos}, retain={msg.retain})"
            )
            if props_dict:
                self.logger.debug(f"  Properties: {self._format_properties_debug(props_dict)}")

            if self.unique_only and not is_new_topic:
                return

            msg_record = {
                "ts": datetime.now(timezone.utc).isoformat() + "Z",
                "topic": msg.topic,
                "payload": payload_str,
                "qos": msg.qos,
                "retain": msg.retain,
            }
            msg_record.update(props_dict)
            stats.messages.append(msg_record)

            if output_fh:
                output_fh.write(json.dumps(msg_record) + "\n")
                output_fh.flush()

        return on_message

    def _wait_for_messages(self):
        """Block until timeout or KeyboardInterrupt."""
        timeout_str = "forever" if self.timeout == 0 else f"{self.timeout}s"
        self.logger.debug(f"Listening for {timeout_str}...")
        try:
            if self.timeout == 0:
                while not self._stop_listen:
                    time.sleep(0.1)
            else:
                time.sleep(self.timeout)
        except KeyboardInterrupt:
            self.logger.debug("Listen interrupted by user (Ctrl-C)")

    def _open_output_file(self):
        """Open the listen output file if configured. Returns file handle or None."""
        if self.listen_output:
            try:
                return open(self.listen_output, "a")
            except OSError as e:
                self.logger.fail(f"Failed to open output file {self.listen_output}: {e}")
        return None

    def _run_listen_mode(self, conn: Any) -> Dict[str, Any]:
        """Run continuous listen mode"""
        stats = ListenStats()
        output_fh = None
        v5_state = {"has_v5_props": False}

        # Determine source description for logging
        if self.topics_from_file:
            source = Path(self.topics_file).name
        else:
            source = f"pattern '{self.topics_pattern}'"
        timeout_str = "forever" if self.timeout == 0 else f"{self.timeout}s"
        self.logger.display(f"Listen mode started (topics: {source}, duration: {timeout_str})")

        try:
            output_fh = self._open_output_file()
            conn.on_message = self._make_on_message(stats, output_fh, v5_state)
            conn.loop_start()
            self.logger.debug("MQTT loop started")

            for topic in self.topics_list:
                result = conn.subscribe(topic)
                self.logger.debug(f"SUBSCRIBE '{topic}' -> mid={result[1]}, rc={result[0]}")

            self._wait_for_messages()
            conn.loop_stop()

        finally:
            if output_fh:
                try:
                    output_fh.close()
                except Exception as e:
                    self.logger.debug(f"output_fh.close(): {e}")

        result = {
            "duration": stats.duration,
            "messages": stats.message_count,
            "topics": len(stats.topics_seen),
            "bytes": stats.bytes_received,
            "rate": stats.rate,
        }

        self.logger.display(
            f"Listen mode complete: {stats.message_count} messages, {len(stats.topics_seen)} topics"
        )

        if stats.messages:
            self._display_message_table(stats.messages, v5_state["has_v5_props"])

        return result

    def publish_and_listen(
        self,
        conn: Any,
        topic: str,
        payload: bytes,
        qos: int = 0,
        retain: bool = False,
        subscribe_topics: List[str] = None,
        properties: Any = None,
    ) -> Dict[str, Any]:
        """Subscribe first, then publish, then listen for messages.

        Args:
            topic: Topic to publish to
            subscribe_topics: Topics to subscribe to (defaults to [topic])
            properties: MQTT 5.0 Properties object (optional)

        This allows seeing your own published message echoed back.
        """
        if subscribe_topics is None:
            subscribe_topics = [topic]

        stats = ListenStats()
        output_fh = None
        publish_result = {
            "success": False,
            "topic": topic,
            "size": len(payload),
            "error": None,
        }
        v5_state = {"has_v5_props": False}

        timeout_str = "forever" if self.timeout == 0 else f"{self.timeout}s"
        sub_desc = (
            ", ".join(subscribe_topics)
            if len(subscribe_topics) <= 3
            else f"{len(subscribe_topics)} topics"
        )
        self.logger.display(
            f"Subscribe to [{sub_desc}], publish to '{topic}', listen ({timeout_str})..."
        )

        try:
            output_fh = self._open_output_file()
            conn.on_message = self._make_on_message(stats, output_fh, v5_state)
            conn.loop_start()
            self.logger.debug("MQTT loop started")

            # 1. Subscribe first
            for t in subscribe_topics:
                result = conn.subscribe(t)
                self.logger.debug(f"SUBSCRIBE '{t}' -> mid={result[1]}, rc={result[0]}")

            # Small delay to ensure subscription is active
            time.sleep(0.1)

            # 2. Publish
            props_str = " (with v5 properties)" if properties else ""
            self.logger.debug(
                f"PUBLISH to '{topic}' ({len(payload)} bytes, qos={qos}, retain={retain}){props_str}"
            )
            try:
                pub_result = conn.publish(
                    topic, payload, qos=qos, retain=retain, properties=properties
                )
                pub_result.wait_for_publish(timeout=5)
                self.logger.debug(f"PUBLISH result: rc={pub_result.rc}, mid={pub_result.mid}")
                if pub_result.rc == 0:
                    publish_result["success"] = True
                    self.logger.success(f"Published {len(payload)} bytes to {topic}")
                else:
                    publish_result["error"] = f"rc={pub_result.rc}"
                    self.logger.fail(f"Publish failed: {publish_result['error']}")
            except Exception as e:
                publish_result["error"] = str(e)
                self.logger.debug(f"PUBLISH exception: {e}")
                self.logger.fail(f"Publish error: {e}")

            # 3. Listen for messages
            self._wait_for_messages()
            conn.loop_stop()

        finally:
            if output_fh:
                try:
                    output_fh.close()
                except Exception as e:
                    self.logger.debug(f"output_fh.close(): {e}")

        self.logger.display(
            f"Listen complete: {stats.message_count} messages, {len(stats.topics_seen)} topics"
        )

        if stats.messages:
            self._display_message_table(stats.messages, v5_state["has_v5_props"])

        return {
            "publish": publish_result,
            "listen": {
                "duration": stats.duration,
                "messages": stats.message_count,
                "topics": len(stats.topics_seen),
                "bytes": stats.bytes_received,
            },
        }

    def publish_message(
        self,
        conn: Any,
        topic: str,
        payload: bytes,
        qos: int = 0,
        retain: bool = False,
        properties: Any = None,
    ) -> Dict[str, Any]:
        """Publish a message to an MQTT topic.

        Args:
            conn: MQTT connection
            topic: Topic to publish to
            payload: Message payload as bytes
            qos: QoS level (0, 1, or 2)
            retain: Whether to set the retain flag
            properties: MQTT 5.0 Properties object (optional)

        Returns:
            Dict with success status and details
        """
        result = {"success": False, "topic": topic, "size": len(payload), "error": None}

        try:
            conn.loop_start()
            props_str = " (with v5 properties)" if properties else ""
            self.logger.debug(
                f"PUBLISH to '{topic}' ({len(payload)} bytes, qos={qos}, retain={retain}){props_str}"
            )
            pub_result = conn.publish(topic, payload, qos=qos, retain=retain, properties=properties)
            pub_result.wait_for_publish(timeout=5)
            self.logger.debug(f"PUBLISH result: rc={pub_result.rc}, mid={pub_result.mid}")
            conn.loop_stop()

            if pub_result.rc == 0:
                result["success"] = True
                self.logger.success(f"Published {len(payload)} bytes to {topic}")
            else:
                result["error"] = f"rc={pub_result.rc}"
                self.logger.fail(f"Publish failed: {result['error']}")

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"PUBLISH exception: {e}")
            self.logger.fail(f"Publish error: {e}")

        return result

    def fuzz_publish_payloads(
        self, conn: Any, topics: List[str], iterations: int = 20
    ) -> Dict[str, Any]:
        """Fuzz publish payloads to topics

        Args:
            conn: MQTT connection
            topics: List of topics to fuzz
            iterations: Number of fuzz payloads per topic

        Returns:
            Dict with fuzzing results
        """
        results = {
            "tested": 0,
            "published": 0,
            "errors": [],
            "topics_fuzzed": [],
        }

        if not conn or not topics:
            return results

        conn.loop_start()

        # Limit to first 10 topics
        for topic in topics[:MAX_FUZZ_TOPICS]:
            topic_stats = {"topic": topic, "payloads_sent": 0, "errors": 0}

            # Generate fuzz payloads
            base_payload = b"test_value"
            for i, (payload, _desc) in enumerate(fuzz(base_payload, count=iterations, max_len=256)):
                try:
                    result = conn.publish(topic, payload, qos=0)
                    if result.rc == 0:
                        topic_stats["payloads_sent"] += 1
                        results["published"] += 1
                    else:
                        topic_stats["errors"] += 1
                        results["errors"].append(
                            {
                                "topic": topic,
                                "payload": payload.hex()[:32],
                                "error": f"rc={result.rc}",
                            }
                        )

                    results["tested"] += 1

                except Exception as e:
                    topic_stats["errors"] += 1
                    results["errors"].append(
                        {
                            "topic": topic,
                            "payload": payload.hex()[:32],
                            "error": str(e),
                        }
                    )

                # Small delay between publishes
                time.sleep(0.02)

            results["topics_fuzzed"].append(topic_stats)

        conn.loop_stop()

        return results

    def _display_message_table(self, messages: List[Dict[str, Any]], has_v5_props: bool) -> None:
        """Display captured messages in a formatted table.

        Args:
            messages: List of message dicts with ts, topic, payload, qos, retain fields
            has_v5_props: Whether to include MQTT 5.0 property columns
        """
        headers = ["Time", "Topic", "Payload", "QoS", "Retain"]
        if has_v5_props:
            headers += ["ContentType", "CorrelationID"]

        rows = []
        for msg in messages:
            ts = msg["ts"].split("T")[1].split(".")[0] if "T" in msg["ts"] else msg["ts"]
            row = [
                ts,
                msg["topic"],
                msg["payload"],
                str(msg["qos"]),
                "Yes" if msg["retain"] else "No",
            ]
            if has_v5_props:
                row += [msg.get("content_type", ""), msg.get("correlation_id", "")]
            rows.append(row)
        print_table(rows, headers, logger=self.logger)
