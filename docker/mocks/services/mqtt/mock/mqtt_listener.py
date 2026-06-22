#!/usr/bin/env python3
"""
MQTT Continuous Listener - Standalone test tool

Demonstrates the listen mode functionality for OIDA MQTT scanner.

Usage:
    python mqtt_listener.py localhost:1883 --topics '#'
    python mqtt_listener.py localhost:1885 --topics 'spBv1.0/#' --output capture.jsonl
    python mqtt_listener.py localhost:1884 -u admin -p admin --filter 'alarm|error'
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Set, Dict

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Error: paho-mqtt not installed. Run: pip install paho-mqtt")
    sys.exit(1)


@dataclass
class ListenStats:
    """Statistics for listen mode"""

    start_time: float = field(default_factory=time.time)
    message_count: int = 0
    topics_seen: Set[str] = field(default_factory=set)
    bytes_received: int = 0
    retained_count: int = 0
    qos_counts: Dict[int, int] = field(default_factory=lambda: {0: 0, 1: 0, 2: 0})

    @property
    def duration(self) -> float:
        return time.time() - self.start_time

    @property
    def rate(self) -> float:
        if self.duration > 0:
            return self.message_count / self.duration
        return 0.0

    def to_dict(self) -> dict:
        return {
            "duration_secs": round(self.duration, 1),
            "messages": self.message_count,
            "topics": len(self.topics_seen),
            "bytes": self.bytes_received,
            "retained": self.retained_count,
            "rate_per_sec": round(self.rate, 2),
            "qos": self.qos_counts,
        }


class MQTTListener:
    """Continuous MQTT listener with filtering and logging"""

    def __init__(
        self,
        host: str,
        port: int = 1883,
        username: Optional[str] = None,
        password: Optional[str] = None,
        topics: str = "#",
        output_file: Optional[str] = None,
        payload_filter: Optional[str] = None,
        stats_interval: int = 0,
        quiet: bool = False,
        tls: bool = False,
        tls_insecure: bool = False,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.topics = topics
        self.output_file = output_file
        self.payload_filter = re.compile(payload_filter) if payload_filter else None
        self.stats_interval = stats_interval
        self.quiet = quiet
        self.tls = tls
        self.tls_insecure = tls_insecure

        self.stats = ListenStats()
        self.running = True
        self.output_fh = None
        self.client = None

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        """Handle connection"""
        if reason_code == 0:
            print(f"[*] Connected to {self.host}:{self.port}")
            print(f"[*] Subscribing to: {self.topics}")
            client.subscribe(self.topics)
        else:
            print(f"[!] Connection failed: {reason_code}")

    def _on_message(self, client, userdata, msg):
        """Handle incoming message"""
        # Update stats
        self.stats.message_count += 1
        self.stats.topics_seen.add(msg.topic)
        self.stats.bytes_received += len(msg.payload)
        self.stats.qos_counts[msg.qos] = self.stats.qos_counts.get(msg.qos, 0) + 1
        if msg.retain:
            self.stats.retained_count += 1

        # Decode payload
        try:
            payload_str = msg.payload.decode("utf-8")
        except:
            payload_str = msg.payload.hex()

        # Apply filter
        if self.payload_filter:
            if not self.payload_filter.search(payload_str):
                return

        # Format timestamp
        ts = datetime.now().strftime("%H:%M:%S")
        ts_iso = datetime.utcnow().isoformat() + "Z"

        # Console output
        if not self.quiet:
            # Truncate long payloads
            display_payload = payload_str[:100] + "..." if len(payload_str) > 100 else payload_str
            retain_flag = " [R]" if msg.retain else ""
            print(f"[{ts}] {msg.topic} = {display_payload}{retain_flag}")

        # File output (JSON lines)
        if self.output_fh:
            record = {
                "ts": ts_iso,
                "topic": msg.topic,
                "payload": payload_str,
                "qos": msg.qos,
                "retain": msg.retain,
            }
            self.output_fh.write(json.dumps(record) + "\n")
            self.output_fh.flush()

    def _print_stats(self):
        """Print current statistics"""
        s = self.stats
        elapsed = int(s.duration)
        print(
            f"[{elapsed}s] msgs={s.message_count} topics={len(s.topics_seen)} "
            f"rate={s.rate:.1f}/s retained={s.retained_count}"
        )

    def _print_final_stats(self):
        """Print final statistics on exit"""
        s = self.stats
        print("\n--- Listen Statistics ---")
        print(f"Duration: {s.duration:.1f}s")
        print(f"Messages: {s.message_count}")
        print(f"Topics: {len(s.topics_seen)}")
        print(f"Bytes: {s.bytes_received}")
        print(f"Retained: {s.retained_count}")
        print(f"Avg rate: {s.rate:.2f} msg/s")
        print(f"QoS distribution: 0={s.qos_counts[0]} 1={s.qos_counts[1]} 2={s.qos_counts[2]}")

        if s.topics_seen:
            print("\nTopics discovered:")
            for topic in sorted(s.topics_seen)[:20]:
                print(f"  {topic}")
            if len(s.topics_seen) > 20:
                print(f"  ... and {len(s.topics_seen) - 20} more")

    def run(self):
        """Run the listener"""
        # Open output file if specified
        if self.output_file:
            self.output_fh = open(self.output_file, "a")
            print(f"[*] Logging to: {self.output_file}")

        # Create MQTT client
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

        if self.username:
            self.client.username_pw_set(self.username, self.password)

        if self.tls:
            import ssl

            context = ssl.create_default_context()
            if self.tls_insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self.client.tls_set_context(context)

        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

        # Connect
        try:
            self.client.connect(self.host, self.port, 60)
        except Exception as e:
            print(f"[!] Connection error: {e}")
            return 1

        print("[*] Starting continuous listen mode (Ctrl+C to stop)")
        print("")

        # Start loop
        self.client.loop_start()

        # Stats printing loop
        last_stats = time.time()
        try:
            while self.running:
                time.sleep(0.5)

                # Print periodic stats
                if self.stats_interval > 0:
                    if time.time() - last_stats >= self.stats_interval:
                        self._print_stats()
                        last_stats = time.time()

        except KeyboardInterrupt:
            self.running = False

        # Cleanup
        self.client.loop_stop()
        self.client.disconnect()

        if self.output_fh:
            self.output_fh.close()

        self._print_final_stats()
        return 0


def main():
    parser = argparse.ArgumentParser(
        description="MQTT Continuous Listener",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s localhost:1883
  %(prog)s localhost:1885 --topics 'spBv1.0/#'
  %(prog)s localhost:1884 -u admin -p admin
  %(prog)s broker.example.com --tls --topics 'sensors/#' --output capture.jsonl
  %(prog)s localhost:1883 --filter 'alarm|error|fault' --stats 10
        """,
    )

    parser.add_argument("target", help="MQTT broker (host:port or just host)")
    parser.add_argument(
        "--topics", "-t", default="#", help="Topic pattern to subscribe (default: #)"
    )
    parser.add_argument("--username", "-u", help="MQTT username")
    parser.add_argument("--password", "-p", help="MQTT password")
    parser.add_argument("--output", "-o", help="Output file (JSON lines format)")
    parser.add_argument("--filter", "-f", help="Regex filter for payload content")
    parser.add_argument("--stats", type=int, default=0, help="Print stats every N seconds")
    parser.add_argument("--quiet", "-q", action="store_true", help="Stats only, no message output")
    parser.add_argument("--tls", action="store_true", help="Use TLS")
    parser.add_argument("--tls-insecure", action="store_true", help="Skip TLS verification")

    args = parser.parse_args()

    # Parse target
    if ":" in args.target:
        host, port = args.target.rsplit(":", 1)
        port = int(port)
    else:
        host = args.target
        port = 8883 if args.tls else 1883

    listener = MQTTListener(
        host=host,
        port=port,
        username=args.username,
        password=args.password,
        topics=args.topics,
        output_file=args.output,
        payload_filter=args.filter,
        stats_interval=args.stats,
        quiet=args.quiet,
        tls=args.tls,
        tls_insecure=args.tls_insecure,
    )

    sys.exit(listener.run())


if __name__ == "__main__":
    main()
