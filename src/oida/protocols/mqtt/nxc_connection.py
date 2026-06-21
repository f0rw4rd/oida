#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MQTT NXC-style callable class."""

from typing import Any, Optional

from ...connection import NetworkConnection
from .scanner import MQTTScanner, dependencies_missing


class mqtt(NetworkConnection):
    """
    MQTT Scanner - NXC-style callable class

    Automatically executes scanning workflow on instantiation.

    Usage:
        result = mqtt(args, db, "192.168.1.100")
    """

    def __init__(self, args: Any, db: Optional[Any], host: str):
        self.protocol_name = "MQTT"
        self.default_port = 1883
        self.conn = None
        self.scanner = None
        self._connection_error = False  # True if connection failed (not auth)
        # Auto-upgrade to MQTT 5.0 if properties are used
        self._auto_upgrade_mqtt_version(args)
        super().__init__(args, db, host)

    def _has_v5_properties(self, args: Any) -> bool:
        """Check if any MQTT 5.0 properties are specified."""
        return any(
            [
                getattr(args, "response_topic", None),
                getattr(args, "correlation_id", None),
                getattr(args, "content_type", None),
                getattr(args, "message_expiry", None),
                getattr(args, "user_prop", None),
            ]
        )

    def _auto_upgrade_mqtt_version(self, args: Any):
        """Auto-upgrade to MQTT 5.0 if properties are used."""
        if self._has_v5_properties(args):
            current_version = getattr(args, "protocol_version", 4)
            if current_version < 5:
                args.protocol_version = 5

    def _build_publish_properties(self) -> Any:
        """Build MQTT 5.0 properties from args.

        Returns:
            Properties object if MQTT 5.0 properties are specified, None otherwise.
        """
        if not self._has_v5_properties(self.args):
            return None

        # Convert args namespace to dict for scanner helper
        args_dict = {
            "response_topic": getattr(self.args, "response_topic", None),
            "correlation_id": getattr(self.args, "correlation_id", None),
            "content_type": getattr(self.args, "content_type", None),
            "message_expiry": getattr(self.args, "message_expiry", None),
            "user_prop": getattr(self.args, "user_prop", None),
        }

        return self.scanner._build_publish_properties(args_dict)

    def proto_flow(self):
        """Execute MQTT scanning workflow"""
        args_dict = self._convert_args_to_dict()
        self.scanner = MQTTScanner(args_dict)

        # Version enumeration (pre-auth, runs before connection)
        if getattr(self.args, "enum_versions", False):
            version_results = self.scanner.enumerate_mqtt_versions()
            self.results["data"]["protocol_versions"] = version_results
            # If only doing version enum, we're done
            if not self._should_continue_after_version_enum():
                return

        # Create connection
        self.create_conn_obj()

        # Show connection status and warnings FIRST
        if self.conn:
            self.enum_host_info()
            self.print_host_info()

        # Stop here if connection failed (no service detected)
        if self._connection_error:
            return

        # Check if both publish and listen are requested
        publish_requested = self._has_publish_request()
        listen_requested = getattr(self.args, "listen", False)

        if publish_requested and listen_requested:
            # Combined: subscribe first, then publish, then listen
            self._handle_publish_and_listen()
        else:
            # Handle publish if -m/-f/-n provided (mosquitto_pub style)
            publish_handled = self._handle_publish()

            # Run scan (handles both connected and disconnected cases)
            # Skip enumeration if only publishing (no -e, -D, etc.)
            if not publish_handled or self._should_run_scan():
                self._execute_scan()

        # Fuzzing (if connected)
        if self.conn and getattr(self.args, "fuzz", False):
            self._handle_fuzz()

    def create_conn_obj(self):
        """Create MQTT connection"""
        self.logger.info(f"Connecting to {self.ip}:{self.args.port}")
        self.conn = self.scanner.connect()
        if self.conn:
            self.logger.success(f"Connected to MQTT broker at {self.ip}:{self.args.port}")
            return

        username = getattr(self.args, "username", "")
        password = getattr(self.args, "password", "")
        auth_result = self.scanner.auth_result

        if auth_result:
            if auth_result.startswith("error:"):
                # Connection error (SSL, network, etc.)
                error_msg = auth_result[7:]  # Remove "error: " prefix
                self.logger.fail(f"Connection failed: {error_msg}")
                self._connection_error = True
            else:
                # Server responded but rejected auth — surface as info so the
                # auth result still shows, but don't emit a green success
                # banner for a session we never actually opened.
                self.logger.info(f"MQTT broker responded at {self.ip}:{self.args.port}")
                if username:
                    self.logger.fail(f"Authentication failed ({username}:{password})")
                else:
                    self.logger.fail(f"Auth required ({auth_result})")
        else:
            self.logger.fail("Connection failed (no response)")
            self._connection_error = True

    def enum_host_info(self):
        """Enumerate MQTT broker information"""
        broker_info = {
            "broker_url": f"mqtt{'s' if getattr(self.args, 'tls', False) else ''}://{self.host}:{self.results.get('port', self.default_port)}",
        }
        self.results["data"]["broker_info"] = broker_info

    def print_host_info(self):
        """Display MQTT broker information.

        ``create_conn_obj`` already emitted the connection-success banner;
        skip a redundant ``success()`` here.
        """

        # Warning if no TLS
        if not getattr(self.args, "tls", False):
            self.logger.security_finding(
                "No encryption",
                category="ENCRYPTION",
                detail="Plaintext connection (no TLS)",
            )

        # The anonymous-access finding is reported once in the scanner's
        # _analyze_security() to avoid duplicate findings for the same broker.

    def _execute_scan(self):
        """Execute MQTT scanning"""
        scan_results = self.scanner.discover(self.conn)
        self.results["data"]["scan_results"] = scan_results
        # All logging is now handled by the scanner during enumeration

    def _has_publish_request(self) -> bool:
        """Check if publish was requested via -m, -f, or -n."""
        message = getattr(self.args, "message", None)
        payload_file = getattr(self.args, "payload_file", None)
        null_msg = getattr(self.args, "null", False)
        return bool(message or payload_file or null_msg)

    def _build_payload(self):
        """Build payload from args. Returns (payload, error_msg) tuple."""
        message = getattr(self.args, "message", None)
        payload_file = getattr(self.args, "payload_file", None)
        null_msg = getattr(self.args, "null", False)

        try:
            if null_msg:
                return b"", None
            elif payload_file:
                with open(payload_file, "rb") as f:
                    return f.read(), None
            else:
                if getattr(self.args, "hex", False):
                    clean = message.replace(":", "").replace(" ", "").replace("0x", "")
                    return bytes.fromhex(clean), None
                else:
                    return message.encode("utf-8"), None
        except FileNotFoundError as e:
            self.logger.debug(f"Payload file read failed: {e}")
            return None, f"Payload file not found: {payload_file}"
        except ValueError as e:
            self.logger.debug(f"Hex payload decode failed: {e}")
            return None, f"Invalid hex payload: {e}"

    def _handle_publish_and_listen(self):
        """Handle combined publish + listen (subscribe first, then publish).

        Supports comma-separated topics: -t "pub_topic,sub_topic1,sub_topic2"
        - First topic is used for publishing
        - All topics are subscribed to
        - Response topic is auto-subscribed if specified
        """
        # Safety check
        if not getattr(self.args, "confirm", False):
            self.logger.fail("Publish requires --confirm flag")
            return

        # Get and parse topics (comma-separated)
        topics_arg = getattr(self.args, "topics", None)
        if not topics_arg or topics_arg == "#":
            self.logger.fail("Publish requires -t TOPIC (not wildcard only)")
            return

        # Parse comma-separated topics
        topics = [t.strip() for t in topics_arg.split(",") if t.strip()]
        if not topics:
            self.logger.fail("No valid topics specified")
            return

        # First topic is for publishing, all topics for subscribing
        publish_topic = topics[0]
        subscribe_topics = list(topics)  # Copy to avoid modifying original

        # Auto-subscribe to response topic if specified
        response_topic = getattr(self.args, "response_topic", None)
        if response_topic and response_topic not in subscribe_topics:
            subscribe_topics.append(response_topic)
            self.logger.debug(f"Auto-subscribed to response topic: {response_topic}")

        if publish_topic == "#":
            self.logger.fail("Cannot publish to wildcard (#)")
            return

        if not self.conn:
            self.logger.fail("Cannot publish without connection")
            return

        # Build payload
        payload, error = self._build_payload()
        if error:
            self.logger.fail(error)
            return

        # Build MQTT 5.0 properties if specified
        properties = self._build_publish_properties()

        # Log if auto-upgraded to MQTT 5.0
        if properties:
            self.logger.debug("Auto-upgraded to MQTT 5.0 (properties specified)")

        # Call combined subscribe-publish-listen
        qos = getattr(self.args, "qos", 0)
        retain = getattr(self.args, "retain", False)
        result = self.scanner.publish_and_listen(
            self.conn,
            publish_topic,
            payload,
            qos,
            retain,
            subscribe_topics=subscribe_topics,
            properties=properties,
        )
        self.results["data"]["publish_and_listen"] = result

    def _handle_publish(self) -> bool:
        """Handle MQTT publish only (no listen).

        Returns:
            True if publish was requested (handled), False otherwise.
        """
        if not self._has_publish_request():
            return False

        # Safety check
        if not getattr(self.args, "confirm", False):
            self.logger.fail("Publish requires --confirm flag")
            return True

        # Get topic
        topic = getattr(self.args, "topics", None)
        if not topic or topic == "#":
            self.logger.fail("Publish requires -t TOPIC (not wildcard)")
            return True

        if not self.conn:
            self.logger.fail("Cannot publish without connection")
            return True

        # Build payload
        payload, error = self._build_payload()
        if error:
            self.logger.fail(error)
            return True

        # Build MQTT 5.0 properties if specified
        properties = self._build_publish_properties()

        # Log if auto-upgraded to MQTT 5.0
        if properties:
            self.logger.debug("Auto-upgraded to MQTT 5.0 (properties specified)")

        # Publish
        qos = getattr(self.args, "qos", 0)
        retain = getattr(self.args, "retain", False)
        result = self.scanner.publish_message(
            self.conn, topic, payload, qos, retain, properties=properties
        )
        self.results["data"]["publish"] = result

        return True

    def _should_run_scan(self) -> bool:
        """Check if enumeration/scan should run (for publish+scan combo)."""
        # Run scan if any enumeration flags are set
        return (
            getattr(self.args, "enumerate", False)
            or getattr(self.args, "enumerate_common", False)
            or getattr(self.args, "default_creds", False)
            or getattr(self.args, "listen", False)
            or getattr(self.args, "fuzz", False)
        )

    def _should_continue_after_version_enum(self) -> bool:
        """Check if we should continue after version enumeration.

        Returns False if -P was the only action requested.
        """
        return (
            getattr(self.args, "enumerate", False)
            or getattr(self.args, "enumerate_common", False)
            or getattr(self.args, "default_creds", False)
            or getattr(self.args, "listen", False)
            or getattr(self.args, "fuzz", False)
            or self._has_publish_request()
        )

    def _handle_fuzz(self):
        """Handle MQTT publish fuzzing"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail("--fuzz requires --confirm flag (publishes to topics)")
            return

        if not self.conn:
            self.logger.fail("Cannot fuzz without connection")
            return

        iterations = getattr(self.args, "fuzz_iterations", 20)

        # Determine topics to fuzz
        fuzz_topics_str = getattr(self.args, "fuzz_topics", "")
        if fuzz_topics_str:
            topics = [t.strip() for t in fuzz_topics_str.split(",") if t.strip()]
        else:
            # Use discovered topics from scan
            topics = list(self.scanner.topics_discovered)

        if not topics:
            self.logger.warning("No topics available for fuzzing")
            return

        self.logger.display(
            f"Starting publish fuzzing on {len(topics)} topic(s) with {iterations} payloads each..."
        )

        # Call scanner's fuzz method
        fuzz_results = self.scanner.fuzz_publish_payloads(self.conn, topics, iterations)

        # Report results
        self.logger.display("\nFuzzing complete:")
        self.logger.display(f"  Payloads tested: {fuzz_results['tested']}")
        self.logger.display(f"  Successfully published: {fuzz_results['published']}")
        if fuzz_results["errors"]:
            self.logger.warning(f"  Errors: {len(fuzz_results['errors'])}")

        self.results["data"]["fuzz_results"] = fuzz_results

    def cleanup(self):
        """Cleanup MQTT connection"""
        if self.conn:
            try:
                self.scanner.disconnect(self.conn)
                self.logger.debug("MQTT connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing connection: {e}")
            finally:
                self.conn = None  # Prevent duplicate cleanup

    @staticmethod
    def check_dependencies() -> bool:
        return not dependencies_missing
