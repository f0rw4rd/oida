#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MQTT Protocol Scanner for OIDA

Supports:
- Broker discovery and version detection
- Anonymous authentication testing
- Password authentication and brute-force
- TLS with client certificate support
- Topic enumeration (including $SYS and Sparkplug B)
- Continuous listen mode
- Message interception and logging
"""

import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Any, Set

from ...utils import (
    register_protocol,
    create_protocol_module,
    NetworkScanner,
    parse_bool,
)


# Default wordlist paths (searched in order, platform-aware)
def _get_default_wordlist_paths():
    from ...utils.platform_compat import get_config_search_paths

    return [p / "default_credentials.txt" for p in get_config_search_paths("mqtt/wordlists")]


DEFAULT_WORDLIST_PATHS = _get_default_wordlist_paths()

# Common MQTT topics for bruteforce enumeration (when wildcards are restricted)
# Organized by protocol/platform - 100 most common ICS/IoT patterns
COMMON_TOPICS = [
    # === Mosquitto $SYS (Broker Internals) ===
    "$SYS/#",
    "$SYS/broker/version",
    "$SYS/broker/uptime",
    "$SYS/broker/clients/connected",
    "$SYS/broker/clients/total",
    "$SYS/broker/messages/received",
    "$SYS/broker/messages/sent",
    "$SYS/broker/bytes/received",
    "$SYS/broker/subscriptions/count",
    "$SYS/broker/retained messages/count",
    "$SYS/broker/heap/current size",
    "$SYS/broker/load/messages/received/1min",
    # === Sparkplug B (ICS/SCADA Standard) ===
    "spBv1.0/#",
    "spBv1.0/+/NBIRTH/#",  # Edge node birth
    "spBv1.0/+/NDEATH/#",  # Edge node death (LWT)
    "spBv1.0/+/NDATA/#",  # Node telemetry
    "spBv1.0/+/NCMD/#",  # Node commands
    "spBv1.0/+/DBIRTH/#",  # Device birth
    "spBv1.0/+/DDEATH/#",  # Device death
    "spBv1.0/+/DDATA/#",  # Device telemetry
    "spBv1.0/+/DCMD/#",  # Device commands
    "STATE/#",  # SCADA host state
    # === Homie Convention (v5.0) ===
    "homie/#",
    "homie/5/+/$state",
    "homie/5/+/$description",
    "homie/5/+/+/+",  # property values
    "homie/5/+/+/+/set",  # property commands
    "homie/5/$broadcast/#",
    "homie/5/+/$log/#",
    # === OPC UA PubSub ===
    "opcua/#",
    "opcua/json/data/#",
    "opcua/uadp/data/#",
    "opcua/json/status/#",
    "opcua/json/connection/#",
    # === AWS IoT Core ===
    "$aws/#",
    "$aws/things/+/shadow/update",
    "$aws/things/+/shadow/update/delta",
    "$aws/things/+/shadow/get",
    "$aws/things/+/jobs/notify",
    "$aws/things/+/defender/metrics/json",
    "$aws/certificates/create/json",
    "$aws/events/presence/connected/#",
    "$aws/events/presence/disconnected/#",
    "$aws/rules/#",
    "dt/#",  # AWS telemetry prefix
    # === Azure IoT Hub ===
    "$iothub/#",
    "$iothub/twin/PATCH/properties/reported/#",
    "$iothub/twin/PATCH/properties/desired/#",
    "$iothub/twin/GET/#",
    "$iothub/methods/POST/#",
    "$iothub/methods/res/#",
    "devices/+/messages/events/",
    "devices/+/messages/devicebound/#",
    "devices/+/modules/+/messages/events/",
    # === Home Assistant Discovery ===
    "homeassistant/#",
    "homeassistant/sensor/+/+/config",
    "homeassistant/switch/+/+/config",
    "homeassistant/light/+/+/config",
    "homeassistant/binary_sensor/+/+/config",
    "homeassistant/climate/+/+/config",
    "homeassistant/status",
    # === OwnTracks (GPS location tracking) ===
    "owntracks/#",
    "owntracks/+/+",  # owntracks/{user}/{device}
    "owntracks/+/+/event",  # Location events
    "owntracks/+/+/step",  # Step counter
    "owntracks/+/+/waypoint",  # Saved locations
    "owntracks/+/+/cmd",  # Commands to device
    # === Zigbee2MQTT ===
    "zigbee2mqtt/#",
    "zigbee2mqtt/+",
    "zigbee2mqtt/+/set",
    "zigbee2mqtt/+/get",
    "zigbee2mqtt/+/availability",
    "zigbee2mqtt/bridge/state",
    "zigbee2mqtt/bridge/devices",
    "zigbee2mqtt/bridge/logging",
    "zigbee2mqtt/bridge/request/#",
    # === Tasmota/Sonoff (credential extraction targets) ===
    "cmnd/#",
    "cmnd/+/POWER",
    "cmnd/+/RESULT",  # Captures command responses
    "cmnd/+/Status",  # Device status with firmware info
    "cmnd/+/Status0",  # Full status dump
    "cmnd/+/MqttUser",  # MQTT credentials
    "cmnd/+/MqttPassword",
    "cmnd/+/MqttHost",
    "cmnd/+/WebPassword",  # Web UI password
    "cmnd/+/SSId1",  # WiFi credentials
    "cmnd/+/Password1",
    "stat/#",
    "stat/+/POWER",
    "stat/+/RESULT",
    "stat/+/STATUS",  # Status responses
    "tele/#",
    "tele/+/STATE",
    "tele/+/SENSOR",
    "tele/+/LWT",
    "tele/+/INFO1",  # Device info
    "tele/+/INFO2",
    "tele/+/INFO3",
    "tasmota/discovery/#",
    # === Shelly Devices ===
    "shellies/#",
    "shellies/+/relay/#",
    "shellies/+/online",
    "shellies/announce",
    # === MQTT 5.0 Shared Subscriptions ===
    "$share/#",
    "$queue/#",
    # === ICS/SCADA Protocols ===
    "plc/#",
    "scada/#",
    "modbus/#",
    "dnp3/#",
    "bacnet/#",
    "iec104/#",
    "iec61850/#",
    "profinet/#",
    "ethernetip/#",
    # === Industrial Vendors ===
    "siemens/#",
    "simatic/#",
    "s7/#",
    "rockwell/#",
    "allen-bradley/#",
    "ab/#",
    "schneider/#",
    "modicon/#",
    "abb/#",
    "honeywell/#",
    "emerson/#",
    "ge/#",
    "omron/#",
    "mitsubishi/#",
    "beckhoff/#",
    "twincat/#",
    "ads/#",
    "codesys/#",
    "wago/#",
    "phoenix/#",
    # === Generic Telemetry/Command Patterns ===
    "telemetry/#",
    "telemetry/+/+",
    "data/#",
    "data/+/+",
    "sensors/#",
    "sensor/+/+",
    "cmd/#",
    "command/#",
    "control/#",
    "request/#",
    "response/#",
    "status/#",
    "availability/#",
    "event/#",
    "events/#",
    "alarm/#",
    "alarms/#",
    "alert/#",
    # === Building/Energy ===
    "building/#",
    "hvac/#",
    "lighting/#",
    "energy/#",
    "power/#",
    "meter/#",
    # === Generic Discovery ===
    "test/#",
    "demo/#",
    "public/#",
]

# Default credentials for IoT/MQTT brute force
# Sources: Mirai botnet, MQTT-PWN, common IoT defaults
DEFAULT_CREDENTIALS = [
    # High-priority: Most common IoT defaults
    ("root", "root"),
    ("admin", "admin"),
    ("root", "admin"),
    ("admin", "password"),
    ("root", "password"),
    ("admin", "1234"),
    ("root", "12345"),
    ("admin", "12345"),
    ("root", "123456"),
    ("admin", "123456"),
    ("user", "user"),
    ("guest", "guest"),
    # Mirai botnet credentials (most effective)
    ("root", "xc3511"),
    ("root", "vizxv"),
    ("root", "888888"),
    ("root", "xmhdipc"),
    ("root", "default"),
    ("root", "jauntech"),
    ("root", "54321"),
    ("support", "support"),
    ("root", ""),
    ("admin", ""),
    ("root", "pass"),
    ("admin", "admin1234"),
    ("root", "1111"),
    ("admin", "smcadmin"),
    ("admin", "1111"),
    ("root", "666666"),
    ("root", "1234"),
    ("root", "klv123"),
    ("Administrator", "admin"),
    ("service", "service"),
    ("supervisor", "supervisor"),
    ("guest", "12345"),
    ("admin1", "password"),
    ("administrator", "1234"),
    ("666666", "666666"),
    ("888888", "888888"),
    ("ubnt", "ubnt"),
    ("root", "klv1234"),
    ("root", "Zte521"),
    ("root", "hi3518"),
    ("root", "jvbzd"),
    ("root", "anko"),
    ("root", "zlxx."),
    ("root", "7ujMko0vizxv"),
    ("root", "7ujMko0admin"),
    ("root", "system"),
    ("root", "ikwb"),
    ("root", "dreambox"),
    ("root", "user"),
    ("root", "realtek"),
    ("root", "000000"),
    ("admin", "1111111"),
    ("admin", "54321"),
    ("admin", "7ujMko0admin"),
    ("admin", "pass"),
    ("admin", "meinsm"),
    ("tech", "tech"),
    # MQTT-specific defaults
    ("mqtt", "mqtt"),
    ("mosquitto", "mosquitto"),
    ("broker", "broker"),
    ("emqx", "public"),
    ("hivemq", "hivemq"),
    ("rabbitmq", "rabbitmq"),
    # ICS/SCADA common defaults
    ("operator", "operator"),
    ("ics", "ics123"),
    ("scada", "scada"),
    ("plc", "plc"),
    ("hmi", "hmi"),
    ("engineer", "engineer"),
    ("maintenance", "maintenance"),
    ("technician", "technician"),
    ("siemens", "siemens"),
    ("rockwell", "rockwell"),
    ("schneider", "schneider"),
    ("abb", "abb"),
    # Additional common passwords with root/admin
    ("root", "toor"),
    ("admin", "nimda"),
    ("root", "alpine"),
    ("admin", "admin123"),
    ("root", "root123"),
    ("admin", "changeme"),
    ("root", "changeme"),
    ("admin", "letmein"),
    ("root", "qwerty"),
    ("admin", "qwerty"),
    ("pi", "raspberry"),
    ("debian", "debian"),
]

# Lazy imports for paho-mqtt dependency
from ...utils.lazy_import import lazy_import

paho_client = lazy_import("paho.mqtt.client", "MQTT", install_hint="pip install oida-ics[mqtt]")
paho_enums = lazy_import("paho.mqtt.enums", "MQTT", install_hint="pip install oida-ics[mqtt]")
paho_properties = lazy_import(
    "paho.mqtt.properties", "MQTT", install_hint="pip install oida-ics[mqtt]"
)
paho_packettypes = lazy_import(
    "paho.mqtt.packettypes", "MQTT", install_hint="pip install oida-ics[mqtt]"
)

# Backward compatibility flag
dependencies_missing = not paho_client.is_available


@dataclass
class MQTTMessage:
    """Captured MQTT message"""

    topic: str
    payload: bytes
    qos: int
    retain: bool
    timestamp: float = field(default_factory=time.time)

    def payload_str(self) -> str:
        try:
            return self.payload.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            return self.payload.hex()


@dataclass
class ListenStats:
    """Statistics for listen mode"""

    start_time: float = field(default_factory=time.time)
    message_count: int = 0
    topics_seen: Set[str] = field(default_factory=set)
    bytes_received: int = 0
    retained_count: int = 0
    messages: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return time.time() - self.start_time

    @property
    def rate(self) -> float:
        return self.message_count / self.duration if self.duration > 0 else 0.0


protocol_options = {
    "username": {
        "type": "string",
        "description": "MQTT username for authentication",
        "required": False,
        "default": "",
    },
    "password": {
        "type": "string",
        "description": "MQTT password for authentication",
        "required": False,
        "default": "",
    },
    "client-id": {
        "type": "string",
        "description": "MQTT client ID",
        "required": False,
        "default": "",
    },
    "protocol-version": {
        "type": "int",
        "description": "MQTT protocol version: 3=3.1, 4=3.1.1, 5=5.0",
        "required": False,
        "default": 4,
    },
    "tls": {
        "type": "bool",
        "description": "Enable TLS encryption",
        "required": False,
        "default": False,
    },
    "tls-cert": {
        "type": "string",
        "description": "Path to client certificate file",
        "required": False,
        "default": "",
    },
    "tls-key": {
        "type": "string",
        "description": "Path to client private key file",
        "required": False,
        "default": "",
    },
    "tls-ca": {
        "type": "string",
        "description": "Path to CA certificate file",
        "required": False,
        "default": "",
    },
    "tls-insecure": {
        "type": "bool",
        "description": "Skip TLS certificate verification",
        "required": False,
        "default": False,
    },
    "topics": {
        "type": "string",
        "description": "Topic pattern to subscribe (default: #)",
        "required": False,
        "default": "#",
    },
    "enumerate": {
        "type": "bool",
        "description": "Enable topic enumeration ($SYS, wildcard #)",
        "required": False,
        "default": False,
    },
    "enumerate-common": {
        "type": "bool",
        "description": "Bruteforce common ICS/IoT topics (useful when # is blocked)",
        "required": False,
        "default": False,
    },
    "topic-list": {
        "type": "string",
        "description": "Custom topic list file (one topic per line)",
        "required": False,
        "default": "",
    },
    "timeout": {
        "type": "int",
        "description": "Topic enumeration timeout in seconds",
        "required": False,
        "default": 10,
    },
    "brute": {
        "type": "bool",
        "description": "Enable credential brute-force",
        "required": False,
        "default": False,
    },
    "wordlist": {
        "type": "string",
        "description": "Path to password wordlist",
        "required": False,
        "default": "",
    },
    "credentials": {
        "type": "string",
        "description": "Path to user:pass credentials file",
        "required": False,
        "default": "",
    },
    "brute-rate": {
        "type": "float",
        "description": "Delay between auth attempts in seconds",
        "required": False,
        "default": 0,
    },
    "continue-on-success": {
        "type": "bool",
        "description": "Keep testing credentials after the first valid hit (default: stop on first success)",
        "required": False,
        "default": False,
    },
    "listen": {
        "type": "bool",
        "description": "Enable continuous listen mode",
        "required": False,
        "default": False,
    },
    "listen-output": {
        "type": "string",
        "description": "Output file for listen mode (JSON lines)",
        "required": False,
        "default": "",
    },
    "unique": {
        "type": "bool",
        "description": "Only show unique topics (filter duplicate messages)",
        "required": False,
        "default": False,
    },
}


# Import mixins (after module-level data so mixins can reference them)
from .mixins import ConnectionMixin, TopicDiscoveryMixin, AuthMixin, MessagingMixin, SecurityMixin


@register_protocol(
    name="MQTT Scanner",
    description="MQTT broker scanner with topic enumeration and Sparkplug B support",
    default_port=1883,
    authors=["f0rw4rd"],
    references=[
        {"type": "url", "ref": "https://mqtt.org"},
        {"type": "url", "ref": "https://sparkplug.eclipse.org"},
        {"type": "url", "ref": "https://owasp.org/www-project-mqtt-guide/"},
    ],
    protocol_options=protocol_options,
)
class MQTTScanner(
    ConnectionMixin,
    TopicDiscoveryMixin,
    AuthMixin,
    MessagingMixin,
    SecurityMixin,
    NetworkScanner,
):
    """MQTT Scanner implementing the base scanner interface"""

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)

        # Authentication
        self.username = args.get("username", "")
        self.password = args.get("password", "")
        self.client_id = args.get("client-id", "")

        # Protocol version (3=3.1, 4=3.1.1, 5=5.0)
        self.protocol_version = int(args.get("protocol-version", 4))

        # TLS settings (cert/key/ca/insecure are read from self.args via
        # build_tls_context() at connect time, not stored as attributes)
        self.use_tls = parse_bool(args.get("tls", False))

        # Topic enumeration - only when -e/--enumerate is set
        self.topics_pattern = args.get("topics", "#")
        self.enumerate = parse_bool(args.get("enumerate", False))
        self.enumerate_sys = self.enumerate  # $SYS enumeration requires -e
        self.enumerate_sparkplug = self.enumerate  # Sparkplug enumeration requires -e
        self.enumerate_common = parse_bool(args.get("enumerate-common", False))
        self.topic_list_file = args.get("topic-list", "")
        self.timeout = int(args.get("timeout", 10))

        # Brute-force
        # Support "brute", "default_creds", and "default-creds" (CLI -D flag converts underscore to hyphen)
        self.brute_enabled = (
            parse_bool(args.get("brute", False))
            or parse_bool(args.get("default_creds", False))
            or parse_bool(args.get("default-creds", False))
        )
        self.wordlist_path = args.get("wordlist", "")
        self.credentials_path = args.get("credentials", "")
        self.brute_rate = float(args.get("brute-rate", 0))
        self.continue_on_success = parse_bool(args.get("continue-on-success", False))

        # Listen mode
        self.listen_mode = parse_bool(args.get("listen", False))
        self.listen_output = args.get("listen-output") or args.get("listen_output") or ""
        self.unique_only = parse_bool(args.get("unique", False))
        # Listen duration: --listen-time/-T controls how long listen mode runs
        # (falls back to --timeout when not provided). 0 = listen forever.
        listen_time = args.get("listen-time")
        if listen_time is None:
            listen_time = args.get("listen_time")
        self.listen_time = int(listen_time) if listen_time is not None else self.timeout

        # Load topics - check if it's a file path first
        topics_arg = args.get("topics", "#")
        if topics_arg and Path(topics_arg).exists():
            self.topics_from_file = True
            self.topics_file = topics_arg
            with open(topics_arg) as f:
                self.topics_list = [
                    line.strip() for line in f if line.strip() and not line.startswith("#")
                ]
            # Use first topic as pattern if single, otherwise subscribe to all
            self.topics_pattern = self.topics_list[0] if len(self.topics_list) == 1 else "#"
        else:
            self.topics_from_file = False
            self.topics_file = ""
            self.topics_pattern = topics_arg
            self.topics_list = [topics_arg] if topics_arg else ["#"]

        # Internal state
        self.topics_discovered: Set[str] = set()
        self.auth_result = None
        self._stop_listen = False

    def get_protocol_name(self) -> str:
        return "MQTT"

    def get_default_port(self) -> int:
        return 8883 if getattr(self, "use_tls", False) else 1883

    def check_dependencies(self) -> bool:
        if not paho_client.is_available:
            self.logger.fail(
                "paho-mqtt library required. Install with: pip install oida-ics[mqtt]"
            )
            return False
        return True

    def connect(self) -> Any:
        """Establish MQTT connection using configured credentials"""
        self.check_dependencies()

        client = self._create_mqtt_client(self.username, self.password, "main")
        connect_result = {"connected": False, "reason": None}

        def on_connect(cli, userdata, flags, reason_code, properties):
            connect_result["connected"] = reason_code == 0
            connect_result["reason"] = str(reason_code)

        client.on_connect = on_connect

        cert_checked = False
        try:
            t_start = time.time()
            version_names = {3: "3.1", 4: "3.1.1", 5: "5.0"}
            ver = version_names.get(self.protocol_version, str(self.protocol_version))
            self.logger.debug(
                f"connect() to {self.host}:{self.port} (TLS={self.use_tls}, MQTT {ver})"
            )
            client.connect(self.host, self.port, keepalive=30)

            # Use sync loop (faster than loop_start/loop_stop)
            connect_timeout = self.timeout if self.timeout > 0 else 5
            start = time.time()
            while time.time() - start < connect_timeout:
                try:
                    client.loop(timeout=0.05)
                except (IndexError, KeyError):
                    # MQTT 5.0 client receiving a MQTT 3.x CONNACK causes
                    # IndexError/KeyError in paho's packet parsing.
                    # This means the server does not support MQTT 5.0.
                    if self.protocol_version == 5:
                        self.logger.fail(
                            "Server does not support MQTT 5.0 (sent 3.x response). "
                            "Try -V 4 for MQTT 3.1.1"
                        )
                        self.auth_result = "error: server does not support MQTT 5.0"
                        return None
                    raise

                # Check TLS certificate after first loop iteration (handshake should be done)
                # Do this BEFORE connection closes due to auth failure
                if self.use_tls and not cert_checked:
                    self._check_tls_certificate(client)
                    cert_checked = True

                if connect_result["connected"] or connect_result["reason"]:
                    break

            elapsed = time.time() - t_start
            self.logger.debug(f"connect() {elapsed:.3f}s result={connect_result['reason']}")

            if not connect_result["connected"]:
                self.auth_result = connect_result["reason"]
                return None

            return client

        except Exception as e:
            self.logger.debug(f"connect() exception: {e}")
            self.auth_result = f"error: {e}"
            return None

    def disconnect(self, conn: Any) -> None:
        """Disconnect from MQTT broker"""
        if conn:
            try:
                conn.loop_stop()
                conn.disconnect()
            except Exception as e:
                self.logger.debug(f"conn.loop_stop(): {e}")

    def discover(self, conn: Any) -> Dict[str, Any]:
        """Main discovery workflow"""
        results = {
            "broker_info": {},
            "auth": {},
            "protocol_versions": {},
            "topics": [],
            "sparkplug": {},
            "common_topics": {},
            "messages": [],
            "security_issues": [],
        }

        if not conn:
            # Check if it was a connection error vs auth error
            if self.auth_result and self.auth_result.startswith("error:"):
                # True connection error - don't try anonymous or brute-force
                results["auth"] = {
                    "connection_error": True,
                    "error": self.auth_result[7:],  # Remove "error: " prefix
                }
                return results

            # Connection failed due to auth - check if we already tested anonymous
            if not self.username and self.auth_result:
                # Already tested anonymous in connect(), don't test again
                results["auth"] = {
                    "anonymous_allowed": False,
                    "requires_auth": True,
                    "connack_code": self.auth_result,
                }
            else:
                # Test anonymous access explicitly
                results["auth"] = self._test_anonymous_auth()

            if not results["auth"].get("anonymous_allowed"):
                # Try brute-force if enabled
                if self.brute_enabled:
                    if not self.args.get("confirm", False):
                        self.logger.fail(
                            "--brute / --default-creds runs credential brute-force "
                            "(trips broker lockout / IDS) — requires --confirm"
                        )
                    else:
                        results["auth"]["brute_results"] = self._brute_force_credentials()
                return results

            # Reconnect for enumeration. This client is created locally and is
            # not tracked by the connection wrapper's cleanup(), so we own its
            # lifecycle and must disconnect it ourselves (see finally below).
            conn = self.connect()
            if not conn:
                return results
            owns_conn = True
        else:
            # Connected - only mark anonymous if no credentials were provided
            results["auth"]["anonymous_allowed"] = not bool(self.username)
            owns_conn = False

        try:
            # Run brute-force if enabled (even when anonymous works, to find additional creds)
            if self.brute_enabled:
                if not self.args.get("confirm", False):
                    self.logger.fail(
                        "--brute / --default-creds runs credential brute-force "
                        "(trips broker lockout / IDS) — requires --confirm"
                    )
                else:
                    results["auth"]["brute_results"] = self._brute_force_credentials()

            # Enumerate broker info via $SYS (requires -e)
            if self.enumerate_sys:
                results["broker_info"] = self._enumerate_sys_topics(conn)

            # Enumerate topics (requires -e)
            if self.enumerate:
                results["topics"] = self._enumerate_topics(conn)

            # Enumerate Sparkplug B (included in -e)
            if self.enumerate:
                results["sparkplug"] = self._enumerate_sparkplug(conn)

            # Enumerate common topics (bruteforce when wildcards are blocked)
            # Auto-enable if custom topic list file is provided
            if self.enumerate_common or self.topic_list_file:
                results["common_topics"] = self._enumerate_common_topics(conn)

            # Listen mode
            if self.listen_mode:
                results["listen_stats"] = self._run_listen_mode(conn)

            # Security analysis
            results["security_issues"] = self._analyze_security(results)
        finally:
            # Close the client we opened here for enumeration. The client passed
            # in by the caller is disconnected by the caller's cleanup().
            if owns_conn:
                self.disconnect(conn)

        return results


# Create protocol module exports
metadata, run = create_protocol_module(MQTTScanner)
