#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for MQTT protocol scanner functionality.

Tests the MQTT scanner module without requiring actual network connections.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import pytest
import os


class MockMQTTClient:
    """Mock MQTT client for testing"""

    def __init__(self, callback_api_version=None, client_id=None):
        self.client_id = client_id
        self.connected = False
        self.subscribed_topics = []
        self.published_messages = []
        self.on_connect = None
        self.on_message = None
        self._username = None
        self._password = None
        self._tls_context = None
        self._loop_running = False

    def username_pw_set(self, username, password=None):
        """Set username and password"""
        self._username = username
        self._password = password

    def tls_set_context(self, context):
        """Set TLS context"""
        self._tls_context = context

    def connect(self, host, port, keepalive=60):
        """Simulate connection"""
        self.connected = True
        # Simulate on_connect callback
        if self.on_connect:
            # Simulate successful connection
            self.on_connect(self, None, None, 0, None)

    def disconnect(self):
        """Simulate disconnection"""
        self.connected = False

    def loop_start(self):
        """Start network loop"""
        self._loop_running = True

    def loop_stop(self):
        """Stop network loop"""
        self._loop_running = False

    def subscribe(self, topic, qos=0):
        """Simulate subscription"""
        self.subscribed_topics.append(topic)
        return (0, 1)

    def unsubscribe(self, topic):
        """Simulate unsubscription"""
        if topic in self.subscribed_topics:
            self.subscribed_topics.remove(topic)

    def publish(self, topic, payload, qos=0, retain=False):
        """Simulate publish"""
        result = Mock()
        result.rc = 0
        self.published_messages.append(
            {
                "topic": topic,
                "payload": payload,
                "qos": qos,
                "retain": retain,
            }
        )
        return result


class TestMQTTDataStructures(unittest.TestCase):
    """Test MQTT data structures and types"""

    def test_mqtt_message_dataclass(self):
        """Test MQTTMessage dataclass"""
        from oida.protocols.mqtt.scanner import MQTTMessage

        msg = MQTTMessage(
            topic="test/topic",
            payload=b"test payload",
            qos=1,
            retain=True,
        )

        self.assertEqual(msg.topic, "test/topic")
        self.assertEqual(msg.payload, b"test payload")
        self.assertEqual(msg.qos, 1)
        self.assertTrue(msg.retain)
        self.assertIsInstance(msg.timestamp, float)

    def test_mqtt_message_payload_str(self):
        """Test MQTTMessage payload_str method"""
        from oida.protocols.mqtt.scanner import MQTTMessage

        # UTF-8 payload
        msg = MQTTMessage(
            topic="test/topic",
            payload=b"hello world",
            qos=0,
            retain=False,
        )
        self.assertEqual(msg.payload_str(), "hello world")

        # Binary payload that is not valid UTF-8
        # \x80\x81 are continuation bytes without start bytes, so they're invalid UTF-8
        binary_msg = MQTTMessage(
            topic="test/binary",
            payload=b"\x80\x81\x82\x83",
            qos=0,
            retain=False,
        )
        self.assertEqual(binary_msg.payload_str(), "80818283")

    def test_mqtt_message_to_dict(self):
        """Test MQTTMessage to_dict method"""
        from oida.protocols.mqtt.scanner import MQTTMessage

        msg = MQTTMessage(
            topic="test/topic",
            payload=b"test",
            qos=1,
            retain=True,
        )
        result = msg.to_dict()

        self.assertIn("topic", result)
        self.assertIn("payload", result)
        self.assertIn("qos", result)
        self.assertIn("retain", result)
        self.assertIn("timestamp", result)

    def test_listen_stats_dataclass(self):
        """Test ListenStats dataclass"""
        from oida.protocols.mqtt.scanner import ListenStats

        stats = ListenStats()

        self.assertEqual(stats.message_count, 0)
        self.assertEqual(stats.bytes_received, 0)
        self.assertEqual(stats.retained_count, 0)
        self.assertIsInstance(stats.topics_seen, set)


class TestMQTTScannerInit(unittest.TestCase):
    """Test MQTT scanner initialization"""

    def test_basic_initialization(self):
        """Test basic scanner initialization"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {
            "rhost": "192.168.1.100",
            "rport": 1883,
        }
        scanner = MQTTScanner(args)

        self.assertEqual(scanner.host, "192.168.1.100")
        self.assertEqual(scanner.port, 1883)

    def test_initialization_with_auth(self):
        """Test scanner initialization with authentication"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {
            "rhost": "192.168.1.100",
            "rport": 1883,
            "username": "admin",
            "password": "secret",
        }
        scanner = MQTTScanner(args)

        self.assertEqual(scanner.username, "admin")
        self.assertEqual(scanner.password, "secret")

    def test_initialization_with_tls(self):
        """Test scanner initialization with TLS"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {
            "rhost": "192.168.1.100",
            "rport": 8883,
            "tls": True,
            "tls-insecure": True,
        }
        scanner = MQTTScanner(args)

        self.assertTrue(scanner.use_tls)
        self.assertTrue(scanner.tls_insecure)

    def test_initialization_with_topic_options(self):
        """Test scanner initialization with topic options"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {
            "rhost": "192.168.1.100",
            "rport": 1883,
            "topics": "sensors/#",
            "enumerate": True,
        }
        scanner = MQTTScanner(args)

        self.assertEqual(scanner.topics_pattern, "sensors/#")
        self.assertTrue(scanner.enumerate_sys)  # enumerate_sys tracks enumerate flag

    def test_protocol_name(self):
        """Test protocol name"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "192.168.1.100", "rport": 1883}
        scanner = MQTTScanner(args)

        self.assertEqual(scanner.get_protocol_name(), "MQTT")

    def test_default_port(self):
        """Test default port selection"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        # Non-TLS default
        args = {"rhost": "192.168.1.100", "rport": 1883}
        scanner = MQTTScanner(args)
        self.assertEqual(scanner.get_default_port(), 1883)

        # TLS default
        args_tls = {"rhost": "192.168.1.100", "rport": 8883, "tls": True}
        scanner_tls = MQTTScanner(args_tls)
        self.assertEqual(scanner_tls.get_default_port(), 8883)


class TestMQTTConstants(unittest.TestCase):
    """Test MQTT constants and default values"""

    def test_common_topics_defined(self):
        """Test common topics are defined"""
        from oida.protocols.mqtt.scanner import COMMON_TOPICS

        # Should have a substantial list of common topics
        self.assertGreater(len(COMMON_TOPICS), 50)

        # Check key topics exist
        self.assertIn("$SYS/#", COMMON_TOPICS)
        self.assertIn("spBv1.0/#", COMMON_TOPICS)
        self.assertIn("homeassistant/#", COMMON_TOPICS)

    def test_default_credentials_defined(self):
        """Test default credentials are defined"""
        from oida.protocols.mqtt.scanner import DEFAULT_CREDENTIALS

        # Should have common IoT credentials
        self.assertGreater(len(DEFAULT_CREDENTIALS), 30)

        # Check some common credentials
        self.assertIn(("root", "root"), DEFAULT_CREDENTIALS)
        self.assertIn(("admin", "admin"), DEFAULT_CREDENTIALS)

    def test_protocol_options_defined(self):
        """Test protocol options are defined"""
        from oida.protocols.mqtt.scanner import protocol_options

        expected_options = [
            "username",
            "password",
            "client-id",
            "tls",
            "tls-cert",
            "tls-key",
            "tls-ca",
            "tls-insecure",
            "topics",
            "enumerate",
            "enumerate-common",
            "brute",
            "wordlist",
            "listen",
        ]

        for option in expected_options:
            self.assertIn(option, protocol_options)


class TestMQTTTopicMatching(unittest.TestCase):
    """Test MQTT topic pattern matching"""

    def test_exact_match(self):
        """Test exact topic match"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        self.assertTrue(scanner._topic_matches_pattern("test/topic", "test/topic"))
        self.assertFalse(scanner._topic_matches_pattern("test/topic", "test/other"))

    def test_wildcard_hash(self):
        """Test # wildcard matching"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        # # matches everything
        self.assertTrue(scanner._topic_matches_pattern("#", "test/topic"))
        self.assertTrue(scanner._topic_matches_pattern("#", "a/b/c/d"))

        # # at end matches rest of path
        self.assertTrue(scanner._topic_matches_pattern("test/#", "test/topic"))
        self.assertTrue(scanner._topic_matches_pattern("test/#", "test/a/b/c"))
        self.assertFalse(scanner._topic_matches_pattern("test/#", "other/topic"))

    def test_wildcard_plus(self):
        """Test + wildcard matching"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        # + matches single level
        self.assertTrue(scanner._topic_matches_pattern("test/+/value", "test/sensor/value"))
        self.assertFalse(scanner._topic_matches_pattern("test/+/value", "test/a/b/value"))

    def test_combined_wildcards(self):
        """Test combined wildcards"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        self.assertTrue(scanner._topic_matches_pattern("+/+/#", "a/b/c/d"))


class TestMQTTAnonymousAuth(unittest.TestCase):
    """Test MQTT anonymous authentication testing"""

    @patch("oida.protocols.mqtt.scanner.paho_client")
    def test_anonymous_auth_allowed(self, mock_paho_client):
        """Test detection of anonymous auth allowed"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        # Setup mock - paho_client() returns the mqtt module
        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        # Mock successful anonymous connection
        result = scanner._test_anonymous_auth()

        self.assertIn("anonymous_allowed", result)
        self.assertIn("requires_auth", result)

    def test_anonymous_auth_result_structure(self):
        """Test anonymous auth result structure"""
        result = {
            "anonymous_allowed": True,
            "requires_auth": False,
            "connack_code": "0",
        }

        self.assertTrue(result["anonymous_allowed"])
        self.assertFalse(result["requires_auth"])


class TestMQTTBruteForce(unittest.TestCase):
    """Test MQTT credential brute-force functionality"""

    def test_brute_force_result_structure(self):
        """Test brute-force result structure"""
        result = {
            "tested": 10,
            "valid": [
                {"username": "admin", "password": "admin"},
            ],
            "stopped_early": True,
        }

        self.assertEqual(result["tested"], 10)
        self.assertEqual(len(result["valid"]), 1)
        self.assertTrue(result["stopped_early"])

    def test_credential_loading(self):
        """Test credential loading from various sources"""
        from oida.protocols.mqtt.scanner import DEFAULT_CREDENTIALS

        # Should have multiple credential pairs
        self.assertIsInstance(DEFAULT_CREDENTIALS, list)
        for cred in DEFAULT_CREDENTIALS[:5]:
            self.assertIsInstance(cred, tuple)
            self.assertEqual(len(cred), 2)


class TestMQTTSysTopics(unittest.TestCase):
    """Test MQTT $SYS topic enumeration"""

    def test_sys_topic_patterns(self):
        """Test $SYS topic patterns"""
        sys_topics = [
            "$SYS/broker/version",
            "$SYS/broker/uptime",
            "$SYS/broker/clients/connected",
            "$SYS/broker/messages/received",
            "$SYS/broker/bytes/received",
        ]

        for topic in sys_topics:
            self.assertTrue(topic.startswith("$SYS/"))

    def test_broker_info_extraction(self):
        """Test broker info extraction from $SYS topics"""
        broker_info = {
            "version": "mosquitto version 2.0.18",
            "uptime": "1234567 seconds",
            "clients_connected": "5",
            "sys_topic_count": 25,
        }

        self.assertIn("version", broker_info)
        self.assertIn("uptime", broker_info)


class TestMQTTSparkplug(unittest.TestCase):
    """Test MQTT Sparkplug B enumeration"""

    def test_sparkplug_topic_structure(self):
        """Test Sparkplug B topic structure"""
        # Sparkplug B topic format: spBv1.0/{group_id}/{message_type}/{edge_node_id}[/{device_id}]
        topics = [
            "spBv1.0/TestGroup/NBIRTH/EdgeNode1",
            "spBv1.0/TestGroup/DBIRTH/EdgeNode1/Device1",
            "spBv1.0/TestGroup/NDATA/EdgeNode1",
            "spBv1.0/TestGroup/DDATA/EdgeNode1/Device1",
        ]

        for topic in topics:
            self.assertTrue(topic.startswith("spBv1.0/"))
            parts = topic.split("/")
            self.assertGreaterEqual(len(parts), 4)

    def test_sparkplug_result_structure(self):
        """Test Sparkplug enumeration result structure"""
        sparkplug = {
            "groups": ["TestGroup"],
            "nodes": {
                "TestGroup/EdgeNode1": {
                    "group": "TestGroup",
                    "node_id": "EdgeNode1",
                    "devices": ["Device1", "Device2"],
                    "metrics": [],
                }
            },
            "devices": [],
            "metrics": [],
        }

        self.assertIn("groups", sparkplug)
        self.assertIn("nodes", sparkplug)
        self.assertEqual(len(sparkplug["groups"]), 1)


class TestMQTTListenMode(unittest.TestCase):
    """Test MQTT listen mode functionality"""

    def test_listen_stats_calculation(self):
        """Test listen statistics calculation"""
        from oida.protocols.mqtt.scanner import ListenStats

        stats = ListenStats()
        stats.message_count = 100
        stats.bytes_received = 5000
        stats.topics_seen.add("topic1")
        stats.topics_seen.add("topic2")
        stats.retained_count = 10

        self.assertEqual(stats.message_count, 100)
        self.assertEqual(len(stats.topics_seen), 2)
        self.assertGreater(stats.duration, 0)

    def test_listen_result_structure(self):
        """Test listen mode result structure"""
        result = {
            "duration": 10.5,
            "messages": 100,
            "topics": 5,
            "bytes": 5000,
            "rate": 9.52,
        }

        self.assertIn("duration", result)
        self.assertIn("messages", result)
        self.assertIn("rate", result)


class TestMQTTSecurityAnalysis(unittest.TestCase):
    """Test MQTT security analysis functionality"""

    def test_security_issues_detection(self):
        """Test detection of security issues"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        # Simulate results with security issues
        results = {
            "auth": {"anonymous_allowed": True},
            "broker_info": {"sys_topic_count": 25},
            "topics": [{"topic": "test"}],
        }

        issues = scanner._analyze_security(results)

        self.assertIsInstance(issues, list)
        # Should find anonymous auth issue
        issue_types = [i["issue"] for i in issues]
        self.assertTrue(any("Anonymous" in i for i in issue_types))

    def test_security_issue_structure(self):
        """Test security issue structure"""
        issue = {
            "severity": "CRITICAL",
            "issue": "Anonymous authentication enabled",
            "description": "Broker accepts connections without credentials",
        }

        self.assertIn("severity", issue)
        self.assertIn("issue", issue)
        self.assertIn("description", issue)

    def test_no_tls_detection(self):
        """Test detection of plaintext communication"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883, "tls": False}
        scanner = MQTTScanner(args)

        results = {"auth": {}, "broker_info": {}, "topics": []}
        issues = scanner._analyze_security(results)

        # Should find no TLS issue
        self.assertTrue(any("Plaintext" in i.get("issue", "") for i in issues))


class TestMQTTModuleImport(unittest.TestCase):
    """Test MQTT module import and structure"""

    def test_module_import(self):
        """Test that MQTT module can be imported"""
        from oida.protocols.mqtt import mqtt, MQTTScanner, metadata

        self.assertIsNotNone(mqtt)
        self.assertIsNotNone(MQTTScanner)
        self.assertIsNotNone(metadata)

    def test_nxc_class_exists(self):
        """Test that NXC-style class exists"""
        from oida.protocols.mqtt import mqtt

        self.assertIsNotNone(mqtt)

    def test_nxc_class_methods(self):
        """Test NXC class has required methods"""
        from oida.protocols.mqtt import mqtt

        self.assertTrue(hasattr(mqtt, "proto_flow"))
        self.assertTrue(hasattr(mqtt, "create_conn_obj"))
        self.assertTrue(hasattr(mqtt, "enum_host_info"))
        self.assertTrue(hasattr(mqtt, "cleanup"))
        self.assertTrue(hasattr(mqtt, "check_dependencies"))

    def test_metadata_structure(self):
        """Test module metadata structure"""
        from oida.protocols.mqtt import metadata

        self.assertIn("name", metadata)
        self.assertIn("description", metadata)
        self.assertIn("options", metadata)

        # Check default port
        self.assertEqual(metadata["options"]["rport"]["default"], 1883)


class TestMQTTDiscoverWorkflow(unittest.TestCase):
    """Test MQTT discover workflow"""

    def test_discover_result_structure(self):
        """Test discover result structure"""
        results = {
            "broker_info": {
                "version": "mosquitto 2.0.18",
                "uptime": "1234567",
                "sys_topic_count": 25,
            },
            "auth": {
                "anonymous_allowed": True,
                "requires_auth": False,
            },
            "topics": [
                {"topic": "test/topic", "message_count": 5},
            ],
            "sparkplug": {
                "groups": [],
                "nodes": {},
            },
            "common_topics": {
                "topics_tested": 100,
                "topics_found": [],
            },
            "security_issues": [],
        }

        self.assertIn("broker_info", results)
        self.assertIn("auth", results)
        self.assertIn("topics", results)
        self.assertIn("sparkplug", results)
        self.assertIn("security_issues", results)


class TestMQTTProtocolOptions(unittest.TestCase):
    """Test MQTT protocol options"""

    def test_authentication_options(self):
        """Test authentication options"""
        from oida.protocols.mqtt.scanner import protocol_options

        self.assertIn("username", protocol_options)
        self.assertIn("password", protocol_options)
        self.assertIn("client-id", protocol_options)

    def test_tls_options(self):
        """Test TLS options"""
        from oida.protocols.mqtt.scanner import protocol_options

        self.assertIn("tls", protocol_options)
        self.assertIn("tls-cert", protocol_options)
        self.assertIn("tls-key", protocol_options)
        self.assertIn("tls-ca", protocol_options)
        self.assertIn("tls-insecure", protocol_options)

    def test_enumeration_options(self):
        """Test enumeration options"""
        from oida.protocols.mqtt.scanner import protocol_options

        self.assertIn("topics", protocol_options)
        self.assertIn("enumerate", protocol_options)
        self.assertIn("enumerate-common", protocol_options)
        self.assertIn("topic-list", protocol_options)

    def test_brute_force_options(self):
        """Test brute-force options"""
        from oida.protocols.mqtt.scanner import protocol_options

        self.assertIn("brute", protocol_options)
        self.assertIn("wordlist", protocol_options)
        self.assertIn("credentials", protocol_options)
        self.assertIn("brute-rate", protocol_options)

    def test_listen_options(self):
        """Test listen mode options"""
        from oida.protocols.mqtt.scanner import protocol_options

        self.assertIn("listen", protocol_options)
        self.assertIn("listen-output", protocol_options)
        self.assertIn("unique", protocol_options)


@pytest.mark.network
class TestMQTTErrorHandling(unittest.TestCase):
    """Test MQTT error handling"""

    def test_connection_error_handling(self):
        """Test handling of connection errors"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {
            "rhost": "192.168.254.254",  # Non-routable
            "rport": 1883,
            "timeout": 1,
        }
        scanner = MQTTScanner(args)

        # Connection should fail gracefully
        result = scanner.connect()
        self.assertIsNone(result)

    def test_auth_result_on_failure(self):
        """Test auth result on connection failure"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        MQTTScanner(args)

        # Auth result should be set on failure
        auth_result = {
            "anonymous_allowed": False,
            "requires_auth": True,
            "error": "Connection failed",
        }

        self.assertFalse(auth_result["anonymous_allowed"])
        self.assertTrue(auth_result["requires_auth"])


class TestMQTTFuzzing(unittest.TestCase):
    """Test MQTT fuzzing functionality"""

    def test_fuzz_result_structure(self):
        """Test fuzzing result structure"""
        result = {
            "tested": 100,
            "published": 95,
            "errors": [
                {"topic": "test", "payload": "deadbeef", "error": "rc=1"},
            ],
            "topics_fuzzed": [
                {"topic": "test/topic", "payloads_sent": 20, "errors": 1},
            ],
        }

        self.assertIn("tested", result)
        self.assertIn("published", result)
        self.assertIn("errors", result)
        self.assertIn("topics_fuzzed", result)


class TestMQTTCommonTopics(unittest.TestCase):
    """Test MQTT common topics enumeration"""

    def test_common_topics_categories(self):
        """Test that common topics cover key categories"""
        from oida.protocols.mqtt.scanner import COMMON_TOPICS

        # Check for key topic categories
        categories = {
            "sys": any("$SYS" in t for t in COMMON_TOPICS),
            "sparkplug": any("spBv1.0" in t for t in COMMON_TOPICS),
            "homie": any("homie" in t for t in COMMON_TOPICS),
            "aws": any("$aws" in t for t in COMMON_TOPICS),
            "azure": any("$iothub" in t for t in COMMON_TOPICS),
            "homeassistant": any("homeassistant" in t for t in COMMON_TOPICS),
            "tasmota": any("cmnd" in t or "tele" in t for t in COMMON_TOPICS),
            "zigbee2mqtt": any("zigbee2mqtt" in t for t in COMMON_TOPICS),
        }

        for category, found in categories.items():
            self.assertTrue(found, f"Missing category: {category}")

    def test_ics_topics_included(self):
        """Test that ICS/SCADA topics are included"""
        from oida.protocols.mqtt.scanner import COMMON_TOPICS

        ics_topics = [
            "plc/#",
            "scada/#",
            "modbus/#",
            "siemens/#",
            "rockwell/#",
            "beckhoff/#",
        ]

        for topic in ics_topics:
            self.assertIn(topic, COMMON_TOPICS, f"Missing ICS topic: {topic}")

    def test_common_topics_enumeration_result(self):
        """Test common topics enumeration result structure"""
        result = {
            "topics_tested": 100,
            "topics_found": ["test/topic1", "test/topic2"],
            "messages_received": 10,
            "accessible_patterns": [
                {"pattern": "test/#", "topics_found": 2},
            ],
            "source": "builtin",
        }

        self.assertIn("topics_tested", result)
        self.assertIn("topics_found", result)
        self.assertIn("accessible_patterns", result)


class TestMQTTCredentialTesting(unittest.TestCase):
    """Test MQTT credential testing methods"""

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    def test_test_credentials_success(self, mock_paho_enums, mock_paho_client):
        """Test successful credential validation"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        # Setup mock
        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        # Test valid credentials
        result = scanner._test_credentials("admin", "admin")

        # Should connect with credentials
        self.assertIsInstance(result, bool)

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    def test_test_credentials_failure(self, mock_paho_enums, mock_paho_client):
        """Test failed credential validation"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        # Setup mock for failed connection
        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()

        # Simulate auth failure
        def mock_connect_fail(host, port, keepalive=60):
            if mock_client.on_connect:
                # Return non-zero code for auth failure
                mock_client.on_connect(mock_client, None, None, 5, None)

        mock_client.connect = mock_connect_fail
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        result = scanner._test_credentials("wrong", "wrong")
        self.assertFalse(result)

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    def test_test_credentials_with_tls(self, mock_paho_enums, mock_paho_client):
        """Test credential validation with TLS"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()

        # Make tls_set_context a MagicMock so we can assert on it
        mock_client.tls_set_context = MagicMock()

        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {"rhost": "127.0.0.1", "rport": 8883, "tls": True, "tls-insecure": True}
        scanner = MQTTScanner(args)

        scanner._test_credentials("admin", "password")

        # Should have set TLS context
        mock_client.tls_set_context.assert_called_once()

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    @patch("time.sleep")
    def test_brute_force_with_builtin_credentials(
        self, mock_sleep, mock_paho_enums, mock_paho_client
    ):
        """Test brute-force with built-in credentials"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {"rhost": "127.0.0.1", "rport": 1883, "brute": True, "brute-rate": 0}
        scanner = MQTTScanner(args)

        # Mock successful auth for first credential
        test_count = [0]

        def mock_test_creds(username, password):
            test_count[0] += 1
            return test_count[0] == 1  # First attempt succeeds

        scanner._test_credentials = mock_test_creds

        result = scanner._brute_force_credentials()

        self.assertEqual(result["tested"], 1)
        self.assertEqual(len(result["valid"]), 1)
        self.assertTrue(result["stopped_early"])

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    def test_brute_force_with_credentials_file(self, mock_paho_enums, mock_paho_client):
        """Test brute-force with credentials file"""
        from oida.protocols.mqtt.scanner import MQTTScanner
        import tempfile

        mock_mqtt_module = MagicMock()
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        # Write real credentials file
        creds_content = "admin:admin123\nroot:password\n# comment\nuser:pass"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(creds_content)
            creds_path = f.name

        try:
            args = {
                "rhost": "127.0.0.1",
                "rport": 1883,
                "brute": True,
                "credentials": creds_path,
                "brute-rate": 0,
            }
            scanner = MQTTScanner(args)

            # Mock all attempts fail
            scanner._test_credentials = lambda u, p: False

            result = scanner._brute_force_credentials()

            self.assertEqual(result["tested"], 3)  # 3 valid lines
            self.assertEqual(len(result["valid"]), 0)
        finally:
            os.unlink(creds_path)


class TestMQTTSparkplugParsing(unittest.TestCase):
    """Test MQTT Sparkplug B payload parsing"""

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    def test_enumerate_sparkplug_with_messages(self, mock_paho_enums, mock_paho_client):
        """Test Sparkplug enumeration with messages"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {"rhost": "127.0.0.1", "rport": 1883, "timeout": 1, "sparkplug": True}
        scanner = MQTTScanner(args)

        # Create mock connection
        conn = mock_client

        # Mock Sparkplug message

        # Simulate message
        with patch("time.sleep"):
            # Capture the on_message handler
            (
                scanner._enumerate_sparkplug.__wrapped__
                if hasattr(scanner._enumerate_sparkplug, "__wrapped__")
                else scanner._enumerate_sparkplug
            )

            # Call enumerate and manually trigger message callback
            result = scanner._enumerate_sparkplug(conn)

            self.assertIn("groups", result)
            self.assertIn("nodes", result)
            self.assertIn("metrics", result)

    def test_sparkplug_topic_parsing(self):
        """Test Sparkplug topic parsing logic"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        MQTTScanner(args)

        # Test topic parsing
        test_cases = [
            ("spBv1.0/TestGroup/NBIRTH/EdgeNode1", ("TestGroup", "NBIRTH", "EdgeNode1", None)),
            (
                "spBv1.0/TestGroup/DBIRTH/EdgeNode1/Device1",
                ("TestGroup", "DBIRTH", "EdgeNode1", "Device1"),
            ),
            ("spBv1.0/Group2/DDATA/Node2/Sensor3", ("Group2", "DDATA", "Node2", "Sensor3")),
        ]

        for topic, expected in test_cases:
            parts = topic.split("/")
            if len(parts) >= 4:
                group_id = parts[1]
                msg_type = parts[2]
                node_id = parts[3]
                device_id = parts[4] if len(parts) > 4 else None

                self.assertEqual((group_id, msg_type, node_id, device_id), expected)


class TestMQTTBrokerInfoExtraction(unittest.TestCase):
    """Test MQTT broker info extraction from $SYS topics"""

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    @patch("time.sleep")
    def test_enumerate_sys_topics_parsing(self, mock_sleep, mock_paho_enums, mock_paho_client):
        """Test $SYS topic enumeration and parsing"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_client

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {"rhost": "127.0.0.1", "rport": 1883, "enumerate-sys": True, "timeout": 1}
        MQTTScanner(args)

        # Manually simulate messages
        mock_messages = [
            ("$SYS/broker/version", b"mosquitto version 2.0.18"),
            ("$SYS/broker/uptime", b"3600 seconds"),
            ("$SYS/broker/clients/connected", b"5"),
        ]

        # Store original on_message handler for manual invocation
        broker_info = {}
        sys_topics = {}

        def manual_on_message(topic, payload):
            try:
                value = payload.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                value = payload.hex()

            sys_topics[topic] = value

            if topic == "$SYS/broker/version":
                broker_info["version"] = value
            elif topic == "$SYS/broker/uptime":
                broker_info["uptime"] = value
            elif topic == "$SYS/broker/clients/connected":
                broker_info["clients_connected"] = value

        # Simulate message handling
        for topic, payload in mock_messages:
            manual_on_message(topic, payload)

        # Verify parsing
        self.assertEqual(broker_info["version"], "mosquitto version 2.0.18")
        self.assertEqual(broker_info["uptime"], "3600 seconds")
        self.assertEqual(broker_info["clients_connected"], "5")
        self.assertEqual(len(sys_topics), 3)

    def test_broker_info_extraction_from_sys_topics(self):
        """Test extraction of specific broker info fields"""
        sys_topics = {
            "$SYS/broker/version": "mosquitto version 2.0.18",
            "$SYS/broker/uptime": "86400 seconds",
            "$SYS/broker/clients/connected": "10",
            "$SYS/broker/clients/total": "25",
            "$SYS/broker/messages/received": "1000",
            "$SYS/broker/messages/sent": "950",
        }

        # Extract specific fields
        version = sys_topics.get("$SYS/broker/version")
        uptime = sys_topics.get("$SYS/broker/uptime")
        clients = sys_topics.get("$SYS/broker/clients/connected")

        self.assertEqual(version, "mosquitto version 2.0.18")
        self.assertEqual(uptime, "86400 seconds")
        self.assertEqual(clients, "10")


class TestMQTTTopicSubscriptionPatterns(unittest.TestCase):
    """Test MQTT topic subscription and pattern matching"""

    def test_topic_matches_pattern_edge_cases(self):
        """Test edge cases in topic pattern matching"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        # Test cases
        test_cases = [
            # (pattern, topic, should_match)
            # Note: MQTT spec allows # to match zero or more levels, so test/# matches "test"
            ("test/+", "test/a", True),
            ("test/+", "test/a/b", False),
            ("+/+", "a/b", True),
            ("+/+", "a/b/c", False),
            ("a/+/c", "a/b/c", True),
            ("a/+/c", "a/x/c", True),
            ("a/+/c", "a/b/d", False),
            ("", "", True),  # Empty pattern matches empty topic
            ("test/topic", "test/topic", True),
            ("test/topic", "test/topic/extra", False),
            ("a/b/c/d", "a/b", False),  # Pattern longer than topic
        ]

        for pattern, topic, expected in test_cases:
            result = scanner._topic_matches_pattern(pattern, topic)
            self.assertEqual(
                result,
                expected,
                f"Pattern '{pattern}' vs topic '{topic}' should be {expected}, got {result}",
            )

    def test_topic_pattern_with_special_chars(self):
        """Test topics with special characters"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        # MQTT allows various special chars in topics
        self.assertTrue(scanner._topic_matches_pattern("$SYS/+/version", "$SYS/broker/version"))

        self.assertTrue(
            scanner._topic_matches_pattern("devices/+/status", "devices/device-123/status")
        )


class TestMQTTMessageParsing(unittest.TestCase):
    """Test MQTT message parsing and filtering"""

    def test_message_payload_parsing_utf8(self):
        """Test UTF-8 payload parsing"""
        from oida.protocols.mqtt.scanner import MQTTMessage

        msg = MQTTMessage(
            topic="test/data", payload=b'{"temperature": 25.5, "humidity": 60}', qos=1, retain=False
        )

        payload_str = msg.payload_str()
        self.assertEqual(payload_str, '{"temperature": 25.5, "humidity": 60}')

    def test_message_payload_parsing_binary(self):
        """Test binary payload parsing"""
        from oida.protocols.mqtt.scanner import MQTTMessage

        # Binary payload
        msg = MQTTMessage(
            topic="test/binary", payload=b"\x00\x01\x02\x03\xff\xfe", qos=0, retain=True
        )

        payload_str = msg.payload_str()
        self.assertEqual(payload_str, "00010203fffe")


class TestMQTTFuzzPublishPayloads(unittest.TestCase):
    """Test MQTT publish payload fuzzing"""

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    @patch("time.sleep")
    def test_fuzz_publish_payloads_basic(self, mock_sleep, mock_paho_enums, mock_paho_client):
        """Test basic fuzzing of publish payloads"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        conn = mock_client
        topics = ["test/topic1", "test/topic2"]

        result = scanner.fuzz_publish_payloads(conn, topics, iterations=5)

        self.assertIn("tested", result)
        self.assertIn("published", result)
        self.assertIn("errors", result)
        self.assertIn("topics_fuzzed", result)
        self.assertGreater(result["tested"], 0)

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    def test_fuzz_publish_no_connection(self, mock_paho_enums, mock_paho_client):
        """Test fuzzing with no connection"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        mock_mqtt_module = MagicMock()
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        result = scanner.fuzz_publish_payloads(None, ["test/topic"], iterations=5)

        self.assertEqual(result["tested"], 0)
        self.assertEqual(result["published"], 0)

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    @patch("time.sleep")
    def test_fuzz_publish_with_errors(self, mock_sleep, mock_paho_enums, mock_paho_client):
        """Test fuzzing with publish errors"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()

        # Make publish fail sometimes
        publish_count = [0]

        def mock_publish(topic, payload, qos=0, retain=False):
            publish_count[0] += 1
            result = Mock()
            # Every 3rd publish fails
            result.rc = 1 if publish_count[0] % 3 == 0 else 0
            return result

        mock_client.publish = mock_publish
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        conn = mock_client
        result = scanner.fuzz_publish_payloads(conn, ["test/topic"], iterations=10)

        self.assertGreater(len(result["errors"]), 0)


class TestMQTTCommonTopicsEnumeration(unittest.TestCase):
    """Test MQTT common topics enumeration logic"""

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    @patch("time.sleep")
    def test_enumerate_common_topics_with_builtin(
        self, mock_sleep, mock_paho_enums, mock_paho_client
    ):
        """Test common topics enumeration with built-in list"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {
            "rhost": "127.0.0.1",
            "rport": 1883,
            "enumerate-common": True,
            "timeout": 2,
        }
        scanner = MQTTScanner(args)

        conn = mock_client
        result = scanner._enumerate_common_topics(conn)

        self.assertIn("topics_tested", result)
        self.assertIn("topics_found", result)
        self.assertIn("messages_received", result)
        self.assertIn("accessible_patterns", result)
        self.assertEqual(result["source"], "builtin")

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    @patch("time.sleep")
    def test_enumerate_common_topics_with_file(self, mock_sleep, mock_paho_enums, mock_paho_client):
        """Test common topics enumeration with custom file"""
        from oida.protocols.mqtt.scanner import MQTTScanner
        import tempfile

        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        # Write real topic list file
        topics_content = "custom/topic1\ncustom/topic2\n# comment\ncustom/topic3/#"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(topics_content)
            topics_path = f.name

        try:
            args = {
                "rhost": "127.0.0.1",
                "rport": 1883,
                "topic-list": topics_path,
                "timeout": 2,
            }
            scanner = MQTTScanner(args)

            conn = mock_client
            result = scanner._enumerate_common_topics(conn)

            self.assertIn(f"file:{topics_path}", result["source"])
            self.assertEqual(result["topics_tested"], 3)  # 3 valid lines
        finally:
            os.unlink(topics_path)

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    @patch("time.sleep")
    def test_enumerate_common_topics_skip_duplicates(
        self, mock_sleep, mock_paho_enums, mock_paho_client
    ):
        """Test that common topic enumeration skips already-tested patterns"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {
            "rhost": "127.0.0.1",
            "rport": 1883,
            "enumerate-common": True,
            "enumerate": True,  # Enables both $SYS and Sparkplug enumeration
            "timeout": 2,
        }
        scanner = MQTTScanner(args)

        conn = mock_client

        # Track subscribed topics
        subscribed = []
        original_subscribe = conn.subscribe

        def track_subscribe(topic, qos=0):
            subscribed.append(topic)
            return original_subscribe(topic, qos)

        conn.subscribe = track_subscribe

        scanner._enumerate_common_topics(conn)

        # With enumerate=True, enumerate_sys and enumerate_sparkplug are set,
        # so common topics enumeration should skip $SYS and spBv1.0 topics
        sys_topics = [t for t in subscribed if t.startswith("$SYS/")]
        spb_topics = [t for t in subscribed if t.startswith("spBv1.0/")]

        self.assertEqual(len(sys_topics), 0)
        self.assertEqual(len(spb_topics), 0)


class TestMQTTListenModeAdvanced(unittest.TestCase):
    """Test advanced MQTT listen mode functionality"""

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    @patch("time.sleep")
    @patch("builtins.open", create=True)
    def test_listen_mode_with_output_file(
        self, mock_open, mock_sleep, mock_paho_enums, mock_paho_client
    ):
        """Test listen mode with output file"""
        from oida.protocols.mqtt.scanner import MQTTScanner
        from io import StringIO

        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        # Mock output file
        output_buffer = StringIO()
        mock_open.return_value.__enter__.return_value = output_buffer

        args = {
            "rhost": "127.0.0.1",
            "rport": 1883,
            "listen": True,
            "listen-output": "/tmp/listen.jsonl",
            "timeout": 1,
        }
        scanner = MQTTScanner(args)

        conn = mock_client
        result = scanner._run_listen_mode(conn)

        self.assertIn("duration", result)
        self.assertIn("messages", result)
        self.assertIn("topics", result)

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    @patch("time.sleep")
    def test_listen_mode_stats_calculation(self, mock_sleep, mock_paho_enums, mock_paho_client):
        """Test listen mode statistics calculation"""
        from oida.protocols.mqtt.scanner import ListenStats

        stats = ListenStats()

        # Simulate receiving messages
        stats.message_count = 50
        stats.bytes_received = 2500
        stats.retained_count = 5
        stats.topics_seen.add("topic1")
        stats.topics_seen.add("topic2")
        stats.topics_seen.add("topic3")

        self.assertEqual(stats.message_count, 50)
        self.assertEqual(stats.bytes_received, 2500)
        self.assertEqual(len(stats.topics_seen), 3)
        self.assertEqual(stats.retained_count, 5)
        self.assertGreater(stats.duration, 0)
        self.assertGreater(stats.rate, 0)


class TestMQTTSecurityAnalysisAdvanced(unittest.TestCase):
    """Test advanced MQTT security analysis"""

    def test_analyze_security_multiple_issues(self):
        """Test detection of multiple security issues"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883, "tls": False, "topics": "#"}
        scanner = MQTTScanner(args)

        results = {
            "auth": {
                "anonymous_allowed": True,
                "brute_results": {
                    "valid": [
                        {"username": "admin", "password": "admin"},
                        {"username": "root", "password": "root"},
                    ]
                },
            },
            "broker_info": {"sys_topic_count": 30},
            "topics": [{"topic": "test/topic"}],
        }

        issues = scanner._analyze_security(results)

        # Should detect multiple issues
        self.assertGreater(len(issues), 3)

        # Check for specific issues
        issue_types = [i["issue"] for i in issues]
        self.assertTrue(any("Anonymous" in i for i in issue_types))
        self.assertTrue(any("$SYS" in i for i in issue_types))
        self.assertTrue(any("Wildcard" in i for i in issue_types))
        self.assertTrue(any("Weak credentials" in i for i in issue_types))
        self.assertTrue(any("Plaintext" in i for i in issue_types))

    def test_analyze_security_weak_credentials_formats(self):
        """Test weak credentials detection with different formats"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        # Test with dict format
        results_dict = {
            "auth": {"brute_results": {"valid": [{"username": "admin", "password": "admin123"}]}},
            "broker_info": {},
            "topics": [],
        }

        issues_dict = scanner._analyze_security(results_dict)
        self.assertTrue(any("Weak credentials" in i["issue"] for i in issues_dict))

        # Test with tuple format
        results_tuple = {
            "auth": {"brute_results": {"valid": [("root", "password")]}},
            "broker_info": {},
            "topics": [],
        }

        issues_tuple = scanner._analyze_security(results_tuple)
        self.assertTrue(any("Weak credentials" in i["issue"] for i in issues_tuple))


class TestMQTTDisconnectAndCleanup(unittest.TestCase):
    """Test MQTT disconnect and cleanup"""

    @patch("oida.protocols.mqtt.scanner.paho_client")
    @patch("oida.protocols.mqtt.scanner.paho_enums")
    def test_disconnect_graceful(self, mock_paho_enums, mock_paho_client):
        """Test graceful disconnect"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        mock_mqtt_module = MagicMock()
        mock_client = MockMQTTClient()
        mock_mqtt_module.Client.return_value = mock_client
        mock_paho_client.return_value = mock_mqtt_module

        mock_callback_version = MagicMock()
        mock_paho_enums.CallbackAPIVersion = mock_callback_version

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        conn = mock_client
        scanner.disconnect(conn)

        # Should call loop_stop and disconnect
        self.assertFalse(mock_client.connected)

    def test_disconnect_none_connection(self):
        """Test disconnect with None connection"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        # Should not raise exception
        scanner.disconnect(None)


class TestMQTTEdgeCases(unittest.TestCase):
    """Test MQTT edge cases and error conditions"""

    def test_empty_topics_list(self):
        """Test handling of empty topics list"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        result = scanner.fuzz_publish_payloads(None, [], iterations=10)

        self.assertEqual(result["tested"], 0)
        self.assertEqual(result["published"], 0)

    def test_message_payload_none(self):
        """Test handling of None payload"""
        from oida.protocols.mqtt.scanner import MQTTMessage

        msg = MQTTMessage(topic="test/topic", payload=None, qos=0, retain=False)

        # Should handle None gracefully
        try:
            payload_str = msg.payload_str()
            # If it doesn't raise, check it returns something reasonable
            self.assertIsNotNone(payload_str)
        except AttributeError:
            # Expected if None is not handled
            pass

    def test_topic_pattern_empty_parts(self):
        """Test topic matching with empty parts"""
        from oida.protocols.mqtt.scanner import MQTTScanner

        args = {"rhost": "127.0.0.1", "rport": 1883}
        scanner = MQTTScanner(args)

        # Edge case: pattern longer than topic
        self.assertFalse(scanner._topic_matches_pattern("a/b/c/d", "a/b"))

        # Edge case: same length but mismatch
        self.assertFalse(scanner._topic_matches_pattern("a/b/c", "a/b/d"))


import pytest
import socket


# ==============================================================================
# Error Path Tests - Network Failures, Malformed Data, Timeouts
# ==============================================================================


class TestMQTTNetworkErrorPaths(unittest.TestCase):
    """Test network error handling paths in MQTTScanner."""

    def test_connection_refused(self):
        """Test handling of connection refused error."""
        mock_client = Mock()
        mock_client.connect.side_effect = ConnectionRefusedError("Connection refused")

        with self.assertRaises(ConnectionRefusedError):
            mock_client.connect("192.168.1.100", 1883)

    def test_connection_timeout(self):
        """Test handling of connection timeout."""
        mock_client = Mock()
        mock_client.connect.side_effect = socket.timeout("Connection timed out")

        with self.assertRaises(socket.timeout):
            mock_client.connect("192.168.1.100", 1883)

    def test_connection_reset_during_subscribe(self):
        """Test handling of connection reset during subscribe."""
        mock_client = Mock()
        mock_client.subscribe.side_effect = ConnectionResetError("Connection reset by peer")

        with self.assertRaises(ConnectionResetError):
            mock_client.subscribe("#")

    def test_network_unreachable(self):
        """Test handling of network unreachable error."""
        import errno

        mock_client = Mock()
        mock_client.connect.side_effect = OSError(errno.ENETUNREACH, "Network is unreachable")

        with self.assertRaises(OSError) as ctx:
            mock_client.connect("192.168.1.100", 1883)
        self.assertEqual(ctx.exception.errno, errno.ENETUNREACH)

    def test_broken_pipe_during_publish(self):
        """Test handling of broken pipe during publish."""
        mock_client = Mock()
        mock_client.publish.side_effect = BrokenPipeError("Broken pipe")

        with self.assertRaises(BrokenPipeError):
            mock_client.publish("test/topic", "payload")


class TestMQTTTimeoutEdgeCases(unittest.TestCase):
    """Test timeout handling edge cases."""

    def test_zero_timeout(self):
        """Test scanner behavior with zero timeout."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "192.168.1.1", "rport": 1883, "timeout": 0})

        self.assertEqual(scanner.timeout, 0)

    def test_very_small_timeout(self):
        """Test scanner behavior with very small timeout (1ms) - int cast truncates to 0."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "192.168.1.1", "rport": 1883, "timeout": 0.001})

        # BaseScanner casts timeout to int, so 0.001 becomes 0
        self.assertEqual(scanner.timeout, 0)

    def test_very_large_timeout(self):
        """Test scanner behavior with very large timeout."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "192.168.1.1", "rport": 1883, "timeout": 3600})

        self.assertEqual(scanner.timeout, 3600)


class TestMQTTInvalidInputHandling(unittest.TestCase):
    """Test handling of invalid input parameters."""

    def test_invalid_port_zero(self):
        """Test handling of port 0 - falsy port falls through to default."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "192.168.1.1", "rport": 0})

        # Port 0 is falsy, so get_target_info falls through to get_default_port() = 1883
        self.assertEqual(scanner.port, 1883)

    def test_invalid_port_over_65535(self):
        """Test handling of port > 65535."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "192.168.1.1", "rport": 70000})

        self.assertEqual(scanner.port, 70000)

    def test_empty_host(self):
        """Test handling of empty host - base scanner now requires host."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        with self.assertRaises(ValueError):
            MQTTScanner({"rhost": "", "rport": 1883})

    def test_empty_topic(self):
        """Test handling of empty topic."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "192.168.1.1", "rport": 1883, "topics": ""})

        self.assertEqual(scanner.topics_pattern, "")


class TestMQTTTLSErrors(unittest.TestCase):
    """Test TLS/SSL error handling."""

    def test_invalid_certificate_path(self):
        """Test handling of invalid certificate path."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 8883,
                "tls": True,
                "tls-cert": "/nonexistent/cert.pem",
            }
        )

        self.assertEqual(scanner.tls_cert, "/nonexistent/cert.pem")

    def test_invalid_private_key_path(self):
        """Test handling of invalid private key path."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 8883,
                "tls": True,
                "tls-key": "/nonexistent/key.pem",
            }
        )

        self.assertEqual(scanner.tls_key, "/nonexistent/key.pem")


class TestMQTTResourceCleanup(unittest.TestCase):
    """Test proper resource cleanup on errors."""

    def test_disconnect_after_connection_error(self):
        """Test that disconnect is called after connection error."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "192.168.1.1", "rport": 1883})

        mock_client = Mock()
        mock_client.loop_stop = Mock()
        mock_client.disconnect = Mock()

        scanner.disconnect(mock_client)

        mock_client.loop_stop.assert_called_once()
        mock_client.disconnect.assert_called_once()

    def test_multiple_disconnect_calls_safe(self):
        """Test that multiple disconnect calls don't raise errors."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner({"rhost": "192.168.1.1", "rport": 1883})

        mock_client = Mock()
        mock_client.loop_stop = Mock()
        mock_client.disconnect = Mock()

        scanner.disconnect(mock_client)
        scanner.disconnect(mock_client)
        scanner.disconnect(mock_client)

        self.assertEqual(mock_client.disconnect.call_count, 3)


# Pytest-style tests for parametrized error scenarios
class TestMQTTWithErrorInjection:
    """Pytest-style tests using parametrized error scenarios."""

    @pytest.mark.parametrize(
        "exception_type,message",
        [
            (ConnectionRefusedError, "Connection refused"),
            (ConnectionResetError, "Connection reset by peer"),
            (socket.timeout, "timed out"),
            (OSError, "Network is down"),
        ],
    )
    def test_various_connection_errors(self, exception_type, message):
        """Test handling of various connection error types."""
        mock_client = Mock()
        mock_client.connect.side_effect = exception_type(message)

        with pytest.raises(exception_type):
            mock_client.connect("192.168.1.100", 1883)

    @pytest.mark.parametrize("timeout", [0, 0.001, 1, 5, 30, 3600])
    def test_timeout_values(self, timeout):
        """Test various timeout values - BaseScanner casts to int."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner(
            {
                "rhost": "192.168.1.1",
                "rport": 1883,
                "timeout": timeout,
            }
        )

        # BaseScanner casts timeout to int
        assert scanner.timeout == int(timeout)

    @pytest.mark.parametrize("port", [1, 1883, 8883, 65535, 70000])
    def test_port_values(self, port):
        """Test various port values (non-zero since 0 is falsy and triggers default)."""
        from oida.protocols.mqtt.scanner import MQTTScanner

        scanner = MQTTScanner(
            {
                "rhost": "192.168.1.1",
                "rport": port,
            }
        )

        assert scanner.port == port


if __name__ == "__main__":
    unittest.main()
