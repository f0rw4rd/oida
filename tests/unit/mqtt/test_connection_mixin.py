#!/usr/bin/env python3
"""
Unit tests for the MQTT ConnectionMixin.

The mixin owns paho client construction, MQTT 5.0 property build/extract,
the synchronous connect loop, and pre-auth version enumeration. These tests
drive the *real* mixin methods and mock ONLY the paho/socket boundary:

  * a fake paho module (Client + version constants) injected via the
    scanner module's lazy-import shims, and
  * fake client sockets for the TLS-certificate path.

No mixin code is patched. Assertions check concrete connection outcomes,
reason strings, captured CONNACK properties and the enumeration verdict.
"""

import ssl

import pytest

from oida.protocols.mqtt import scanner as scanner_mod
from oida.protocols.mqtt.mixins.connection import ConnectionMixin
from tests.service_gate import require_import


# ---------------------------------------------------------------------------
# Fake paho boundary
# ---------------------------------------------------------------------------


class FakeReasonCode:
    """Mimics paho-mqtt 2.x ReasonCode: int(), .value, str()."""

    def __init__(self, value, name=None):
        self.value = value
        self._name = name or f"rc{value}"

    def __int__(self):
        return self.value

    def __eq__(self, other):
        return int(self) == int(other)

    def __str__(self):
        return self._name


class FakeProperties:
    """Bare attribute bag standing in for paho property objects."""

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class FakeClient:
    """Fake paho client. Records calls and fires on_connect synchronously."""

    # Scenario knobs set per-test via the factory closure
    def __init__(self, *, callback_api_version=None, client_id=None, protocol=None):
        self.client_id = client_id
        self.protocol = protocol
        self.on_connect = None
        self.username = None
        self.password = None
        self.tls_context = None
        self.connected_args = None
        self.disconnect_called = False
        self.loops = 0
        # Behaviour injected by the test:
        self._connect_exc = None
        self._loop_exc = None
        self._reason_code = FakeReasonCode(0)
        self._connack_props = None
        self._sock = None

    # --- paho API surface used by the mixin -----------------------------
    def username_pw_set(self, username, password=None):
        self.username = username
        self.password = password

    def tls_set_context(self, context):
        self.tls_context = context

    def connect(self, host, port, keepalive=60):
        self.connected_args = (host, port, keepalive)
        if self._connect_exc is not None:
            raise self._connect_exc

    def loop(self, timeout=0.0):
        self.loops += 1
        if self._loop_exc is not None:
            raise self._loop_exc
        # Deliver the CONNACK once, on the first loop iteration.
        if self.on_connect and self.loops == 1:
            flags = {}
            self.on_connect(self, None, flags, self._reason_code, self._connack_props)

    def disconnect(self):
        self.disconnect_called = True

    def socket(self):
        return self._sock


def make_fake_paho(client_factory):
    """Return a fake paho.mqtt.client module exposing Client + version consts."""

    class FakeMqttModule:
        MQTTv31 = 3
        MQTTv311 = 4
        MQTTv5 = 5
        Client = staticmethod(client_factory)

    return FakeMqttModule()


class FakeEnums:
    class CallbackAPIVersion:
        VERSION2 = "v2"


# ---------------------------------------------------------------------------
# Host object that mixes in ConnectionMixin (construction only - no patching)
# ---------------------------------------------------------------------------


class _Logger:
    def __init__(self):
        self.messages = []

    def _record(self, level, msg):
        self.messages.append((level, str(msg)))

    def debug(self, msg):
        self._record("debug", msg)

    def display(self, msg):
        self._record("display", msg)

    def warning(self, msg):
        self._record("warning", msg)

    def security_finding(self, msg, detail=None, **kw):
        self._record("finding", msg)

    def info(self, msg):
        self._record("info", msg)

    def fail(self, msg):
        self._record("fail", msg)

    def success(self, msg):
        self._record("success", msg)

    def text(self):
        return " | ".join(m for _, m in self.messages)


class MqttHost(ConnectionMixin):
    def __init__(self, *, protocol_version=4, use_tls=False, client_id="", args=None):
        self.host = "broker.test"
        self.port = 1883
        self.timeout = 5
        self.debug = False
        self.protocol_version = protocol_version
        self.client_id = client_id
        self.use_tls = use_tls
        self.args = args or {}
        self.logger = _Logger()


@pytest.fixture
def install_fake_paho(monkeypatch):
    """Install a fake paho boundary; returns a setter taking a client factory.

    monkeypatch targets the scanner module's lazy-import *shims* (the external
    paho dependency), never the mixin under test.
    """

    def _install(client_factory):
        monkeypatch.setattr(scanner_mod, "paho_client", lambda: make_fake_paho(client_factory))
        monkeypatch.setattr(scanner_mod, "paho_enums", FakeEnums)
        return client_factory

    return _install


# ---------------------------------------------------------------------------
# _create_mqtt_client
# ---------------------------------------------------------------------------


class TestCreateClient:
    def test_protocol_version_mapping(self, install_fake_paho):
        created = {}

        def factory(**kw):
            c = FakeClient(**kw)
            created["client"] = c
            return c

        install_fake_paho(factory)
        host = MqttHost(protocol_version=5, client_id="fixed-id")
        client = host._create_mqtt_client()
        assert client.protocol == 5  # MQTTv5
        assert client.client_id == "fixed-id"

    def test_unknown_version_defaults_to_311(self, install_fake_paho):
        install_fake_paho(lambda **kw: FakeClient(**kw))
        host = MqttHost(protocol_version=99)
        client = host._create_mqtt_client()
        assert client.protocol == 4  # MQTTv311 fallback

    def test_auto_client_id_generated_when_blank(self, install_fake_paho):
        install_fake_paho(lambda **kw: FakeClient(**kw))
        host = MqttHost(client_id="")
        client = host._create_mqtt_client(client_id_suffix="probe")
        assert client.client_id.startswith("oida-probe-")

    def test_username_password_set(self, install_fake_paho):
        install_fake_paho(lambda **kw: FakeClient(**kw))
        host = MqttHost()
        client = host._create_mqtt_client(username="admin", password="secret")
        assert client.username == "admin"
        assert client.password == "secret"

    def test_no_auth_leaves_credentials_unset(self, install_fake_paho):
        install_fake_paho(lambda **kw: FakeClient(**kw))
        host = MqttHost()
        client = host._create_mqtt_client()
        assert client.username is None

    def test_tls_context_applied(self, install_fake_paho):
        install_fake_paho(lambda **kw: FakeClient(**kw))
        host = MqttHost(use_tls=True, args={"tls_insecure": True})
        client = host._create_mqtt_client()
        # real build_tls_context produced an SSLContext and it was passed through
        assert isinstance(client.tls_context, ssl.SSLContext)

    def test_paho2x_socket_connection_patch_installed(self, install_fake_paho):
        # When the client exposes _create_socket_connection (paho 2.x), the mixin
        # replaces it with a source_address-free variant. Verify the patched
        # function builds a connection using the client's host/port.
        import socket as real_socket

        def factory(**kw):
            c = FakeClient(**kw)
            # Emulate paho 2.x internals the patch reads.
            c._create_socket_connection = lambda: None
            c._get_proxy = lambda: None
            c._host = "127.0.0.1"
            c._port = 0
            c._connect_timeout = 1
            return c

        install_fake_paho(factory)
        host = MqttHost()
        client = host._create_mqtt_client()

        # Stand up a throwaway listener so the patched connector can connect.
        server = real_socket.socket(real_socket.AF_INET, real_socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        client._host, client._port = server.getsockname()
        try:
            conn = client._create_socket_connection()
            assert isinstance(conn, real_socket.socket)
            conn.close()
        finally:
            server.close()


# ---------------------------------------------------------------------------
# MQTT 5.0 property build / has-properties
# ---------------------------------------------------------------------------


class TestV5Properties:
    def test_has_v5_properties_true_and_false(self):
        host = MqttHost()
        assert host._has_v5_properties({"content_type": "text/plain"}) is True
        assert host._has_v5_properties({}) is False
        assert host._has_v5_properties({"unrelated": "x"}) is False

    def test_build_publish_properties_none_when_empty(self, install_fake_paho):
        host = MqttHost()
        assert host._build_publish_properties({}) is None

    def test_build_publish_properties_full(self, monkeypatch):
        # Use real paho Properties to assert concrete field assignment.
        require_import("paho.mqtt.properties")
        host = MqttHost()
        args = {
            "response_topic": "resp/topic",
            "correlation_id": "abc123",
            "content_type": "application/json",
            "message_expiry": "60",
            "user_prop": ["a=1", "b=2", "noequals"],
        }
        props = host._build_publish_properties(args)
        assert props is not None
        assert props.ResponseTopic == "resp/topic"
        assert props.CorrelationData == b"abc123"
        assert props.ContentType == "application/json"
        assert props.PayloadFormatIndicator == 1
        assert props.MessageExpiryInterval == 60
        # "noequals" (no '=') is dropped
        assert props.UserProperty == [("a", "1"), ("b", "2")]


# ---------------------------------------------------------------------------
# _extract_message_properties / _format_properties_debug
# ---------------------------------------------------------------------------


class TestMessagePropertyExtraction:
    def test_extract_full(self):
        host = MqttHost()
        msg = FakeProperties(
            properties=FakeProperties(
                ResponseTopic="r/t",
                CorrelationData=b"hello",
                ContentType="text/plain",
                MessageExpiryInterval=30,
                UserProperty=[("k", "v")],
            )
        )
        out = host._extract_message_properties(msg)
        assert out == {
            "response_topic": "r/t",
            "correlation_id": "hello",
            "content_type": "text/plain",
            "message_expiry": 30,
            "user_properties": [("k", "v")],
        }

    def test_extract_non_utf8_correlation_falls_back_to_hex(self):
        host = MqttHost()
        msg = FakeProperties(properties=FakeProperties(CorrelationData=b"\xff\xfe"))
        out = host._extract_message_properties(msg)
        assert out["correlation_id"] == "fffe"

    def test_extract_no_properties_returns_empty(self):
        host = MqttHost()
        assert host._extract_message_properties(FakeProperties(properties=None)) == {}
        assert host._extract_message_properties(object()) == {}

    def test_format_properties_debug(self):
        host = MqttHost()
        props = {
            "response_topic": "r",
            "correlation_id": "c",
            "content_type": "ct",
            "message_expiry": 5,
            "user_properties": [("x", "y")],
        }
        s = host._format_properties_debug(props)
        assert "ResponseTopic=r" in s
        assert "CorrelationID=c" in s
        assert "ContentType=ct" in s
        assert "Expiry=5s" in s
        assert "x=y" in s

    def test_format_properties_debug_empty(self):
        host = MqttHost()
        assert host._format_properties_debug({}) == ""


# ---------------------------------------------------------------------------
# _attempt_connect
# ---------------------------------------------------------------------------


class TestAttemptConnect:
    def _factory(self, **scenario):
        def factory(**kw):
            c = FakeClient(**kw)
            for k, v in scenario.items():
                setattr(c, k, v)
            return c

        return factory

    def test_successful_connect(self, install_fake_paho):
        install_fake_paho(self._factory(_reason_code=FakeReasonCode(0, "Success")))
        host = MqttHost()
        client = host._create_mqtt_client()
        ok, reason = host._attempt_connect(client, timeout=0.5)
        assert ok is True
        assert reason == "Success"
        assert client.connected_args == ("broker.test", 1883, 10)
        assert client.disconnect_called is True

    def test_auth_failure_reports_reason(self, install_fake_paho):
        install_fake_paho(self._factory(_reason_code=FakeReasonCode(5, "Not authorized")))
        host = MqttHost()
        client = host._create_mqtt_client()
        ok, reason = host._attempt_connect(client, timeout=0.5)
        assert ok is False
        assert reason == "Not authorized"

    def test_connect_exception_returns_error_string(self, install_fake_paho):
        install_fake_paho(self._factory(_connect_exc=OSError("connection refused")))
        host = MqttHost()
        client = host._create_mqtt_client()
        ok, reason = host._attempt_connect(client, timeout=0.5)
        assert ok is False
        assert "connection refused" in reason
        assert client.disconnect_called is True

    def test_v5_client_against_3x_server_indexerror(self, install_fake_paho):
        install_fake_paho(self._factory(_loop_exc=IndexError()))
        host = MqttHost(protocol_version=5)
        client = host._create_mqtt_client()
        ok, reason = host._attempt_connect(client, timeout=0.5)
        assert ok is False
        assert reason == "Server does not support MQTT 5.0"

    def test_disconnect_exception_swallowed(self, install_fake_paho):
        def factory(**kw):
            c = FakeClient(**kw)
            c._reason_code = FakeReasonCode(0, "Success")

            def boom():
                raise RuntimeError("nope")

            c.disconnect = boom
            return c

        install_fake_paho(factory)
        host = MqttHost()
        client = host._create_mqtt_client()
        # disconnect() in the finally block raises but is swallowed
        ok, reason = host._attempt_connect(client, timeout=0.5)
        assert ok is True

    def test_non_v5_loop_indexerror_propagates_as_error(self, install_fake_paho):
        install_fake_paho(self._factory(_loop_exc=KeyError("boom")))
        host = MqttHost(protocol_version=4)
        client = host._create_mqtt_client()
        ok, reason = host._attempt_connect(client, timeout=0.5)
        # KeyError is re-raised inside loop then caught by outer except -> error string
        assert ok is False
        assert "boom" in reason


# ---------------------------------------------------------------------------
# _attempt_connect_with_properties (used by enumeration)
# ---------------------------------------------------------------------------


class TestAttemptConnectWithProperties:
    def _install(self, install_fake_paho, **scenario):
        def factory(**kw):
            c = FakeClient(**kw)
            for k, v in scenario.items():
                setattr(c, k, v)
            return c

        install_fake_paho(factory)

    def test_success_marks_supported(self, install_fake_paho):
        self._install(install_fake_paho, _reason_code=FakeReasonCode(0, "Success"))
        host = MqttHost(protocol_version=4)
        ok, reason, props, supported = host._attempt_connect_with_properties(4, timeout=0.5)
        assert ok is True
        assert supported is True
        assert reason == "Success"

    def test_auth_failure_still_supported(self, install_fake_paho):
        # rc 0x87 (not authorized) is NOT a protocol-rejection -> version supported
        self._install(install_fake_paho, _reason_code=FakeReasonCode(0x87, "NotAuthorized"))
        host = MqttHost(protocol_version=4)
        ok, reason, props, supported = host._attempt_connect_with_properties(4, timeout=0.5)
        assert ok is False
        assert supported is True

    def test_unsupported_protocol_version_code(self, install_fake_paho):
        # 0x84 = unsupported protocol version -> NOT supported
        self._install(install_fake_paho, _reason_code=FakeReasonCode(0x84, "BadVersion"))
        host = MqttHost(protocol_version=5)
        ok, reason, props, supported = host._attempt_connect_with_properties(5, timeout=0.5)
        assert ok is False
        assert supported is False

    def test_v5_keyerror_means_3x_server(self, install_fake_paho):
        self._install(install_fake_paho, _loop_exc=KeyError())
        host = MqttHost(protocol_version=5)
        ok, reason, props, supported = host._attempt_connect_with_properties(5, timeout=0.5)
        assert ok is False
        assert supported is False
        assert reason == "Server sent MQTT 3.x response"

    def test_v5_captures_connack_capabilities(self, install_fake_paho):
        connack = FakeProperties(
            MaximumQoS=2,
            RetainAvailable=1,
            WildcardSubscriptionAvailable=0,
            SubscriptionIdentifierAvailable=1,
            SharedSubscriptionAvailable=1,
            MaximumPacketSize=1048576,
            TopicAliasMaximum=10,
            ReceiveMaximum=20,
            ServerKeepAlive=60,
            AssignedClientIdentifier="auto-id",
            ServerReference="other.broker:1883",
            ReasonString="OK",
            ResponseInformation="resp/info",
            SessionExpiryInterval=300,
        )
        self._install(
            install_fake_paho,
            _reason_code=FakeReasonCode(0, "Success"),
            _connack_props=connack,
        )
        host = MqttHost(protocol_version=5)
        ok, reason, props, supported = host._attempt_connect_with_properties(5, timeout=0.5)
        assert ok is True
        assert props["max_qos"] == 2
        assert props["retain_available"] is True
        assert props["wildcard_subscription"] is False
        assert props["subscription_identifier"] is True
        assert props["shared_subscription"] is True
        assert props["max_packet_size"] == 1048576
        assert props["topic_alias_max"] == 10
        assert props["receive_max"] == 20
        assert props["server_keepalive"] == 60
        assert props["assigned_client_id"] == "auto-id"
        assert props["server_reference"] == "other.broker:1883"
        assert props["reason_string"] == "OK"
        assert props["response_info"] == "resp/info"
        assert props["session_expiry"] == 300

    def test_reason_code_value_attr_rejection(self, install_fake_paho):
        # A ReasonCode-like object that has .value but NO __int__: it survives
        # into the rejection check, which reads .value (line 378). value 0x84
        # (unsupported protocol version) -> NOT supported.
        class ValueOnlyReasonCode:
            value = 0x84

            def __str__(self):
                return "BadVersion"

        self._install(install_fake_paho, _reason_code=ValueOnlyReasonCode())
        host = MqttHost(protocol_version=4)
        ok, reason, props, supported = host._attempt_connect_with_properties(4, timeout=0.5)
        assert ok is False
        assert supported is False

    def test_reason_code_value_attr_supported(self, install_fake_paho):
        # Same .value path but a non-rejection code (auth failure 0x87) -> supported.
        class ValueOnlyReasonCode:
            value = 0x87

            def __str__(self):
                return "NotAuthorized"

        self._install(install_fake_paho, _reason_code=ValueOnlyReasonCode())
        host = MqttHost(protocol_version=4)
        ok, reason, props, supported = host._attempt_connect_with_properties(4, timeout=0.5)
        assert ok is False
        assert supported is True

    def test_reason_code_unconvertible_treated_as_unsupported(self, install_fake_paho):
        # A reason code object with no .value and a non-int str() -> the int(rc)
        # branch raises ValueError, caught at 381-382 -> rc=-1 -> unsupported.
        class StrReasonCode:
            def __str__(self):
                return "not-a-number"

        rc = StrReasonCode()
        # on_connect stores reason_code as-is (no __int__), reason str() is truthy
        self._install(install_fake_paho, _reason_code=rc)
        host = MqttHost(protocol_version=4)
        ok, reason, props, supported = host._attempt_connect_with_properties(4, timeout=0.5)
        assert ok is False
        assert supported is False

    def test_non_v5_keyerror_reraised_into_outer_handler(self, install_fake_paho):
        # KeyError during loop() for a non-5 probe is re-raised (line 360) and
        # caught by the outer handler -> unsupported with the error string.
        self._install(install_fake_paho, _loop_exc=KeyError("parse"))
        host = MqttHost(protocol_version=4)
        ok, reason, props, supported = host._attempt_connect_with_properties(4, timeout=0.5)
        assert ok is False
        assert supported is False
        assert "parse" in reason

    def test_connect_exception_returns_unsupported(self, install_fake_paho):
        self._install(install_fake_paho, _connect_exc=OSError("refused"))
        host = MqttHost(protocol_version=4)
        ok, reason, props, supported = host._attempt_connect_with_properties(4, timeout=0.5)
        assert ok is False
        assert supported is False
        assert "refused" in reason
        assert props == {}

    def test_plain_int_reason_code_supported(self, install_fake_paho):
        # A reason code that is a plain int (no .value attr) takes the int() branch
        # and, being a non-rejection code, is treated as supported.
        self._install(install_fake_paho, _reason_code=4)
        host = MqttHost(protocol_version=4)
        ok, reason, props, supported = host._attempt_connect_with_properties(4, timeout=0.5)
        assert ok is False
        assert supported is True  # rc=4 not in {0x81,0x82,0x84}

    def test_tls_context_applied_in_version_probe(self, install_fake_paho):
        captured = {}

        def factory(**kw):
            c = FakeClient(**kw)
            c._reason_code = FakeReasonCode(0, "Success")
            orig = c.tls_set_context

            def record(ctx):
                captured["ctx"] = ctx
                return orig(ctx)

            c.tls_set_context = record
            return c

        install_fake_paho(factory)
        host = MqttHost(protocol_version=4, use_tls=True, args={"tls_insecure": True})
        host._attempt_connect_with_properties(4, timeout=0.5)
        assert isinstance(captured["ctx"], ssl.SSLContext)

    def test_disconnect_exception_swallowed(self, install_fake_paho):
        def factory(**kw):
            c = FakeClient(**kw)
            c._reason_code = FakeReasonCode(0, "Success")

            def boom():
                raise RuntimeError("disconnect failed")

            c.disconnect = boom
            return c

        install_fake_paho(factory)
        host = MqttHost(protocol_version=4)
        # finally-block disconnect raises but must be swallowed
        ok, reason, props, supported = host._attempt_connect_with_properties(4, timeout=0.5)
        assert ok is True


# ---------------------------------------------------------------------------
# enumerate_mqtt_versions (drives _attempt_connect_with_properties 3x)
# ---------------------------------------------------------------------------


class TestEnumerateVersions:
    def test_all_versions_anonymous(self, install_fake_paho):
        # Every probe succeeds anonymously, v5 carries capabilities.
        def factory(**kw):
            c = FakeClient(**kw)
            c._reason_code = FakeReasonCode(0, "Success")
            if kw.get("protocol") == 5:
                c._connack_props = FakeProperties(MaximumQoS=2, RetainAvailable=1)
            return c

        install_fake_paho(factory)
        host = MqttHost(protocol_version=4)
        result = host.enumerate_mqtt_versions()

        assert result["versions_supported"] == ["3.1", "3.1.1", "5.0"]
        assert result["anonymous_allowed"] is True
        assert result["requires_auth"] is False
        assert result["recommended_version"] == "5.0"
        assert result["mqtt5_capabilities"]["max_qos"] == 2
        # capabilities surfaced in operator output
        assert "MaxQoS=2" in host.logger.text()

    def test_all_versions_auth_required(self, install_fake_paho):
        # Auth-required everywhere: rc 0x87, supported but not anonymous.
        def factory(**kw):
            c = FakeClient(**kw)
            c._reason_code = FakeReasonCode(0x87, "NotAuthorized")
            return c

        install_fake_paho(factory)
        host = MqttHost(protocol_version=4)
        result = host.enumerate_mqtt_versions()

        assert set(result["versions_supported"]) == {"3.1", "3.1.1", "5.0"}
        assert result["requires_auth"] is True
        assert result["anonymous_allowed"] is False
        assert result["recommended_version"] == "5.0"
        assert "auth required" in host.logger.text()

    def test_no_versions_supported(self, install_fake_paho):
        # Connection refused for every probe -> nothing detected.
        def factory(**kw):
            c = FakeClient(**kw)
            c._connect_exc = OSError("refused")
            return c

        install_fake_paho(factory)
        host = MqttHost(protocol_version=4)
        result = host.enumerate_mqtt_versions()

        assert result["versions_supported"] == []
        assert result["recommended_version"] is None
        assert any(level == "warning" for level, _ in host.logger.messages)

    def test_only_legacy_versions_supported(self, install_fake_paho):
        # 3.1 / 3.1.1 succeed; 5.0 gets a 3.x response (KeyError path).
        def factory(**kw):
            c = FakeClient(**kw)
            if kw.get("protocol") == 5:
                c._loop_exc = KeyError()
            else:
                c._reason_code = FakeReasonCode(0, "Success")
            return c

        install_fake_paho(factory)
        host = MqttHost(protocol_version=4)
        result = host.enumerate_mqtt_versions()

        assert "5.0" not in result["versions_supported"]
        assert result["recommended_version"] == "3.1.1"

    def test_capability_security_notes_emitted(self, install_fake_paho):
        # v5 reports wildcard + retain DISABLED -> security-note lines fire.
        def factory(**kw):
            c = FakeClient(**kw)
            c._reason_code = FakeReasonCode(0, "Success")
            if kw.get("protocol") == 5:
                c._connack_props = FakeProperties(
                    MaximumQoS=1,
                    RetainAvailable=0,
                    WildcardSubscriptionAvailable=0,
                    SharedSubscriptionAvailable=0,
                    MaximumPacketSize=256,
                )
            return c

        install_fake_paho(factory)
        host = MqttHost(protocol_version=4)
        host.enumerate_mqtt_versions()
        text = host.logger.text()
        assert "Wildcard=No" in text
        assert "SharedSub=No" in text
        assert "MaxPacket=256" in text
        assert "Wildcard subscriptions disabled" in text
        assert "Retain disabled" in text

    def test_recommended_version_3_1_only(self, install_fake_paho):
        # Only the 3.1 probe (protocol const 3) succeeds.
        def factory(**kw):
            c = FakeClient(**kw)
            if kw.get("protocol") == 3:
                c._reason_code = FakeReasonCode(0, "Success")
            else:
                c._reason_code = FakeReasonCode(0x84, "BadVersion")
            return c

        install_fake_paho(factory)
        host = MqttHost(protocol_version=4)
        result = host.enumerate_mqtt_versions()
        assert result["versions_supported"] == ["3.1"]
        assert result["recommended_version"] == "3.1"


# ---------------------------------------------------------------------------
# _check_tls_certificate (socket boundary mocked)
# ---------------------------------------------------------------------------


class _CertSocket:
    def __init__(self, der):
        self._der = der

    def getpeercert(self, binary_form=False):
        return self._der


def _make_self_signed_der():
    """Build a minimal self-signed cert DER for display_cert_info to parse."""
    crypto = require_import("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "broker.test")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    assert crypto  # importorskip guard
    return cert.public_bytes(serialization.Encoding.DER)


class TestCheckTlsCertificate:
    def test_cert_extracted_from_client_socket(self):
        der = _make_self_signed_der()
        host = MqttHost(use_tls=True)

        class _Client:
            def socket(self_inner):
                return _CertSocket(der)

        # Should parse the DER cert and emit findings without raising.
        host._check_tls_certificate(_Client())
        # display_cert_info logs through host.logger; at least one message recorded
        assert len(host.logger.messages) >= 1

    def test_socket_access_exception_falls_back(self):
        host = MqttHost(use_tls=True)
        host.host = "127.0.0.1"
        host.port = 1  # standalone probe will fail to connect, handled gracefully

        class _Client:
            def socket(self_inner):
                raise RuntimeError("socket not ready")

        # socket() raising is caught (lines 31-32), then standalone probe runs.
        host._check_tls_certificate(_Client())

        # The socket() exception is logged at debug, and since no cert_der was
        # extracted, the code falls through to the standalone probe branch
        # instead of calling display_cert_info.
        debug_msgs = [m for level, m in host.logger.messages if level == "debug"]
        assert any("Could not extract cert from client socket" in m for m in debug_msgs)
        # ...and then the standalone probe actually ran and failed to connect
        # to the closed port, logging its own debug message too.
        assert any("TLS certificate probe failed" in m for m in debug_msgs)

    def test_no_socket_falls_back_to_standalone_probe(self, monkeypatch):
        host = MqttHost(use_tls=True)
        host.host = "127.0.0.1"
        host.port = 1  # nothing listening -> standalone probe fails gracefully

        class _Client:
            def socket(self_inner):
                return None

        # Must not raise even though the fallback probe cannot connect.
        host._check_tls_certificate(_Client())

        # socket() returned None -> no exception, no cert_der, so display_cert_info
        # was never reached; only the standalone-probe path could have logged,
        # and it fails to connect to the closed port.
        debug_msgs = [m for level, m in host.logger.messages if level == "debug"]
        assert not any("Could not extract cert" in m for m in debug_msgs)
        assert any("TLS certificate probe failed" in m for m in debug_msgs)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
