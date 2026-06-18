"""Integration tests for MQTT passive listener in EK mode.

Tests cover all T1 field extractions plus key T2 fields:
- mqtt.protoname: protocol name string
- mqtt.ver: MQTT protocol version
- mqtt.msgid: message ID for QoS tracking
- mqtt.username_len: username length
- mqtt.username: username from CONNECT
- mqtt.passwd: password from CONNECT
- mqtt.clientid: client identifier
- mqtt.msgtype: message type dispatching (CONNECT, CONNACK, PUBLISH, SUBSCRIBE, etc.)
- mqtt.topic: topic string from PUBLISH/SUBSCRIBE
- mqtt.conack.val: CONNACK return code
- mqtt.kalive: keep-alive interval
- mqtt.qos: QoS level
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestMQTTPassiveEK:
    """MQTT-specific tests beyond the parametrized quality suite."""

    def test_mqtt_credentials_extracted(self):
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
            expect_details=["username"],
        )

        # MQTT credential extraction
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected at least 1 credential, got {len(creds)}"
        for cred in creds:
            assert cred["protocol"] == "MQTT"
            assert cred["username"], "Credential missing username"

    def test_mqtt_generated(self):
        """Generated MQTT pcap should also parse without errors."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/generated_mqtt.pcap",
        )


class TestMQTTProtoname:
    """T1 field: mqtt.protoname -- protocol name string."""

    def test_protoname_in_connect_details(self):
        """CONNECT interactions must include protoname in details."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
            expect_details=["protoname"],
        )

        connects = [ix for ix in listener.interactions if ix.details.get("msg_type") == "CONNECT"]
        assert len(connects) >= 1, "No CONNECT interactions found"
        for ix in connects:
            pn = ix.details.get("protoname", "")
            assert pn, f"protoname missing in CONNECT details: {ix.details}"
            assert pn in ("MQTT", "MQIsdp"), f"Unexpected protoname: {pn}"

    def test_protoname_in_device_data(self):
        """Client device mqtt_passive_data must include protoname."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        client_devs = [d for d in devices.values() if d.device_type == "MQTT Client"]
        assert len(client_devs) >= 1, "No MQTT Client devices found"
        for dev in client_devs:
            pd = getattr(dev, "mqtt_passive_data", None)
            assert pd is not None, "mqtt_passive_data missing on client device"
            assert pd.get("protoname"), f"protoname missing in device data: {pd}"

    def test_protoname_generated_pcap(self):
        """Generated pcap also has protoname in CONNECT."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/generated_mqtt.pcap",
            expect_details=["protoname"],
        )
        connects = [ix for ix in listener.interactions if ix.details.get("msg_type") == "CONNECT"]
        assert connects[0].details["protoname"] == "MQTT"


class TestMQTTVersion:
    """T1 field: mqtt.ver -- MQTT protocol version."""

    def test_ver_in_connect_details(self):
        """CONNECT interactions must include ver and ver_display."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
            expect_details=["ver"],
        )

        connects = [ix for ix in listener.interactions if ix.details.get("msg_type") == "CONNECT"]
        assert len(connects) >= 1
        for ix in connects:
            assert ix.details.get("ver"), f"ver missing: {ix.details}"
            assert ix.details.get("ver_display"), f"ver_display missing: {ix.details}"

    def test_ver_display_human_readable(self):
        """ver_display should be a human-readable version like '3.1.1'."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        connects = [ix for ix in listener.interactions if ix.details.get("msg_type") == "CONNECT"]
        for ix in connects:
            vd = ix.details.get("ver_display", "")
            assert vd in ("3.1", "3.1.1", "5.0"), f"Unexpected ver_display: {vd}"

    def test_version_in_device_data(self):
        """Client device data should include mqtt_version."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        client_devs = [d for d in devices.values() if d.device_type == "MQTT Client"]
        for dev in client_devs:
            pd = getattr(dev, "mqtt_passive_data", None)
            assert pd is not None
            assert pd.get("mqtt_version"), f"mqtt_version missing: {pd}"

    def test_version_in_broker_protocol_string(self):
        """Broker protocol string should include version."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        broker_devs = [d for d in devices.values() if d.device_type == "MQTT Broker"]
        assert len(broker_devs) >= 1
        for dev in broker_devs:
            pd = getattr(dev, "mqtt_passive_data", None)
            assert pd is not None
            proto = pd.get("protocol", "")
            assert "v" in proto, f"Protocol string lacks version: {proto}"


class TestMQTTMsgID:
    """T1 field: mqtt.msgid -- message ID for QoS tracking."""

    def test_msgid_in_subscribe(self):
        """SUBSCRIBE interactions must include msgid in details."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        subscribes = [
            ix for ix in listener.interactions if ix.details.get("msg_type") == "SUBSCRIBE"
        ]
        assert len(subscribes) >= 1, "No SUBSCRIBE interactions found"
        for ix in subscribes:
            assert ix.details.get("msgid"), f"msgid missing in SUBSCRIBE: {ix.details}"

    def test_msgid_in_suback(self):
        """SUBACK interactions must include msgid."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        subacks = [ix for ix in listener.interactions if ix.details.get("msg_type") == "SUBACK"]
        assert len(subacks) >= 1, "No SUBACK interactions found"
        for ix in subacks:
            assert ix.details.get("msgid"), f"msgid missing in SUBACK: {ix.details}"

    def test_msgid_appears_in_interactions(self):
        """Msg ID should be populated in interaction details."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        has_msgid = any(ix.details.get("msgid") for ix in listener.interactions)
        assert has_msgid, "No interactions have a non-empty msgid value"


class TestMQTTUsernamelen:
    """T1 field: mqtt.username_len -- username length."""

    def test_username_len_in_connect_details(self):
        """CONNECT details must include username_len."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
            expect_details=["username_len"],
        )

        connects = [ix for ix in listener.interactions if ix.details.get("msg_type") == "CONNECT"]
        assert len(connects) >= 1
        for ix in connects:
            ulen = ix.details.get("username_len", "")
            assert ulen, f"username_len missing in CONNECT: {ix.details}"
            assert int(ulen) > 0, f"username_len should be positive: {ulen}"

    def test_username_len_generated_pcap(self):
        """Generated pcap also has username_len."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/generated_mqtt.pcap",
            expect_details=["username_len"],
        )
        connects = [ix for ix in listener.interactions if ix.details.get("msg_type") == "CONNECT"]
        assert connects[0].details.get("username_len")


class TestMQTTMsgTypeDispatch:
    """T2 field: mqtt.msgtype -- message type dispatching."""

    def test_connect_interactions_detected(self):
        """CONNECT messages produce interactions with msg_type=CONNECT."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        connects = [ix for ix in listener.interactions if ix.details.get("msg_type") == "CONNECT"]
        assert len(connects) >= 1
        for ix in connects:
            assert ix.operation == "MQTT CONNECT"
            assert ix.direction == "request"

    def test_connack_interactions_detected(self):
        """CONNACK messages produce response interactions."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        connacks = [ix for ix in listener.interactions if ix.details.get("msg_type") == "CONNACK"]
        assert len(connacks) >= 1, "No CONNACK interactions found"
        for ix in connacks:
            assert ix.operation == "MQTT CONNACK"
            assert ix.direction == "response"

    def test_publish_interactions_detected(self):
        """PUBLISH messages produce interactions with topic."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        publishes = [ix for ix in listener.interactions if ix.details.get("msg_type") == "PUBLISH"]
        assert len(publishes) >= 1, "No PUBLISH interactions found"
        for ix in publishes:
            assert ix.operation == "MQTT PUBLISH"
            assert ix.details.get("topic"), f"topic missing in PUBLISH: {ix.details}"

    def test_subscribe_interactions_detected(self):
        """SUBSCRIBE messages produce interactions with topic and msgid."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        subscribes = [
            ix for ix in listener.interactions if ix.details.get("msg_type") == "SUBSCRIBE"
        ]
        assert len(subscribes) >= 1, "No SUBSCRIBE interactions found"
        for ix in subscribes:
            assert ix.operation == "MQTT SUBSCRIBE"
            assert ix.details.get("topic"), f"topic missing in SUBSCRIBE: {ix.details}"

    def test_disconnect_interactions_detected(self):
        """DISCONNECT messages produce interactions."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        disconnects = [
            ix for ix in listener.interactions if ix.details.get("msg_type") == "DISCONNECT"
        ]
        assert len(disconnects) >= 1, "No DISCONNECT interactions found"
        for ix in disconnects:
            assert ix.operation == "MQTT DISCONNECT"

    def test_multiple_msg_types_in_single_pcap(self):
        """A typical session has CONNECT, CONNACK, SUBSCRIBE, SUBACK, PUBLISH, DISCONNECT."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        seen_types = {ix.details.get("msg_type") for ix in listener.interactions}
        expected_types = {"CONNECT", "CONNACK", "SUBSCRIBE", "SUBACK", "PUBLISH", "DISCONNECT"}
        missing = expected_types - seen_types
        assert not missing, f"Missing msg types: {missing}; seen: {seen_types}"


class TestMQTTTopicExtraction:
    """T2 field: mqtt.topic -- topic string from PUBLISH/SUBSCRIBE."""

    def test_topic_in_publish_details(self):
        """PUBLISH interactions must have topic in details."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        publishes = [ix for ix in listener.interactions if ix.details.get("msg_type") == "PUBLISH"]
        for ix in publishes:
            assert ix.details.get("topic"), f"topic missing: {ix.details}"
            assert ix.details["topic"] != "?", "topic should not be placeholder"

    def test_topic_in_subscribe_details(self):
        """SUBSCRIBE interactions must have topic."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        subscribes = [
            ix for ix in listener.interactions if ix.details.get("msg_type") == "SUBSCRIBE"
        ]
        for ix in subscribes:
            assert ix.details.get("topic"), f"topic missing: {ix.details}"

    def test_topic_appears_in_interactions(self):
        """Topic should be populated in interaction details for PUBLISH/SUBSCRIBE."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        has_topic = any(
            ix.details.get("topic")
            for ix in listener.interactions
            if ix.details.get("msg_type") in ("PUBLISH", "SUBSCRIBE")
        )
        assert has_topic, "No PUBLISH/SUBSCRIBE interactions have a non-empty topic"


class TestMQTTConackVal:
    """T2 field: mqtt.conack.val -- CONNACK return code."""

    def test_conack_val_in_details(self):
        """CONNACK interactions include conack_val and conack_desc."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        connacks = [ix for ix in listener.interactions if ix.details.get("msg_type") == "CONNACK"]
        assert len(connacks) >= 1
        for ix in connacks:
            assert "conack_val" in ix.details, f"conack_val missing: {ix.details}"
            assert "conack_desc" in ix.details, f"conack_desc missing: {ix.details}"

    def test_conack_accepted(self):
        """conack_val=0 means Accepted."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        connacks = [ix for ix in listener.interactions if ix.details.get("msg_type") == "CONNACK"]
        # This pcap has successful connections
        accepted = [ix for ix in connacks if ix.details.get("conack_val") == "0"]
        assert len(accepted) >= 1, "No accepted CONNACK found"
        for ix in accepted:
            assert "Accepted" in ix.details.get("conack_desc", "")


class TestMQTTKeepalive:
    """T2 field: mqtt.kalive -- keep-alive interval."""

    def test_kalive_in_connect_details(self):
        """CONNECT interactions must include kalive."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
            expect_details=["kalive"],
        )

        connects = [ix for ix in listener.interactions if ix.details.get("msg_type") == "CONNECT"]
        for ix in connects:
            assert ix.details.get("kalive"), f"kalive missing: {ix.details}"
            assert int(ix.details["kalive"]) > 0

    def test_kalive_in_device_data(self):
        """Client device data should include kalive."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        client_devs = [d for d in devices.values() if d.device_type == "MQTT Client"]
        for dev in client_devs:
            pd = getattr(dev, "mqtt_passive_data", None)
            assert pd is not None
            assert pd.get("kalive"), f"kalive missing in device data: {pd}"


class TestMQTTInteractionTable:
    """Verify the PROTOCOL_COLUMNS + _format_protocol_columns wiring."""

    def test_protocol_columns_set(self):
        """PROTOCOL_COLUMNS is set on the listener class."""
        from oida.pcap.passive.mqtt import MQTTPassiveListener

        assert MQTTPassiveListener.PROTOCOL_COLUMNS
        assert "type" in MQTTPassiveListener.PROTOCOL_COLUMNS

    def test_format_protocol_columns_count(self):
        """_format_protocol_columns output must match PROTOCOL_COLUMNS length."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        from oida.pcap.passive.mqtt import MQTTPassiveListener

        expected = len(MQTTPassiveListener.PROTOCOL_COLUMNS)
        for ix in listener.interactions:
            row = listener._format_protocol_columns(ix)
            assert len(row) == expected, f"Row has {len(row)} columns, expected {expected}: {row}"


class TestMQTTCredentialDedup:
    """Verify credential deduplication works correctly."""

    def test_no_duplicate_credentials(self):
        """Same username+password+client_id+client_ip+server_ip should not be duplicated."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        creds = listener.get_credentials_summary()
        seen = set()
        for c in creds:
            key = (
                c["username"],
                c.get("password", ""),
                c.get("client_id", ""),
                c["client_ip"],
                c["server_ip"],
            )
            assert key not in seen, f"Duplicate credential: {key}"
            seen.add(key)


class TestMQTTFlowTracking:
    """Verify flow_id is populated on all interactions."""

    def test_all_interactions_have_flow_id(self):
        """Every interaction should have a non-empty flow_id."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        for ix in listener.interactions:
            assert ix.flow_id, (
                f"Empty flow_id on interaction: {ix.operation} {ix.details.get('msg_type')}"
            )

    def test_both_directions_recorded(self):
        """Both request and response directions should appear."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        directions = {ix.direction for ix in listener.interactions}
        assert "request" in directions, "No request-direction interactions"
        assert "response" in directions, "No response-direction interactions"


class TestMQTTDeviceData:
    """Verify device enrichment with new fields."""

    def test_broker_device_created(self):
        """Broker device should be created with role and protocol."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        brokers = [d for d in devices.values() if d.device_type == "MQTT Broker"]
        assert len(brokers) >= 1
        for dev in brokers:
            pd = getattr(dev, "mqtt_passive_data", None)
            assert pd is not None
            assert pd.get("role") == "broker"
            assert "MQTT" in pd.get("protocol", "")

    def test_client_device_created(self):
        """Client device should be created with client_id and version."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        clients = [d for d in devices.values() if d.device_type == "MQTT Client"]
        assert len(clients) >= 1
        for dev in clients:
            pd = getattr(dev, "mqtt_passive_data", None)
            assert pd is not None
            assert pd.get("role") == "client"
            assert pd.get("client_id"), f"client_id missing: {pd}"
            assert pd.get("mqtt_version"), f"mqtt_version missing: {pd}"

    def test_both_endpoints_tracked(self):
        """Both broker and client devices should exist."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
            min_devices=2,
        )

        types = {d.device_type for d in devices.values()}
        assert "MQTT Broker" in types, f"No broker device; types: {types}"
        assert "MQTT Client" in types, f"No client device; types: {types}"


class TestMQTTHarvestQuality:
    """Verify harvest() output structure and completeness."""

    def test_harvest_returns_dict(self):
        """harvest() should return a dict."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        assert isinstance(result, dict), f"Expected dict, got {type(result)}"

    def test_no_raw_dicts_in_table_cells(self):
        """No table cell should contain a raw dict or set."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/emreekin_mqtt_user_credentials.pcap",
        )

        for table in result.get("tables", []):
            for row in table.get("rows", []):
                for cell in row:
                    assert not isinstance(cell, dict), f"Raw dict in cell: {cell}"
                    assert not isinstance(cell, set), f"Raw set in cell: {cell}"

    def test_generated_pcap_harvest(self):
        """Generated pcap should also produce valid harvest output."""
        listener, devices, result = _run_listener_test(
            "mqtt",
            "MQTTPassiveListener",
            "mqtt",
            "mqtt/generated_mqtt.pcap",
        )

        assert isinstance(result, dict), f"Expected dict, got {type(result)}"
