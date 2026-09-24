"""Integration tests for the MQTT-SN passive listener.

Tests cover:
- Message-type extraction across the full CONNECT->PUBLISH->DISCONNECT flow
- Gateway vs. client role classification
- Topic namespace mapping (REGISTER/PUBLISH)
- Harvest gateway/topic table quality
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

_PCAP = "mqttsn/oida_mqttsn_message_matrix.pcap"
_DECODE = {"udp.port==1883": "mqttsn"}


class TestMQTTSNPassive:
    def test_basic_extraction(self):
        listener, devices, result = _run_listener_test(
            "mqttsn",
            "MQTTSNPassiveListener",
            "mqttsn",
            _PCAP,
            min_devices=1,
            min_interactions=9,
            expect_details=["msg_name", "msg_type"],
            expect_operations=["CONNECT", "PUBLISH", "REGISTER", "SUBSCRIBE"],
            decode_as=_DECODE,
        )
        assert len(listener.interactions) == 9

    def test_message_types_seen(self):
        listener, _, _ = _run_listener_test(
            "mqttsn", "MQTTSNPassiveListener", "mqttsn", _PCAP, decode_as=_DECODE
        )
        names = {ix.details.get("msg_name") for ix in listener.interactions}
        assert {"ADVERTISE", "CONNECT", "REGISTER", "PUBLISH", "DISCONNECT"} <= names, (
            f"got {names}"
        )

    def test_client_id_extracted(self):
        listener, _, _ = _run_listener_test(
            "mqttsn", "MQTTSNPassiveListener", "mqttsn", _PCAP, decode_as=_DECODE
        )
        client_ids = {
            ix.details.get("client_id")
            for ix in listener.interactions
            if ix.details.get("client_id")
        }
        assert "sensor-01" in client_ids, f"got {client_ids}"

    def test_topics_mapped(self):
        listener, _, _ = _run_listener_test(
            "mqttsn", "MQTTSNPassiveListener", "mqttsn", _PCAP, decode_as=_DECODE
        )
        topics = set()
        for info in listener.nodes.values():
            topics |= info.get("topics", set())
        assert "temp/room1" in topics, f"got {topics}"

    def test_gateway_and_client_roles(self):
        listener, devices, _ = _run_listener_test(
            "mqttsn", "MQTTSNPassiveListener", "mqttsn", _PCAP, decode_as=_DECODE
        )
        roles = {getattr(d, "mqttsn_passive_data", {}).get("role") for d in devices.values()}
        assert "gateway" in roles and "client" in roles, f"got {roles}"

    def test_harvest_tables(self):
        listener, _, result = _run_listener_test(
            "mqttsn", "MQTTSNPassiveListener", "mqttsn", _PCAP, decode_as=_DECODE
        )
        titles = {t.get("title") for t in result.get("tables", [])}
        assert "MQTT-SN Topics" in titles, f"got {titles}"
