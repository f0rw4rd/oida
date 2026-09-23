"""Integration tests for the IEEE 1722 / AVTP passive listener.

Tests cover:
- AVTP subtype decoding (AAF, CVF, CRF, 61883)
- Stream ID extraction from subtype layers
- Stream vs. control classification
- Talker device registration (L2 / MAC-addressed)
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

_PCAP = "ieee1722/oida_avtp_subtypes.pcap"


class TestIEEE1722Passive:
    def test_basic_extraction(self):
        listener, devices, result = _run_listener_test(
            "ieee1722",
            "IEEE1722PassiveListener",
            "ieee1722",
            _PCAP,
            min_devices=1,
            min_interactions=4,
            expect_details=["subtype_name", "subtype"],
            expect_operations=["AAF", "CRF"],
        )
        assert len(listener.interactions) == 4

    def test_subtypes_decoded(self):
        listener, _, _ = _run_listener_test(
            "ieee1722", "IEEE1722PassiveListener", "ieee1722", _PCAP
        )
        names = {ix.details.get("subtype_name") for ix in listener.interactions}
        assert "AAF (Audio)" in names, f"got {names}"
        assert "CRF (Clock Reference)" in names, f"got {names}"
        assert "CVF (Compressed Video)" in names, f"got {names}"

    def test_stream_ids_extracted(self):
        listener, _, _ = _run_listener_test(
            "ieee1722",
            "IEEE1722PassiveListener",
            "ieee1722",
            _PCAP,
            expect_details=["stream_id"],
        )
        stream_ids = {
            ix.details.get("stream_id")
            for ix in listener.interactions
            if ix.details.get("stream_id")
        }
        assert len(stream_ids) >= 3, f"expected distinct stream ids; got {stream_ids}"

    def test_talker_registered(self):
        listener, devices, _ = _run_listener_test(
            "ieee1722", "IEEE1722PassiveListener", "ieee1722", _PCAP, min_devices=1
        )
        talkers = [
            d
            for d in devices.values()
            if getattr(d, "ieee1722_passive_data", {}).get("role") == "talker"
        ]
        assert talkers, "no AVTP talker device registered"

    def test_harvest_table(self):
        listener, _, result = _run_listener_test(
            "ieee1722", "IEEE1722PassiveListener", "ieee1722", _PCAP
        )
        titles = {t.get("title") for t in result.get("tables", [])}
        assert "AVTP Talkers / Streams" in titles, f"got {titles}"
