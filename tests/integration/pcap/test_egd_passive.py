"""Integration tests for the GE EGD passive listener.

Tests cover:
- EGD producer/exchange field extraction (pid, exid, status, csig)
- Producer device registration and aggregation
- Non-zero production status detection
- Harvest producer-inventory table quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

_PCAP = "egd/oida_egd_producer_exchanges.pcap"


class TestEGDPassive:
    def test_basic_extraction(self):
        listener, devices, result = _run_listener_test(
            "egd",
            "EGDPassiveListener",
            "egd",
            _PCAP,
            min_devices=1,
            min_interactions=3,
            expect_details=["producer_id", "exchange_id", "status"],
            expect_operations=["EGD produce"],
        )
        assert len(listener.interactions) == 3

    def test_producer_ids_extracted(self):
        listener, _, _ = _run_listener_test(
            "egd", "EGDPassiveListener", "egd", _PCAP, expect_details=["producer_id"]
        )
        pids = {ix.details.get("producer_id") for ix in listener.interactions}
        # producer id 0x0A0B0C0D is rendered as an IPv4 address by tshark
        assert "10.11.12.13" in pids, f"expected producer id; got {pids}"

    def test_exchange_ids_tracked(self):
        listener, _, _ = _run_listener_test("egd", "EGDPassiveListener", "egd", _PCAP)
        # exchange ids 100 and 200 were produced
        all_exchanges = set()
        for info in listener.producers.values():
            all_exchanges |= info["exchanges"]
        assert {"100", "200"} <= all_exchanges, f"got {all_exchanges}"

    def test_nonzero_status_flagged(self):
        """A producer error status (22) must be captured in details."""
        listener, _, _ = _run_listener_test("egd", "EGDPassiveListener", "egd", _PCAP)
        statuses = {ix.details.get("status_name") for ix in listener.interactions}
        # Label text is verbatim from the egd.stat value_string (packet-egd.c);
        # see tests/unit/pcap/test_egd_status_review.py.
        assert "Ethernet Interface does not support EGD" in statuses, f"got {statuses}"

    def test_producer_device_role(self):
        listener, devices, _ = _run_listener_test(
            "egd", "EGDPassiveListener", "egd", _PCAP, min_devices=1
        )
        producers = [
            d
            for d in devices.values()
            if getattr(d, "egd_passive_data", {}).get("role") == "producer"
        ]
        assert producers, "no EGD producer device registered"

    def test_harvest_table(self):
        listener, _, result = _run_listener_test("egd", "EGDPassiveListener", "egd", _PCAP)
        titles = {t.get("title") for t in result.get("tables", [])}
        assert "EGD Producers" in titles, f"got {titles}"
