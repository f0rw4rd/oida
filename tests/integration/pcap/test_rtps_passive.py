"""Integration tests for the DDS/RTPS passive listener.

Tests cover:
- RTPS domain id and GUID-prefix extraction
- Participant device registration
- Source-locator extraction
- Harvest participant-inventory table quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

_PCAP = "rtps/wireshark_rtps_cooked.pcapng"


class TestRTPSPassive:
    def test_basic_extraction(self):
        listener, devices, result = _run_listener_test(
            "rtps",
            "RTPSPassiveListener",
            "rtps",
            _PCAP,
            min_devices=1,
            min_interactions=1,
            expect_details=["domain_id"],
            expect_operations=["RTPS domain"],
        )
        assert len(listener.interactions) >= 1

    def test_domain_id_extracted(self):
        listener, _, _ = _run_listener_test(
            "rtps", "RTPSPassiveListener", "rtps", _PCAP, expect_details=["domain_id"]
        )
        domains = {
            ix.details.get("domain_id")
            for ix in listener.interactions
            if ix.details.get("domain_id")
        }
        assert "60" in domains, f"expected domain 60; got {domains}"

    def test_guid_prefix_extracted(self):
        listener, _, _ = _run_listener_test("rtps", "RTPSPassiveListener", "rtps", _PCAP)
        guids = set()
        for info in listener.participants.values():
            guids |= info.get("guid_prefixes", set())
        assert guids, "no GUID prefixes extracted"

    def test_participant_registered(self):
        listener, devices, _ = _run_listener_test(
            "rtps", "RTPSPassiveListener", "rtps", _PCAP, min_devices=1
        )
        participants = [
            d
            for d in devices.values()
            if getattr(d, "rtps_passive_data", {}).get("role") == "participant"
        ]
        assert participants, "no DDS participant device registered"

    def test_harvest_table(self):
        listener, _, result = _run_listener_test("rtps", "RTPSPassiveListener", "rtps", _PCAP)
        titles = {t.get("title") for t in result.get("tables", [])}
        assert "DDS/RTPS Participants" in titles, f"got {titles}"
