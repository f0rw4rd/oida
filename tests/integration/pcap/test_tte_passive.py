"""Integration tests for the TTEthernet (TTE / SAE AS6802) passive listener.

Tests cover:
- PCF (Protocol Control Frame) decoding and integration-cycle extraction
- MAC extraction from the eth fields nested in the tte layer (L2 handoff)
- Sync-master vs. end-system role classification
- Harvest station-inventory table quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

_PCAP = "tte/wireshark_TTE_mix_small.pcap"


class TestTTEPassive:
    def test_basic_extraction(self):
        listener, devices, result = _run_listener_test(
            "tte",
            "TTEPassiveListener",
            "tte || tte_pcf",
            _PCAP,
            min_devices=1,
            min_interactions=1,
            expect_details=["frame_type"],
            expect_operations=["TTE"],
        )
        assert len(listener.interactions) >= 1

    def test_mac_extracted(self):
        """MACs live inside the tte layer (no standalone eth) -- must resolve."""
        listener, devices, _ = _run_listener_test(
            "tte", "TTEPassiveListener", "tte || tte_pcf", _PCAP, min_devices=1
        )
        macs = {d.mac_address for d in devices.values() if d.mac_address}
        assert macs, "no MAC extracted from TTE frames"
        # the sync master in the sample capture
        assert any(m.startswith("00:1b:21") for m in macs), f"got {macs}"

    def test_pcf_frames(self):
        listener, _, _ = _run_listener_test("tte", "TTEPassiveListener", "tte || tte_pcf", _PCAP)
        frame_types = {ix.details.get("frame_type") for ix in listener.interactions}
        assert "PCF" in frame_types, f"got {frame_types}"

    def test_sync_master_role(self):
        listener, devices, _ = _run_listener_test(
            "tte", "TTEPassiveListener", "tte || tte_pcf", _PCAP
        )
        roles = {getattr(d, "tte_passive_data", {}).get("role") for d in devices.values()}
        assert "sync_master" in roles, f"got {roles}"

    def test_harvest_table(self):
        listener, _, result = _run_listener_test(
            "tte", "TTEPassiveListener", "tte || tte_pcf", _PCAP
        )
        titles = {t.get("title") for t in result.get("tables", [])}
        assert "TTEthernet Stations" in titles, f"got {titles}"
