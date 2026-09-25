"""Regression tests for the pcap-tail group GB fixes.

1. hsr.py - unbounded per-node supervision timestamp list.
   ``_supervision_times`` was appended one timestamp per supervision frame,
   for every node, for the entire capture, and never read anywhere.  A long
   capture on a real HSR ring (supervision every ~2 ms per node) grows this
   dict without bound.  Replaced by a bounded ``HSRNode.last_supervision``
   scalar surfaced in ``hsr_passive_data``.

2. hartip.py - ambiguous device-status abbreviations.
   ``_decode_device_status`` took only the first word of each flag
   description, so 0xd0 rendered as "Device | Configuration | More"
   ("Device Malfunction" -> "Device", "More Status Available" -> "More").
   The decode now uses unambiguous short labels.
"""

import pytest

from oida.pcap.hartip import HARTIPPassiveListener
from oida.pcap.hsr import HSRNode, HSRPassiveListener


class TestHsrSupervisionTracking:
    def test_no_unbounded_supervision_dict(self):
        """The per-frame timestamp list must be gone."""
        listener = HSRPassiveListener(interface="lo", timeout=1)
        assert not hasattr(listener, "_supervision_times"), (
            "_supervision_times grew one entry per supervision frame for the "
            "whole capture lifetime and was never read"
        )

    def test_node_last_supervision_recorded(self):
        node = HSRNode(src_mac="00:11:22:33:44:55")
        assert node.last_supervision == ""

    def test_device_data_includes_last_supervision(self):
        listener = HSRPassiveListener(interface="lo", timeout=1)
        node = HSRNode(
            src_mac="00:11:22:33:44:55",
            node_type="DAN",
            first_seen="2026-01-01T00:00:00",
            last_seen="2026-01-01T00:00:02",
            last_supervision="2026-01-01T00:00:02",
        )
        listener.nodes[node.src_mac] = node
        data = listener._build_device_data(node.src_mac)
        assert data["last_supervision"] == "2026-01-01T00:00:02"


class TestHartipDeviceStatusDecode:
    @pytest.mark.parametrize(
        "status,expected_substrings",
        [
            (0x80, ["Malfunction"]),  # was "Device"
            (0x40, ["Config Changed"]),  # was "Configuration"
            (0x10, ["More Status"]),  # was "More"
            (0x08, ["Loop Fixed"]),  # was "Loop" (collides with 0x04 "Loop Saturated")
            (0x04, ["Loop Saturated"]),
            (0x02, ["Non-PV"]),
            (0x01, ["PV Out"]),
        ],
    )
    def test_flag_labels_are_unambiguous(self, status, expected_substrings):
        decoded = HARTIPPassiveListener._decode_device_status(status)
        for sub in expected_substrings:
            assert sub in decoded, f"0x{status:02x} -> {decoded!r} lost {sub!r}"

    def test_combined_flags_stay_distinguishable(self):
        """0xd0 used to render 'Device | Configuration | More'."""
        decoded = HARTIPPassiveListener._decode_device_status(0xD0)
        assert "Malfunction" in decoded
        assert "Config" in decoded
        assert "More Status" in decoded
        # "Device" alone is ambiguous (Device Malfunction vs a device name).
        assert decoded != "Device | Configuration | More"

    def test_zero_status_renders_empty(self):
        assert HARTIPPassiveListener._decode_device_status(0) == ""
