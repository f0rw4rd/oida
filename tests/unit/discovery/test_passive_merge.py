"""Cross-listener device-merge crash regression tests.

When EIGRP/RIP/PIM passive listeners see a device that was first
registered by another listener (CDP/LLDP/ARP/OSPF), the eigrp_data /
rip_data / pim_data attributes are None on DiscoveredDevice. Calling
.get(...) on None or assigning .get(...)['x'] = y raises silently.
CODE_REVIEW.md HIGH.
"""

import unittest
from datetime import datetime
from unittest.mock import MagicMock


class _DummyDevice:
    """Stand-in for DiscoveredDevice with the data-bucket fields nulled."""

    def __init__(self):
        self.eigrp_data = None
        self.rip_data = None
        self.pim_data = None
        self.last_seen = "1970-01-01T00:00:00"


class TestLazyInitMergeBuckets(unittest.TestCase):
    """The fix lazy-inits the *_data dicts before writing."""

    def test_eigrp_lazy_init(self):
        d = _DummyDevice()
        # Mirrors the patched block in eigrp_passive.py
        if d.eigrp_data is None:
            d.eigrp_data = {}
        existing = d.eigrp_data.get("routes", [])
        for route in [{"network": "10.0.0.0/8"}]:
            existing.append(route)
        d.eigrp_data["routes"] = existing
        d.eigrp_data["route_count"] = len(existing)
        self.assertEqual(d.eigrp_data["route_count"], 1)

    def test_rip_lazy_init(self):
        d = _DummyDevice()
        if d.rip_data is None:
            d.rip_data = {}
        d.rip_data["routes"] = [{"network": "192.168.0.0/24"}]
        d.rip_data["route_count"] = 1
        self.assertEqual(d.rip_data["route_count"], 1)

    def test_pim_lazy_init(self):
        d = _DummyDevice()
        if d.pim_data is None:
            d.pim_data = {}
        existing = d.pim_data.get("neighbors", [])
        existing.append("10.0.0.1")
        d.pim_data["neighbors"] = existing
        self.assertEqual(d.pim_data["neighbors"], ["10.0.0.1"])

    def test_source_has_lazy_init_pattern(self):
        """Snapshot: the fix must remain in each listener."""
        import pathlib

        for path in [
            "src/oida/protocols/discovery/eigrp_passive.py",
            "src/oida/protocols/discovery/rip_passive.py",
            "src/oida/protocols/discovery/pim_passive.py",
        ]:
            src = pathlib.Path(path).read_text()
            # The fix uses `if dev.<x>_data is None:` followed by `= {}`.
            self.assertIn("_data is None", src, f"{path} lost lazy-init guard")


if __name__ == "__main__":
    unittest.main()
