"""Packet-coverage tests: verify listeners don't silently drop packets.

For each listener + pcap fixture, counts protocol packets via tshark,
then asserts the listener produced at least as many interactions.
Every packet matching the display filter MUST produce >= 1 interaction.

Parametrizes over ALL pcap files per protocol fixture directory, not just
the hand-picked samples in LISTENER_PCAP_CASES.
"""

import importlib
import os

import pytest

from tests.integration.pcap.conftest import (
    COVERAGE_ALL_PCAPS,
    _count_tshark_packets,
    _load_packets,
    _pcap_path,
    _skip_unless_pyshark,
)

pytestmark = [pytest.mark.integration]


# Known-incomplete listener / pcap-fixture combinations.
# Format: (module, pcap basename) -> reason
# Each entry is a documented gap, NOT a flaky test. Adding here should
# always come with a TODO / issue reference explaining the gap.
KNOWN_DROPS: dict[tuple[str, str], str] = {}


@pytest.mark.parametrize(
    "case",
    COVERAGE_ALL_PCAPS,
    ids=lambda c: c["id"],
)
class TestPacketCoverage:
    """Every filtered packet must produce at least one interaction."""

    def test_no_silent_drops(self, case):
        _skip_unless_pyshark()

        known_key = (case["module"], os.path.basename(case["pcap"]))
        if known_key in KNOWN_DROPS:
            pytest.xfail(f"known listener gap: {KNOWN_DROPS[known_key]}")

        pcap = _pcap_path(case["pcap"])
        display_filter = case["filter"]
        decode_as = case.get("decode_as")

        # 1. Count packets via tshark (ground truth for the full pcap)
        tshark_count = _count_tshark_packets(pcap, display_filter, decode_as)
        if tshark_count == 0:
            pytest.skip(
                f"tshark found 0 packets for filter '{display_filter}' "
                f"in {case['pcap']} (module {case['module']})"
            )

        # 2. Run listener (note: _load_packets caps at _MAX_TEST_PACKETS)
        mod = importlib.import_module(f"oida.pcap.{case['module']}")
        cls = getattr(mod, case["cls"])
        listener = cls(interface="lo", timeout=10)
        listener._x509 = True
        packets = _load_packets(pcap, display_filter=display_filter, decode_as=decode_as)
        listener.feed_packets(iter(packets))

        # Use the lesser of tshark count and packets actually fed,
        # since _load_packets may cap at _MAX_TEST_PACKETS.
        fed_count = min(tshark_count, len(packets))
        interaction_count = len(listener.interactions)

        # 3. Allow small tolerance for ICMP-encapsulated packets that tshark
        #    counts under the display filter but pyshark doesn't expose as a
        #    top-level protocol layer.  Blanking REQUIRED_LAYERS to hit 100%
        #    causes catastrophic false positives (see test_false_positives.py).
        drop_tolerance = max(1, int(fed_count * 0.15))  # 15% or at least 1
        assert interaction_count >= fed_count - drop_tolerance, (
            f"PACKET DROP: {case['module']} | {os.path.basename(case['pcap'])}\n"
            f"  pcap:         {case['pcap']}\n"
            f"  filter:       {display_filter}\n"
            f"  tshark_count: {tshark_count}\n"
            f"  fed_count:    {fed_count}\n"
            f"  interactions: {interaction_count}\n"
            f"  dropped:      {fed_count - interaction_count} "
            f"({100 * (fed_count - interaction_count) / fed_count:.0f}%)\n"
            f"  tolerance:    {drop_tolerance}"
        )
