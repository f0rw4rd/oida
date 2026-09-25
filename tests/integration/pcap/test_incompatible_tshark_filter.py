"""Regression: the full listener pipeline must survive a tshark that lacks a
protocol named in the combined display filter, and the non-EK (XML) fallback
must not pass include_raw without use_ek/use_json.

Two bugs, both on the path a pre-4.6 / stock tshark takes:

1. The combined display filter aggregates every active listener's
   ``DISPLAY_FILTER``. One term (``wsdiscovery``) names a protocol stock
   tshark builds don't have, so tshark rejected the WHOLE filter (retcode 4)
   and the scan aborted at 0 packets. ``_filter_supported_by_tshark`` now
   drops the pre-filter when tshark can't compile it.

2. When EK mode is unavailable, the pipeline falls back to XML/PDML. That path
   used to forward ``include_raw=True`` (set for routing listeners) without
   ``use_ek``/``use_json``, which pyshark rejects at construction
   ("use_json/use_ek must be True if include_raw") -- aborting the scan.

Running the FULL listener set (no ``protocols`` restriction) is what exercises
both: it is exactly the ``oida pcap <file>`` default that surfaced the bug.
"""

import shutil

import pytest

from tests.service_gate import require_service

from oida.protocols.pcap.scanner import PcapScanner

from tests.integration.pcap.conftest import _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]


def test_full_pipeline_completes_with_all_listeners():
    """`oida pcap <iec104-sample>` with every listener active must complete.

    Before the fix this aborted at 0 packets (tshark rejected the combined
    filter). The IEC 104 Industroyer2 sample has 542 packets, so a healthy run
    processes them all and still recognises the IEC 104 traffic.
    """
    _skip_unless_pyshark()
    pcap = _pcap_path("iec104", "eset_industroyer2_sample1.pcap")

    # No "protocols" key -> load the full listener set, so the display filter
    # includes the wsdiscovery term that stock tshark can't compile.
    scanner = PcapScanner(pcap, args={})
    result = scanner.run_scan()

    stats = result.get("statistics", {})
    processed = stats.get("packets_processed", 0)
    assert processed >= 500, (
        f"pipeline processed only {processed} packets - the combined display "
        "filter or the XML fallback aborted the scan"
    )


def test_filter_supported_by_tshark_drops_unknown_protocol():
    """The validator keeps a compilable filter and drops one tshark can't."""
    if not shutil.which("tshark"):
        require_service("tshark not on PATH")
    _skip_unless_pyshark()
    pcap = _pcap_path("iec104", "eset_industroyer2_sample1.pcap")
    scanner = PcapScanner(pcap, args={})

    # A filter tshark understands is returned unchanged.
    assert scanner._filter_supported_by_tshark("tcp or udp") == "tcp or udp"

    # A filter naming a protocol no tshark build has is dropped to None, so the
    # scan falls back to processing every packet instead of aborting.
    assert scanner._filter_supported_by_tshark("nosuchproto_xyz123 or tcp") is None
