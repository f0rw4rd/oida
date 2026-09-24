"""Known-answer test for VNC hash extraction on the existing wireshark_vnc fixture.

The expected hash is the one an independent tool extracts from this pcap. The
challenge/response were confirmed via Wireshark's own RFB dissector, independent
of OIDA's field-selection/assembly path:

    tshark -r wireshark_vnc.pcap -Y vnc \\
        -e vnc.auth_challenge -e vnc.auth_response
    -> challenge f4de8f89c25f7fdcd93ea82151483da3
       response  d5c9ebd37125c5bed6ff7ca5128a7d2a

That is the John `vnc` line ``$vnc$*<challenge>*<response>`` (hashcat has no VNC
mode; john's `vnc` format PASSes self-test and consumes this exact string).
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

# Wireshark RFB dissector ground truth for wireshark_vnc.pcap.
EXPECTED = "$vnc$*f4de8f89c25f7fdcd93ea82151483da3*d5c9ebd37125c5bed6ff7ca5128a7d2a"


def test_vnc_hash_matches_wireshark_dissector():
    listener, _devices, _result = _run_listener_test(
        "vnc",
        "VNCPassiveListener",
        "vnc",
        "vnc/wireshark_vnc.pcap",
        min_devices=0,
        min_interactions=0,
    )
    assert EXPECTED in listener.get_hashcat_hashes(), (
        f"expected {EXPECTED!r}, got {listener.get_hashcat_hashes()}"
    )
