"""Review tests for the mDNS fuzzer's DNS header section counts.

Bug A: ~20 of the mDNS requests appended real question/RR blocks to the body
while the header (built by ``_create_dns_header``) still declared
QD/AN/NS/AR = 0/0/0/0.  A spec-compliant mDNS responder reading QDCOUNT=0
never parses any of the appended payload, so those fuzz cases were invisible.

These tests assert on the RENDERED BYTES of every request in the mDNS session:
for every request except the two self-advertised malformed ones
(``Malformed_Header``, ``Truncated_Packet``), it must NOT be the case that all
four section counts are zero while a non-empty body follows.
"""

import struct

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

# Requests whose header counts intentionally do NOT match their body; the
# mismatch is the point of the test case and is advertised by the name.
SELF_ADVERTISED_MALFORMED = {"Malformed_Header", "Truncated_Packet"}


def _build_mdns_requests():
    config = FuzzerConfig(
        target_ip="224.0.0.251",
        target_port=5353,
        protocol_type=ProtocolType.UDP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    fuzzer = PROTOCOL_FUZZERS["mdns"](config=config, connection_factory=MockConnectionFactory())
    return {node.name: node for node in fuzzer.session.nodes.values() if hasattr(node, "render")}


REQUESTS = _build_mdns_requests()

RECORDED_REQUESTS = sorted(name for name in REQUESTS if name not in SELF_ADVERTISED_MALFORMED)


@pytest.mark.parametrize("request_name", RECORDED_REQUESTS)
def test_header_counts_not_all_zero_with_body(request_name):
    """No (non-self-advertised) request may claim zero records with a body."""
    data = REQUESTS[request_name].render()
    assert len(data) >= 12, f"{request_name}: shorter than a DNS header"

    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    body_len = len(data) - 12

    assert not (qd == an == ns == ar == 0 and body_len > 0), (
        f"{request_name}: header declares 0/0/0/0 records but a "
        f"{body_len}-byte body follows — a compliant parser ignores it all"
    )


def test_known_counts_match_expected_sections():
    """Spot-check the exact counts for requests with known section layouts."""
    expected = {
        "Quick_Coverage": (1, 8, 1, 1),
        "Multi_Answer_Response": (1, 3, 0, 0),
        "Mixed_Records_Response": (1, 2, 1, 3),
        "Nested_Compression": (1, 0, 0, 0),
        "Multi_Question_Query": (3, 0, 0, 0),
        "Zero_Entry_Query": (0, 0, 0, 0),
        "Standard_Query": (1, 0, 0, 0),
        "Standard_Response": (1, 1, 1, 1),
        "Oversized_Packet": (1, 3, 0, 0),
        "EDNS0_Malformed": (1, 0, 0, 1),
        "Variable_Records": (2, 3, 0, 0),  # Group defaults pick first matching body
        "Multi_Known_Answer": (2, 2, 0, 0),
        "Probe_Query": (1, 0, 1, 0),
        "EDNS0_Packet": (1, 0, 0, 1),
    }
    for name, counts in expected.items():
        data = REQUESTS[name].render()
        assert struct.unpack(">HHHH", data[4:12]) == counts, name
