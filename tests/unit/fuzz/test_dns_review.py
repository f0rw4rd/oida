"""Review tests for the DNS fuzzer's EDNS0 / RCODE request rendering.

Bug B: DNS_RCODE_BADSIG / BADKEY / BADTIME declared QDCOUNT=1 but had no
question block, so a parser consumed the OPT record's own name/type/class as
the question and was left with 7 bytes where an RR needs >= 11.

Bug C: DNS_EDNS0_OPTIONS hardcoded RDLENGTH=0x0010 (16) while the rendered
option RDATA is 12 bytes.

All assertions are on the RENDERED BYTES of the real request objects.
"""

import struct

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS


def _build_dns_request(name):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=53,
        protocol_type=ProtocolType.UDP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    fuzzer = PROTOCOL_FUZZERS["dns"](config=config, connection_factory=MockConnectionFactory())
    return {n.name: n for n in fuzzer.session.nodes.values() if hasattr(n, "render")}[name]


def parse_question(data, offset):
    """Parse a DNS question (wire-format QNAME, qtype, qclass) at offset."""
    start = offset
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        offset += length
    qtype, qclass = struct.unpack(">HH", data[offset : offset + 4])
    return offset + 4, data[start:offset] + struct.pack(">HH", qtype, qclass)


def parse_opt_rr(data, offset):
    """Parse an OPT pseudo-RR (10-byte fixed part after the root name).

    Returns (rdlength, rdata bytes, bytes consumed after the name byte).
    """
    assert data[offset] == 0, "OPT name must be the root domain (single 0x00)"
    rr_type, _rr_class, _ttl, rdlength = struct.unpack(">HHIH", data[offset + 1 : offset + 11])
    assert rr_type == 0x0029, "fixed part must be an OPT record (type 41)"
    rdata = data[offset + 11 : offset + 11 + rdlength]
    return rdlength, rdata, 10 + rdlength


RCODE_REQUESTS = [
    "DNS_RCODE_BADVERS",
    "DNS_RCODE_BADCOOKIE",
    "DNS_RCODE_BADSIG",
    "DNS_RCODE_BADKEY",
    "DNS_RCODE_BADTIME",
]


@pytest.mark.parametrize("request_name", RCODE_REQUESTS)
def test_rcode_requests_question_then_opt(request_name):
    """QDCOUNT=1 must be followed by a parseable question, then the OPT RR."""
    data = _build_dns_request(request_name).render()

    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    assert qd == 1, f"{request_name}: expected QDCOUNT=1, got {qd}"
    assert ar == 1, f"{request_name}: expected ARCOUNT=1, got {ar}"

    offset, question = parse_question(data, 12)
    assert question.startswith(b"\x04test\x00"), f"{request_name}: question QNAME is {question!r}"
    assert question.endswith(b"\x00\x01\x00\x01"), (
        f"{request_name}: question must be A/IN, got {question!r}"
    )
    rdlength, rdata, consumed = parse_opt_rr(data, offset)
    assert consumed == rdlength + 10
    assert offset + 1 + consumed == len(data), (
        f"{request_name}: {len(data) - (offset + 1 + consumed)} trailing bytes after OPT RR"
    )
    # No option payload in these RCODE requests: RDLENGTH must be 0.
    assert rdlength == 0 and rdata == b""


def test_edns0_options_rdlength_matches_rdata():
    """RDLENGTH must equal the actual option RDATA bytes (Bug C: was 16, real 12)."""
    data = _build_dns_request("DNS_EDNS0_OPTIONS").render()

    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    assert (qd, an, ns, ar) == (1, 0, 0, 1)

    offset, question = parse_question(data, 12)
    assert question.startswith(b"\x04oida\x05local\x00")

    rdlength, rdata, _ = parse_opt_rr(data, offset)
    assert offset + 1 + 10 + rdlength == len(data)
    # The trailing RDATA must be exactly what RDLENGTH claims...
    assert rdlength == len(rdata) == 12
    # ...and must be a well-formed ECS option: code 8, length 8, family 1.
    option_code, option_length = struct.unpack(">HH", rdata[:4])
    assert option_code == 8
    assert option_length == 8
    assert len(rdata[4:]) == option_length
    assert struct.unpack(">H", rdata[4:6])[0] == 1  # family IPv4
