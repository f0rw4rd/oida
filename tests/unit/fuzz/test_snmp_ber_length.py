"""ASN.1/BER length-of-length mutation tests for the SNMP fuzzers.

The inner BER TLV length fields (community OCTET STRING, varbind OID, varbind
value) are normally auto-computed by boofuzz Size / BERSize primitives and thus
never mutated. The new SNMPvX_BER_LengthOfLength / SNMPvX_BER_Truncated_Length
requests inject malformed long-form, indefinite and truncated length octets --
the parse path behind CVE-2019-9162 (net-snmp), CVE-2020-14934 (Contiki-NG),
CVE-2015-5621 (net-snmp) and CVE-2022-24805 (Linux kernel BER decoder).

These tests build each fuzzer offline (MockConnectionFactory, recording session,
no network) and assert the new requests are advertised + connected and that the
malformed length-of-length octets actually reach the rendered output.
"""

import pytest

from boofuzz.mutation_context import MutationContext

from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType
from src.oida.fuzz.core.connections.base import MockConnectionFactory
from src.oida.fuzz.protocols.snmp_common import BER_LENGTH_OF_LENGTH_MUTATIONS
from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer
from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer
from src.oida.fuzz.protocols.snmpv3 import SNMPv3Fuzzer


# (fuzzer class, LengthOfLength request name, Truncated request name)
SNMP_FUZZERS = [
    (SNMPv1Fuzzer, "SNMP_BER_LengthOfLength", "SNMP_BER_Truncated_Length"),
    (SNMPv2cFuzzer, "SNMPv2c_BER_LengthOfLength", "SNMPv2c_BER_Truncated_Length"),
    (SNMPv3Fuzzer, "SNMPv3_BER_LengthOfLength", "SNMPv3_BER_Truncated_Length"),
]


class _Collector:
    """Records connected Request objects without touching the network."""

    def __init__(self):
        self.requests = {}

    def connect(self, request, *args, **kwargs):
        self.requests[request.name] = request


def _connected_requests(cls, enable_set=True):
    """Build a fuzzer offline and return {name: Request} for every connected request."""
    config = FuzzerConfig(
        target_ip="192.168.1.100",
        target_port=161,
        protocol_type=ProtocolType.UDP,
    )
    config.protocol_options = {"enable_set": enable_set}

    fuzzer = cls(config, connection_factory=MockConnectionFactory())
    collector = _Collector()
    fuzzer._session = collector
    fuzzer._define_protocol()
    return collector.requests


def _all_renders(request):
    """Return base render plus every mutated render for a Request."""
    blobs = [request.render()]
    for mutation in request.mutations(None):
        blobs.append(request.render(MutationContext(mutation)))
    return blobs


# =============================================================================
# Constant sanity
# =============================================================================


class TestBERLengthConstants:
    def test_covers_longform_indefinite_and_multibyte(self):
        """The shared mutation set covers long-form, multi-byte and indefinite forms."""
        assert b"\x81\xff" in BER_LENGTH_OF_LENGTH_MUTATIONS  # 1-octet long form
        assert b"\x82\xff\xff" in BER_LENGTH_OF_LENGTH_MUTATIONS  # 2-octet long form
        assert b"\x84\xff\xff\xff\xff" in BER_LENGTH_OF_LENGTH_MUTATIONS  # 4-octet
        assert b"\x80" in BER_LENGTH_OF_LENGTH_MUTATIONS  # indefinite form


# =============================================================================
# Advertised + connected
# =============================================================================


@pytest.mark.parametrize("cls,lol_name,trunc_name", SNMP_FUZZERS)
class TestBERRequestsAdvertisedAndConnected:
    def test_advertised(self, cls, lol_name, trunc_name):
        """Both new requests appear in get_request_definitions()."""
        names = {r.name for r in cls.get_request_definitions()}
        assert lol_name in names
        assert trunc_name in names

    def test_connected(self, cls, lol_name, trunc_name):
        """Both new requests are connected to the session on a default run."""
        connected = _connected_requests(cls)
        assert lol_name in connected
        assert trunc_name in connected

    def test_categories_are_existing_balance_categories(self, cls, lol_name, trunc_name):
        """New requests reuse existing high_crash / boundary categories."""
        by_name = {r.name: r for r in cls.get_request_definitions()}
        assert by_name[lol_name].category == "high_crash"
        assert by_name[trunc_name].category == "boundary"


# =============================================================================
# Length-of-length octets reach the wire
# =============================================================================


@pytest.mark.parametrize("cls,lol_name,trunc_name", SNMP_FUZZERS)
class TestBERLengthOfLengthOnWire:
    def test_longform_or_indefinite_in_mutated_output(self, cls, lol_name, trunc_name):
        """A long-form (0x81 0xFF / 0x82 0xFF..) or indefinite (0x80) length octet
        appears once the length-of-length field is mutated."""
        request = _connected_requests(cls)[lol_name]
        blobs = _all_renders(request)
        assert any(
            (b"\x81\xff" in blob) or (b"\x82\xff\xff" in blob) or (b"\x80" in blob)
            for blob in blobs
        )

    def test_all_malformed_length_forms_emitted_across_mutations(self, cls, lol_name, trunc_name):
        """Every length-of-length mutation form appears somewhere in the fuzzed output."""
        request = _connected_requests(cls)[lol_name]
        blobs = _all_renders(request)

        for lol_octets in BER_LENGTH_OF_LENGTH_MUTATIONS:
            assert any(lol_octets in blob for blob in blobs), (
                f"{lol_name}: length-of-length octets {lol_octets!r} never emitted"
            )

    def test_truncated_length_declared_shorter_than_content(self, cls, lol_name, trunc_name):
        """Truncated request carries a short declared length ahead of longer content."""
        request = _connected_requests(cls)[trunc_name]
        blob = request.render()
        # The community/context-name OCTET STRING declares 2 bytes (04 02) but the
        # overflow marker string that follows is far longer than 2 bytes.
        assert b"\x04\x02" in blob
        assert b"overflow" in blob


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
