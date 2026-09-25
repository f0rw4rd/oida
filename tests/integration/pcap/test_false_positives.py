"""Cross-protocol false positive tests.

Feeds alien pcaps (from unrelated protocol families) into listeners and
asserts zero interactions.  Catches greedy listeners that accidentally
match all traffic - e.g. when REQUIRED_LAYERS is blanked without adding
a should_process_packet() guard.
"""

import importlib

import pytest

from tests.integration.pcap.conftest import _load_packets, _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]

# ---------------------------------------------------------------------------
# Alien pcaps - one per protocol family (ICS, industrial, credential)
# ---------------------------------------------------------------------------
_ALIEN_PCAPS = {
    "iec104": ("iec104/eset_industroyer2_sample2.pcap", "iec60870_104"),
    "modbus": ("modbus/digitalbond_modbus_part1.pcap", "mbtcp"),
    "http": ("http/bruteshark_http_basic.pcap", "http"),
}

# Listeners under test - protocols that have had REQUIRED_LAYERS issues
# or complex fallback paths.  (module, class, own_protocol_label)
_LISTENERS = [
    # Original 6 with known fallback-path risk
    ("smtp", "SMTPPassiveListener", "smtp"),
    ("memcached", "MemcachedPassiveListener", "memcached"),
    ("kerberos", "KerberosPassiveListener", "kerberos"),
    ("pjl", "PJLPassiveListener", "pjl"),
    ("ftp", "FTPPassiveListener", "ftp"),
    ("telnet", "TelnetPassiveListener", "telnet"),
    # High-traffic OT/IT listeners - false positives here are highest-blast
    # because they'd contaminate real captures during a live engagement.
    ("modbus", "ModbusPassiveListener", "modbus"),
    ("dnp3", "DNP3PassiveListener", "dnp3"),
    ("s7comm", "S7commPassiveListener", "s7comm"),
    ("iec104", "IEC104PassiveListener", "iec104"),
    ("opcua", "OPCUAPassiveListener", "opcua"),
    ("enip", "EtherNetIPPassiveListener", "enip"),
    ("bacnet", "BACnetPassiveListener", "bacnet"),
    ("hl7", "HL7PassiveListener", "hl7"),
    ("http", "HTTPPassiveListener", "http"),
    ("tls", "TLSPassiveListener", "tls"),
]

# Build parametrized cases: (module, cls, own_label, alien_label, alien_pcap, alien_filter)
_FP_CASES = []
for mod, cls, own_label in _LISTENERS:
    for alien_label, (alien_pcap, alien_filter) in _ALIEN_PCAPS.items():
        if own_label == alien_label:
            continue
        _FP_CASES.append((mod, cls, own_label, alien_label, alien_pcap, alien_filter))

_FP_IDS = [f"{own}←{alien}" for _, _, own, alien, _, _ in _FP_CASES]


class TestCrossProtocolFalsePositives:
    """Feed alien pcaps to listeners and assert zero interactions."""

    @pytest.mark.parametrize(
        "module_name,class_name,own_label,alien_label,alien_pcap,alien_filter",
        _FP_CASES,
        ids=_FP_IDS,
    )
    def test_no_false_positives(
        self,
        module_name,
        class_name,
        own_label,
        alien_label,
        alien_pcap,
        alien_filter,
    ):
        _skip_unless_pyshark()
        pcap = _pcap_path(alien_pcap)
        packets = _load_packets(pcap, display_filter=alien_filter, max_packets=50)
        if not packets:
            pytest.skip(f"No packets in {alien_pcap} with filter {alien_filter}")

        mod = importlib.import_module(f"oida.pcap.{module_name}")
        cls = getattr(mod, class_name)
        listener = cls(interface="lo", timeout=10)
        listener.feed_packets(iter(packets))

        spurious = [ix.operation for ix in listener.interactions[:3]]
        assert len(listener.interactions) == 0, (
            f"{class_name} produced {len(listener.interactions)} false positive(s) "
            f"from {alien_label} pcap; first ops: {spurious}"
        )
