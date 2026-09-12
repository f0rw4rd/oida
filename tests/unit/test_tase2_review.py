"""
G3 bug-hunt review tests for TASE.2 (see .bughunt/catchall.md).

Covers a confirmed --no-discover-vcc / --no-discover-icc bypass: the flags
were honoured for the *displayed/results* domain list, but self.domains
(the list every other mixin - enumeration, control testing, transfer set
discovery - iterates over) was populated from the unfiltered server
response, so a domain the operator explicitly asked to skip was still
touched by downstream operations.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from oida.protocols.tase2.mixins.discovery import DiscoveryMixin


class _FakeScanner(DiscoveryMixin):
    def __init__(self, discover_vcc=True, discover_icc=True):
        self.discover_vcc = discover_vcc
        self.discover_icc = discover_icc
        self.max_points = 100
        self.logger = MagicMock()


def _domains():
    vcc = SimpleNamespace(name="VCC", is_vcc=True, variables=[1, 2], data_sets=[])
    icc = SimpleNamespace(name="ICC1", is_vcc=False, variables=[3], data_sets=[])
    return vcc, icc


def test_no_discover_vcc_excludes_vcc_from_self_domains():
    """--no-discover-vcc must keep the VCC domain out of self.domains too,
    not just out of the displayed results list, since self.domains is what
    enumeration/control/transfer-set mixins actually operate on."""
    vcc, icc = _domains()
    conn = MagicMock()
    conn.get_domains.return_value = [vcc, icc]

    scanner = _FakeScanner(discover_vcc=False, discover_icc=True)
    result = scanner._discover_domains(conn)

    result_names = {d["name"] for d in result}
    domain_names = {d.name for d in scanner.domains}

    assert result_names == {"ICC1"}
    assert domain_names == {"ICC1"}, (
        f"self.domains leaked VCC domain despite --no-discover-vcc: {domain_names}"
    )


def test_no_discover_icc_excludes_icc_from_self_domains():
    vcc, icc = _domains()
    conn = MagicMock()
    conn.get_domains.return_value = [vcc, icc]

    scanner = _FakeScanner(discover_vcc=True, discover_icc=False)
    result = scanner._discover_domains(conn)

    result_names = {d["name"] for d in result}
    domain_names = {d.name for d in scanner.domains}

    assert result_names == {"VCC"}
    assert domain_names == {"VCC"}, (
        f"self.domains leaked ICC domain despite --no-discover-icc: {domain_names}"
    )


def test_both_enabled_keeps_all_domains():
    vcc, icc = _domains()
    conn = MagicMock()
    conn.get_domains.return_value = [vcc, icc]

    scanner = _FakeScanner(discover_vcc=True, discover_icc=True)
    result = scanner._discover_domains(conn)

    assert {d["name"] for d in result} == {"VCC", "ICC1"}
    assert {d.name for d in scanner.domains} == {"VCC", "ICC1"}
