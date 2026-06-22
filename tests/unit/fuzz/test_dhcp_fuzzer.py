"""Tests for DHCP / DHCPv6 Protocol Fuzzer request gating.

Regression tests for the selective-fuzzing gate bug: ``_define_protocol()``
must gate every ``session.connect()`` on the same per-request name that
``get_request_definitions()`` advertises, so that ``--enable``/``--disable``
actually select requests. Previously the connects were gated on coarse group
names (DHCP_Baseline, DHCP_Overflow, ...) that were never registered, so
``--enable <real-name>`` connected nothing and ``--disable`` was a no-op.

No network is required: accessing ``fuzzer.session`` triggers
``_define_protocol()`` and we inspect the connected boofuzz nodes.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.dhcp import DHCPFuzzer, DHCPv6Fuzzer


def _make_config(enabled=None, disabled=None):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=9999,
        protocol_type=ProtocolType.UDP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    config.enabled_requests = enabled
    config.disabled_requests = disabled
    return config


def _connected_request_names(fuzzer):
    """Return the set of connected request node names (excluding the root)."""
    return {node.name for node in fuzzer.session.nodes.values() if node.name != "__ROOT_NODE__"}


class TestDHCPRequestGating:
    """DHCPFuzzer per-request --enable/--disable gating."""

    def test_default_connects_all_advertised_requests(self):
        """No --enable/--disable: every advertised request must connect."""
        fuzzer = DHCPFuzzer(
            config=_make_config(),
            connection_factory=MockConnectionFactory(),
        )
        connected = _connected_request_names(fuzzer)
        advertised = {r.name for r in DHCPFuzzer.get_request_definitions()}
        assert connected == advertised

    def test_enable_single_request_connects_only_that_request(self):
        """--enable DHCP_DISCOVER connects exactly DHCP_DISCOVER."""
        fuzzer = DHCPFuzzer(
            config=_make_config(enabled=["DHCP_DISCOVER"]),
            connection_factory=MockConnectionFactory(),
        )
        connected = _connected_request_names(fuzzer)
        assert connected == {"DHCP_DISCOVER"}

    def test_disable_single_request_removes_only_that_request(self):
        """--disable DHCP_DISCOVER connects everything except DHCP_DISCOVER."""
        fuzzer = DHCPFuzzer(
            config=_make_config(disabled=["DHCP_DISCOVER"]),
            connection_factory=MockConnectionFactory(),
        )
        connected = _connected_request_names(fuzzer)
        advertised = {r.name for r in DHCPFuzzer.get_request_definitions()}
        assert "DHCP_DISCOVER" not in connected
        assert connected == advertised - {"DHCP_DISCOVER"}

    @pytest.mark.parametrize("name", [r.name for r in DHCPFuzzer.get_request_definitions()])
    def test_each_advertised_name_is_individually_enableable(self, name):
        """Every advertised name must be reachable via --enable."""
        fuzzer = DHCPFuzzer(
            config=_make_config(enabled=[name]),
            connection_factory=MockConnectionFactory(),
        )
        assert _connected_request_names(fuzzer) == {name}


class TestDHCPv6RequestGating:
    """DHCPv6Fuzzer per-request --enable/--disable gating."""

    def test_default_connects_all_advertised_requests(self):
        fuzzer = DHCPv6Fuzzer(
            config=_make_config(),
            connection_factory=MockConnectionFactory(),
        )
        connected = _connected_request_names(fuzzer)
        advertised = {r.name for r in DHCPv6Fuzzer.get_request_definitions()}
        assert connected == advertised

    def test_enable_single_request_connects_only_that_request(self):
        fuzzer = DHCPv6Fuzzer(
            config=_make_config(enabled=["DHCPv6_SOLICIT"]),
            connection_factory=MockConnectionFactory(),
        )
        assert _connected_request_names(fuzzer) == {"DHCPv6_SOLICIT"}

    def test_disable_single_request_removes_only_that_request(self):
        fuzzer = DHCPv6Fuzzer(
            config=_make_config(disabled=["DHCPv6_SOLICIT"]),
            connection_factory=MockConnectionFactory(),
        )
        connected = _connected_request_names(fuzzer)
        advertised = {r.name for r in DHCPv6Fuzzer.get_request_definitions()}
        assert "DHCPv6_SOLICIT" not in connected
        assert connected == advertised - {"DHCPv6_SOLICIT"}

    @pytest.mark.parametrize("name", [r.name for r in DHCPv6Fuzzer.get_request_definitions()])
    def test_each_advertised_name_is_individually_enableable(self, name):
        fuzzer = DHCPv6Fuzzer(
            config=_make_config(enabled=[name]),
            connection_factory=MockConnectionFactory(),
        )
        assert _connected_request_names(fuzzer) == {name}
