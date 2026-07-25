"""Tests for the DHCP option-overload / domain-list / DNS-len-lie requests.

Covers the three requests added to ``DHCPFuzzer`` for two proven parser gaps:

* ``DHCP_Option_Overload`` -- DHO_OPTIONSOVERLOADED (option 52) sub-parsing of
  malformed options placed inside the 64-byte ``sname`` and 128-byte ``file``
  BOOTP fields.
* ``DHCP_Domain_List_Overflow`` -- RFC1035 domain search list (119) / DNS list
  (6) overflow (udhcpc CVE-2016-2148 class): oversized labels + compression
  pointer loops.
* ``DHCP_DNS_Server_List_Len_Lie`` -- option 6 length that is not a multiple of
  4 and/or larger than the addresses present (tail overrun).

No network is required: accessing ``fuzzer.session`` triggers
``_define_protocol()`` and we inspect / render the connected boofuzz nodes.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.dhcp import DHCPFuzzer

NEW_REQUESTS = [
    "DHCP_Option_Overload",
    "DHCP_Domain_List_Overflow",
    "DHCP_DNS_Server_List_Len_Lie",
]


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
    return {node.name for node in fuzzer.session.nodes.values() if node.name != "__ROOT_NODE__"}


def _render(fuzzer, name):
    for node in fuzzer.session.nodes.values():
        if node.name == name:
            return node.render()
    raise AssertionError(f"request {name!r} not connected")


class TestNewOverloadRequestsAdvertised:
    """The three new requests are advertised and individually enable-selectable."""

    def test_all_new_requests_are_advertised(self):
        advertised = {r.name for r in DHCPFuzzer.get_request_definitions()}
        for name in NEW_REQUESTS:
            assert name in advertised

    def test_new_requests_are_overflow_category(self):
        by_name = {r.name: r for r in DHCPFuzzer.get_request_definitions()}
        for name in NEW_REQUESTS:
            assert by_name[name].category == "overflow"

    def test_balance_categories_present(self):
        cats = {r.category for r in DHCPFuzzer.get_request_definitions()}
        assert {"baseline", "standard", "overflow"} <= cats

    def test_new_requests_connect_by_default(self):
        fuzzer = DHCPFuzzer(config=_make_config(), connection_factory=MockConnectionFactory())
        connected = _connected_request_names(fuzzer)
        for name in NEW_REQUESTS:
            assert name in connected

    @pytest.mark.parametrize("name", NEW_REQUESTS)
    def test_each_new_request_individually_enableable(self, name):
        fuzzer = DHCPFuzzer(
            config=_make_config(enabled=[name]),
            connection_factory=MockConnectionFactory(),
        )
        assert _connected_request_names(fuzzer) == {name}


class TestOptionOverloadRendering:
    """Rendered bytes carry the option-52 overload flag + malformed field options."""

    def test_option_52_overload_byte_present(self):
        fuzzer = DHCPFuzzer(
            config=_make_config(enabled=["DHCP_Option_Overload"]),
            connection_factory=MockConnectionFactory(),
        )
        rendered = _render(fuzzer, "DHCP_Option_Overload")
        # option 52, length 1, overload flag default (first Group value = 1/file)
        assert bytes([52, 1, 1]) in rendered

    def test_default_render_embeds_options_in_sname_and_file(self):
        fuzzer = DHCPFuzzer(
            config=_make_config(enabled=["DHCP_Option_Overload"]),
            connection_factory=MockConnectionFactory(),
        )
        rendered = _render(fuzzer, "DHCP_Option_Overload")
        # BOOTP fields stay their fixed sizes (64 + 128) so the frame is valid
        assert len(rendered) >= 64 + 128
        # sname field carries an embedded option 12 (hostname) sub-option
        assert bytes([12, 4]) + b"host" in rendered
        # file field carries an embedded option 67 (bootfile-name) sub-option
        assert bytes([67, 4]) + b"boot" in rendered

    def test_overrun_variants_available_for_fuzzing(self):
        """The malformed 0xff-length overrun option is a mutation variant of the
        sname/file Group fields, sub-parsed by a client that follows option 52."""
        fuzzer = DHCPFuzzer(
            config=_make_config(enabled=["DHCP_Option_Overload"]),
            connection_factory=MockConnectionFactory(),
        )
        overrun_values = set()
        for node in fuzzer.session.nodes.values():
            if node.name != "DHCP_Option_Overload":
                continue
            for block in node.stack:
                for child in getattr(block, "stack", []):
                    if child.name in ("sname", "file"):
                        overrun_values.update(child.values)
        assert bytes([12, 0xFF]) + b"A" * 62 in overrun_values
        assert bytes([67, 0xFF]) + b"B" * 126 in overrun_values


class TestDomainListOverflowRendering:
    """Domain search list (119) renders oversized RFC1035 label bytes."""

    def test_option_119_and_oversized_labels_present(self):
        fuzzer = DHCPFuzzer(
            config=_make_config(enabled=["DHCP_Domain_List_Overflow"]),
            connection_factory=MockConnectionFactory(),
        )
        rendered = _render(fuzzer, "DHCP_Domain_List_Overflow")
        assert bytes([119]) in rendered
        # default Group value: declared len 255 followed by an oversized 63-byte label
        assert bytes([255]) + b"\x3f" + b"A" * 63 in rendered


class TestDnsServerListLenLieRendering:
    """Option 6 renders a declared length that is not a multiple of 4."""

    def test_option_6_len_not_multiple_of_four(self):
        fuzzer = DHCPFuzzer(
            config=_make_config(enabled=["DHCP_DNS_Server_List_Len_Lie"]),
            connection_factory=MockConnectionFactory(),
        )
        rendered = _render(fuzzer, "DHCP_DNS_Server_List_Len_Lie")
        # option 6, default Group value: declared len 7 (not /4) + 7 payload bytes
        assert bytes([6, 7]) + b"\x08" * 7 in rendered
