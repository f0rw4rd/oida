"""Behavioral tests for the global "<host>:<port>" target shorthand.

Three layers are covered, matching where the feature lives:
  - oida.targets.split_host_port: the splitter itself (bracketed IPv6, the
    one-colon rule, rejection of malformed ports).
  - oida.targets.parse_targets: an embedded port survives CIDR/range/file/comma
    expansion, and the pre-existing host:port/path forms still pass through.
  - oida.cli.scan_target: the port lands on the per-target args copy, beats
    -p/--port, does not leak between targets, and is skipped for URL, file,
    serial and interface targets.

Nothing is mocked except the protocol class handed to scan_target, which is a
plain recorder — the splitting logic under test runs unmodified.
"""

from argparse import Namespace

import pytest

from oida import cli
from oida.targets import parse_targets, split_host_port

pytestmark = pytest.mark.core


# ---------------------------------------------------------------------------
# split_host_port
# ---------------------------------------------------------------------------


class TestSplitHostPort:
    @pytest.mark.parametrize(
        "target,expected",
        [
            ("10.0.0.1:502", ("10.0.0.1", 502)),
            ("host.example.com:502", ("host.example.com", 502)),
            ("[2001:db8::1]:502", ("2001:db8::1", 502)),
            ("[::1]:8080", ("::1", 8080)),
            ("10.0.0.1:65535", ("10.0.0.1", 65535)),
            ("10.0.0.1:1", ("10.0.0.1", 1)),
        ],
    )
    def test_splits_embedded_port(self, target, expected):
        assert split_host_port(target) == expected

    @pytest.mark.parametrize(
        "target,expected_host",
        [
            ("10.0.0.1", "10.0.0.1"),
            ("host.example.com", "host.example.com"),
            ("2001:db8::1", "2001:db8::1"),
            ("::1", "::1"),
            ("[::1]", "::1"),
            ("", ""),
        ],
    )
    def test_no_port_returns_host_unchanged(self, target, expected_host):
        assert split_host_port(target) == (expected_host, None)

    @pytest.mark.parametrize("target", ["10.0.0.1:0", "10.0.0.1:99999", "10.0.0.1:abc"])
    def test_invalid_port_is_not_split(self, target):
        # An unparseable suffix must not raise and must not be silently eaten:
        # the caller falls back to --port / the protocol default.
        assert split_host_port(target) == (target, None)


# ---------------------------------------------------------------------------
# parse_targets with an embedded port
# ---------------------------------------------------------------------------


class TestParseTargetsWithPort:
    def test_single_host(self):
        assert parse_targets("10.0.0.1:502") == ["10.0.0.1:502"]

    def test_cidr_expansion_keeps_port(self):
        targets = parse_targets("10.0.0.0/30:5020")
        assert targets
        assert all(t.endswith(":5020") for t in targets)
        assert "10.0.0.1:5020" in targets

    def test_ip_range_expansion_keeps_port(self):
        assert parse_targets("192.168.1.1-3:502") == [
            "192.168.1.1:502",
            "192.168.1.2:502",
            "192.168.1.3:502",
        ]

    def test_comma_list_keeps_per_entry_ports(self):
        assert parse_targets("10.0.0.1:502,10.0.0.2:5020") == ["10.0.0.1:502", "10.0.0.2:5020"]

    def test_target_file_keeps_per_line_ports(self, tmp_path):
        p = tmp_path / "targets.txt"
        p.write_text("# comment\n10.0.0.1:502\n10.0.0.2:5020\n10.0.0.3\n")
        assert parse_targets(str(p)) == ["10.0.0.1:502", "10.0.0.2:5020", "10.0.0.3"]

    def test_ipv6_port_round_trips_through_brackets(self):
        # A bare IPv6 plus ":port" would be ambiguous with a longer address, so
        # the port is re-attached in bracketed form and splits back cleanly.
        (target,) = parse_targets("[2001:db8::1]:502")
        assert target == "[2001:db8::1]:502"
        assert split_host_port(target) == ("2001:db8::1", 502)


class TestParseTargetsRegressions:
    @pytest.mark.parametrize(
        "spec",
        [
            "10.0.0.1:8080/2",
            "milo.digitalpetri.com:62541/milo",
            "opc.tcp://192.168.1.100:4840",
            "ws://10.0.0.1:9000/cp1",
        ],
    )
    def test_url_and_path_forms_pass_through_untouched(self, spec):
        assert parse_targets(spec) == [spec]

    def test_plain_forms_unaffected(self):
        assert parse_targets("192.168.1.100") == ["192.168.1.100"]
        assert parse_targets("can0") == ["can0"]
        # /30 expands to its two usable hosts, with or without a port
        assert parse_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]


# ---------------------------------------------------------------------------
# cli.scan_target
# ---------------------------------------------------------------------------


class _RecordingProtocol:
    """Minimal stand-in for a Layer-2 connection class.

    scan_target only constructs the class and calls get_results(), so recording
    the args copy it was handed is enough to assert the port wiring.
    """

    seen = []

    def __init__(self, args, db, host):
        self.args = args
        self.host = host
        type(self).seen.append((host, getattr(args, "port", None), getattr(args, "host", None)))

    def get_results(self):
        return {"host": self.host, "success": True}


@pytest.fixture
def recorder():
    _RecordingProtocol.seen = []
    yield _RecordingProtocol
    _RecordingProtocol.seen = []


def _args(protocol="modbus", port=502, **extra):
    return Namespace(protocol=protocol, port=port, **extra)


class TestScanTargetShorthand:
    def test_embedded_port_is_applied_and_host_is_bare(self, recorder):
        cli.scan_target(recorder, _args(), "10.0.0.1:5020")
        assert recorder.seen == [("10.0.0.1", 5020, "10.0.0.1")]

    def test_embedded_port_beats_explicit_flag(self, recorder):
        cli.scan_target(recorder, _args(port=502), "10.0.0.1:5020")
        host, port, _ = recorder.seen[0]
        assert (host, port) == ("10.0.0.1", 5020)

    def test_without_shorthand_flag_port_is_kept(self, recorder):
        cli.scan_target(recorder, _args(port=502), "10.0.0.1")
        assert recorder.seen == [("10.0.0.1", 502, "10.0.0.1")]

    def test_unset_port_sentinel_survives(self, recorder):
        # coap/dicom/mqtt register --port with default=None and branch on that
        # "unset" sentinel to choose their plain-vs-TLS default port.
        cli.scan_target(recorder, _args(protocol="coap", port=None), "10.0.0.1")
        assert recorder.seen == [("10.0.0.1", None, "10.0.0.1")]

    def test_port_does_not_leak_between_targets(self, recorder):
        args = _args(port=502)
        cli.scan_target(recorder, args, "10.0.0.1:5020")
        cli.scan_target(recorder, args, "10.0.0.2")
        assert [(h, p) for h, p, _ in recorder.seen] == [("10.0.0.1", 5020), ("10.0.0.2", 502)]
        assert args.port == 502

    def test_ipv6_shorthand(self, recorder):
        cli.scan_target(recorder, _args(), "[2001:db8::1]:5020")
        assert recorder.seen == [("2001:db8::1", 5020, "2001:db8::1")]

    def test_bare_ipv6_is_not_split(self, recorder):
        cli.scan_target(recorder, _args(), "2001:db8::1")
        assert recorder.seen == [("2001:db8::1", 502, "2001:db8::1")]

    @pytest.mark.parametrize(
        "protocol,target",
        [
            ("opcua", "opc.tcp://10.0.0.1:4840"),
            ("ocpp", "ws://10.0.0.1:9000/cp1"),
            ("pcap", "/tmp/capture.pcap"),
            ("can", "can0:1"),
            ("discovery", "eth0:1"),
            ("ethercat", "eth0:1"),
            ("goose", "eth0:1"),
            ("profinet", "eth0:1"),
        ],
    )
    def test_exempt_targets_are_passed_through_verbatim(self, recorder, protocol, target):
        cli.scan_target(recorder, _args(protocol=protocol), target)
        host, port, _ = recorder.seen[0]
        assert host == target
        assert port == 502  # untouched flag/default value


class TestAcceptsHostPort:
    @pytest.mark.parametrize("protocol", ["modbus", "snmp", "mqtt", "hl7", "knx"])
    def test_host_based_protocols_accept_shorthand(self, protocol):
        assert cli._accepts_host_port(protocol, "10.0.0.1:502") is True

    @pytest.mark.parametrize("protocol", sorted(cli.INTERFACE_TARGET_PROTOCOLS | {"pcap"}))
    def test_non_host_protocols_do_not(self, protocol):
        assert cli._accepts_host_port(protocol, "eth0:1") is False

    def test_cli_aliases_are_resolved(self):
        # args.protocol holds the CLI name, so the "discover" alias must fold
        # into "discovery" before the interface-target exemption is checked.
        assert cli._accepts_host_port("discover", "eth0:1") is False
        assert cli._accepts_host_port("s7", "10.0.0.1:102") is True

    def test_url_targets_never_split(self):
        assert cli._accepts_host_port("modbus", "opc.tcp://10.0.0.1:4840") is False

    def test_empty_target(self):
        assert cli._accepts_host_port("modbus", "") is False
