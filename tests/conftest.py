"""
Shared pytest fixtures for OIDA testing.

This module provides common fixtures used across all test modules.
"""

import pytest
from pathlib import Path

# Check for scapy availability at module level
try:
    from scapy.all import rdpcap

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    rdpcap = None


# PCAP fixtures directory
PCAP_FIXTURES = Path(__file__).parent / "fixtures" / "pcap"


@pytest.fixture(scope="session")
def pcap_dir():
    """Path to PCAP test fixtures directory."""
    return PCAP_FIXTURES


@pytest.fixture
def load_pcap():
    """Factory fixture to load PCAP files.

    Usage:
        def test_something(load_pcap):
            packets = load_pcap("hsrp/filtered_hsrp.pcap")
    """
    if not SCAPY_AVAILABLE:
        pytest.skip("scapy not available")

    def _load(filename: str):
        path = PCAP_FIXTURES / filename
        if not path.exists():
            pytest.fail(f"PCAP fixture not found: {filename}")
        return rdpcap(str(path))

    return _load


# Protocol-specific PCAP fixtures


@pytest.fixture
def hsrp_packets(load_pcap):
    """Load HSRP test packets."""
    return load_pcap("hsrp/filtered_hsrp.pcap")


@pytest.fixture
def dhcp_packets(load_pcap):
    """Load DHCP test packets."""
    return load_pcap("dhcp/filtered_dhcp.pcap")


@pytest.fixture
def dhcpv6_packets(load_pcap):
    """Load DHCPv6 test packets."""
    return load_pcap("dhcpv6/filtered_dhcpv6.pcap")


@pytest.fixture
def igmp_packets(load_pcap):
    """Load IGMP test packets."""
    return load_pcap("igmp/filtered_igmp.pcap")


@pytest.fixture
def arp_packets(load_pcap):
    """Load ARP test packets."""
    return load_pcap("arp/filtered_arp.pcap")


@pytest.fixture
def ssdp_packets(load_pcap):
    """Load SSDP test packets."""
    return load_pcap("ssdp/filtered_ssdp.pcap")


@pytest.fixture
def mdns_packets(load_pcap):
    """Load mDNS test packets."""
    return load_pcap("mdns/filtered_mdns.pcap")


@pytest.fixture
def ipv6_nd_packets(load_pcap):
    """Load IPv6 Neighbor Discovery test packets."""
    return load_pcap("ipv6/filtered_ipv6_nd.pcap")


@pytest.fixture
def vrrp_packets(load_pcap):
    """Load VRRP test packets."""
    return load_pcap("vrrp/filtered_vrrp.pcap")


@pytest.fixture
def snmp_packets(load_pcap):
    """Load SNMP test packets."""
    return load_pcap("snmp/filtered_snmp.pcap")


@pytest.fixture
def lldp_packets(load_pcap):
    """Load LLDP test packets."""
    return load_pcap("lldp/filtered_lldp.pcap")


@pytest.fixture
def cdp_packets(load_pcap):
    """Load CDP test packets."""
    return load_pcap("cdp/filtered_cdp.pcap")


@pytest.fixture
def ntp_packets(load_pcap):
    """Load NTP test packets."""
    return load_pcap("ntp/filtered_ntp.pcap")


@pytest.fixture
def modbus_packets(load_pcap):
    """Load Modbus TCP test packets."""
    return load_pcap("modbus/filtered_modbus.pcap")


@pytest.fixture
def dnp3_packets(load_pcap):
    """Load DNP3 test packets."""
    return load_pcap("dnp3/filtered_dnp3.pcap")


@pytest.fixture
def bacnet_packets(load_pcap):
    """Load BACnet test packets."""
    return load_pcap("bacnet/filtered_bacnet.pcap")


@pytest.fixture
def s7_mms_packets(load_pcap):
    """Load S7/MMS test packets."""
    return load_pcap("s7comm/filtered_s7_mms.pcap")


# Pytest configuration


def pytest_configure(config):
    """Register custom markers for test categorization."""
    config.addinivalue_line("markers", "pcap: tests using PCAP fixtures")
    config.addinivalue_line("markers", "discovery: discovery protocol tests")
    config.addinivalue_line("markers", "slow: marks tests as slow running")
    config.addinivalue_line("markers", "network: marks tests requiring network access")
    config.addinivalue_line(
        "markers",
        "allow_credential_in_log: opt out of the no_credential_leak fixture "
        "for tests that intentionally place a credential string in log output "
        "(e.g. testing the redaction itself).",
    )


# ---------------------------------------------------------------------------
# Credential-leak protection (autouse)
# ---------------------------------------------------------------------------
#
# Closes the credential-log-leak gap class.
#
# OIDA's defensive-tool contract: a credential the operator passes via
# --password / --credentials / --psk, or one the scanner recovers via
# brute-force, MUST NOT appear in any user-facing log line OR in the
# structured JSON audit log. The structured `listener.credentials` /
# `results["data"]["credentials_found"]` state IS the feature; logging
# the raw value at INFO is the leak.
#
# This fixture seeds a sentinel string into the parts of every test's
# environment that production code reads as a credential (env vars +
# the canonical CredentialRegistry), captures all log + stdout/stderr
# output for the duration of the test, and on teardown asserts the
# sentinel never appears in any captured stream.
#
# Per-test opt-out: `@pytest.mark.allow_credential_in_log` for tests
# that legitimately need to inspect the redaction itself.

import logging

# Pattern: SECRET-style sentinels we seed into the env. Real protocol code
# that reads a credential MUST NOT leak any of these to logs.
_SENTINEL_PASSWORDS = ("OIDA_TESTLEAK_SECRET_PWD_xq2", "h0lyM0lyP@ssword_zz9")
_SENTINEL_USERS = ("oida_testleak_user_xq2", "oida_testleak_user_zz9")
_SENTINEL_PSKS = ("DEADBEEFCAFEBABE0123456789ABCDEF",)

# Substrings whose presence in captured log/stdout/stderr signals a leak.
_LEAK_SENTINELS = (
    *_SENTINEL_PASSWORDS,
    *_SENTINEL_USERS,
    *_SENTINEL_PSKS,
)


class _LeakBuffer(logging.Handler):
    """Captures every log record so we can grep on teardown."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record):
        try:
            self.lines.append(self.format(record))
        except Exception:  # noqa: BLE001
            # Never let a leak buffer error crash the test under guard.
            pass

    def contains(self, needle: str) -> bool:
        return any(needle in line for line in self.lines)


@pytest.fixture(autouse=True)
def _reset_mock_cli_singleton():
    """Keep the legacy MockCLI logger from outliving a test's captured stream.

    ics_logger._get_cli() caches a MockCLI singleton whose logging.StreamHandler
    binds to sys.stderr at creation time. When it is first created inside a
    capsys-capturing test (the autouse no_credential_leak fixture captures on
    every test), the handler keeps a reference to that test's captured stream;
    after the test that stream is closed, so the next log write raises
    "I/O operation on closed file" -- an order-dependent flake (e.g.
    test_json_log_path_configured and the log-level forwarding tests, which
    pass in isolation). Dropping the singleton and its stale handler on teardown
    forces a fresh handler bound to the live stream in the next test.
    """
    yield
    try:
        import oida.utils.ics_logger as _icslog

        _icslog._cli_instance = None
        logging.getLogger("oida._mock_cli").handlers.clear()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def no_credential_leak(request, capsys, monkeypatch):
    """Assert no test leaks a seeded credential into logs / stdout / stderr.

    Seeds sentinel strings into the canonical OIDA places a real
    operator would put credentials (env vars + import-time registries
    where supported), captures every log record + stdout/stderr line
    via the existing `capsys` machinery, and on teardown asserts none
    of the sentinels appear in any captured stream.

    Tests that intentionally need to inspect credential redaction can
    opt out with `@pytest.mark.allow_credential_in_log`.

    This is the SINGLE fixture that closes the credential-log-leak gap
    class across the entire 3000+ test suite.
    Each new logger.info(f"...{password}...") regression should make
    at least one existing auth/brute/pcap-credential test fail.
    """
    if request.node.get_closest_marker("allow_credential_in_log"):
        yield
        return

    # Seed every well-known credential channel with a sentinel.
    monkeypatch.setenv("OIDA_DEFAULT_PASSWORD", _SENTINEL_PASSWORDS[0])
    monkeypatch.setenv("OIDA_DEFAULT_USER", _SENTINEL_USERS[0])

    # Attach a capture handler to the stdlib root logger AND to OIDA's
    # logger trees. ICSLogger uses get_module_logger() which returns a
    # child of logging.getLogger("oida"); ProtocolLogger uses the same
    # tree. Capturing the root gets both.
    buf = _LeakBuffer()
    buf.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    oida = logging.getLogger("oida")
    prior_levels = (root.level, oida.level)
    root.setLevel(logging.DEBUG)
    oida.setLevel(logging.DEBUG)
    root.addHandler(buf)
    # Force propagation for OIDA's tree so child loggers reach root.
    prior_propagate = oida.propagate
    oida.propagate = True

    try:
        yield
    finally:
        root.removeHandler(buf)
        oida.propagate = prior_propagate
        root.setLevel(prior_levels[0])
        oida.setLevel(prior_levels[1])

    # Also collect any stdout / stderr produced by the test.
    cap = capsys.readouterr()
    captured = "\n".join([*buf.lines, cap.out, cap.err])

    leaks = []
    for sentinel in _LEAK_SENTINELS:
        if sentinel in captured:
            # Pinpoint which channel + which line(s).
            for source, text in (
                ("LOG", "\n".join(buf.lines)),
                ("STDOUT", cap.out),
                ("STDERR", cap.err),
            ):
                for line in text.splitlines():
                    if sentinel in line:
                        leaks.append(f"{source}: {line!r}")
    if leaks:
        pytest.fail(
            "Credential leak detected - sentinel(s) appeared in captured "
            "log / stdout / stderr:\n  " + "\n  ".join(leaks[:20])
        )
