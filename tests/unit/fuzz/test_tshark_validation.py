"""
Tshark Dissector Validation — validates that baseline (non-mutated) fuzzer
payloads are structurally correct by running them through Wireshark's protocol
dissectors.

This catches real bugs: wrong CRCs, wrong tags, wrong encoding (text vs binary),
incorrect length fields, and other structural issues that would cause every
mutated packet to be malformed from the start.

Pipeline:
    1. Instantiate fuzzer with MockConnectionFactory (no network I/O)
    2. Find baseline / quick_coverage Request nodes in the session
    3. Render the non-mutated payload via request.render()
    4. Wrap in Ether/IP/TCP or Ether/IP/UDP with the correct port
    5. Write pcap, run tshark -T json
    6. Assert: protocol dissector found, no [Malformed Packet]

Requires: tshark (Wireshark CLI) installed on the system.
"""

import json
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

import pytest

from boofuzz import Request

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS
from tests.service_gate import require_service

# ---------------------------------------------------------------------------
# Skip entire module if tshark is not installed
# ---------------------------------------------------------------------------
TSHARK_BIN = shutil.which("tshark")
if TSHARK_BIN is None:
    require_service("tshark not installed")
pytestmark = [pytest.mark.slow]

# ---------------------------------------------------------------------------
# Protocol -> tshark dissector mapping
# ---------------------------------------------------------------------------
# Each entry: (port, transport, tshark_filter, expected_layer_keys, decode_as)
#   decode_as: optional list of tshark -d arguments for non-standard ports
#   expected_layer_keys: list of layer keys that should appear in tshark JSON

TSHARK_PROTOCOLS: Dict[str, dict] = {
    "modbus": {
        "port": 502,
        "transport": "tcp",
        "tshark_filter": "mbtcp",
        "expected_layers": ["mbtcp"],
        "decode_as": [],
    },
    "opcua": {
        "port": 4840,
        "transport": "tcp",
        "tshark_filter": "opcua",
        "expected_layers": ["opcua"],
        "decode_as": ["tcp.port==4840,opcua"],
    },
    "iec104": {
        "port": 2404,
        "transport": "tcp",
        "tshark_filter": "iec60870_104",
        "expected_layers": ["iec60870_104"],
        "decode_as": ["tcp.port==2404,iec60870_104"],
    },
    "dnp3": {
        "port": 20000,
        "transport": "tcp",
        "tshark_filter": "dnp3",
        "expected_layers": ["dnp3"],
        "decode_as": ["tcp.port==20000,dnp3"],
    },
    "snmpv2c": {
        "port": 161,
        "transport": "udp",
        "tshark_filter": "snmp",
        "expected_layers": ["snmp"],
        "decode_as": [],
    },
    "dhcpv6": {
        "port": 547,
        "transport": "udp",
        "tshark_filter": "dhcpv6",
        "expected_layers": ["dhcpv6"],
        "decode_as": [],
    },
    "ipv4": {
        "port": 0,
        "transport": "raw_ipv4",
        "tshark_filter": "ip",
        "expected_layers": ["ip"],
        "decode_as": [],
    },
    "icmp": {
        "port": 0,
        "transport": "icmp",
        "tshark_filter": "icmp",
        "expected_layers": ["icmp"],
        "decode_as": [],
    },
    "icmpv6": {
        "port": 0,
        "transport": "icmpv6",
        "tshark_filter": "icmpv6",
        "expected_layers": ["icmpv6"],
        "decode_as": [],
    },
    "mdns": {
        "port": 5353,
        "transport": "udp",
        "tshark_filter": "mdns",
        "expected_layers": ["mdns"],
        "decode_as": [],
    },
    "mqtt": {
        "port": 1883,
        "transport": "tcp",
        "tshark_filter": "mqtt",
        "expected_layers": ["mqtt"],
        "decode_as": [],
    },
    "http": {
        "port": 80,
        "transport": "tcp",
        "tshark_filter": "http",
        "expected_layers": ["http"],
        "decode_as": [],
    },
    "ftp": {
        "port": 21,
        "transport": "tcp",
        "tshark_filter": "ftp",
        "expected_layers": ["ftp"],
        "decode_as": [],
    },
    "smtp": {
        "port": 25,
        "transport": "tcp",
        "tshark_filter": "smtp",
        "expected_layers": ["smtp"],
        "decode_as": [],
    },
    "mms": {
        "port": 102,
        "transport": "tcp",
        "tshark_filter": "mms",
        "expected_layers": ["tpkt", "cotp"],
        # MMS sits on COTP on TPKT — tshark may not decode down to MMS
        # without a full association, but TPKT+COTP must be clean
        "decode_as": [],
    },
    "coap": {
        "port": 5683,
        "transport": "udp",
        "tshark_filter": "coap",
        "expected_layers": ["coap"],
        "decode_as": [],
    },
    "dns": {
        "port": 53,
        "transport": "udp",
        "tshark_filter": "dns",
        "expected_layers": ["dns"],
        "decode_as": [],
    },
    "snmpv1": {
        "port": 161,
        "transport": "udp",
        "tshark_filter": "snmp",
        "expected_layers": ["snmp"],
        "decode_as": [],
    },
    "snmpv3": {
        "port": 161,
        "transport": "udp",
        "tshark_filter": "snmp",
        "expected_layers": ["snmp"],
        "decode_as": [],
    },
    "bacnet": {
        "port": 47808,
        "transport": "udp",
        "tshark_filter": "bacnet",
        "expected_layers": ["bvlc"],
        # tshark uses "bvlc" for BACnet/IP, "bacnet" for the NPDU layer
        "decode_as": [],
    },
    "dhcp": {
        "port": 67,
        "transport": "udp",
        "tshark_filter": "dhcp",
        "expected_layers": ["dhcp"],
        "decode_as": [],
    },
    "ntp": {
        "port": 123,
        "transport": "udp",
        "tshark_filter": "ntp",
        "expected_layers": ["ntp"],
        "decode_as": [],
    },
    "tftp": {
        "port": 69,
        "transport": "udp",
        "tshark_filter": "tftp",
        "expected_layers": ["tftp"],
        "decode_as": [],
    },
    "vnc": {
        "port": 5900,
        "transport": "tcp",
        "tshark_filter": "vnc",
        "expected_layers": ["vnc"],
        "decode_as": ["tcp.port==5900,vnc"],
    },
    "ads": {
        "port": 48898,
        "transport": "tcp",
        "tshark_filter": "ams",
        "expected_layers": ["ams"],
        "decode_as": ["tcp.port==48898,ams"],
    },
    "ethernetip": {
        "port": 44818,
        "transport": "tcp",
        "tshark_filter": "enip",
        "expected_layers": ["enip"],
        "decode_as": [],
    },
}

# Protocols that can't instantiate in test environment (raw socket, serial, etc.)
SKIP_INSTANTIATE = {
    # mutation: generic mutation engine, not a wire protocol.
    "mutation",
    # modbus_rtu: serial framing has no standard pcap encapsulation for tshark;
    # CRC correctness is guarded by the dedicated render check instead.
    "modbus_rtu",
}

# Protocols without a stock tshark dissector — skip them
NO_TSHARK_DISSECTOR = {
    "echo",
    "daytime",
    "hl7",
    "tcp",
    "http2",
}

# Text-based protocols where baseline packets are command strings, not binary
# frames. Tshark may not recognize a bare command without server context
# (e.g., FTP needs a server banner first, SMTP needs 220 greeting).
# We still try them but accept if tshark doesn't find the protocol layer.
TEXT_PROTOCOL_LENIENT = {"ftp", "smtp"}

# Protocols where tshark may flag expert warnings (not malformed) that are OK
EXPERT_WARNING_OK = {"modbus", "opcua", "mms", "vnc"}

# Protocols with known tshark dissector issues on specific builds.
# (Empty: the DNP3 entry was removed once the real cause was found — the fuzzer
# emitted a data-link CRC that omitted the start bytes 0x0564, so Wireshark
# rejected every frame as raw "data". Fixed in dnp3.py; the dissector decodes
# the corrected frames fine, so this test now guards that the CRC stays valid.)
TSHARK_DISSECTOR_XFAIL = set()

# Baseline request name indicators
BASELINE_INDICATORS = {
    "baseline",
    "quick_coverage",
    "hello",
    "pingreq",
    "disconnect",
    "startdt",
    "testfr",
    "s_frame",
    "keepalive",
    "ping",
    "staticprotocolversion",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(port: int = 9999) -> FuzzerConfig:
    """Create a FuzzerConfig for offline instantiation."""
    return FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=port,
        protocol_type=ProtocolType.TCP,
        log_session=False,
        console_output=False,
        skip_pre_send_checks=True,
        web_interface=False,
    )


def _is_baseline_request(name: str) -> bool:
    """Heuristic: is this request likely a baseline / quick-coverage node?"""
    lower = name.lower()
    return any(indicator in lower for indicator in BASELINE_INDICATORS)


def _find_baseline_requests(session) -> List[Tuple[str, Request]]:
    """Find baseline Request nodes in a boofuzz session."""
    baselines = []
    for _key, node in session.nodes.items():
        if isinstance(node, Request) and _is_baseline_request(node.name):
            baselines.append((node.name, node))
    return baselines


def _find_all_requests(session) -> List[Tuple[str, Request]]:
    """Find ALL Request nodes in a boofuzz session."""
    results = []
    for _key, node in session.nodes.items():
        if isinstance(node, Request):
            results.append((node.name, node))
    return results


def _instantiate_fuzzer(protocol_name: str):
    """Instantiate a fuzzer, returning its session. Skips on failure."""
    if protocol_name in SKIP_INSTANTIATE:
        require_service(f"{protocol_name} requires special environment")

    cls = PROTOCOL_FUZZERS.get(protocol_name)
    if cls is None:
        require_service(f"{protocol_name} not in PROTOCOL_FUZZERS registry")

    try:
        fuzzer = cls(config=_make_config(), connection_factory=MockConnectionFactory())
        return fuzzer.session
    except ImportError as exc:
        require_service(f"Missing dependency: {exc}")
    except Exception as exc:
        pytest.fail(f"Instantiation failed for {protocol_name}: {exc}")


def _write_pcap(payload: bytes, port: int, transport: str, pcap_path: str) -> None:
    """Wrap payload in transport headers and write pcap.

    Transports:
      tcp/udp        - app-layer payload over Ether/IP/{TCP,UDP}
      raw_eth        - payload IS a complete Ethernet frame (L2 fuzzers)
      raw_ipv4/ipv6  - payload IS an IP packet; wrap only in Ethernet
      icmp           - payload is a bare ICMP message; wrap in Ether/IP(proto=1)
      icmpv6         - payload is a bare ICMPv6 message; wrap in Ether/IPv6(nh=58)
    """
    from scapy.all import IP, IPv6, TCP, UDP, Raw, wrpcap, Ether, conf

    conf.verb = 0

    if transport == "udp":
        pkt = Ether() / IP(dst="10.0.0.1") / UDP(dport=port, sport=12345) / Raw(load=payload)
    elif transport == "raw_eth":
        pkt = Ether(payload)
    elif transport == "raw_ipv4":
        pkt = Ether(type=0x0800) / Raw(load=payload)
    elif transport == "raw_ipv6":
        pkt = Ether(type=0x86DD) / Raw(load=payload)
    elif transport == "icmp":
        pkt = Ether() / IP(dst="10.0.0.1", proto=1) / Raw(load=payload)
    elif transport == "icmpv6":
        pkt = Ether() / IPv6(dst="fe80::1", nh=58) / Raw(load=payload)
    else:
        pkt = (
            Ether()
            / IP(dst="10.0.0.1")
            / TCP(dport=port, sport=12345, flags="PA")
            / Raw(load=payload)
        )

    wrpcap(pcap_path, [pkt])


def _run_tshark(
    pcap_path: str,
    tshark_filter: str,
    decode_as: List[str],
) -> Optional[dict]:
    """Run tshark and return parsed JSON output, or None on failure."""
    cmd = [TSHARK_BIN, "-r", pcap_path, "-T", "json"]

    # Add decode-as hints
    for da in decode_as:
        cmd.extend(["-d", da])

    # Use -J to filter which protocol layers are expanded
    cmd.extend(["-J", tshark_filter])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        return None

    try:
        data = json.loads(result.stdout)
        if data and len(data) > 0:
            return data[0]
    except (json.JSONDecodeError, IndexError):
        return None

    return None


def _check_dissection(
    tshark_result: Optional[dict],
    expected_layers: List[str],
    protocol_name: str,
) -> Tuple[bool, bool, List[str]]:
    """Check tshark result for dissector recognition and malformed indicators.

    Returns:
        (dissector_found, is_malformed, found_layers)
    """
    if tshark_result is None:
        return False, False, []

    layers = tshark_result.get("_source", {}).get("layers", {})
    found_layers = list(layers.keys())

    # Check if any expected layer is present
    dissector_found = any(layer in layers for layer in expected_layers)

    # Check for [Malformed Packet] anywhere in the JSON
    full_text = json.dumps(tshark_result)
    is_malformed = "Malformed Packet" in full_text or "_ws.malformed" in full_text

    return dissector_found, is_malformed, found_layers


# ---------------------------------------------------------------------------
# Build parametrized test list
# ---------------------------------------------------------------------------


def _get_testable_protocols() -> List[str]:
    """Return list of protocol names that have tshark dissectors and can instantiate."""
    testable = []
    for proto_name in sorted(TSHARK_PROTOCOLS.keys()):
        if proto_name in SKIP_INSTANTIATE:
            continue
        if proto_name in NO_TSHARK_DISSECTOR:
            continue
        if proto_name not in PROTOCOL_FUZZERS:
            continue
        testable.append(proto_name)
    return testable


TESTABLE_PROTOCOLS = _get_testable_protocols()


# ---------------------------------------------------------------------------
# Main test: parametrized over all testable protocols
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("protocol_name", TESTABLE_PROTOCOLS)
def test_tshark_dissector_validates_baseline(protocol_name, tmp_path, capsys):
    """Baseline payloads must be recognized by tshark's protocol dissector
    without [Malformed Packet] indicators.

    For each protocol:
    1. Instantiate fuzzer offline
    2. Find baseline/quick_coverage Request nodes
    3. Render non-mutated payload
    4. Write pcap with correct transport wrapping
    5. Run tshark -T json
    6. Assert: dissector found AND no malformed indicator
    """
    proto_config = TSHARK_PROTOCOLS[protocol_name]
    port = proto_config["port"]
    transport = proto_config["transport"]
    tshark_filter = proto_config["tshark_filter"]
    expected_layers = proto_config["expected_layers"]
    decode_as = proto_config["decode_as"]

    # 1. Instantiate
    session = _instantiate_fuzzer(protocol_name)

    # 2. Find baseline requests first, fall back to ALL requests
    candidates = _find_baseline_requests(session)
    if not candidates:
        candidates = _find_all_requests(session)

    if not candidates:
        pytest.skip(f"{protocol_name}: no Request nodes found in session")

    # 3. Test each candidate — at least ONE must pass
    results = []
    any_dissector_found = False

    for req_name, req_node in candidates:
        try:
            payload = req_node.render()
        except Exception as exc:
            results.append((req_name, "RENDER_ERROR", str(exc), []))
            continue

        if not payload or len(payload) == 0:
            results.append((req_name, "EMPTY", "zero-length payload", []))
            continue

        # 4. Write pcap
        pcap_path = str(tmp_path / f"{protocol_name}_{req_name}.pcap")
        _write_pcap(payload, port, transport, pcap_path)

        # 5. Run tshark
        tshark_result = _run_tshark(pcap_path, tshark_filter, decode_as)

        # 6. Check dissection
        dissector_found, is_malformed, found_layers = _check_dissection(
            tshark_result, expected_layers, protocol_name
        )

        if dissector_found:
            any_dissector_found = True

        status = "OK" if dissector_found and not is_malformed else "FAIL"
        if dissector_found and is_malformed:
            status = "MALFORMED"
        elif not dissector_found:
            status = "NO_DISSECTOR"

        results.append((req_name, status, "", found_layers))

        # Early success: if we find at least one clean baseline, that's enough
        # to validate the protocol framing is correct
        if status == "OK":
            break

    # Report
    with capsys.disabled():
        print()
        for req_name, status, detail, found_layers in results:
            layer_str = ", ".join(found_layers) if found_layers else "none"
            if status == "OK":
                print(f"  {protocol_name}: {req_name} -> tshark found [{layer_str}] PASS")
            elif status == "MALFORMED":
                print(f"  {protocol_name}: {req_name} -> [Malformed Packet] FAIL")
            elif status == "NO_DISSECTOR":
                print(f"  {protocol_name}: {req_name} -> no dissector [{layer_str}] SKIP")
            else:
                print(f"  {protocol_name}: {req_name} -> {status}: {detail}")

    # For text-based protocols, accept if tshark can't find the dissector
    # (they need server-side context for tshark to recognize them)
    if protocol_name in TEXT_PROTOCOL_LENIENT and not any_dissector_found:
        pytest.skip(
            f"{protocol_name}: text-based protocol, tshark needs server context to recognize"
        )

    # For protocols with known tshark dissector issues, xfail instead of hard fail
    if protocol_name in TSHARK_DISSECTOR_XFAIL and not any_dissector_found:
        pytest.xfail(
            f"{protocol_name}: known tshark dissector issue "
            f"(dissector registered but not invoked on this tshark build)"
        )

    # Assertion: at least one request must be recognized by the dissector
    assert any_dissector_found, (
        f"{protocol_name}: tshark could not find any expected layer "
        f"{expected_layers} in any of {len(results)} requests tested. "
        f"Results: {[(r[0], r[1]) for r in results]}"
    )

    # Assertion: no malformed packets among recognized requests
    malformed_requests = [r[0] for r in results if r[1] == "MALFORMED"]
    assert not malformed_requests, (
        f"{protocol_name}: [Malformed Packet] detected in baseline requests: "
        f"{malformed_requests}. These are structural bugs in the fuzzer "
        f"payload construction."
    )


# ---------------------------------------------------------------------------
# All-requests validation: every well-formed request must decode cleanly.
# The baseline test above only checks ONE request per protocol, which let
# structural bugs in non-baseline requests hide (DNP3/RTU CRCs, mDNS records,
# iec104 ApduLen were all found this way). This validates every request whose
# name does NOT mark it as an intentional attack/boundary/malformed payload.
# ---------------------------------------------------------------------------

# Request-name fragments that signal an INTENTIONALLY malformed / boundary /
# attack payload — such requests are supposed to be rejected by a strict
# dissector, so the all-requests validator skips them.
_INTENTIONAL_MALFORMED_KEYWORDS = (
    "malform",
    "truncat",
    "invalid",
    "oversiz",
    "overflow",
    "underflow",
    "overrun",
    "attack",
    "circular",
    "nested",
    "mismatch",
    "corrupt",
    "excessiv",
    "crash",
    "exploit",
    "flood",
    "giant",
    "huge",
    "garbage",
    "evil",
    "boundar",
    "boundr",
    "negative",
    "_bad",
    "bad_",
    "badcrc",
    "fuzz",
    "loop",
    "wrap",
    "max_",
    "_max",
    "256",
    "1024",
    "65535",
    "9999",
    "large",
    "long",
    "short",
    "zero",
    "sweep",
)

# Explicit (protocol, request) pairs that are intentionally malformed but whose
# names lack an obvious keyword. Each entry verified by hand.
_INTENTIONAL_MALFORMED: set = {
    "dns/DNS_No_Null_Term",  # deliberately omits the QNAME root label
    "dns/DNS_Pointer_Forward",  # NAME:WRECK forward compression pointer
    "dns/DNS_Pointer_Past_Packet",  # NAME:WRECK pointer beyond packet end
    "dhcp/DHCP_OPTION_CHAIN",  # option-chain parser overflow attack
    "dhcp/DHCP_Option_Refcount",  # CVE-2022-2928 option refcount overflow
    "ethernetip/EIP_Get_Attribute_List_OOB",  # CVE-2022-43604 OpENer attr-count OOB read
    "ethernetip/EIP_Set_Attribute_List_OOB",  # CVE-2022-43605 OpENer attr-count OOB write
    "iec104/IEC104_APDU_Length_Lie",  # APDU length field deliberately lies about frame size
}

# Raw L3 protocols excluded from the all-requests validator. ipv4 and icmp
# validate cleanly offline and are NOT excluded. ipv6/ethernet/icmpv6 carry
# content the offline harness can't fairly judge: ethernet frames carry an
# arbitrary L3 payload (the fuzzer owns only the L2 framing), and ICMPv6 error
# messages embed a (deliberately minimal) packet that tshark flags as malformed
# below the icmpv6 layer the fuzzer is responsible for.
_ALL_REQUESTS_RAW_EXCLUDE = {"ethernet", "ipv6", "icmpv6"}

# Documented backlog: protocols whose NON-baseline requests still produce
# structurally-invalid frames (verified real bugs of the same class as the
# DNP3/RTU CRC and mDNS endianness bugs). xfail'd here so the validator ships
# green and these are tracked; remove a protocol once its requests are fixed.
# DNS shares mDNS's big-endian/flags bug; the rest are length/encoding bugs.
# Empty: all protocols whose well-formed requests previously produced malformed
# frames have been fixed (dns, bacnet, dhcp, dhcpv6, coap, http, iec104, mqtt).
_KNOWN_STRUCTURAL_BUGS: set = set()


def _is_wellformed_request(protocol_name: str, req_name: str) -> bool:
    """Heuristic: should this request produce a spec-valid frame?"""
    low = req_name.lower()
    if any(k in low for k in _INTENTIONAL_MALFORMED_KEYWORDS):
        return False
    return f"{protocol_name}/{req_name}" not in _INTENTIONAL_MALFORMED


def _tshark_malformed(pcap_path: str, decode_as: List[str]) -> bool:
    """Run tshark over the FULL packet (no -J layer filter) and report whether
    it flags a malformed packet — including expert-info malformed (e.g. iec104
    'Invalid Apdulen') that the -J-filtered JSON in _run_tshark would hide."""
    cmd = [TSHARK_BIN, "-r", pcap_path, "-T", "json"]
    for da in decode_as:
        cmd.extend(["-d", da])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    out = result.stdout
    return ("_ws.malformed" in out) or ("Malformed Packet" in out)


@pytest.mark.parametrize("protocol_name", TESTABLE_PROTOCOLS)
def test_tshark_validates_all_wellformed_requests(protocol_name, tmp_path):
    """Every well-formed (non-attack) request must decode without [Malformed].

    Unlike the baseline test, this checks ALL requests so a structural bug
    (wrong CRC / length / endianness / record encoding) in any non-baseline
    request is caught rather than hidden behind one clean baseline.
    """
    if protocol_name in _ALL_REQUESTS_RAW_EXCLUDE:
        pytest.skip(
            f"{protocol_name}: L2/L3 framing fuzzer — requests carry arbitrary upper-layer "
            f"payloads / embedded packets below the layer it owns, so a no-malformed-anywhere "
            f"check doesn't apply (its baseline framing is still checked by the baseline test)"
        )

    cfg = TSHARK_PROTOCOLS[protocol_name]
    session = _instantiate_fuzzer(protocol_name)

    malformed = []
    checked = 0
    for req_name, node in _find_all_requests(session):
        if not _is_wellformed_request(protocol_name, req_name):
            continue
        try:
            payload = node.render()
        except Exception:
            continue
        if not payload:
            continue
        checked += 1
        pcap_path = str(tmp_path / f"all_{protocol_name}_{req_name}.pcap")
        _write_pcap(payload, cfg["port"], cfg["transport"], pcap_path)
        if _tshark_malformed(pcap_path, cfg["decode_as"]):
            malformed.append(req_name)

    if checked == 0:
        pytest.skip(f"{protocol_name}: no well-formed requests to validate")

    if protocol_name in _KNOWN_STRUCTURAL_BUGS:
        if malformed:
            pytest.xfail(f"{protocol_name}: known structural payload bugs (backlog): {malformed}")
        return  # an empty list means the backlog entry can be removed

    assert not malformed, (
        f"{protocol_name}: {len(malformed)} well-formed request(s) produce "
        f"[Malformed Packet] in tshark — structural payload bugs: {malformed}"
    )


# ---------------------------------------------------------------------------
# Render integrity: every request must serialize without raising.
# A request that can't render is a fuzzer bug (e.g. a binary value handed to a
# string primitive) — the fuzzer would crash trying to send it, so it must
# never be silently skipped.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("protocol_name", TESTABLE_PROTOCOLS)
def test_all_requests_render_without_error(protocol_name):
    """Every request in the session must serialize via render() cleanly."""
    session = _instantiate_fuzzer(protocol_name)
    errors = []
    for req_name, node in _find_all_requests(session):
        try:
            node.render()
        except Exception as exc:  # noqa: BLE001 - report any render failure
            errors.append(f"{req_name}: {type(exc).__name__}: {exc}")
    assert not errors, f"{protocol_name}: {len(errors)} request(s) fail to render: {errors}"


# ---------------------------------------------------------------------------
# Bidirectional guard: requests on the intentional-malformed allowlist must
# STAY malformed. If one becomes well-formed the attack/CVE payload has been
# silently neutralized — remove it from _INTENTIONAL_MALFORMED (and validate it
# in the well-formed test instead).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry", sorted(_INTENTIONAL_MALFORMED))
def test_intentional_malformed_stays_malformed(entry, tmp_path):
    """Allowlisted intentionally-malformed requests must remain malformed."""
    protocol_name, req_name = entry.split("/", 1)
    cfg = TSHARK_PROTOCOLS[protocol_name]
    session = _instantiate_fuzzer(protocol_name)
    node = dict(_find_all_requests(session)).get(req_name)
    assert node is not None, f"{entry}: request no longer exists in the session"
    pcap_path = str(tmp_path / f"intent_{protocol_name}_{req_name}.pcap")
    _write_pcap(node.render(), cfg["port"], cfg["transport"], pcap_path)
    assert _tshark_malformed(pcap_path, cfg["decode_as"]), (
        f"{entry} is allowlisted as intentionally malformed but tshark now parses "
        f"it cleanly — the attack/CVE payload was neutralized. Remove it from "
        f"_INTENTIONAL_MALFORMED and validate it via the well-formed test instead."
    )


# ---------------------------------------------------------------------------
# Summary report (always passes, prints overview)
# ---------------------------------------------------------------------------


def test_tshark_validation_summary(tmp_path, capsys):
    """Generate a summary report of tshark validation across all protocols."""
    rows = []

    for proto_name in sorted(TSHARK_PROTOCOLS.keys()):
        if proto_name in SKIP_INSTANTIATE or proto_name in NO_TSHARK_DISSECTOR:
            rows.append((proto_name, "SKIPPED", "-", 0, 0))
            continue
        if proto_name not in PROTOCOL_FUZZERS:
            rows.append((proto_name, "NO_FUZZER", "-", 0, 0))
            continue

        proto_config = TSHARK_PROTOCOLS[proto_name]

        try:
            session = _instantiate_fuzzer(proto_name)
        except Exception:
            rows.append((proto_name, "INIT_FAIL", "-", 0, 0))
            continue

        candidates = _find_baseline_requests(session)
        if not candidates:
            candidates = _find_all_requests(session)

        ok_count = 0
        malformed_count = 0
        tested = 0

        for req_name, req_node in candidates[:5]:  # Test up to 5 per protocol
            try:
                payload = req_node.render()
            except Exception:
                continue

            if not payload:
                continue

            pcap_path = str(tmp_path / f"summary_{proto_name}_{req_name}.pcap")
            _write_pcap(payload, proto_config["port"], proto_config["transport"], pcap_path)

            tshark_result = _run_tshark(
                pcap_path,
                proto_config["tshark_filter"],
                proto_config["decode_as"],
            )

            dissector_found, is_malformed, _ = _check_dissection(
                tshark_result, proto_config["expected_layers"], proto_name
            )

            tested += 1
            if dissector_found and not is_malformed:
                ok_count += 1
            elif is_malformed:
                malformed_count += 1

        status = "PASS" if ok_count > 0 and malformed_count == 0 else "FAIL"
        if tested == 0:
            status = "NO_CANDIDATES"
        elif ok_count == 0 and malformed_count == 0:
            status = "NO_DISSECTOR"

        rows.append((proto_name, status, proto_config["tshark_filter"], ok_count, malformed_count))

    with capsys.disabled():
        print("\n")
        print("=" * 78)
        print("TSHARK DISSECTOR VALIDATION SUMMARY")
        print("=" * 78)
        print(f"{'Protocol':<16} {'Status':<14} {'Filter':<18} {'OK':>4} {'Malformed':>9}")
        print("-" * 78)

        pass_count = 0
        fail_count = 0
        skip_count = 0

        for row in rows:
            print(f"{row[0]:<16} {row[1]:<14} {row[2]:<18} {row[3]:>4} {row[4]:>9}")
            if row[1] == "PASS":
                pass_count += 1
            elif row[1] in ("SKIPPED", "NO_FUZZER", "NO_CANDIDATES", "NO_DISSECTOR"):
                skip_count += 1
            else:
                fail_count += 1

        print("-" * 78)
        print(
            f"Totals: {pass_count} passed, {fail_count} failed, "
            f"{skip_count} skipped out of {len(rows)} protocols"
        )
        print("=" * 78)

    # The summary is only meaningful if it actually validated protocols and
    # none of them came back genuinely FAIL (dissector found but malformed,
    # or no dissector matched at all despite being expected to).
    assert rows, "expected at least one protocol row in the tshark summary"
    by_name = {row[0]: row for row in rows}
    assert "modbus" in by_name, "modbus must be part of the tshark validation summary"
    assert by_name["modbus"][1] == "PASS", (
        f"modbus baseline payload must dissect cleanly via tshark, got status "
        f"{by_name['modbus'][1]!r}"
    )
    assert fail_count == 0, f"{fail_count} protocol(s) genuinely FAILed tshark validation: " + (
        ", ".join(
            row[0]
            for row in rows
            if row[1] not in ("PASS", "SKIPPED", "NO_FUZZER", "NO_CANDIDATES", "NO_DISSECTOR")
        )
    )
