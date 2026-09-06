"""
Fuzzer Reach Benchmark — measures three dimensions of fuzzer quality:

1. **Breadth** (Spec Coverage): How many boofuzz Request nodes does each protocol build?
2. **Depth** (Mutation Count): How many total test-case mutations are generated?
3. **Completeness** (Field Coverage): What fraction of fields are fuzzable, and how
   diverse are the primitive types?

All tests run offline using MockConnectionFactory — no network I/O required.

Gaps filled vs. existing tests:
- test_fuzzer_coverage.py checks get_request_definitions() counts (group-level)
  → this checks actual session Request nodes (individual requests)
- No existing test measures num_mutations() per Request node
- No existing test walks the boofuzz primitive tree to count fuzzable fields
- No existing test checks for "dead" requests (all-Static, zero fuzzable fields)
- No existing test measures primitive type diversity per protocol
"""

import sys
from collections import Counter

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

pytestmark = pytest.mark.core

# ---------------------------------------------------------------------------
# Protocols that can't instantiate in test environment
# ---------------------------------------------------------------------------
SKIP_PROTOCOLS = {
    "icmp",
    "icmpv6",
    "ipv4",
    "ipv6",
    "ethernet",
    "industrial_ethernet",
    "profinet_dcp",
    "modbus_rtu",
    "mutation",
}

# Protocols with known structural issues (e.g. recursive walk). Empty: the old
# {"snmpv2c"} entry was dead — snmpv2c is not a benchmarked protocol (the SNMP
# fuzzers are snmpv1/snmpv3, both of which walk cleanly), so the xfail never
# fired. Keep the guard hook in case a real recursive-walk protocol appears.
WALK_XFAIL: set[str] = set()

# ---------------------------------------------------------------------------
# Baselines — regression anchors.  Update when new requests are added.
# Format: protocol → (min_requests, min_mutations, min_fuzzable_fields)
# ---------------------------------------------------------------------------
BENCHMARKS = {
    # P0 Critical ICS
    "modbus": (55, 20000, 180),
    "opcua": (45, 250000, 1800),
    "iec104": (90, 100000, 650),
    "mms": (20, 1500, 25),
    "dnp3": (20, 22000, 170),
    "ethernetip": (18, 22000, 170),
    "bacnet": (20, 28000, 240),
    "ads": (18, 12000, 100),
    # P1 Critical IoT/Net
    "dns": (20, 50000, 350),
    "http": (14, 30000, 140),
    "http2": (25, 14000, 90),
    "ftp": (45, 16000, 80),
    "smtp": (15, 14000, 30),
    "mqtt": (20, 9000, 70),
    "snmpv1": (10, 10000, 30),
    "snmpv3": (5, 18000, 70),
    # P2 Standard
    "coap": (18, 7000, 55),
    "dhcp": (14, 35000, 300),
    "dhcpv6": (14, 40000, 300),
    "ntp": (22, 30000, 240),
    "vnc": (6, 1500, 20),
    "hl7": (8, 12000, 60),
    # min_fuzzable lowered 350->240: the DNS flags are now one fuzzable 16-bit
    # Word per header instead of 8 byte-padded BitFields (which mis-rendered the
    # header). Fewer fields, but valid packets and broader flag-value coverage.
    "mdns": (24, 24000, 240),
    "tftp": (16, 7000, 55),
    # P3 Simple
    "echo": (7, 500, 7),
    "daytime": (10, 1500, 10),
    "tcp": (40, 55000, 500),
}

# Minimum fuzzable-to-total field ratio per tier
# Lower bounds account for raw-byte protocols (SNMP BER, MMS ASN.1)
# where Static framing dominates and only payloads are fuzzable
MIN_FUZZABLE_RATIO = {
    "P0": 0.30,
    "P1": 0.15,
    "P2": 0.25,
    "P3": 0.25,
}

# Tier assignment (matching test_fuzzer_coverage.py)
PROTOCOL_TIER = {
    "modbus": "P0",
    "opcua": "P0",
    "iec104": "P0",
    "mms": "P0",
    "dnp3": "P0",
    "ethernetip": "P0",
    "bacnet": "P0",
    "ads": "P0",
    "dns": "P1",
    "http": "P1",
    "http2": "P1",
    "ftp": "P1",
    "smtp": "P1",
    "mqtt": "P1",
    "snmpv1": "P1",
    "snmpv3": "P1",
    "coap": "P2",
    "dhcp": "P2",
    "dhcpv6": "P2",
    "ntp": "P2",
    "vnc": "P2",
    "hl7": "P2",
    "mdns": "P2",
    "tftp": "P2",
    "echo": "P3",
    "daytime": "P3",
    "tcp": "P3",
}

# Minimum distinct fuzzable primitive types per tier
MIN_PRIMITIVE_TYPES = {
    "P0": 4,
    "P1": 2,
    "P2": 2,
    "P3": 2,
}

# Baseline request names are intentionally all-static (valid packets)
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
}

# No-argument protocol commands that are intentionally all-Static
# (nothing to fuzz about a bare "NOOP\r\n" or "QUIT\r\n")
STATIC_COMMANDS = {
    "NOOP",
    "PWD",
    "SYST",
    "FEAT",
    "CDUP",
    "PASV",
    "CCC",
    "ABOR",
    "QUIT",
    "REIN",
    "STOU",
    "LIST",
    "NLST",
    "STAT",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_config():
    return FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=9999,
        protocol_type=ProtocolType.TCP,
        log_session=False,
        console_output=False,
        skip_pre_send_checks=True,
        web_interface=False,
        enumerate=False,
    )


def _is_baseline_request(name: str) -> bool:
    """Heuristic: is this a baseline/keepalive/no-arg request (intentionally non-fuzzable)?"""
    if name in STATIC_COMMANDS:
        return True
    lower = name.lower()
    return any(indicator in lower for indicator in BASELINE_INDICATORS)


def _instantiate(protocol_name: str):
    """Instantiate a fuzzer and return its session, or skip/fail appropriately."""
    if protocol_name in SKIP_PROTOCOLS:
        pytest.skip(f"{protocol_name} requires special environment")

    cls = PROTOCOL_FUZZERS.get(protocol_name)
    if cls is None:
        pytest.skip(f"{protocol_name} not registered")

    try:
        fuzzer = cls(config=_make_config(), connection_factory=MockConnectionFactory())
        return fuzzer.session
    except ImportError as exc:
        pytest.skip(f"Missing dependency: {exc}")
    except Exception as exc:
        pytest.fail(f"Instantiation failed for {protocol_name}: {exc}")


def _walk_safe(request):
    """Walk a boofuzz Request tree with recursion guard."""
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(200)
    try:
        return list(request.walk())
    except RecursionError:
        return None
    finally:
        sys.setrecursionlimit(old_limit)


def _collect_metrics(session):
    """Collect all benchmark metrics from a boofuzz session."""
    from boofuzz import Request

    requests = {k: v for k, v in session.nodes.items() if isinstance(v, Request)}

    total_mutations = 0
    total_fields = 0
    total_fuzzable = 0
    dead_non_baseline = []
    fuzzable_type_counts = Counter()
    per_request = {}
    walk_failed = []

    for _key, req in requests.items():
        primitives = _walk_safe(req)
        if primitives is None:
            walk_failed.append(req.name)
            continue

        fields = 0
        fuzzable = 0
        for prim in primitives:
            fields += 1
            if prim.fuzzable:
                fuzzable += 1
                fuzzable_type_counts[type(prim).__name__] += 1

        try:
            muts = req.num_mutations(None)
        except Exception:
            muts = 0

        total_mutations += muts
        total_fields += fields
        total_fuzzable += fuzzable

        per_request[req.name] = {
            "fields": fields,
            "fuzzable": fuzzable,
            "mutations": muts,
        }

        if fuzzable == 0 and not _is_baseline_request(req.name):
            dead_non_baseline.append(req.name)

    return {
        "request_count": len(requests),
        "total_mutations": total_mutations,
        "total_fields": total_fields,
        "total_fuzzable": total_fuzzable,
        "dead_non_baseline": dead_non_baseline,
        "fuzzable_types": dict(fuzzable_type_counts),
        "fuzzable_type_count": len(fuzzable_type_counts),
        "per_request": per_request,
        "walk_failed": walk_failed,
    }


# ---------------------------------------------------------------------------
# Parametrized protocol list
# ---------------------------------------------------------------------------
BENCHMARK_PROTOCOLS = sorted(BENCHMARKS.keys())


# ---------------------------------------------------------------------------
# Test 1: Request Node Count (Breadth)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("protocol_name", BENCHMARK_PROTOCOLS)
def test_session_request_count(protocol_name):
    """Each protocol builds at least the baseline number of boofuzz Request nodes."""
    session = _instantiate(protocol_name)
    metrics = _collect_metrics(session)
    min_requests = BENCHMARKS[protocol_name][0]
    assert metrics["request_count"] >= min_requests, (
        f"{protocol_name}: {metrics['request_count']} session requests, baseline is {min_requests}"
    )


# ---------------------------------------------------------------------------
# Test 2: Total Mutations (Depth)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("protocol_name", BENCHMARK_PROTOCOLS)
def test_total_mutations_baseline(protocol_name):
    """Each protocol generates at least the baseline number of mutations."""
    session = _instantiate(protocol_name)
    metrics = _collect_metrics(session)
    min_mutations = BENCHMARKS[protocol_name][1]
    assert metrics["total_mutations"] >= min_mutations, (
        f"{protocol_name}: {metrics['total_mutations']} total mutations, "
        f"baseline is {min_mutations}"
    )


# ---------------------------------------------------------------------------
# Test 3: Fuzzable Field Count (Completeness)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("protocol_name", BENCHMARK_PROTOCOLS)
def test_fuzzable_field_count(protocol_name):
    """Each protocol has at least the baseline number of fuzzable fields."""
    session = _instantiate(protocol_name)
    metrics = _collect_metrics(session)
    min_fuzzable = BENCHMARKS[protocol_name][2]
    assert metrics["total_fuzzable"] >= min_fuzzable, (
        f"{protocol_name}: {metrics['total_fuzzable']} fuzzable fields, baseline is {min_fuzzable}"
    )


# ---------------------------------------------------------------------------
# Test 4: No Dead Requests (non-baseline with zero fuzzable fields)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("protocol_name", BENCHMARK_PROTOCOLS)
def test_no_dead_requests(protocol_name):
    """Non-baseline requests should have at least one fuzzable field."""
    if protocol_name in WALK_XFAIL:
        pytest.xfail(f"{protocol_name} has known walk() recursion issue")

    session = _instantiate(protocol_name)
    metrics = _collect_metrics(session)

    dead = metrics["dead_non_baseline"]
    # Allow up to 30% dead requests — some protocols use raw-byte
    # requests where the entire PDU is Static (e.g., MMS ASN.1)
    max_dead = max(3, metrics["request_count"] * 3 // 10)
    assert len(dead) <= max_dead, (
        f"{protocol_name}: {len(dead)} dead (non-fuzzable, non-baseline) requests "
        f"(max allowed {max_dead}): {dead[:10]}"
    )


# ---------------------------------------------------------------------------
# Test 5: Fuzzable Field Ratio
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("protocol_name", BENCHMARK_PROTOCOLS)
def test_fuzzable_field_ratio(protocol_name):
    """Fuzzable-to-total field ratio meets tier minimum."""
    if protocol_name in WALK_XFAIL:
        pytest.xfail(f"{protocol_name} has known walk() recursion issue")

    session = _instantiate(protocol_name)
    metrics = _collect_metrics(session)

    if metrics["total_fields"] == 0:
        pytest.fail(f"{protocol_name}: zero fields in session")

    ratio = metrics["total_fuzzable"] / metrics["total_fields"]
    tier = PROTOCOL_TIER.get(protocol_name, "P3")
    min_ratio = MIN_FUZZABLE_RATIO[tier]

    assert ratio >= min_ratio, (
        f"{protocol_name} (tier {tier}): fuzzable ratio {ratio:.1%} "
        f"< minimum {min_ratio:.0%} "
        f"({metrics['total_fuzzable']}/{metrics['total_fields']} fields)"
    )


# ---------------------------------------------------------------------------
# Test 6: Primitive Type Diversity
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("protocol_name", BENCHMARK_PROTOCOLS)
def test_primitive_type_diversity(protocol_name):
    """Each protocol uses a diverse set of fuzzable primitive types."""
    if protocol_name in WALK_XFAIL:
        pytest.xfail(f"{protocol_name} has known walk() recursion issue")

    session = _instantiate(protocol_name)
    metrics = _collect_metrics(session)

    tier = PROTOCOL_TIER.get(protocol_name, "P3")
    min_types = MIN_PRIMITIVE_TYPES[tier]

    assert metrics["fuzzable_type_count"] >= min_types, (
        f"{protocol_name} (tier {tier}): {metrics['fuzzable_type_count']} distinct "
        f"fuzzable types, minimum is {min_types}. "
        f"Types found: {sorted(metrics['fuzzable_types'].keys())}"
    )


# ---------------------------------------------------------------------------
# Test 7: Walk Structural Integrity
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("protocol_name", BENCHMARK_PROTOCOLS)
def test_walk_no_recursion(protocol_name):
    """Request.walk() must not recurse infinitely (structural integrity)."""
    session = _instantiate(protocol_name)

    from boofuzz import Request

    failures = []
    for _key, node in session.nodes.items():
        if not isinstance(node, Request):
            continue
        primitives = _walk_safe(node)
        if primitives is None:
            failures.append(node.name)

    if protocol_name in WALK_XFAIL:
        if failures:
            pytest.xfail(f"{protocol_name}: known walk() recursion in {len(failures)} requests")
        return

    assert not failures, (
        f"{protocol_name}: walk() recursion in {len(failures)} requests: {failures[:5]}"
    )


# ---------------------------------------------------------------------------
# Test 8: Per-Request Mutation Floor
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("protocol_name", BENCHMARK_PROTOCOLS)
def test_per_request_mutation_floor(protocol_name):
    """Non-baseline requests should generate a meaningful number of mutations."""
    if protocol_name in WALK_XFAIL:
        pytest.xfail(f"{protocol_name} has known walk() recursion issue")

    session = _instantiate(protocol_name)
    metrics = _collect_metrics(session)

    # Requests with fewer than 3 mutations are effectively useless
    MIN_MUTATIONS = 3
    shallow = []
    for name, data in metrics["per_request"].items():
        if _is_baseline_request(name):
            continue
        if data["mutations"] < MIN_MUTATIONS:
            shallow.append((name, data["mutations"]))

    max_shallow = max(3, metrics["request_count"] * 3 // 10)
    assert len(shallow) <= max_shallow, (
        f"{protocol_name}: {len(shallow)} requests with <{MIN_MUTATIONS} mutations "
        f"(max allowed {max_shallow}): {shallow[:10]}"
    )


# ---------------------------------------------------------------------------
# Test 9: Coverage Summary Report (always passes, prints stats)
# ---------------------------------------------------------------------------
def test_benchmark_summary_report(capsys):
    """Generate a coverage summary report across all benchmarked protocols."""
    rows = []
    for proto_name in sorted(BENCHMARKS.keys()):
        if proto_name in SKIP_PROTOCOLS:
            continue
        cls = PROTOCOL_FUZZERS.get(proto_name)
        if cls is None:
            continue
        try:
            session = _instantiate(proto_name)
            metrics = _collect_metrics(session)
            tier = PROTOCOL_TIER.get(proto_name, "?")
            ratio = (
                metrics["total_fuzzable"] / metrics["total_fields"] * 100
                if metrics["total_fields"]
                else 0
            )
            rows.append(
                (
                    proto_name,
                    tier,
                    metrics["request_count"],
                    metrics["total_fields"],
                    metrics["total_fuzzable"],
                    ratio,
                    metrics["total_mutations"],
                    metrics["fuzzable_type_count"],
                    len(metrics["dead_non_baseline"]),
                    len(metrics["walk_failed"]),
                )
            )
        except Exception:
            continue

    with capsys.disabled():
        print("\n")
        print("=" * 95)
        print("FUZZER REACH BENCHMARK REPORT")
        print("=" * 95)
        print(
            f"{'Protocol':<16} {'Tier':>4} {'Reqs':>5} {'Fields':>6} "
            f"{'Fuzz':>5} {'Ratio':>6} {'Mutations':>10} {'Types':>5} "
            f"{'Dead':>4} {'Err':>3}"
        )
        print("-" * 95)

        totals = [0] * 8
        for row in sorted(rows, key=lambda r: r[0]):
            print(
                f"{row[0]:<16} {row[1]:>4} {row[2]:>5} {row[3]:>6} "
                f"{row[4]:>5} {row[5]:>5.0f}% {row[6]:>10,} {row[7]:>5} "
                f"{row[8]:>4} {row[9]:>3}"
            )
            totals[0] += row[2]
            totals[1] += row[3]
            totals[2] += row[4]
            totals[3] += row[6]
            totals[4] += row[7]
            totals[5] += row[8]
            totals[6] += row[9]

        total_ratio = totals[2] / totals[1] * 100 if totals[1] else 0
        print("-" * 95)
        print(
            f"{'TOTAL':<16} {'':>4} {totals[0]:>5} {totals[1]:>6} "
            f"{totals[2]:>5} {total_ratio:>5.0f}% {totals[3]:>10,} {'':>5} "
            f"{totals[5]:>4} {totals[6]:>3}"
        )
        print(f"\nProtocols benchmarked: {len(rows)}")
        print("=" * 95)
