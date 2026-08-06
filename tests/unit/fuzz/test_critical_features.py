"""
Test that fuzzer-relevant CVE patterns from ref/ are covered by existing requests.

This does NOT require a 1:1 mapping of CVEs to requests. A generic request
that mutates the relevant field counts as coverage. Only flags gaps when NO
existing request touches the vulnerable field/path.

CVE filter: Only counts CVEs where malformed bytes on the wire trigger parsing
failures (buffer overflows, integer overflows, NULL derefs, type confusion, etc).
Skips SSRF, path traversal, logic flaws, crypto weaknesses, auth bypasses.
"""

import pytest

from oida.fuzz.protocols import PROTOCOL_FUZZERS

pytestmark = pytest.mark.core


# Critical feature patterns that MUST be covered, mapped to request categories
# or name substrings that indicate coverage.
#
# Format: protocol -> list of (feature_description, coverage_indicators)
# coverage_indicators: list of substrings to search in request names/categories

CRITICAL_FEATURE_REQUIREMENTS = {
    # === P0 ICS Protocols (ICS audit 2026-02-14) ===
    "modbus": [
        (
            "MBAP length field manipulation",
            ["MBAP", "Boundary", "Combined"],
        ),
        (
            "All standard function codes covered",
            ["Baseline", "Quick", "Read", "Write"],
        ),
        (
            "Boundary value testing",
            ["Boundary", "Combined"],
        ),
        (
            "Exception response testing",
            ["Exception"],
        ),
    ],
    "dnp3": [
        (
            "Length overflow (CVE-2020-10615 pattern)",
            ["Overflow"],
        ),
        (
            "All function codes covered",
            ["Baseline"],
        ),
        (
            "Control operations",
            ["Control"],
        ),
        (
            "File operations (CVE-2020-10611)",
            ["File"],
        ),
        (
            "SAv5 authentication fuzzing",
            ["Auth"],
        ),
    ],
    "iec104": [
        (
            "U-format connection testing",
            ["Baseline", "Connection"],
        ),
        (
            "Control commands",
            ["Control"],
        ),
        (
            "Attack patterns",
            ["Attack"],
        ),
        (
            "Sequence number manipulation",
            ["Sequence"],
        ),
    ],
    "opcua": [
        (
            "Hello/Acknowledge handshake",
            ["Hello", "Baseline"],
        ),
        (
            "OpenSecureChannel",
            ["SecureChannel", "Channel"],
        ),
        (
            "Session creation",
            ["Session"],
        ),
        (
            "Boundary testing",
            ["Boundary"],
        ),
        (
            "Chunk flood (CVE-2022-25761)",
            ["Chunk", "Flood"],
        ),
        (
            "Nested message (CVE-2021-27432)",
            ["Nested"],
        ),
    ],
    "bacnet": [
        (
            "BVLL length overflow",
            ["Overflow"],
        ),
        (
            "Malformed APDU",
            ["Malformed"],
        ),
        (
            "Service sweep",
            ["Quick", "Coverage"],
        ),
        (
            "Boundary testing",
            ["Boundary"],
        ),
    ],
    "ethernetip": [
        (
            "Encapsulation length overflow (CVE-2020-25159)",
            ["Overflow"],
        ),
        (
            "CPF Item Count boundary",
            ["Boundary", "CPF"],
        ),
        (
            "CIP path overflow (CVE-2021-27478)",
            # Delivered by the EIP_Overflow group, which connects the
            # EIP_CIP_Path_Overflow request. Previously this matched the
            # phantom EIP_CIP_Boundary (advertised but never connected;
            # CODE_REVIEW.md ethernetip.py:179) - which delivered nothing.
            ["Overflow", "Path"],
        ),
    ],
    # fins / tase2 / hartip / profinet_dcp / industrial_ethernet entries
    # removed in §4 cleanup (2026-06-03): no corresponding fuzzer source
    # exists in src/oida/fuzz/protocols/; tests unconditionally skipped.
    # Re-add when the underlying fuzzer modules land — see §4.2 in
    # RELEASE_TODO.md (currently "deferred post-1.0"). MMS coverage moved
    # below since it IS implemented.
    "mms": [
        (
            "ASN.1 BER attacks (CVE-2022-2971)",
            ["ASN1"],
        ),
        (
            "Buffer overflow (CVE-2022-2970)",
            ["Buffer_Overflow", "Overflow"],
        ),
        (
            "OSI layer attacks",
            ["OSI"],
        ),
    ],
    # === P0 ICS (from earlier audit) ===
    "ads": [
        (
            "AMS/TCP length field manipulation (CVE-2019-5636 pattern)",
            ["Overflow", "Length", "Boundary"],
        ),
        (
            "AMS NetId routing attacks",
            ["Route", "NetId", "Boundary"],
        ),
        (
            "WriteControl state changes (CVE-2019-16871 pattern)",
            ["Write_Control", "Write"],
        ),
        (
            "Index Group/Offset boundary values",
            ["Write", "Read", "Symbol", "Boundary"],
        ),
        (
            "All 9 ADS command IDs covered",
            ["Quick_Coverage", "Coverage"],
        ),
    ],
    "hl7": [
        (
            "MLLP framing corruption",
            ["MLLP", "Corruption"],
        ),
        (
            "Oversized field buffer overflow",
            ["Oversized", "Overflow"],
        ),
        (
            "Delimiter injection in fields",
            ["Delimiter", "Injection"],
        ),
        (
            "Encoding character manipulation",
            ["Encoding", "Chars"],
        ),
        (
            "All major message types (ADT, ORU, ORM, QRY)",
            ["Quick_Coverage", "ADT", "ORU", "ORM", "Query"],
        ),
    ],
    "echo": [
        (
            "Buffer overflow with large payloads",
            ["Buffer_Overflow", "Overflow"],
        ),
        (
            "Format string injection",
            ["Format_String", "Format"],
        ),
    ],
    "daytime": [
        (
            "Buffer overflow with large payloads",
            ["Overflow"],
        ),
        (
            "Format string / boundary attacks",
            ["Boundary"],
        ),
    ],
    # ---------------------------------------------------------------------- #
    # Network/IT protocols (audit 2026-02-14)
    # ---------------------------------------------------------------------- #
    "dns": [
        (
            "Name compression pointer loops (CVE-2020-25681/25682 dnsmasq)",
            ["Compress", "Pointer", "Label", "Name"],
        ),
        (
            "EDNS0 option overflow (CVE-2020-8616/8617)",
            ["EDNS", "OPT", "Extension"],
        ),
        (
            "DNSSEC record parsing (CVE-2023-50387 KeyTrap)",
            ["DNSSEC", "DNSKEY", "RRSIG", "NSEC"],
        ),
        (
            "Overflow / boundary values in header counts",
            ["Overflow", "Boundary", "Count"],
        ),
    ],
    "mdns": [
        (
            "Standard query/response fuzzing (CVE-2015-7987 mDNSResponder)",
            ["Query", "Response", "Standard"],
        ),
        (
            "Name compression pointer handling",
            ["Compress", "Pointer", "Name"],
        ),
    ],
    "dhcp": [
        (
            "Option length overflow (CVE-2004-0460, CVE-2022-2928)",
            ["Overflow", "Option", "Length", "Boundary"],
        ),
        (
            "Vendor-specific option nesting",
            ["Vendor", "Option"],
        ),
    ],
    "http": [
        (
            "Chunked transfer encoding (smuggling vector CVE-2023-25690)",
            ["Chunk", "Transfer"],
        ),
        (
            "Header/delimiter fuzzing",
            ["Header", "Delimit", "Injection", "Duplicate"],
        ),
    ],
    "http2": [
        (
            "Rapid Reset stream cancellation (CVE-2023-44487)",
            ["Rapid", "Reset", "RST_STREAM"],
        ),
        (
            "CONTINUATION frame flood (CVE-2024-27316)",
            ["Continuation", "Flood"],
        ),
        (
            "HPACK header compression",
            ["HPACK", "Header"],
        ),
    ],
    "ftp": [
        (
            "Path traversal in filenames",
            ["Travers", "Path", "Directory"],
        ),
        (
            "AUTH/LOGIN fuzzing (pre-auth attack surface)",
            ["Auth", "Login", "USER", "PASS"],
        ),
    ],
    "smtp": [
        (
            "AUTH command fuzzing (CVE-2018-6789 Exim base64)",
            ["Auth"],
        ),
        (
            "STARTTLS / security commands",
            ["STARTTLS", "TLS", "Security"],
        ),
    ],
    "mqtt": [
        (
            "CONNECT auth bypass / overflow",
            ["Auth", "Connect", "Bypass"],
        ),
        (
            "Remaining length encoding manipulation",
            ["Remaining", "Length", "Malform"],
        ),
        (
            "Buffer overflow in topic/payload",
            ["Buffer", "Overflow", "Boundary", "Topic"],
        ),
    ],
    "coap": [
        (
            "Option parser overflow (CVE-2019-17212 Mbed OS CVSS 9.8)",
            ["Option", "Overflow", "Boundary"],
        ),
        (
            "Block transfer option fuzzing",
            ["Block", "Transfer", "Observe"],
        ),
    ],
    "ntp": [
        (
            "Control message (mode 6) overflow (CVE-2014-9295)",
            ["Control", "Mode", "Boundary"],
        ),
        (
            "Authentication / autokey crypto (CVE-2015-7691)",
            ["Auth", "Crypto", "Autokey", "MAC"],
        ),
    ],
    "tftp": [
        (
            "Filename buffer overflow (CVE-2008-1611 CVSS 10.0)",
            ["Overflow", "Filename", "Path", "Traversal"],
        ),
        (
            "Malformed opcode/packet structure",
            ["Malform", "Opcode", "Boundary"],
        ),
    ],
    "vnc": [
        (
            "Security type negotiation (CVE-2018-7225)",
            ["Auth", "Security", "Type"],
        ),
        (
            "Client message parsing (SetPixelFormat, SetEncodings)",
            ["Pixel", "Encoding", "Framebuffer", "PostAuth"],
        ),
    ],
    "snmpv1": [
        (
            "Community string overflow (classic SNMP attack)",
            ["Community", "Overflow", "Format", "256"],
        ),
        (
            "Standard SNMP operations (Get/Set/Trap)",
            ["Get", "Set", "Trap"],
        ),
    ],
    "snmpv2c": [
        (
            "GetBulk max-repetitions boundary (PROTOS pattern)",
            ["Bulk", "Repetit", "Boundary", "Extreme"],
        ),
        (
            "Malformed packet structure",
            ["Malform", "Malformed"],
        ),
    ],
}


def _request_matches_indicator(request_name: str, indicator: str) -> bool:
    """Check if a request name matches a coverage indicator (case-insensitive)."""
    return indicator.lower() in request_name.lower()


@pytest.mark.parametrize(
    "protocol_name",
    sorted(CRITICAL_FEATURE_REQUIREMENTS.keys()),
    ids=sorted(CRITICAL_FEATURE_REQUIREMENTS.keys()),
)
def test_critical_features_covered(protocol_name):
    """All critical fuzzer-relevant features have at least one covering request."""
    fuzzer_class = PROTOCOL_FUZZERS.get(protocol_name)
    if fuzzer_class is None:
        pytest.skip(f"{protocol_name} not available in PROTOCOL_FUZZERS")

    requests = fuzzer_class.get_request_definitions()
    request_names = [r.name for r in requests]

    requirements = CRITICAL_FEATURE_REQUIREMENTS[protocol_name]
    uncovered = []

    for feature_desc, indicators in requirements:
        # A feature is covered if ANY request name matches ANY indicator
        covered = False
        for req_name in request_names:
            for indicator in indicators:
                if _request_matches_indicator(req_name, indicator):
                    covered = True
                    break
            if covered:
                break

        if not covered:
            uncovered.append(f"  - {feature_desc} (looked for: {indicators} in {request_names})")

    assert not uncovered, (
        f"{protocol_name}: {len(uncovered)} critical feature(s) not covered:\n"
        + "\n".join(uncovered)
    )


@pytest.mark.parametrize(
    "protocol_name",
    sorted(CRITICAL_FEATURE_REQUIREMENTS.keys()),
    ids=sorted(CRITICAL_FEATURE_REQUIREMENTS.keys()),
)
def test_no_empty_request_list(protocol_name):
    """Protocol fuzzers must have at least one request definition."""
    fuzzer_class = PROTOCOL_FUZZERS.get(protocol_name)
    if fuzzer_class is None:
        pytest.skip(f"{protocol_name} not available in PROTOCOL_FUZZERS")

    requests = fuzzer_class.get_request_definitions()
    assert len(requests) > 0, (
        f"{protocol_name}: get_request_definitions() returned empty list. "
        f"This is a zero-score protocol."
    )


# ---------------------------------------------------------------------- #
# Protocol-specific critical checks (network/IT audit 2026-02-14)
# ---------------------------------------------------------------------- #


class TestDNSCritical:
    """DNS has 64 requests and should cover all major record types."""

    def test_dns_covers_standard_query_types(self):
        fuzzer_class = PROTOCOL_FUZZERS.get("dns")
        if fuzzer_class is None:
            pytest.skip("dns not available")

        requests = fuzzer_class.get_request_definitions()
        names = [r.name.lower() for r in requests]

        # Map conceptual types to actual request name patterns
        expected_types = {
            "A": ["dns_a_", "_a_query"],
            "AAAA": ["aaaa"],
            "MX": ["mx"],
            "PTR": ["ptr"],
            "TXT": ["txt"],
            "SRV": ["srv"],
        }
        for qtype, patterns in expected_types.items():
            found = any(any(p in n for p in patterns) for n in names)
            assert found, (
                f"DNS fuzzer missing query type: {qtype} "
                f"(searched for {patterns}). "
                f"Standard query types must all be covered."
            )

    def test_dns_covers_dnssec(self):
        fuzzer_class = PROTOCOL_FUZZERS.get("dns")
        if fuzzer_class is None:
            pytest.skip("dns not available")

        requests = fuzzer_class.get_request_definitions()
        names = [r.name.lower() for r in requests]
        dnssec_keywords = ["dnskey", "rrsig", "nsec"]
        found = any(any(kw in n for kw in dnssec_keywords) for n in names)
        assert found, "DNS fuzzer should cover DNSSEC record types"


class TestHTTP2Critical:
    """HTTP/2 must cover rapid reset and CONTINUATION flood."""

    def test_http2_rapid_reset(self):
        fuzzer_class = PROTOCOL_FUZZERS.get("http2")
        if fuzzer_class is None:
            pytest.skip("http2 not available")

        requests = fuzzer_class.get_request_definitions()
        names = [r.name.lower() for r in requests]
        found = any("rapid" in n or "reset" in n for n in names)
        assert found, (
            "HTTP/2 must cover Rapid Reset (CVE-2023-44487). "
            f"Requests: {[r.name for r in requests]}"
        )

    def test_http2_continuation(self):
        fuzzer_class = PROTOCOL_FUZZERS.get("http2")
        if fuzzer_class is None:
            pytest.skip("http2 not available")

        requests = fuzzer_class.get_request_definitions()
        names = [r.name.lower() for r in requests]
        found = any("continuation" in n for n in names)
        assert found, (
            "HTTP/2 must cover CONTINUATION flood (CVE-2024-27316). "
            f"Requests: {[r.name for r in requests]}"
        )


class TestMQTTCritical:
    """MQTT is stateful and must cover pre-auth and post-auth."""

    def test_mqtt_has_auth_category(self):
        fuzzer_class = PROTOCOL_FUZZERS.get("mqtt")
        if fuzzer_class is None:
            pytest.skip("mqtt not available")

        requests = fuzzer_class.get_request_definitions()
        cats = {r.category for r in requests}
        assert "auth" in cats, "MQTT must have auth category"

    def test_mqtt_has_boundary_category(self):
        fuzzer_class = PROTOCOL_FUZZERS.get("mqtt")
        if fuzzer_class is None:
            pytest.skip("mqtt not available")

        requests = fuzzer_class.get_request_definitions()
        cats = {r.category for r in requests}
        assert "boundary" in cats, "MQTT must have boundary category"


class TestSNMPCritical:
    """All SNMP versions should have core operations."""

    def test_snmpv1_has_get_request(self):
        fuzzer_class = PROTOCOL_FUZZERS.get("snmpv1")
        if fuzzer_class is None:
            pytest.skip("snmpv1 not available")

        requests = fuzzer_class.get_request_definitions()
        names = [r.name.lower() for r in requests]
        found = any("get" in n for n in names)
        assert found, "SNMPv1 must have GetRequest"

    def test_snmpv1_has_set_request(self):
        fuzzer_class = PROTOCOL_FUZZERS.get("snmpv1")
        if fuzzer_class is None:
            pytest.skip("snmpv1 not available")

        requests = fuzzer_class.get_request_definitions()
        names = [r.name.lower() for r in requests]
        found = any("set" in n for n in names)
        assert found, "SNMPv1 must have SetRequest"

    def test_snmpv2c_has_getbulk(self):
        fuzzer_class = PROTOCOL_FUZZERS.get("snmpv2c")
        if fuzzer_class is None:
            pytest.skip("snmpv2c not available")

        requests = fuzzer_class.get_request_definitions()
        names = [r.name.lower() for r in requests]
        found = any("bulk" in n or "getbulk" in n for n in names)
        assert found, "SNMPv2c must have GetBulkRequest"


class TestLengthFieldCoverage:
    """Protocols with length fields must have overflow/boundary requests.

    Length field manipulation is the #1 vulnerability pattern in protocol parsing.
    """

    LENGTH_FIELD_PROTOCOLS = {
        "dns": ["overflow", "boundary", "length", "count"],
        "dhcp": ["overflow", "length", "option"],
        "http2": ["overflow", "boundary", "length", "frame"],
        "mqtt": ["overflow", "boundary", "length", "remaining"],
        "coap": ["overflow", "boundary", "option"],
        "ntp": ["overflow", "boundary"],
        "snmpv1": ["high_crash", "overflow", "256"],
        "snmpv2c": ["high_crash", "boundary", "extreme"],
    }

    @pytest.mark.parametrize(
        "protocol_name,keywords",
        sorted(LENGTH_FIELD_PROTOCOLS.items()),
        ids=sorted(LENGTH_FIELD_PROTOCOLS.keys()),
    )
    def test_length_field_overflow_coverage(self, protocol_name, keywords):
        """Protocol must have at least one overflow/boundary request."""
        fuzzer_class = PROTOCOL_FUZZERS.get(protocol_name)
        if fuzzer_class is None:
            pytest.skip(f"{protocol_name} not available")

        requests = fuzzer_class.get_request_definitions()
        names = [r.name.lower() for r in requests]
        cats = [r.category.lower() for r in requests]
        all_text = names + cats

        covered = any(any(kw in text for kw in keywords) for text in all_text)
        assert covered, (
            f"{protocol_name}: no length field overflow/boundary testing found. "
            f"Searched for keywords: {keywords}. "
            f"Request names: {[r.name for r in requests]}"
        )


# ---------------------------------------------------------------------- #
# Transport & network-layer CVE coverage (audit 2026-02-14)
# ---------------------------------------------------------------------- #

# CVE coverage maps: CVE desc -> list of substrings in request names
IPV4_CVE_COVERAGE = {
    "CVE-2020-11896 (Ripple20 fragment RCE)": [
        "Ripple20",
        "Fragment",
        "fragment",
    ],
    "CVE-2021-24086 (fragment reassembly DoS)": [
        "Fragment",
        "fragment",
    ],
    "CVE-2018-5391 (FragmentSmack)": [
        "Fragment",
        "fragment",
    ],
    "CVE-1999-0016 (Teardrop)": [
        "Fragment",
        "fragment",
        "Teardrop",
    ],
    "CVE-2024-20467 (Cisco IOS XE fragment)": [
        "Fragment",
        "fragment",
    ],
}

ICMP_CVE_COVERAGE = {
    "CVE-2018-4407 (ICMP/TCP options heap overflow)": [
        "Overflow",
        "Oversized",
        "overflow",
    ],
    "CVE-2023-23415 (ICMP error with embedded IP)": [
        "Extension",
        "extension",
        "Dest_Unreachable",
    ],
}

ICMPV6_CVE_COVERAGE = {
    "CVE-2020-16898 (Bad Neighbor, CVSS 9.8)": [
        "Bad_Neighbor",
        "RDNSS",
    ],
    "CVE-2020-16899 (RA DoS)": [
        "Bad_Neighbor",
        "Router_Advertisement",
        "RDNSS",
    ],
    "CVE-2024-38063 (Windows IPv6 RCE, CVSS 9.8)": [
        "Windows_IPv6",
        "CVE_2024",
    ],
    "CVE-2023-32154 (MikroTik RDNSS)": [
        "MikroTik",
        "RDNSS",
    ],
}

TCP_CVE_COVERAGE = {
    "CVE-2020-13987 (Checksum OOB read)": [
        "CVE_2020_13987",
        "Checksum",
    ],
    "CVE-2020-17437 (Urgent pointer no bounds)": [
        "CVE_2020_17437",
        "Urgent",
    ],
    "CVE-2021-31401 (Header overflow)": [
        "CVE_2021_31401",
        "Header_Overflow",
    ],
}

TRANSPORT_CVE_MAPS = {
    "ipv4": IPV4_CVE_COVERAGE,
    "icmp": ICMP_CVE_COVERAGE,
    "icmpv6": ICMPV6_CVE_COVERAGE,
    "tcp": TCP_CVE_COVERAGE,
}


def _build_transport_cve_params():
    """Build parametrize params for transport CVE tests."""
    params = []
    ids = []
    for proto, cve_map in sorted(TRANSPORT_CVE_MAPS.items()):
        for cve_desc, substrings in sorted(cve_map.items()):
            cve_id = cve_desc.split(" ")[0]
            params.append((proto, cve_desc, substrings))
            ids.append(f"{proto}-{cve_id}")
    return params, ids


_transport_cve_params, _transport_cve_ids = _build_transport_cve_params()


@pytest.mark.parametrize(
    "protocol_name,cve_desc,substrings",
    _transport_cve_params,
    ids=_transport_cve_ids,
)
def test_transport_cve_covered(protocol_name, cve_desc, substrings):
    """Transport/network fuzzer covers wire-level CVE pattern."""
    fuzzer_class = PROTOCOL_FUZZERS.get(protocol_name)
    if fuzzer_class is None:
        pytest.skip(f"{protocol_name} not available")

    requests = fuzzer_class.get_request_definitions()
    request_names = [r.name for r in requests]

    covered = any(
        any(_request_matches_indicator(rname, sub) for sub in substrings) for rname in request_names
    )
    assert covered, (
        f"{protocol_name}: {cve_desc} not covered by any request. "
        f"Expected one of {substrings} in request names. "
        f"Found: {request_names}"
    )
