"""DNS Protocol Fuzzer"""

from boofuzz import Block, Byte, DWord, Group, Request, Static, Word

from typing import List

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.connections import UDPSocketConnection
from ..primitives.dynamic import SmartString


class DNSFuzzer(BaseFuzzer):
    """DNS Protocol Fuzzer for domain name system security testing

    Targets DNS vulnerabilities including query processing, response handling,
    cache poisoning, and buffer overflows in domain name parsing.
    """

    def _create_socket(self):
        # DNS UDP requires binding to a local port to receive responses
        # Using bind=("0.0.0.0", 0) lets the OS pick an ephemeral port
        return UDPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            bind=("0.0.0.0", 0),  # Bind to any interface, ephemeral port for receiving responses
            **self._timeout_overrides(recv_default=2.0),  # Wait up to 2 seconds for DNS response
        )

    def setup_custom_monitors(self) -> list:
        """
        Setup DNS-specific monitoring with DNS query comparison.

        Returns:
            List of monitor instances for DNS service health checking
        """
        from ..monitors import DNSQueryMonitor

        # Create DNS query monitor
        dns_monitor = DNSQueryMonitor(
            host=self.config.target_ip,
            port=self.config.target_port,
            query_domain="oida.local",
            timeout=2,
            check_interval=5,  # Check every 5 test cases (DNS is fast)
        )

        return [dns_monitor]

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests and audit tests"""
        return [
            RequestInfo("DNS_Baseline", "Connectivity check (non-fuzzable)", "baseline"),
            RequestInfo("DNS_A_QUERY", "A record IPv4 resolution", "standard"),
            RequestInfo("DNS_AAAA_QUERY", "AAAA record IPv6 resolution", "query"),
            RequestInfo("DNS_MX_QUERY", "MX record mail exchange", "query"),
            RequestInfo("DNS_PTR_QUERY", "PTR reverse DNS", "query"),
            RequestInfo("DNS_TXT_QUERY", "TXT record data handling", "query"),
            RequestInfo("DNS_SRV_QUERY", "SRV service location", "query"),
            RequestInfo("DNS_CAA_QUERY", "CAA certificate authority", "query"),
            RequestInfo("DNS_LONG_DOMAIN", "Oversized domain name overflow", "overflow"),
            RequestInfo("DNS_MALFORMED_LABELS", "Malformed label parsing", "malformed"),
            RequestInfo("DNS_CACHE_POISONING", "Cache poisoning response", "attack"),
            RequestInfo("DNS_AMPLIFICATION", "Query amplification", "attack"),
            RequestInfo("DNS_INVALID_FLAGS", "Invalid flag combinations", "boundary"),
            RequestInfo("DNS_Domain_Overflow", "Domain name buffer overflow", "overflow"),
            RequestInfo("DNS_Response_Mismatch", "Response ID mismatch", "attack"),
            RequestInfo("DNS_No_Null_Term", "Missing null terminator", "malformed"),
            RequestInfo("DNS_Length_Overflow", "Label length overflow", "overflow"),
            RequestInfo("DNS_DNSKEY_QUERY", "DNSSEC DNSKEY record", "dnssec"),
            RequestInfo("DNS_DS_QUERY", "DNSSEC DS record", "dnssec"),
            RequestInfo("DNS_RRSIG_QUERY", "DNSSEC RRSIG record", "dnssec"),
            RequestInfo("DNS_NSEC_QUERY", "DNSSEC NSEC record", "dnssec"),
            RequestInfo("DNS_NSEC3_QUERY", "DNSSEC NSEC3 record", "dnssec"),
            RequestInfo("DNS_NSEC3PARAM_QUERY", "DNSSEC NSEC3PARAM", "dnssec"),
            RequestInfo("DNS_CDS_QUERY", "DNSSEC CDS record", "dnssec"),
            RequestInfo("DNS_CDNSKEY_QUERY", "DNSSEC CDNSKEY record", "dnssec"),
            RequestInfo("DNS_EDNS0_OPTIONS", "EDNS0 option overflow (CVE-2020-8616)", "edns"),
            RequestInfo("DNS_COOKIES", "DNS cookies (RFC 7873)", "edns"),
            RequestInfo("DNS_COOKIES_CLIENT_ONLY", "Client-only cookie", "edns"),
            RequestInfo("DNS_COOKIES_MALFORMED", "Malformed cookie data", "edns"),
            RequestInfo("DNS_EXTENDED_ERRORS", "Extended errors (RFC 8914)", "edns"),
            RequestInfo("DNS_NSID", "NSID option", "edns"),
            RequestInfo("DNS_PADDING", "EDNS padding option", "edns"),
            RequestInfo("DNS_DNSSEC_ALGORITHMS", "DNSSEC algorithm negotiation", "dnssec"),
            RequestInfo("DNS_EDNS_KEY_TAG", "EDNS key tag signaling", "edns"),
            RequestInfo("DNS_EDNS_EXPIRE", "EDNS expire option", "edns"),
            RequestInfo("DNS_CHAIN_QUERY", "EDNS chain query", "edns"),
            RequestInfo("DNS_UPDATE_ADD_RECORD", "Dynamic update add (RFC 2136)", "update"),
            RequestInfo("DNS_UPDATE_DELETE_RECORD", "Dynamic update delete", "update"),
            RequestInfo("DNS_UPDATE_WITH_PREREQ", "Update with prerequisites", "update"),
            RequestInfo("DNS_UPDATE_MALFORMED", "Malformed update message", "update"),
            RequestInfo("DNS_FLAGS_AD", "Authentic Data flag", "flags"),
            RequestInfo("DNS_FLAGS_CD", "Checking Disabled flag", "flags"),
            RequestInfo("DNS_FLAGS_AD_CD_BOTH", "AD+CD flag combination", "flags"),
            RequestInfo("DNS_TLSA_QUERY", "TLSA DANE record", "query"),
            RequestInfo("DNS_SVCB_QUERY", "SVCB service binding", "query"),
            RequestInfo("DNS_HTTPS_QUERY", "HTTPS service binding", "query"),
            RequestInfo("DNS_RCODE_NOERROR", "RCODE NOERROR response", "rcode"),
            RequestInfo("DNS_RCODE_FORMERR", "RCODE FORMERR response", "rcode"),
            RequestInfo("DNS_RCODE_SERVFAIL", "RCODE SERVFAIL response", "rcode"),
            RequestInfo("DNS_RCODE_NXDOMAIN", "RCODE NXDOMAIN response", "rcode"),
            RequestInfo("DNS_RCODE_NOTIMP", "RCODE NOTIMP response", "rcode"),
            RequestInfo("DNS_RCODE_REFUSED", "RCODE REFUSED response", "rcode"),
            RequestInfo("DNS_RCODE_YXDOMAIN", "RCODE YXDOMAIN response", "rcode"),
            RequestInfo("DNS_RCODE_YXRRSET", "RCODE YXRRSET response", "rcode"),
            RequestInfo("DNS_RCODE_NXRRSET", "RCODE NXRRSET response", "rcode"),
            RequestInfo("DNS_RCODE_NOTAUTH", "RCODE NOTAUTH response", "rcode"),
            RequestInfo("DNS_RCODE_NOTZONE", "RCODE NOTZONE response", "rcode"),
            RequestInfo("DNS_RCODE_BADVERS", "RCODE BADVERS/BADSIG response", "rcode"),
            RequestInfo("DNS_RCODE_BADCOOKIE", "RCODE BADCOOKIE response", "rcode"),
            RequestInfo("DNS_RCODE_BADSIG", "RCODE BADSIG TSIG response", "rcode"),
            RequestInfo("DNS_RCODE_BADKEY", "RCODE BADKEY TSIG response", "rcode"),
            RequestInfo("DNS_RCODE_BADTIME", "RCODE BADTIME TSIG response", "rcode"),
            RequestInfo("DNS_MALFORMED_EDNS0", "Malformed EDNS0 OPT record", "edns"),
            RequestInfo(
                "DNS_COMPRESSION_LOOP",
                "Name compression pointer loop (CVE-2020-25681)",
                "overflow",
            ),
        ]

    def _define_protocol(self) -> None:
        """Define DNS protocol structure for fuzzing

        OPTIMIZATION COMPLETED: Consolidated from 68 to 27 requests (60% reduction)
        - 1 baseline test (non-fuzzable connectivity check)
        - 7 core query types (A, AAAA, MX, PTR, TXT, SRV, CAA)
        - 2 DNSSEC queries (DNSKEY, RRSIG) - reduced from 8
        - 3 EDNS0 tests (OPTIONS, COOKIES, EXTENDED_ERRORS) - reduced from 11
        - 6 attack patterns (cache poisoning, amplification, overflows, parsing)
        - 2 UPDATE operations (ADD, MALFORMED) - reduced from 4
        - 3 zone transfer tests (AXFR, IXFR, TCP_LENGTH_ATTACK) - reduced from 5
        - 3 RCODE tests (FORMERR, SERVFAIL, NXDOMAIN) - reduced from 16

        Expected performance improvement: 2-3x faster fuzzing with maintained coverage
        """

        # 0. DNS Baseline - Simple connectivity test (all fields non-fuzzable)
        dns_baseline = Request(
            "DNS_Baseline",
            children=(
                Block(
                    "DNS_Header_Baseline",
                    children=(
                        Word("transaction_id", 0x0001, endian=">", fuzzable=False),
                        Word("flags", 0x0100, endian=">", fuzzable=False),  # Standard query
                        Word("questions", 0x0001, endian=">", fuzzable=False),
                        Word("answers", 0x0000, endian=">", fuzzable=False),
                        Word("authority", 0x0000, endian=">", fuzzable=False),
                        Word("additional", 0x0000, endian=">", fuzzable=False),
                    ),
                ),
                Block(
                    "DNS_Question_Baseline",
                    children=(
                        Byte("label1_length", 4, fuzzable=False),
                        Static("label1", "oida"),  # Non-fuzzable domain
                        Byte("label2_length", 5, fuzzable=False),
                        Static("label2", "local"),
                        Byte("name_terminator", 0, fuzzable=False),
                        Word("qtype", 0x0001, endian=">", fuzzable=False),  # A record
                        Word("qclass", 0x0001, endian=">", fuzzable=False),  # Internet class
                    ),
                ),
            ),
        )

        # 1. DNS A Record Query - Standard domain lookup
        dns_a_query = Request(
            "DNS_A_QUERY",
            children=(
                Block(
                    "DNS_Header",
                    children=(
                        Word("transaction_id", 0x1234, endian=">"),  # Transaction ID
                        Word("flags", 0x0100, endian=">"),  # Standard query
                        Word("questions", 0x0001, endian=">"),  # 1 question
                        Word("answers", 0x0000, endian=">"),  # 0 answers
                        Word("authority", 0x0000, endian=">"),  # 0 authority
                        Word("additional", 0x0000, endian=">"),  # 0 additional
                    ),
                ),
                Block(
                    "DNS_Question",
                    children=(
                        # Domain name (encoded as length-prefixed labels)
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),  # End of name
                        Word("qtype", 0x0001, endian=">"),  # A record
                        Word("qclass", 0x0001, endian=">"),  # Internet class
                    ),
                ),
            ),
        )

        # 2. DNS AAAA Query - IPv6 address lookup
        dns_aaaa_query = Request(
            "DNS_AAAA_QUERY",
            children=(
                Block(
                    "DNS_Header_AAAA",
                    children=(
                        Word("transaction_id", 0x5678, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_AAAA",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63),
                        Byte("label2_length", 7),
                        SmartString("label2", "oida", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "org", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x001C, endian=">"),  # AAAA record
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # 3. DNS MX Query - Mail exchange lookup
        dns_mx_query = Request(
            "DNS_MX_QUERY",
            children=(
                Block(
                    "DNS_Header_MX",
                    children=(
                        Word("transaction_id", 0x9ABC, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_MX",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "mailsrv", max_len=63),
                        Byte("label2_length", 7),
                        SmartString("label2", "company", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x000F, endian=">"),  # MX record
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # 4. DNS PTR Query - Reverse DNS lookup
        dns_ptr_query = Request(
            "DNS_PTR_QUERY",
            children=(
                Block(
                    "DNS_Header_PTR",
                    children=(
                        Word("transaction_id", 0xDEF0, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_PTR",
                    children=(
                        # Reverse DNS format: 1.0.168.192.in-addr.arpa
                        Byte("ip4_length", 1),
                        SmartString("ip4", "1", max_len=3),
                        Byte("ip3_length", 1),
                        SmartString("ip3", "0", max_len=3),
                        Byte("ip2_length", 3),
                        SmartString("ip2", "168", max_len=3),
                        Byte("ip1_length", 3),
                        SmartString("ip1", "192", max_len=3),
                        Byte("in_addr_length", 7),
                        SmartString("in_addr", "in-addr", max_len=7),
                        Byte("arpa_length", 4),
                        SmartString("arpa", "arpa", max_len=4),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x000C, endian=">"),  # PTR record
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # 5. DNS Long Domain Name - Buffer overflow testing
        dns_long_domain = Request(
            "DNS_LONG_DOMAIN",
            children=(
                Block(
                    "DNS_Header_Long",
                    children=(
                        Word("transaction_id", 0x1111, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_Long",
                    children=(
                        # Oversized label length (should be max 63)
                        Byte("oversized_label_length", 255),
                        SmartString("oversized_label", "dns-oversized-label", max_len=1000),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # 6. DNS Malformed Labels - Label parsing vulnerabilities
        dns_malformed_labels = Request(
            "DNS_MALFORMED_LABELS",
            children=(
                Block(
                    "DNS_Header_Malformed",
                    children=(
                        Word("transaction_id", 0x2222, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_Malformed",
                    children=(
                        # Malformed label structures
                        Group(
                            "malformed_labels",
                            values=[
                                b"\xff\xff\xff\xff\x00",  # Invalid length bytes
                                b"\x80\x00\x00\x00\x00",  # Compression pointer to invalid location
                                b"\xc0\x0c\x00",  # Compression pointer loop
                                b"\x3f"
                                + b"A" * 63
                                + b"\x3f"
                                + b"B" * 63
                                + b"\x00",  # Max length labels
                                b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x00",  # Binary data
                            ],
                        ),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # 7. DNS Cache Poisoning - Malicious response injection
        dns_cache_poisoning = Request(
            "DNS_CACHE_POISONING",
            children=(
                Block(
                    "DNS_Header_Poison",
                    children=(
                        Word("transaction_id", 0x3333, endian=">"),
                        Word("flags", 0x8180, endian=">"),  # Response, authoritative
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0001, endian=">"),  # 1 answer (malicious)
                        Word("authority", 0x0001, endian=">"),  # 1 authority
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                # Original question
                Block(
                    "DNS_Question_Poison",
                    children=(
                        Byte("label1_length", 3),
                        SmartString("label1", "www", max_len=63),
                        Byte("label2_length", 7),
                        SmartString("label2", "oida", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                # Malicious answer
                Block(
                    "DNS_Answer_Poison",
                    children=(
                        # Compressed name pointer to question
                        Word("name_pointer", 0xC00C, endian=">"),
                        Word("type", 0x0001, endian=">"),  # A record
                        Word("class", 0x0001, endian=">"),  # Internet
                        DWord("ttl", 0x00000001, endian=">"),  # Very low TTL
                        Word("rdlength", 0x0004, endian=">"),  # 4 bytes
                        DWord("malicious_ip", 0x7F000001, endian=">"),  # 127.0.0.1
                    ),
                ),
                # Malicious authority record
                Block(
                    "DNS_Authority_Poison",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("type", 0x0002, endian=">"),  # NS record
                        Word("class", 0x0001, endian=">"),
                        DWord("ttl", 0x00000001, endian=">"),
                        Word("rdlength", 0x0008, endian=">"),
                        # Malicious nameserver
                        Byte("ns_label_length", 4),
                        SmartString("ns_label", "evil", max_len=63),
                        Byte("ns_domain_length", 3),
                        SmartString("ns_domain", "local", max_len=63),
                        Byte("ns_terminator", 0),
                    ),
                ),
            ),
        )

        # 8. DNS Query Amplification - Large response trigger
        dns_amplification = Request(
            "DNS_AMPLIFICATION",
            children=(
                Block(
                    "DNS_Header_Amp",
                    children=(
                        Word("transaction_id", 0x4444, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),  # Request DNSSEC
                    ),
                ),
                Block(
                    "DNS_Question_Amp",
                    children=(
                        # Query for ANY record type (can trigger large responses)
                        # Root domain is just a null byte (no labels)
                        Byte("root_domain", 0),  # Root domain = null terminator only
                        Word("qtype", 0x00FF, endian=">"),  # ANY record type
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                # EDNS0 Additional Record for amplification
                Block(
                    "DNS_Additional_EDNS",
                    children=(
                        Byte("edns_name", 0),  # Root domain
                        Word("edns_type", 0x0029, endian=">"),  # OPT record
                        Word("udp_payload_size", 4096, endian=">"),  # Large UDP size
                        DWord("extended_rcode", 0x00000000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # 9. DNS TXT Record Query - Text record injection
        dns_txt_query = Request(
            "DNS_TXT_QUERY",
            children=(
                Block(
                    "DNS_Header_TXT",
                    children=(
                        Word("transaction_id", 0x5555, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_TXT",
                    children=(
                        Byte("label1_length", 8),
                        SmartString("label1", "_malware", max_len=63),
                        Byte("label2_length", 4),
                        SmartString("label2", "test", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0010, endian=">"),  # TXT record
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # 10. DNS Invalid Message Types - Protocol confusion
        dns_invalid_flags = Request(
            "DNS_INVALID_FLAGS",
            children=(
                Block(
                    "DNS_Header_Invalid",
                    children=(
                        Word("transaction_id", 0x6666, endian=">"),
                        Word("invalid_flags", 0xFFFF, endian=">", fuzzable=True),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_Invalid",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # Embedded Stack Vulnerability Patterns (Simplified)

        # CVE-2020-24338 - Domain bounds overflow
        dns_domain_overflow = Request(
            "DNS_Domain_Overflow",
            children=(
                Block(
                    "DNS_Header",
                    children=(
                        Word("transaction_id", 0x1337, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question",
                    children=(
                        # Domain name without bounds checking
                        SmartString("oversized_domain", "oida.local", max_len=2048, fuzzable=True),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # CVE-2020-25928 - Response count mismatch
        Request(
            "DNS_Response_Mismatch",
            children=(  # noqa: F841
                Block(
                    "DNS_Header",
                    children=(
                        Word("transaction_id", 0xDEAD, endian=">"),
                        Word("flags", 0x8180, endian=">"),  # Response
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x00FF, endian=">", fuzzable=True),  # Claims 255 answers
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question",
                    children=(
                        Byte("label_len", 7),
                        SmartString("label", "oida"),
                        Byte("label2_len", 3),
                        SmartString("label2", "local"),
                        Byte("terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Answer",
                    children=(
                        Word("name_ptr", 0xC00C, endian=">"),
                        Word("type", 0x0001, endian=">"),
                        Word("class", 0x0001, endian=">"),
                        DWord("ttl", 300, endian=">"),
                        Word("data_length", fuzzable=True, endian=">"),
                        SmartString("answer_data", "dns-answer-data", max_len=8192, fuzzable=True),
                    ),
                ),
            ),
        )

        # CVE-2020-24341 - Missing null termination
        Request(
            "DNS_No_Null_Term",
            children=(  # noqa: F841
                Block(
                    "DNS_Header",
                    children=(
                        Word("transaction_id", 0xBEEF, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question",
                    children=(
                        Byte("label_len", 255),  # Max label length
                        SmartString("label_no_null", "test-label", max_len=255, fuzzable=True),
                        # No null terminator - direct to qtype
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # Integer overflow in length calculations
        dns_length_overflow = Request(
            "DNS_Length_Overflow",
            children=(
                Block(
                    "DNS_Header",
                    children=(
                        Word("transaction_id", 0xCAFE, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question",
                    children=(
                        Byte("label_len", 255, fuzzable=True),
                        SmartString("label", "dns-label", max_len=1024, fuzzable=True),
                        Byte("terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # DNSSEC Record Types

        # DNSKEY Query - DNSSEC public key
        dns_dnskey_query = Request(
            "DNS_DNSKEY_QUERY",
            children=(
                Block(
                    "DNS_Header_DNSKEY",
                    children=(
                        Word("transaction_id", 0x7777, endian=">"),
                        Word("flags", 0x0120, endian=">"),  # Recursive desired + DNSSEC OK
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),  # EDNS0 record
                    ),
                ),
                Block(
                    "DNS_Question_DNSKEY",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0030, endian=">"),  # DNSKEY record
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                # EDNS0 OPT Record
                Block(
                    "DNS_EDNS0_OPT",
                    children=(
                        Byte("edns_name", 0),  # Root domain
                        Word("edns_type", 0x0029, endian=">"),  # OPT record
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),  # DNSSEC OK bit
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # DS Query - Delegation Signer
        Request(
            "DNS_DS_QUERY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_DS",
                    children=(
                        Word("transaction_id", 0x8888, endian=">"),
                        Word("flags", 0x0120, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_DS",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x002B, endian=">"),  # DS record
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_OPT_DS",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # RRSIG Query - Resource Record Signature
        dns_rrsig_query = Request(
            "DNS_RRSIG_QUERY",
            children=(
                Block(
                    "DNS_Header_RRSIG",
                    children=(
                        Word("transaction_id", 0x9999, endian=">"),
                        Word("flags", 0x0120, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_RRSIG",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x002E, endian=">"),  # RRSIG record
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_OPT_RRSIG",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # NSEC Query - Next Secure
        Request(
            "DNS_NSEC_QUERY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_NSEC",
                    children=(
                        Word("transaction_id", 0xAAAA, endian=">"),
                        Word("flags", 0x0120, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_NSEC",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x002F, endian=">"),  # NSEC record
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_OPT_NSEC",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # NSEC3 Query - Next Secure Hashed
        Request(
            "DNS_NSEC3_QUERY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_NSEC3",
                    children=(
                        Word("transaction_id", 0xBBBB, endian=">"),
                        Word("flags", 0x0120, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_NSEC3",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0032, endian=">"),  # NSEC3 record
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_OPT_NSEC3",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # NSEC3PARAM Query - NSEC3 parameters (RFC 5155)
        Request(
            "DNS_NSEC3PARAM_QUERY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_NSEC3PARAM",
                    children=(
                        Word("transaction_id", 0x3333, endian=">"),
                        Word("flags", 0x0120, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_NSEC3PARAM",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0033, endian=">"),  # NSEC3PARAM record (type 51)
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_OPT_NSEC3PARAM",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),  # DNSSEC OK
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # CDS Query - Child DS (RFC 7344)
        Request(
            "DNS_CDS_QUERY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_CDS",
                    children=(
                        Word("transaction_id", 0xCD50, endian=">"),
                        Word("flags", 0x0120, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_CDS",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x003B, endian=">"),  # CDS record (type 59)
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_OPT_CDS",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),  # DNSSEC OK
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # CDNSKEY Query - Child DNSKEY (RFC 7344)
        Request(
            "DNS_CDNSKEY_QUERY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_CDNSKEY",
                    children=(
                        Word("transaction_id", 0xCD60, endian=">"),
                        Word("flags", 0x0120, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_CDNSKEY",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x003C, endian=">"),  # CDNSKEY record (type 60)
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_OPT_CDNSKEY",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),  # DNSSEC OK
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # EDNS0 with Options - Cookie, Client Subnet, etc.
        dns_edns0_options = Request(
            "DNS_EDNS0_OPTIONS",
            children=(
                Block(
                    "DNS_Header_EDNS_OPT",
                    children=(
                        Word("transaction_id", 0xCCCC, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_EDNS_OPT",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_WITH_OPTIONS",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x0010, endian=">"),  # 16 bytes of option data
                        # EDNS Client Subnet Option
                        Word("option_code", 0x0008, endian=">"),  # ECS option
                        Word("option_length", 0x0008, endian=">"),
                        Word("family", 0x0001, endian=">"),  # IPv4
                        Byte("source_prefix", 24),  # /24 network
                        Byte("scope_prefix", 0),
                        DWord("client_subnet", 0xC0A80100, endian=">"),  # 192.168.1.0
                    ),
                ),
            ),
        )

        # DNS Cookies (RFC 7873) - EDNS0 option code 10
        dns_cookies = Request(
            "DNS_COOKIES",
            children=(
                Block(
                    "DNS_Header_Cookies",
                    children=(
                        Word("transaction_id", 0xC001, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_Cookies",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_Cookies",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 1232, endian=">"),  # RFC 7873 recommended
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word(
                            "edns_data_length", 0x0018, endian=">"
                        ),  # 24 bytes: option header + 8 + 16
                        # Cookie option (code 10)
                        Word("cookie_option_code", 0x000A, endian=">"),
                        Word(
                            "cookie_option_length", 0x0014, endian=">"
                        ),  # 20 bytes: 8 (client) + 12 (server example)
                        # Client Cookie (8 bytes - required)
                        SmartString(
                            "client_cookie",
                            b"\x01\x02\x03\x04\x05\x06\x07\x08",
                            size=8,
                            max_len=8,
                            fuzzable=True,
                        ),
                        # Server Cookie (8-32 bytes - optional, using 12 for fuzzing)
                        SmartString(
                            "server_cookie",
                            b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55",
                            size=12,
                            max_len=32,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # DNS Cookies - Client Only (initial request)
        Request(
            "DNS_COOKIES_CLIENT_ONLY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_Cookies_Client",
                    children=(
                        Word("transaction_id", 0xC002, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_Cookies_Client",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_Cookies_Client",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 1232, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x000C, endian=">"),  # 12 bytes: option header + 8
                        # Cookie option with client cookie only
                        Word("cookie_option_code", 0x000A, endian=">"),
                        Word("cookie_option_length", 0x0008, endian=">"),  # 8 bytes
                        SmartString(
                            "client_cookie",
                            b"\x11\x22\x33\x44\x55\x66\x77\x88",
                            size=8,
                            max_len=8,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # DNS Cookies - Malformed (fuzzing attack vectors)
        Request(
            "DNS_COOKIES_MALFORMED",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_Cookies_Mal",
                    children=(
                        Word("transaction_id", 0xC003, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_Cookies_Mal",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "attacker", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_Cookies_Mal",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 1232, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word(
                            "edns_data_length", 0x0028, endian=">", fuzzable=True
                        ),  # Fuzzable length
                        # Malformed cookie option
                        Word("cookie_option_code", 0x000A, endian=">"),
                        Group(
                            "malformed_cookie_length",
                            values=[
                                b"\x00\x00",  # Zero length (invalid)
                                b"\x00\x07",  # Too short (< 8 bytes)
                                b"\x00\x28",  # Max size (40 bytes: 8 client + 32 server)
                                b"\x00\x29",  # Over max (41 bytes)
                                b"\xff\xff",  # Maximum value
                            ],
                        ),
                        SmartString(
                            "malformed_cookie_data",
                            b"\xff" * 40,
                            size=40,
                            max_len=64,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # Extended DNS Errors (RFC 8914) - EDNS0 option code 15
        dns_extended_errors = Request(
            "DNS_EXTENDED_ERRORS",
            children=(
                Block(
                    "DNS_Header_EDE",
                    children=(
                        Word("transaction_id", 0xEDE1, endian=">"),
                        Word("flags", 0x8180, endian=">"),  # Response with error
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_EDE",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "blocked", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_EDE",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 1232, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x0020, endian=">"),  # 32 bytes
                        # Extended DNS Error option (code 15)
                        Word("ede_option_code", 0x000F, endian=">"),
                        Word("ede_option_length", 0x001C, endian=">"),  # 28 bytes
                        # INFO-CODE (2 bytes) - using code 15 (Blocked)
                        Group(
                            "info_code",
                            values=[
                                b"\x00\x00",  # Other Error
                                b"\x00\x01",  # Unsupported DNSKEY Algorithm
                                b"\x00\x02",  # Unsupported DS Digest Type
                                b"\x00\x03",  # Stale Answer
                                b"\x00\x06",  # DNSSEC Bogus
                                b"\x00\x09",  # DNSKEY Missing
                                b"\x00\x0a",  # RRSIGs Missing
                                b"\x00\x0f",  # Blocked
                                b"\x00\x11",  # Filtered
                                b"\x00\x12",  # Prohibited
                                b"\x00\x16",  # No Reachable Authority
                                b"\x00\x17",  # Network Error
                                b"\x00\x18",  # Invalid Data
                                b"\x00\x19",  # Signature Expired before Valid
                            ],
                        ),
                        # EXTRA-TEXT (UTF-8 string, variable length)
                        SmartString(
                            "extra_text", "Access denied by policy", max_len=256, fuzzable=True
                        ),
                    ),
                ),
            ),
        )

        # NSID - Name Server Identifier (RFC 5001) - EDNS0 option code 3
        Request(
            "DNS_NSID",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_NSID",
                    children=(
                        Word("transaction_id", 0x0301, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_NSID",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "net", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_NSID",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x0004, endian=">"),  # Request with empty NSID
                        # NSID option (code 3) - client sends empty, server responds with ID
                        Word("nsid_option_code", 0x0003, endian=">"),
                        Word("nsid_option_length", 0x0000, endian=">"),  # Empty in request
                    ),
                ),
            ),
        )

        # Padding (RFC 7830) - EDNS0 option code 12 (for privacy/anti-fingerprinting)
        Request(
            "DNS_PADDING",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_Padding",
                    children=(
                        Word("transaction_id", 0x0C01, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_Padding",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "privacy", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "org", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_Padding",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 1232, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        # Variable padding length for different block sizes
                        Group(
                            "edns_data_length",
                            values=[
                                b"\x00\x44",  # 68 bytes (64 padding + 4 header)
                                b"\x01\x04",  # 260 bytes (256 padding + 4 header)
                                b"\x02\x04",  # 516 bytes (512 padding + 4 header)
                            ],
                        ),
                        # Padding option (code 12)
                        Word("padding_option_code", 0x000C, endian=">"),
                        Group(
                            "padding_length",
                            values=[
                                b"\x00\x40",  # 64 bytes
                                b"\x01\x00",  # 256 bytes
                                b"\x02\x00",  # 512 bytes
                            ],
                        ),
                        SmartString(
                            "padding_data", b"\x00" * 64, size=64, max_len=512, fuzzable=True
                        ),
                    ),
                ),
            ),
        )

        # DAU/DHU/N3U - DNSSEC Algorithm Understood (RFC 6975) - codes 5, 6, 7
        Request(
            "DNS_DNSSEC_ALGORITHMS",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_DNSSEC_Alg",
                    children=(
                        Word("transaction_id", 0x0567, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_DNSSEC_Alg",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "dnssec", max_len=63),
                        Byte("label2_length", 7),
                        SmartString("label2", "oida", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_DNSSEC_Alg",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),  # DNSSEC OK
                        Word("edns_data_length", 0x0012, endian=">"),  # 18 bytes total
                        # DAU - DNSSEC Algorithm Understood (code 5)
                        Word("dau_option_code", 0x0005, endian=">"),
                        Word("dau_option_length", 0x0003, endian=">"),
                        SmartString(
                            "dau_algorithms", b"\x08\x0d\x0e", size=3, max_len=16, fuzzable=True
                        ),  # RSA-SHA256, ECDSA P-256, Ed25519
                        # DHU - DS Hash Understood (code 6)
                        Word("dhu_option_code", 0x0006, endian=">"),
                        Word("dhu_option_length", 0x0002, endian=">"),
                        SmartString(
                            "dhu_hashes", b"\x02\x04", size=2, max_len=8, fuzzable=True
                        ),  # SHA-256, SHA-384
                        # N3U - NSEC3 Hash Understood (code 7)
                        Word("n3u_option_code", 0x0007, endian=">"),
                        Word("n3u_option_length", 0x0001, endian=">"),
                        Byte("n3u_hash", 0x01, fuzzable=True),  # SHA-1
                    ),
                ),
            ),
        )

        # edns-key-tag (RFC 8145) - option code 14
        Request(
            "DNS_EDNS_KEY_TAG",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_KeyTag",
                    children=(
                        Word("transaction_id", 0x0E14, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_KeyTag",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_KeyTag",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),  # DNSSEC OK
                        Word("edns_data_length", 0x0008, endian=">"),
                        # Key Tag option (code 14) - list of DNSKEY key tags
                        Word("keytag_option_code", 0x000E, endian=">"),
                        Word("keytag_option_length", 0x0004, endian=">"),
                        # Two key tags (2 bytes each)
                        Word("key_tag_1", 0x1234, endian=">", fuzzable=True),
                        Word("key_tag_2", 0x5678, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # EDNS EXPIRE (RFC 7314) - option code 9
        Request(
            "DNS_EDNS_EXPIRE",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_Expire",
                    children=(
                        Word("transaction_id", 0x0E09, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_Expire",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0006, endian=">"),  # SOA query
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_Expire",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x0004, endian=">"),
                        # EXPIRE option (code 9) - client sends empty
                        Word("expire_option_code", 0x0009, endian=">"),
                        Word("expire_option_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # CHAIN Query (RFC 7901) - option code 13
        Request(
            "DNS_CHAIN_QUERY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_Chain",
                    children=(
                        Word("transaction_id", 0xC013, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_Chain",
                    children=(
                        Byte("label1_length", 3),
                        SmartString("label1", "www", max_len=63),
                        Byte("label2_length", 7),
                        SmartString("label2", "oida", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_Chain",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),  # DNSSEC OK
                        Word("edns_data_length", 0x000E, endian=">"),
                        # CHAIN option (code 13) - closest trust point
                        Word("chain_option_code", 0x000D, endian=">"),
                        Word("chain_option_length", 0x000A, endian=">"),
                        # Closest Trust Point: "oida.local."
                        Byte("ctp_label1_length", 7),
                        SmartString("ctp_label1", "oida", max_len=63, fuzzable=True),
                        Byte("ctp_label2_length", 3),
                        SmartString("ctp_label2", "local", max_len=63, fuzzable=True),
                        Byte("ctp_terminator", 0),
                    ),
                ),
            ),
        )

        # Dynamic DNS UPDATE (RFC 2136) - Opcode 5
        # UPDATE request to add a record
        dns_update_add = Request(
            "DNS_UPDATE_ADD_RECORD",
            children=(
                Block(
                    "DNS_Header_UPDATE",
                    children=(
                        Word("transaction_id", 0x5001, endian=">"),
                        Word(
                            "flags", 0x2800, endian=">"
                        ),  # Opcode 5 (UPDATE), bits: 0010 1000 0000 0000
                        Word("zocount", 0x0001, endian=">"),  # Zone count (replaces questions)
                        Word(
                            "prcount", 0x0000, endian=">"
                        ),  # Prerequisite count (replaces answers)
                        Word("upcount", 0x0001, endian=">"),  # Update count (replaces authority)
                        Word("adcount", 0x0000, endian=">"),  # Additional count
                    ),
                ),
                # Zone Section
                Block(
                    "DNS_Zone",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("ztype", 0x0006, endian=">"),  # SOA
                        Word("zclass", 0x0001, endian=">"),  # IN
                    ),
                ),
                # Update Section - Add A record
                Block(
                    "DNS_Update_Add",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63, fuzzable=True),
                        Byte("label2_length", 7),
                        SmartString("label2", "oida", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("type", 0x0001, endian=">"),  # A record
                        Word("class", 0x0001, endian=">"),  # IN
                        DWord("ttl", 3600, endian=">", fuzzable=True),
                        Word("rdlength", 4, endian=">"),
                        DWord("rdata", 0xC0A80101, endian=">", fuzzable=True),  # 192.168.1.1
                    ),
                ),
            ),
        )

        # UPDATE request to delete a record
        Request(
            "DNS_UPDATE_DELETE_RECORD",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_UPDATE_DEL",
                    children=(
                        Word("transaction_id", 0x5002, endian=">"),
                        Word("flags", 0x2800, endian=">"),  # Opcode 5 (UPDATE)
                        Word("zocount", 0x0001, endian=">"),
                        Word("prcount", 0x0000, endian=">"),
                        Word("upcount", 0x0001, endian=">"),
                        Word("adcount", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Zone_DEL",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("ztype", 0x0006, endian=">"),  # SOA
                        Word("zclass", 0x0001, endian=">"),  # IN
                    ),
                ),
                # Update Section - Delete using CLASS NONE
                Block(
                    "DNS_Update_Delete",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63, fuzzable=True),
                        Byte("label2_length", 7),
                        SmartString("label2", "oida", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("type", 0x0001, endian=">"),  # A record
                        Word("class", 0x00FE, endian=">"),  # CLASS NONE (254) = delete
                        DWord("ttl", 0, endian=">"),
                        Word("rdlength", 0, endian=">"),
                    ),
                ),
            ),
        )

        # UPDATE with prerequisites
        Request(
            "DNS_UPDATE_WITH_PREREQ",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_UPDATE_PR",
                    children=(
                        Word("transaction_id", 0x5003, endian=">"),
                        Word("flags", 0x2800, endian=">"),  # Opcode 5 (UPDATE)
                        Word("zocount", 0x0001, endian=">"),
                        Word("prcount", 0x0001, endian=">"),  # 1 prerequisite
                        Word("upcount", 0x0001, endian=">"),
                        Word("adcount", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Zone_PR",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("ztype", 0x0006, endian=">"),
                        Word("zclass", 0x0001, endian=">"),
                    ),
                ),
                # Prerequisite - Name must exist
                Block(
                    "DNS_Prerequisite",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63, fuzzable=True),
                        Byte("label2_length", 7),
                        SmartString("label2", "oida", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("type", 0x00FF, endian=">"),  # ANY - name must exist
                        Word("class", 0x00FF, endian=">"),  # ANY
                        DWord("ttl", 0, endian=">"),
                        Word("rdlength", 0, endian=">"),
                    ),
                ),
                # Update Section
                Block(
                    "DNS_Update_PR",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63, fuzzable=True),
                        Byte("label2_length", 7),
                        SmartString("label2", "oida", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("type", 0x0001, endian=">"),  # A record
                        Word("class", 0x0001, endian=">"),
                        DWord("ttl", 7200, endian=">", fuzzable=True),
                        Word("rdlength", 4, endian=">"),
                        DWord("rdata", 0xC0A80102, endian=">", fuzzable=True),  # 192.168.1.2
                    ),
                ),
            ),
        )

        # UPDATE with invalid/attack vectors
        dns_update_malformed = Request(
            "DNS_UPDATE_MALFORMED",
            children=(
                Block(
                    "DNS_Header_UPDATE_MAL",
                    children=(
                        Word("transaction_id", 0x5004, endian=">"),
                        Word("flags", 0x2800, endian=">"),  # Opcode 5 (UPDATE)
                        Group(
                            "zone_count",
                            values=[
                                b"\x00\x00",  # Zero zones (invalid)
                                b"\x00\xff",  # Too many zones
                            ],
                        ),
                        Word("prcount", 0x0000, endian=">"),
                        Group(
                            "update_count",
                            values=[
                                b"\x00\x00",  # Zero updates (no-op)
                                b"\xff\xff",  # Maximum updates
                            ],
                        ),
                        Word("adcount", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Zone_MAL",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("ztype", 0x0006, endian=">"),
                        Word("zclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Update_MAL",
                    children=(
                        SmartString("malformed_update", "update-data", max_len=1024, fuzzable=True),
                    ),
                ),
            ),
        )

        # DNS Header Flags - AD (Authentic Data) and CD (Checking Disabled)
        Request(
            "DNS_FLAGS_AD",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_AD",
                    children=(
                        Word("transaction_id", 0xAD01, endian=">"),
                        Word(
                            "flags", 0x0120, endian=">"
                        ),  # AD bit set (bit 5): 0000 0001 0010 0000
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_AD",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "dnssec", max_len=63),
                        Byte("label2_length", 7),
                        SmartString("label2", "oida", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_AD",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),  # DNSSEC OK
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        Request(
            "DNS_FLAGS_CD",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_CD",
                    children=(
                        Word("transaction_id", 0xCD01, endian=">"),
                        Word(
                            "flags", 0x0110, endian=">"
                        ),  # CD bit set (bit 4): 0000 0001 0001 0000
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_CD",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "untrust", max_len=63),
                        Byte("label2_length", 7),
                        SmartString("label2", "oida", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_CD",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),  # DNSSEC OK
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        Request(
            "DNS_FLAGS_AD_CD_BOTH",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_AD_CD",
                    children=(
                        Word("transaction_id", 0xADCD, endian=">"),
                        Word("flags", 0x0130, endian=">"),  # Both AD and CD bits set
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_AD_CD",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "org", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_AD_CD",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # ============================================================
        # Modern DNS Record Types (RFC 6844, RFC 6698, RFC 9460, RFC 2782)
        # ============================================================

        # CAA - Certificate Authority Authorization (RFC 6844) - Type 257
        dns_caa_query = Request(
            "DNS_CAA_QUERY",
            children=(
                Block(
                    "DNS_Header_CAA",
                    children=(
                        Word("transaction_id", 0xCAA0, endian=">"),
                        Word("flags", 0x0100, endian=">"),  # Standard query
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_CAA",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0101, endian=">"),  # CAA = 257 = 0x0101
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_CAA",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # TLSA - TLS Authentication (RFC 6698) - Type 52
        Request(
            "DNS_TLSA_QUERY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_TLSA",
                    children=(
                        Word("transaction_id", 0x7152, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_TLSA",
                    children=(
                        # _443._tcp.oida.local
                        Byte("label1_length", 4),
                        SmartString("label1", "_443", max_len=63),
                        Byte("label2_length", 4),
                        SmartString("label2", "_tcp", max_len=63),
                        Byte("label3_length", 7),
                        SmartString("label3", "oida", max_len=63),
                        Byte("label4_length", 3),
                        SmartString("label4", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0034, endian=">"),  # TLSA = 52 = 0x0034
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_TLSA",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),  # DNSSEC OK
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # SVCB - Service Binding (RFC 9460) - Type 64
        Request(
            "DNS_SVCB_QUERY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_SVCB",
                    children=(
                        Word("transaction_id", 0x5BC8, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_SVCB",
                    children=(
                        # _service.oida.local
                        Byte("label1_length", 8),
                        SmartString("label1", "_service", max_len=63),
                        Byte("label2_length", 7),
                        SmartString("label2", "oida", max_len=63),
                        Byte("label3_length", 3),
                        SmartString("label3", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0040, endian=">"),  # SVCB = 64 = 0x0040
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_SVCB",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # HTTPS - HTTPS Service (RFC 9460) - Type 65
        Request(
            "DNS_HTTPS_QUERY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_HTTPS",
                    children=(
                        Word("transaction_id", 0x4770, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_HTTPS",
                    children=(
                        Byte("label1_length", 7),
                        SmartString("label1", "oida", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0041, endian=">"),  # HTTPS = 65 = 0x0041
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_HTTPS",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # SRV - Service Record (RFC 2782) - Type 33
        dns_srv_query = Request(
            "DNS_SRV_QUERY",
            children=(
                Block(
                    "DNS_Header_SRV",
                    children=(
                        Word("transaction_id", 0x5211, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_SRV",
                    children=(
                        # _http._tcp.oida.local
                        Byte("label1_length", 5),
                        SmartString("label1", "_http", max_len=63),
                        Byte("label2_length", 4),
                        SmartString("label2", "_tcp", max_len=63),
                        Byte("label3_length", 7),
                        SmartString("label3", "oida", max_len=63),
                        Byte("label4_length", 3),
                        SmartString("label4", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0021, endian=">"),  # SRV = 33 = 0x0021
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_SRV",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 0),
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # ============================================================
        # Complete RCODE Coverage (RFC 1035, RFC 2136, RFC 2671, RFC 7873)
        # ============================================================

        # Standard RCODEs (RFC 1035)
        Request(
            "DNS_RCODE_NOERROR",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_NOERROR",
                    children=(
                        Word("transaction_id", 0x2C00, endian=">"),
                        Word("flags", 0x8000, endian=">"),  # Response, RCODE=0
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_RC0",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        Request(
            "DNS_RCODE_FORMERR",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_FORMERR",
                    children=(
                        Word("transaction_id", 0x2C01, endian=">"),
                        Word("flags", 0x8001, endian=">"),  # Response, RCODE=1 (Format Error)
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_RC1",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        Request(
            "DNS_RCODE_SERVFAIL",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_SERVFAIL",
                    children=(
                        Word("transaction_id", 0x2C02, endian=">"),
                        Word("flags", 0x8002, endian=">"),  # Response, RCODE=2 (Server Failure)
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                )
            ),
        )

        Request(
            "DNS_RCODE_NXDOMAIN",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_NXDOMAIN",
                    children=(
                        Word("transaction_id", 0x2C03, endian=">"),
                        Word("flags", 0x8003, endian=">"),  # Response, RCODE=3 (Name Error)
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                )
            ),
        )

        Request(
            "DNS_RCODE_NOTIMP",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_NOTIMP",
                    children=(
                        Word("transaction_id", 0x2C04, endian=">"),
                        Word("flags", 0x8004, endian=">"),  # Response, RCODE=4 (Not Implemented)
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                )
            ),
        )

        Request(
            "DNS_RCODE_REFUSED",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_REFUSED",
                    children=(
                        Word("transaction_id", 0x2C05, endian=">"),
                        Word("flags", 0x8005, endian=">"),  # Response, RCODE=5 (Refused)
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                )
            ),
        )

        # UPDATE-specific RCODEs (RFC 2136)
        Request(
            "DNS_RCODE_YXDOMAIN",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_YXDOMAIN",
                    children=(
                        Word("transaction_id", 0x2C06, endian=">"),
                        Word("flags", 0x8006, endian=">"),  # Response, RCODE=6 (Name Exists)
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                )
            ),
        )

        Request(
            "DNS_RCODE_YXRRSET",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_YXRRSET",
                    children=(
                        Word("transaction_id", 0x2C07, endian=">"),
                        Word("flags", 0x8007, endian=">"),  # Response, RCODE=7 (RRSet Exists)
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                )
            ),
        )

        Request(
            "DNS_RCODE_NXRRSET",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_NXRRSET",
                    children=(
                        Word("transaction_id", 0x2C08, endian=">"),
                        Word(
                            "flags", 0x8008, endian=">"
                        ),  # Response, RCODE=8 (RRSet Does Not Exist)
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                )
            ),
        )

        Request(
            "DNS_RCODE_NOTAUTH",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_NOTAUTH",
                    children=(
                        Word("transaction_id", 0x2C09, endian=">"),
                        Word("flags", 0x8009, endian=">"),  # Response, RCODE=9 (Not Authoritative)
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                )
            ),
        )

        Request(
            "DNS_RCODE_NOTZONE",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_NOTZONE",
                    children=(
                        Word("transaction_id", 0x2C10, endian=">"),
                        Word("flags", 0x800A, endian=">"),  # Response, RCODE=10 (Name Not In Zone)
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                )
            ),
        )

        # EDNS Extended RCODEs (RFC 2671, RFC 6891)
        Request(
            "DNS_RCODE_BADVERS",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_BADVERS",
                    children=(
                        Word("transaction_id", 0x2C16, endian=">"),
                        Word("flags", 0x8000, endian=">"),  # Response, base RCODE=0
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_BADVERS",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_BADVERS",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 16),  # BADVERS = 16 (extended RCODE)
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # DNS Cookies RCODE (RFC 7873)
        Request(
            "DNS_RCODE_BADCOOKIE",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_BADCOOKIE",
                    children=(
                        Word("transaction_id", 0x2C23, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_BADCOOKIE",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_BADCOOKIE",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 23),  # BADCOOKIE = 23 (extended RCODE)
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # Additional Important RCODEs
        Request(
            "DNS_RCODE_BADSIG",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_BADSIG",
                    children=(
                        Word("transaction_id", 0x2C16, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_BADSIG",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 16),  # BADSIG/BADVERS share RCODE 16
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),  # DNSSEC OK
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        Request(
            "DNS_RCODE_BADKEY",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_BADKEY",
                    children=(
                        Word("transaction_id", 0x2C17, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_BADKEY",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 17),  # BADKEY = 17
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x8000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        Request(
            "DNS_RCODE_BADTIME",
            children=(  # noqa: F841
                Block(
                    "DNS_Header_BADTIME",
                    children=(
                        Word("transaction_id", 0x2C18, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_EDNS0_BADTIME",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 4096, endian=">"),
                        Byte("extended_rcode", 18),  # BADTIME = 18
                        Byte("edns_version", 0),
                        Word("edns_flags", 0x0000, endian=">"),
                        Word("edns_data_length", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        # Malformed EDNS0 record
        dns_malformed_edns0 = Request(
            "DNS_MALFORMED_EDNS0",
            children=(
                Block(
                    "DNS_Header_MAL_EDNS",
                    children=(
                        Word("transaction_id", 0xDDDD, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_MAL_EDNS",
                    children=(
                        Byte("label1_length", 4),
                        SmartString("label1", "test", max_len=63),
                        Byte("label2_length", 3),
                        SmartString("label2", "local", max_len=63),
                        Byte("name_terminator", 0),
                        Word("qtype", 0x0001, endian=">"),
                        Word("qclass", 0x0001, endian=">"),
                    ),
                ),
                Block(
                    "DNS_MALFORMED_EDNS0",
                    children=(
                        Byte("edns_name", 0),
                        Word("edns_type", 0x0029, endian=">"),
                        Word("udp_payload_size", 0xFFFF, endian=">", fuzzable=True),  # Max UDP size
                        Byte("extended_rcode", 255, fuzzable=True),
                        Byte("edns_version", 255, fuzzable=True),  # Invalid EDNS version
                        Word("edns_flags", 0xFFFF, endian=">", fuzzable=True),
                        Word("edns_data_length", 0x1000, endian=">", fuzzable=True),  # Large data
                        SmartString(
                            "malformed_options", "edns-option", max_len=8192, fuzzable=True
                        ),
                    ),
                ),
            ),
        )

        # DNS Compression Pointer Loop - Circular reference attack (exploitdb pattern)
        dns_compression_loop = Request(
            "DNS_COMPRESSION_LOOP",
            children=(
                Block(
                    "DNS_Header_CompLoop",
                    children=(
                        Word("transaction_id", 0x3333, endian=">"),
                        Word("flags", 0x0100, endian=">"),
                        Word("questions", 0x0001, endian=">"),
                        Word("answers", 0x0000, endian=">"),
                        Word("authority", 0x0000, endian=">"),
                        Word("additional", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "DNS_Question_CompLoop",
                    children=(
                        # Compression pointer that points to itself or earlier in packet
                        # Format: 11xxxxxx xxxxxxxx (top 2 bits = 11 for compression)
                        # Example: \xC0\x0C points to offset 12 (the header end)
                        Group(
                            "compression_attack",
                            values=[
                                b"\xc0\x0c\x00\x01\x00\x01",  # Point to offset 12 (self-reference)
                                b"\xc0\x00\x00\x01\x00\x01",  # Point to offset 0 (start of packet)
                                b"\xc0\x0c\xc0\x0c\x00\x01\x00\x01",  # Double pointer (circular)
                                b"\xc0\x0e\xc0\x0c\x00\x01\x00\x01",  # Pointer chain loop
                                b"\xff\xff\x00\x01\x00\x01",  # Invalid pointer (all bits set)
                                b"\xc0\xff\x00\x01\x00\x01",  # Pointer beyond packet
                                b"\xc0\x0c\xc0\x0e\xc0\x10\x00\x01\x00\x01",  # Triple pointer chain
                            ],
                        ),
                    ),
                ),
            ),
        )

        # ==================== TIERED REQUEST ORDERING ====================
        # CONSOLIDATED: Reduced from 68 to 27 requests for 2-3x faster fuzzing
        # Optimized for efficiency: baseline → core → security-critical → exotic

        # TIER 0: BASELINE - Non-fuzzable connectivity test (FASTEST - <100ms)
        self.session.connect(dns_baseline)  # Simple A query, all fields static

        # TIER 1: CORE A RECORD - Fuzzed baseline query
        self.session.connect(dns_a_query)  # A record with fuzzing

        # TIER 2: CORE QUERY TYPES - Most common DNS operations
        self.session.connect(dns_aaaa_query)  # IPv6 addresses
        self.session.connect(dns_mx_query)  # Mail exchange
        self.session.connect(dns_ptr_query)  # Reverse DNS
        self.session.connect(dns_txt_query)  # Text records
        self.session.connect(dns_srv_query)  # Service discovery
        self.session.connect(dns_caa_query)  # Certificate authority authorization

        # TIER 3: CRITICAL ATTACK PATTERNS - High-severity vulnerabilities
        self.session.connect(dns_cache_poisoning)  # CVE-2008-1447, Kaminsky attack
        self.session.connect(dns_amplification)  # DDoS amplification
        self.session.connect(dns_domain_overflow)  # AMNESIA:33 buffer overflow
        self.session.connect(dns_length_overflow)  # AMNESIA:33 length validation

        # TIER 4: BUFFER OVERFLOW & PARSING ATTACKS
        self.session.connect(dns_long_domain)  # Oversized domain names
        self.session.connect(dns_malformed_labels)  # Invalid label structures
        self.session.connect(dns_compression_loop)  # Compression pointer loops
        self.session.connect(dns_invalid_flags)  # Invalid header flags
        self.session.connect(dns_malformed_edns0)  # Malformed EDNS0 extensions

        # TIER 5: DNSSEC QUERIES - Cryptographic extensions (2 of 8 tests)
        self.session.connect(dns_dnskey_query)  # Public key records
        self.session.connect(dns_rrsig_query)  # Resource record signatures

        # TIER 6: EDNS0 EXTENSIONS - Modern DNS features (3 of 11 tests)
        self.session.connect(dns_edns0_options)  # Extended DNS options
        self.session.connect(dns_cookies)  # DNS cookies (RFC 7873)
        self.session.connect(dns_extended_errors)  # Extended error codes (RFC 8914)

        # TIER 7: DYNAMIC UPDATE - DNS UPDATE operations (RFC 2136) (2 of 4 tests)
        self.session.connect(dns_update_add)  # Add resource records
        self.session.connect(dns_update_malformed)  # Malformed UPDATE messages

        # NOTE: TCP/Zone Transfer and RCODE tests are connected later after their definitions

    def get_fuzzing_targets(self) -> list:
        """Return list of DNS fuzzing targets and their purposes"""
        return [
            {
                "name": "DNS_A_QUERY",
                "description": "A record queries - tests IPv4 address resolution",
            },
            {
                "name": "DNS_AAAA_QUERY",
                "description": "AAAA record queries - tests IPv6 address resolution",
            },
            {
                "name": "DNS_MX_QUERY",
                "description": "MX record queries - tests mail exchange resolution",
            },
            {
                "name": "DNS_PTR_QUERY",
                "description": "PTR record queries - tests reverse DNS resolution",
            },
            {
                "name": "DNS_LONG_DOMAIN",
                "description": "Oversized domain names - tests buffer overflow protection",
            },
            {
                "name": "DNS_MALFORMED_LABELS",
                "description": "Malformed label structures - tests parsing robustness",
            },
            {
                "name": "DNS_CACHE_POISONING",
                "description": "Cache poisoning attempts - tests response validation",
            },
            {
                "name": "DNS_AMPLIFICATION",
                "description": "Query amplification attacks - tests response size limits",
            },
            {
                "name": "DNS_TXT_QUERY",
                "description": "TXT record queries - tests text data handling",
            },
            {
                "name": "DNS_INVALID_FLAGS",
                "description": "Invalid flag combinations - tests protocol state validation",
            },
        ]


# For backward compatibility and explicit exports
__all__ = ["DNSFuzzer"]
