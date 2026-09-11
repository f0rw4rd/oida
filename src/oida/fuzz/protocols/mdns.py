"""mDNS Protocol Fuzzer"""

from enum import IntEnum

from boofuzz import BitField, Block, DWord, Group, Request, Size, Static, Word
from boofuzz.connections import UDPSocketConnection

from typing import List

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig
from ..primitives.dynamic import SmartString
from ..primitives.smart_string import StringContext


class DNSType(IntEnum):
    """DNS Resource Record Types"""

    A = 1  # IPv4 Address
    NS = 2  # Name Server
    CNAME = 5  # Canonical Name
    SOA = 6  # Start of Authority
    PTR = 12  # Pointer Record
    MX = 15  # Mail Exchange
    TXT = 16  # Text Record
    AAAA = 28  # IPv6 Address
    SRV = 33  # Service Record
    NSEC = 47  # DNSSEC - Next Secure
    OPT = 41  # EDNS Options
    ANY = 255  # Any Record Type


class DNSClass(IntEnum):
    """DNS Resource Record Classes"""

    IN = 1  # Internet
    CS = 2  # CSNET (obsolete)
    CH = 3  # CHAOS
    HS = 4  # Hesiod
    NONE = 254  # None
    ANY = 255  # Any Class

    # mDNS specific classes (IN + cache flush bit)
    IN_FLUSH = 0x8001  # Internet with cache flush bit


class MDNSFuzzer(BaseFuzzer):
    """Multicast DNS (mDNS) Protocol Fuzzer Implementation"""

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Quick coverage
            RequestInfo("Quick_Coverage", "All mDNS operations sweep", "quick_coverage"),
            # Malformed packets
            RequestInfo("Malformed_Header", "Malformed DNS headers", "high_crash"),
            RequestInfo("Long_Name", "Long domain name attacks", "high_crash"),
            RequestInfo("Oversized_Packet", "Oversized packet tests", "high_crash"),
            # Compression attacks
            RequestInfo("Invalid_Compression", "Invalid compression pointers", "compression"),
            RequestInfo("Circular_Compression", "Circular compression loops", "compression"),
            RequestInfo("Nested_Compression", "Nested compression attacks", "compression"),
            # EDNS
            RequestInfo("EDNS0_Malformed", "Malformed EDNS0 options", "edns"),
            # Standard
            RequestInfo("Variable_Records", "Variable record tests", "standard"),
            RequestInfo("Truncated_Packet", "Truncated packets", "standard"),
            RequestInfo("Zero_Length_Label", "Zero-length labels", "standard"),
            RequestInfo("Standard_Query", "Standard mDNS queries", "query"),
            RequestInfo("Zero_Entry_Query", "Zero entry queries", "query"),
            RequestInfo("Multi_Question_Query", "Multi-question queries", "query"),
            RequestInfo("Standard_Response", "Standard responses", "response"),
            RequestInfo("Multi_Answer_Response", "Multi-answer responses", "response"),
            RequestInfo("Mixed_Records_Response", "Mixed record responses", "response"),
            RequestInfo("Service_Subtypes", "Service subtype queries", "service"),
            RequestInfo("Unicast_Response_Query", "Unicast response flag", "service"),
            RequestInfo("Duplicate_Records", "Duplicate record tests", "standard"),
            RequestInfo("Multi_Known_Answer", "Known answer suppression", "query"),
            RequestInfo("Negative_Response", "NSEC negative responses", "response"),
            RequestInfo("PTR_Query", "Service discovery PTR queries", "query"),
            RequestInfo("SRV_Query", "Service instance SRV queries", "query"),
            RequestInfo("Cache_Flush_Query", "Cache flush bit queries", "query"),
            RequestInfo("Probe_Query", "Name uniqueness probe", "query"),
            RequestInfo("Goodbye_Packet", "Service termination announcements", "response"),
            RequestInfo("EDNS0_Packet", "EDNS0 extension packets", "edns"),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        # Default mDNS port if not specified
        if config.target_port == 0:
            config.target_port = 5353
        super().__init__(config, connection_factory)
        # max_recv_bytes lives on the boofuzz Target, not the Session — setting
        # it on self.session was a dead write, leaving the 10000 default so the
        # 8192 cap for large mDNS responses never applied.
        if self.session.targets:
            self.session.targets[0].max_recv_bytes = 8192

    def _create_socket(self):
        # mDNS uses UDP multicast - need to bind to receive responses
        return UDPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            bind=("0.0.0.0", 0),  # Bind to any interface, ephemeral port for receiving responses
            **self._timeout_overrides(recv_default=2.0, send_default=2.0),
        )

    def setup_custom_monitors(self) -> list:
        """Setup mDNS-specific monitoring with DNS query comparison"""
        from ..monitors import DNSQueryMonitor

        mdns_monitor = DNSQueryMonitor(
            host=self.config.target_ip,
            port=self.config.target_port,
            query_domain="_services._dns-sd._udp.local",  # mDNS service discovery
            timeout=2,
            check_interval=3,  # Check every 3 test cases
        )

        return [mdns_monitor]

    def _create_dns_header(
        self,
        name="DNS_Header",
        qr=0,
        opcode=0,
        aa=0,
        tc=0,
        rd=0,
        ra=0,
        z=0,
        rcode=0,
        qdcount=0,
        ancount=0,
        nscount=0,
        arcount=0,
    ) -> Block:
        """Create a DNS header block.

        The 16-bit flags field must be a single packed value: boofuzz renders
        each separate ``BitField`` primitive to its own byte boundary, so eight
        BitFields would emit eight bytes, not the two the DNS header requires.
        We pack the flags into one big-endian Word instead. Section counts must
        match the records the caller appends, so they are explicit parameters.
        """
        flags = (
            (qr & 0x1) << 15
            | (opcode & 0xF) << 11
            | (aa & 0x1) << 10
            | (tc & 0x1) << 9
            | (rd & 0x1) << 8
            | (ra & 0x1) << 7
            | (z & 0x7) << 4
            | (rcode & 0xF)
        )
        return Block(
            name,
            children=(
                Word("ID", 0x1234, output_format="binary", endian=">"),  # Transaction ID
                Word("Flags", flags, output_format="binary", endian=">"),  # QR/Opcode/AA/.../Rcode
                Word("QDCount", qdcount, output_format="binary", endian=">"),  # Question count
                Word("ANCount", ancount, output_format="binary", endian=">"),  # Answer count
                Word("NSCount", nscount, output_format="binary", endian=">"),  # Authority count
                Word("ARCount", arcount, output_format="binary", endian=">"),  # Additional count
            ),
        )

    def _create_dns_question(self, name="DNS_Question") -> Block:
        """Create a DNS Question section"""
        # Use the parent name to create unique QNAME block identifiers
        qname_block = f"{name}_QNAME"

        return Block(
            name,
            children=(
                # NOTE: no Size prefix here — the QNAME block already begins with its
                # own wire-format label-length byte (the Label_Type Group), and a
                # duplicate outer length byte renders an invalid DNS name.
                Block(
                    qname_block,
                    children=(
                        Group(
                            f"{name}_Label_Type",
                            values=[
                                b"\x05",  # Standard label
                                b"\x00",  # Root domain
                                b"\xc0",  # Compression pointer
                            ],
                        ),
                        SmartString(
                            f"{name}_Label_Text",
                            "local",
                            max_len=63,
                            context=StringContext.HOSTNAME,
                        ),
                        Group(
                            f"{name}_Domain_Suffix",
                            values=[
                                b"\x00",  # Root domain
                                b"\x05local\x00",  # .local
                                b"\x04arpa\x00",  # .arpa
                                b"\x07example\x03com\x00",  # .example.com
                                b"\x08_service\x04_tcp\x05local\x00",  # Service name
                                b"\xc0\x0c",  # Compression pointer
                            ],
                        ),
                    ),
                ),
                Word("QTYPE", DNSType.PTR, output_format="binary", endian=">"),  # Query type
                Word("QCLASS", DNSClass.IN, output_format="binary", endian=">"),  # Query class
            ),
        )

    def _create_dns_rr(self, name="DNS_ResourceRecord") -> Block:
        """Create a DNS Resource Record section"""
        # Use the parent name to create unique NAME block identifiers
        name_block = f"{name}_NAME"

        return Block(
            name,
            children=(
                # NOTE: no Size prefix here — the NAME block already begins with its
                # own wire-format label-length byte (the Label_Type Group), and a
                # duplicate outer length byte renders an invalid DNS name.
                Block(
                    name_block,
                    children=(
                        Group(
                            f"{name}_Label_Type",
                            values=[
                                b"\x05",  # Standard label
                                b"\x00",  # Root domain
                                b"\xc0",  # Compression pointer
                            ],
                        ),
                        SmartString(
                            f"{name}_Label_Text",
                            "local",
                            max_len=63,
                            context=StringContext.HOSTNAME,
                        ),
                        Group(
                            f"{name}_Domain_Suffix",
                            values=[
                                b"\x00",  # Root domain
                                b"\x05local\x00",  # .local
                                b"\x04arpa\x00",  # .arpa
                                b"\xc0\x0c",  # Compression pointer
                            ],
                        ),
                    ),
                ),
                Word("TYPE", DNSType.PTR, output_format="binary", endian=">"),  # RR type
                Word("CLASS", DNSClass.IN, output_format="binary", endian=">"),  # RR class
                DWord("TTL", 120, output_format="binary", endian=">"),  # Time to live
                Size(
                    f"{name}_RDLENGTH",
                    block_name=f"{name}_RDATA",
                    length=2,
                    endian=">",
                    inclusive=False,
                ),  # RData length
                Block(
                    f"{name}_RDATA",
                    children=(
                        # Different data formats based on record type
                        Block(
                            f"{name}_PTR_Data",
                            children=(
                                Size(
                                    f"{name}_PTR_Length",
                                    block_name=f"{name}_PTR_Name",
                                    length=1,
                                    inclusive=False,
                                ),
                                Block(
                                    f"{name}_PTR_Name",
                                    children=(
                                        SmartString(
                                            f"{name}_Service_Name",
                                            "_http._tcp.local",
                                            max_len=128,
                                            context=StringContext.HOSTNAME,
                                        ),
                                        Static(f"{name}_Terminator", b"\x00"),
                                    ),
                                ),
                            ),
                        ),
                        Block(
                            f"{name}_SRV_Data",
                            children=(
                                Word(f"{name}_Priority", 0, output_format="binary", endian=">"),
                                Word(f"{name}_Weight", 0, output_format="binary", endian=">"),
                                Word(f"{name}_Port", 80, output_format="binary", endian=">"),
                                Size(
                                    f"{name}_Target_Length",
                                    block_name=f"{name}_Target",
                                    length=1,
                                    inclusive=False,
                                ),
                                Block(
                                    f"{name}_Target",
                                    children=(
                                        SmartString(
                                            f"{name}_Hostname",
                                            "device",
                                            max_len=63,
                                            context=StringContext.HOSTNAME,
                                        ),
                                        Static(f"{name}_Domain", b"\x05local\x00"),
                                    ),
                                ),
                            ),
                        ),
                        Block(
                            f"{name}_TXT_Data",
                            children=(
                                Size(
                                    f"{name}_TXT_Length",
                                    block_name=f"{name}_TXT_Value",
                                    length=1,
                                    inclusive=False,
                                ),
                                Block(
                                    f"{name}_TXT_Value",
                                    children=(
                                        SmartString(
                                            f"{name}_TXT_Attribute", "name=value", max_len=255
                                        )
                                    ),
                                ),
                            ),
                        ),
                        Block(
                            f"{name}_A_Data",
                            children=(
                                SmartString(f"{name}_IPv4_Address", "192.168.1.1", max_len=4)
                            ),
                        ),
                        Block(
                            f"{name}_AAAA_Data",
                            children=(SmartString(f"{name}_IPv6_Address", "fe80::1", max_len=16)),
                        ),
                    ),
                ),
            ),
        )

    def _define_protocol(self) -> None:
        """Define the complete mDNS protocol structure

        Test ordering optimized for maximum early coverage:
        - Phase 1: Quick_Coverage (all record types in ~30 seconds)
        - Phase 2: High-crash tests (overflow, buffer attacks)
        - Phase 3: CVE-targeted operations (compression, name length)
        - Phase 4: Boundary attacks (variable counts, truncation)
        - Phase 5: Normal operations and edge cases
        """

        # =================================================================
        # PHASE 1: Quick Feature Sweep (~30 seconds)
        # Touch all mDNS operations and record types once
        # =================================================================

        # Quick Coverage - touches all record types in a single request
        quick_coverage = Request(
            "Quick_Coverage",
            children=(
                Block(
                    "QC_Header",
                    children=(
                        Word("ID", 0xABCD, output_format="binary", endian=">"),
                        Word("Flags", 0x8400, output_format="binary", endian=">"),
                        # Section counts are now Word (fuzzable) so boofuzz
                        # mutates them — section-count lies about actual record
                        # count are a classic DNS parser bug class
                        # (RDLENGTH confusion); see ref/mdns/cves/README.md.
                        Word("QDCount", 1, output_format="binary", endian=">"),  # 1 question
                        Word("ANCount", 8, output_format="binary", endian=">"),  # 8 answers
                        Word("NSCount", 1, output_format="binary", endian=">"),  # 1 authority
                        Word("ARCount", 1, output_format="binary", endian=">"),  # 1 additional
                    ),
                ),
                # Question: ANY record for service discovery
                Block(
                    "QC_Question",
                    children=(
                        Static("QC_Q_Name", b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"),
                        Static("QC_Q_Type", b"\x00\xff"),  # ANY
                        Static("QC_Q_Class", b"\x00\x01"),  # IN
                    ),
                ),
                # Answer 1: A record
                Block(
                    "QC_A_Record",
                    children=(
                        Static("QC_A_Name", b"\x08hostname\x05local\x00"),
                        Static("QC_A_Type", b"\x00\x01"),  # A
                        Static("QC_A_Class", b"\x80\x01"),  # IN + cache flush
                        Static("QC_A_TTL", b"\x00\x00\x00\x78"),
                        Static("QC_A_RDLength", b"\x00\x04"),
                        Static("QC_A_RData", b"\xc0\xa8\x01\x0a"),  # 192.168.1.10
                    ),
                ),
                # Answer 2: AAAA record
                Block(
                    "QC_AAAA_Record",
                    children=(
                        Static("QC_AAAA_Name", b"\x08hostname\x05local\x00"),
                        Static("QC_AAAA_Type", b"\x00\x1c"),  # AAAA
                        Static("QC_AAAA_Class", b"\x80\x01"),
                        Static("QC_AAAA_TTL", b"\x00\x00\x00\x78"),
                        Static("QC_AAAA_RDLength", b"\x00\x10"),
                        Static(
                            "QC_AAAA_RData",
                            b"\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x0c\x29\xff\xfe\x4a\xde\x44",
                        ),
                    ),
                ),
                # Answer 3: PTR record
                Block(
                    "QC_PTR_Record",
                    children=(
                        Static("QC_PTR_Name", b"\x05_http\x04_tcp\x05local\x00"),
                        Static("QC_PTR_Type", b"\x00\x0c"),  # PTR
                        Static("QC_PTR_Class", b"\x00\x01"),
                        Static("QC_PTR_TTL", b"\x00\x00\x01\x2c"),
                        Static("QC_PTR_RDLength", b"\x00\x1b"),  # auto: len(QC_PTR_RData)=27
                        Static("QC_PTR_RData", b"\x08WebShare\x05_http\x04_tcp\x05local\x00"),
                    ),
                ),
                # Answer 4: SRV record
                Block(
                    "QC_SRV_Record",
                    children=(
                        Static("QC_SRV_Name", b"\x08WebShare\x05_http\x04_tcp\x05local\x00"),
                        Static("QC_SRV_Type", b"\x00\x21"),  # SRV
                        Static("QC_SRV_Class", b"\x00\x01"),
                        Static("QC_SRV_TTL", b"\x00\x00\x01\x2c"),
                        Static("QC_SRV_RDLength", b"\x00\x16"),
                        Static("QC_SRV_Priority", b"\x00\x00"),
                        Static("QC_SRV_Weight", b"\x00\x00"),
                        Static("QC_SRV_Port", b"\x00\x50"),
                        Static("QC_SRV_Target", b"\x08webshare\x05local\x00"),
                    ),
                ),
                # Answer 5: TXT record
                Block(
                    "QC_TXT_Record",
                    children=(
                        Static("QC_TXT_Name", b"\x08hostname\x05local\x00"),
                        Static("QC_TXT_Type", b"\x00\x10"),  # TXT
                        Static("QC_TXT_Class", b"\x00\x01"),
                        Static("QC_TXT_TTL", b"\x00\x00\x00\x78"),
                        Static("QC_TXT_RDLength", b"\x00\x0c"),
                        Static("QC_TXT_RData", b"\x0bmodel=test\x00"),
                    ),
                ),
                # Answer 6: CNAME record
                Block(
                    "QC_CNAME_Record",
                    children=(
                        Static("QC_CNAME_Name", b"\x05alias\x05local\x00"),
                        Static("QC_CNAME_Type", b"\x00\x05"),  # CNAME
                        Static("QC_CNAME_Class", b"\x00\x01"),
                        Static("QC_CNAME_TTL", b"\x00\x00\x00\x78"),
                        Static("QC_CNAME_RDLength", b"\x00\x10"),  # auto: len(QC_CNAME_RData)=16
                        Static("QC_CNAME_RData", b"\x08hostname\x05local\x00"),
                    ),
                ),
                # Answer 7: NS record
                Block(
                    "QC_NS_Record",
                    children=(
                        Static("QC_NS_Name", b"\x05local\x00"),
                        Static("QC_NS_Type", b"\x00\x02"),  # NS
                        Static("QC_NS_Class", b"\x00\x01"),
                        Static("QC_NS_TTL", b"\x00\x00\x00\x78"),
                        Static("QC_NS_RDLength", b"\x00\x0e"),  # auto: len(QC_NS_RData)=14
                        Static("QC_NS_RData", b"\x06ns-srv\x05local\x00"),
                    ),
                ),
                # Answer 8: MX record
                Block(
                    "QC_MX_Record",
                    children=(
                        Static("QC_MX_Name", b"\x05local\x00"),
                        Static("QC_MX_Type", b"\x00\x0f"),  # MX
                        Static("QC_MX_Class", b"\x00\x01"),
                        Static("QC_MX_TTL", b"\x00\x00\x00\x78"),
                        Static("QC_MX_RDLength", b"\x00\x10"),
                        Static("QC_MX_Pref", b"\x00\x0a"),  # Preference 10
                        Static("QC_MX_RData", b"\x06mail01\x05local\x00"),
                    ),
                ),
                # Authority: SOA record
                Block(
                    "QC_SOA_Record",
                    children=(
                        Static("QC_SOA_Name", b"\x05local\x00"),
                        Static("QC_SOA_Type", b"\x00\x06"),  # SOA
                        Static("QC_SOA_Class", b"\x00\x01"),
                        Static("QC_SOA_TTL", b"\x00\x00\x00\x78"),
                        Static("QC_SOA_RDLength", b"\x00\x2b"),
                        Static(
                            "QC_SOA_RData",
                            b"\x02ns\x05local\x00"
                            + b"\x05admin\x05local\x00"
                            + b"\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x12\x75\x00\x00\x00\x00\x0e",
                        ),
                    ),
                ),
                # Additional: NSEC record
                Block(
                    "QC_NSEC_Record",
                    children=(
                        Static("QC_NSEC_Name", b"\x08hostname\x05local\x00"),
                        Static("QC_NSEC_Type", b"\x00\x2f"),  # NSEC
                        Static("QC_NSEC_Class", b"\x00\x01"),
                        Static("QC_NSEC_TTL", b"\x00\x00\x00\x78"),
                        Static("QC_NSEC_RDLength", b"\x00\x18"),
                        Static(
                            "QC_NSEC_RData",
                            b"\x08hostname\x05local\x00" + b"\x00\x06\x40\x00\x00\x08\x00\x01",
                        ),
                    ),
                ),
            ),
        )

        # =================================================================
        # PHASE 2: High-Crash Tests (Buffer Overflows, Invalid Data)
        # Run early to detect crashes quickly
        # =================================================================

        # Malformed header with invalid field values
        malformed_header = Request(
            "Malformed_Header",
            children=(
                Block(
                    "Bad_Header",
                    children=(
                        Word("ID", 0xFFFF, output_format="binary", endian=">"),
                        BitField(
                            "QR", default_value=2, width=1
                        ),  # Invalid value (should be 0 or 1)
                        BitField("Opcode", default_value=15, width=4),  # Invalid opcode
                        BitField("AA", default_value=1, width=1),
                        BitField("TC", default_value=1, width=1),
                        BitField("RD", default_value=1, width=1),
                        BitField("RA", default_value=1, width=1),
                        BitField("Z", default_value=7, width=3),  # Reserved bits set
                        BitField("Rcode", default_value=15, width=4),  # Invalid response code
                        Word(
                            "QDCount", 65535, output_format="binary", endian=">"
                        ),  # Excessive count
                        Word("ANCount", 65535, output_format="binary", endian=">"),
                        Word("NSCount", 65535, output_format="binary", endian=">"),
                        Word("ARCount", 65535, output_format="binary", endian=">"),
                    ),
                )
            ),
        )

        # Extremely long name - buffer overflow attack
        long_name = Request(
            "Long_Name",
            children=(
                self._create_dns_header(name="Long_Name_Header", qr=0, qdcount=1),
                Block(
                    "Long_Question",
                    children=(
                        # Extremely long labels that together approach DNS limit
                        Static("Long_Name_1", b"\x3f" + b"a" * 63),  # Max length label
                        Static("Long_Name_2", b"\x3f" + b"b" * 63),
                        Static("Long_Name_3", b"\x3f" + b"c" * 63),
                        Static("Long_Name_4", b"\x3f" + b"d" * 63),
                        Static("Long_Suffix", b"\x00"),
                        Static("Long_Type", b"\x00\x01"),  # A
                        Static("Long_Class", b"\x00\x01"),  # IN
                    ),
                ),
            ),
        )

        # Oversized packet approaching UDP limits
        oversized_packet = Request(
            "Oversized_Packet",
            children=(
                self._create_dns_header(name="Large_Header", qr=1, aa=1, qdcount=1, ancount=3),
                self._create_dns_question(name="Large_Question"),
                # Many TXT records with large data to push packet size
                Block(
                    "Large_Answer1",
                    children=(
                        Static("L_A1_Name", b"\x08hostname\x05local\x00"),
                        Static("L_A1_Type", b"\x00\x10"),  # TXT
                        Static("L_A1_Class", b"\x00\x01"),  # IN
                        Static("L_A1_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("L_A1_RDLength", b"\x01\x00"),  # Length 256
                        Static("L_A1_RData", b"\xff" + b"X" * 255),  # Large TXT record
                    ),
                ),
                Block(
                    "Large_Answer2",
                    children=(
                        Static("L_A2_Name", b"\x08hostname\x05local\x00"),
                        Static("L_A2_Type", b"\x00\x10"),  # TXT
                        Static("L_A2_Class", b"\x00\x01"),  # IN
                        Static("L_A2_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("L_A2_RDLength", b"\x01\x00"),  # Length 256
                        Static("L_A2_RData", b"\xff" + b"Y" * 255),  # Large TXT record
                    ),
                ),
                Block(
                    "Large_Answer3",
                    children=(
                        Static("L_A3_Name", b"\x08hostname\x05local\x00"),
                        Static("L_A3_Type", b"\x00\x10"),  # TXT
                        Static("L_A3_Class", b"\x00\x01"),  # IN
                        Static("L_A3_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("L_A3_RDLength", b"\x01\x00"),  # Length 256
                        Static("L_A3_RData", b"\xff" + b"Z" * 255),  # Large TXT record
                    ),
                ),
            ),
        )

        # =================================================================
        # PHASE 3: CVE-Targeted Operations
        # Compression pointer attacks, EDNS abuse
        # =================================================================

        # Compressed label with invalid pointer (CVE-2020-8617 style)
        invalid_compression = Request(
            "Invalid_Compression",
            children=(
                self._create_dns_header(name="Compression_Header", qr=0, qdcount=1),
                Block(
                    "Bad_Question",
                    children=(
                        Static("Bad_Name", b"\xc0\xff"),  # Invalid compression pointer
                        Static("Bad_Type", b"\x00\x01"),  # A
                        Static("Bad_Class", b"\x00\x01"),  # IN
                    ),
                ),
            ),
        )

        # Circular compression pointer - infinite loop attack
        circular_compression = Request(
            "Circular_Compression",
            children=(
                self._create_dns_header(name="Circular_Header", qr=0, qdcount=1),
                Block(
                    "Circular_Question",
                    children=(
                        # Self-referencing pointer at offset 12 (header size)
                        Static("Circular_Name", b"\xc0\x0c"),  # Points to itself
                        Static("Circular_Type", b"\x00\x01"),  # A
                        Static("Circular_Class", b"\x00\x01"),  # IN
                    ),
                ),
            ),
        )

        # Nested compression pointers - deep recursion attack
        nested_compression = Request(
            "Nested_Compression",
            children=(
                Block(
                    "Nested_Header",
                    children=(
                        Word("ID", 0x1234, output_format="binary", endian=">"),
                        Word("Flags", 0x0000, output_format="binary", endian=">"),
                        Static("QDCount", b"\x00\x01"),
                        Static("ANCount", b"\x00\x00"),
                        Static("NSCount", b"\x00\x00"),
                        Static("ARCount", b"\x00\x00"),
                    ),
                ),
                # Chain of compression pointers: ptr1->ptr2->ptr3->actual_name
                Block(
                    "Nested_Question",
                    children=(
                        Static("NQ_Name", b"\x05local\x00"),  # Offset 12: actual name
                        Static("NQ_Ptr1", b"\xc0\x0c"),  # Offset 19: points to 12
                        Static("NQ_Ptr2", b"\xc0\x13"),  # Offset 21: points to 19
                        Static("NQ_Ptr3", b"\xc0\x15"),  # Offset 23: points to 21
                        Static("NQ_Type", b"\x00\x01"),
                        Static("NQ_Class", b"\x00\x01"),
                    ),
                ),
            ),
        )

        # EDNS0 with malformed options
        edns0_malformed = Request(
            "EDNS0_Malformed",
            children=(
                self._create_dns_header(name="EDNS0_Bad_Header", qr=0, qdcount=1, arcount=1),
                self._create_dns_question(name="EDNS0_Bad_Question"),
                Block(
                    "Bad_OPT_Record",
                    children=(
                        Static("Bad_OPT_Name", b"\x00"),
                        Static("Bad_OPT_Type", b"\x00\x29"),  # OPT
                        Static("Bad_OPT_UDP_Size", b"\xff\xff"),  # Max UDP size
                        Static("Bad_OPT_ExtRcode", b"\xff"),  # Invalid extended RCODE
                        Static("Bad_OPT_Version", b"\xff"),  # Invalid EDNS version
                        Static("Bad_OPT_Z", b"\xff\xff"),  # All flags set
                        Static("Bad_OPT_Data_Len", b"\x00\x10"),  # Claim 16 bytes
                        # But only provide 4 bytes - underflow
                        Static("Bad_OPT_Data", b"\x00\x00\x00\x00"),
                    ),
                ),
            ),
        )

        # =================================================================
        # PHASE 4: Boundary Attacks and Variable Counts
        # Test edge cases in parsing
        # =================================================================

        # Variable record count with fuzzing
        variable_records = Request(
            "Variable_Records",
            children=(
                Block(
                    "Variable_Header",
                    children=(
                        Word("ID", 0x1234, output_format="binary", endian=">"),
                        Word("Flags", 0x8400, output_format="binary", endian=">"),
                        # Fuzzable record counts
                        Group(
                            "VR_QDCount",
                            default_value=b"\x00\x02",  # matches the 2 appended questions
                            values=[
                                b"\x00\x00",  # 0 questions
                                b"\x00\x01",  # 1 question
                                b"\x00\x02",  # 2 questions
                                b"\x00\x05",  # 5 questions
                                b"\xff\xff",  # Max questions (invalid)
                            ],
                        ),
                        Group(
                            "VR_ANCount",
                            default_value=b"\x00\x03",  # matches the 3 appended answers
                            values=[
                                b"\x00\x00",  # 0 answers
                                b"\x00\x01",  # 1 answer
                                b"\x00\x03",  # 3 answers
                                b"\x00\x0a",  # 10 answers
                                b"\xff\xff",  # Max answers (invalid)
                            ],
                        ),
                        Group(
                            "VR_NSCount",
                            values=[
                                b"\x00\x00",  # 0 authority records
                                b"\x00\x01",  # 1 authority record
                                b"\x00\x03",  # 3 authority records
                                b"\xff\xff",  # Max authorities (invalid)
                            ],
                        ),
                        Group(
                            "VR_ARCount",
                            values=[
                                b"\x00\x00",  # 0 additional records
                                b"\x00\x01",  # 1 additional record
                                b"\x00\x05",  # 5 additional records
                                b"\xff\xff",  # Max additionals (invalid)
                            ],
                        ),
                    ),
                ),
                # Include actual records that may or may not match the counts
                # Question
                Block(
                    "VR_Question1",
                    children=(
                        Static("VR_Q1_Name", b"\x05_http\x04_tcp\x05local\x00"),
                        Static("VR_Q1_Type", b"\x00\x0c"),  # PTR
                        Static("VR_Q1_Class", b"\x00\x01"),  # IN
                    ),
                ),
                Block(
                    "VR_Question2",
                    children=(
                        Static("VR_Q2_Name", b"\x04_ipp\x04_tcp\x05local\x00"),
                        Static("VR_Q2_Type", b"\x00\x0c"),  # PTR
                        Static("VR_Q2_Class", b"\x00\x01"),  # IN
                    ),
                ),
                # Answers
                Block(
                    "VR_Answer1",
                    children=(
                        Static("VR_A1_Name", b"\x05_http\x04_tcp\x05local\x00"),
                        Static("VR_A1_Type", b"\x00\x0c"),  # PTR
                        Static("VR_A1_Class", b"\x00\x01"),  # IN
                        Static("VR_A1_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("VR_A1_RDLength", b"\x00\x1b"),  # auto: len(VR_A1_RData)=27
                        Static("VR_A1_RData", b"\x08WebShare\x05_http\x04_tcp\x05local\x00"),
                    ),
                ),
                Block(
                    "VR_Answer2",
                    children=(
                        Static("VR_A2_Name", b"\x04_ipp\x04_tcp\x05local\x00"),
                        Static("VR_A2_Type", b"\x00\x0c"),  # PTR
                        Static("VR_A2_Class", b"\x00\x01"),  # IN
                        Static("VR_A2_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("VR_A2_RDLength", b"\x00\x19"),  # auto: len(VR_A2_RData)=25
                        Static("VR_A2_RData", b"\x07Printer\x04_ipp\x04_tcp\x05local\x00"),
                    ),
                ),
                Block(
                    "VR_Answer3",
                    children=(
                        Static("VR_A3_Name", b"\x08WebShare\x05_http\x04_tcp\x05local\x00"),
                        Static("VR_A3_Type", b"\x00\x21"),  # SRV
                        Static("VR_A3_Class", b"\x00\x01"),  # IN
                        Static("VR_A3_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("VR_A3_RDLength", b"\x00\x12"),  # Length 18
                        Static("VR_A3_Priority", b"\x00\x00"),  # Priority 0
                        Static("VR_A3_Weight", b"\x00\x00"),  # Weight 0
                        Static("VR_A3_Port", b"\x00\x50"),  # Port 80
                        Static("VR_A3_Target", b"\x08webshare\x05local\x00"),  # Target hostname
                    ),
                ),
            ),
        )

        # Truncated packet test
        truncated_packet = Request(
            "Truncated_Packet",
            children=(
                Block(
                    "TC_Header",
                    children=(
                        Word("ID", 0x1234, output_format="binary", endian=">"),
                        Word("Flags", 0x8600, output_format="binary", endian=">"),
                        Static("QDCount", b"\x00\x01"),  # 1 question
                        Static("ANCount", b"\x00\x05"),  # 5 answers claimed
                        Static("NSCount", b"\x00\x00"),
                        Static("ARCount", b"\x00\x00"),
                    ),
                ),
                # Question
                Block(
                    "TC_Question",
                    children=(
                        Static("TC_Q_Name", b"\x05_http\x04_tcp\x05local\x00"),
                        Static("TC_Q_Type", b"\x00\x0c"),  # PTR
                        Static("TC_Q_Class", b"\x00\x01"),  # IN
                    ),
                ),
                # Just one answer instead of 5 claimed
                Block(
                    "TC_Answer1",
                    children=(
                        Static("TC_A1_Name", b"\x05_http\x04_tcp\x05local\x00"),
                        Static("TC_A1_Type", b"\x00\x0c"),  # PTR
                        Static("TC_A1_Class", b"\x00\x01"),  # IN
                        Static("TC_A1_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("TC_A1_RDLength", b"\x00\x1b"),  # auto: len(TC_A1_RData)=27
                        Static("TC_A1_RData", b"\x08WebShare\x05_http\x04_tcp\x05local\x00"),
                    ),
                ),
            ),
        )

        # Zero-length label attack
        zero_length_label = Request(
            "Zero_Length_Label",
            children=(
                self._create_dns_header(name="ZL_Header", qr=0, qdcount=1),
                Block(
                    "ZL_Question",
                    children=(
                        # Multiple zero-length labels
                        Static("ZL_Name", b"\x00\x00\x00\x00\x00"),
                        Static("ZL_Type", b"\x00\x01"),
                        Static("ZL_Class", b"\x00\x01"),
                    ),
                ),
            ),
        )

        # =================================================================
        # PHASE 5: Normal Operations and Edge Cases
        # Standard protocol operations with mutation
        # =================================================================

        # Standard query packet
        standard_query = Request(
            "Standard_Query",
            children=(
                self._create_dns_header(name="Query_Header", qr=0, qdcount=1),  # Query
                self._create_dns_question(name="Query_Question"),
            ),
        )

        # Zero-entry query packet
        zero_entry_query = Request(
            "Zero_Entry_Query",
            children=(
                self._create_dns_header(
                    name="Zero_Query_Header", qr=0
                ),  # Query with zero questions
            ),
        )

        # Multiple questions query packet
        multi_question_query = Request(
            "Multi_Question_Query",
            children=(
                Block(
                    "Multi_Header",
                    children=(
                        Word("ID", 0x1234, output_format="binary", endian=">"),
                        Word("Flags", 0x0000, output_format="binary", endian=">"),
                        # Multiple questions
                        Static("QDCount", b"\x00\x03"),  # 3 questions
                        Static("ANCount", b"\x00\x00"),
                        Static("NSCount", b"\x00\x00"),
                        Static("ARCount", b"\x00\x00"),
                    ),
                ),
                # First question - A record
                Block(
                    "Question1",
                    children=(
                        Static("Q1_Name", b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"),
                        Static("Q1_Type", b"\x00\x0c"),  # PTR
                        Static("Q1_Class", b"\x00\x01"),  # IN
                    ),
                ),
                # Second question - SRV record
                Block(
                    "Question2",
                    children=(
                        Static("Q2_Name", b"\x05_http\x04_tcp\x05local\x00"),
                        Static("Q2_Type", b"\x00\x0c"),  # PTR
                        Static("Q2_Class", b"\x00\x01"),  # IN
                    ),
                ),
                # Third question - ANY record
                Block(
                    "Question3",
                    children=(
                        Static("Q3_Name", b"\x04_ipp\x04_tcp\x05local\x00"),
                        Static("Q3_Type", b"\x00\xff"),  # ANY
                        Static("Q3_Class", b"\x00\x01"),  # IN
                    ),
                ),
            ),
        )

        # Standard response packet
        standard_response = Request(
            "Standard_Response",
            children=(
                self._create_dns_header(
                    name="Response_Header", qr=1, aa=1, qdcount=1, ancount=1, nscount=1, arcount=1
                ),  # Response, authoritative
                self._create_dns_question(name="Response_Question"),
                self._create_dns_rr(name="Answer_RR"),
                self._create_dns_rr(name="Authority_RR"),
                self._create_dns_rr(name="Additional_RR"),
            ),
        )

        # Multiple answers response packet
        multi_answer_response = Request(
            "Multi_Answer_Response",
            children=(
                Block(
                    "Multi_Answer_Header",
                    children=(
                        Word("ID", 0x1234, output_format="binary", endian=">"),
                        Word("Flags", 0x8400, output_format="binary", endian=">"),
                        # One question, multiple answers
                        Static("QDCount", b"\x00\x01"),  # 1 question
                        Static("ANCount", b"\x00\x03"),  # 3 answers
                        Static("NSCount", b"\x00\x00"),  # No authority records
                        Static("ARCount", b"\x00\x00"),  # No additional records
                    ),
                ),
                # Question
                Block(
                    "MA_Question",
                    children=(
                        Static("MA_Q_Name", b"\x05_http\x04_tcp\x05local\x00"),
                        Static("MA_Q_Type", b"\x00\x0c"),  # PTR
                        Static("MA_Q_Class", b"\x00\x01"),  # IN
                    ),
                ),
                # First Answer - PTR record
                Block(
                    "MA_Answer1",
                    children=(
                        Static("MA_A1_Name", b"\x05_http\x04_tcp\x05local\x00"),
                        Static("MA_A1_Type", b"\x00\x0c"),  # PTR
                        Static("MA_A1_Class", b"\x00\x01"),  # IN
                        Static("MA_A1_TTL", b"\x00\x00\x01\x2c"),  # TTL 300s
                        Static("MA_A1_RDLength", b"\x00\x1b"),  # auto: len(MA_A1_RData)=27
                        Static("MA_A1_RData", b"\x08WebShare\x05_http\x04_tcp\x05local\x00"),
                    ),
                ),
                # Second Answer - PTR record for different service
                Block(
                    "MA_Answer2",
                    children=(
                        Static("MA_A2_Name", b"\x05_http\x04_tcp\x05local\x00"),
                        Static("MA_A2_Type", b"\x00\x0c"),  # PTR
                        Static("MA_A2_Class", b"\x00\x01"),  # IN
                        Static("MA_A2_TTL", b"\x00\x00\x01\x2c"),  # TTL 300s
                        Static("MA_A2_RDLength", b"\x00\x1a"),  # Length 20
                        Static("MA_A2_RData", b"\x07Printer\x05_http\x04_tcp\x05local\x00"),
                    ),
                ),
                # Third Answer - SRV record
                Block(
                    "MA_Answer3",
                    children=(
                        Static("MA_A3_Name", b"\x08WebShare\x05_http\x04_tcp\x05local\x00"),
                        Static("MA_A3_Type", b"\x00\x21"),  # SRV
                        Static("MA_A3_Class", b"\x00\x01"),  # IN
                        Static("MA_A3_TTL", b"\x00\x00\x01\x2c"),  # TTL 300s
                        Static("MA_A3_RDLength", b"\x00\x16"),  # Length 18
                        Static("MA_A3_Priority", b"\x00\x00"),  # Priority 0
                        Static("MA_A3_Weight", b"\x00\x00"),  # Weight 0
                        Static("MA_A3_Port", b"\x00\x50"),  # Port 80
                        Static("MA_A3_Target", b"\x08webshare\x05local\x00"),  # Target hostname
                    ),
                ),
            ),
        )

        # Multiple records of mixed types
        mixed_records_response = Request(
            "Mixed_Records_Response",
            children=(
                Block(
                    "Mixed_Header",
                    children=(
                        Word("ID", 0x1234, output_format="binary", endian=">"),
                        Word("Flags", 0x8400, output_format="binary", endian=">"),
                        # Multiple entries in all sections
                        Static("QDCount", b"\x00\x01"),  # 1 question
                        Static("ANCount", b"\x00\x02"),  # 2 answers
                        Static("NSCount", b"\x00\x01"),  # 1 authority record
                        Static("ARCount", b"\x00\x03"),  # 3 additional records
                    ),
                ),
                # Question
                Block(
                    "MR_Question",
                    children=(
                        Static("MR_Q_Name", b"\x08hostname\x05local\x00"),
                        Static("MR_Q_Type", b"\x00\x01"),  # A record
                        Static("MR_Q_Class", b"\x00\x01"),  # IN
                    ),
                ),
                # First Answer - A record
                Block(
                    "MR_Answer1",
                    children=(
                        Static("MR_A1_Name", b"\x08hostname\x05local\x00"),
                        Static("MR_A1_Type", b"\x00\x01"),  # A
                        Static("MR_A1_Class", b"\x80\x01"),  # IN with cache flush
                        Static("MR_A1_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("MR_A1_RDLength", b"\x00\x04"),  # Length 4
                        Static("MR_A1_RData", b"\xc0\xa8\x01\x0a"),  # 192.168.1.10
                    ),
                ),
                # Second Answer - AAAA record
                Block(
                    "MR_Answer2",
                    children=(
                        Static("MR_A2_Name", b"\x08hostname\x05local\x00"),
                        Static("MR_A2_Type", b"\x00\x1c"),  # AAAA
                        Static("MR_A2_Class", b"\x80\x01"),  # IN with cache flush
                        Static("MR_A2_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("MR_A2_RDLength", b"\x00\x10"),  # Length 16
                        Static(
                            "MR_A2_RData",
                            b"\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x0c\x29\xff\xfe\x4a\xde\x44",
                        ),  # IPv6
                    ),
                ),
                # Authority Record - SOA
                Block(
                    "MR_Auth1",
                    children=(
                        Static("MR_Auth_Name", b"\x05local\x00"),
                        Static("MR_Auth_Type", b"\x00\x06"),  # SOA
                        Static("MR_Auth_Class", b"\x00\x01"),  # IN
                        Static("MR_Auth_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("MR_Auth_RDLength", b"\x00\x2b"),  # Length 34
                        Static(
                            "MR_Auth_RData",
                            # MNAME: ns.local
                            b"\x02ns\x05local\x00"
                            +
                            # RNAME: admin.local
                            b"\x05admin\x05local\x00"
                            +
                            # Serial, Refresh, Retry, Expire, Minimum
                            b"\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x12\x75\x00\x00\x00\x00\x0e",
                        ),
                    ),
                ),
                # Additional Record 1 - TXT
                Block(
                    "MR_Add1",
                    children=(
                        Static("MR_Add1_Name", b"\x08hostname\x05local\x00"),
                        Static("MR_Add1_Type", b"\x00\x10"),  # TXT
                        Static("MR_Add1_Class", b"\x00\x01"),  # IN
                        Static("MR_Add1_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("MR_Add1_RDLength", b"\x00\x11"),  # Length 16
                        Static("MR_Add1_RData", b"\x0fname=mycomputer\x00"),
                    ),
                ),
                # Additional Record 2 - SRV
                Block(
                    "MR_Add2",
                    children=(
                        Static("MR_Add2_Name", b"\x0f_companion-link\x04_tcp\x05local\x00"),
                        Static("MR_Add2_Type", b"\x00\x21"),  # SRV
                        Static("MR_Add2_Class", b"\x00\x01"),  # IN
                        Static("MR_Add2_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("MR_Add2_RDLength", b"\x00\x16"),  # Length 18
                        Static(
                            "MR_Add2_RData",
                            # Priority, Weight, Port
                            b"\x00\x00\x00\x00\x22\xb8"
                            +
                            # Target
                            b"\x08hostname\x05local\x00",
                        ),
                    ),
                ),
                # Additional Record 3 - NSEC
                Block(
                    "MR_Add3",
                    children=(
                        Static("MR_Add3_Name", b"\x08hostname\x05local\x00"),
                        Static("MR_Add3_Type", b"\x00\x2f"),  # NSEC
                        Static("MR_Add3_Class", b"\x00\x01"),  # IN
                        Static("MR_Add3_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("MR_Add3_RDLength", b"\x00\x18"),  # Length 18
                        Static(
                            "MR_Add3_RData",
                            # Next Domain Name
                            b"\x08hostname\x05local\x00"
                            +
                            # Type Bit Maps
                            b"\x00\x06\x40\x00\x00\x08\x00\x01",
                        ),
                    ),
                ),
            ),
        )

        # Service subtypes test
        service_subtypes = Request(
            "Service_Subtypes",
            children=(
                self._create_dns_header(name="Subtype_Header", qr=1, aa=1, qdcount=1, ancount=1),
                Block(
                    "Subtype_Question",
                    children=(
                        Static("ST_Q_Name", b"\x08_printer\x04_sub\x05_http\x04_tcp\x05local\x00"),
                        Static("ST_Q_Type", b"\x00\x0c"),  # PTR
                        Static("ST_Q_Class", b"\x00\x01"),  # IN
                    ),
                ),
                Block(
                    "Subtype_Answer",
                    children=(
                        Static("ST_A_Name", b"\x08_printer\x04_sub\x05_http\x04_tcp\x05local\x00"),
                        Static("ST_A_Type", b"\x00\x0c"),  # PTR
                        Static("ST_A_Class", b"\x00\x01"),  # IN
                        Static("ST_A_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("ST_A_RDLength", b"\x00\x1b"),  # auto: len(ST_A_RData)=27
                        Static("ST_A_RData", b"\x08LaserJet\x05_http\x04_tcp\x05local\x00"),
                    ),
                ),
            ),
        )

        # Unicast response bit testing (QU bit)
        unicast_response_query = Request(
            "Unicast_Response_Query",
            children=(
                self._create_dns_header(name="QU_Header", qr=0, qdcount=1),
                Block(
                    "QU_Question",
                    children=(
                        Static("QU_Name", b"\x08hostname\x05local\x00"),
                        Static("QU_Type", b"\x00\x01"),  # A record
                        Static("QU_Class", b"\x80\x01"),  # Top bit set = unicast response requested
                    ),
                ),
            ),
        )

        # Duplicate records test
        duplicate_records = Request(
            "Duplicate_Records",
            children=(
                self._create_dns_header(name="Dup_Header", qr=1, aa=1, qdcount=1, ancount=3),
                Block(
                    "Dup_Question",
                    children=(
                        Static("Dup_Q_Name", b"\x08hostname\x05local\x00"),
                        Static("Dup_Q_Type", b"\x00\x01"),  # A
                        Static("Dup_Q_Class", b"\x00\x01"),  # IN
                    ),
                ),
                # First instance of record
                Block(
                    "Dup_Answer1",
                    children=(
                        Static("Dup_A1_Name", b"\x08hostname\x05local\x00"),
                        Static("Dup_A1_Type", b"\x00\x01"),  # A
                        Static("Dup_A1_Class", b"\x00\x01"),  # IN
                        Static("Dup_A1_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("Dup_A1_RDLength", b"\x00\x04"),
                        Static("Dup_A1_RData", b"\xc0\xa8\x01\x0a"),  # 192.168.1.10
                    ),
                ),
                # Exactly same record (duplicate) with different TTL
                Block(
                    "Dup_Answer2",
                    children=(
                        Static("Dup_A2_Name", b"\x08hostname\x05local\x00"),
                        Static("Dup_A2_Type", b"\x00\x01"),  # A
                        Static("Dup_A2_Class", b"\x00\x01"),  # IN
                        Static("Dup_A2_TTL", b"\x00\x00\x01\x2c"),  # TTL 300s - different!
                        Static("Dup_A2_RDLength", b"\x00\x04"),
                        Static("Dup_A2_RData", b"\xc0\xa8\x01\x0a"),  # 192.168.1.10
                    ),
                ),
                # Same record with cache flush bit set
                Block(
                    "Dup_Answer3",
                    children=(
                        Static("Dup_A3_Name", b"\x08hostname\x05local\x00"),
                        Static("Dup_A3_Type", b"\x00\x01"),  # A
                        Static("Dup_A3_Class", b"\x80\x01"),  # IN with cache flush bit
                        Static("Dup_A3_TTL", b"\x00\x00\x01\x2c"),  # TTL 300s
                        Static("Dup_A3_RDLength", b"\x00\x04"),
                        Static("Dup_A3_RData", b"\xc0\xa8\x01\x0a"),  # 192.168.1.10
                    ),
                ),
            ),
        )

        # Multiple questions with known answers
        multi_known_answer = Request(
            "Multi_Known_Answer",
            children=(
                self._create_dns_header(name="MKA_Header", qr=0, qdcount=2, ancount=2),
                # First question
                Block(
                    "MKA_Question1",
                    children=(
                        Static("MKA_Q1_Name", b"\x05_http\x04_tcp\x05local\x00"),
                        Static("MKA_Q1_Type", b"\x00\x0c"),  # PTR
                        Static("MKA_Q1_Class", b"\x00\x01"),  # IN
                    ),
                ),
                # Second question
                Block(
                    "MKA_Question2",
                    children=(
                        Static("MKA_Q2_Name", b"\x04_ipp\x04_tcp\x05local\x00"),
                        Static("MKA_Q2_Type", b"\x00\x0c"),  # PTR
                        Static("MKA_Q2_Class", b"\x00\x01"),  # IN
                    ),
                ),
                # Known answer for first question
                Block(
                    "MKA_Answer1",
                    children=(
                        Static("MKA_A1_Name", b"\x05_http\x04_tcp\x05local\x00"),
                        Static("MKA_A1_Type", b"\x00\x0c"),  # PTR
                        Static("MKA_A1_Class", b"\x00\x01"),  # IN
                        Static("MKA_A1_TTL", b"\x00\x00\x00\x10"),  # TTL 16 seconds
                        Static("MKA_A1_RDLength", b"\x00\x1b"),  # auto: len(MKA_A1_RData)=27
                        Static("MKA_A1_RData", b"\x08WebShare\x05_http\x04_tcp\x05local\x00"),
                    ),
                ),
                # Known answer for second question
                Block(
                    "MKA_Answer2",
                    children=(
                        Static("MKA_A2_Name", b"\x04_ipp\x04_tcp\x05local\x00"),
                        Static("MKA_A2_Type", b"\x00\x0c"),  # PTR
                        Static("MKA_A2_Class", b"\x00\x01"),  # IN
                        Static("MKA_A2_TTL", b"\x00\x00\x00\x10"),  # TTL 16 seconds
                        Static("MKA_A2_RDLength", b"\x00\x1a"),  # auto: len(MKA_A2_RData)=26
                        Static("MKA_A2_RData", b"\x08Printer1\x04_ipp\x04_tcp\x05local\x00"),
                    ),
                ),
            ),
        )

        # Negative response with NSEC records
        negative_response = Request(
            "Negative_Response",
            children=(
                self._create_dns_header(name="NR_Header", qr=1, aa=1, qdcount=1, nscount=1),
                Block(
                    "NR_Question",
                    children=(
                        Static("NR_Q_Name", b"\x08hostname\x05local\x00"),
                        Static("NR_Q_Type", b"\x00\x1c"),  # AAAA record
                        Static("NR_Q_Class", b"\x00\x01"),  # IN
                    ),
                ),
                # No answers section (empty)
                # NSEC record in authority section showing which types exist
                Block(
                    "NR_Authority",
                    children=(
                        Static("NR_Auth_Name", b"\x08hostname\x05local\x00"),
                        Static("NR_Auth_Type", b"\x00\x2f"),  # NSEC
                        Static("NR_Auth_Class", b"\x00\x01"),  # IN
                        Static("NR_Auth_TTL", b"\x00\x00\x00\x78"),  # TTL 120s
                        Static("NR_Auth_RDLength", b"\x00\x0d"),  # Length 13
                        Static(
                            "NR_Auth_RData",
                            # Next Domain
                            b"\x08hostname\x05local\x00"
                            +
                            # Type Bit Maps - A record exists, AAAA doesn't
                            b"\x00\x02\x00\x02",
                        ),
                    ),
                ),
            ),
        )

        # PTR Query (Service Discovery)
        ptr_query = Request(
            "PTR_Query",
            children=(
                self._create_dns_header(name="PTR_Header", qr=0, qdcount=1),
                Block(
                    "PTR_Question",
                    children=(
                        Static("PTR_Name", b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"),
                        Static("PTR_Type", b"\x00\x0c"),  # PTR
                        Static("PTR_Class", b"\x00\x01"),  # IN
                    ),
                ),
            ),
        )

        # SRV Query (Service instance details)
        srv_query = Request(
            "SRV_Query",
            children=(
                self._create_dns_header(name="SRV_Header", qr=0, qdcount=1),
                Block(
                    "SRV_Question",
                    children=(
                        Static("SRV_Name", b"\x07MyPrint\x05_ipps\x04_tcp\x05local\x00"),
                        Static("SRV_Type", b"\x00\x21"),  # SRV
                        Static("SRV_Class", b"\x00\x01"),  # IN
                    ),
                ),
            ),
        )

        # Query with cache flush bit
        cache_flush_query = Request(
            "Cache_Flush_Query",
            children=(
                self._create_dns_header(name="Cache_Flush_Header", qr=0, qdcount=1),
                Block(
                    "Cache_Flush_Question",
                    children=(
                        Static("CF_Name", b"\x08hostname\x05local\x00"),
                        Static("CF_Type", b"\x00\x01"),  # A record
                        Static("CF_Class", b"\x80\x01"),  # IN with cache flush bit
                    ),
                ),
            ),
        )

        # Probe query (checking name uniqueness)
        probe_query = Request(
            "Probe_Query",
            children=(
                self._create_dns_header(name="Probe_Header", qr=0, qdcount=1, nscount=1),
                Block(
                    "Probe_Question",
                    children=(
                        Static("Probe_Name", b"\x08hostname\x05local\x00"),
                        Static("Probe_Type", b"\x00\x01"),  # A
                        Static("Probe_Class", b"\x00\x01"),  # IN
                    ),
                ),
                Block(
                    "Probe_AuthorityRR",
                    children=(
                        Static("Auth_Name", b"\x08hostname\x05local\x00"),
                        Static("Auth_Type", b"\x00\x01"),  # A
                        Static("Auth_Class", b"\x00\x01"),  # IN
                        Static("Auth_TTL", b"\x00\x00\x00\x00"),  # TTL 0 for probes
                        Static("Auth_RDLength", b"\x00\x04"),
                        Static("Auth_RData", b"\xc0\xa8\x01\x0a"),  # 192.168.1.10
                    ),
                ),
            ),
        )

        # Goodbye packet (announcing service termination)
        goodbye_packet = Request(
            "Goodbye_Packet",
            children=(
                self._create_dns_header(name="Goodbye_Header", qr=1, aa=1, ancount=1),
                Block(
                    "Goodbye_Answer",
                    children=(
                        Static("Goodbye_Name", b"\x07MyPrint\x05_ipps\x04_tcp\x05local\x00"),
                        Static("Goodbye_Type", b"\x00\x21"),  # SRV
                        Static("Goodbye_Class", b"\x00\x01"),  # IN
                        Static("Goodbye_TTL", b"\x00\x00\x00\x00"),  # TTL 0 for goodbye
                        # SRV record data with target
                        Static("Goodbye_RDLength", b"\x00\x08"),
                        Static("Goodbye_Priority", b"\x00\x00"),
                        Static("Goodbye_Weight", b"\x00\x00"),
                        Static("Goodbye_Port", b"\x00\x50"),  # Port 80
                        Static("Goodbye_Target", b"\xc0\x0c"),  # Compressed pointer
                    ),
                ),
            ),
        )

        # Packet with EDNS0 options
        edns0_packet = Request(
            "EDNS0_Packet",
            children=(
                self._create_dns_header(name="EDNS0_Header", qr=0, qdcount=1, arcount=1),
                self._create_dns_question(name="EDNS0_Question"),
                Block(
                    "OPT_Record",
                    children=(
                        Static("OPT_Name", b"\x00"),  # Root domain
                        Static("OPT_Type", b"\x00\x29"),  # OPT (41)
                        Static("OPT_UDP_Size", b"\x10\x00"),  # 4096 UDP size
                        Static("OPT_Higher_Bits", b"\x00"),  # Extended RCODE & flags
                        Static("OPT_EDNS0_Version", b"\x00"),  # EDNS version 0
                        Static("OPT_Z", b"\x80\x00"),  # DO bit set
                        Static("OPT_Data_Len", b"\x00\x0b"),  # 11 bytes of option data
                        # NSID option
                        Static("OPT_Option_Code", b"\x00\x03"),  # NSID
                        Static("OPT_Option_Len", b"\x00\x07"),
                        Static("OPT_Option_Data", b"nsid123"),
                    ),
                ),
            ),
        )

        # =================================================================
        # CONNECT REQUESTS IN OPTIMIZED ORDER
        # Phase 1: Quick Coverage (~30 seconds for all record types)
        # Phase 2: High-crash tests (overflow, buffer attacks)
        # Phase 3: CVE-targeted operations
        # Phase 4: Boundary attacks
        # Phase 5: Normal operations and edge cases
        # =================================================================

        # Phase 1: Quick Feature Sweep
        if self.is_request_enabled("Quick_Coverage"):
            self.session.connect(quick_coverage)  # All record types in one request

        # Phase 2: High-Crash Tests (move early for fast crash detection)
        if self.is_request_enabled("Malformed_Header"):
            self.session.connect(malformed_header)  # Invalid header fields
        if self.is_request_enabled("Long_Name"):
            self.session.connect(long_name)  # Buffer overflow via long names
        if self.is_request_enabled("Oversized_Packet"):
            self.session.connect(oversized_packet)  # UDP size limit attacks

        # Phase 3: CVE-Targeted Operations
        if self.is_request_enabled("Invalid_Compression"):
            self.session.connect(invalid_compression)  # CVE-2020-8617 style pointer attack
        if self.is_request_enabled("Circular_Compression"):
            self.session.connect(circular_compression)  # Infinite loop attack
        if self.is_request_enabled("Nested_Compression"):
            self.session.connect(nested_compression)  # Deep recursion attack
        if self.is_request_enabled("EDNS0_Malformed"):
            self.session.connect(edns0_malformed)  # EDNS0 parsing vulnerabilities

        # Phase 4: Boundary Attacks
        if self.is_request_enabled("Variable_Records"):
            self.session.connect(variable_records)  # Count mismatch attacks
        if self.is_request_enabled("Truncated_Packet"):
            self.session.connect(truncated_packet)  # TC bit with missing data
        if self.is_request_enabled("Zero_Length_Label"):
            self.session.connect(zero_length_label)  # Zero-length label attack

        # Phase 5: Normal Operations (comprehensive coverage)
        if self.is_request_enabled("Standard_Query"):
            self.session.connect(standard_query)  # Basic query
        if self.is_request_enabled("Zero_Entry_Query"):
            self.session.connect(zero_entry_query)  # Empty query
        if self.is_request_enabled("Multi_Question_Query"):
            self.session.connect(multi_question_query)  # Multiple questions
        if self.is_request_enabled("Standard_Response"):
            self.session.connect(standard_response)  # Basic response
        if self.is_request_enabled("Multi_Answer_Response"):
            self.session.connect(multi_answer_response)  # Multiple answers
        if self.is_request_enabled("Mixed_Records_Response"):
            self.session.connect(mixed_records_response)  # Mixed record types
        if self.is_request_enabled("Unicast_Response_Query"):
            self.session.connect(unicast_response_query)  # QU bit test
        if self.is_request_enabled("Duplicate_Records"):
            self.session.connect(duplicate_records)  # Duplicate handling
        if self.is_request_enabled("Service_Subtypes"):
            self.session.connect(service_subtypes)  # Service subtypes
        if self.is_request_enabled("Multi_Known_Answer"):
            self.session.connect(multi_known_answer)  # Known answer suppression
        if self.is_request_enabled("Negative_Response"):
            self.session.connect(negative_response)  # NSEC negative responses
        if self.is_request_enabled("PTR_Query"):
            self.session.connect(ptr_query)  # Service discovery
        if self.is_request_enabled("SRV_Query"):
            self.session.connect(srv_query)  # Service instance details
        if self.is_request_enabled("Cache_Flush_Query"):
            self.session.connect(cache_flush_query)  # Cache flush bit
        if self.is_request_enabled("Probe_Query"):
            self.session.connect(probe_query)  # Name uniqueness probe
        if self.is_request_enabled("Goodbye_Packet"):
            self.session.connect(goodbye_packet)  # Service termination
        if self.is_request_enabled("EDNS0_Packet"):
            self.session.connect(edns0_packet)  # EDNS0 extensions

        return self.session
