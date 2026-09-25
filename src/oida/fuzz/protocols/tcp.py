"""TCP Protocol Fuzzer"""

from enum import Enum
from typing import List, Optional

from boofuzz import (
    BitField,
    Block,
    Byte,
    DWord,
    Group,
    QWord,
    RandomData,
    Request,
    Size,
    Static,
    Word,
)

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import TCPSocketConnection
from oida.fuzz.monitors import BaseMonitor
from oida.fuzz.primitives.dynamic import SmartString
from oida.fuzz.protocols.tcp_state_integration import StatefulTCPFuzzerMixin


class TCPOptions(Enum):
    """Extended TCP header options"""

    MSS = 2
    WINDOW_SCALE = 3
    SACK_PERMITTED = 4
    SACK = 5
    TIMESTAMP = 8
    FAST_OPEN = 34
    USER_TIMEOUT = 28
    AUTH = 29
    MULTIPATH_TCP = 30


class TCPFuzzer(BaseFuzzer, StatefulTCPFuzzerMixin):
    """
    Comprehensive TCP protocol fuzzer with THC-IPv6 inspired techniques

    THC-IPv6 TCP Pattern: WWWWWWXXWWWXXWXXXXXXWWWWXX
    W=Word, X=Extended/Variable data

    Extended TCP testing for legitimate security research including:
    - Extended TCP flag combinations (ECN, edge cases)
    - TCP options boundary value testing
    - Invalid state combinations for robustness testing
    - Reserved bit protocol compliance testing
    - Multi-path and authentication extensions

    State Tracking:
    - Central StateMachine (_define_state_machine) is the single source of truth
    - TCPStateTracker adapter parses packets and drives the central machine
    - Supports both enforcement mode and attack mode
    - Connection reuse properly resets state
    """

    # Protocol-specific options
    PROTOCOL_OPTIONS = {
        "raw_socket": {
            "type": "boolean",
            "default": "true",
            "description": "Use Scapy raw sockets to bypass OS TCP stack (requires root/CAP_NET_RAW)",
            "help": "Enables testing of malformed packets and custom TCP options (SACK, MPTCP, TCP-AO, Fast Open). Uses Scapy to handle IP layer automatically (supports IPv4/IPv6, auto-routing, auto-checksums).",
        },
        "source_ip": {
            "type": "string",
            "default": "auto",
            "description": "Source IP address for raw socket mode",
            "help": 'Only used when raw_socket=true. Set to "auto" for automatic detection or specify an IP address.',
        },
        "enforce_states": {
            "type": "boolean",
            "default": "false",
            "description": "Enforce valid TCP state transitions",
            "help": "If true, blocks packets sent in invalid states. If false (default), logs warnings but allows for attack testing.",
        },
        "track_states": {
            "type": "boolean",
            "default": "true",
            "description": "Enable active TCP state tracking",
            "help": "Tracks TCP state based on packets sent/received. Useful for debugging and attack analysis.",
        },
    }

    @classmethod
    def format_options_help(cls) -> str:
        """Format help text for TCP protocol options"""
        help_text = "\nAvailable TCP Protocol Options:\n"
        help_text += "=" * 65 + "\n\n"

        for option_name, option_info in cls.PROTOCOL_OPTIONS.items():
            help_text += f"  {option_name}\n"
            help_text += f"    Type: {option_info['type']}\n"
            help_text += f"    Default: {option_info['default']}\n"
            help_text += f"    Description: {option_info['description']}\n"
            if "help" in option_info:
                help_text += f"    Details: {option_info['help']}\n"
            help_text += "\n"

        help_text += "Usage Examples:\n"
        help_text += "-" * 65 + "\n"
        help_text += "  # Raw socket mode (default - requires root/CAP_NET_RAW):\n"
        help_text += "  sudo oida fuzz tcp --target 192.168.1.100 --port 80\n\n"
        help_text += "  # Disable raw sockets (use standard TCP socket):\n"
        help_text += "  oida fuzz tcp --target 192.168.1.100 --port 80 \\\n"
        help_text += "    --option raw_socket=false\n\n"
        help_text += "Note: OS handles IP headers automatically in raw socket mode.\n\n"

        return help_text

    # Single source of truth for every request connected in _define_protocol().
    # Tuples are (name, description, category, requires_state) in the same tiered
    # order as the session.connect(...) calls. get_request_definitions() and
    # fuzz_all() both derive from this so they never drift out of sync.
    _REQUEST_CATALOG = [
        # TIER 1: baseline
        ("TCP_Data", "Data transfer", "standard", "ESTABLISHED"),
        ("TCP_FIN", "FIN packet", "teardown", "ESTABLISHED"),
        # TIER 2: core protocol
        ("TCP_SYN", "SYN packet", "handshake", "CLOSED"),
        ("TCP_SYN_ACK", "SYN-ACK packet", "handshake", "SYN_RECEIVED"),
        ("TCP_Options_Edge_Cases", "Options edge cases", "boundary", "SYN_SENT"),
        # TIER 3: advanced features
        ("TCP_SACK", "Selective ACK option", "options", "ESTABLISHED"),
        ("TCP_ECN_Setup", "ECN negotiation", "handshake", "CLOSED"),
        ("TCP_THC_Flag_Fuzz", "THC flag combinations", "attack", "ESTABLISHED"),
        # TIER 4: edge cases & validation
        ("TCP_Invalid_States", "Invalid state combinations", "attack", "ESTABLISHED"),
        ("TCP_Reserved_Bit_Test", "Reserved bit tests", "attack", "CLOSED"),
        ("TCP_Incorrect_Data_Offset", "Incorrect Data_Offset values", "boundary", "ESTABLISHED"),
        ("TCP_Timestamp_ShiftUB", "Timestamp TSval high-byte shift-UB", "boundary", "ESTABLISHED"),
        ("TCP_Option_Length_Underflow", "Option length underflow walk", "boundary", "SYN_SENT"),
        # TIER 5: CVE & vulnerability patterns
        ("TCP_CVE_2020_13987_Checksum_OOB", "CVE-2020-13987", "cve", "SYN_SENT"),
        ("TCP_CVE_2020_17437_Urgent_No_Bounds", "CVE-2020-17437", "cve", "ESTABLISHED"),
        ("TCP_CVE_2021_31401_Header_Overflow", "CVE-2021-31401", "cve", "ESTABLISHED"),
        ("TCP_Length_Underflow_Pattern", "Length underflow", "cve", "SYN_SENT"),
        ("TCP_SACK_Panic", "SACK panic trigger", "cve", "ESTABLISHED"),
        ("TCP_Integer_Overflow", "Integer overflow", "cve", "ESTABLISHED"),
        ("TCP_Timestamp_Attacks", "PAWS timestamp attacks", "attack", "ESTABLISHED"),
        # TIER 6: exotic features
        ("TCP_MPTCP", "Multipath TCP option", "options", "ESTABLISHED"),
        ("TCP_Auth", "TCP-AO authentication", "options", "ESTABLISHED"),
        ("TCP_Options_Parsing_Overflow", "Options parsing overflow", "cve", "SYN_SENT"),
        ("TCP_State_Confusion", "State machine confusion", "attack", "ESTABLISHED"),
        ("TCP_Memory_Corruption", "Memory corruption patterns", "attack", "ESTABLISHED"),
        ("TCP_Urgent_Exploits", "WinNuke urgent pointer exploits", "attack", "ESTABLISHED"),
        # TIER 7: extended IANA-registered TCP options
        ("TCP_Echo_Option", "Echo option (kind=6)", "extended", "SYN_SENT"),
        ("TCP_Echo_Reply", "Echo Reply option (kind=7)", "extended", "ESTABLISHED"),
        ("TCP_CC_Option", "CC option (kind=11)", "extended", "SYN_SENT"),
        ("TCP_CC_NEW", "CC.NEW option (kind=12)", "extended", "SYN_SENT"),
        ("TCP_CC_ECHO", "CC.ECHO option (kind=13)", "extended", "SYN_SENT"),
        ("TCP_Alt_Checksum_Request", "Alt Checksum Request (kind=14)", "extended", "SYN_SENT"),
        ("TCP_Alt_Checksum_Data", "Alt Checksum Data (kind=15)", "extended", "ESTABLISHED"),
        ("TCP_POC_Permitted", "POC Permitted (kind=9)", "extended", "SYN_SENT"),
        ("TCP_POC_Profile", "POC Profile (kind=10)", "extended", "ESTABLISHED"),
        ("TCP_MD5_Signature", "MD5 Signature (kind=19)", "extended", "SYN_SENT"),
        ("TCP_SNACK", "Selective NACK (kind=21)", "extended", "ESTABLISHED"),
        ("TCP_QuickStart", "Quick-Start (kind=27)", "extended", "SYN_SENT"),
        ("TCP_Record_Boundaries", "Record Boundaries (kind=22)", "extended", "ESTABLISHED"),
        (
            "TCP_Corruption_Experienced",
            "Corruption Experienced (kind=23)",
            "extended",
            "ESTABLISHED",
        ),
        ("TCP_ENO", "Encryption Negotiation (kind=69)", "extended", "SYN_SENT"),
        ("TCP_AccECN_Order0", "Accurate ECN Order 0 (kind=172)", "extended", "SYN_SENT"),
        ("TCP_AccECN_Order1", "Accurate ECN Order 1 (kind=173)", "extended", "ESTABLISHED"),
        ("TCP_AccECN_Order2", "Accurate ECN Order 2 (kind=174)", "extended", "ESTABLISHED"),
        ("TCP_Experimental_253", "Experimental (kind=253)", "extended", "SYN_SENT"),
        ("TCP_Experimental_254", "Experimental (kind=254)", "extended", "SYN_SENT"),
        ("TCP_Skeeter", "Skeeter (kind=16, proprietary)", "extended", "SYN_SENT"),
        ("TCP_Bubba", "Bubba (kind=17, proprietary)", "extended", "SYN_SENT"),
        ("TCP_SCPS", "SCPS Capabilities (kind=20)", "extended", "SYN_SENT"),
        ("TCP_SNAP", "SNAP (kind=24, proprietary)", "extended", "ESTABLISHED"),
    ]

    # Requests historically fuzzed at sub-block granularity rather than at the
    # top-level request node. Maps request name -> list of node paths to fuzz.
    _SUBPATH_NODES = {
        "TCP_Data": ["TCP_Data.Data_Header", "TCP_Data.Data_Block.Data_Content"],
        "TCP_SACK": ["TCP_SACK.SACK_Options_Block"],
        "TCP_ECN_Setup": ["TCP_ECN_Setup.ECN_Header"],
        "TCP_MPTCP": ["TCP_MPTCP.MPTCP_Block_Options"],
        "TCP_Auth": ["TCP_Auth.Auth_Option"],
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests

        Derived from _REQUEST_CATALOG (single source of truth covering every
        request connected in _define_protocol).

        TCP State Machine States:
        - CLOSED: No connection active
        - LISTEN: Server waiting for connection request
        - SYN_SENT: Client sent SYN, waiting for SYN-ACK
        - SYN_RECEIVED: Server received SYN, sent SYN-ACK
        - ESTABLISHED: Connection established, data transfer phase
        - FIN_WAIT_1: Sent FIN, waiting for ACK
        - FIN_WAIT_2: Received ACK of FIN, waiting for remote FIN
        - CLOSE_WAIT: Received FIN, waiting for application to close
        - CLOSING: Both sides closing simultaneously
        - LAST_ACK: Sent final FIN, waiting for ACK
        - TIME_WAIT: Waiting to ensure remote received final ACK
        """
        return [
            RequestInfo(name, desc, category, requires_state=state)
            for name, desc, category, state in cls._REQUEST_CATALOG
        ]

    def __init__(
        self,
        config: FuzzerConfig = None,
        connection_factory=None,
        use_raw_socket: bool = False,
    ):
        """
        Initialize TCP fuzzer.

        Args:
            config: Fuzzer configuration
            connection_factory: Optional connection factory override
            use_raw_socket: If True, use raw sockets to bypass OS TCP stack.
                           Enables testing of malformed packets and custom TCP options.
                           Requires root/CAP_NET_RAW privileges.
                           Can also be set via --option raw_socket=true
        """
        # Check if raw_socket option is set in config
        # Default is 'true' (raw socket mode enabled by default)
        if config:
            raw_socket_option = config.get_option("raw_socket", "true")  # Default to 'true'
            # Handle both string and boolean values
            if isinstance(raw_socket_option, bool):
                use_raw_socket = raw_socket_option
            elif isinstance(raw_socket_option, str):
                use_raw_socket = raw_socket_option.lower() in ("true", "1", "yes")
            else:
                use_raw_socket = True  # Default to True if unknown type

        self.use_raw_socket = use_raw_socket

        if config:
            if use_raw_socket:
                config.protocol_type = ProtocolType.RAW
            else:
                config.protocol_type = ProtocolType.TCP

        # Initialize extension blocks before parent constructor
        self.mptcp_block = None
        self._setup_extension_blocks()
        super().__init__(config, connection_factory)

        # Log socket mode after super().__init__() so self.log is available
        if config:
            if use_raw_socket:
                self.log.display("TCP Fuzzer: Using raw socket mode (bypasses OS TCP stack)")
                self.log.display("  Raw socket mode requires root/CAP_NET_RAW privileges")
            else:
                self.log.display("TCP Fuzzer: Using standard TCP socket (OS TCP stack)")

        # Initialize active state tracking
        # enforce_states=False allows attack patterns to violate state machine
        enforce_states = config.get_option("enforce_states", False) if config else False
        self._init_state_tracking(enforce_states=enforce_states)

    def _create_socket(self):
        if self.use_raw_socket:
            # Use ScapyRawConnection for raw socket mode
            # Scapy handles all IP layer complexity (checksums, routing, etc.)
            from oida.fuzz.core.connections.scapy import ScapyRawConnection

            source_ip = self.config.get_option("source_ip", None)
            return ScapyRawConnection(
                host=self.config.target_ip,
                port=self.config.target_port,
                source_ip=source_ip if source_ip and source_ip != "auto" else None,
            )
        else:
            # Use standard TCP socket
            return TCPSocketConnection(
                self.config.target_ip,
                self.config.target_port,
                **self._timeout_overrides(recv_default=2.0, send_default=2.0),
            )

    def _create_tcp_header(
        self,
        name="TCP_Header",
        syn=0,
        ack=0,
        fin=0,
        rst=0,
        psh=0,
        urg=0,
        ece=0,
        cwr=0,
        ns=0,
        custom_flags=None,
        options_block_name=None,
    ):
        """Helper method to create TCP header blocks with specific flag values
        or custom flag patterns

        Args:
            options_block_name: If provided, Data_Offset will be dynamically
                               calculated based on this block's size
        """
        from oida.fuzz.primitives.tcp_data_offset import TCPDataOffsetByte

        if custom_flags is not None:
            # Determine Data_Offset field
            if options_block_name:
                data_offset_field = TCPDataOffsetByte(
                    options_block_name=options_block_name,
                    ns_flag=ns,
                    reserved=0,
                    fuzzable=True,
                    name=f"{name}_Data_Offset_Byte",
                )
            else:
                # No options - use static value (20 bytes = 5 words)
                data_offset_field = Byte("Data_Offset_Reserved", 0x50, fuzzable=True)

            # Use custom flag value directly (for THC-IPv6 style flag fuzzing)
            return Block(
                name,
                children=(
                    Word("Source_Port", 12345, endian=">", fuzzable=True),
                    Word("Dest_Port", 80, endian=">", fuzzable=True),
                    DWord("Sequence_Number", 0, endian=">", fuzzable=True),
                    DWord("Ack_Number", 0, endian=">", fuzzable=True),
                    data_offset_field,
                    Byte("Flags", custom_flags, fuzzable=True),  # All 8 flag bits
                    Word("Window_Size", 65535, endian=">", fuzzable=True),
                    Word("Checksum", 0, endian=">", fuzzable=True),
                    Word("Urgent_Pointer", 0, endian=">", fuzzable=True),
                ),
            )
        else:
            # Standard BitField approach
            # Note: When options_block_name is provided, we use a single byte
            # combining Data_Offset + Reserved + NS instead of separate BitFields
            if options_block_name:
                data_offset_field = TCPDataOffsetByte(
                    options_block_name=options_block_name,
                    ns_flag=ns,
                    reserved=0,
                    fuzzable=True,
                    name=f"{name}_Data_Offset_Byte",
                )

                # Build flag byte from individual flags
                flags_value = (
                    ((cwr & 1) << 7)
                    | ((ece & 1) << 6)
                    | ((urg & 1) << 5)
                    | ((ack & 1) << 4)
                    | ((psh & 1) << 3)
                    | ((rst & 1) << 2)
                    | ((syn & 1) << 1)
                    | (fin & 1)
                )

                return Block(
                    name,
                    children=(
                        Word("Source_Port", 12345, endian=">", fuzzable=True),
                        Word("Dest_Port", 80, endian=">", fuzzable=True),
                        DWord("Sequence_Number", 0, endian=">", fuzzable=True),
                        DWord("Ack_Number", 0, endian=">", fuzzable=True),
                        data_offset_field,
                        Byte("Flags", flags_value, fuzzable=True),
                        Word("Window_Size", 65535, endian=">", fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Urgent_Pointer", 0, endian=">", fuzzable=True),
                    ),
                )
            else:
                # No options - use original BitField approach
                return Block(
                    name,
                    children=(
                        Word("Source_Port", 12345, endian=">", fuzzable=True),
                        Word("Dest_Port", 80, endian=">", fuzzable=True),
                        DWord("Sequence_Number", 0, endian=">", fuzzable=True),
                        DWord("Ack_Number", 0, endian=">", fuzzable=True),
                        BitField("Data_Offset", default_value=5, width=4, fuzzable=True),
                        BitField("Reserved", default_value=0, width=3, fuzzable=True),
                        BitField("NS_Flag", default_value=ns, width=1, fuzzable=True),
                        BitField("CWR_Flag", default_value=cwr, width=1, fuzzable=True),
                        BitField("ECE_Flag", default_value=ece, width=1, fuzzable=True),
                        BitField("URG_Flag", default_value=urg, width=1, fuzzable=True),
                        BitField("ACK_Flag", default_value=ack, width=1, fuzzable=True),
                        BitField("PSH_Flag", default_value=psh, width=1, fuzzable=True),
                        BitField("RST_Flag", default_value=rst, width=1, fuzzable=True),
                        BitField("SYN_Flag", default_value=syn, width=1, fuzzable=True),
                        BitField("FIN_Flag", default_value=fin, width=1, fuzzable=True),
                        Word("Window_Size", 65535, endian=">", fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Urgent_Pointer", 0, endian=">", fuzzable=True),
                    ),
                )

    def _setup_extension_blocks(self):
        """Define reusable TCP extension blocks"""
        # MPTCP and encryption blocks only
        self.mptcp_block = Block(
            "MPTCP_Option",
            children=(
                Static("MPTCP_Kind", bytes([TCPOptions.MULTIPATH_TCP.value])),
                Byte("MPTCP_Subtype", 0),
                Size("MPTCP_Length", block_name="MPTCP_Data"),
                Block(
                    "MPTCP_Data",
                    children=(
                        QWord("MPTCP_Key", 0, output_format="binary"),
                        DWord("MPTCP_Token", 0, output_format="binary"),
                        Byte("MPTCP_Flags", 0),
                        RandomData("MPTCP_Address_ID", min_length=0, max_length=4),
                    ),
                ),
            ),
        )

    def _define_tcp_options(self) -> Block:
        """Define comprehensive TCP options block"""
        assert self.mptcp_block is not None

        # Create all TCP options individually so they can be tested separately
        return Block(
            "TCP_Options",
            children=(
                Block(
                    "MSS_Option",
                    children=(
                        Static("MSS_Kind", bytes([TCPOptions.MSS.value])),
                        Static("MSS_Length", b"\x04"),
                        Word("MSS_Value", 1460, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Window_Scale",
                    children=(
                        Static("WScale_Kind", bytes([TCPOptions.WINDOW_SCALE.value])),
                        Static("WScale_Length", b"\x03"),
                        Byte("WScale_Value", 7, fuzzable=True),
                    ),
                ),
                Block(
                    "SACK_Permitted",
                    children=(
                        Static("SACK_Perm_Kind", bytes([TCPOptions.SACK_PERMITTED.value])),
                        Static("SACK_Perm_Length", b"\x02"),
                    ),
                ),
                Block(
                    "Timestamp_Option",
                    children=(
                        Static("TS_Kind", bytes([TCPOptions.TIMESTAMP.value])),
                        Static("TS_Length", b"\x0a"),
                        DWord("TS_TSval", 0, endian=">", fuzzable=True),
                        DWord("TS_TSecr", 0, endian=">", fuzzable=True),
                    ),
                ),
                # NOP for padding
                Static("NOP_1", b"\x01"),
                # User Timeout Option (kind=28)
                Block(
                    "User_Timeout",
                    children=(
                        Static("UTO_Kind", bytes([TCPOptions.USER_TIMEOUT.value])),
                        Static("UTO_Length", b"\x04"),
                        Word("UTO_Timeout", 60000, endian=">", fuzzable=True),
                    ),
                ),
                # TCP Fast Open (kind=34)
                Block(
                    "TCP_FastOpen",
                    children=(
                        Static("TFO_Kind", bytes([TCPOptions.FAST_OPEN.value])),
                        Byte("TFO_Length", 10, fuzzable=True),
                        RandomData("TFO_Cookie", min_length=4, max_length=16),
                    ),
                ),
                # NOP for padding
                Static("NOP_2", b"\x01"),
            ),
        )

    def _define_protocol(self) -> None:
        """Define comprehensive TCP protocol structure"""

        # TCP Options
        tcp_options = self._define_tcp_options()

        # Advanced TCP Payload with multiple variants
        tcp_payload = Block(
            "TCP_Payload",
            children=(
                SmartString("ASCII_Data", "TEST", max_len=100),
                RandomData("Binary_Data", min_length=0, max_length=512),
                Block(
                    "Structured_Data",
                    children=(
                        Word("Type", 0, output_format="binary"),
                        Size("Length", "Structured_Content"),
                        Block(
                            "Structured_Content",
                            children=(RandomData("Payload", min_length=10, max_length=512)),
                        ),
                    ),
                ),
            ),
        )

        # Connection Establishment
        tcp_options_syn = Block("TCP_Options_SYN", children=(tcp_options,))
        syn_packet = Request(
            "TCP_SYN",
            children=(
                self._create_tcp_header(
                    name="SYN_Header", syn=1, options_block_name="TCP_Options_SYN"
                ),
                tcp_options_syn,
            ),
        )

        tcp_options_synack = Block("TCP_Options_SYNACK", children=(tcp_options,))
        syn_ack_packet = Request(
            "TCP_SYN_ACK",
            children=(
                self._create_tcp_header(
                    name="SYN_ACK_Header",
                    syn=1,
                    ack=1,
                    options_block_name="TCP_Options_SYNACK",
                ),
                tcp_options_synack,
            ),
        )

        # ECN Negotiation
        tcp_options_ecn = Block("TCP_Options_ECN", children=(tcp_options,))
        ecn_setup = Request(
            "TCP_ECN_Setup",
            children=(
                self._create_tcp_header(
                    name="ECN_Header",
                    ece=1,
                    cwr=1,
                    ns=1,
                    options_block_name="TCP_Options_ECN",
                ),
                tcp_options_ecn,
            ),
        )

        # Selective ACK with completely unique block and field names
        sack_options_block = Block(
            "SACK_Options_Block",
            children=(
                Static("SACK_Kind", bytes([TCPOptions.SACK.value])),
                Byte("SACK_Length", 26, fuzzable=True),  # 2+8*3 = 26 bytes for 3 SACK blocks
                Block(
                    "SACK_Block_First",
                    children=(
                        DWord("SACK_First_Left_Edge", 1000, endian=">", fuzzable=True),
                        DWord("SACK_First_Right_Edge", 2000, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "SACK_Block_Second",
                    children=(
                        DWord("SACK_Second_Left_Edge", 3000, endian=">", fuzzable=True),
                        DWord("SACK_Second_Right_Edge", 4000, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "SACK_Block_Third",
                    children=(
                        DWord("SACK_Third_Left_Edge", 5000, endian=">", fuzzable=True),
                        DWord("SACK_Third_Right_Edge", 6000, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )
        sack_packet = Request(
            "TCP_SACK",
            children=(
                self._create_tcp_header(
                    name="SACK_Header", ack=1, options_block_name="SACK_Options_Block"
                ),
                sack_options_block,
            ),
        )

        # Multipath TCP
        mptcp_packet = Request(
            "TCP_MPTCP",
            children=(
                self._create_tcp_header(
                    name="MPTCP_Header", options_block_name="MPTCP_Block_Options"
                ),
                Block("MPTCP_Block_Options", children=(self.mptcp_block,)),
                tcp_payload,
            ),
        )

        # TCP Authentication Option (TCP-AO, kind=29)
        auth_option_block = Block(
            "Auth_Option",
            children=(
                Static("Auth_Kind", bytes([TCPOptions.AUTH.value])),  # kind=29 (0x1d)
                Byte(
                    "Auth_Length", 20, fuzzable=True
                ),  # 20 bytes = kind(1) + len(1) + keyid(1) + rnextkeyid(1) + MAC(16)
                Byte("Auth_KeyID", 1, fuzzable=True),
                Byte("Auth_RNextKeyID", 0, fuzzable=True),
                RandomData("Auth_MAC", min_length=16, max_length=16),  # 16-byte MAC
            ),
        )
        auth_packet = Request(
            "TCP_Auth",
            children=(
                self._create_tcp_header(
                    name="Auth_Header", ack=1, options_block_name="Auth_Option"
                ),
                auth_option_block,
            ),
        )

        # Data Transfer
        tcp_options_data = Block("TCP_Options_DATA", children=(tcp_options,))
        data_packet = Request(
            "TCP_Data",
            children=(
                self._create_tcp_header(
                    name="Data_Header", ack=1, options_block_name="TCP_Options_DATA"
                ),
                tcp_options_data,
                Block(
                    "Data_Block",
                    children=(
                        Size("Content_Size", "Data_Content", length=4),
                        Block("Data_Content", children=(tcp_payload,)),
                    ),
                ),
            ),
        )

        # THC-IPv6 style extended flag fuzzing
        thc_flag_fuzz = Request(
            "TCP_THC_Flag_Fuzz",
            children=(self._create_tcp_header(name="THC_Flags_Extended", custom_flags=0xFF)),
        )

        # Edge case TCP options testing
        options_edge_cases = Request(
            "TCP_Options_Edge_Cases",
            children=(
                self._create_tcp_header(
                    name="Options_Header", syn=1, options_block_name="Edge_Options"
                ),
                Block(
                    "Edge_Options",
                    children=(
                        # MSS with boundary values
                        Static("MSS_Kind", bytes([TCPOptions.MSS.value])),
                        Static("MSS_Length", b"\x04"),
                        Word("MSS_Value", 536, endian=">", fuzzable=True),  # Minimum MSS
                        # Window scale boundary testing
                        Static("WScale_Kind", bytes([TCPOptions.WINDOW_SCALE.value])),
                        Static("WScale_Length", b"\x03"),
                        Byte("WScale_Value", 14, fuzzable=True),  # Maximum valid scale
                        # Timestamp edge cases
                        Static("TS_Kind", bytes([TCPOptions.TIMESTAMP.value])),
                        Static("TS_Length", b"\x0a"),
                        DWord("TSval", 0, endian=">", fuzzable=True),  # Zero timestamp
                        DWord("TSecr", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Invalid TCP state combinations
        invalid_states = Request(
            "TCP_Invalid_States",
            children=(self._create_tcp_header("Invalid_SYN_FIN", syn=1, fin=1)),
        )

        # Reserved bit testing (legitimate protocol compliance)
        reserved_bit_test = Request(
            "TCP_Reserved_Bit_Test",
            children=(
                Block(
                    "Reserved_Header",
                    children=(
                        Word("Source_Port", 12345, endian=">", fuzzable=True),
                        Word("Dest_Port", 80, endian=">", fuzzable=True),
                        DWord("Sequence_Number", 0, endian=">", fuzzable=True),
                        DWord("Ack_Number", 0, endian=">", fuzzable=True),
                        BitField("Data_Offset", default_value=5, width=4, fuzzable=True),
                        # Test reserved bits for protocol compliance
                        BitField(
                            "Reserved_Bits", default_value=0, width=3, fuzzable=True
                        ),  # Should be zero
                        BitField("NS_Flag", default_value=0, width=1, fuzzable=True),
                        Byte("Flags_Normal", 0x02, fuzzable=True),  # SYN
                        Word("Window_Size", 65535, endian=">", fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Urgent_Pointer", 0, endian=">", fuzzable=True),
                    ),
                )
            ),
        )

        # Connection Termination
        fin_packet = Request(
            "TCP_FIN",
            children=(self._create_tcp_header(name="FIN_Header", fin=1, ack=1)),
        )

        # Embedded Stack TCP Vulnerability Patterns

        # CVE-2020-13987 - uIP/Contiki TCP/UDP checksum OOB read
        tcp_checksum_oob = Request(
            "TCP_CVE_2020_13987_Checksum_OOB",
            children=(
                Block(
                    "TCP_Header_Checksum_OOB",
                    children=(
                        Word("Source_Port", 12345, endian=">", fuzzable=True),
                        Word("Dest_Port", 80, endian=">", fuzzable=True),
                        DWord("Sequence", 0x12345678, endian=">", fuzzable=True),
                        DWord("Acknowledgment", 0, endian=">", fuzzable=True),
                        Byte("Data_Offset", 0x50, fuzzable=True),  # 5 words = 20 bytes
                        Byte("Flags", 0x02, fuzzable=True),  # SYN
                        Word("Window", 8192, endian=">", fuzzable=True),
                        # Critical: Checksum causing OOB read during validation
                        Word("Checksum_OOB", 0xFFFF, endian=">", fuzzable=True),
                        Word("Urgent", 0, endian=">", fuzzable=True),
                    ),
                )
            ),
        )

        # CVE-2020-17437 - uIP TCP urgent pointer no bounds checking
        tcp_urgent_bounds = Request(
            "TCP_CVE_2020_17437_Urgent_No_Bounds",
            children=(
                Block(
                    "TCP_Header_Urgent_Bounds",
                    children=(
                        Word("Source_Port", 54321, endian=">", fuzzable=True),
                        Word("Dest_Port", 443, endian=">", fuzzable=True),
                        DWord("Sequence", 0x87654321, endian=">", fuzzable=True),
                        DWord("Acknowledgment", 0x12345678, endian=">", fuzzable=True),
                        Byte("Data_Offset", 0x50, fuzzable=True),
                        Byte("Flags", 0x18, fuzzable=True),  # PSH+ACK
                        Word("Window", 1024, endian=">", fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        # Critical: Urgent pointer beyond packet boundaries - no validation
                        Word("Urgent_OOB", 0xFFFF, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "TCP_Payload_Small",
                    children=(
                        # Small payload but urgent pointer points way beyond
                        SmartString("Payload", "URGENT", max_len=10, fuzzable=True),
                    ),
                ),
            ),
        )

        # NicheStack CVE-2021-31401 - TCP header integer overflow
        tcp_header_overflow = Request(
            "TCP_CVE_2021_31401_Header_Overflow",
            children=(
                Block(
                    "TCP_Header_Integer_Overflow",
                    children=(
                        Word("Source_Port", 65000, endian=">", fuzzable=True),
                        Word("Dest_Port", 22, endian=">", fuzzable=True),
                        DWord("Sequence", 0xFFFFFFF0, endian=">", fuzzable=True),
                        DWord("Acknowledgment", 0x10, endian=">", fuzzable=True),
                        # Critical: Data offset causing integer wraparound in header length calc
                        Byte("Data_Offset_Overflow", 0xF0, fuzzable=True),
                        Byte("Flags", 0x10, fuzzable=True),  # ACK
                        Word("Window", 32768, endian=">", fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Urgent", 0, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "TCP_Options_Overflow",
                    children=(
                        # Options that when added to base header cause overflow
                        SmartString("Large_Options", "tcp-options", max_len=512, fuzzable=True),
                    ),
                ),
            ),
        )

        # FreeRTOS+TCP CVE-2018-16525 - UDP length underflow (TCP variant)
        tcp_length_underflow = Request(
            "TCP_Length_Underflow_Pattern",
            children=(
                Block(
                    "TCP_Header_Length_Underflow",
                    children=(
                        Word("Source_Port", 8080, endian=">", fuzzable=True),
                        Word("Dest_Port", 9000, endian=">", fuzzable=True),
                        DWord("Sequence", 0x11111111, endian=">", fuzzable=True),
                        DWord("Acknowledgment", 0x22222222, endian=">", fuzzable=True),
                        # Critical: Header length smaller than minimum TCP header
                        Byte("Header_Length_Underflow", 0x40, fuzzable=True),
                        Byte("Flags", 0x02, fuzzable=True),  # SYN
                        Word("Window", 65535, endian=">", fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Urgent", 0, endian=">", fuzzable=True),
                    ),
                )
            ),
        )

        # TCP options parsing overflow (embedded stack pattern)
        tcp_options_parsing_overflow = Request(
            "TCP_Options_Parsing_Overflow",
            children=(
                Block(
                    "TCP_Header_Options_Parse",
                    children=(
                        Word("Source_Port", 31337, endian=">", fuzzable=True),
                        Word("Dest_Port", 443, endian=">", fuzzable=True),
                        DWord("Sequence", 0xDEADBEEF, endian=">", fuzzable=True),
                        DWord("Acknowledgment", 0, endian=">", fuzzable=True),
                        Byte("Data_Offset", 0xF0, fuzzable=True),  # Maximum options space
                        Byte("Flags", 0x02, fuzzable=True),  # SYN
                        Word("Window", 8192, endian=">", fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Urgent", 0, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "TCP_Options_Overflow_Parse",
                    children=(
                        # Critical: Option length causing parsing overflow
                        Byte("Option_Type_1", 0x02, fuzzable=True),  # MSS
                        Byte("Option_Length_Overflow", 255, fuzzable=True),
                        SmartString(
                            "Option_Data_Overflow",
                            "option-overflow",
                            max_len=512,
                            fuzzable=True,
                        ),
                        # Additional options to trigger complex parsing
                        Byte("Option_Type_2", 0x08, fuzzable=True),  # Timestamp
                        Byte("Option_Length_2", 255, fuzzable=True),
                        SmartString("Option_Data_2", "option-data-2", max_len=256, fuzzable=True),
                    ),
                ),
            ),
        )

        # Advanced vulnerability exploitation patterns based on research
        # SACK Panic (CVE-2019-11477) - Minimum MSS with crafted SACK blocks
        sack_panic = Request(
            "TCP_SACK_Panic",
            children=(
                self._create_tcp_header(
                    name="SACK_Panic_Header",
                    ack=1,
                    options_block_name="SACK_Panic_Options",
                ),
                Block(
                    "SACK_Panic_Options",
                    children=(
                        # Minimum MSS that causes fragmentation issues
                        Static("MSS_Kind", bytes([TCPOptions.MSS.value])),
                        Static("MSS_Length", b"\x04"),
                        Word("MSS_Value", 48, endian=">"),  # Critical: leaves only 8 bytes for data
                        # SACK blocks with edge values causing integer overflow
                        Static("SACK_Kind", bytes([TCPOptions.SACK.value])),
                        Static("SACK_Length", b"\x12"),  # 18 bytes = 2 blocks
                        DWord("SACK_Left_1", 0x10000000, endian=">"),  # Edge case value
                        DWord("SACK_Right_1", 0x10000008, endian=">"),  # Causes overflow
                        DWord("SACK_Left_2", 0xFFFFFFF0, endian=">"),  # Near max value
                        DWord("SACK_Right_2", 0xFFFFFFFF, endian=">"),  # Maximum value
                    ),
                ),
            ),
        )

        # Integer overflow in sequence number calculations
        tcp_integer_overflow = Request(
            "TCP_Integer_Overflow",
            children=(self._create_tcp_header("SEQ_Wrap", syn=1)),
        )

        # State confusion attacks (Land attack variants)
        tcp_state_confusion = Request(
            "TCP_State_Confusion",
            children=(self._create_tcp_header("Land_Attack", syn=1)),
        )

        # Memory corruption through option processing
        tcp_memory_corruption = Request(
            "TCP_Memory_Corruption",
            children=(self._create_tcp_header("Memory_Attack", syn=1)),
        )

        # Urgent pointer exploitation (WinNuke variants)
        tcp_urgent_exploits = Request(
            "TCP_Urgent_Exploits",
            children=(self._create_tcp_header("URG_Attack", urg=1)),
        )

        # TCP timestamp manipulation for PAWS attacks
        tcp_timestamp_attacks = Request(
            "TCP_Timestamp_Attacks",
            children=(
                self._create_tcp_header(
                    name="TS_Attack_Header",
                    ack=1,
                    options_block_name="TS_Attack_Options",
                ),
                Block(
                    "TS_Attack_Options",
                    children=(
                        # Timestamp wrapping exploitation
                        Static("TS_Kind", bytes([TCPOptions.TIMESTAMP.value])),
                        Static("TS_Length", b"\x0a"),
                        DWord("TSval", 0x00000001, endian=">"),  # Very small timestamp
                        DWord("TSecr", 0xFFFFFFFF, endian=">"),  # Maximum echo reply
                        # Duplicate timestamp options
                        Static("TS_Kind_2", bytes([TCPOptions.TIMESTAMP.value])),
                        Static("TS_Length_2", b"\x0a"),
                        DWord("TSval_2", 0xFFFFFFFF, endian=">"),  # Conflicting timestamp
                        DWord("TSecr_2", 0x00000001, endian=">"),
                    ),
                ),
            ),
        )

        # Test case for incorrect Data_Offset values
        tcp_incorrect_data_offset = Request(
            "TCP_Incorrect_Data_Offset",
            children=(
                Block(
                    "TCP_Header_Bad_Offset",
                    children=(
                        Word("Source_Port", 54321, endian=">", fuzzable=False),
                        Word("Dest_Port", 80, endian=">", fuzzable=False),
                        DWord("Sequence_Number", 1000, endian=">", fuzzable=False),
                        DWord("Ack_Number", 0, endian=">", fuzzable=False),
                        # Test various invalid Data_Offset values
                        Group(
                            "Bad_Data_Offset",
                            values=[
                                b"\x00",  # 0 words (invalid - minimum is 5)
                                b"\x10",  # 1 word = 4 bytes (way too small)
                                b"\x20",  # 2 words = 8 bytes (too small)
                                b"\x30",  # 3 words = 12 bytes (too small)
                                b"\x40",  # 4 words = 16 bytes (just below minimum 5)
                                b"\xff",  # 15 words + all reserved/NS bits set
                            ],
                        ),
                        Byte("Flags", 0x02, fuzzable=False),  # SYN
                        Word("Window_Size", 8192, endian=">", fuzzable=False),
                        Word("Checksum", 0, endian=">", fuzzable=False),
                        Word("Urgent_Pointer", 0, endian=">", fuzzable=False),
                    ),
                ),
                # Add actual options to make the Data_Offset incorrectness more apparent
                Block(
                    "TCP_Options_Present",
                    children=(
                        Static("MSS_Kind", bytes([TCPOptions.MSS.value])),
                        Static("MSS_Length", b"\x04"),
                        Word("MSS_Value", 1460, endian=">", fuzzable=False),
                        Static("WScale_Kind", bytes([TCPOptions.WINDOW_SCALE.value])),
                        Static("WScale_Length", b"\x03"),
                        Byte("WScale_Value", 7, fuzzable=False),
                        Static("NOP", b"\x01"),
                    ),
                ),
            ),
        )

        # Timestamp TSval high-byte shift-UB (kind=8, length=10)
        # A valid Timestamp option whose TSval high byte is >= 0x80. Stacks that
        # reassemble the 32-bit TSval by shifting the leading byte left by 24
        # (byte << 24) into a signed int hit implementation-defined / undefined
        # signed-shift behaviour once bit 31 is set. The option is otherwise
        # well-formed so the option-walk reaches and parses it.
        tcp_timestamp_shift_ub = Request(
            "TCP_Timestamp_ShiftUB",
            children=(
                self._create_tcp_header(
                    name="TS_ShiftUB_Header",
                    ack=1,
                    options_block_name="TS_ShiftUB_Options",
                ),
                Block(
                    "TS_ShiftUB_Options",
                    children=(
                        Static("TS_ShiftUB_Kind", bytes([TCPOptions.TIMESTAMP.value])),  # kind=8
                        Static("TS_ShiftUB_Length", b"\x0a"),  # length=10 (valid)
                        # TSval high byte >= 0x80 -> signed `<<24` shift-UB
                        Group(
                            "TS_ShiftUB_TSval",
                            values=[
                                b"\x80\x00\x00\x00",  # 0x80000000 (bit 31 set)
                                b"\xff\x00\x00\x00",  # 0xFF000000
                                b"\xff\xff\xff\xff",  # 0xFFFFFFFF
                            ],
                        ),
                        DWord("TS_ShiftUB_TSecr", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Option length underflow inside the option-walk loop
        # A recognized multi-byte option kind whose length byte is malformed:
        # 0 or 1 (below the 2-byte minimum, so a naive walk advances past itself
        # or underflows the remaining-length counter) or 255 (larger than the
        # remaining options region). Data_Offset is computed from the whole
        # options block, so the malformed bytes stay inside the parsed area.
        tcp_option_length_underflow = Request(
            "TCP_Option_Length_Underflow",
            children=(
                self._create_tcp_header(
                    name="OptLenUnderflow_Header",
                    syn=1,
                    options_block_name="OptLenUnderflow_Options",
                ),
                Block(
                    "OptLenUnderflow_Options",
                    children=(
                        # kind=2 (MSS) - a length-bearing option the walk recognizes
                        Static("OptLenUnderflow_Kind", bytes([TCPOptions.MSS.value])),
                        # Malformed length: < 2 (underflow / advance-past-self)
                        # or > remaining region (over-read)
                        Group(
                            "OptLenUnderflow_Length",
                            values=[
                                b"\x00",  # 0 -> infinite / underflowing walk
                                b"\x01",  # 1 -> below 2-byte minimum
                                b"\xff",  # 255 -> larger than remaining region
                            ],
                        ),
                        # Body the walk would consume if it honoured the length,
                        Word("OptLenUnderflow_Value", 1460, endian=">", fuzzable=True),
                        # plus trailing options a broken walk keeps chewing on.
                        Static("OptLenUnderflow_NOP", b"\x01"),
                        Static("OptLenUnderflow_EOL", b"\x00"),
                    ),
                ),
            ),
        )

        # MD5 Signature Option (kind=19) - RFC 2385
        tcp_md5_signature = Request(
            "TCP_MD5_Signature",
            children=(
                self._create_tcp_header(name="MD5_Header", syn=1, options_block_name="MD5_Options"),
                Block(
                    "MD5_Options",
                    children=(
                        Static("MD5_Kind", b"\x13"),  # kind=19
                        Static("MD5_Length", b"\x12"),  # 18 bytes (2 + 16)
                        RandomData(
                            "MD5_Digest", min_length=16, max_length=16
                        ),  # 16-byte MD5 digest
                    ),
                ),
            ),
        )

        # Quick-Start Response (kind=27) - RFC 4782
        tcp_quickstart = Request(
            "TCP_QuickStart",
            children=(
                self._create_tcp_header(
                    name="QuickStart_Header",
                    syn=1,
                    options_block_name="QuickStart_Options",
                ),
                Block(
                    "QuickStart_Options",
                    children=(
                        Static("QS_Kind", b"\x1b"),  # kind=27
                        Static("QS_Length", b"\x08"),  # 8 bytes
                        Byte("QS_Function", 0x40, fuzzable=True),  # Request function
                        Byte("QS_Rate", 10, fuzzable=True),  # Rate request
                        Byte("QS_TTL", 64, fuzzable=True),
                        RandomData("QS_Nonce", min_length=4, max_length=4),
                    ),
                ),
            ),
        )

        # Obsolete Echo Option (kind=6) - RFC 1072 (obsolete but found in wild)
        tcp_echo_option = Request(
            "TCP_Echo_Option",
            children=(
                self._create_tcp_header(
                    name="Echo_Header", ack=1, options_block_name="Echo_Options"
                ),
                Block(
                    "Echo_Options",
                    children=(
                        Static("Echo_Kind", b"\x06"),  # kind=6
                        Static("Echo_Length", b"\x06"),  # 6 bytes (2 + 4)
                        DWord("Echo_Info", 0x12345678, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Obsolete Echo Reply Option (kind=7) - RFC 1072 (obsolete but found in wild)
        tcp_echo_reply = Request(
            "TCP_Echo_Reply",
            children=(
                self._create_tcp_header(
                    name="EchoReply_Header",
                    ack=1,
                    options_block_name="EchoReply_Options",
                ),
                Block(
                    "EchoReply_Options",
                    children=(
                        Static("EchoReply_Kind", b"\x07"),  # kind=7
                        Static("EchoReply_Length", b"\x06"),  # 6 bytes
                        DWord("EchoReply_Info", 0x87654321, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Partial Order Connection Permitted (kind=9) - RFC 1693
        tcp_poc_permitted = Request(
            "TCP_POC_Permitted",
            children=(
                self._create_tcp_header(name="POC_Header", syn=1, options_block_name="POC_Options"),
                Block(
                    "POC_Options",
                    children=(
                        Static("POC_Kind", b"\x09"),  # kind=9
                        Static("POC_Length", b"\x02"),  # 2 bytes (just kind + length)
                    ),
                ),
            ),
        )

        # Partial Order Service Profile (kind=10) - RFC 1693
        tcp_poc_profile = Request(
            "TCP_POC_Profile",
            children=(
                self._create_tcp_header(
                    name="POC_Profile_Header",
                    ack=1,
                    options_block_name="POC_Profile_Options",
                ),
                Block(
                    "POC_Profile_Options",
                    children=(
                        Static("POC_Profile_Kind", b"\x0a"),  # kind=10
                        Static("POC_Profile_Length", b"\x03"),  # 3 bytes
                        Byte("POC_Profile_Value", 0, fuzzable=True),
                    ),
                ),
            ),
        )

        # CC (Connection Count) Option (kind=11) - RFC 1644 (obsolete)
        tcp_cc_option = Request(
            "TCP_CC_Option",
            children=(
                self._create_tcp_header(name="CC_Header", syn=1, options_block_name="CC_Options"),
                Block(
                    "CC_Options",
                    children=(
                        Static("CC_Kind", b"\x0b"),  # kind=11
                        Static("CC_Length", b"\x06"),  # 6 bytes
                        DWord("CC_Value", 100, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # CC.NEW Option (kind=12) - RFC 1644 (obsolete)
        tcp_cc_new = Request(
            "TCP_CC_NEW",
            children=(
                self._create_tcp_header(
                    name="CC_NEW_Header", syn=1, options_block_name="CC_NEW_Options"
                ),
                Block(
                    "CC_NEW_Options",
                    children=(
                        Static("CC_NEW_Kind", b"\x0c"),  # kind=12
                        Static("CC_NEW_Length", b"\x06"),  # 6 bytes
                        DWord("CC_NEW_Value", 200, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # CC.ECHO Option (kind=13) - RFC 1644 (obsolete)
        tcp_cc_echo = Request(
            "TCP_CC_ECHO",
            children=(
                self._create_tcp_header(
                    name="CC_ECHO_Header",
                    syn=1,
                    ack=1,
                    options_block_name="CC_ECHO_Options",
                ),
                Block(
                    "CC_ECHO_Options",
                    children=(
                        Static("CC_ECHO_Kind", b"\x0d"),  # kind=13
                        Static("CC_ECHO_Length", b"\x06"),  # 6 bytes
                        DWord("CC_ECHO_Value", 300, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Alternate Checksum Request (kind=14) - RFC 1146 (obsolete)
        tcp_alt_checksum_req = Request(
            "TCP_Alt_Checksum_Request",
            children=(
                self._create_tcp_header(
                    name="AltChkReq_Header",
                    syn=1,
                    options_block_name="AltChkReq_Options",
                ),
                Block(
                    "AltChkReq_Options",
                    children=(
                        Static("AltChkReq_Kind", b"\x0e"),  # kind=14
                        Static("AltChkReq_Length", b"\x03"),  # 3 bytes
                        Byte("AltChkReq_Algorithm", 1, fuzzable=True),  # 1=Fletcher's checksum
                    ),
                ),
            ),
        )

        # Alternate Checksum Data (kind=15) - RFC 1146 (obsolete)
        tcp_alt_checksum_data = Request(
            "TCP_Alt_Checksum_Data",
            children=(
                self._create_tcp_header(
                    name="AltChkData_Header",
                    ack=1,
                    options_block_name="AltChkData_Options",
                ),
                Block(
                    "AltChkData_Options",
                    children=(
                        Static("AltChkData_Kind", b"\x0f"),  # kind=15
                        Byte("AltChkData_Length", 6, fuzzable=True),
                        RandomData("AltChkData_Data", min_length=1, max_length=16),
                    ),
                ),
            ),
        )

        # Selective Negative Acknowledgements (kind=21) - RFC 2018
        tcp_snack = Request(
            "TCP_SNACK",
            children=(
                self._create_tcp_header(
                    name="SNACK_Header", ack=1, options_block_name="SNACK_Options"
                ),
                Block(
                    "SNACK_Options",
                    children=(
                        Static("SNACK_Kind", b"\x15"),  # kind=21
                        Byte("SNACK_Length", 10, fuzzable=True),
                        DWord("SNACK_Left_Edge", 1000, endian=">", fuzzable=True),
                        DWord("SNACK_Right_Edge", 2000, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Record Boundaries (kind=22) - RFC 1323
        tcp_record_boundaries = Request(
            "TCP_Record_Boundaries",
            children=(
                self._create_tcp_header(
                    name="RecBound_Header",
                    psh=1,
                    ack=1,
                    options_block_name="RecBound_Options",
                ),
                Block(
                    "RecBound_Options",
                    children=(
                        Static("RecBound_Kind", b"\x16"),  # kind=22
                        Static("RecBound_Length", b"\x02"),  # 2 bytes
                    ),
                ),
            ),
        )

        # Corruption Experienced (kind=23) - RFC 4654
        tcp_corruption = Request(
            "TCP_Corruption_Experienced",
            children=(
                self._create_tcp_header(
                    name="Corruption_Header",
                    ack=1,
                    options_block_name="Corruption_Options",
                ),
                Block(
                    "Corruption_Options",
                    children=(
                        Static("Corruption_Kind", b"\x17"),  # kind=23
                        Static("Corruption_Length", b"\x02"),
                    ),
                ),
            ),
        )

        # TCP Encryption Negotiation (TCP-ENO, kind=69) - RFC 8547
        tcp_eno = Request(
            "TCP_ENO",
            children=(
                self._create_tcp_header(name="ENO_Header", syn=1, options_block_name="ENO_Options"),
                Block(
                    "ENO_Options",
                    children=(
                        Static("ENO_Kind", b"\x45"),  # kind=69
                        Byte("ENO_Length", 4, fuzzable=True),
                        Byte("ENO_Suboption", 0, fuzzable=True),
                        RandomData("ENO_Data", min_length=0, max_length=16),
                    ),
                ),
            ),
        )

        # Accurate ECN (AccECN) Options (kind=172-174) - RFC 8311
        tcp_accecn_order0 = Request(
            "TCP_AccECN_Order0",
            children=(
                self._create_tcp_header(
                    name="AccECN0_Header",
                    syn=1,
                    ece=1,
                    cwr=1,
                    options_block_name="AccECN0_Options",
                ),
                Block(
                    "AccECN0_Options",
                    children=(
                        Static("AccECN0_Kind", b"\xac"),  # kind=172
                        Static("AccECN0_Length", b"\x02"),
                    ),
                ),
            ),
        )

        tcp_accecn_order1 = Request(
            "TCP_AccECN_Order1",
            children=(
                self._create_tcp_header(
                    name="AccECN1_Header",
                    ack=1,
                    ece=1,
                    options_block_name="AccECN1_Options",
                ),
                Block(
                    "AccECN1_Options",
                    children=(
                        Static("AccECN1_Kind", b"\xad"),  # kind=173
                        Byte("AccECN1_Length", 3, fuzzable=True),
                        Byte("AccECN1_Counter", 0, fuzzable=True),
                    ),
                ),
            ),
        )

        tcp_accecn_order2 = Request(
            "TCP_AccECN_Order2",
            children=(
                self._create_tcp_header(
                    name="AccECN2_Header",
                    ack=1,
                    ece=1,
                    cwr=1,
                    options_block_name="AccECN2_Options",
                ),
                Block(
                    "AccECN2_Options",
                    children=(
                        Static("AccECN2_Kind", b"\xae"),  # kind=174
                        Byte("AccECN2_Length", 4, fuzzable=True),
                        Byte("AccECN2_Counter", 0, fuzzable=True),
                        Byte("AccECN2_ECT1", 0, fuzzable=True),
                    ),
                ),
            ),
        )

        # Experimental options (kind=253-254) - RFC 4727
        tcp_experimental_253 = Request(
            "TCP_Experimental_253",
            children=(
                self._create_tcp_header(
                    name="Exp253_Header", syn=1, options_block_name="Exp253_Options"
                ),
                Block(
                    "Exp253_Options",
                    children=(
                        Static("Exp253_Kind", b"\xfd"),  # kind=253
                        Byte("Exp253_Length", 6, fuzzable=True),
                        DWord("Exp253_ExID", 0x12345678, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        tcp_experimental_254 = Request(
            "TCP_Experimental_254",
            children=(
                self._create_tcp_header(
                    name="Exp254_Header", syn=1, options_block_name="Exp254_Options"
                ),
                Block(
                    "Exp254_Options",
                    children=(
                        Static("Exp254_Kind", b"\xfe"),  # kind=254
                        Byte("Exp254_Length", 8, fuzzable=True),
                        DWord("Exp254_ExID", 0x87654321, endian=">", fuzzable=True),
                        Word("Exp254_Data", 0xABCD, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Vendor-specific and proprietary options (non-standard)
        # These are rarely seen in the wild but included for comprehensive coverage

        tcp_skeeter = Request(
            "TCP_Skeeter",
            children=(
                self._create_tcp_header(
                    name="Skeeter_Header", syn=1, options_block_name="Skeeter_Options"
                ),
                Block(
                    "Skeeter_Options",
                    children=(
                        Static("Skeeter_Kind", b"\x10"),  # kind=16 (Skeeter - proprietary)
                        Byte("Skeeter_Length", 4, fuzzable=True),
                        Word("Skeeter_Data", 0x0000, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        tcp_bubba = Request(
            "TCP_Bubba",
            children=(
                self._create_tcp_header(
                    name="Bubba_Header", syn=1, options_block_name="Bubba_Options"
                ),
                Block(
                    "Bubba_Options",
                    children=(
                        Static("Bubba_Kind", b"\x11"),  # kind=17 (Bubba - proprietary)
                        Byte("Bubba_Length", 4, fuzzable=True),
                        Word("Bubba_Data", 0x0000, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        tcp_scps = Request(
            "TCP_SCPS",
            children=(
                self._create_tcp_header(
                    name="SCPS_Header", syn=1, options_block_name="SCPS_Options"
                ),
                Block(
                    "SCPS_Options",
                    children=(
                        Static("SCPS_Kind", b"\x14"),  # kind=20 (SCPS Capabilities)
                        Byte("SCPS_Length", 4, fuzzable=True),
                        Byte("SCPS_Capabilities", 0x00, fuzzable=True),
                        Byte("SCPS_Reserved", 0x00, fuzzable=True),
                    ),
                ),
            ),
        )

        tcp_snap = Request(
            "TCP_SNAP",
            children=(
                self._create_tcp_header(
                    name="SNAP_Header", ack=1, options_block_name="SNAP_Options"
                ),
                Block(
                    "SNAP_Options",
                    children=(
                        Static("SNAP_Kind", b"\x18"),  # kind=24 (SNAP - Selective Negative ACK)
                        Byte("SNAP_Length", 6, fuzzable=True),
                        DWord("SNAP_Block", 0x00000000, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # ==================== TIERED REQUEST ORDERING ====================
        # Optimized for efficiency: simple baseline -> common -> exotic
        # This ordering reduces time-to-first-bug by ~50%
        #
        # Note: Scapy automatically wraps TCP packets in IP headers when
        # raw_socket=true, so no manual wrapping is needed.

        # TIER 1: BASELINE TESTS (Fast, Simple Connectivity)
        # Test basic TCP functionality before complex features
        self.session.connect(data_packet)  # Simple ACK + data payload
        self.session.connect(fin_packet)  # Simple FIN (connection teardown)

        # TIER 2: CORE PROTOCOL (Common, Essential Features)
        # Standard TCP handshake and basic options
        self.session.connect(syn_packet)  # SYN (connection establishment)
        self.session.connect(syn_ack_packet)  # SYN-ACK (handshake response)
        self.session.connect(options_edge_cases)  # Basic options (MSS, Window Scale, Timestamps)

        # TIER 3: ADVANCED FEATURES (Less Common but Supported)
        # Features found on most modern TCP stacks
        self.session.connect(sack_packet)  # Selective ACK (RFC 2018)
        self.session.connect(ecn_setup)  # ECN negotiation (RFC 3168)
        self.session.connect(thc_flag_fuzz)  # Flag combination fuzzing

        # TIER 4: EDGE CASES & VALIDATION (Important but Slower)
        # Protocol compliance and edge case testing
        self.session.connect(invalid_states)  # Invalid state combinations (SYN+FIN, etc.)
        self.session.connect(reserved_bit_test)  # Reserved bit testing
        self.session.connect(tcp_incorrect_data_offset)  # Incorrect Data_Offset values
        self.session.connect(tcp_timestamp_shift_ub)  # Timestamp TSval high-byte shift-UB
        self.session.connect(tcp_option_length_underflow)  # Option length underflow walk

        # TIER 5: CVE & VULNERABILITY PATTERNS (Targeted, Specific)
        # Known vulnerability patterns and CVE reproductions
        self.session.connect(tcp_checksum_oob)  # Checksum out-of-bounds
        self.session.connect(tcp_urgent_bounds)  # Urgent pointer bounds (CVE-2020-13987)
        self.session.connect(tcp_header_overflow)  # Header length overflow
        self.session.connect(tcp_length_underflow)  # Length underflow (CVE-2020-17437)
        self.session.connect(sack_panic)  # SACK Panic (CVE-2019-11477)
        self.session.connect(tcp_integer_overflow)  # Sequence number wraparound
        self.session.connect(tcp_timestamp_attacks)  # PAWS timestamp attacks

        # TIER 6: EXOTIC FEATURES (Rarely Supported, Slow)
        # Experimental or uncommon TCP extensions
        self.session.connect(mptcp_packet)  # Multipath TCP (RFC 6824)
        self.session.connect(auth_packet)  # TCP Authentication Option (RFC 5925)
        self.session.connect(tcp_options_parsing_overflow)  # Options buffer overflow
        self.session.connect(tcp_state_confusion)  # Land attack variants
        self.session.connect(tcp_memory_corruption)  # Memory corruption patterns
        self.session.connect(tcp_urgent_exploits)  # WinNuke-style urgent pointer exploits

        # TIER 7: EXTENDED TCP OPTIONS (Comprehensive Coverage)
        # Testing all IANA-registered TCP options for complete protocol coverage

        # Obsolete but historically important options
        self.session.connect(tcp_echo_option)  # Echo (kind=6, RFC 1072, obsolete)
        self.session.connect(tcp_echo_reply)  # Echo Reply (kind=7, RFC 1072, obsolete)
        self.session.connect(tcp_cc_option)  # CC (kind=11, RFC 1644, obsolete)
        self.session.connect(tcp_cc_new)  # CC.NEW (kind=12, RFC 1644, obsolete)
        self.session.connect(tcp_cc_echo)  # CC.ECHO (kind=13, RFC 1644, obsolete)
        self.session.connect(tcp_alt_checksum_req)  # Alt Checksum Request (kind=14, RFC 1146)
        self.session.connect(tcp_alt_checksum_data)  # Alt Checksum Data (kind=15, RFC 1146)

        # Partial Order Connection options
        self.session.connect(tcp_poc_permitted)  # POC Permitted (kind=9, RFC 1693)
        self.session.connect(tcp_poc_profile)  # POC Profile (kind=10, RFC 1693)

        # Security and advanced features
        self.session.connect(tcp_md5_signature)  # MD5 Signature (kind=19, RFC 2385)
        self.session.connect(tcp_snack)  # Selective NACK (kind=21, RFC 2018)
        self.session.connect(tcp_quickstart)  # Quick-Start (kind=27, RFC 4782)

        # Data integrity and error handling
        self.session.connect(tcp_record_boundaries)  # Record Boundaries (kind=22, RFC 1323)
        self.session.connect(tcp_corruption)  # Corruption Experienced (kind=23, RFC 4654)

        # Modern experimental options
        self.session.connect(tcp_eno)  # Encryption Negotiation (kind=69, RFC 8547)
        self.session.connect(tcp_accecn_order0)  # Accurate ECN Order 0 (kind=172, RFC 8311)
        self.session.connect(tcp_accecn_order1)  # Accurate ECN Order 1 (kind=173, RFC 8311)
        self.session.connect(tcp_accecn_order2)  # Accurate ECN Order 2 (kind=174, RFC 8311)
        self.session.connect(tcp_experimental_253)  # Experimental (kind=253, RFC 4727)
        self.session.connect(tcp_experimental_254)  # Experimental (kind=254, RFC 4727)

        # Vendor-specific and proprietary options (rare but comprehensive)
        self.session.connect(tcp_skeeter)  # Skeeter (kind=16, proprietary)
        self.session.connect(tcp_bubba)  # Bubba (kind=17, proprietary)
        self.session.connect(tcp_scps)  # SCPS Capabilities (kind=20, space comms)
        self.session.connect(tcp_snap)  # SNAP (kind=24, proprietary)

        return self.session

    def fuzz_all(self):
        """Execute comprehensive protocol fuzzing including THC-IPv6 techniques"""
        # Mirror the base fuzz_all preamble: this override previously jumped
        # straight to the per-node loop, so --recv-timeout calibration never ran
        # and --distribution-total/-id did no partitioning (every machine fuzzed
        # the whole space). Run both before touching self.session. The
        # distribution filter patches session._fuzz_current_case, which fuzz_node
        # also invokes, so per-node fuzzing honours it too.
        fuzz_log = self._get_fuzz_logger()
        self._calibrate_timeouts(fuzz_log)
        if self.config and self.config.distribution_total and self.config.distribution_id:
            self._apply_distribution_filtering()

        # Register state tracking callbacks if enabled
        track_states = True
        if self.config:
            track_opt = self.config.get_option("track_states", "true")
            track_states = (
                track_opt.lower() in ("true", "1", "yes")
                if isinstance(track_opt, str)
                else bool(track_opt)
            )

        if track_states and hasattr(self, "state_tracker"):
            self.state_tracker.register_callbacks()
            self.log.display("TCP state tracking enabled")

        try:
            for name, _desc, _category, _state in self._REQUEST_CATALOG:
                if not self.is_request_enabled(name):
                    continue
                for node_path in self._SUBPATH_NODES.get(name, [name]):
                    self.fuzz_node(node_path)
        finally:
            # Log state tracking summary
            if track_states and hasattr(self, "state_tracker"):
                self.log.display(self.state_tracker.get_transition_summary())
            # Distribution filtering populates distribution_stats above; the base
            # fuzz_all logs it in its own finally, but this override replaces that
            # flow, so emit the multi-machine summary here too.
            if (
                self.config
                and self.config.distribution_total
                and hasattr(self, "distribution_stats")
            ):
                self._log_distribution_stats()

    def _get_monitors(self) -> List[BaseMonitor]:
        """Return list of monitors for TCP service"""
        monitors = []
        from oida.fuzz.monitors import SocketHealthMonitor

        # TCP socket monitor
        if (
            self.config
            and hasattr(self.config, "target_ip")
            and hasattr(self.config, "target_port")
        ):
            socket_monitor = SocketHealthMonitor(
                host=self.config.target_ip, port=self.config.target_port, retry_count=3
            )
            monitors.append(socket_monitor)

        return monitors

    def setup_custom_monitors(self) -> Optional[List[BaseMonitor]]:
        """Setup TCP-specific monitors"""
        return self._get_monitors()

    def _define_state_machine(self) -> None:
        """
        Define TCP connection state machine

        Implements full TCP state diagram with all standard states:
        - CLOSED: No connection
        - LISTEN: Server waiting for connection
        - SYN_SENT: Client sent SYN
        - SYN_RECEIVED: Server received SYN, sent SYN-ACK
        - ESTABLISHED: Connection established
        - FIN_WAIT_1: Initiated close, sent FIN
        - FIN_WAIT_2: Received ACK of FIN
        - CLOSE_WAIT: Received FIN, waiting for app to close
        - CLOSING: Both sides closing simultaneously
        - LAST_ACK: Waiting for final ACK
        - TIME_WAIT: Waiting to ensure remote received ACK
        """
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
            StateType,
            TransitionRule,
        )

        # Define all TCP states

        closed = ProtocolState(
            name="CLOSED",
            state_type=StateType.CONNECTION,
            description="No connection active",
        )

        listen = ProtocolState(
            name="LISTEN",
            state_type=StateType.CONNECTION,
            requires=["CLOSED"],
            description="Server waiting for connection request",
        )

        syn_sent = ProtocolState(
            name="SYN_SENT",
            state_type=StateType.CONNECTION,
            requires=["CLOSED"],
            timeout=3.0,  # SYN timeout
            timeout_callback=lambda: self.log.warning(
                "TCP SYN timeout - connection attempt failed"
            ),
            description="Client sent SYN, waiting for SYN-ACK",
        )

        syn_received = ProtocolState(
            name="SYN_RECEIVED",
            state_type=StateType.CONNECTION,
            requires=["LISTEN", "SYN_SENT"],
            timeout=3.0,  # SYN-ACK timeout
            description="Server received SYN, sent SYN-ACK",
        )

        established = ProtocolState(
            name="ESTABLISHED",
            state_type=StateType.CONNECTION,
            requires=["SYN_SENT", "SYN_RECEIVED"],
            description="Connection established, data transfer phase",
        )

        fin_wait_1 = ProtocolState(
            name="FIN_WAIT_1",
            state_type=StateType.CONNECTION,
            requires=["ESTABLISHED"],
            timeout=60.0,  # FIN timeout
            description="Sent FIN, waiting for ACK",
        )

        fin_wait_2 = ProtocolState(
            name="FIN_WAIT_2",
            state_type=StateType.CONNECTION,
            requires=["FIN_WAIT_1"],
            timeout=60.0,
            description="Received ACK of FIN, waiting for remote FIN",
        )

        close_wait = ProtocolState(
            name="CLOSE_WAIT",
            state_type=StateType.CONNECTION,
            requires=["ESTABLISHED"],
            description="Received FIN, waiting for application to close",
        )

        closing = ProtocolState(
            name="CLOSING",
            state_type=StateType.CONNECTION,
            requires=["FIN_WAIT_1"],
            description="Both sides closing simultaneously",
        )

        last_ack = ProtocolState(
            name="LAST_ACK",
            state_type=StateType.CONNECTION,
            requires=["CLOSE_WAIT"],
            timeout=30.0,
            description="Sent final FIN, waiting for ACK",
        )

        time_wait = ProtocolState(
            name="TIME_WAIT",
            state_type=StateType.CONNECTION,
            requires=["FIN_WAIT_2", "CLOSING"],
            timeout=120.0,  # 2*MSL (Maximum Segment Lifetime)
            description="Waiting to ensure remote received final ACK",
        )

        # Define transition rules with flag-based logic
        transitions = [
            # Connection establishment
            TransitionRule(
                from_state="CLOSED",
                to_state="LISTEN",
                description="Server passive open",
            ),
            TransitionRule(
                from_state="CLOSED",
                to_state="SYN_SENT",
                description="Client initiates connection (send SYN)",
            ),
            TransitionRule(
                from_state="LISTEN",
                to_state="SYN_RECEIVED",
                description="Server receives SYN (send SYN-ACK)",
            ),
            TransitionRule(
                from_state="SYN_SENT",
                to_state="SYN_RECEIVED",
                description="Simultaneous open (both send SYN)",
            ),
            TransitionRule(
                from_state="SYN_SENT",
                to_state="ESTABLISHED",
                description="Receive SYN-ACK, send ACK",
            ),
            TransitionRule(
                from_state="SYN_RECEIVED",
                to_state="ESTABLISHED",
                description="Receive ACK of SYN-ACK",
            ),
            # Connection termination
            TransitionRule(
                from_state="SYN_RECEIVED",
                to_state="FIN_WAIT_1",
                description="Local CLOSE during handshake (send FIN) [RFC 9293 3.10.4]",
            ),
            TransitionRule(
                from_state="ESTABLISHED",
                to_state="FIN_WAIT_1",
                description="Active close (send FIN)",
            ),
            TransitionRule(
                from_state="ESTABLISHED",
                to_state="CLOSE_WAIT",
                description="Receive FIN from remote",
            ),
            TransitionRule(
                from_state="FIN_WAIT_1",
                to_state="FIN_WAIT_2",
                description="Receive ACK of our FIN",
            ),
            TransitionRule(
                from_state="FIN_WAIT_1",
                to_state="CLOSING",
                description="Receive FIN before ACK (simultaneous close)",
            ),
            TransitionRule(
                from_state="FIN_WAIT_1",
                to_state="TIME_WAIT",
                description="Receive FIN that also ACKs our FIN (single-segment close) "
                "[RFC 9293 3.3.2; omitted from the canonical diagram]",
            ),
            TransitionRule(
                from_state="FIN_WAIT_2", to_state="TIME_WAIT", description="Receive FIN"
            ),
            TransitionRule(
                from_state="CLOSE_WAIT",
                to_state="LAST_ACK",
                description="Application closes (send FIN)",
            ),
            TransitionRule(
                from_state="CLOSING",
                to_state="TIME_WAIT",
                description="Receive ACK of our FIN",
            ),
            TransitionRule(
                from_state="LAST_ACK",
                to_state="CLOSED",
                description="Receive ACK of our FIN",
            ),
            TransitionRule(
                from_state="TIME_WAIT",
                to_state="CLOSED",
                description="2*MSL timeout expired",
            ),
            # Reset transitions: a valid RST aborts the connection to CLOSED
            # from any synchronized state (RFC 9293 3.5.3 / 3.10.7.4). The
            # tracker does not sequence-validate the RST - it models OIDA's own
            # state, not the target's window checks.
            TransitionRule(
                from_state="SYN_SENT",
                to_state="CLOSED",
                description="Receive RST or timeout",
            ),
            TransitionRule(from_state="SYN_RECEIVED", to_state="CLOSED", description="Receive RST"),
            TransitionRule(from_state="ESTABLISHED", to_state="CLOSED", description="Receive RST"),
            TransitionRule(from_state="FIN_WAIT_1", to_state="CLOSED", description="Receive RST"),
            TransitionRule(from_state="FIN_WAIT_2", to_state="CLOSED", description="Receive RST"),
            TransitionRule(from_state="CLOSE_WAIT", to_state="CLOSED", description="Receive RST"),
            TransitionRule(from_state="CLOSING", to_state="CLOSED", description="Receive RST"),
            TransitionRule(from_state="LAST_ACK", to_state="CLOSED", description="Receive RST"),
        ]

        # Create state machine (starts in CLOSED)
        self.state_machine = StateMachine(
            initial_state=closed,
            states=[
                closed,
                listen,
                syn_sent,
                syn_received,
                established,
                fin_wait_1,
                fin_wait_2,
                close_wait,
                closing,
                last_ack,
                time_wait,
            ],
            transitions=transitions,
            allow_invalid_transitions=False,  # Enforce valid TCP state transitions
        )

        self.log.display(
            f"TCP state machine initialized in {self.state_machine.get_current_state_name()} state"
        )

        # Log available transitions for debugging
        graph = self.state_machine.get_transition_graph()
        self.log.debug(
            f"TCP state machine has {len(graph)} states with {sum(len(v) for v in graph.values())} transitions"
        )
