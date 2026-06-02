"""EtherNet/IP Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.
CVE targets: CVE-2024-45825, CVE-2024-40619, CVE-2024-2424, CVE-2024-10386/10387
"""

from typing import List

from boofuzz import Block, Byte, DWord, Group, QWord, Request, Size, Word

from ..core.base_fuzzer import BaseFuzzer, CommonState, RequestInfo
from ..core.connections import TCPSocketConnection
from ..core.session.state_context import StateContext
from ..core.session.sequence import SequenceConfig, SequenceDirection
from ..core.session.state_machine import ProtocolState, StateMachine, StateType
from ..primitives.dynamic import DynamicDWord, SmartString, StringContext

import logging

logger = logging.getLogger(__name__)


# EtherNet/IP Command Codes for quick coverage sweep
class EIPCommands:
    """EtherNet/IP Encapsulation Commands"""

    NOP = b"\x00\x00"  # 0x0000 - No operation
    LIST_SERVICES = b"\x04\x00"  # 0x0004 - List services
    LIST_IDENTITY = b"\x63\x00"  # 0x0063 - List identity
    LIST_INTERFACES = b"\x64\x00"  # 0x0064 - List interfaces
    REGISTER_SESSION = b"\x65\x00"  # 0x0065 - Register session
    UNREGISTER_SESSION = b"\x66\x00"  # 0x0066 - Unregister session
    SEND_RR_DATA = b"\x6f\x00"  # 0x006F - Send RR Data (CIP)
    SEND_UNIT_DATA = b"\x70\x00"  # 0x0070 - Send Unit Data
    INDICATE_STATUS = b"\x72\x00"  # 0x0072 - Indicate status
    CANCEL = b"\x73\x00"  # 0x0073 - Cancel


# CIP Service Codes
class CIPServices:
    """CIP Service Codes"""

    GET_ATTRIBUTES_ALL = 0x01
    SET_ATTRIBUTES_ALL = 0x02
    GET_ATTRIBUTE_LIST = 0x03
    SET_ATTRIBUTE_LIST = 0x04
    RESET = 0x05
    START = 0x06
    STOP = 0x07
    CREATE = 0x08
    DELETE = 0x09
    MULTIPLE_SERVICE = 0x0A
    APPLY_ATTRIBUTES = 0x0D
    GET_ATTRIBUTE_SINGLE = 0x0E
    SET_ATTRIBUTE_SINGLE = 0x10
    FIND_NEXT = 0x11
    READ_TAG = 0x4C
    WRITE_TAG = 0x4D
    READ_TAG_FRAGMENTED = 0x52
    WRITE_TAG_FRAGMENTED = 0x53
    FORWARD_OPEN = 0x54
    FORWARD_CLOSE = 0x4E
    READ_TEMPLATE = 0x50


class EtherNetIPFuzzer(BaseFuzzer):
    """EtherNet/IP Protocol Fuzzer for industrial automation security testing

    Targets EtherNet/IP vulnerabilities including CIP service exploitation,
    tag manipulation, and device enumeration attacks.

    Optimization Strategy (Breadth-First):
    - Phase 1: Quick coverage sweep (~30 sec) - all commands/services once
    - Phase 2: High-crash tests (~3 min) - overflow, malformed headers
    - Phase 3: CVE-targeted writes (~3 min) - Write_Tag, Set_Attribute, Forward_Open
    - Phase 4: Boundary attacks (~3 min) - field boundaries, length mismatches
    - Phase 5: Everything else - reads, diagnostics, enumeration
    """

    PROTOCOL_OPTIONS = {
        "session_handle": {
            "type": int,
            "default": 0,
            "description": "Session handle for authenticated operations",
            "example": "0",
        },
        "enable_write": {
            "type": bool,
            "default": False,
            "description": "Enable write operations (risky for production devices)",
        },
        "cip_username": {
            "type": str,
            "default": "",
            "description": "CIP Security username for authentication fuzzing",
            "example": "admin",
        },
        "cip_password": {
            "type": str,
            "default": "",
            "description": "CIP Security password for authentication fuzzing",
            "example": "password123",
        },
        "enable_auth": {
            "type": bool,
            "default": False,
            "description": "Enable CIP Security authentication fuzzing",
        },
    }

    def __init__(self, config, connection_factory=None):
        # State tracking for RegisterSession handshake
        self.session_handle = 0
        self.session_established = False

        # StateContext for carrying state between transitions
        self._state_context = StateContext()

        # Sequence manager for sender context tracking
        seq_mgr = self._state_context.get_sequence_manager("enip")
        seq_mgr.add_sequence(
            SequenceConfig(
                name="sender_context",
                initial=1,
                increment=1,
                max_value=0xFFFFFFFF,
                direction=SequenceDirection.SEND,
                wrap_behavior="modulo",
                fuzzable=True,
            )
        )

        super().__init__(config, connection_factory)

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick coverage
            RequestInfo(
                "EIP_Baseline",
                "Quick command sweep (10 commands) + CIP services",
                "baseline",
                requires_state="CONNECTED",
            ),
            # Phase 2: High-crash tests
            RequestInfo(
                "EIP_Overflow",
                "Malformed packets, buffer overflow, length attacks",
                "overflow",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "EIP_Header_Malformed",
                "MBAP-style header attacks (CVE-2024-45825)",
                "protocol",
                requires_state=CommonState.ANY,
            ),
            # Phase 3: CVE-targeted writes
            RequestInfo(
                "EIP_Write_Operations",
                "Write_Tag, Set_Attribute, Forward_Open (CVE targets)",
                "write",
                requires_state="SESSION_REGISTERED",
            ),
            RequestInfo(
                "EIP_Program_Attack",
                "Program upload/download attacks",
                "write",
                requires_state="SESSION_REGISTERED",
            ),
            # Phase 4: Boundary attacks
            RequestInfo(
                "EIP_Boundary",
                "Field boundary testing (length, session, context)",
                "boundary",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "EIP_CIP_Boundary",
                "CIP-specific boundary attacks",
                "boundary",
                requires_state=CommonState.ANY,
            ),
            # Phase 5: Remaining tests
            RequestInfo(
                "EIP_Read_Operations",
                "Get_Attribute, Read_Tag, List_Identity",
                "read",
                requires_state="SESSION_REGISTERED",
            ),
            RequestInfo(
                "EIP_Session",
                "Session register/unregister, NOP",
                "session",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "EIP_Network_Objects",
                "TCP/IP and Ethernet Link objects",
                "read",
                requires_state="SESSION_REGISTERED",
            ),
            RequestInfo(
                "EIP_CIP_Security",
                "CIP Security authentication fuzzing",
                "auth",
                requires_state="SESSION_REGISTERED",
            ),
            RequestInfo(
                "CIP_Class_Enumeration",
                "Well-known + vendor-reserved CIP class IDs (0x01..0x110)",
                "enumeration",
                requires_state="SESSION_REGISTERED",
            ),
        ]

    def _create_socket(self):
        """Create TCP socket for EtherNet/IP communication (typically port 44818)"""
        return TCPSocketConnection(self.config.target_ip, self.config.target_port or 44818)

    def _define_state_machine(self) -> None:
        """Perform RegisterSession handshake and build state machine.

        EtherNet/IP requires RegisterSession (command 0x0065) to obtain a
        session handle before CIP operations can be performed.
        """
        import socket
        import struct

        target_ip = self.config.target_ip
        target_port = self.config.target_port or 44818
        sock = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target_ip, target_port))

            # Build RegisterSession packet (command 0x0065)
            # Encap header: command(2) + length(2) + session_handle(4) + status(4)
            #               + sender_context(8) + options(4) = 24 bytes
            # Data: protocol_version(2) + options_flags(2) = 4 bytes
            register_packet = struct.pack(
                "<HH I I 8s I HH",
                0x0065,  # Command: RegisterSession
                4,  # Length: 4 bytes of data
                0x00000000,  # Session Handle (0 for registration)
                0x00000000,  # Status
                b"\x00" * 8,  # Sender Context
                0x00000000,  # Options
                1,  # Protocol Version
                0,  # Options Flags
            )
            sock.send(register_packet)
            response = sock.recv(1024)

            if len(response) >= 8:
                resp_command = struct.unpack_from("<H", response, 0)[0]
                resp_session = struct.unpack_from("<I", response, 4)[0]
                resp_status = struct.unpack_from("<I", response, 8)[0]

                if resp_command == 0x0065 and resp_status == 0 and resp_session != 0:
                    self.session_handle = resp_session
                    self.session_established = True
                    self._state_context.set("session_handle", self.session_handle)
                    self.log.display(
                        f"[EIP] RegisterSession OK - handle: 0x{self.session_handle:08X}"
                    )
                else:
                    self.log.warning(
                        f"[EIP] RegisterSession failed: "
                        f"cmd=0x{resp_command:04X} status=0x{resp_status:08X}"
                    )
            else:
                self.log.warning("[EIP] RegisterSession response too short")

        except socket.timeout:
            self.log.warning("[EIP] RegisterSession timed out, using defaults")
        except Exception as e:
            self.log.warning(f"[EIP] RegisterSession failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    logger.debug(f"sock.close(): {e}")

        # Define state machine
        connected = ProtocolState(
            name="CONNECTED",
            state_type=StateType.CONNECTION,
            description="TCP connection established",
        )
        session_registered = ProtocolState(
            name="SESSION_REGISTERED",
            validation=self._validate_session,
            requires=["CONNECTED"],
            description="EtherNet/IP session registered with valid handle",
        )

        self.state_machine = StateMachine(
            initial_state=connected,
            states=[connected, session_registered],
            context=self._state_context,
        )

        if self.session_established:
            self.state_machine.transition_to("SESSION_REGISTERED")

        self.log.display(
            f"[EIP] State machine initialized: {self.state_machine.get_current_state_name()}"
        )

    def _validate_session(self) -> bool:
        """Check if session handle is valid."""
        return self.session_handle != 0 and self.session_established

    def _session_handle_value(self) -> int:
        """Return current session handle from state context.

        Used as the value_func for DynamicDWord fields so all requests
        automatically pick up the handle obtained during RegisterSession.
        """
        return self._state_context.get("session_handle", 0)

    def _create_encap_header(self, command: int = 0x006F, length: int = 0) -> Block:
        """Create standard EtherNet/IP encapsulation header.

        Encapsulation Header format (24 bytes):
        - Command: 2 bytes (little-endian)
        - Length: 2 bytes (data length after header)
        - Session Handle: 4 bytes (from RegisterSession)
        - Status: 4 bytes
        - Sender Context: 8 bytes
        - Options: 4 bytes
        """
        return Block(
            "EIP_Encap_Header",
            children=(
                Word("Command", command, endian="<", fuzzable=False),
                Size(
                    "Length",
                    block_name="Encap_Data",
                    length=2,
                    endian="<",
                    inclusive=False,
                    fuzzable=False,
                ),
                DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                DWord("Status", 0x00000000, endian="<", fuzzable=False),
                QWord("Context", 0x0000000000000000, endian="<", fuzzable=False),
                DWord("Options", 0x00000000, endian="<", fuzzable=False),
            ),
        )

    def _define_protocol(self) -> None:
        """Define EtherNet/IP protocol structure with vulnerability patterns.

        Optimized request ordering for breadth-first coverage:
        - Phase 1: Quick command/service sweep (all operations once)
        - Phase 2: High-crash tests (overflow, malformed)
        - Phase 3: CVE-targeted writes (Write_Tag, Set_Attribute)
        - Phase 4: Boundary attacks
        - Phase 5: Everything else
        """

        # ================================================================
        # PHASE 1: QUICK COVERAGE SWEEP (~30 seconds)
        # Touch all EIP commands and CIP services once for maximum breadth
        # ================================================================

        # Quick EIP Command Sweep - All 10 encapsulation commands once
        quick_eip_coverage = Request(
            "Quick_EIP_Coverage",
            children=(
                Block(
                    "EIP_Header_Quick",
                    children=(
                        Group(
                            "Command",
                            values=[
                                EIPCommands.NOP,
                                EIPCommands.LIST_SERVICES,
                                EIPCommands.LIST_IDENTITY,
                                EIPCommands.LIST_INTERFACES,
                                EIPCommands.REGISTER_SESSION,
                                EIPCommands.UNREGISTER_SESSION,
                                EIPCommands.SEND_RR_DATA,
                                EIPCommands.SEND_UNIT_DATA,
                                EIPCommands.INDICATE_STATUS,
                                EIPCommands.CANCEL,
                            ],
                        ),
                        Word("Length", 0x0000, endian="<", fuzzable=False),
                        DynamicDWord(
                            "Session_Handle", self._session_handle_value, endian="<", fuzzable=False
                        ),
                        DWord("Status", 0x00000000, endian="<", fuzzable=False),
                        QWord("Context", 0x0000000000000000, endian="<", fuzzable=False),
                        DWord("Options", 0x00000000, endian="<", fuzzable=False),
                    ),
                ),
            ),
        )

        # Quick CIP Service Sweep - All CIP services once
        quick_cip_coverage = Request(
            "Quick_CIP_Coverage",
            children=(
                Block(
                    "EIP_Encap_Header_CIP",
                    children=(
                        Word("Command", 0x006F, endian="<", fuzzable=False),
                        Size(
                            "Length",
                            block_name="CIP_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord(
                            "Session_Handle", self._session_handle_value, endian="<", fuzzable=False
                        ),
                        DWord("Status", 0x00000000, endian="<", fuzzable=False),
                        QWord("Context", 0x0000000000000000, endian="<", fuzzable=False),
                        DWord("Options", 0x00000000, endian="<", fuzzable=False),
                    ),
                ),
                Block(
                    "CIP_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<", fuzzable=False),
                        Word("Timeout", 0x0000, endian="<", fuzzable=False),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<", fuzzable=False),
                                Word("Address_Type", 0x0000, endian="<", fuzzable=False),
                                Word("Address_Length", 0x0000, endian="<", fuzzable=False),
                                Word("Data_Type", 0x00B2, endian="<", fuzzable=False),
                                Word("Data_Length", 0x0006, endian="<", fuzzable=False),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Group(
                                    "Service",
                                    values=[
                                        bytes([CIPServices.GET_ATTRIBUTES_ALL]),
                                        bytes([CIPServices.SET_ATTRIBUTES_ALL]),
                                        bytes([CIPServices.GET_ATTRIBUTE_LIST]),
                                        bytes([CIPServices.SET_ATTRIBUTE_LIST]),
                                        bytes([CIPServices.RESET]),
                                        bytes([CIPServices.START]),
                                        bytes([CIPServices.STOP]),
                                        bytes([CIPServices.CREATE]),
                                        bytes([CIPServices.DELETE]),
                                        bytes([CIPServices.MULTIPLE_SERVICE]),
                                        bytes([CIPServices.APPLY_ATTRIBUTES]),
                                        bytes([CIPServices.GET_ATTRIBUTE_SINGLE]),
                                        bytes([CIPServices.SET_ATTRIBUTE_SINGLE]),
                                        bytes([CIPServices.FIND_NEXT]),
                                        bytes([CIPServices.READ_TAG]),
                                        bytes([CIPServices.WRITE_TAG]),
                                        bytes([CIPServices.READ_TAG_FRAGMENTED]),
                                        bytes([CIPServices.WRITE_TAG_FRAGMENTED]),
                                        bytes([CIPServices.FORWARD_OPEN]),
                                        bytes([CIPServices.FORWARD_CLOSE]),
                                        bytes([CIPServices.READ_TEMPLATE]),
                                    ],
                                ),
                                Byte("Request_Path_Size", 0x02, fuzzable=False),
                                Byte("Class_Segment", 0x20, fuzzable=False),
                                # Class/instance VALUE bytes are default-fuzzable
                                # per ref/ethernetip/cve_patterns.json#enip-cip-path-encoding
                                Byte("Class_ID", 0x01),
                                Byte("Instance_Segment", 0x24, fuzzable=False),
                                Byte("Instance_ID", 0x01),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # CIP Class Enumeration - Iterate well-known CIP object classes
        # See ref/ethernetip/cve_patterns.json#enip-class-enumeration
        # Uses 16-bit class segment (0x21 0x00) so a single Group can hold
        # both standard 8-bit class IDs and vendor-reserved 16-bit IDs.
        cip_class_enumeration = Request(
            "CIP_Class_Enumeration",
            children=(
                Block(
                    "EIP_Encap_Header_ClassEnum",
                    children=(
                        Word("Command", 0x006F, endian="<", fuzzable=False),
                        Size(
                            "Length",
                            block_name="CIP_ClassEnum_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord(
                            "Session_Handle",
                            self._session_handle_value,
                            endian="<",
                            fuzzable=False,
                        ),
                        DWord("Status", 0x00000000, endian="<", fuzzable=False),
                        QWord("Context", 0x0000000000000000, endian="<", fuzzable=False),
                        DWord("Options", 0x00000000, endian="<", fuzzable=False),
                    ),
                ),
                Block(
                    "CIP_ClassEnum_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<", fuzzable=False),
                        Word("Timeout", 0x0000, endian="<", fuzzable=False),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<", fuzzable=False),
                                Word("Address_Type", 0x0000, endian="<", fuzzable=False),
                                Word("Address_Length", 0x0000, endian="<", fuzzable=False),
                                Word("Data_Type", 0x00B2, endian="<", fuzzable=False),
                                Word("Data_Length", 0x0008, endian="<", fuzzable=False),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x01, fuzzable=False),  # Get_Attributes_All
                                Byte("Path_Size", 0x03, fuzzable=False),  # 3 words
                                Byte(
                                    "Class_Segment_16bit", 0x21, fuzzable=False
                                ),  # 16-bit logical class
                                Byte("Pad", 0x00, fuzzable=False),
                                Group(
                                    "ClassID",
                                    values=[
                                        b"\x01\x00",  # 0x0001 - Identity
                                        b"\x02\x00",  # 0x0002 - Message Router
                                        b"\x04\x00",  # 0x0004 - Assembly
                                        b"\x06\x00",  # 0x0006 - Connection Manager
                                        b"\xf4\x00",  # 0x00F4 - Port
                                        b"\xf5\x00",  # 0x00F5 - TCP/IP Interface
                                        b"\xf6\x00",  # 0x00F6 - Ethernet Link
                                        b"\xac\x00",  # 0x00AC - Vendor-defined
                                        b"\x00\x01",  # 0x0100 - Vendor-reserved
                                        b"\x01\x01",  # 0x0101 - Vendor-reserved
                                        b"\x10\x01",  # 0x0110 - Vendor-reserved
                                    ],
                                ),
                                Byte("Instance_Segment", 0x24, fuzzable=False),
                                Byte("Instance_ID", 0x01, fuzzable=False),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 2: HIGH-CRASH TESTS (~3 minutes)
        # Buffer overflows, malformed headers - highest crash potential
        # CVE-2024-45825, CVE-2024-40619: Malformed CIP packets
        # ================================================================

        # Malformed EtherNet/IP Packet (Buffer Overflow) - MOVED TO TOP
        malformed = Request(
            "EIP_Malformed_Packet",
            children=(
                Block(
                    "EIP_Malformed_Header",
                    children=(
                        Word("Command_Malformed", 0xFFFF, endian="<"),
                        Word("Length_Malformed", 0xFFFF, endian="<"),
                        DWord("Session_Malformed", 0xFFFFFFFF, endian="<"),
                        DWord("Status_Malformed", 0xFFFFFFFF, endian="<"),
                        QWord("Context_Malformed", 0xFFFFFFFFFFFFFFFF, endian="<"),
                        DWord("Options_Malformed", 0xFFFFFFFF, endian="<"),
                    ),
                ),
                SmartString("Overflow_Payload", "A" * 256, max_len=1024),
            ),
        )

        # Length field overflow attacks (CVE-2024-45825 pattern)
        length_overflow = Request(
            "EIP_Length_Overflow",
            children=(
                Block(
                    "EIP_Header_LenOvf",
                    children=(
                        Word("Command", 0x006F, endian="<", fuzzable=False),
                        Group(
                            "Length_Overflow",
                            values=[
                                b"\x00\x40",  # 64 bytes (borderline)
                                b"\x00\x64",  # 100 bytes
                                b"\x00\xc8",  # 200 bytes
                                b"\x01\x00",  # 256 bytes
                                b"\x04\x00",  # 1024 bytes
                                b"\x10\x00",  # 4096 bytes
                                b"\xff\xff",  # Maximum (65535)
                            ],
                        ),
                        DynamicDWord(
                            "Session_Handle", self._session_handle_value, endian="<", fuzzable=False
                        ),
                        DWord("Status", 0x00000000, endian="<", fuzzable=False),
                        QWord("Context", 0x0000000000000000, endian="<", fuzzable=False),
                        DWord("Options", 0x00000000, endian="<", fuzzable=False),
                    ),
                ),
                Group(
                    "Overflow_Data",
                    values=[
                        b"A" * 64,
                        b"A" * 100,
                        b"A" * 200,
                        b"A" * 256,
                        b"A" * 512,
                    ],
                ),
            ),
        )

        # Command code fuzzing with overflow payloads
        command_overflow = Request(
            "EIP_Command_Overflow",
            children=(
                Block(
                    "EIP_Header_CmdOvf",
                    children=(
                        Group(
                            "Invalid_Command",
                            values=[
                                b"\x00\x01",  # Invalid
                                b"\x00\x02",  # Invalid
                                b"\x00\x03",  # Invalid
                                b"\x67\x00",  # Invalid (after unregister)
                                b"\x68\x00",  # Invalid
                                b"\x71\x00",  # Invalid (between Send_Unit and Indicate)
                                b"\xff\x00",  # Invalid
                                b"\xff\xff",  # Maximum
                            ],
                        ),
                        Word("Length", 0x0100, endian="<", fuzzable=False),
                        DWord("Session_Handle", 0xFFFFFFFF, endian="<"),
                        DWord("Status", 0xFFFFFFFF, endian="<"),
                        QWord("Context", 0xFFFFFFFFFFFFFFFF, endian="<"),
                        DWord("Options", 0xFFFFFFFF, endian="<"),
                    ),
                ),
                SmartString("Overflow_Data", "B" * 256, max_len=512),
            ),
        )

        # Session handle boundary attacks
        session_overflow = Request(
            "EIP_Session_Overflow",
            children=(
                Block(
                    "EIP_Header_SessOvf",
                    children=(
                        Word("Command", 0x006F, endian="<", fuzzable=False),
                        Size(
                            "Length",
                            block_name="CIP_Data_SessOvf",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        Group(
                            "Session_Handle_Boundary",
                            values=[
                                b"\x00\x00\x00\x00",  # Zero
                                b"\x00\x00\x00\x01",  # Minimum valid
                                b"\x7f\xff\xff\xff",  # Maximum positive signed
                                b"\x80\x00\x00\x00",  # Sign bit
                                b"\xff\xff\xff\xfe",  # Maximum - 1
                                b"\xff\xff\xff\xff",  # Maximum
                            ],
                        ),
                        DWord("Status", 0x00000000, endian="<", fuzzable=False),
                        QWord("Context", 0x0000000000000000, endian="<", fuzzable=False),
                        DWord("Options", 0x00000000, endian="<", fuzzable=False),
                    ),
                ),
                Block(
                    "CIP_Data_SessOvf",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<", fuzzable=False),
                        Word("Timeout", 0x0000, endian="<", fuzzable=False),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<", fuzzable=False),
                                Word("Address_Type", 0x0000, endian="<", fuzzable=False),
                                Word("Address_Length", 0x0000, endian="<", fuzzable=False),
                                Word("Data_Type", 0x00B2, endian="<", fuzzable=False),
                                Word("Data_Length", 0x0008, endian="<", fuzzable=False),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x0E, fuzzable=False),
                                Byte("Request_Path_Size", 0x02, fuzzable=False),
                                Byte("Class_Segment", 0x20, fuzzable=False),
                                # Class/instance/attribute VALUE bytes are default-fuzzable
                                # per ref/ethernetip/cve_patterns.json#enip-cip-path-encoding
                                Byte("Class_ID", 0x01),
                                Byte("Instance_Segment", 0x24, fuzzable=False),
                                Byte("Instance_ID", 0x01),
                                Word("Attribute_ID", 0x0001, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # CIP path length overflow (triggers buffer overflow in path parsing)
        cip_path_overflow = Request(
            "EIP_CIP_Path_Overflow",
            children=(
                Block(
                    "EIP_Encap_Header_PathOvf",
                    children=(
                        Word("Command", 0x006F, endian="<", fuzzable=False),
                        Size(
                            "Length",
                            block_name="CIP_Path_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord(
                            "Session_Handle", self._session_handle_value, endian="<", fuzzable=False
                        ),
                        DWord("Status", 0x00000000, endian="<", fuzzable=False),
                        QWord("Context", 0x0000000000000000, endian="<", fuzzable=False),
                        DWord("Options", 0x00000000, endian="<", fuzzable=False),
                    ),
                ),
                Block(
                    "CIP_Path_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<", fuzzable=False),
                        Word("Timeout", 0x0000, endian="<", fuzzable=False),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<", fuzzable=False),
                                Word("Address_Type", 0x0000, endian="<", fuzzable=False),
                                Word("Address_Length", 0x0000, endian="<", fuzzable=False),
                                Word("Data_Type", 0x00B2, endian="<", fuzzable=False),
                                Size(
                                    "Data_Length",
                                    block_name="CIP_Request_PathOvf",
                                    length=2,
                                    endian="<",
                                    inclusive=False,
                                    fuzzable=False,
                                ),
                            ),
                        ),
                        Block(
                            "CIP_Request_PathOvf",
                            children=(
                                Byte("Service", 0x0E, fuzzable=False),
                                Group(
                                    "Path_Size_Overflow",
                                    values=[
                                        b"\x40",  # 64 words = 128 bytes
                                        b"\x7f",  # 127 words = 254 bytes
                                        b"\x80",  # 128 words = 256 bytes (sign bit)
                                        b"\xff",  # 255 words = 510 bytes (maximum)
                                    ],
                                ),
                                # Oversized path data
                                SmartString("Path_Data", "\x20\x01\x24\x01" * 64, max_len=512),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 3: CVE-TARGETED WRITE OPERATIONS (~3 minutes)
        # Write_Tag, Set_Attribute, Forward_Open - highest CVE relevance
        # CVE-2024-10386: Database manipulation (CRITICAL)
        # ================================================================

        # CIP Set Attribute Single (Configuration Manipulation)
        set_attribute = Request(
            "EIP_CIP_Set_Attribute",
            children=(
                Block(
                    "EIP_Encap_Header_SET_ATTR",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Set_Attribute_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Set_Attribute_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0010, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x10),
                                Byte("Request_Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x01),
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                                Word("Attribute_ID", 0x0007, endian="<"),
                                SmartString("New_Product_Name", "FUZZED", max_len=32),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # CIP Write Tag Service (Tag Manipulation Attack)
        write_tag = Request(
            "EIP_CIP_Write_Tag",
            children=(
                Block(
                    "EIP_Encap_Header_WRITE_TAG",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Write_Tag_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Write_Tag_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0016, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Write_Tag_Service", 0x4D),
                                Byte("Tag_Path_Size", 0x06),
                                Byte("Tag_Path_Segment", 0x91),
                                Byte("Tag_Name_Length", 0x0C),
                                SmartString("Tag_Name", "SAFETY_ENABLE", max_len=32),
                                Word("Data_Type", 0x00C1, endian="<"),
                                Word("Element_Count", 0x0001, endian="<"),
                                Byte("Tag_Value", 0x00),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Forward Open Request (Connection Manipulation)
        forward_open = Request(
            "EIP_Forward_Open",
            children=(
                Block(
                    "EIP_Encap_Header_FWD_OPEN",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="Forward_Open_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "Forward_Open_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0030, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Forward_Open_Service", 0x54),
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x06),
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                                Byte("Priority_Time_Tick", 0x01),
                                Byte("Timeout_Ticks", 0x05),
                                DWord("O_to_T_Connection_ID", 0x12345678, endian="<"),
                                DWord("T_to_O_Connection_ID", 0x87654321, endian="<"),
                                Word("Connection_Serial", 0x0100, endian="<"),
                                Word("Vendor_ID", 0x1234, endian="<"),
                                DWord("Originator_Serial", 0x56789ABC, endian="<"),
                                Byte("Connection_Timeout_Mult", 0x03),
                                Byte("Reserved1", 0x00),
                                Word("Reserved2", 0x0000, endian="<"),
                                # OT_RPI / TO_RPI: extreme values hit timer crashes.
                                # See ref/ethernetip/cve_patterns.json#enip-forward-open-rpi
                                Group(
                                    "O_to_T_RPI",
                                    values=[
                                        b"\x00\x00\x00\x00",  # 0
                                        b"\x01\x00\x00\x00",  # 1
                                        b"\xe8\x03\x00\x00",  # 1000
                                        b"\x40\x42\x0f\x00",  # 1000000
                                        b"\xff\xff\xff\xff",  # 0xFFFFFFFF
                                    ],
                                ),
                                Word("O_to_T_Network_Params", 0x43F4, endian="<"),
                                Group(
                                    "T_to_O_RPI",
                                    values=[
                                        b"\x00\x00\x00\x00",  # 0
                                        b"\x01\x00\x00\x00",  # 1
                                        b"\xe8\x03\x00\x00",  # 1000
                                        b"\x40\x42\x0f\x00",  # 1000000
                                        b"\xff\xff\xff\xff",  # 0xFFFFFFFF
                                    ],
                                ),
                                Word("T_to_O_Network_Params", 0x43F4, endian="<"),
                                Byte("Transport_Type_Trigger", 0xA3),
                                Byte("Connection_Path_Size", 0x01),
                                Byte("Port_Segment", 0x01),
                                Byte("Link_Address", 0x00),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # CIP Reset Service (can cause device restart)
        reset_service = Request(
            "EIP_CIP_Reset",
            children=(
                Block(
                    "EIP_Encap_Header_RESET",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Reset_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Reset_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0006, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x05),  # Reset
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x01),
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Program Upload/Download Attack
        program_attack = Request(
            "EIP_Program_Attack",
            children=(
                Block(
                    "EIP_Encap_Header_PROG",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Program_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Program_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x000A, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x50),  # Read template service
                                Byte("Path_Size", 0x03),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x68),  # Symbol Object
                                Byte("Instance_Segment", 0x25),  # Extended
                                Word("Instance_ID", 0x0000, endian="<"),
                                Word("Offset", 0x0000, endian="<"),
                                Word("Element_Count", 0x0064, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 4: BOUNDARY ATTACKS (~3 minutes)
        # Field boundary testing for edge cases
        # ================================================================

        # CPF Item Count boundary testing
        cpf_boundary = Request(
            "EIP_CPF_Boundary",
            children=(
                Block(
                    "EIP_Encap_Header_CPF",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_CPF_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord(
                            "Session_Handle", self._session_handle_value, endian="<", fuzzable=False
                        ),
                        DWord("Status", 0x00000000, endian="<", fuzzable=False),
                        QWord("Context", 0x0000000000000000, endian="<", fuzzable=False),
                        DWord("Options", 0x00000000, endian="<", fuzzable=False),
                    ),
                ),
                Block(
                    "CIP_CPF_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<", fuzzable=False),
                        Word("Timeout", 0x0000, endian="<", fuzzable=False),
                        Group(
                            "Item_Count_Boundary",
                            values=[
                                b"\x00\x00",  # Zero items (invalid)
                                b"\x00\x01",  # One item
                                b"\x00\x02",  # Two items (typical)
                                b"\x00\x03",  # Three items
                                b"\x00\xff",  # 255 items
                                b"\xff\xff",  # Maximum
                            ],
                        ),
                        Word("Address_Type", 0x0000, endian="<", fuzzable=False),
                        Word("Address_Length", 0x0000, endian="<", fuzzable=False),
                        Word("Data_Type", 0x00B2, endian="<", fuzzable=False),
                        Word("Data_Length", 0x0006, endian="<", fuzzable=False),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x0E, fuzzable=False),
                                Byte("Path_Size", 0x02, fuzzable=False),
                                Byte("Class_Segment", 0x20, fuzzable=False),
                                # Class/instance VALUE bytes are default-fuzzable
                                # per ref/ethernetip/cve_patterns.json#enip-cip-path-encoding
                                Byte("Class_ID", 0x01),
                                Byte("Instance_Segment", 0x24, fuzzable=False),
                                Byte("Instance_ID", 0x01),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Context field boundary testing
        context_boundary = Request(
            "EIP_Context_Boundary",
            children=(
                Block(
                    "EIP_Header_Ctx",
                    children=(
                        Word("Command", 0x006F, endian="<", fuzzable=False),
                        Size(
                            "Length",
                            block_name="CIP_Ctx_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord(
                            "Session_Handle", self._session_handle_value, endian="<", fuzzable=False
                        ),
                        DWord("Status", 0x00000000, endian="<", fuzzable=False),
                        Group(
                            "Context_Boundary",
                            values=[
                                b"\x00\x00\x00\x00\x00\x00\x00\x00",  # Zero
                                b"\x00\x00\x00\x00\x00\x00\x00\x01",  # Minimum
                                b"\x7f\xff\xff\xff\xff\xff\xff\xff",  # Max positive
                                b"\x80\x00\x00\x00\x00\x00\x00\x00",  # Sign bit
                                b"\xff\xff\xff\xff\xff\xff\xff\xff",  # Maximum
                                b"\xde\xad\xbe\xef\xca\xfe\xba\xbe",  # Test pattern
                            ],
                        ),
                        DWord("Options", 0x00000000, endian="<", fuzzable=False),
                    ),
                ),
                Block(
                    "CIP_Ctx_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<", fuzzable=False),
                        Word("Timeout", 0x0000, endian="<", fuzzable=False),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<", fuzzable=False),
                                Word("Address_Type", 0x0000, endian="<", fuzzable=False),
                                Word("Address_Length", 0x0000, endian="<", fuzzable=False),
                                Word("Data_Type", 0x00B2, endian="<", fuzzable=False),
                                Word("Data_Length", 0x0008, endian="<", fuzzable=False),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x0E, fuzzable=False),
                                Byte("Path_Size", 0x02, fuzzable=False),
                                Byte("Class_Segment", 0x20, fuzzable=False),
                                # Class/instance/attribute VALUE bytes are default-fuzzable
                                # per ref/ethernetip/cve_patterns.json#enip-cip-path-encoding
                                Byte("Class_ID", 0x01),
                                Byte("Instance_Segment", 0x24, fuzzable=False),
                                Byte("Instance_ID", 0x01),
                                Word("Attribute_ID", 0x0001, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 5: REMAINING TESTS
        # Read operations, session management, network objects
        # ================================================================

        # List Services Request (Device Enumeration)
        list_services = Request(
            "EIP_List_Services",
            children=(
                Block(
                    "EIP_Encap_Header_LIST_SERVICES",
                    children=(
                        Word("Command", 0x0004, endian="<"),
                        Word("Length", 0x0000, endian="<"),
                        DWord("Session_Handle", 0x00000000, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
            ),
        )

        # List Identity Request (Device Information Disclosure)
        list_identity = Request(
            "EIP_List_Identity",
            children=(
                Block(
                    "EIP_Encap_Header_LIST_IDENTITY",
                    children=(
                        Word("Command", 0x0063, endian="<"),
                        Word("Length", 0x0000, endian="<"),
                        DWord("Session_Handle", 0x00000000, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
            ),
        )

        # Register Session (Session Establishment)
        register_session = Request(
            "EIP_Register_Session",
            children=(
                Block(
                    "EIP_Encap_Header_REGISTER",
                    children=(
                        Word("Command", 0x0065, endian="<"),
                        Size(
                            "Length",
                            block_name="Register_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DWord("Session_Handle", 0x00000000, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "Register_Data",
                    children=(
                        Word("Protocol_Version", 0x0001, endian="<"),
                        Word("Options_Flags", 0x0000, endian="<"),
                    ),
                ),
            ),
        )

        # Unregister Session
        unregister_session = Request(
            "EIP_Unregister_Session",
            children=(
                Block(
                    "EIP_Encap_Header_UNREG",
                    children=(
                        Word("Command", 0x0066, endian="<"),
                        Word("Length", 0x0000, endian="<"),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
            ),
        )

        # NOP (Keep-alive)
        nop = Request(
            "EIP_NOP",
            children=(
                Block(
                    "EIP_Encap_Header_NOP",
                    children=(
                        Word("Command", 0x0000, endian="<"),
                        Word("Length", 0x0000, endian="<"),
                        DWord("Session_Handle", 0x00000000, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
            ),
        )

        # CIP Get Attribute Single (Data Extraction)
        get_attribute = Request(
            "EIP_CIP_Get_Attribute",
            children=(
                Block(
                    "EIP_Encap_Header_GET_ATTR",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Get_Attribute_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Get_Attribute_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0008, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x0E),
                                Byte("Request_Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x01),
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                                Word("Attribute_ID", 0x0001, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # CIP Get Attribute All (Full object dump)
        get_all = Request(
            "EIP_CIP_Get_Attribute_All",
            children=(
                Block(
                    "EIP_Encap_Header_GET_ALL",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Get_All_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Get_All_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0006, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x01),  # Get Attributes All
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x01),  # Identity
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # CIP Read Tag Service (Tag Data Extraction)
        read_tag = Request(
            "EIP_CIP_Read_Tag",
            children=(
                Block(
                    "EIP_Encap_Header_READ_TAG",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Read_Tag_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Read_Tag_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x000E, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Read_Tag_Service", 0x4C),
                                Byte("Tag_Path_Size", 0x04),
                                Byte("Tag_Path_Segment", 0x91),
                                Byte("Tag_Name_Length", 0x08),
                                SmartString("Tag_Name", "PASSWORD", max_len=32),
                                Word("Element_Count", 0x0001, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # CIP Multiple Service Packet
        multiple_service = Request(
            "EIP_CIP_Multiple_Service",
            children=(
                Block(
                    "EIP_Encap_Header_MULTI",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Multi_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Multi_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0018, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x0A),  # Multiple Service Packet
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x02),  # Message Router
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                                Word("Service_Count", 0x0002, endian="<"),
                                Word("Offset1", 0x0006, endian="<"),
                                Word("Offset2", 0x000C, endian="<"),
                                # First service request (Get Attribute Single)
                                Byte("Svc1_Service", 0x0E),
                                Byte("Svc1_Path_Size", 0x02),
                                Byte("Svc1_Class_Seg", 0x20),
                                Byte("Svc1_Class", 0x01),
                                Byte("Svc1_Inst_Seg", 0x24),
                                Byte("Svc1_Inst", 0x01),
                                # Second service request
                                Byte("Svc2_Service", 0x01),
                                Byte("Svc2_Path_Size", 0x02),
                                Byte("Svc2_Class_Seg", 0x20),
                                Byte("Svc2_Class", 0x01),
                                Byte("Svc2_Inst_Seg", 0x24),
                                Byte("Svc2_Inst", 0x01),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Forward Close Request
        forward_close = Request(
            "EIP_Forward_Close",
            children=(
                Block(
                    "EIP_Encap_Header_FWD_CLOSE",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="Forward_Close_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "Forward_Close_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0012, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Forward_Close_Service", 0x4E),
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x06),  # Connection Manager
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                                Byte("Priority_Time_Tick", 0x01),
                                Byte("Timeout_Ticks", 0x05),
                                Word("Connection_Serial", 0x0100, endian="<"),
                                Word("Vendor_ID", 0x1234, endian="<"),
                                DWord("Originator_Serial", 0x56789ABC, endian="<"),
                                Byte("Connection_Path_Size", 0x00),
                                Byte("Reserved", 0x00),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # TCP/IP Interface Object (Class 0xF5)
        tcpip_get = Request(
            "EIP_TCPIP_Object",
            children=(
                Block(
                    "EIP_Encap_Header_TCPIP",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_TCPIP_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_TCPIP_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0008, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x0E),  # Get Attribute Single
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0xF5),  # TCP/IP Interface
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                                Word("Attribute_ID", 0x0005, endian="<"),  # IP Address
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Ethernet Link Object (Class 0xF6)
        ethlink_get = Request(
            "EIP_EthLink_Object",
            children=(
                Block(
                    "EIP_Encap_Header_ETHLINK",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_EthLink_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_EthLink_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0008, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x0E),
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0xF6),  # Ethernet Link
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                                Word("Attribute_ID", 0x0003, endian="<"),  # MAC Address
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ================================================================
        # CIP SECURITY AUTHENTICATION REQUESTS
        # Uses SmartString CREDENTIAL for credential fuzzing
        # ================================================================

        # Get credentials from options
        cip_username = self.config.get_option("cip_username", "") or "admin"
        cip_password = self.config.get_option("cip_password", "") or "password"

        # CIP Security Object (Class 0x5D) - Get Security Profiles
        cip_security_get = Request(
            "EIP_CIP_Security_Get",
            children=(
                Block(
                    "EIP_Encap_Header_SEC",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Security_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Security_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0006, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x01),  # Get Attributes All
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x5D),  # CIP Security Object
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # CIP Security - User Authentication Request
        cip_user_auth = Request(
            "EIP_CIP_User_Auth",
            children=(
                Block(
                    "EIP_Encap_Header_AUTH",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Auth_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Auth_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0022, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x4B),  # Begin_Session (CIP Security service)
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x5D),  # CIP Security Object
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                                # Authentication data using SmartString CREDENTIAL
                                Byte("Username_Length", len(cip_username)),
                                SmartString(
                                    "CIP_Username",
                                    cip_username,
                                    max_len=32,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Byte("Password_Length", len(cip_password)),
                                SmartString(
                                    "CIP_Password",
                                    cip_password,
                                    max_len=32,
                                    context=StringContext.CREDENTIAL,
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # CIP Security - Certificate-based Authentication
        cip_cert_auth = Request(
            "EIP_CIP_Cert_Auth",
            children=(
                Block(
                    "EIP_Encap_Header_CERT",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Cert_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Cert_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0032, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x4C),  # Authenticate (CIP Security service)
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x5D),
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                                # Certificate subject - use SmartString CREDENTIAL
                                Byte("Cert_Type", 0x01),  # X.509 certificate
                                Word("Cert_Length", 0x0020, endian="<"),
                                SmartString(
                                    "Cert_Subject",
                                    cip_username,
                                    max_len=32,
                                    context=StringContext.CREDENTIAL,
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # CIP Security - Session Key Exchange
        cip_key_exchange = Request(
            "EIP_CIP_Key_Exchange",
            children=(
                Block(
                    "EIP_Encap_Header_KEY",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Key_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Key_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x002A, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x4D),  # Key_Exchange (CIP Security service)
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x5D),
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                                # Session key data - use SmartString CREDENTIAL for key material
                                DWord("Session_ID", 0x12345678, endian="<"),
                                SmartString(
                                    "Session_Key",
                                    cip_password,
                                    max_len=32,
                                    context=StringContext.CREDENTIAL,
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # CIP Security - Malformed Authentication (boundary testing)
        cip_auth_malformed = Request(
            "EIP_CIP_Auth_Malformed",
            children=(
                Block(
                    "EIP_Encap_Header_MAL",
                    children=(
                        Word("Command", 0x006F, endian="<"),
                        Size(
                            "Length",
                            block_name="CIP_Auth_Mal_Data",
                            length=2,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DynamicDWord("Session_Handle", self._session_handle_value, endian="<"),
                        DWord("Status", 0x00000000, endian="<"),
                        QWord("Context", 0x0000000000000000, endian="<"),
                        DWord("Options", 0x00000000, endian="<"),
                    ),
                ),
                Block(
                    "CIP_Auth_Mal_Data",
                    children=(
                        DWord("Interface_Handle", 0x00000000, endian="<"),
                        Word("Timeout", 0x0000, endian="<"),
                        Block(
                            "CPF_Header",
                            children=(
                                Word("Item_Count", 0x0002, endian="<"),
                                Word("Address_Type", 0x0000, endian="<"),
                                Word("Address_Length", 0x0000, endian="<"),
                                Word("Data_Type", 0x00B2, endian="<"),
                                Word("Data_Length", 0x0012, endian="<"),
                            ),
                        ),
                        Block(
                            "CIP_Request",
                            children=(
                                Byte("Service", 0x4B),  # Begin_Session
                                Byte("Path_Size", 0x02),
                                Byte("Class_Segment", 0x20),
                                Byte("Class_ID", 0x5D),
                                Byte("Instance_Segment", 0x24),
                                Byte("Instance_ID", 0x01),
                                # Malformed auth data
                                Group(
                                    "Malformed_Auth",
                                    values=[
                                        b"\xff" * 10,  # All 0xFF
                                        b"\x00" * 10,  # All 0x00
                                        b"\xff\x00" * 5,  # Alternating
                                        b"A" * 256,  # Oversized
                                    ],
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ================================================================
        # OPTIMIZED REQUEST ORDERING
        # Requests are connected in phase order for maximum early coverage
        # Use --enable or --disable CLI flags to select specific groups
        # ================================================================

        # ==================== PHASE 1: QUICK COVERAGE (~30 sec) ====================
        if self.is_request_enabled("EIP_Baseline"):
            self.session.connect(quick_eip_coverage)  # All 10 EIP commands
            self.session.connect(quick_cip_coverage)  # All 21 CIP services
            self.session.connect(cip_class_enumeration)  # Well-known CIP object classes

        # ==================== PHASE 2: HIGH-CRASH TESTS (~3 min) ====================
        if self.is_request_enabled("EIP_Overflow"):
            self.session.connect(malformed)  # Buffer overflow (0xFFFF fields)
            self.session.connect(length_overflow)  # Length field overflow
            self.session.connect(command_overflow)  # Invalid commands with overflow
            self.session.connect(cip_path_overflow)  # CIP path length overflow

        if self.is_request_enabled("EIP_Header_Malformed"):
            self.session.connect(session_overflow)  # Session handle boundary

        # ==================== PHASE 3: CVE-TARGETED WRITES (~3 min) ====================
        enable_write = self.config.get_option("enable_write", False)

        if self.is_request_enabled("EIP_Write_Operations") and enable_write:
            self.session.connect(set_attribute)  # CIP Set Attribute (config manip)
            self.session.connect(write_tag)  # CIP Write Tag (tag manip)
            self.session.connect(forward_open)  # Forward Open (connection manip)
            self.session.connect(reset_service)  # Reset service (device restart)
        elif self.is_request_enabled("EIP_Write_Operations") and not enable_write:
            self.log.warning("[EIP] Write operations skipped (enable with --enable-write)")

        if self.is_request_enabled("EIP_Program_Attack") and enable_write:
            self.session.connect(program_attack)  # Program upload/download
        elif self.is_request_enabled("EIP_Program_Attack") and not enable_write:
            self.log.warning("[EIP] Program attack skipped (enable with --enable-write)")

        # ==================== PHASE 4: BOUNDARY TESTS (~3 min) ====================
        if self.is_request_enabled("EIP_Boundary"):
            self.session.connect(cpf_boundary)  # CPF item count boundary
            self.session.connect(context_boundary)  # Context field boundary

        # ==================== PHASE 5: REMAINING TESTS ====================
        if self.is_request_enabled("EIP_Read_Operations"):
            self.session.connect(get_attribute)  # CIP Get Attribute Single
            self.session.connect(get_all)  # CIP Get Attribute All
            self.session.connect(read_tag)  # CIP Read Tag
            self.session.connect(multiple_service)  # Multiple Service Packet
            self.session.connect(forward_close)  # Forward Close

        if self.is_request_enabled("EIP_Session"):
            self.session.connect(list_services)  # List Services
            self.session.connect(list_identity)  # List Identity
            self.session.connect(register_session)  # Register Session
            self.session.connect(unregister_session)  # Unregister Session
            self.session.connect(nop)  # NOP

        if self.is_request_enabled("EIP_Network_Objects"):
            self.session.connect(tcpip_get)  # TCP/IP Interface Object
            self.session.connect(ethlink_get)  # Ethernet Link Object

        # ==================== CIP SECURITY AUTHENTICATION ====================
        if self.is_request_enabled("EIP_CIP_Security") and self.config.get_option(
            "enable_auth", False
        ):
            self.session.connect(cip_security_get)  # CIP Security Object attributes
            self.session.connect(cip_user_auth)  # User authentication
            self.session.connect(cip_cert_auth)  # Certificate authentication
            self.session.connect(cip_key_exchange)  # Session key exchange
            self.session.connect(cip_auth_malformed)  # Malformed auth (boundary test)


__all__ = ["EtherNetIPFuzzer"]
