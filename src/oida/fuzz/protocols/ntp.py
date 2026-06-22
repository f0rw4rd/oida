"""NTP Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.

Test Ordering Strategy (5 Phases):
    Phase 1 (0-30s): Quick_Coverage - One request per mode (1-7) plus extensions
    Phase 2 (30s-2m): High-crash tests - Malformed packets, length attacks, overflow
    Phase 3 (2m-5m): CVE-targeted - Mode 7 private, control traps, crypto-NAK
    Phase 4 (5m-10m): Boundary attacks - All field boundary tests
    Phase 5 (10m+): Deep fuzzing - Standard requests with full mutation

CVE Coverage:
    - CVE-2013-5211: Mode 7 monlist (Phase 1 quick, Phase 3 deep)
    - CVE-2014-9295: Buffer overflow in crypto-NAK (Phase 2)
    - CVE-2016-9311: Control mode trap crash (Phase 3)
    - CVE-2023-26551-26555: Extension parsing (Phase 2)
    - CVE-2014-9296: Timestamp epoch handling (Phase 4)
"""

import struct
import time

from boofuzz import Block, Byte, DWord, Group, QWord, Request, Word

from typing import List

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..monitors import PingMonitor
from ..primitives.dynamic import SmartString


class NTPFuzzer(BaseFuzzer):
    """NTP (Network Time Protocol) Fuzzer

    Supports fuzzing NTP v3/v4 protocol messages including:
    - Client requests
    - Server responses
    - Control messages
    - Authentication extensions

    Optimized test ordering ensures:
    - All 7 NTP modes tested within first 30 seconds
    - High-crash tests (malformed, overflow) run in first 2 minutes
    - CVE-relevant operations tested within first 5 minutes
    - Boundary attacks complete within first 10 minutes
    """

    PROTOCOL_OPTIONS = {
        "ntp_version": {
            "type": int,
            "default": 4,
            "description": "NTP protocol version",
            "choices": [3, 4],
        },
        "ntp_mode": {
            "type": int,
            "default": 3,
            "description": "NTP mode (1-7, default: 3 for client)",
            "choices": [1, 2, 3, 4, 5, 6, 7],
        },
        "enable_auth": {
            "type": bool,
            "default": False,
            "description": "Enable authentication extension",
        },
        "auth_key_id": {
            "type": int,
            "default": 1,
            "description": "Authentication key ID",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Quick coverage
            RequestInfo("NTP_Quick_Coverage", "All-modes sweep", "quick"),
            # Standard NTP
            RequestInfo("NTP_Client_Request", "Standard client request", "standard"),
            RequestInfo("NTP_Control_Message", "Mode 6 control message", "control"),
            RequestInfo("NTP_Auth_Request", "Authenticated request", "auth"),
            RequestInfo("NTP_Private_Request", "Mode 7 private request", "private"),
            # Extensions
            RequestInfo("NTP_Extension_Request", "Extension field", "extension"),
            RequestInfo("NTP_Multi_Extension_Request", "Multiple extensions", "extension"),
            # Special messages
            RequestInfo("NTP_Kiss_Of_Death", "KoD packet", "special"),
            RequestInfo("NTP_Broadcast_Message", "Broadcast mode", "special"),
            RequestInfo("NTP_Autokey_Request", "Autokey protocol", "crypto"),
            # Attack patterns
            RequestInfo("NTP_Malformed", "Malformed packets", "high_crash"),
            RequestInfo("NTP_Extension_Overflow", "Extension length overflow", "high_crash"),
            RequestInfo("NTP_Crypto_NAK_Attack", "Crypto-NAK buffer attack (CVE-2014-9295)", "cve"),
            RequestInfo("NTP_Monlist_Attack", "Mode 7 monlist (CVE-2013-5211)", "cve"),
            RequestInfo("NTP_Trap_Attack", "Control trap (CVE-2016-9311)", "cve"),
            # Boundary tests
            RequestInfo("NTP_Reference_ID_Boundary", "Reference ID boundary", "boundary"),
            RequestInfo(
                "NTP_Timestamp_Fraction_Boundary", "Timestamp fraction boundary", "boundary"
            ),
            RequestInfo("NTP_Leap_Indicator_Boundary", "Leap indicator boundary", "boundary"),
            RequestInfo("NTP_Version_Boundary", "Version field boundary", "boundary"),
            RequestInfo("NTP_Mode_Boundary", "Mode field boundary", "boundary"),
            RequestInfo("NTP_Stratum_Boundary", "Stratum boundary", "boundary"),
            RequestInfo("NTP_Poll_Boundary", "Poll interval boundary", "boundary"),
            RequestInfo("NTP_Precision_Boundary", "Precision boundary", "boundary"),
            RequestInfo("NTP_Timestamp_Epoch_Boundary", "Timestamp epoch", "boundary"),
            RequestInfo("NTP_Root_Delay_Boundary", "Root delay boundary", "boundary"),
            RequestInfo("NTP_Root_Dispersion_Boundary", "Root dispersion", "boundary"),
            RequestInfo("NTP_Extension_Length_Attack", "Extension length attack", "cve"),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        config.protocol_type = ProtocolType.UDP
        super().__init__(config, connection_factory)

    def setup_custom_monitors(self):
        """Setup NTP-specific monitors

        Note: NTP uses UDP, so we don't use TCP-based SocketHealthMonitor.
        We explicitly return only PingMonitor to avoid the default TCP monitor.
        """
        # Return only PingMonitor - no TCP socket health checks for UDP protocols
        return [PingMonitor(self.config.target_ip)]

    def _define_protocol(self):
        """Define NTP protocol structure"""
        # Get protocol options
        ntp_version = self.config.get_option("ntp_version", 4)
        ntp_mode = self.config.get_option("ntp_mode", 3)  # Client mode
        enable_auth = self.config.get_option("enable_auth", False)
        auth_key_id = self.config.get_option("auth_key_id", 1)

        # NTP Client Request
        client_req = Request(
            "NTP_Client_Request",
            children=(
                # NTP Header (48 bytes)
                Block(
                    "NTP_Header",
                    children=(
                        # Byte 0: LI, VN, Mode (LI=0, VN=version, Mode=mode)
                        Byte("LI_VN_Mode", (0 << 6) | (ntp_version << 3) | ntp_mode, fuzzable=True),
                        # Byte 1: Stratum
                        Byte("Stratum", 0x00, fuzzable=True),
                        # Byte 2: Poll Interval
                        Byte("Poll", 0x06, fuzzable=True),
                        # Byte 3: Precision
                        Byte("Precision", 0xEC, fuzzable=True),
                        # Bytes 4-7: Root Delay (32 bits)
                        DWord("RootDelay", 0, endian=">", fuzzable=True),
                        # Bytes 8-11: Root Dispersion (32 bits)
                        DWord("RootDispersion", 0, endian=">", fuzzable=True),
                        # Bytes 12-15: Reference ID (32 bits)
                        DWord("ReferenceID", 0, endian=">", fuzzable=True),
                        # Bytes 16-23: Reference Timestamp (64 bits)
                        QWord("ReferenceTimestamp", 0, endian=">", fuzzable=True),
                        # Bytes 24-31: Originate Timestamp (64 bits)
                        QWord("OriginateTimestamp", 0, endian=">", fuzzable=True),
                        # Bytes 32-39: Receive Timestamp (64 bits)
                        QWord("ReceiveTimestamp", 0, endian=">", fuzzable=True),
                        # Bytes 40-47: Transmit Timestamp (64 bits)
                        QWord(
                            "TransmitTimestamp",
                            self._get_ntp_timestamp(),
                            endian=">",
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # NTP Control Message
        control_msg = Request(
            "NTP_Control_Message",
            children=(
                Block(
                    "Control_Header",
                    children=(
                        # Control message header
                        # Mode 6 = Control message
                        Byte(
                            "Control_LI_VN_Mode", (0 << 6) | (ntp_version << 3) | 6, fuzzable=True
                        ),
                        # R E M Op Code
                        Byte("Control_Flags", 0x00, fuzzable=True),
                        # Sequence
                        Word("Sequence", 0, endian=">", fuzzable=True),
                        # Status
                        Word("Status", 0, endian=">", fuzzable=True),
                        # Association ID
                        Word("AssociationID", 0, endian=">", fuzzable=True),
                        # Offset
                        Word("Offset", 0, endian=">", fuzzable=True),
                        # Count
                        Word("Count", 0, endian=">", fuzzable=True),
                        # Data (variable length)
                        SmartString("Control_Data", "", max_len=468, fuzzable=True),
                    ),
                ),
            ),
        )

        # NTP with Authentication Extension
        if enable_auth:
            auth_req = Request(
                "NTP_Auth_Request",
                children=(
                    # Standard NTP header
                    Block(
                        "NTP_Header",
                        children=(
                            Byte(
                                "LI_VN_Mode",
                                (0 << 6) | (ntp_version << 3) | ntp_mode,
                                fuzzable=True,
                            ),
                            Byte("Stratum", 0x00, fuzzable=True),
                            Byte("Poll", 0x06, fuzzable=True),
                            Byte("Precision", 0xEC, fuzzable=True),
                            DWord("RootDelay", 0, endian=">", fuzzable=True),
                            DWord("RootDispersion", 0, endian=">", fuzzable=True),
                            DWord("ReferenceID", 0, endian=">", fuzzable=True),
                            QWord("ReferenceTimestamp", 0, endian=">", fuzzable=True),
                            QWord("OriginateTimestamp", 0, endian=">", fuzzable=True),
                            QWord("ReceiveTimestamp", 0, endian=">", fuzzable=True),
                            QWord(
                                "TransmitTimestamp",
                                self._get_ntp_timestamp(),
                                endian=">",
                                fuzzable=True,
                            ),
                        ),
                    ),
                    # Authentication Extension
                    Block(
                        "Auth_Extension",
                        children=(
                            # Key Identifier (4 bytes)
                            DWord("KeyID", auth_key_id, endian=">", fuzzable=True),
                            # Message Digest (16 bytes for MD5)
                            SmartString("Digest", "0" * 32, size=16, fuzzable=True),
                        ),
                    ),
                ),
            )

        # NTP Private/Mode 7 Request
        private_req = Request(
            "NTP_Private_Request",
            children=(
                Block(
                    "Private_Header",
                    children=(
                        # Mode 7 = Private
                        # Mode 7 = Private
                        Byte(
                            "Private_LI_VN_Mode", (0 << 6) | (ntp_version << 3) | 7, fuzzable=True
                        ),
                        # Implementation number
                        Byte("Implementation", 0x03, fuzzable=True),  # XNTPD
                        # Request code
                        Byte("RequestCode", 0x00, fuzzable=True),
                        # Error/More/Auth flags
                        Byte("Flags", 0x00, fuzzable=True),
                        # Sequence
                        Word("Sequence", 0, endian=">", fuzzable=True),
                        # Status/Num items
                        Word("Status", 0, endian=">", fuzzable=True),
                        # Data size
                        Word("DataSize", 0, endian=">", fuzzable=True),
                        # Reserved
                        DWord("Reserved", 0, endian=">", fuzzable=True),
                        # Data (variable)
                        SmartString("Private_Data", "", max_len=468, fuzzable=True),
                    ),
                ),
            ),
        )

        # NTPv4 Extension Fields
        extension_req = Request(
            "NTP_Extension_Request",
            children=(
                # Standard NTP header
                Block(
                    "NTP_Header_Ext",
                    children=(
                        # Force NTPv4
                        Byte("LI_VN_Mode", (0 << 6) | (4 << 3) | ntp_mode, fuzzable=True),
                        Byte("Stratum", 0x00, fuzzable=True),
                        Byte("Poll", 0x06, fuzzable=True),
                        Byte("Precision", 0xEC, fuzzable=True),
                        DWord("RootDelay", 0, endian=">", fuzzable=True),
                        DWord("RootDispersion", 0, endian=">", fuzzable=True),
                        DWord("ReferenceID", 0, endian=">", fuzzable=True),
                        QWord("ReferenceTimestamp", 0, endian=">", fuzzable=True),
                        QWord("OriginateTimestamp", 0, endian=">", fuzzable=True),
                        QWord("ReceiveTimestamp", 0, endian=">", fuzzable=True),
                        QWord(
                            "TransmitTimestamp",
                            self._get_ntp_timestamp(),
                            endian=">",
                            fuzzable=True,
                        ),
                    ),
                ),
                # NTPv4 Extension Field
                Block(
                    "Extension_Field",
                    children=(
                        # Field Type (16 bits)
                        Word("ExtensionType", 0x0104, endian=">", fuzzable=True),  # NTS Cookie
                        # Field Length (16 bits)
                        Word("ExtensionLength", 36, endian=">", fuzzable=True),
                        # Extension Value (variable)
                        SmartString("ExtensionValue", "ntp-extension", max_len=1000, fuzzable=True),
                    ),
                ),
            ),
        )

        # NTPv4 with Multiple Extensions
        multi_ext_req = Request(
            "NTP_Multi_Extension_Request",
            children=(
                # Standard NTP header
                Block(
                    "NTP_Header_Multi",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (4 << 3) | ntp_mode, fuzzable=True),
                        Byte("Stratum", 0x00, fuzzable=True),
                        Byte("Poll", 0x06, fuzzable=True),
                        Byte("Precision", 0xEC, fuzzable=True),
                        DWord("RootDelay", 0, endian=">", fuzzable=True),
                        DWord("RootDispersion", 0, endian=">", fuzzable=True),
                        DWord("ReferenceID", 0, endian=">", fuzzable=True),
                        QWord("ReferenceTimestamp", 0, endian=">", fuzzable=True),
                        QWord("OriginateTimestamp", 0, endian=">", fuzzable=True),
                        QWord("ReceiveTimestamp", 0, endian=">", fuzzable=True),
                        QWord(
                            "TransmitTimestamp",
                            self._get_ntp_timestamp(),
                            endian=">",
                            fuzzable=True,
                        ),
                    ),
                ),
                # NTS Cookie Extension
                Block(
                    "NTS_Cookie_Extension",
                    children=(
                        Word("ExtType1", 0x0104, endian=">"),  # NTS Cookie
                        Word("ExtLength1", 132, endian=">"),
                        SmartString("Cookie", "ntp-cookie", max_len=128, fuzzable=True),
                    ),
                ),
                # NTS Cookie Placeholder Extension
                Block(
                    "NTS_Placeholder_Extension",
                    children=(
                        Word("ExtType2", 0x0204, endian=">"),  # NTS Cookie Placeholder
                        Word("ExtLength2", 8, endian=">"),
                        DWord("PlaceholderData", 0xDEADBEEF, endian=">", fuzzable=True),
                    ),
                ),
                # NTS Authenticator and Encrypted Extensions
                Block(
                    "NTS_Auth_Extension",
                    children=(
                        Word(
                            "ExtType3", 0x0404, endian=">"
                        ),  # NTS Authenticator and Encrypted Extensions
                        Word("ExtLength3", 52, endian=">"),
                        SmartString("AuthData", "ntp-auth-data", max_len=48, fuzzable=True),
                    ),
                ),
            ),
        )

        # Kiss of Death Messages
        kiss_of_death = Request(
            "NTP_Kiss_Of_Death",
            children=(
                Block(
                    "KOD_Header",
                    children=(
                        # LI=3 (alarm), Mode=4 (server)
                        Byte("LI_VN_Mode", (3 << 6) | (ntp_version << 3) | 4, fuzzable=True),
                        Byte("Stratum", 0x00, fuzzable=True),  # Stratum 0 for KoD
                        Byte("Poll", 0x00, fuzzable=True),
                        Byte("Precision", 0x00, fuzzable=True),
                        DWord("RootDelay", 0, endian=">", fuzzable=True),
                        DWord("RootDispersion", 0, endian=">", fuzzable=True),
                        # Reference ID contains KoD code
                        Group(
                            "KissCode",
                            values=[
                                b"ACST",  # The association belongs to a unicast server
                                b"AUTH",  # Server authentication failed
                                b"AUTO",  # Autokey sequence failed
                                b"BCST",  # The association belongs to a broadcast server
                                b"CRYP",  # Cryptographic authentication or identification failed
                                b"DENY",  # Access denied by remote server
                                b"DROP",  # Lost peer in symmetric mode
                                b"RSTR",  # Access denied due to local policy
                                b"INIT",  # The association has not yet synchronized for the first time
                                b"MCST",  # The association belongs to a manycast server
                                b"NKEY",  # No key found
                                b"RATE",  # Rate exceeded
                                b"RMOT",  # Alteration of association from a remote host running ntpdc
                                b"STEP",  # A step change in system time has occurred
                                b"\xff\xff\xff\xff",  # Invalid/malformed
                            ],
                        ),
                        QWord("ReferenceTimestamp", 0, endian=">", fuzzable=True),
                        QWord("OriginateTimestamp", 0, endian=">", fuzzable=True),
                        QWord("ReceiveTimestamp", 0, endian=">", fuzzable=True),
                        QWord(
                            "TransmitTimestamp",
                            self._get_ntp_timestamp(),
                            endian=">",
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # NTP Broadcast Message
        broadcast_msg = Request(
            "NTP_Broadcast_Message",
            children=(
                Block(
                    "Broadcast_Header",
                    children=(
                        # Mode 5 = Broadcast
                        Byte("LI_VN_Mode", (0 << 6) | (ntp_version << 3) | 5, fuzzable=True),
                        Byte("Stratum", 0x01, fuzzable=True),  # Primary server
                        Byte("Poll", 0x06, fuzzable=True),
                        Byte("Precision", 0xEC, fuzzable=True),
                        DWord("RootDelay", 0x00000100, endian=">", fuzzable=True),  # 1ms
                        DWord("RootDispersion", 0x00000100, endian=">", fuzzable=True),  # 1ms
                        # Reference ID for stratum 1 servers (e.g., GPS, ATOM, etc.)
                        Group(
                            "RefID",
                            values=[
                                b"GPS\x00",  # Global Positioning System
                                b"ATOM",  # Atomic clock
                                b"WWVB",  # NIST radio station
                                b"DCF\x00",  # German radio station
                                b"LORC",  # LORAN-C radionavigation
                                b"EVIL",  # Malicious reference
                                b"\x00\x00\x00\x00",  # Invalid
                            ],
                        ),
                        QWord(
                            "ReferenceTimestamp",
                            self._get_ntp_timestamp(),
                            endian=">",
                            fuzzable=True,
                        ),
                        QWord("OriginateTimestamp", 0, endian=">", fuzzable=True),
                        QWord("ReceiveTimestamp", 0, endian=">", fuzzable=True),
                        QWord(
                            "TransmitTimestamp",
                            self._get_ntp_timestamp(),
                            endian=">",
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # Autokey Authentication Protocol (NTPv4)
        autokey_req = Request(
            "NTP_Autokey_Request",
            children=(
                # Standard NTP header
                Block(
                    "NTP_Header_Autokey",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (4 << 3) | ntp_mode, fuzzable=True),  # NTPv4
                        Byte("Stratum", 0x00, fuzzable=True),
                        Byte("Poll", 0x06, fuzzable=True),
                        Byte("Precision", 0xEC, fuzzable=True),
                        DWord("RootDelay", 0, endian=">", fuzzable=True),
                        DWord("RootDispersion", 0, endian=">", fuzzable=True),
                        DWord("ReferenceID", 0, endian=">", fuzzable=True),
                        QWord("ReferenceTimestamp", 0, endian=">", fuzzable=True),
                        QWord("OriginateTimestamp", 0, endian=">", fuzzable=True),
                        QWord("ReceiveTimestamp", 0, endian=">", fuzzable=True),
                        QWord(
                            "TransmitTimestamp",
                            self._get_ntp_timestamp(),
                            endian=">",
                            fuzzable=True,
                        ),
                    ),
                ),
                # Autokey Extension Field
                Block(
                    "Autokey_Extension",
                    children=(
                        Word("ExtType", 0x0002, endian=">"),  # Autokey Request
                        Word("ExtLength", 16, endian=">"),
                        DWord("AssocID", 0x12345678, endian=">", fuzzable=True),
                        DWord("Timestamp", int(time.time()), endian=">", fuzzable=True),
                        DWord("Filestamp", 0x87654321, endian=">", fuzzable=True),
                        DWord("Flags", 0x00000001, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Malformed NTP with Invalid Fields
        malformed_ntp = Request(
            "NTP_Malformed",
            children=(
                Block(
                    "Malformed_Header",
                    children=(
                        # Invalid LI, VN, Mode combinations
                        Group(
                            "Invalid_LI_VN_Mode",
                            values=[
                                bytes([0xFF]),  # All bits set
                                bytes([0x00]),  # All bits clear
                                bytes([0x3F]),  # Invalid version (7)
                                bytes([0x38]),  # Invalid mode (0)
                                bytes([0x07]),  # Invalid mode (7) with version 0
                            ],
                        ),
                        Byte("Stratum", 255, fuzzable=True),  # Invalid stratum
                        Byte("Poll", 255, fuzzable=True),  # Invalid poll
                        Byte("Precision", 127, fuzzable=True),  # Invalid precision
                        DWord("RootDelay", 0xFFFFFFFF, endian=">", fuzzable=True),
                        DWord("RootDispersion", 0xFFFFFFFF, endian=">", fuzzable=True),
                        DWord("ReferenceID", 0xDEADBEEF, endian=">", fuzzable=True),
                        QWord("ReferenceTimestamp", 0xFFFFFFFFFFFFFFFF, endian=">", fuzzable=True),
                        QWord("OriginateTimestamp", 0xFFFFFFFFFFFFFFFF, endian=">", fuzzable=True),
                        QWord("ReceiveTimestamp", 0xFFFFFFFFFFFFFFFF, endian=">", fuzzable=True),
                        QWord("TransmitTimestamp", 0xFFFFFFFFFFFFFFFF, endian=">", fuzzable=True),
                    ),
                ),
                # Malformed Extension
                Block(
                    "Malformed_Extension",
                    children=(
                        Word("BadExtType", 0xFFFF, endian=">", fuzzable=True),
                        Word("BadExtLength", 0xFFFF, endian=">", fuzzable=True),
                        SmartString(
                            "BadExtData", "bad-extension-data", max_len=2000, fuzzable=True
                        ),
                    ),
                ),
            ),
        )

        # ============================================================
        # SERVER-SIDE FUZZING ENHANCEMENTS
        # Testing NTP server parsing and validation logic
        # ============================================================

        # Leap Indicator Systematic Testing
        leap_indicator_test = Request(
            "NTP_Leap_Indicator_Boundary",
            children=(
                Block(
                    "LI_Test_Header",
                    children=(
                        Group(
                            "LI_Boundary",
                            values=[
                                bytes(
                                    [(0 << 6) | (ntp_version << 3) | ntp_mode]
                                ),  # LI=0: No warning
                                bytes(
                                    [(1 << 6) | (ntp_version << 3) | ntp_mode]
                                ),  # LI=1: Last minute has 61 seconds
                                bytes(
                                    [(2 << 6) | (ntp_version << 3) | ntp_mode]
                                ),  # LI=2: Last minute has 59 seconds
                                bytes(
                                    [(3 << 6) | (ntp_version << 3) | ntp_mode]
                                ),  # LI=3: Alarm (clock not synchronized)
                            ],
                        ),
                        Byte("Stratum", 0x00),
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                )
            ),
        )

        # Version Boundary Testing
        version_boundary_test = Request(
            "NTP_Version_Boundary",
            children=(
                Block(
                    "Version_Test_Header",
                    children=(
                        Group(
                            "Version_Boundary",
                            values=[
                                bytes([(0 << 6) | (0 << 3) | ntp_mode]),  # Version 0 (reserved)
                                bytes([(0 << 6) | (1 << 3) | ntp_mode]),  # Version 1 (obsolete)
                                bytes([(0 << 6) | (2 << 3) | ntp_mode]),  # Version 2 (obsolete)
                                bytes([(0 << 6) | (3 << 3) | ntp_mode]),  # Version 3 (current)
                                bytes([(0 << 6) | (4 << 3) | ntp_mode]),  # Version 4 (current)
                                bytes([(0 << 6) | (5 << 3) | ntp_mode]),  # Version 5 (reserved)
                                bytes([(0 << 6) | (6 << 3) | ntp_mode]),  # Version 6 (reserved)
                                bytes([(0 << 6) | (7 << 3) | ntp_mode]),  # Version 7 (invalid)
                            ],
                        ),
                        Byte("Stratum", 0x00),
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                )
            ),
        )

        # Mode Boundary Testing
        mode_boundary_test = Request(
            "NTP_Mode_Boundary",
            children=(
                Block(
                    "Mode_Test_Header",
                    children=(
                        Group(
                            "Mode_Boundary",
                            values=[
                                bytes([(0 << 6) | (ntp_version << 3) | 0]),  # Reserved mode 0
                                bytes([(0 << 6) | (ntp_version << 3) | 1]),  # Symmetric active
                                bytes([(0 << 6) | (ntp_version << 3) | 2]),  # Symmetric passive
                                bytes([(0 << 6) | (ntp_version << 3) | 3]),  # Client
                                bytes(
                                    [(0 << 6) | (ntp_version << 3) | 4]
                                ),  # Server (invalid in request)
                                bytes([(0 << 6) | (ntp_version << 3) | 5]),  # Broadcast
                                bytes([(0 << 6) | (ntp_version << 3) | 6]),  # Control
                                bytes([(0 << 6) | (ntp_version << 3) | 7]),  # Private
                            ],
                        ),
                        Byte("Stratum", 0x00),
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                )
            ),
        )

        # Stratum Boundary Testing
        stratum_boundary_test = Request(
            "NTP_Stratum_Boundary",
            children=(
                Block(
                    "Stratum_Test_Header",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (ntp_version << 3) | ntp_mode),
                        Group(
                            "Stratum_Boundary",
                            values=[
                                bytes([0]),  # Kiss of Death / unspecified
                                bytes([1]),  # Primary reference
                                bytes([2]),  # Secondary
                                bytes([8]),  # Mid-range
                                bytes([15]),  # Maximum valid
                                bytes([16]),  # Invalid (unsynchronized)
                                bytes([127]),  # Mid-invalid range
                                bytes([255]),  # Maximum value
                            ],
                        ),
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                )
            ),
        )

        # Poll Interval Boundary Testing
        poll_boundary_test = Request(
            "NTP_Poll_Boundary",
            children=(
                Block(
                    "Poll_Test_Header",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (ntp_version << 3) | ntp_mode),
                        Byte("Stratum", 0x00),
                        Group(
                            "Poll_Boundary",
                            values=[
                                bytes([0]),  # 1 second (2^0) - too frequent
                                bytes([3]),  # 8 seconds (2^3) - minpoll
                                bytes([4]),  # 16 seconds (2^4)
                                bytes([6]),  # 64 seconds (2^6) - typical default
                                bytes([10]),  # 1024 seconds (2^10) - maxpoll
                                bytes([17]),  # ~36 hours (2^17) - excessive
                                bytes([255]),  # Invalid maximum
                            ],
                        ),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                )
            ),
        )

        # Precision Boundary Testing
        precision_boundary_test = Request(
            "NTP_Precision_Boundary",
            children=(
                Block(
                    "Precision_Test_Header",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (ntp_version << 3) | ntp_mode),
                        Byte("Stratum", 0x00),
                        Byte("Poll", 0x06),
                        Group(
                            "Precision_Boundary",
                            values=[
                                bytes([0]),  # 1 second (2^0)
                                bytes([0xE0]),  # ~1ms (2^-32) - typical
                                bytes([0xEC]),  # ~244ns (2^-20) - high precision
                                bytes([0xF0]),  # ~16ns (2^-16) - very high
                                bytes([0x7F]),  # Maximum positive (huge positive value)
                                bytes([0x80]),  # -128 (sign bit flip)
                                bytes([0xFF]),  # -1 (2^-1 = 0.5s)
                            ],
                        ),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                )
            ),
        )

        # Timestamp Epoch Boundary Testing
        timestamp_epoch_test = Request(
            "NTP_Timestamp_Epoch_Boundary",
            children=(
                Block(
                    "Epoch_Test_Header",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (ntp_version << 3) | ntp_mode),
                        Byte("Stratum", 0x00),
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        DWord("ReferenceID", 0, endian=">"),
                        # Critical epoch boundaries
                        Group(
                            "Epoch_Timestamps",
                            values=[
                                struct.pack(
                                    ">Q", 0x0000000000000000
                                ),  # NTP epoch start (1900-01-01)
                                struct.pack(">Q", 0x0000000100000000),  # 1900-01-01 + 1 second
                                struct.pack(">Q", 0x83AA7E8000000000),  # Unix epoch (1970-01-01)
                                struct.pack(
                                    ">Q", 0xFFFFFFFF00000000
                                ),  # NTP era 0 end (2036-02-07) - CRITICAL!
                                struct.pack(
                                    ">Q", 0x0000000000000001
                                ),  # NTP era 1 start (with wraparound)
                                struct.pack(
                                    ">Q", 0x7FFFFFFF00000000
                                ),  # Unix 32-bit overflow (2038-01-19)
                                struct.pack(">Q", 0xFFFFFFFFFFFFFFFF),  # Maximum timestamp
                                struct.pack(">Q", 0x8000000000000000),  # Sign bit flip
                            ],
                        ),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                )
            ),
        )

        # Root Delay Boundary Testing
        root_delay_test = Request(
            "NTP_Root_Delay_Boundary",
            children=(
                Block(
                    "RootDelay_Test_Header",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (ntp_version << 3) | ntp_mode),
                        Byte("Stratum", 0x00),
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        Group(
                            "RootDelay_Boundary",
                            values=[
                                struct.pack(">I", 0x00000000),  # Zero delay (perfect)
                                struct.pack(">I", 0x00000001),  # Minimum non-zero (~15ps)
                                struct.pack(">I", 0x00010000),  # ~1ms
                                struct.pack(">I", 0x00100000),  # ~1 second
                                struct.pack(
                                    ">I", 0x7FFFFFFF
                                ),  # Maximum positive (signed interpretation)
                                struct.pack(">I", 0x80000000),  # Sign bit
                                struct.pack(">I", 0xFFFFFFFF),  # Maximum value
                            ],
                        ),
                        DWord("RootDispersion", 0x00010000, endian=">"),  # 1ms
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                )
            ),
        )

        # Root Dispersion Boundary Testing
        root_dispersion_test = Request(
            "NTP_Root_Dispersion_Boundary",
            children=(
                Block(
                    "RootDispersion_Test_Header",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (ntp_version << 3) | ntp_mode),
                        Byte("Stratum", 0x00),
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0x00010000, endian=">"),  # 1ms
                        Group(
                            "RootDispersion_Boundary",
                            values=[
                                struct.pack(">I", 0x00000000),  # Zero dispersion
                                struct.pack(">I", 0x00000001),  # Minimum non-zero
                                struct.pack(">I", 0x00010000),  # ~1ms
                                struct.pack(">I", 0x01000000),  # High dispersion (~16s)
                                struct.pack(">I", 0x7FFFFFFF),  # Maximum positive
                                struct.pack(">I", 0x80000000),  # Sign bit
                                struct.pack(">I", 0xFFFFFFFF),  # Maximum (poor quality)
                            ],
                        ),
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                )
            ),
        )

        # Extension Field Length Attack Testing
        extension_length_attack = Request(
            "NTP_Extension_Length_Attack",
            children=(
                Block(
                    "NTP_Header_Ext_Length",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (4 << 3) | ntp_mode),  # NTPv4 required
                        Byte("Stratum", 0x00),
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                ),
                Block(
                    "Extension_Length_Attack",
                    children=(
                        Word("ExtType", 0x0104, endian=">"),  # NTS Cookie
                        Group(
                            "ExtLength_Boundary",
                            values=[
                                struct.pack(">H", 0),  # Zero length (invalid)
                                struct.pack(">H", 1),  # Too small (minimum is 4)
                                struct.pack(">H", 2),  # Still too small
                                struct.pack(">H", 3),  # Still too small
                                struct.pack(">H", 4),  # Minimum valid (header only)
                                struct.pack(">H", 8),  # Valid small
                                struct.pack(">H", 16),  # Valid medium
                                struct.pack(">H", 1024),  # Large
                                struct.pack(">H", 32768),  # Very large
                                struct.pack(">H", 65535),  # Maximum 16-bit value
                            ],
                        ),
                        SmartString("ExtData", "ext-data", max_len=2000, fuzzable=True),
                    ),
                ),
            ),
        )

        # Reference ID Boundary Testing
        reference_id_test = Request(
            "NTP_Reference_ID_Boundary",
            children=(
                Block(
                    "RefID_Test_Header",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (ntp_version << 3) | ntp_mode),
                        Byte("Stratum", 0x02),  # Stratum 2 (IPv4 address in RefID)
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        Group(
                            "RefID_Boundary",
                            values=[
                                struct.pack(">I", 0x00000000),  # Null
                                struct.pack(">I", 0x7F000001),  # 127.0.0.1 (localhost)
                                struct.pack(">I", 0xC0A80001),  # 192.168.0.1 (private)
                                struct.pack(">I", 0x08080808),  # 8.8.8.8 (Google DNS)
                                struct.pack(">I", 0xFFFFFFFF),  # Broadcast/invalid
                                struct.pack(">I", 0xDEADBEEF),  # Invalid pattern
                                struct.pack(">I", 0x47505300),  # "GPS\x00" (invalid for stratum 2+)
                                struct.pack(">I", 0x41544F4D),  # "ATOM" (invalid for stratum 2+)
                            ],
                        ),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                )
            ),
        )

        # Timestamp Fraction Field Testing
        timestamp_fraction_test = Request(
            "NTP_Timestamp_Fraction_Boundary",
            children=(
                Block(
                    "Fraction_Test_Header",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (ntp_version << 3) | ntp_mode),
                        Byte("Stratum", 0x00),
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        # Testing fractional second boundaries
                        Group(
                            "TransmitTimestamp_Fraction",
                            values=[
                                struct.pack(
                                    ">Q", self._get_ntp_timestamp() & 0xFFFFFFFF00000000
                                ),  # Zero fraction
                                struct.pack(
                                    ">Q",
                                    (self._get_ntp_timestamp() & 0xFFFFFFFF00000000) | 0x00000001,
                                ),  # Min fraction
                                struct.pack(
                                    ">Q",
                                    (self._get_ntp_timestamp() & 0xFFFFFFFF00000000) | 0x80000000,
                                ),  # 0.5 second
                                struct.pack(
                                    ">Q",
                                    (self._get_ntp_timestamp() & 0xFFFFFFFF00000000) | 0xFFFFFFFF,
                                ),  # Max fraction
                            ],
                        ),
                    ),
                )
            ),
        )

        # ============================================================
        # PHASE 1: QUICK COVERAGE (~30 seconds)
        # Single request that touches all NTP modes and key operations
        # ============================================================

        quick_coverage = Request(
            "NTP_Quick_Coverage",
            children=(
                Block(
                    "Quick_All_Modes",
                    children=(
                        # Sweep through all 8 modes (0-7) plus version variants
                        # This ensures every code path is touched within first 30 seconds
                        Group(
                            "Mode_Sweep",
                            values=[
                                # Mode 0: Reserved (invalid)
                                bytes([(0 << 6) | (ntp_version << 3) | 0])
                                + b"\x00\x06\xec"
                                + b"\x00" * 44,
                                # Mode 1: Symmetric Active
                                bytes([(0 << 6) | (ntp_version << 3) | 1])
                                + b"\x00\x06\xec"
                                + b"\x00" * 44,
                                # Mode 2: Symmetric Passive
                                bytes([(0 << 6) | (ntp_version << 3) | 2])
                                + b"\x00\x06\xec"
                                + b"\x00" * 44,
                                # Mode 3: Client (standard)
                                bytes([(0 << 6) | (ntp_version << 3) | 3])
                                + b"\x00\x06\xec"
                                + b"\x00" * 44,
                                # Mode 4: Server
                                bytes([(0 << 6) | (ntp_version << 3) | 4])
                                + b"\x00\x06\xec"
                                + b"\x00" * 44,
                                # Mode 5: Broadcast
                                bytes([(0 << 6) | (ntp_version << 3) | 5])
                                + b"\x01\x06\xec"
                                + b"\x00" * 44,
                                # Mode 6: Control - with CTL_OP_READVAR (1)
                                bytes([(0 << 6) | (ntp_version << 3) | 6, 0x01]) + b"\x00" * 10,
                                # Mode 6: Control - with CTL_OP_WRITEVAR (2)
                                bytes([(0 << 6) | (ntp_version << 3) | 6, 0x02]) + b"\x00" * 10,
                                # Mode 6: Control - with CTL_OP_TRAP (6) - CVE-2016-9311
                                bytes([(0 << 6) | (ntp_version << 3) | 6, 0x06]) + b"\x00" * 10,
                                # Mode 7: Private - REQ_MON_GETLIST_1 (42) - CVE-2013-5211
                                bytes([(0 << 6) | (ntp_version << 3) | 7, 0x03, 0x2A, 0x00])
                                + b"\x00" * 8,
                                # Mode 7: Private - REQ_PEER_LIST (0)
                                bytes([(0 << 6) | (ntp_version << 3) | 7, 0x03, 0x00, 0x00])
                                + b"\x00" * 8,
                                # NTPv3 variants
                                bytes([(0 << 6) | (3 << 3) | 3]) + b"\x00\x06\xec" + b"\x00" * 44,
                                bytes([(0 << 6) | (3 << 3) | 6, 0x01]) + b"\x00" * 10,
                                bytes([(0 << 6) | (3 << 3) | 7, 0x03, 0x2A, 0x00]) + b"\x00" * 8,
                                # NTPv4 with extension field (minimal)
                                bytes([(0 << 6) | (4 << 3) | 3])
                                + b"\x00\x06\xec"
                                + b"\x00" * 44
                                + b"\x01\x04\x00\x08"
                                + b"test",
                                # Kiss of Death (LI=3, stratum=0)
                                bytes([(3 << 6) | (ntp_version << 3) | 4, 0x00, 0x00, 0x00])
                                + b"\x00" * 8
                                + b"RATE"
                                + b"\x00" * 32,
                                # Autokey extension
                                bytes([(0 << 6) | (4 << 3) | 3])
                                + b"\x00\x06\xec"
                                + b"\x00" * 44
                                + b"\x00\x02\x00\x10"
                                + b"\x00" * 16,
                            ],
                        ),
                    ),
                )
            ),
        )

        # ============================================================
        # PHASE 2: HIGH-CRASH TESTS (30s - 2 minutes)
        # Buffer overflows, length attacks, malformed packets
        # ============================================================

        # Extension Length Overflow Attack
        extension_overflow = Request(
            "NTP_Extension_Overflow",
            children=(
                Block(
                    "NTP_Header_Overflow",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (4 << 3) | 3),  # NTPv4 client
                        Byte("Stratum", 0x00),
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                ),
                Block(
                    "Overflow_Extension",
                    children=(
                        Word("ExtType", 0x0104, endian=">"),  # NTS Cookie
                        # Length values designed to trigger buffer overflows
                        Group(
                            "Overflow_Length",
                            values=[
                                struct.pack(">H", 0xFFFF),  # Maximum 16-bit
                                struct.pack(">H", 0x8000),  # Large signed
                                struct.pack(">H", 0x7FFF),  # Max signed
                                struct.pack(">H", 0x1000),  # 4KB
                                struct.pack(">H", 0x0800),  # 2KB
                                struct.pack(">H", 0x0400),  # 1KB
                            ],
                        ),
                        # Payload with overflow pattern
                        SmartString("OverflowData", "A" * 1500, max_len=2000, fuzzable=True),
                    ),
                ),
            ),
        )

        # Crypto-NAK Buffer Attack (CVE-2014-9295)
        crypto_nak_attack = Request(
            "NTP_Crypto_NAK_Attack",
            children=(
                Block(
                    "CryptoNAK_Header",
                    children=(
                        Byte("LI_VN_Mode", (0 << 6) | (4 << 3) | 3),  # NTPv4 client
                        Byte("Stratum", 0x00),
                        Byte("Poll", 0x06),
                        Byte("Precision", 0xEC),
                        DWord("RootDelay", 0, endian=">"),
                        DWord("RootDispersion", 0, endian=">"),
                        DWord("ReferenceID", 0, endian=">"),
                        QWord("ReferenceTimestamp", 0, endian=">"),
                        QWord("OriginateTimestamp", 0, endian=">"),
                        QWord("ReceiveTimestamp", 0, endian=">"),
                        QWord("TransmitTimestamp", self._get_ntp_timestamp(), endian=">"),
                    ),
                ),
                Block(
                    "CryptoNAK_Extension",
                    children=(
                        # Crypto-NAK: Extension with Key ID = 0 and no MAC
                        DWord("KeyID", 0, endian=">"),  # Key ID 0 = crypto-NAK
                        # Malformed digest with various sizes
                        Group(
                            "NAK_Digest",
                            values=[
                                b"",  # Empty digest
                                b"\x00" * 4,  # Too short
                                b"\x00" * 8,  # Still too short
                                b"\x00" * 16,  # MD5 size
                                b"\x00" * 20,  # SHA1 size
                                b"\x00" * 32,  # SHA256 size
                                b"\xff" * 16,  # All 1s MD5
                                b"\xff" * 64,  # Oversized
                                b"A" * 256,  # Large buffer
                            ],
                        ),
                    ),
                ),
            ),
        )

        # ============================================================
        # PHASE 3: CVE-TARGETED OPERATIONS (2-5 minutes)
        # Specific attacks for known vulnerabilities
        # ============================================================

        # Mode 7 Monlist Attack (CVE-2013-5211)
        monlist_attack = Request(
            "NTP_Monlist_Attack",
            children=(
                Block(
                    "Monlist_Header",
                    children=(
                        Byte("Private_LI_VN_Mode", (0 << 6) | (ntp_version << 3) | 7),  # Mode 7
                        Byte("Implementation", 0x03, fuzzable=True),  # XNTPD
                        # Request codes that can leak information
                        Group(
                            "Monlist_Request",
                            values=[
                                bytes([0x2A]),  # REQ_MON_GETLIST_1 (42) - CVE-2013-5211
                                bytes([0x00]),  # REQ_PEER_LIST
                                bytes([0x01]),  # REQ_PEER_LIST_SUM
                                bytes([0x02]),  # REQ_PEER_INFO
                                bytes([0x04]),  # REQ_MEM_STATS
                                bytes([0x05]),  # REQ_IO_STATS
                                bytes([0x06]),  # REQ_TIMER_STATS
                                bytes([0x07]),  # REQ_CONFIG
                                bytes([0x08]),  # REQ_UNCONFIG
                                bytes([0x09]),  # REQ_SET_SYS_FLAG
                                bytes([0x0A]),  # REQ_CLR_SYS_FLAG
                                bytes([0x0B]),  # REQ_MONITOR (obsolete)
                                bytes([0x0C]),  # REQ_NOMONITOR (obsolete)
                                bytes([0x20]),  # REQ_MON_GETLIST (old version)
                            ],
                        ),
                        Byte("Flags", 0x00, fuzzable=True),
                        Word("Sequence", 0, endian=">", fuzzable=True),
                        Word("Status", 0, endian=">", fuzzable=True),
                        Word("DataSize", 0, endian=">", fuzzable=True),
                        DWord("Reserved", 0, endian=">"),
                    ),
                ),
            ),
        )

        # Control Mode Trap Attack (CVE-2016-9311)
        trap_attack = Request(
            "NTP_Trap_Attack",
            children=(
                Block(
                    "Trap_Header",
                    children=(
                        Byte("Control_LI_VN_Mode", (0 << 6) | (ntp_version << 3) | 6),  # Mode 6
                        # Op codes including trap operations
                        Group(
                            "Trap_OpCode",
                            values=[
                                bytes([0x06]),  # CTL_OP_SETTRAP
                                bytes([0x07]),  # CTL_OP_UNSETTRAP
                                bytes([0x1F]),  # Invalid op code
                                bytes([0xFF]),  # Maximum op code
                            ],
                        ),
                        Word("Sequence", 0, endian=">", fuzzable=True),
                        Word("Status", 0, endian=">", fuzzable=True),
                        Word("AssociationID", 0, endian=">", fuzzable=True),
                        Word("Offset", 0, endian=">", fuzzable=True),
                        Word("Count", 0, endian=">", fuzzable=True),
                        # Trap data with various payloads
                        SmartString("Trap_Data", "trap_attack_data", max_len=468, fuzzable=True),
                    ),
                ),
            ),
        )

        # ============================================================
        # Connect requests in optimized order
        # ============================================================

        # PHASE 1: Quick Coverage (first ~30 seconds)
        # Single request that sweeps all modes and key operations
        if self.is_request_enabled("NTP_Quick_Coverage"):
            self.session.connect(quick_coverage)

        # PHASE 2: High-Crash Tests (30s - 2 minutes)
        # These are most likely to find crashes quickly
        if self.is_request_enabled("NTP_Malformed"):
            self.session.connect(malformed_ntp)  # Invalid field combinations
        if self.is_request_enabled("NTP_Extension_Overflow"):
            self.session.connect(extension_overflow)  # Buffer overflow via extension
        if self.is_request_enabled("NTP_Crypto_NAK_Attack"):
            self.session.connect(crypto_nak_attack)  # CVE-2014-9295
        if self.is_request_enabled("NTP_Extension_Length_Attack"):
            self.session.connect(extension_length_attack)  # Extension length boundary

        # PHASE 3: CVE-Targeted Operations (2 - 5 minutes)
        # Known vulnerability patterns
        if self.is_request_enabled("NTP_Monlist_Attack"):
            self.session.connect(monlist_attack)  # CVE-2013-5211
        if self.is_request_enabled("NTP_Trap_Attack"):
            self.session.connect(trap_attack)  # CVE-2016-9311
        if self.is_request_enabled("NTP_Private_Request"):
            self.session.connect(private_req)  # Mode 7 deep fuzzing
        if self.is_request_enabled("NTP_Control_Message"):
            self.session.connect(control_msg)  # Mode 6 deep fuzzing

        # PHASE 4: Boundary Attacks (5 - 10 minutes)
        # Systematic boundary value testing
        if self.is_request_enabled("NTP_Timestamp_Epoch_Boundary"):
            self.session.connect(timestamp_epoch_test)  # Critical epoch boundaries (2036, 2038)
        if self.is_request_enabled("NTP_Version_Boundary"):
            self.session.connect(version_boundary_test)  # Version 0-7
        if self.is_request_enabled("NTP_Mode_Boundary"):
            self.session.connect(mode_boundary_test)  # Mode 0-7
        if self.is_request_enabled("NTP_Stratum_Boundary"):
            self.session.connect(stratum_boundary_test)  # Stratum 0-255
        if self.is_request_enabled("NTP_Leap_Indicator_Boundary"):
            self.session.connect(leap_indicator_test)  # LI 0-3
        if self.is_request_enabled("NTP_Poll_Boundary"):
            self.session.connect(poll_boundary_test)  # Poll interval
        if self.is_request_enabled("NTP_Precision_Boundary"):
            self.session.connect(precision_boundary_test)  # Precision values
        if self.is_request_enabled("NTP_Root_Delay_Boundary"):
            self.session.connect(root_delay_test)  # Root delay boundaries
        if self.is_request_enabled("NTP_Root_Dispersion_Boundary"):
            self.session.connect(root_dispersion_test)  # Root dispersion boundaries
        if self.is_request_enabled("NTP_Reference_ID_Boundary"):
            self.session.connect(reference_id_test)  # Reference ID patterns
        if self.is_request_enabled("NTP_Timestamp_Fraction_Boundary"):
            self.session.connect(timestamp_fraction_test)  # Fractional timestamp

        # PHASE 5: Deep Fuzzing (10+ minutes)
        # Standard protocol operations with full mutation
        if self.is_request_enabled("NTP_Client_Request"):
            self.session.connect(client_req)  # Standard client request
        if self.is_request_enabled("NTP_Broadcast_Message"):
            self.session.connect(broadcast_msg)  # Broadcast mode
        if self.is_request_enabled("NTP_Kiss_Of_Death"):
            self.session.connect(kiss_of_death)  # KoD messages
        if self.is_request_enabled("NTP_Extension_Request"):
            self.session.connect(extension_req)  # Single extension
        if self.is_request_enabled("NTP_Multi_Extension_Request"):
            self.session.connect(multi_ext_req)  # Multiple extensions
        if self.is_request_enabled("NTP_Autokey_Request"):
            self.session.connect(autokey_req)  # Autokey protocol
        if enable_auth and self.is_request_enabled("NTP_Auth_Request"):
            self.session.connect(auth_req)  # Authenticated requests

    def _get_ntp_timestamp(self):
        """Generate current NTP timestamp"""
        # NTP timestamp: seconds since 1900-01-01 00:00:00
        ntp_epoch = 2208988800  # Seconds between 1900 and 1970
        current_time = time.time()
        ntp_seconds = int(current_time + ntp_epoch)
        ntp_fraction = int((current_time % 1) * (2**32))
        return (ntp_seconds << 32) | ntp_fraction
