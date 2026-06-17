"""BACnet Protocol Fuzzer

BACnet/IP uses UDP with the following protocol stack:
1. BVLC (BACnet Virtual Link Control) Header:
   - Type: 0x81 (BACnet/IP)
   - Function: 0x0a (Original-Unicast-NPDU) or 0x0b (Original-Broadcast-NPDU)
   - Length: 2 bytes (total message length including BVLC header)

2. NPDU (Network Protocol Data Unit):
   - Version: 0x01 (ASHRAE 135-1995)
   - Control: Flags for message type, dest/src specifiers, priority
   - Optional: Destination/Source network info, hop count

3. APDU (Application Protocol Data Unit):
   - Type: Upper nibble (0=confirmed, 1=unconfirmed, 2=simple-ack, etc.)
   - Service: Service choice (e.g., 0x08=Who-Is, 0x0C=ReadProperty)
   - Data: Service-specific parameters

Fuzzer Optimization Strategy (Breadth-First):
==============================================
Phase 1 (0-30s): Quick Coverage - all 18 service types once
Phase 2 (30s-3m): High-crash tests - malformed APDU, buffer overflow
Phase 3 (3-6m): CVE-targeted - WriteProperty, ReinitializeDevice, DeviceCommControl
Phase 4 (6-10m): Boundary attacks - field limits, invalid values
Phase 5 (10m+): Remaining tests - discovery, event services, VT

CVE Coverage:
- CVE-2019-9569: Malformed APDU causes crash (buffer overflow)
- CVE-2022-4873: ReinitializeDevice without auth
- CVE-2021-32926: WriteProperty unauthorized access
- CVE-2020-12029: DeviceCommunicationControl DoS
- CVE-2017-16744: Time synchronization manipulation
"""

from typing import List

from boofuzz import Block, Byte, DWord, Group, Request, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import ProtocolType
from ..primitives.dynamic import SmartString, StringContext


# BACnet service codes for quick reference
class BACnetServiceCodes:
    """BACnet confirmed and unconfirmed service codes"""

    # Unconfirmed Services (APDU type 0x10)
    I_AM = 0x00
    I_HAVE = 0x01
    UNCONFIRMED_COV_NOTIFICATION = 0x02
    UNCONFIRMED_EVENT_NOTIFICATION = 0x03
    UNCONFIRMED_PRIVATE_TRANSFER = 0x04
    UNCONFIRMED_TEXT_MESSAGE = 0x05
    TIME_SYNCHRONIZATION = 0x06
    WHO_HAS = 0x07
    WHO_IS = 0x08
    UTC_TIME_SYNCHRONIZATION = 0x09

    # Confirmed Services (APDU type 0x00)
    ACKNOWLEDGE_ALARM = 0x00
    CONFIRMED_COV_NOTIFICATION = 0x01
    CONFIRMED_EVENT_NOTIFICATION = 0x02
    GET_ALARM_SUMMARY = 0x03
    GET_ENROLLMENT_SUMMARY = 0x04
    SUBSCRIBE_COV = 0x05
    ATOMIC_READ_FILE = 0x06
    ATOMIC_WRITE_FILE = 0x07
    ADD_LIST_ELEMENT = 0x08
    REMOVE_LIST_ELEMENT = 0x09
    CREATE_OBJECT = 0x0A
    DELETE_OBJECT = 0x0B
    READ_PROPERTY = 0x0C
    READ_PROPERTY_CONDITIONAL = 0x0D
    READ_PROPERTY_MULTIPLE = 0x0E
    WRITE_PROPERTY = 0x0F
    WRITE_PROPERTY_MULTIPLE = 0x10
    DEVICE_COMMUNICATION_CONTROL = 0x11
    CONFIRMED_PRIVATE_TRANSFER = 0x12
    CONFIRMED_TEXT_MESSAGE = 0x13
    REINITIALIZE_DEVICE = 0x14
    VT_OPEN = 0x15
    VT_CLOSE = 0x16
    VT_DATA = 0x17
    AUTHENTICATE = 0x18
    REQUEST_KEY = 0x19
    READ_RANGE = 0x1A
    LIFE_SAFETY_OPERATION = 0x1B
    SUBSCRIBE_COV_PROPERTY = 0x1C
    GET_EVENT_INFORMATION = 0x1D


class BACnetFuzzer(BaseFuzzer):
    """BACnet Protocol Fuzzer for building automation security testing

    Targets BACnet vulnerabilities including device discovery, malformed APDU
    packets, property manipulation, and buffer overflow conditions.

    BACnet/IP uses UDP port 47808 (0xBAC0) by default.

    Test Ordering (Optimized for Early Coverage):
    - Phase 1: Quick_Coverage touches all 18 services in ~30 seconds
    - Phase 2: Buffer overflow and malformed APDU tests (high crash likelihood)
    - Phase 3: CVE-targeted write operations (WriteProperty, Reinitialize)
    - Phase 4: Boundary value attacks
    - Phase 5: Discovery, event, and VT services
    """

    PROTOCOL_OPTIONS = {
        "device_instance": {
            "type": int,
            "default": 1234,
            "description": "Target BACnet device instance number",
            "example": "1234",
        },
        "timeout": {
            "type": float,
            "default": 2.0,
            "description": "Response timeout in seconds",
            "example": "2.0",
        },
        "enable_write": {
            "type": bool,
            "default": True,
            "description": "Enable write operations (risky for production devices)",
        },
        "enable_reinit": {
            "type": bool,
            "default": False,
            "description": "Enable ReinitializeDevice testing (can reboot devices)",
        },
        "bacnet_password": {
            "type": str,
            "default": "",
            "description": "BACnet device password for authentication fuzzing",
            "example": "admin123",
        },
        "device_password": {
            "type": str,
            "default": "",
            "description": "Device-specific password for ReinitializeDevice",
            "example": "password",
        },
        "enable_auth": {
            "type": bool,
            "default": False,
            "description": "Enable BACnet authentication service fuzzing",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick Coverage
            RequestInfo(
                "BACnet_Quick_Coverage", "Quick sweep of all 18 service types (~30s)", "baseline"
            ),
            # Phase 2: High-crash tests
            RequestInfo(
                "BACnet_Malformed_APDU",
                "Malformed APDU buffer overflow (CVE-2019-9569)",
                "overflow",
            ),
            RequestInfo(
                "BACnet_Overflow_Tests", "Oversized payload and length attacks", "overflow"
            ),
            # Phase 3: CVE-targeted writes
            RequestInfo(
                "BACnet_Write_Operations",
                "WriteProperty/WritePropertyMultiple (CVE-2021-32926)",
                "write",
            ),
            RequestInfo(
                "BACnet_Device_Control",
                "DeviceCommControl + ReinitializeDevice (CVE-2022-4873)",
                "write",
            ),
            # Phase 4: Boundary attacks
            RequestInfo(
                "BACnet_Boundary_Tests", "Field boundary and invalid value testing", "boundary"
            ),
            # Phase 5: Remaining services
            RequestInfo("BACnet_Discovery", "Who-Is, I-Am device discovery", "discovery"),
            RequestInfo(
                "BACnet_Read_Operations",
                "ReadProperty, ReadPropertyMultiple, ReadObjectList",
                "read",
            ),
            RequestInfo("BACnet_Event_Services", "Alarm, Event, and COV services", "event"),
            RequestInfo("BACnet_Time_Services", "TimeSynchronization (CVE-2017-16744)", "time"),
            RequestInfo("BACnet_VT_Services", "Virtual Terminal session attacks", "vt"),
            RequestInfo(
                "BACnet_Object_Services", "CreateObject, DeleteObject operations", "object"
            ),
            RequestInfo(
                "BACnet_Auth_Services", "Authenticate and RequestKey service fuzzing", "auth"
            ),
        ]

    def __init__(self, config, connection_factory=None):
        # BACnet uses UDP
        config.protocol_type = ProtocolType.UDP
        super().__init__(config, connection_factory)

    def _create_socket(self):
        """Create UDP socket configured for bidirectional BACnet communication.

        BACnet/IP requires binding to a local port to receive responses.
        The bind tuple (host, port) specifies where to listen for responses.
        Using port 0 lets the OS pick an available ephemeral port.
        """
        from boofuzz import UDPSocketConnection

        return UDPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            bind=("0.0.0.0", 0),  # Bind to any interface, ephemeral port
            **self._timeout_overrides(recv_default=2.0),  # Wait up to 2 seconds for response
        )

    def _create_bvlc_header(self, function: int = 0x0A, length: int = 0x000C) -> Block:
        """Create standard BVLC header block.

        Args:
            function: BVLC function (0x0A=Unicast, 0x0B=Broadcast)
            length: Total message length including BVLC header
        """
        return Block(
            "BVLC_Header",
            children=(
                Byte("BVLL_Type", 0x81),  # BACnet/IP
                Byte("BVLL_Function", function),
                Word("BVLL_Length", length, endian=">"),
            ),
        )

    def _create_npdu_unicast(self) -> Block:
        """Create NPDU header for unicast (expecting reply)."""
        return Block(
            "NPDU_Header",
            children=(
                Byte("NPDU_Version", 0x01),
                Byte("NPDU_Control", 0x04),  # Expecting reply
            ),
        )

    def _create_npdu_broadcast(self) -> Block:
        """Create NPDU header for broadcast."""
        return Block(
            "NPDU_Header",
            children=(
                Byte("NPDU_Version", 0x01),
                Byte("NPDU_Control", 0x20),  # Destination specifier present
                Word("DEST_Network", 0xFFFF, endian=">"),  # Global broadcast
                Byte("DLEN", 0x00),  # Broadcast
                Byte("HOP_Count", 0xFF),
            ),
        )

    def _define_protocol(self) -> None:
        """Define BACnet protocol structure with vulnerability patterns.

        Test Ordering Strategy (Breadth-First Optimized):
        =================================================
        Phase 1 (0-30s): Quick_Coverage - all service types once
        Phase 2 (30s-3m): High-crash tests - malformed APDU, overflow
        Phase 3 (3-6m): CVE-targeted writes - WriteProperty, Reinitialize
        Phase 4 (6-10m): Boundary attacks - field limits
        Phase 5 (10m+): Discovery, events, VT services
        """

        # ================================================================
        # PHASE 1: QUICK COVERAGE (~30 seconds)
        # Touch all 18 BACnet service types once for maximum breadth
        # ================================================================

        # Quick Coverage Request - cycles through all service types
        # Uses Group primitive to test each service code once
        quick_coverage = Request(
            "BACnet_Quick_Coverage",
            children=(
                Block(
                    "BVLC_Header_QC",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0010, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_QC",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_QC",
                    children=(
                        # Test confirmed services (most common attack surface)
                        Group(
                            "Service_Choice",
                            values=[
                                # Confirmed services (APDU type 0x00)
                                bytes(
                                    [0x00, BACnetServiceCodes.READ_PROPERTY, 0x01]
                                ),  # ReadProperty
                                bytes(
                                    [0x00, BACnetServiceCodes.WRITE_PROPERTY, 0x01]
                                ),  # WriteProperty
                                bytes(
                                    [0x00, BACnetServiceCodes.READ_PROPERTY_MULTIPLE, 0x01]
                                ),  # ReadPropertyMultiple
                                bytes(
                                    [0x00, BACnetServiceCodes.WRITE_PROPERTY_MULTIPLE, 0x01]
                                ),  # WritePropertyMultiple
                                bytes(
                                    [0x00, BACnetServiceCodes.SUBSCRIBE_COV, 0x01]
                                ),  # SubscribeCOV
                                bytes(
                                    [0x00, BACnetServiceCodes.CONFIRMED_EVENT_NOTIFICATION, 0x01]
                                ),
                                bytes([0x00, BACnetServiceCodes.GET_ALARM_SUMMARY, 0x01]),
                                bytes([0x00, BACnetServiceCodes.GET_EVENT_INFORMATION, 0x01]),
                                bytes(
                                    [0x00, BACnetServiceCodes.DEVICE_COMMUNICATION_CONTROL, 0x01]
                                ),
                                bytes([0x00, BACnetServiceCodes.REINITIALIZE_DEVICE, 0x01]),
                                bytes([0x00, BACnetServiceCodes.CREATE_OBJECT, 0x01]),
                                bytes([0x00, BACnetServiceCodes.DELETE_OBJECT, 0x01]),
                                bytes([0x00, BACnetServiceCodes.VT_OPEN, 0x01]),
                                bytes([0x00, BACnetServiceCodes.ATOMIC_READ_FILE, 0x01]),
                                bytes([0x00, BACnetServiceCodes.ATOMIC_WRITE_FILE, 0x01]),
                            ],
                        ),
                    ),
                ),
                # Minimal valid payload for most services
                Byte("Object_ID_Tag", 0x0C),
                DWord("Object_ID", 0x020004D2, endian=">"),
                Byte("Property_ID_Tag", 0x19),
                Byte("Property_Value", 0x4D),
            ),
        )

        # Quick Coverage - Unconfirmed Services
        quick_coverage_unconfirmed = Request(
            "BACnet_Quick_Coverage_Unconfirmed",
            children=(
                Block(
                    "BVLC_Header_QCU",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0B),
                        Word("BVLL_Length", 0x000C, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_QCU",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x20),
                        Word("DEST_Network", 0xFFFF, endian=">"),
                        Byte("DLEN", 0x00),
                        Byte("HOP_Count", 0xFF),
                    ),
                ),
                Block(
                    "APDU_Header_QCU",
                    children=(
                        Byte("APDU_Type", 0x10),  # Unconfirmed
                        Group(
                            "Service_Choice",
                            values=[
                                bytes([BACnetServiceCodes.WHO_IS]),
                                bytes([BACnetServiceCodes.I_AM]),
                                bytes([BACnetServiceCodes.TIME_SYNCHRONIZATION]),
                            ],
                        ),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 2: HIGH-CRASH TESTS (buffer overflow, malformed packets)
        # These tests trigger CVE-2019-9569 type vulnerabilities
        # ================================================================

        # Malformed APDU - Buffer Overflow Testing (CVE-2019-9569 pattern)
        malformed_apdu = Request(
            "BACnet_Malformed_APDU",
            children=(
                Block(
                    "BVLC_Header_MAL",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x00FF, endian=">"),  # Large length
                    ),
                ),
                Block(
                    "NPDU_Header_MAL",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0xFF),  # Invalid control flags
                    ),
                ),
                Block(
                    "APDU_Header_MAL",
                    children=(
                        Byte("APDU_Type", 0xFF),  # Invalid APDU type
                        Byte("PDU_Flags", 0xFF),
                        Byte("Invoke_ID", 0xFF),
                        Byte("Service_Choice", 0xFF),
                    ),
                ),
                SmartString("Oversized_Payload", "A" * 200),
            ),
        )

        # BVLC Length Field Overflow
        bvlc_overflow = Request(
            "BACnet_BVLC_Overflow",
            children=(
                Block(
                    "BVLC_Header_OVF",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Group(
                            "Length_Overflow",
                            values=[
                                b"\xff\xff",  # Maximum length (65535)
                                b"\x00\x00",  # Zero length
                                b"\x00\x03",  # Too short for valid packet
                                b"\x10\x00",  # 4096 bytes
                            ],
                        ),
                    ),
                ),
                Block(
                    "NPDU_Header_OVF",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Payload_OVF",
                    children=(
                        Byte("APDU_Type", 0x00),
                        Byte("Service_Choice", 0x0C),
                        Byte("Invoke_ID", 0x01),
                    ),
                ),
                SmartString("Overflow_Data", "B" * 250),
            ),
        )

        # NPDU Control Byte Fuzzing
        npdu_control_fuzz = Request(
            "BACnet_NPDU_Control_Fuzz",
            children=(
                Block(
                    "BVLC_Header_NPDU",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0014, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_NPDU",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Group(
                            "NPDU_Control_Fuzz",
                            values=[
                                b"\x00",  # No options
                                b"\x04",  # Expecting reply
                                b"\x08",  # Source specifier present
                                b"\x20",  # Destination specifier present
                                b"\x28",  # Both specifiers
                                b"\x80",  # Network layer message
                                b"\xff",  # All bits set
                                b"\x7f",  # High bits
                            ],
                        ),
                    ),
                ),
                Block(
                    "APDU_Payload_NPDU",
                    children=(
                        Byte("APDU_Type", 0x00),
                        Byte("Service_Choice", 0x0C),
                        Byte("Invoke_ID", 0x01),
                        Byte("Object_ID_Tag", 0x0C),
                        DWord("Object_ID", 0x020004D2, endian=">"),
                        Byte("Property_ID_Tag", 0x19),
                        Byte("Property_Value", 0x4D),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 3: CVE-TARGETED WRITE OPERATIONS
        # WriteProperty (CVE-2021-32926), ReinitializeDevice (CVE-2022-4873)
        # DeviceCommunicationControl (CVE-2020-12029)
        # ================================================================

        # BACnet Write Property Request (CVE-2021-32926 target)
        write_property = Request(
            "BACnet_Write_Property",
            children=(
                Block(
                    "BVLC_Header_WP",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0017, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_WP",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_WP",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.WRITE_PROPERTY),
                        Byte("Invoke_ID", 0x02),
                    ),
                ),
                Byte("Object_ID_Tag", 0x0C),
                DWord("Object_ID", 0x00800001, endian=">"),
                Byte("Property_ID_Tag", 0x19),
                Byte("Property_ID", 0x55),  # Present-Value
                Byte("Value_Opening_Tag", 0x3E),
                Byte("Value_App_Tag", 0x44),
                DWord("Value_Real", 0x42C80000, endian=">"),  # 100.0
                Byte("Value_Closing_Tag", 0x3F),
            ),
        )

        # BACnet Write Property Multiple
        write_property_multiple = Request(
            "BACnet_Write_Property_Multiple",
            children=(
                Block(
                    "BVLC_Header_WPM",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0019, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_WPM",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_WPM",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.WRITE_PROPERTY_MULTIPLE),
                        Byte("Invoke_ID", 0x06),
                    ),
                ),
                Byte("Object_ID_Tag", 0x0C),
                DWord("Target_Object_ID", 0x00800001, endian=">"),
                Byte("Prop_List_Open", 0x1E),
                Byte("Property_ID_Tag", 0x09),
                Byte("Property_ID", 0x55),
                Byte("Value_Opening_Tag", 0x2E),
                Byte("Value_App_Tag", 0x44),
                DWord("Value_Real", 0x42C80000, endian=">"),
                Byte("Value_Closing_Tag", 0x2F),
                Byte("Prop_List_Close", 0x1F),
            ),
        )

        # BACnet Reinitialize Device (CVE-2022-4873 - dangerous!)
        reinit_device = Request(
            "BACnet_Reinitialize_Device",
            children=(
                Block(
                    "BVLC_Header_RD",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x000C, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_RD",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_RD",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.REINITIALIZE_DEVICE),
                        Byte("Invoke_ID", 0x04),
                    ),
                ),
                Byte("Reinit_State_Tag", 0x09),
                Group(
                    "Reinitialization_State",
                    values=[
                        b"\x00",  # ColdStart
                        b"\x01",  # WarmStart
                        b"\x02",  # StartBackup
                        b"\x03",  # EndBackup
                        b"\x04",  # StartRestore
                        b"\x05",  # EndRestore
                        b"\x06",  # AbortRestore
                    ],
                ),
                Byte("Padding", 0x00),
            ),
        )

        # BACnet Device Communication Control (CVE-2020-12029 - DoS)
        device_comm_control = Request(
            "BACnet_Device_Communication_Control",
            children=(
                Block(
                    "BVLC_Header_DCC",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x000C, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_DCC",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_DCC",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.DEVICE_COMMUNICATION_CONTROL),
                        Byte("Invoke_ID", 0x03),
                    ),
                ),
                Byte("Enable_Disable_Tag", 0x19),
                Group(
                    "Enable_Disable",
                    values=[
                        b"\x00",  # Enable
                        b"\x01",  # Disable
                        b"\x02",  # DisableInitiation
                    ],
                ),
                Byte("Padding", 0x00),
            ),
        )

        # ================================================================
        # PHASE 4: BOUNDARY VALUE ATTACKS
        # ================================================================

        # Object ID Boundary Testing
        object_id_boundary = Request(
            "BACnet_Object_ID_Boundary",
            children=(
                Block(
                    "BVLC_Header_OIB",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x000F, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_OIB",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_OIB",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.READ_PROPERTY),
                        Byte("Invoke_ID", 0x01),
                    ),
                ),
                Byte("Object_ID_Tag", 0x0C),
                Group(
                    "Object_ID_Boundary",
                    values=[
                        b"\x00\x00\x00\x00",  # Object type 0, instance 0
                        b"\x00\x00\x00\x01",  # Object type 0, instance 1
                        b"\x00\x3f\xff\xff",  # Object type 0, max instance (4194303)
                        b"\x00\x80\x00\x00",  # Object type 2, instance 0
                        b"\x02\x00\x04\xd2",  # Device object, instance 1234
                        b"\x3f\xc0\x00\x00",  # Max object type (1023), instance 0
                        b"\xff\xff\xff\xff",  # All bits set (invalid)
                    ],
                ),
                Byte("Property_ID_Tag", 0x19),
                Byte("Property_Value", 0x4D),
            ),
        )

        # Property ID Boundary Testing
        property_id_boundary = Request(
            "BACnet_Property_ID_Boundary",
            children=(
                Block(
                    "BVLC_Header_PIB",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x000F, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_PIB",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_PIB",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.READ_PROPERTY),
                        Byte("Invoke_ID", 0x01),
                    ),
                ),
                Byte("Object_ID_Tag", 0x0C),
                DWord("Device_Object_ID", 0x020004D2, endian=">"),
                Byte("Property_ID_Tag", 0x19),
                Group(
                    "Property_ID_Boundary",
                    values=[
                        b"\x00",  # ackedTransitions (0)
                        b"\x01",  # ackRequired (1)
                        b"\x4c",  # object-list (76)
                        b"\x4d",  # object-name (77)
                        b"\x55",  # present-value (85)
                        b"\x70",  # object-type (112)
                        b"\xff",  # Proprietary start (255)
                        b"\xfe\x00",  # Extended property ID
                    ],
                ),
            ),
        )

        # APDU Type Boundary Testing
        apdu_type_boundary = Request(
            "BACnet_APDU_Type_Boundary",
            children=(
                Block(
                    "BVLC_Header_ATB",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0010, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_ATB",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_ATB",
                    children=(
                        Group(
                            "APDU_Type_Boundary",
                            values=[
                                b"\x00",  # Confirmed-REQ
                                b"\x10",  # Unconfirmed-REQ
                                b"\x20",  # Simple-ACK
                                b"\x30",  # Complex-ACK
                                b"\x40",  # Segment-ACK
                                b"\x50",  # Error
                                b"\x60",  # Reject
                                b"\x70",  # Abort
                                b"\x80",  # Invalid (reserved)
                                b"\xf0",  # Invalid (high nibble)
                                b"\xff",  # Invalid (all bits)
                            ],
                        ),
                        Byte("Service_Choice", 0x0C),
                        Byte("Invoke_ID", 0x01),
                    ),
                ),
                Byte("Object_ID_Tag", 0x0C),
                DWord("Object_ID", 0x020004D2, endian=">"),
                Byte("Property_ID_Tag", 0x19),
                Byte("Property_Value", 0x4D),
            ),
        )

        # ================================================================
        # PHASE 5: REMAINING SERVICES
        # Discovery, Read, Event, Time, VT services
        # ================================================================

        # BACnet Who-Is Request (Device Discovery)
        who_is = Request(
            "BACnet_Who_Is",
            children=(
                Block(
                    "BVLL_Header",
                    children=(
                        Byte("BVLL_Type", 0x81),  # BACnet/IP
                        Byte("BVLL_Function", 0x0B),  # Original-Broadcast-NPDU
                        Word("BVLL_Length", 0x000C, endian=">"),  # Message length (12 bytes)
                    ),
                ),
                Block(
                    "NPDU_Header",
                    children=(
                        Byte("NPDU_Version", 0x01),  # Version 1
                        Byte("NPDU_Control", 0x20),  # Destination specifier present
                        Word("DEST_Network", 0xFFFF, endian=">"),  # Global broadcast
                        Byte("DLEN", 0x00),  # Broadcast (no specific MAC)
                        Byte("HOP_Count", 0xFF),  # Max hops
                    ),
                ),
                Block(
                    "APDU_Header",
                    children=(
                        Byte("APDU_Type", 0x10),  # Unconfirmed service request
                        Byte("Service_Choice", 0x08),  # Who-Is service
                    ),
                ),
                # Note: No device instance range = unbounded Who-Is (all devices)
            ),
        )

        # BACnet I-Am Response Fuzzer (targets responses)
        # I-Am uses local broadcast (no destination specifier in NPDU)
        i_am = Request(
            "BACnet_I_Am",
            children=(
                Block(
                    "BVLL_Header_IAM",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0B),  # Original-Broadcast-NPDU
                        Word("BVLL_Length", 0x0015, endian=">"),  # 21 bytes total
                    ),
                ),
                Block(
                    "NPDU_Header_IAM",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x00),  # No network layer message, no dest/src
                    ),
                ),
                Block(
                    "APDU_Header_IAM",
                    children=(
                        Byte("APDU_Type", 0x10),  # Unconfirmed service request
                        Byte("Service_Choice", 0x00),  # I-Am service
                    ),
                ),
                # I-Am content with proper BACnet ASN.1 encoding
                # Object Identifier (context tag 0, 4 bytes): device,1234
                Byte("Object_ID_Tag", 0xC4),  # Application tag 12 (Object ID), length 4
                DWord(
                    "Device_Object_ID", 0x020004D2, endian=">"
                ),  # Device object type (8) + instance 1234
                # Max APDU Length Accepted (application tag 2, 2 bytes)
                Byte("Max_APDU_Tag", 0x22),  # Application tag 2 (unsigned), length 2
                Word("Max_APDU_Length", 1476, endian=">"),
                # Segmentation Supported (application tag 9, 1 byte)
                Byte("Segmentation_Tag", 0x91),  # Application tag 9 (enumerated), length 1
                Byte("Segmentation_Support", 0x03),  # No segmentation
                # Vendor ID (application tag 2, 1 byte)
                Byte("Vendor_ID_Tag", 0x21),  # Application tag 2 (unsigned), length 1
                Byte("Vendor_ID", 0x0F),  # Vendor ID 15
            ),
        )

        # BACnet Read Property Request (property manipulation attacks)
        # ReadProperty is a confirmed service (expects BACnet response)
        # Simplified APDU format: type + service_choice immediately after NPDU
        read_property = Request(
            "BACnet_Read_Property",
            children=(
                Block(
                    "BVLL_Header_RP",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),  # Original-Unicast-NPDU
                        Word("BVLL_Length", 0x000F, endian=">"),  # 15 bytes total
                    ),
                ),
                Block(
                    "NPDU_Header_RP",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),  # Expecting reply, no dest/src specifier
                    ),
                ),
                Block(
                    "APDU_Header_RP",
                    children=(
                        # Simplified format: APDU type immediately followed by service choice
                        Byte("APDU_Type_Flags", 0x00),  # Confirmed-REQ
                        Byte("Service_Choice", 0x0C),  # ReadProperty service
                        Byte("Invoke_ID", 0x01),  # Transaction ID (after service for payload)
                    ),
                ),
                # Object identifier with context tag [0]
                Byte("Object_ID_Tag", 0x0C),  # Context tag 0, length 4
                DWord("Object_ID", 0x020004D2, endian=">"),  # Device object, instance 1234
                # Property identifier with context tag [1]
                Byte("Property_ID_Tag", 0x19),  # Context tag 1, length 1
                Byte("Property_Value", 0x4D),  # Object-Name property (77)
            ),
        )

        # BACnet Read Property Multiple
        read_property_multiple = Request(
            "BACnet_Read_Property_Multiple",
            children=(
                Block(
                    "BVLC_Header_RPM",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0014, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_RPM",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_RPM",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.READ_PROPERTY_MULTIPLE),
                        Byte("Invoke_ID", 0x05),
                    ),
                ),
                Byte("Object_ID_Tag", 0x0C),
                DWord("Device_Object_ID", 0x020004D2, endian=">"),
                Byte("Property_List_Open", 0x1E),
                Byte("Property_ID_Tag", 0x09),
                Byte("Object_Name_Property", 0x4D),
                Byte("Property_List_Close", 0x1F),
            ),
        )

        # BACnet Read Object List
        read_object_list = Request(
            "BACnet_Read_Object_List",
            children=(
                Block(
                    "BVLC_Header_ROL",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x000F, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_ROL",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_ROL",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.READ_PROPERTY),
                        Byte("Invoke_ID", 0x0C),
                    ),
                ),
                Byte("Object_ID_Tag", 0x0C),
                DWord("Device_Object_ID", 0x020004D2, endian=">"),
                Byte("Property_ID_Tag", 0x19),
                Byte("Object_List_Property", 0x4C),
            ),
        )

        # BACnet Get Alarm Summary
        get_alarm_summary = Request(
            "BACnet_Get_Alarm_Summary",
            children=(
                Block(
                    "BVLC_Header_GAS",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x000C, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_GAS",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_GAS",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.GET_ALARM_SUMMARY),
                        Byte("Invoke_ID", 0x07),
                        Byte("Padding", 0x00),
                    ),
                ),
            ),
        )

        # BACnet Get Event Information
        get_event_info = Request(
            "BACnet_Get_Event_Information",
            children=(
                Block(
                    "BVLC_Header_GEI",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x000C, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_GEI",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_GEI",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.GET_EVENT_INFORMATION),
                        Byte("Invoke_ID", 0x08),
                        Byte("Padding", 0x00),
                    ),
                ),
            ),
        )

        # BACnet Subscribe COV
        subscribe_cov = Request(
            "BACnet_Subscribe_COV",
            children=(
                Block(
                    "BVLC_Header_SCOV",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0013, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_SCOV",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_SCOV",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.SUBSCRIBE_COV),
                        Byte("Invoke_ID", 0x09),
                    ),
                ),
                Byte("Process_ID_Tag", 0x09),
                Byte("Process_ID", 0x01),
                Byte("Object_ID_Tag", 0x1C),
                DWord("Monitored_Object_ID", 0x00800001, endian=">"),
                Byte("Confirmed_Tag", 0x29),
                Byte("Confirmed_Notifications", 0x00),
            ),
        )

        # BACnet Confirmed Event Notification
        confirmed_event = Request(
            "BACnet_Confirmed_Event_Notification",
            children=(
                Block(
                    "BVLC_Header_CEN",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x001E, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_CEN",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_CEN",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.CONFIRMED_EVENT_NOTIFICATION),
                        Byte("Invoke_ID", 0x0A),
                    ),
                ),
                Byte("Process_ID_Tag", 0x09),
                Byte("Process_ID", 0x01),
                Byte("Init_Device_Tag", 0x1C),
                DWord("Initiating_Device_ID", 0x020004D2, endian=">"),
                Byte("Event_Object_Tag", 0x2C),
                DWord("Event_Object_ID", 0x00800001, endian=">"),
                Byte("Timestamp_Open", 0x3E),
                Byte("Seq_Tag", 0x21),
                Byte("Sequence_Number", 0x01),
                Byte("Timestamp_Close", 0x3F),
                Byte("Notif_Class_Tag", 0x49),
                Byte("Notification_Class", 0x01),
            ),
        )

        # BACnet Time Synchronization (CVE-2017-16744)
        time_sync = Request(
            "BACnet_Time_Synchronization",
            children=(
                Block(
                    "BVLC_Header_TS",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0B),
                        Word("BVLL_Length", 0x0014, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_TS",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x20),
                        Word("DEST_Network", 0xFFFF, endian=">"),
                        Byte("DLEN", 0x00),
                        Byte("HOP_Count", 0xFF),
                    ),
                ),
                Block(
                    "APDU_Header_TS",
                    children=(
                        Byte("APDU_Type", 0x10),
                        Byte("Service_Choice", BACnetServiceCodes.TIME_SYNCHRONIZATION),
                    ),
                ),
                Byte("Date_Tag", 0xA4),
                Byte("Year", 0x7D),
                Byte("Month", 0x0C),
                Byte("Day", 0x1F),
                Byte("Day_Of_Week", 0x03),
                Byte("Time_Tag", 0xB4),
                Byte("Hour", 0x17),
                Byte("Minute", 0x3B),
                Byte("Second", 0x3B),
                Byte("Hundredths", 0x63),
            ),
        )

        # BACnet VT Open
        vt_open = Request(
            "BACnet_VT_Open",
            children=(
                Block(
                    "BVLC_Header_VTO",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x000D, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_VTO",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_VTO",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.VT_OPEN),
                        Byte("Invoke_ID", 0x0B),
                    ),
                ),
                Byte("VT_Class_Tag", 0x09),
                Byte("VT_Class", 0x01),
                Byte("VT_Session_Tag", 0x19),
                Byte("Local_VT_Session_ID", 0x10),
            ),
        )

        # BACnet Create Object
        create_object = Request(
            "BACnet_Create_Object",
            children=(
                Block(
                    "BVLC_Header_CO",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0010, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_CO",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_CO",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.CREATE_OBJECT),
                        Byte("Invoke_ID", 0x0D),
                    ),
                ),
                Byte("Object_Specifier_Open", 0x0E),
                Byte("Object_Type_Tag", 0x09),
                Byte("Object_Type", 0x00),
                Byte("Object_Specifier_Close", 0x0F),
            ),
        )

        # ================================================================
        # AUTHENTICATION SERVICES (BACnet SC / BACnet Addendum 135-2012j)
        # Uses SmartString CREDENTIAL for password fuzzing
        # ================================================================

        # Get authentication credentials from options
        bacnet_password = self.config.get_option("bacnet_password", "") or "password"
        device_password = self.config.get_option("device_password", "") or ""

        # BACnet Authenticate Request
        # Service code 0x18 (24) - used for device authentication
        authenticate_request = Request(
            "BACnet_Authenticate",
            children=(
                Block(
                    "BVLC_Header_AUTH",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0020, endian=">"),  # 32 bytes
                    ),
                ),
                Block(
                    "NPDU_Header_AUTH",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),  # Expecting reply
                    ),
                ),
                Block(
                    "APDU_Header_AUTH",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),  # Confirmed-REQ
                        Byte("Service_Choice", BACnetServiceCodes.AUTHENTICATE),
                        Byte("Invoke_ID", 0x18),
                    ),
                ),
                # Pseudo Random Number (context tag 0)
                Byte("PRN_Tag", 0x09),
                DWord("Pseudo_Random_Number", 0x12345678, endian=">"),
                # Expected Reply Length (context tag 1)
                Byte("Reply_Len_Tag", 0x19),
                Byte("Expected_Reply_Length", 0x10),  # 16 bytes
                # Operator Name (context tag 2) - use SmartString CREDENTIAL
                Byte("Operator_Tag", 0x2E),  # Opening tag
                SmartString(
                    "Operator_Name", bacnet_password, max_len=32, context=StringContext.CREDENTIAL
                ),
                Byte("Operator_Close", 0x2F),  # Closing tag
                # Operator Password (context tag 3) - use SmartString CREDENTIAL
                Byte("Password_Tag", 0x3E),  # Opening tag
                SmartString(
                    "Operator_Password",
                    bacnet_password,
                    max_len=32,
                    context=StringContext.CREDENTIAL,
                ),
                Byte("Password_Close", 0x3F),  # Closing tag
            ),
        )

        # BACnet Request Key
        # Service code 0x19 (25) - used for key exchange
        request_key = Request(
            "BACnet_Request_Key",
            children=(
                Block(
                    "BVLC_Header_RK",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0018, endian=">"),  # 24 bytes
                    ),
                ),
                Block(
                    "NPDU_Header_RK",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_RK",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.REQUEST_KEY),
                        Byte("Invoke_ID", 0x19),
                    ),
                ),
                # Requesting Device Identifier (context tag 0)
                Byte("Req_Device_Tag", 0x0C),
                DWord("Requesting_Device_ID", 0x020004D2, endian=">"),  # Device 1234
                # Requesting Device Address (context tag 1)
                Byte("Req_Addr_Tag", 0x1E),  # Opening tag
                Byte("Network_Tag", 0x21),
                Word("Network_Number", 0x0001, endian=">"),
                Byte("MAC_Tag", 0x75),
                Byte("MAC_Length", 0x06),
                SmartString(
                    "MAC_Address", "010203040506", max_len=12, context=StringContext.CREDENTIAL
                ),
                Byte("Req_Addr_Close", 0x1F),
                # Remote Device Identifier (context tag 2)
                Byte("Remote_Device_Tag", 0x2C),
                DWord("Remote_Device_ID", 0x02000001, endian=">"),  # Device 1
            ),
        )

        # BACnet Authenticate with Password for ReinitializeDevice
        # ReinitializeDevice accepts optional password in context tag 1
        reinit_with_password = Request(
            "BACnet_Reinitialize_With_Password",
            children=(
                Block(
                    "BVLC_Header_RDP",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0018, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_RDP",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_RDP",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.REINITIALIZE_DEVICE),
                        Byte("Invoke_ID", 0x14),
                    ),
                ),
                # Reinitialized State of Device (context tag 0)
                Byte("Reinit_State_Tag", 0x09),
                Group(
                    "Reinit_State",
                    values=[
                        b"\x00",  # ColdStart
                        b"\x01",  # WarmStart
                    ],
                ),
                # Password (context tag 1) - optional, use SmartString CREDENTIAL
                Byte("Password_Opening_Tag", 0x1D),  # Context 1, length 13
                SmartString(
                    "Device_Password",
                    device_password or bacnet_password,
                    max_len=20,
                    context=StringContext.CREDENTIAL,
                ),
            ),
        )

        # BACnet DeviceCommunicationControl with Password
        # Password is context tag 2
        dcc_with_password = Request(
            "BACnet_DCC_With_Password",
            children=(
                Block(
                    "BVLC_Header_DCCP",
                    children=(
                        Byte("BVLL_Type", 0x81),
                        Byte("BVLL_Function", 0x0A),
                        Word("BVLL_Length", 0x0018, endian=">"),
                    ),
                ),
                Block(
                    "NPDU_Header_DCCP",
                    children=(
                        Byte("NPDU_Version", 0x01),
                        Byte("NPDU_Control", 0x04),
                    ),
                ),
                Block(
                    "APDU_Header_DCCP",
                    children=(
                        Byte("APDU_Type_Flags", 0x00),
                        Byte("Service_Choice", BACnetServiceCodes.DEVICE_COMMUNICATION_CONTROL),
                        Byte("Invoke_ID", 0x11),
                    ),
                ),
                # Time Duration (context tag 0) - in minutes
                Byte("Duration_Tag", 0x05),
                Word("Time_Duration", 0x0000, endian=">"),  # Indefinite
                # Enable/Disable (context tag 1)
                Byte("Enable_Tag", 0x19),
                Group(
                    "Enable_Disable",
                    values=[
                        b"\x00",  # Enable
                        b"\x01",  # Disable
                        b"\x02",  # DisableInitiation
                    ],
                ),
                # Password (context tag 2) - use SmartString CREDENTIAL
                Byte("Password_Tag", 0x2D),
                SmartString(
                    "DCC_Password", bacnet_password, max_len=20, context=StringContext.CREDENTIAL
                ),
            ),
        )

        # ================================================================
        # OPTIMIZED SESSION CONNECTION ORDERING
        # ================================================================
        # Reordered for maximum early coverage and crash detection:
        # - PHASE 1 (0-30s): Quick Coverage - all service types once
        # - PHASE 2 (30s-3m): High-crash tests - malformed APDU, overflow
        # - PHASE 3 (3-6m): CVE-targeted writes
        # - PHASE 4 (6-10m): Boundary attacks
        # - PHASE 5 (10m+): Discovery, events, VT
        # ================================================================

        # ==================== PHASE 1: QUICK COVERAGE (~30 sec) ====================
        if self.is_request_enabled("BACnet_Quick_Coverage"):
            self.session.connect(quick_coverage)
            self.session.connect(quick_coverage_unconfirmed)

        # ==================== PHASE 2: HIGH-CRASH TESTS (~3 min) ====================
        if self.is_request_enabled("BACnet_Malformed_APDU"):
            self.session.connect(malformed_apdu)

        if self.is_request_enabled("BACnet_Overflow_Tests"):
            self.session.connect(bvlc_overflow)
            self.session.connect(npdu_control_fuzz)

        # ==================== PHASE 3: CVE-TARGETED WRITES (~3 min) ====================
        if self.is_request_enabled("BACnet_Write_Operations"):
            self.session.connect(write_property)
            self.session.connect(write_property_multiple)

        if self.is_request_enabled("BACnet_Device_Control"):
            self.session.connect(device_comm_control)
            # Only enable ReinitializeDevice if explicitly allowed
            if self.config.get_option("enable_reinit", False):
                self.session.connect(reinit_device)

        # ==================== PHASE 4: BOUNDARY ATTACKS (~4 min) ====================
        if self.is_request_enabled("BACnet_Boundary_Tests"):
            self.session.connect(object_id_boundary)
            self.session.connect(property_id_boundary)
            self.session.connect(apdu_type_boundary)

        # ==================== PHASE 5: REMAINING SERVICES ====================
        if self.is_request_enabled("BACnet_Discovery"):
            self.session.connect(who_is)
            self.session.connect(i_am)

        if self.is_request_enabled("BACnet_Read_Operations"):
            self.session.connect(read_property)
            self.session.connect(read_property_multiple)
            self.session.connect(read_object_list)

        if self.is_request_enabled("BACnet_Event_Services"):
            self.session.connect(get_alarm_summary)
            self.session.connect(get_event_info)
            self.session.connect(subscribe_cov)
            self.session.connect(confirmed_event)

        if self.is_request_enabled("BACnet_Time_Services"):
            self.session.connect(time_sync)

        if self.is_request_enabled("BACnet_VT_Services"):
            self.session.connect(vt_open)

        if self.is_request_enabled("BACnet_Object_Services"):
            self.session.connect(create_object)

        # ==================== AUTH SERVICES ====================
        if self.is_request_enabled("BACnet_Auth_Services") and self.config.get_option(
            "enable_auth", False
        ):
            self.session.connect(authenticate_request)
            self.session.connect(request_key)
            self.session.connect(reinit_with_password)
            self.session.connect(dcc_with_password)


# For backward compatibility and explicit exports
__all__ = ["BACnetFuzzer"]
