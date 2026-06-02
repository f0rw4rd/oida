"""IEC 60870-5-104 Protocol Fuzzer

Refactored to use the StatefulFuzzer framework with:
- IEC104SocketConnection: Connection with automatic STARTDT handshake (from tcp.py)
- No authentication required (IEC 104 doesn't have protocol-level auth)

State Machine V2 Integration (Phase 1):
- StateContext: Carries response data between state transitions
- SequenceManager: Tracks send/receive sequence numbers bidirectionally
- Context-aware callbacks: State callbacks can access shared context

Integration Pattern Example:
    This fuzzer demonstrates the StateContext integration pattern that other
    protocols can adopt. Key integration points:

    1. Create StateContext in __init__ and register SequenceManager:
        self._state_context = StateContext()
        seq_mgr = self._state_context.get_sequence_manager("iec104")
        seq_mgr.add_sequence(SequenceConfig(name="send_seq", ...))

    2. Use context in state callbacks (callbacks automatically receive context):
        def _on_data_transfer_enter(self, ctx: StateContext):
            ctx.set("connection_time", time.time())
            seq_mgr = ctx.get_sequence_manager("iec104")
            send_seq = seq_mgr.get_and_increment("send_seq")

    3. Store responses for cross-state data access:
        ctx.set_response("STARTDT", ResponseData(
            raw=response_bytes,
            parsed={"confirmed": True}
        ))

    4. Access previous responses in later states:
        startdt_resp = ctx.get_response("STARTDT")
        if startdt_resp and not startdt_resp.has_error():
            # Connection is ready for data transfer
"""

import struct
import time
from enum import IntEnum
from typing import List, Optional

from boofuzz import Block, Byte, Bytes, DWord, Group, Request, Size, Static, Word

from ..core.base_fuzzer import CommonState, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..core.stateful_fuzzer import StatefulFuzzer
from ..core.auth import ProtocolAuthenticator
from ..core.session import (
    StateContext,
    ResponseData,
    SequenceConfig,
    SequenceDirection,
)
from ..core.session.state_machine import ProtocolState, StateMachine, StateType
from ..primitives.dynamic import SmartBytes, SmartString, StringContext


class APCI_Types(IntEnum):
    I_FORMAT = 0x00  # Information transfer format
    S_FORMAT = 0x01  # Supervisory format
    U_FORMAT = 0x03  # Unnumbered format


class UFormat_Functions(IntEnum):
    STARTDT_ACT = 0x07  # Start data transfer activation
    STARTDT_CON = 0x0B  # Start data transfer confirmation
    STOPDT_ACT = 0x13  # Stop data transfer activation
    STOPDT_CON = 0x23  # Stop data transfer confirmation
    TESTFR_ACT = 0x43  # Test frame activation
    TESTFR_CON = 0x83  # Test frame confirmation


class ASDU_Types(IntEnum):
    # Essential monitoring ASDU types
    M_SP_NA_1 = 1  # Single-point information
    M_SP_TA_1 = 2  # Single-point information with time tag
    M_DP_NA_1 = 3  # Double-point information
    M_DP_TA_1 = 4  # Double-point information with time tag
    M_ST_NA_1 = 5  # Step position information
    M_ST_TA_1 = 6  # Step position information with time tag
    M_BO_NA_1 = 7  # Bitstring of 32 bit
    M_BO_TA_1 = 8  # Bitstring of 32 bit with time tag
    M_ME_NA_1 = 9  # Measured value, normalized
    M_ME_TA_1 = 10  # Measured value, normalized with time tag
    M_ME_NB_1 = 11  # Measured value, scaled
    M_ME_TB_1 = 12  # Measured value, scaled with time tag
    M_ME_NC_1 = 13  # Measured value, floating point
    M_ME_TC_1 = 14  # Measured value, floating point with time tag
    M_IT_NA_1 = 15  # Integrated totals
    M_IT_TA_1 = 16  # Integrated totals with time tag
    M_EP_TA_1 = 17  # Event of protection equipment with time tag
    M_EP_TB_1 = 18  # Packed start events of protection equipment with time tag
    M_EP_TC_1 = 19  # Packed output circuit information of protection equipment with time tag
    M_PS_NA_1 = 20  # Packed single-point with SCD
    M_ME_ND_1 = 21  # Measured value, normalized without quality

    # Additional monitoring with time tags
    M_SP_TB_1 = 30  # Single-point with time tag CP56Time2a
    M_DP_TB_1 = 31  # Double-point with time tag CP56Time2a
    M_ST_TB_1 = 32  # Step position with time tag CP56Time2a
    M_BO_TB_1 = 33  # Bitstring of 32 bit with time tag CP56Time2a
    M_ME_TD_1 = 34  # Measured value, normalized with time tag CP56Time2a
    M_ME_TE_1 = 35  # Measured value, scaled with time tag CP56Time2a
    M_ME_TF_1 = 36  # Measured value, floating point with time tag CP56Time2a
    M_IT_TB_1 = 37  # Integrated totals with time tag CP56Time2a
    M_EP_TD_1 = 38  # Event of protection equipment with time tag CP56Time2a
    M_EP_TE_1 = 39  # Packed start events of protection equipment with time tag CP56Time2a
    M_EP_TF_1 = 40  # Packed output circuit information with time tag CP56Time2a

    # Essential control ASDU types
    C_SC_NA_1 = 45  # Single command
    C_DC_NA_1 = 46  # Double command
    C_RC_NA_1 = 47  # Regulating step command
    C_SE_NA_1 = 48  # Set-point command, normalized
    C_SE_NB_1 = 49  # Set-point command, scaled
    C_SE_NC_1 = 50  # Set-point command, floating point
    C_BO_NA_1 = 51  # Bitstring of 32 bit command

    # Time-tagged control commands
    C_SC_TA_1 = 58  # Single command with time tag CP56Time2a
    C_DC_TA_1 = 59  # Double command with time tag CP56Time2a
    C_RC_TA_1 = 60  # Regulating step command with time tag CP56Time2a
    C_SE_TA_1 = 61  # Set-point command, normalized with time tag CP56Time2a
    C_SE_TB_1 = 62  # Set-point command, scaled with time tag CP56Time2a
    C_SE_TC_1 = 63  # Set-point command, floating point with time tag CP56Time2a
    C_BO_TA_1 = 64  # Bitstring of 32 bit command with time tag CP56Time2a

    # System commands
    M_EI_NA_1 = 70  # End of initialization
    C_IC_NA_1 = 100  # Interrogation command
    C_CI_NA_1 = 101  # Counter interrogation command
    C_RD_NA_1 = 102  # Read command
    C_CS_NA_1 = 103  # Clock synchronization command
    C_TS_NA_1 = 104  # Test command
    C_RP_NA_1 = 105  # Reset process command
    C_CD_NA_1 = 106  # Delay acquisition command
    C_TS_TA_1 = 107  # Test command with time tag CP56Time2a

    # Parameter commands
    P_ME_NA_1 = 110  # Parameter of measured values, normalized value
    P_ME_NB_1 = 111  # Parameter of measured values, scaled value
    P_ME_NC_1 = 112  # Parameter of measured values, floating point value
    P_AC_NA_1 = 113  # Parameter activation

    # File transfer
    F_FR_NA_1 = 120  # File ready
    F_SR_NA_1 = 121  # Section ready
    F_SC_NA_1 = 122  # Call file
    F_LS_NA_1 = 123  # Last section
    F_AF_NA_1 = 124  # ACK file, ACK section
    F_SG_NA_1 = 125  # Segment
    F_DR_TA_1 = 126  # Directory
    F_SC_NB_1 = 127  # Query log - Request archive file


class CauseOfTransmission(IntEnum):
    PERIODIC = 1
    BACKGROUND = 2
    SPONTANEOUS = 3
    INITIALIZED = 4
    REQUEST = 5
    ACTIVATION = 6
    ACTIVATION_CON = 7
    DEACTIVATION = 8
    DEACTIVATION_CON = 9
    ACTIVATION_TERMINATION = 10
    RETURN_INFO_REMOTE = 11
    RETURN_INFO_LOCAL = 12
    FILE_TRANSFER = 13
    AUTHENTICATION = 14
    MAINTENANCE_OF_AUTH_SESSION_KEY = 15
    MAINTENANCE_OF_USER_ROLE_AND_UPDATE_KEY = 16
    INROGEN = 20
    INRO1 = 21
    INRO2 = 22
    INRO3 = 23
    INRO4 = 24
    INRO5 = 25
    INRO6 = 26
    INRO7 = 27
    INRO8 = 28
    INRO9 = 29
    INRO10 = 30
    INRO11 = 31
    INRO12 = 32
    INRO13 = 33
    INRO14 = 34
    INRO15 = 35
    INRO16 = 36
    REQCOGEN = 37
    REQCO1 = 38
    REQCO2 = 39
    REQCO3 = 40
    REQCO4 = 41
    UNKNOWN_TYPE_ID = 44
    UNKNOWN_COT = 45
    UNKNOWN_CA = 46
    UNKNOWN_IOA = 47


class IEC104StateMachine:
    """Enhanced state machine for IEC 104 connection with StateContext support.

    Wraps the framework StateMachine and adds IEC 104-specific functionality
    (sequence tracking, response storage, protocol-aware transitions). All
    StateMachine attributes (states, transition_to, state_history, etc.) are
    transparently delegated to the inner StateMachine via __getattr__, so this
    class is a drop-in replacement wherever a StateMachine is expected.

    State Machine V2 Integration:
    This class demonstrates how to integrate StateContext with a protocol
    state machine. The StateContext provides:

    1. Sequence tracking via SequenceManager:
       - send_seq: Incremented when sending I-format frames (wire: 0x0000-0xFFFE even)
       - recv_seq: Updated when receiving I-format frames

    2. Response storage:
       - Stores STARTDT_CON, TESTFR_CON responses for later reference
       - Enables cross-state data access (e.g., check STARTDT response in DATA_TRANSFER)

    3. Context callbacks:
       - on_enter/on_exit hooks can access context for logging and state setup

    Example Usage:
        sm = IEC104StateMachine()
        ctx = sm.context  # Get the StateContext

        # Get sequence numbers for I-format frame
        seq_mgr = ctx.get_sequence_manager("iec104")
        send_seq = seq_mgr.get_and_increment("send_seq")
        recv_seq = seq_mgr.get("recv_seq")

        # Store response after STARTDT
        ctx.set_response("STARTDT", ResponseData(raw=response, parsed={"confirmed": True}))

        # StateMachine attributes are transparently available:
        sm.states              # Dict[str, ProtocolState] from inner StateMachine
        sm.state_history       # deque of state names
        sm.transition_to(...)  # delegates to inner StateMachine
    """

    def __init__(self, context: Optional[StateContext] = None):
        """Initialize IEC 104 state machine.

        Args:
            context: Optional StateContext for data propagation. If not provided,
                     a new context is created with IEC 104 sequence configuration.
        """
        # State Machine V2: Initialize or use provided context
        self._context = context or StateContext()

        # Build framework StateMachine with IEC 104 states
        disconnected = ProtocolState(
            name="DISCONNECTED",
            state_type=StateType.CONNECTION,
            description="TCP disconnected",
        )
        connected = ProtocolState(
            name="CONNECTED",
            requires=["DISCONNECTED"],
            state_type=StateType.CONNECTION,
            description="TCP connected, STARTDT not yet sent",
        )
        data_transfer = ProtocolState(
            name="DATA_TRANSFER",
            requires=["CONNECTED"],
            state_type=StateType.DATA_TRANSFER,
            description="STARTDT confirmed, I-format transfer active",
        )
        self._sm = StateMachine(
            initial_state=disconnected,
            states=[disconnected, connected, data_transfer],
            context=self._context,
            allow_invalid_transitions=True,
        )

        # Configure IEC 104 sequence numbers
        # IEC 104 uses 15-bit sequence numbers (0-32767 logical).
        # On the wire, values are shifted left 1 bit (bit 0 is frame type indicator),
        # giving wire-format range 0x0000-0xFFFE (even values only).
        self._setup_sequences()

    def _setup_sequences(self) -> None:
        """Configure IEC 104 sequence numbers in the context.

        IEC 104 wire-format sequence number layout (16-bit word, little-endian):
        - Bit 0: Frame type indicator (always 0 for I-format)
        - Bits 1-15: 15-bit sequence number (0-32767 logical)

        Wire-format values are therefore always even: 0x0000, 0x0002, ..., 0xFFFE.
        We set max_value=0xFFFF so that range_size=0x10000, giving correct modular
        wrap: (0xFFFE + 2) % 0x10000 = 0x0000. The odd value 0xFFFF is never
        produced because we start at 0 and increment by 2.
        """
        seq_mgr = self._context.get_sequence_manager("iec104")

        # Send sequence number (SSN) - incremented when we send I-format
        seq_mgr.add_sequence(
            SequenceConfig(
                name="send_seq",
                initial=0,
                min_value=0,
                max_value=0xFFFF,  # 16-bit modular space for correct even-value wrap
                increment=2,  # Skip by 2 to maintain even values (bit 0 = 0)
                direction=SequenceDirection.SEND,
                wrap_behavior="modulo",
                fuzzable=True,
            )
        )

        # Receive sequence number (RSN) - updated from received I-format
        seq_mgr.add_sequence(
            SequenceConfig(
                name="recv_seq",
                initial=0,
                min_value=0,
                max_value=0xFFFF,  # 16-bit modular space for correct even-value wrap
                increment=2,
                direction=SequenceDirection.RECEIVE,
                wrap_behavior="modulo",
                fuzzable=True,
            )
        )

    def __getattr__(self, name: str):
        """Delegate attribute access to the inner StateMachine.

        This makes IEC104StateMachine a transparent proxy for StateMachine,
        so code that accesses .states, .state_history, .transition_to(),
        .allow_invalid_transitions, etc. works correctly without explicit
        delegation methods for each attribute.

        Only called when normal attribute lookup fails, so IEC104-specific
        methods/properties defined on this class take priority.
        """
        # Guard against infinite recursion during __init__ (before _sm is set)
        if name == "_sm":
            raise AttributeError(name)
        return getattr(self._sm, name)

    @property
    def context(self) -> StateContext:
        """Get the StateContext for data propagation."""
        return self._context

    @property
    def state(self) -> str:
        """Current state name (backward-compatible property)."""
        return self._sm.current_state.name

    @property
    def state_machine(self) -> StateMachine:
        """Expose framework StateMachine for StatefulFuzzer integration."""
        return self._sm

    def start_data_transfer(self) -> None:
        """Transition to DATA_TRANSFER state.

        Called after STARTDT_ACT/STARTDT_CON handshake completes.
        """
        self._sm.transition_to("DATA_TRANSFER", force=True)
        self._context.set("data_transfer_started", time.time())

    def stop_data_transfer(self) -> None:
        """Transition back to CONNECTED state.

        Called after STOPDT_ACT/STOPDT_CON handshake.
        """
        self._sm.transition_to("CONNECTED", force=True)
        self._context.set("data_transfer_stopped", time.time())

    def disconnect(self) -> None:
        """Transition to DISCONNECTED state."""
        self._sm.transition_to("DISCONNECTED", force=True)

    def get_current_state_name(self) -> str:
        """Get the name of the current state."""
        return self._sm.current_state.name

    def validate_current_state(self) -> bool:
        """Validate current state.

        Returns:
            True if current state passes validation
        """
        return self._sm.validate_current_state()

    def get_send_sequence(self) -> int:
        """Get current send sequence number without incrementing.

        Returns:
            Current send sequence value
        """
        seq_mgr = self._context.get_sequence_manager("iec104")
        return seq_mgr.get("send_seq")

    def get_and_increment_send_sequence(self) -> int:
        """Get send sequence and increment for next use.

        This is the standard pattern for sending I-format frames:
        1. Get current sequence for the frame being sent
        2. Increment for the next frame

        Returns:
            Send sequence value to use in the current frame
        """
        seq_mgr = self._context.get_sequence_manager("iec104")
        return seq_mgr.get_and_increment("send_seq")

    def get_recv_sequence(self) -> int:
        """Get current receive sequence number.

        Returns:
            Current receive sequence value
        """
        seq_mgr = self._context.get_sequence_manager("iec104")
        return seq_mgr.get("recv_seq")

    def update_recv_sequence(self, value: int) -> None:
        """Update receive sequence from received frame.

        Called when an I-format frame is received to track the peer's
        send sequence.

        Args:
            value: Sequence number from received frame
        """
        seq_mgr = self._context.get_sequence_manager("iec104")
        seq_mgr.set("recv_seq", value)

    def store_response(self, operation: str, raw: bytes, parsed: dict = None) -> None:
        """Store a response for later reference.

        Args:
            operation: Operation name (e.g., "STARTDT", "TESTFR", "INTERROGATION")
            raw: Raw response bytes
            parsed: Optional parsed response data
        """
        self._context.set_response(
            operation,
            ResponseData(
                raw=raw,
                parsed=parsed or {},
                # timestamp defaults to datetime.now() in ResponseData
            ),
        )

    def get_response(self, operation: str) -> Optional[ResponseData]:
        """Get a stored response.

        Args:
            operation: Operation name

        Returns:
            ResponseData or None if not found
        """
        return self._context.get_response(operation)

    def reset_sequences(self) -> None:
        """Reset sequence numbers to initial values.

        Called when connection is re-established.
        """
        seq_mgr = self._context.get_sequence_manager("iec104")
        seq_mgr.reset()

    def to_dict(self) -> dict:
        """Serialize state machine state for debugging.

        Returns:
            Dictionary with current state and context info
        """
        return {
            "state": self._sm.current_state.name,
            "history": list(self._sm.state_history),
            "context": self._context.to_dict(),
            "sequences": self._context.get_sequence_manager("iec104").to_dict(),
        }


# Helper functions to create IEC 104 Block structures


def create_apci_u_format(name: str, function_code: int, fuzzable: bool = True):
    """Create U-format APCI frame Block

    IEC 60870-5-104 APCI U-format frame structure:
    - Start byte: 0x68
    - Length: 0x04 (4 bytes of control field)
    - Control field 1: Function code (bits 7-2) + U-frame marker 0x03 (bits 1-0)
    - Control fields 2-4: 0x00

    For STARTDT_ACT (function=0x07): 68 04 07 00 00 00
    For TESTFR_ACT (function=0x43): 68 04 43 00 00 00

    Args:
        name: Block name
        function_code: U-format function code
        fuzzable: Whether the control field is fuzzable (default True)
    """
    return Block(
        name,
        children=(
            Static("start", b"\x68"),
            Byte("length", 0x04, fuzzable=False),  # Length must always be 4 for U-format
            Byte("control_1", function_code, fuzzable=fuzzable),
            Byte("control_2", 0x00, fuzzable=False),
            Byte("control_3", 0x00, fuzzable=False),
            Byte("control_4", 0x00, fuzzable=False),
        ),
    )


def create_apci_s_format(name: str, recv_seq: int = 0, fuzzable: bool = True):
    """Create S-format (supervisory) APCI frame Block.

    IEC 60870-5-104 S-format frame structure (6 bytes):
    - Byte 0: 0x68 (start)
    - Byte 1: 0x04 (length = 4 bytes of control field)
    - Byte 2: 0x01 (S-format indicator: bit 0 = 1, bit 1 = 0)
    - Byte 3: 0x00
    - Bytes 4-5: Receive sequence number N(R) (16-bit LE, bit 0 always 0)

    S-frames acknowledge received I-format frames without carrying data.

    Args:
        name: Block name
        recv_seq: Receive sequence number (wire format, must be even)
        fuzzable: Whether the receive sequence is fuzzable (default True)
    """
    return Block(
        name,
        children=(
            Static("start", b"\x68"),
            Byte("length", 0x04, fuzzable=False),
            Byte("control_1", 0x01, fuzzable=fuzzable),  # S-format: bit 0=1, bit 1=0
            Byte("control_2", 0x00, fuzzable=False),
            Word("recv_seq", recv_seq, endian="<", fuzzable=fuzzable),  # N(R)
        ),
    )


def create_apci_i_format_header(name: str = "apci"):
    """Create I-format APCI header Block (without ASDU payload)"""
    return Block(
        name,
        children=(
            Static("start", b"\x68"),
            Size("length", block_name="asdu_block", length=1, math=lambda x: x + 4),
            Word("send_seq", 0, endian="<", fuzzable=True),
            Word("recv_seq", 0, endian="<", fuzzable=True),
        ),
    )


def create_asdu_header(type_id: int, cot: int = 3, ca: int = 1):
    """Create ASDU header Block"""
    return Block(
        "asdu_header",
        children=(
            Byte("type_id", type_id, fuzzable=True),
            Byte("vsq", 0x01, fuzzable=True),  # Variable structure qualifier
            Word("cot", cot, endian="<", fuzzable=True),  # Cause of transmission
            Word("ca", ca, endian="<", fuzzable=True),  # Common address
        ),
    )


def create_cp56time2a(name: str = "time_tag"):
    """Create CP56Time2a timestamp Block (7 bytes)"""
    ms = int(time.time() * 1000) % 60000
    return Block(
        name,
        children=(
            Word("milliseconds", ms & 0xFFFF, endian="<", fuzzable=True),
            Byte("minutes", 0, fuzzable=True),
            Byte("hours", 0, fuzzable=True),
            Byte("day", 1, fuzzable=True),
            Byte("month", 1, fuzzable=True),
            Byte("year", 24, fuzzable=True),  # Years since 2000
        ),
    )


def create_info_object_single_point(ioa: int, value: int):
    """Create single-point information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Byte("siq", value, fuzzable=True),  # Single-point + quality
        ),
    )


def create_info_object_double_point(ioa: int, value: int):
    """Create double-point information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Byte("diq", value, fuzzable=True),  # Double-point + quality
        ),
    )


def create_info_object_step_position(ioa: int, value: int, quality: int):
    """Create step position information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Byte("value", value, fuzzable=True),
            Byte("quality", quality, fuzzable=True),
        ),
    )


def create_info_object_bitstring(ioa: int, value: int, quality: int):
    """Create bitstring of 32 bit information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            DWord("bitstring", value, endian="<", fuzzable=True),
            Byte("quality", quality, fuzzable=True),
        ),
    )


def create_info_object_measured_normalized(ioa: int, value: int, quality: int):
    """Create measured value normalized information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Word("value", value, endian="<", signed=True, fuzzable=True),
            Byte("quality", quality, fuzzable=True),
        ),
    )


def create_info_object_measured_scaled(ioa: int, value: int, quality: int):
    """Create measured value scaled information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Word("value", value, endian="<", signed=True, fuzzable=True),
            Byte("quality", quality, fuzzable=True),
        ),
    )


def create_info_object_measured_float(ioa: int, value: float, quality: int):
    """Create measured value floating point information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            DWord(
                "value",
                int.from_bytes(struct.pack("<f", value), "little"),
                endian="<",
                fuzzable=True,
            ),
            Byte("quality", quality, fuzzable=True),
        ),
    )


def create_info_object_integrated_totals(ioa: int, counter_value: int):
    """Create integrated totals information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            DWord("counter", counter_value, endian="<", fuzzable=True),
        ),
    )


def create_info_object_single_command(ioa: int, sco: int):
    """Create single command information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Byte("sco", sco, fuzzable=True),  # Single command + qualifier
        ),
    )


def create_info_object_double_command(ioa: int, dco: int):
    """Create double command information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Byte("dco", dco, fuzzable=True),  # Double command + qualifier
        ),
    )


def create_info_object_regulating_step(ioa: int, rco: int):
    """Create regulating step command information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Byte("rco", rco, fuzzable=True),  # Regulating command
        ),
    )


def create_info_object_setpoint_normalized(ioa: int, value: int, ql: int, se: int):
    """Create set-point command normalized information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Word("nva", value, endian="<", signed=True, fuzzable=True),
            Byte("ql", ql, fuzzable=True),
            Byte("se", se, fuzzable=True),
        ),
    )


def create_info_object_setpoint_scaled(ioa: int, value: int, ql: int, se: int):
    """Create set-point command scaled information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Word("sva", value, endian="<", signed=True, fuzzable=True),
            Byte("ql", ql, fuzzable=True),
            Byte("se", se, fuzzable=True),
        ),
    )


def create_info_object_setpoint_float(ioa: int, value: float, ql: int, se: int):
    """Create set-point command floating point information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            DWord(
                "value",
                int.from_bytes(struct.pack("<f", value), "little"),
                endian="<",
                fuzzable=True,
            ),
            Byte("ql", ql, fuzzable=True),
            Byte("se", se, fuzzable=True),
        ),
    )


def create_info_object_bitstring_command(ioa: int, bitstring: int, se: int):
    """Create bitstring command information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            DWord("bitstring", bitstring, endian="<", fuzzable=True),
            Byte("se", se, fuzzable=True),
        ),
    )


def create_info_object_interrogation(ioa: int, qoi: int):
    """Create interrogation command information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Byte("qoi", qoi, fuzzable=True),  # Qualifier of interrogation
        ),
    )


def create_info_object_read_command(ioa: int):
    """Create read command information object"""
    return Block(
        "info_object",
        children=(Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),),
    )


def create_complete_asdu_message(name: str, type_id: int, info_object, cot: int = 3, ca: int = 1):
    """Create a complete IEC 104 message with APCI + ASDU + information object"""
    return Request(
        name,
        children=(
            create_apci_i_format_header("apci"),
            Block(
                "asdu_block",
                children=(
                    create_asdu_header(type_id, cot, ca),
                    info_object,
                ),
            ),
        ),
    )


def create_info_object_clock_sync(ioa: int):
    """Create clock synchronization information object with time tag"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            create_cp56time2a("time_tag"),
        ),
    )


def create_info_object_test_command(ioa: int, test_value: int):
    """Create test command information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Word("test_pattern", test_value, endian="<", fuzzable=True),
        ),
    )


def create_info_object_parameter(ioa: int, value: int, quality: int, kind: int, change: int):
    """Create parameter information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Word("value", value, endian="<", signed=True, fuzzable=True),
            Byte("quality", quality, fuzzable=True),
            Byte("kind", kind, fuzzable=True),
            Byte("change", change, fuzzable=True),
        ),
    )


def create_info_object_file_ready(ioa: int, file_id: int, filename: str):
    """Create file ready information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Word("file_id", file_id, endian="<", fuzzable=True),
            Byte("name_length", 0x01, fuzzable=True),
            Byte("file_length", 0x02, fuzzable=True),
            Byte("ready", 0x03, fuzzable=True),
            Byte("checksum", 0x04, fuzzable=True),
            Byte("reserved", 0x05, fuzzable=True),
            Word("length", 1024, endian="<", fuzzable=True),
            SmartBytes("filename", filename.encode() + b"\x00", max_len=255, fuzzable=True),
        ),
    )


def create_info_object_file_section(ioa: int, file_id: int, section: int, status: int):
    """Create file section information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Word("file_id", file_id, endian="<", fuzzable=True),
            Byte("section", section, fuzzable=True),
            Byte("status", status, fuzzable=True),
        ),
    )


def create_info_object_file_segment(
    ioa: int, file_id: int, section: int, segment: int, data: bytes
):
    """Create file segment information object"""
    return Block(
        "info_object",
        children=(
            Bytes("ioa", ioa.to_bytes(3, "little"), size=3, fuzzable=True),
            Word("file_id", file_id, endian="<", fuzzable=True),
            Byte("section", section, fuzzable=True),
            Byte("segment", segment, fuzzable=True),
            SmartBytes("data", data, max_len=250, fuzzable=True),
        ),
    )


class IEC104Fuzzer(StatefulFuzzer):
    """
    Simplified IEC 60870-5-104 Protocol Fuzzer

    Uses StatefulFuzzer framework with:
    - IEC104SocketConnection: Handles STARTDT handshake automatically (via ProtocolType.IEC104)
    - No authentication: IEC 104 doesn't have protocol-level authentication

    Focuses on essential attack vectors and vulnerability patterns without redundancy.
    Covers the most critical ASDU types and real-world attack scenarios.
    """

    # StatefulFuzzer configuration
    PROTOCOL_NAME = "iec104"
    CONNECTION_CLASS = None  # Uses IEC104SocketConnection via ProtocolType.IEC104
    AUTHENTICATOR_CLASS = None  # IEC 104 has no protocol-level authentication

    # Protocol-specific monitor: IEC104 TESTFR check every 5 tests
    # Lower interval for faster crash detection in industrial protocols
    DEFAULT_MONITORS = "iec104:5"

    PROTOCOL_OPTIONS = {
        "common_address": {
            "type": int,
            "default": 1,
            "description": "Common address of ASDU",
            "example": "65535",
        },
        "enable_file_transfer": {
            "type": bool,
            "default": False,
            "description": "Enable file transfer ASDU fuzzing",
            "example": "true",
        },
        "attack_intensity": {
            "type": str,
            "default": "medium",
            "description": "Attack intensity level",
            "choices": ["low", "medium", "high"],
            "example": "high",
        },
        "enable_vendor_attacks": {
            "type": bool,
            "default": False,
            "description": "Enable vendor-specific attack patterns",
            "example": "true",
        },
        # IEC 62351 Authentication Options (IEC 62351-5 for IEC 60870-5 protocols)
        "iec62351_username": {
            "type": str,
            "default": "",
            "description": "IEC 62351 username for authentication fuzzing",
            "example": "admin",
        },
        "iec62351_password": {
            "type": str,
            "default": "",
            "description": "IEC 62351 password/key for authentication fuzzing",
            "example": "password123",
        },
        "enable_auth": {
            "type": bool,
            "default": False,
            "description": "Enable IEC 62351 authentication fuzzing",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests

        IEC 104 doesn't have authentication but has state requirements:
        - CONNECTED: After TCP connection but before STARTDT
        - DATA_TRANSFER: After STARTDT_ACT/CON handshake (most ASDUs)

        Note: IEC 104 has no protocol-level authentication, so we use
        CONNECTED state for connection setup and ANY for data transfer
        since STARTDT is handled by the connection class.
        """
        return [
            # Connection establishment (before STARTDT handshake)
            RequestInfo(
                "IEC104_Baseline",
                "TESTFR baseline connectivity test",
                "baseline",
                requires_state=CommonState.CONNECTED,
            ),
            RequestInfo(
                "IEC104_Connection",
                "U-format connection establishment",
                "core",
                requires_state=CommonState.CONNECTED,
            ),
            RequestInfo(
                "IEC104_S_Frame",
                "S-format supervisory acknowledgment frames",
                "core",
                requires_state=CommonState.CONNECTED,
            ),
            # Monitoring ASDUs (after STARTDT - data transfer active)
            RequestInfo(
                "IEC104_Monitoring",
                "Single/double point monitoring ASDUs",
                "read",
                requires_state=CommonState.ANY,
            ),  # IEC104Connection handles STARTDT
            RequestInfo(
                "IEC104_Measured_Values",
                "Measured value ASDUs (normalized, scaled, float)",
                "read",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "IEC104_Counters",
                "Integrated totals and counter ASDUs",
                "read",
                requires_state=CommonState.ANY,
            ),
            # Control ASDUs (after STARTDT - data transfer active)
            RequestInfo(
                "IEC104_Control",
                "Control commands (single, double, setpoint)",
                "write",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "IEC104_System",
                "System commands (interrogation, clock sync)",
                "write",
                requires_state=CommonState.ANY,
            ),
            # File transfer (after STARTDT)
            RequestInfo(
                "IEC104_File_Transfer",
                "File transfer ASDUs",
                "write",
                requires_state=CommonState.ANY,
            ),
            # Attack patterns (can be sent in any state to test protocol robustness)
            RequestInfo(
                "IEC104_Attack_Patterns",
                "Known attack patterns and malformed ASDUs",
                "attacks",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "IEC104_Vendor_Attacks",
                "Vendor-specific vulnerability patterns",
                "attacks",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "IEC104_Sequence_Attacks",
                "Sequence number manipulation attacks",
                "attacks",
                requires_state=CommonState.ANY,
            ),
            # IEC 62351 Authentication fuzzing
            RequestInfo(
                "IEC104_IEC62351_Auth",
                "IEC 62351-5 authentication service fuzzing",
                "auth",
                requires_state=CommonState.ANY,
            ),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        """Initialize IEC 104 fuzzer with StateContext integration.

        State Machine V2 Integration:
        This constructor demonstrates the recommended pattern for integrating
        StateContext into protocol fuzzers:

        1. Create StateContext BEFORE super().__init__ if needed in _define_protocol
        2. Initialize state machine with the context
        3. Access sequences via state_machine.context.get_sequence_manager()

        The StateContext persists across:
        - State transitions within a connection
        - Multiple fuzz iterations (unless explicitly reset)
        - Parent/child context hierarchy (for nested protocols)
        """
        config.protocol_type = ProtocolType.IEC104  # Use IEC104 connection with auto STARTDT

        # State Machine V2: Create shared StateContext for protocol
        # This context carries data between state transitions and across requests
        self._state_context = StateContext()

        # Initialize the IEC 104 state machine with shared context
        # The state machine configures sequence numbers in the context
        self._iec104_state_machine = IEC104StateMachine(context=self._state_context)

        # Call parent init (this calls _define_protocol)
        super().__init__(config, connection_factory)

        # For backward compatibility, also expose as state_machine property
        self.state_machine = self._iec104_state_machine

        # Transition the state machine to DATA_TRANSFER. The IEC104SocketConnection
        # performs the STARTDT_ACT / STARTDT_CON handshake before any boofuzz Request
        # is sent — so by the time the fuzzer runs its sequence, the protocol is
        # already in DATA_TRANSFER. Without this transition, every Request tagged
        # ``requires_state="DATA_TRANSFER"`` would be incorrectly blocked.
        # (Audit finding B8, fixed 1.0.)
        try:
            self._iec104_state_machine.start_data_transfer()
        except Exception as exc:
            self.log.debug(f"[IEC104] Could not pre-transition to DATA_TRANSFER: {exc}")

        # Log context initialization
        self.log.debug(f"[IEC104] StateContext initialized: {self._state_context}")
        self.log.debug(
            f"[IEC104] Sequences configured: {self._state_context.get_sequence_manager('iec104').to_dict()}"
        )

    @property
    def context(self) -> StateContext:
        """Get the StateContext for data propagation.

        Protocols can use this to access shared state:
            ctx = fuzzer.context
            send_seq = ctx.get_sequence_manager("iec104").get("send_seq")
            last_response = ctx.get_response("INTERROGATION")
        """
        return self._state_context

    @property
    def send_seq(self) -> int:
        """Get current send sequence number (backward compatible property).

        Deprecated: Use state_machine.get_send_sequence() instead.
        """
        return self._iec104_state_machine.get_send_sequence()

    @property
    def recv_seq(self) -> int:
        """Get current receive sequence number (backward compatible property).

        Deprecated: Use state_machine.get_recv_sequence() instead.
        """
        return self._iec104_state_machine.get_recv_sequence()

    def _create_authenticator(self, config: FuzzerConfig) -> Optional[ProtocolAuthenticator]:
        """IEC 104 doesn't require authentication - return None."""
        return None

    def setup_custom_monitors(self):
        """
        Setup IEC 104-specific monitoring with TESTFR frame validation.

        Uses protocol-specific IEC104Monitor that sends TESTFR (Test Frame)
        U-format frames and validates TESTFR ACK responses. This provides
        protocol-level health checking beyond basic TCP socket connectivity.

        Returns:
            List of monitor instances for IEC 104 service health checking
        """
        from ..monitors import IEC104Monitor

        # Create IEC 104 TESTFR monitor
        # Lower failure_threshold to detect crashes faster
        iec104_monitor = IEC104Monitor(
            host=self.config.target_ip,
            port=self.config.target_port or 2404,
            timeout=2,
            check_interval=3,  # Check every 3 test cases (CombinedMonitor overrides)
            failure_threshold=1,  # Trigger recovery after just 1 failed check
        )

        return [iec104_monitor]

    # ==================== STATE CONTEXT HELPER METHODS ====================
    # These methods demonstrate the StateContext integration pattern that
    # other protocols can adopt.

    def get_next_send_sequence(self) -> int:
        """Get and increment the send sequence number.

        State Machine V2 Pattern:
        Use this method when building I-format frames to get the correct
        sequence number. The sequence is automatically incremented for
        the next frame.

        Returns:
            Send sequence number to use in the current frame

        Example:
            send_seq = fuzzer.get_next_send_sequence()
            # Build I-format frame with send_seq
        """
        return self._iec104_state_machine.get_and_increment_send_sequence()

    def update_recv_sequence_from_response(self, response: bytes) -> None:
        """Update receive sequence from a received I-format frame.

        State Machine V2 Pattern:
        Call this method when processing I-format responses to track
        the peer's sequence numbers for proper acknowledgment.

        Args:
            response: Raw response bytes containing I-format frame

        Example:
            response = connection.recv(1024)
            if is_i_format(response):
                fuzzer.update_recv_sequence_from_response(response)
        """
        if len(response) >= 6:
            # I-format: control field bytes 1-2 are send sequence (LSB first)
            # Sequence is in bits 1-15 (bit 0 is always 0 for I-format)
            send_seq = struct.unpack("<H", response[2:4])[0]
            if (send_seq & 0x01) == 0:  # Verify it's I-format (bit 0 = 0)
                self._iec104_state_machine.update_recv_sequence(send_seq)

    def store_interrogation_response(self, response: bytes, parsed_data: dict = None) -> None:
        """Store an interrogation response for later reference.

        State Machine V2 Pattern:
        Store responses from general interrogation (C_IC_NA_1) commands
        to track device state across fuzz iterations.

        Args:
            response: Raw response bytes
            parsed_data: Optional parsed response data (e.g., discovered IOAs)

        Example:
            # After sending interrogation command
            response = connection.recv(4096)
            fuzzer.store_interrogation_response(response, {
                "ioa_count": 10,
                "types_found": ["M_SP_NA_1", "M_ME_NA_1"]
            })

            # Later, check what we discovered
            resp = fuzzer.context.get_response("INTERROGATION")
            if resp:
                print(f"Found {resp.parsed['ioa_count']} IOAs")
        """
        self._iec104_state_machine.store_response("INTERROGATION", response, parsed_data or {})

    def get_sequence_info(self) -> dict:
        """Get current sequence number information.

        State Machine V2 Pattern:
        Use this for debugging and logging sequence state.

        Returns:
            Dictionary with send_seq, recv_seq, and state info
        """
        return {
            "send_seq": self._iec104_state_machine.get_send_sequence(),
            "recv_seq": self._iec104_state_machine.get_recv_sequence(),
            "state": self._iec104_state_machine.get_current_state_name(),
            "context_keys": self._state_context.keys(),
            "responses_stored": self._state_context.response_keys(),
        }

    def reset_protocol_state(self) -> None:
        """Reset protocol state for a new connection.

        State Machine V2 Pattern:
        Call this when starting a new fuzzing session or after a
        connection reset to ensure clean state.

        Example:
            # After connection failure
            fuzzer.reset_protocol_state()
            # Reconnect and resume fuzzing
        """
        self._iec104_state_machine.reset_sequences()
        self._iec104_state_machine.disconnect()
        # Clear response storage but keep sequence config
        self._state_context.clear(preserve_keys=["iec104_config"])
        self.log.debug("[IEC104] Protocol state reset")

    def _define_protocol(self):
        """Define IEC 104 protocol using Block hierarchy"""

        # Connection establishment
        self._create_connection_sequence()

        # Core ASDU testing
        self._add_core_asdus()

        # Attack patterns
        self._add_attack_patterns()

        # File transfer patterns
        if self.config.get_option("enable_file_transfer", False):
            self._add_file_transfer_patterns()

        # Optional advanced features
        if self.config.get_option("enable_vendor_attacks", False):
            self._add_vendor_patterns()

        # IEC 62351 Authentication fuzzing
        if self.config.get_option("enable_auth", False):
            self._add_iec62351_auth_patterns()

    def _create_connection_sequence(self):
        """Create connection establishment sequence.

        Note: The actual STARTDT handshake is performed in the pre_send callback.
        These requests are for testing U-format frame fuzzing after connection is established.
        """
        # STARTDT activation - non-fuzzable baseline test
        startdt_baseline = create_apci_u_format(
            "STARTDT_ACT", UFormat_Functions.STARTDT_ACT, fuzzable=False
        )
        self.session.connect(Request("STARTDT_Baseline", children=(startdt_baseline,)))

        # TESTFR activation - non-fuzzable baseline test
        testfr_baseline = create_apci_u_format(
            "TESTFR_ACT", UFormat_Functions.TESTFR_ACT, fuzzable=False
        )
        self.session.connect(Request("TESTFR_Baseline", children=(testfr_baseline,)))

        # Fuzzable U-format frames for attack testing
        startdt_fuzz = create_apci_u_format(
            "STARTDT_ACT_Fuzz", UFormat_Functions.STARTDT_ACT, fuzzable=True
        )
        self.session.connect(Request("STARTDT_Fuzz", children=(startdt_fuzz,)))

        testfr_fuzz = create_apci_u_format(
            "TESTFR_ACT_Fuzz", UFormat_Functions.TESTFR_ACT, fuzzable=True
        )
        self.session.connect(Request("TESTFR_Fuzz", children=(testfr_fuzz,)))

        # STOPDT activation
        stopdt = create_apci_u_format("STOPDT_ACT", UFormat_Functions.STOPDT_ACT, fuzzable=True)
        self.session.connect(Request("STOPDT", children=(stopdt,)))

        # S-format (supervisory) frames for acknowledgment fuzzing
        s_frame_baseline = create_apci_s_format("S_Frame_Baseline", recv_seq=0, fuzzable=False)
        self.session.connect(Request("S_Frame_Baseline", children=(s_frame_baseline,)))

        s_frame_fuzz = create_apci_s_format("S_Frame_Fuzz", recv_seq=0, fuzzable=True)
        self.session.connect(Request("S_Frame_Fuzz", children=(s_frame_fuzz,)))

    def _add_core_asdus(self):
        """Add core essential ASDU types - monitoring messages"""
        # Single-point information
        self.session.connect(
            create_complete_asdu_message(
                "M_SP_NA_1",
                ASDU_Types.M_SP_NA_1,
                create_info_object_single_point(0x000001, 0x01),
            )
        )

        # Double-point information
        self.session.connect(
            create_complete_asdu_message(
                "M_DP_NA_1",
                ASDU_Types.M_DP_NA_1,
                create_info_object_double_point(0x000002, 0x02),
            )
        )

        # Step position information
        self.session.connect(
            create_complete_asdu_message(
                "M_ST_NA_1",
                ASDU_Types.M_ST_NA_1,
                create_info_object_step_position(0x000003, 0x7F, 0x00),
            )
        )

        # Bitstring of 32 bit
        self.session.connect(
            create_complete_asdu_message(
                "M_BO_NA_1",
                ASDU_Types.M_BO_NA_1,
                create_info_object_bitstring(0x000004, 0x12345678, 0x00),
            )
        )

        # Measured value normalized
        self.session.connect(
            create_complete_asdu_message(
                "M_ME_NA_1",
                ASDU_Types.M_ME_NA_1,
                create_info_object_measured_normalized(0x000005, 16384, 0x00),
            )
        )

        # Measured value scaled
        self.session.connect(
            create_complete_asdu_message(
                "M_ME_NB_1",
                ASDU_Types.M_ME_NB_1,
                create_info_object_measured_scaled(0x000006, 1000, 0x00),
            )
        )

        # Measured value floating point
        self.session.connect(
            create_complete_asdu_message(
                "M_ME_NC_1",
                ASDU_Types.M_ME_NC_1,
                create_info_object_measured_float(0x000007, 123.45, 0xC0),
            )
        )

        # Integrated totals
        self.session.connect(
            create_complete_asdu_message(
                "M_IT_NA_1",
                ASDU_Types.M_IT_NA_1,
                create_info_object_integrated_totals(0x000008, 12345),
            )
        )

        # Time-tagged single-point
        self.session.connect(
            create_complete_asdu_message(
                "M_SP_TB_1",
                ASDU_Types.M_SP_TB_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_single_point(0x000001, 0x01),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        # Time-tagged double-point
        self.session.connect(
            create_complete_asdu_message(
                "M_DP_TB_1",
                ASDU_Types.M_DP_TB_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_double_point(0x000002, 0x02),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        # Time-tagged step position
        self.session.connect(
            create_complete_asdu_message(
                "M_ST_TB_1",
                ASDU_Types.M_ST_TB_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_step_position(0x000003, 0x7F, 0x00),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        # Time-tagged bitstring
        self.session.connect(
            create_complete_asdu_message(
                "M_BO_TB_1",
                ASDU_Types.M_BO_TB_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_bitstring(0x000004, 0x12345678, 0x00),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        # Time-tagged measured value normalized
        self.session.connect(
            create_complete_asdu_message(
                "M_ME_TD_1",
                ASDU_Types.M_ME_TD_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_measured_normalized(0x000005, 16384, 0x00),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        # Time-tagged measured value scaled
        self.session.connect(
            create_complete_asdu_message(
                "M_ME_TE_1",
                ASDU_Types.M_ME_TE_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_measured_scaled(0x000006, 1000, 0x00),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        # Time-tagged measured value floating point
        self.session.connect(
            create_complete_asdu_message(
                "M_ME_TF_1",
                ASDU_Types.M_ME_TF_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_measured_float(0x000007, 123.45, 0x00),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        # Time-tagged integrated totals
        self.session.connect(
            create_complete_asdu_message(
                "M_IT_TB_1",
                ASDU_Types.M_IT_TB_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_integrated_totals(0x000008, 12345),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        # Control commands
        # Single command
        self.session.connect(
            create_complete_asdu_message(
                "C_SC_NA_1",
                ASDU_Types.C_SC_NA_1,
                create_info_object_single_command(0x001001, 0x81),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        # Double command
        self.session.connect(
            create_complete_asdu_message(
                "C_DC_NA_1",
                ASDU_Types.C_DC_NA_1,
                create_info_object_double_command(0x001002, 0x02),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        # Regulating step command
        self.session.connect(
            create_complete_asdu_message(
                "C_RC_NA_1",
                ASDU_Types.C_RC_NA_1,
                create_info_object_regulating_step(0x001003, 0x01),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        # Set-point command normalized
        self.session.connect(
            create_complete_asdu_message(
                "C_SE_NA_1",
                ASDU_Types.C_SE_NA_1,
                create_info_object_setpoint_normalized(0x002001, 16384, 0x00, 0x81),
            )
        )

        # Set-point command scaled
        self.session.connect(
            create_complete_asdu_message(
                "C_SE_NB_1",
                ASDU_Types.C_SE_NB_1,
                create_info_object_setpoint_scaled(0x002002, 1000, 0x00, 0x81),
            )
        )

        # Set-point command floating point
        self.session.connect(
            create_complete_asdu_message(
                "C_SE_NC_1",
                ASDU_Types.C_SE_NC_1,
                create_info_object_setpoint_float(0x002003, 100.0, 0x00, 0x81),
            )
        )

        # Bitstring command
        self.session.connect(
            create_complete_asdu_message(
                "C_BO_NA_1",
                ASDU_Types.C_BO_NA_1,
                create_info_object_bitstring_command(0x003001, 0x12345678, 0x81),
            )
        )

        # Time-tagged control commands
        self.session.connect(
            create_complete_asdu_message(
                "C_SC_TA_1",
                ASDU_Types.C_SC_TA_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_single_command(0x001001, 0x81),
                        create_cp56time2a("time_tag"),
                    ),
                ),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        self.session.connect(
            create_complete_asdu_message(
                "C_DC_TA_1",
                ASDU_Types.C_DC_TA_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_double_command(0x001002, 0x02),
                        create_cp56time2a("time_tag"),
                    ),
                ),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        self.session.connect(
            create_complete_asdu_message(
                "C_RC_TA_1",
                ASDU_Types.C_RC_TA_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_regulating_step(0x001003, 0x01),
                        create_cp56time2a("time_tag"),
                    ),
                ),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        self.session.connect(
            create_complete_asdu_message(
                "C_SE_TA_1",
                ASDU_Types.C_SE_TA_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_setpoint_normalized(0x002001, 16384, 0x00, 0x81),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        self.session.connect(
            create_complete_asdu_message(
                "C_SE_TB_1",
                ASDU_Types.C_SE_TB_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_setpoint_scaled(0x002002, 1000, 0x00, 0x81),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        self.session.connect(
            create_complete_asdu_message(
                "C_SE_TC_1",
                ASDU_Types.C_SE_TC_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_setpoint_float(0x002003, 100.0, 0x00, 0x81),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        self.session.connect(
            create_complete_asdu_message(
                "C_BO_TA_1",
                ASDU_Types.C_BO_TA_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_bitstring_command(0x003001, 0x12345678, 0x81),
                        create_cp56time2a("time_tag"),
                    ),
                ),
            )
        )

        # System commands
        # General interrogation
        self.session.connect(
            create_complete_asdu_message(
                "C_IC_NA_1",
                ASDU_Types.C_IC_NA_1,
                create_info_object_interrogation(0x000000, 0x14),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        # Counter interrogation
        self.session.connect(
            create_complete_asdu_message(
                "C_CI_NA_1",
                ASDU_Types.C_CI_NA_1,
                create_info_object_interrogation(0x000000, 0x05),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        # Read command
        self.session.connect(
            create_complete_asdu_message(
                "C_RD_NA_1",
                ASDU_Types.C_RD_NA_1,
                create_info_object_read_command(0x000001),
                cot=CauseOfTransmission.REQUEST,
            )
        )

        # Clock synchronization
        self.session.connect(
            create_complete_asdu_message(
                "C_CS_NA_1",
                ASDU_Types.C_CS_NA_1,
                create_info_object_clock_sync(0x000000),
            )
        )

        # Test command
        self.session.connect(
            create_complete_asdu_message(
                "C_TS_NA_1",
                ASDU_Types.C_TS_NA_1,
                create_info_object_test_command(0x000000, 0xAAAA),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        # Reset process command
        self.session.connect(
            create_complete_asdu_message(
                "C_RP_NA_1",
                ASDU_Types.C_RP_NA_1,
                create_info_object_interrogation(0x000000, 0x01),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        # Delay acquisition command
        self.session.connect(
            create_complete_asdu_message(
                "C_CD_NA_1",
                ASDU_Types.C_CD_NA_1,
                Block(
                    "info_object",
                    children=(
                        Bytes(
                            "ioa",
                            (0x000000).to_bytes(3, "little"),
                            size=3,
                            fuzzable=True,
                        ),
                        Word("delay", 1000, endian="<", fuzzable=True),
                    ),
                ),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        # Test command with time tag
        self.session.connect(
            create_complete_asdu_message(
                "C_TS_TA_1",
                ASDU_Types.C_TS_TA_1,
                Block(
                    "info_with_time",
                    children=(
                        create_info_object_test_command(0x000000, 0xAAAA),
                        create_cp56time2a("time_tag"),
                    ),
                ),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

        # End of initialization
        self.session.connect(
            create_complete_asdu_message(
                "M_EI_NA_1",
                ASDU_Types.M_EI_NA_1,
                create_info_object_interrogation(0x000000, 0x01),
            )
        )

        # Parameter commands
        # Parameter of measured values, normalized
        self.session.connect(
            create_complete_asdu_message(
                "P_ME_NA_1",
                ASDU_Types.P_ME_NA_1,
                create_info_object_parameter(0x004001, 16384, 0x00, 0x01, 0x01),
            )
        )

        # Parameter of measured values, scaled
        self.session.connect(
            create_complete_asdu_message(
                "P_ME_NB_1",
                ASDU_Types.P_ME_NB_1,
                create_info_object_parameter(0x004002, 1000, 0x00, 0x01, 0x01),
            )
        )

        # Parameter of measured values, floating point
        self.session.connect(
            create_complete_asdu_message(
                "P_ME_NC_1",
                ASDU_Types.P_ME_NC_1,
                Block(
                    "info_object",
                    children=(
                        Bytes(
                            "ioa",
                            (0x004003).to_bytes(3, "little"),
                            size=3,
                            fuzzable=True,
                        ),
                        DWord(
                            "value",
                            int.from_bytes(struct.pack("<f", 100.0), "little"),
                            endian="<",
                            fuzzable=True,
                        ),
                        Byte("quality", 0x00, fuzzable=True),
                        Byte("kind", 0x01, fuzzable=True),
                        Byte("change", 0x01, fuzzable=True),
                    ),
                ),
            )
        )

        # Parameter activation
        self.session.connect(
            create_complete_asdu_message(
                "P_AC_NA_1",
                ASDU_Types.P_AC_NA_1,
                create_info_object_interrogation(0x000000, 0x01),
                cot=CauseOfTransmission.ACTIVATION,
            )
        )

    def _add_attack_patterns(self):
        """Add consolidated attack patterns based on research"""
        intensity = self.config.get_option("attack_intensity", "medium")

        # Reconnaissance - Device discovery
        self.session.connect(
            create_complete_asdu_message(
                "ATTACK_DeviceDiscovery",
                ASDU_Types.C_IC_NA_1,
                create_info_object_interrogation(0x000000, 0x14),
            )
        )

        # Reconnaissance - Address enumeration (multiple addresses)
        for i in range(5):
            self.session.connect(
                create_complete_asdu_message(
                    f"ATTACK_AddrEnum_{i}",
                    ASDU_Types.M_SP_NA_1,
                    create_info_object_single_point(0x000001 + i, 0x01),
                )
            )

        # Operation failure - Invalid measurement (infinity)
        self.session.connect(
            create_complete_asdu_message(
                "ATTACK_InvalidMeasurement",
                ASDU_Types.M_ME_NC_1,
                create_info_object_measured_float(0x000001, float("inf"), 0xFF),
            )
        )

        # Operation failure - Unauthorized command
        self.session.connect(
            create_complete_asdu_message(
                "ATTACK_UnauthorizedCommand",
                ASDU_Types.C_SC_NA_1,
                create_info_object_single_command(0x001001, 0x81),
            )
        )

        # Operation failure - Rapid command sequence
        for i in range(5):
            self.session.connect(
                create_complete_asdu_message(
                    f"ATTACK_RapidCmd_{i}",
                    ASDU_Types.C_SC_NA_1,
                    create_info_object_single_command(0x001001, 0x81 if i % 2 else 0x82),
                )
            )

        # DoS - Reset flood
        flood_count = 10 if intensity == "low" else 20
        for i in range(flood_count):
            startdt = create_apci_u_format(f"ATTACK_ResetFlood_{i}", UFormat_Functions.STARTDT_ACT)
            self.session.connect(Request(f"ATTACK_ResetFlood_{i}", children=(startdt,)))

        # DoS - Invalid ASDU flood
        invalid_count = 5 if intensity == "low" else 15
        for i in range(invalid_count):
            self.session.connect(
                Request(
                    f"ATTACK_InvalidFlood_{i}",
                    children=(
                        create_apci_i_format_header("apci"),
                        Block(
                            "asdu_block",
                            children=(
                                Byte("invalid_type", 255, fuzzable=True),
                                SmartBytes(
                                    "invalid_payload",
                                    b"\xff" * 10,
                                    max_len=250,
                                    fuzzable=True,
                                ),
                            ),
                        ),
                    ),
                )
            )

        # DoS - Malformed APCI
        self.session.connect(
            Request(
                "ATTACK_MalformedAPCI",
                children=(
                    Static("start", b"\x68"),
                    Byte("bad_length", 0xFF, fuzzable=True),
                    Byte("bad_control_1", 0x00, fuzzable=True),
                    Byte("bad_control_2", 0x00, fuzzable=True),
                    SmartBytes("junk_data", b"\x00" * 100, max_len=250, fuzzable=True),
                ),
            )
        )

        # Protocol violation - Invalid sequence numbers
        self.session.connect(
            Request(
                "ATTACK_InvalidSeqNum",
                children=(
                    Static("start", b"\x68"),
                    Byte("length", 10),
                    Word("send_seq", 0xFFFF, endian="<", fuzzable=True),
                    Word("recv_seq", 0xFFFF, endian="<", fuzzable=True),
                    SmartBytes(
                        "payload",
                        b"\x01\x01\x06\x00\x01\x00\x01\x00\x00\x01",
                        max_len=250,
                        fuzzable=True,
                    ),
                ),
            )
        )

        # Protocol violation - Wrong COT for ASDU type
        self.session.connect(
            create_complete_asdu_message(
                "ATTACK_WrongCOT",
                ASDU_Types.M_SP_NA_1,
                create_info_object_single_point(0x000001, 0x01),
                cot=CauseOfTransmission.ACTIVATION,  # Wrong COT for monitoring ASDU
            )
        )

        # Protocol violation - Zero-length payload
        self.session.connect(
            Request(
                "ATTACK_ZeroPayload",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            create_asdu_header(
                                ASDU_Types.C_IC_NA_1, CauseOfTransmission.ACTIVATION
                            ),
                            # No information object = zero-length
                        ),
                    ),
                ),
            )
        )

        # Protocol violation - Maximum payload
        self.session.connect(
            Request(
                "ATTACK_MaxPayload",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            create_asdu_header(ASDU_Types.F_SG_NA_1),
                            Block(
                                "info_object",
                                children=(
                                    Bytes(
                                        "ioa",
                                        (0x010000).to_bytes(3, "little"),
                                        size=3,
                                        fuzzable=True,
                                    ),
                                    SmartBytes(
                                        "large_payload",
                                        b"X" * 245,
                                        max_len=250,
                                        fuzzable=True,
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )

        # ASDU TypeId sweep: valid (1-127), reserved (128-135), vendor (136-255).
        # Pair with a Common Address sweep across boundary values (0, 1, 0x7FFF,
        # 0x8000, 0xFFFE, 0xFFFF) to catch parsers that hard-code CA==1 or
        # mis-handle the reserved CA=0/broadcast CA=0xFFFF.
        # Refs: cve_patterns.json#iec104-asdu-type-id-reserved,
        #       cve_patterns.json#iec104-common-address-sweep.
        self.session.connect(
            Request(
                "IEC104_ASDU_TypeId",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            Group(
                                "ASDU.TypeId",
                                values=[
                                    bytes([n]) for n in list(range(1, 128)) + list(range(128, 256))
                                ],
                            ),
                            Byte("vsq", 0x01, fuzzable=True),
                            Word("cot", CauseOfTransmission.SPONTANEOUS, endian="<", fuzzable=True),
                            Group(
                                "ASDU.CommonAddress",
                                values=[
                                    struct.pack("<H", v) for v in (0, 1, 65534, 65535, 32767, 32768)
                                ],
                            ),
                            create_info_object_single_point(0x000001, 0x01),
                        ),
                    ),
                ),
            )
        )

    def _add_file_transfer_patterns(self):
        """Add comprehensive file transfer ASDU patterns"""
        # File ready
        self.session.connect(
            create_complete_asdu_message(
                "FILE_Ready",
                ASDU_Types.F_FR_NA_1,
                create_info_object_file_ready(0x000000, 0x1234, "testfile.txt"),
            )
        )

        # Section ready
        self.session.connect(
            create_complete_asdu_message(
                "FILE_SectionReady",
                ASDU_Types.F_SR_NA_1,
                create_info_object_file_section(0x000000, 0x1234, 0x01, 0x01),
            )
        )

        # Call file
        self.session.connect(
            create_complete_asdu_message(
                "FILE_CallFile",
                ASDU_Types.F_SC_NA_1,
                Block(
                    "info_object",
                    children=(
                        Bytes(
                            "ioa",
                            (0x000000).to_bytes(3, "little"),
                            size=3,
                            fuzzable=True,
                        ),
                        Word("file_id", 0x1234, endian="<", fuzzable=True),
                        Byte("section", 0x01, fuzzable=True),
                        Byte("status", 0x02, fuzzable=True),
                        SmartBytes("filename", b"config.ini\x00", max_len=255, fuzzable=True),
                    ),
                ),
            )
        )

        # Last section
        self.session.connect(
            create_complete_asdu_message(
                "FILE_LastSection",
                ASDU_Types.F_LS_NA_1,
                create_info_object_file_section(0x000000, 0x1234, 0x01, 0x03),
            )
        )

        # ACK file/section
        self.session.connect(
            create_complete_asdu_message(
                "FILE_Ack",
                ASDU_Types.F_AF_NA_1,
                create_info_object_file_section(0x000000, 0x1234, 0x01, 0x00),
            )
        )

        # File segment
        self.session.connect(
            create_complete_asdu_message(
                "FILE_Segment",
                ASDU_Types.F_SG_NA_1,
                create_info_object_file_segment(0x000000, 0x1234, 0x01, 0x01, b"X" * 100),
            )
        )

        # Directory
        self.session.connect(
            create_complete_asdu_message(
                "FILE_Directory",
                ASDU_Types.F_DR_TA_1,
                Block(
                    "info_object",
                    children=(
                        Bytes(
                            "ioa",
                            (0x000000).to_bytes(3, "little"),
                            size=3,
                            fuzzable=True,
                        ),
                        create_cp56time2a("time_tag"),
                        SmartBytes(
                            "file_list",
                            b"file1.txt\x00file2.log\x00file3.cfg\x00",
                            max_len=250,
                            fuzzable=True,
                        ),
                    ),
                ),
            )
        )

        # Query log - Request archive file
        self.session.connect(
            create_complete_asdu_message(
                "FILE_QueryLog",
                ASDU_Types.F_SC_NB_1,
                Block(
                    "info_object",
                    children=(
                        Bytes(
                            "ioa",
                            (0x000000).to_bytes(3, "little"),
                            size=3,
                            fuzzable=True,
                        ),
                        create_cp56time2a("start_time"),
                        create_cp56time2a("end_time"),
                        SmartBytes("filename", b"archive.log\x00", max_len=255, fuzzable=True),
                    ),
                ),
            )
        )

        # File attack - Oversized filename
        self.session.connect(
            create_complete_asdu_message(
                "FILE_ATTACK_OversizedName",
                ASDU_Types.F_SC_NA_1,
                Block(
                    "info_object",
                    children=(
                        Bytes(
                            "ioa",
                            (0x000000).to_bytes(3, "little"),
                            size=3,
                            fuzzable=True,
                        ),
                        Word("file_id", 0x1234, endian="<", fuzzable=True),
                        Byte("section", 0x01, fuzzable=True),
                        Byte("status", 0x02, fuzzable=True),
                        SmartBytes("filename", b"A" * 255, max_len=255, fuzzable=True),
                    ),
                ),
            )
        )

        # File attack - Invalid operations
        self.session.connect(
            create_complete_asdu_message(
                "FILE_ATTACK_InvalidOp",
                ASDU_Types.F_SG_NA_1,
                create_info_object_file_segment(0x000000, 0xFFFF, 0xFF, 0xFF, b"\xff" * 250),
            )
        )

        # File attack - Path traversal
        self.session.connect(
            create_complete_asdu_message(
                "FILE_ATTACK_PathTraversal",
                ASDU_Types.F_SC_NA_1,
                Block(
                    "info_object",
                    children=(
                        Bytes(
                            "ioa",
                            (0x000000).to_bytes(3, "little"),
                            size=3,
                            fuzzable=True,
                        ),
                        Word("file_id", 0x1234, endian="<", fuzzable=True),
                        Byte("section", 0x01, fuzzable=True),
                        Byte("status", 0x02, fuzzable=True),
                        SmartBytes(
                            "filename",
                            b"../" * 100 + b"testfile\x00",
                            max_len=255,
                            fuzzable=True,
                        ),
                    ),
                ),
            )
        )

        # File attack - Malformed segment (zero-length)
        self.session.connect(
            create_complete_asdu_message(
                "FILE_ATTACK_ZeroLength",
                ASDU_Types.F_SG_NA_1,
                create_info_object_file_segment(0x000000, 0x0000, 0x00, 0x00, b""),
            )
        )

        # File attack - Operation flood
        for i in range(10):
            self.session.connect(
                create_complete_asdu_message(
                    f"FILE_ATTACK_Flood_{i}",
                    ASDU_Types.F_FR_NA_1,
                    create_info_object_file_ready(0x000000, i, f"file{i}.tmp"),
                )
            )

    def _add_vendor_patterns(self):
        """Add vendor-specific attack patterns"""
        # Siemens SICAM pattern 1
        self.session.connect(
            Request(
                "VENDOR_Siemens_SICAM_1",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            create_asdu_header(200),  # Private ASDU type
                            Block(
                                "info_object",
                                children=(
                                    Bytes(
                                        "ioa",
                                        (0x010000).to_bytes(3, "little"),
                                        size=3,
                                        fuzzable=True,
                                    ),
                                    SmartBytes(
                                        "sicam_data",
                                        b"SICAM\x00\x12\x34",
                                        max_len=250,
                                        fuzzable=True,
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )

        # Siemens SICAM pattern 2
        self.session.connect(
            Request(
                "VENDOR_Siemens_SICAM_2",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            create_asdu_header(205),  # Private ASDU type
                            Block(
                                "info_object",
                                children=(
                                    Bytes(
                                        "ioa",
                                        (0x001000).to_bytes(3, "little"),
                                        size=3,
                                        fuzzable=True,
                                    ),
                                    DWord(
                                        "value",
                                        int.from_bytes(struct.pack("<f", 12345.67), "little"),
                                        endian="<",
                                        fuzzable=True,
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )

        # ABB pattern 1
        self.session.connect(
            Request(
                "VENDOR_ABB_1",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            create_asdu_header(135),  # Private ASDU type
                            Block(
                                "info_object",
                                children=(
                                    Bytes(
                                        "ioa",
                                        (0x000001).to_bytes(3, "little"),
                                        size=3,
                                        fuzzable=True,
                                    ),
                                    Word("abb_param", 100, endian="<", fuzzable=True),
                                    SmartBytes(
                                        "abb_blob",
                                        b"ABB_BLOB" * 10,
                                        max_len=250,
                                        fuzzable=True,
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )

        # ABB pattern 2
        self.session.connect(
            Request(
                "VENDOR_ABB_2",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            create_asdu_header(252),  # Private ASDU type
                            Block(
                                "info_object",
                                children=(
                                    Bytes(
                                        "ioa",
                                        (0x003000).to_bytes(3, "little"),
                                        size=3,
                                        fuzzable=True,
                                    ),
                                    DWord(
                                        "value",
                                        int.from_bytes(struct.pack("<f", 123.45), "little"),
                                        endian="<",
                                        fuzzable=True,
                                    ),
                                    Word("abb_code", 0x1234, endian="<", fuzzable=True),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )

        # Generic private ASDU range
        for i in range(0, 128, 16):  # Every 16th private ASDU
            self.session.connect(
                Request(
                    f"VENDOR_Private_{128 + i}",
                    children=(
                        create_apci_i_format_header("apci"),
                        Block(
                            "asdu_block",
                            children=(
                                create_asdu_header(128 + i),
                                Block(
                                    "info_object",
                                    children=(
                                        Bytes(
                                            "ioa",
                                            (0x000001 + i).to_bytes(3, "little"),
                                            size=3,
                                            fuzzable=True,
                                        ),
                                        SmartBytes(
                                            "private_data",
                                            b"\xff" * 5,
                                            max_len=250,
                                            fuzzable=True,
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                )
            )

        # Boundary test - Maximum values
        self.session.connect(
            create_complete_asdu_message(
                "BOUNDARY_MaxValues",
                ASDU_Types.M_ME_NC_1,
                create_info_object_measured_float(0xFFFFFF, 1e38, 0xFF),
            )
        )

        # Boundary test - Minimum values
        self.session.connect(
            create_complete_asdu_message(
                "BOUNDARY_MinValues",
                ASDU_Types.M_ME_NC_1,
                create_info_object_measured_float(0x000001, -1e38, 0x00),
            )
        )

        # Boundary test - Reserved type
        self.session.connect(
            Request(
                "BOUNDARY_ReservedType",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            create_asdu_header(0),  # Reserved type
                            # Empty payload
                        ),
                    ),
                ),
            )
        )

        # Boundary test - Beyond range
        self.session.connect(
            Request(
                "BOUNDARY_BeyondRange",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            Byte("invalid_type", 0xFF, fuzzable=True),  # Maximum byte value (255)
                            Byte("vsq", 0x01, fuzzable=True),
                            Word("cot", 3, endian="<", fuzzable=True),
                            Word("ca", 1, endian="<", fuzzable=True),
                            # Empty payload
                        ),
                    ),
                ),
            )
        )

    def _add_iec62351_auth_patterns(self):
        """Add IEC 62351-5 authentication fuzzing patterns.

        IEC 62351-5 adds authentication to IEC 60870-5 protocols using:
        - COT 14: Authentication
        - COT 15: Maintenance of authentication session key
        - COT 16: Maintenance of user role and update key

        Authentication ASDUs use private type IDs 80-83:
        - 80 (S_AR_NA_1): Authentication request
        - 81 (S_AR_NA_1): Authentication response
        - 82 (S_KR_NA_1): Session key status request
        - 83 (S_KS_NA_1): Session key status response
        """
        if not self.is_request_enabled("IEC104_IEC62351_Auth"):
            return

        # Get credentials from options
        username = self.config.get_option("iec62351_username", "") or "admin"
        password = self.config.get_option("iec62351_password", "") or "password"

        # Authentication Request (ASDU type 80 - S_AR_NA_1)
        # Based on IEC 62351-5 authentication challenge/response
        self.session.connect(
            Request(
                "IEC62351_Auth_Request",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            Byte("type_id", 80, fuzzable=True),  # S_AR_NA_1
                            Byte("vsq", 0x01, fuzzable=True),
                            Word(
                                "cot",
                                CauseOfTransmission.AUTHENTICATION,
                                endian="<",
                                fuzzable=True,
                            ),
                            Word(
                                "ca",
                                self.config.get_option("common_address", 1),
                                endian="<",
                                fuzzable=True,
                            ),
                            Block(
                                "info_object",
                                children=(
                                    Bytes(
                                        "ioa",
                                        (0x000000).to_bytes(3, "little"),
                                        size=3,
                                        fuzzable=True,
                                    ),
                                    Byte("user_role", 0x01, fuzzable=True),  # Role ID
                                    Byte("sequence_number", 0x01, fuzzable=True),
                                    SmartString(
                                        "username",
                                        username,
                                        max_len=32,
                                        context=StringContext.CREDENTIAL,
                                    ),
                                    Byte("challenge_type", 0x01, fuzzable=True),  # HMAC-SHA256
                                    SmartBytes(
                                        "challenge",
                                        b"\x00" * 32,
                                        max_len=64,
                                        fuzzable=True,
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )

        # Authentication Response with HMAC (ASDU type 81)
        self.session.connect(
            Request(
                "IEC62351_Auth_Response",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            Byte("type_id", 81, fuzzable=True),  # Authentication response
                            Byte("vsq", 0x01, fuzzable=True),
                            Word(
                                "cot",
                                CauseOfTransmission.AUTHENTICATION,
                                endian="<",
                                fuzzable=True,
                            ),
                            Word(
                                "ca",
                                self.config.get_option("common_address", 1),
                                endian="<",
                                fuzzable=True,
                            ),
                            Block(
                                "info_object",
                                children=(
                                    Bytes(
                                        "ioa",
                                        (0x000000).to_bytes(3, "little"),
                                        size=3,
                                        fuzzable=True,
                                    ),
                                    Byte("user_role", 0x01, fuzzable=True),
                                    Byte("sequence_number", 0x01, fuzzable=True),
                                    SmartString(
                                        "password_hmac",
                                        password,
                                        max_len=64,
                                        context=StringContext.CREDENTIAL,
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )

        # Session Key Status Request (ASDU type 82 - S_KR_NA_1)
        self.session.connect(
            Request(
                "IEC62351_Key_Status_Request",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            Byte("type_id", 82, fuzzable=True),  # S_KR_NA_1
                            Byte("vsq", 0x01, fuzzable=True),
                            Word(
                                "cot",
                                CauseOfTransmission.MAINTENANCE_OF_AUTH_SESSION_KEY,
                                endian="<",
                                fuzzable=True,
                            ),
                            Word(
                                "ca",
                                self.config.get_option("common_address", 1),
                                endian="<",
                                fuzzable=True,
                            ),
                            Block(
                                "info_object",
                                children=(
                                    Bytes(
                                        "ioa",
                                        (0x000000).to_bytes(3, "little"),
                                        size=3,
                                        fuzzable=True,
                                    ),
                                    Byte("key_id", 0x01, fuzzable=True),
                                    Byte("key_status", 0x00, fuzzable=True),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )

        # Session Key Change (ASDU type 83 - S_KS_NA_1)
        self.session.connect(
            Request(
                "IEC62351_Key_Change",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            Byte("type_id", 83, fuzzable=True),  # S_KS_NA_1
                            Byte("vsq", 0x01, fuzzable=True),
                            Word(
                                "cot",
                                CauseOfTransmission.MAINTENANCE_OF_AUTH_SESSION_KEY,
                                endian="<",
                                fuzzable=True,
                            ),
                            Word(
                                "ca",
                                self.config.get_option("common_address", 1),
                                endian="<",
                                fuzzable=True,
                            ),
                            Block(
                                "info_object",
                                children=(
                                    Bytes(
                                        "ioa",
                                        (0x000000).to_bytes(3, "little"),
                                        size=3,
                                        fuzzable=True,
                                    ),
                                    Byte("key_id", 0x01, fuzzable=True),
                                    SmartString(
                                        "new_session_key",
                                        password,
                                        max_len=32,
                                        context=StringContext.CREDENTIAL,
                                    ),
                                    SmartBytes(
                                        "wrapped_key",
                                        b"\x00" * 64,
                                        max_len=128,
                                        fuzzable=True,
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )

        # User Role Update (COT 16)
        self.session.connect(
            Request(
                "IEC62351_User_Role_Update",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            Byte("type_id", 80, fuzzable=True),  # Use auth request type
                            Byte("vsq", 0x01, fuzzable=True),
                            Word(
                                "cot",
                                CauseOfTransmission.MAINTENANCE_OF_USER_ROLE_AND_UPDATE_KEY,
                                endian="<",
                                fuzzable=True,
                            ),
                            Word(
                                "ca",
                                self.config.get_option("common_address", 1),
                                endian="<",
                                fuzzable=True,
                            ),
                            Block(
                                "info_object",
                                children=(
                                    Bytes(
                                        "ioa",
                                        (0x000000).to_bytes(3, "little"),
                                        size=3,
                                        fuzzable=True,
                                    ),
                                    Byte("user_role", 0xFF, fuzzable=True),  # Try max role (admin)
                                    Byte("operation", 0x01, fuzzable=True),  # Add/Update
                                    SmartString(
                                        "username",
                                        username,
                                        max_len=32,
                                        context=StringContext.CREDENTIAL,
                                    ),
                                    SmartString(
                                        "update_key",
                                        password,
                                        max_len=64,
                                        context=StringContext.CREDENTIAL,
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )

        # Malformed Authentication (boundary testing)
        self.session.connect(
            Request(
                "IEC62351_Auth_Malformed",
                children=(
                    create_apci_i_format_header("apci"),
                    Block(
                        "asdu_block",
                        children=(
                            Byte("type_id", 80, fuzzable=True),
                            Byte("vsq", 0xFF, fuzzable=True),  # Invalid VSQ
                            Word(
                                "cot",
                                CauseOfTransmission.AUTHENTICATION,
                                endian="<",
                                fuzzable=True,
                            ),
                            Word("ca", 0xFFFF, endian="<", fuzzable=True),  # Invalid CA
                            Block(
                                "info_object",
                                children=(
                                    Bytes(
                                        "ioa",
                                        (0xFFFFFF).to_bytes(3, "little"),
                                        size=3,
                                        fuzzable=True,
                                    ),
                                    SmartBytes(
                                        "malformed_auth",
                                        b"\xff" * 128,
                                        max_len=250,
                                        fuzzable=True,
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )


# Alias for compatibility
IEC104EnhancedFuzzer = IEC104Fuzzer
